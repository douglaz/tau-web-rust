//! Closed original file invocation domains. These rules validate observations, never dispatch.
use crate::{completion, history, reader_checks};
use serde_json::Value;
use std::collections::BTreeMap;

type Context = (String, String, String, u64, Option<usize>);
type CaptureKey = (Context, String, String);
type Counts = BTreeMap<CaptureKey, usize>;
const ERROR: &str = "original file invocation/comparison domain mismatch";

fn context(state: &reader_checks::CallerState) -> Result<Context, String> {
    let owner = state.owner.as_ref().ok_or(ERROR)?;
    Ok((
        owner.0.clone(),
        owner.1.clone(),
        owner.2.clone(),
        state.invocation,
        state.prepare,
    ))
}

fn before(mut owner: Context, execution: &[Value]) -> Result<Context, String> {
    let index = execution
        .iter()
        .position(|id| id == &owner.2)
        .ok_or(ERROR)?;
    owner.1 = "after".into();
    owner.2 = index
        .checked_sub(1)
        .map_or("", |i| execution[i].as_str().unwrap())
        .into();
    Ok(owner)
}

fn captures(expected: &mut Counts, owner: Context, site: &str, kind: &str, n: usize, once: bool) {
    for kind in if kind == "browser.store" {
        vec!["browser.dump", "browser.store"]
    } else {
        vec![kind]
    } {
        let count = expected
            .entry((owner.clone(), site.into(), kind.into()))
            .or_default();
        if once {
            *count = (*count).max(n);
        } else {
            *count += n;
        }
    }
}

pub fn validate(report: &Value) -> Result<(), String> {
    validate_primary(report, completion::inventory())?;
    validate_with(
        report,
        completion::inventory(),
        &reader_checks::resolve_callers(report)?,
    )
}

fn validate_primary(report: &Value, key: &Value) -> Result<(), String> {
    let error = "original primary predicate checkpoint mismatch";
    let states = reader_checks::caller_states(report);
    let history = report["helper_history"].as_array().ok_or(error)?;
    let rows = report["primary_history"].as_array().ok_or(error)?;
    let mut expected = Vec::new();
    for case in report["cases"].as_array().ok_or(error)? {
        let spec = key["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == case["id"])
            .ok_or(error)?;
        for id in completion::expected_assertions(spec, case, report)? {
            expected.push((case["id"].as_str().ok_or(error)?, id));
        }
    }
    if rows.len() != expected.len() {
        return Err(error.into());
    }
    let mut previous = 0;
    for (row, (case, id)) in rows.iter().zip(expected) {
        let at = row["at_ns"].as_u64().ok_or(error)?;
        let cursor = row["history_cursor"].as_u64().ok_or(error)? as usize;
        let state = states.get(cursor).ok_or(error)?;
        if row.as_object().is_none_or(|o| o.len() != 4)
            || row["case"] != case
            || row["id"] != id
            || state
                .owner
                .as_ref()
                .is_none_or(|o| o.1 != "inside" || o.2 != case)
            || at < previous
            || at > report["duration_ns"].as_u64().ok_or(error)?
            || cursor > 0 && history[cursor - 1]["at_ns"].as_u64().ok_or(error)? > at
            || cursor < history.len() && history[cursor]["at_ns"].as_u64().ok_or(error)? < at
        {
            return Err(error.into());
        }
        previous = at;
    }
    Ok(())
}

pub(super) fn checkpoint(
    report: &Value,
    original: &Value,
    case: &str,
    predicate: &str,
    instance: usize,
) -> Result<(), String> {
    checkpoint_with_checks(report, original, case, predicate, instance, &[])
}

pub(super) fn checkpoint_with_checks(
    report: &Value,
    original: &Value,
    case: &str,
    predicate: &str,
    instance: usize,
    checks: &[Value],
) -> Result<(), String> {
    let error = "original file source checkpoint/window mismatch";
    let rows = report["primary_history"].as_array().ok_or(error)?;
    let id = format!("{predicate}.i{instance:03}");
    let index = rows
        .iter()
        .position(|r| r["case"] == case && r["id"] == id)
        .ok_or(error)?;
    let target = &rows[index];
    let lower = if index > 0 && rows[index - 1]["case"] == case {
        rows[index - 1]["at_ns"].as_u64().ok_or(error)?
    } else {
        report["cases"]
            .as_array()
            .ok_or(error)?
            .iter()
            .find(|c| c["id"] == case)
            .ok_or(error)?["start_ns"]
            .as_u64()
            .ok_or(error)?
    };
    let at = original["at_ns"].as_u64().ok_or(error)?;
    let cursor = original["history_cursor"].as_u64().ok_or(error)? as usize;
    let until = target["history_cursor"].as_u64().ok_or(error)? as usize;
    let events = report["helper_history"].as_array().ok_or(error)?;
    if at < lower
        || at > target["at_ns"].as_u64().ok_or(error)?
        || until.checked_sub(cursor) != Some(checks.len())
        || events.get(cursor..until).is_none_or(|slice| {
            slice
                .iter()
                .zip(checks)
                .any(|(e, c)| e["event"] != "check" || !c.is_string() || e["id"] != *c)
        })
        || cursor > 0 && events[cursor - 1]["at_ns"].as_u64().ok_or(error)? > at
        || cursor < events.len() && events[cursor]["at_ns"].as_u64().ok_or(error)? < at
    {
        return Err(error.into());
    }
    if original["kind"] == "browser.store" {
        let parent = original["parent"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or(error)? as usize
            - 1;
        checkpoint_with_checks(
            report,
            report["file_captures"]
                .as_array()
                .ok_or(error)?
                .get(parent)
                .ok_or(error)?,
            case,
            predicate,
            instance,
            checks,
        )?;
    }
    Ok(())
}

fn validate_with(
    report: &Value,
    key: &Value,
    readers: &[reader_checks::SourceRoot],
) -> Result<(), String> {
    let requirements = if report["mode"] == "full" {
        key
    } else {
        &report["plan"]
    };
    let execution: Vec<_> = if report["mode"] == "full" {
        key["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].clone())
            .collect()
    } else {
        requirements["expected_execution"]
            .as_array()
            .ok_or(ERROR)?
            .clone()
    };
    let states = reader_checks::caller_states(report);
    let pages = history::source_page_states(report)?;
    let mut preparation_pages = BTreeMap::new();
    for (index, event) in report["helper_history"]
        .as_array()
        .ok_or(ERROR)?
        .iter()
        .enumerate()
    {
        if event["event"] == "call_start" && event["kind"] == "binding.prepare" {
            preparation_pages.insert(
                context(&states[index + 1])?,
                event["page"].as_u64().ok_or(ERROR)?,
            );
        }
    }
    let mut expected = Counts::new();
    let mut comparisons: BTreeMap<Context, Vec<String>> = BTreeMap::new();
    let rules = key["file_comparison_sources"].as_object().ok_or(ERROR)?;
    for source in readers {
        let rule = &key["file_read_sources"][&source.site];
        if matches!(rule[1].as_str(), Some("current" | "reload")) {
            captures(
                &mut expected,
                (
                    source.owner.0.clone(),
                    source.owner.1.clone(),
                    source.owner.2.clone(),
                    source.invocation,
                    source.prepare,
                ),
                rule[0].as_str().ok_or(ERROR)?,
                "browser.store",
                1,
                false,
            );
        }
    }
    for case in key["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| execution.contains(&c["id"]))
    {
        let owner = (
            format!(
                "{}.run",
                case["site_id"].as_str().unwrap().split('.').next().unwrap()
            ),
            "inside".into(),
            case["id"].as_str().unwrap().into(),
            case["invocation"].as_u64().ok_or(ERROR)?,
            None,
        );
        // A selected lifecycle phase may have a different enclosing source scope.
        let scenario = if owner.0 == "lifecycle_cases.run"
            && requirements["scenario_scopes"].get(&owner.0).is_none()
        {
            "lifecycle_cases.selected"
        } else {
            &owner.0
        };
        let owner = (scenario.to_owned(), owner.1, owner.2, owner.3, owner.4);
        for predicate in case["assertions"].as_array().unwrap() {
            for (site, rule) in rules.iter().filter(|(_, r)| r["predicate"] == *predicate) {
                comparisons
                    .entry(owner.clone())
                    .or_default()
                    .push(site.clone());
                for side in ["left", "right"] {
                    let operand = &rule[side];
                    let mode = operand[2].as_str().ok_or(ERROR)?;
                    if matches!(mode, "constructor" | "reader") {
                        continue;
                    }
                    let capture_owner = if operand[3] == "before" {
                        before(owner.clone(), &execution)?
                    } else {
                        owner.clone()
                    };
                    captures(
                        &mut expected,
                        capture_owner,
                        operand[0].as_str().ok_or(ERROR)?,
                        operand[1].as_str().ok_or(ERROR)?,
                        1,
                        mode == "once",
                    );
                }
            }
        }
    }
    let mut preparation_counts = BTreeMap::new();
    let mut contracts = BTreeMap::new();
    for row in requirements["invocation_root_sequences"]
        .as_array()
        .ok_or(ERROR)?
    {
        let base: Context = (
            row["scenario"].as_str().unwrap().to_owned(),
            row["owner"].as_str().unwrap().to_owned(),
            row["case"].as_str().unwrap_or("").to_owned(),
            row["invocation"].as_u64().ok_or(ERROR)?,
            None,
        );
        for domain in row["prepare_domains"].as_array().unwrap() {
            let ordinal = preparation_counts.entry(base.clone()).or_insert(0);
            *ordinal += 1;
            if domain["active"] == true {
                let owner = (
                    base.0.clone(),
                    base.1.clone(),
                    base.2.clone(),
                    base.3,
                    Some(*ordinal),
                );
                comparisons.insert(
                    owner.clone(),
                    vec![
                        "binding.contracts.observe".into(),
                        "binding.contracts.branch".into(),
                    ],
                );
                contracts.insert(owner, domain["contracts"].as_bool().ok_or(ERROR)?);
            }
        }
    }
    for rule in key["file_observation_sources"].as_array().ok_or(ERROR)? {
        let site = rule[0].as_str().ok_or(ERROR)?;
        let scenario = rule[2].as_str().ok_or(ERROR)?;
        if rule[1] == "scope" {
            let Some(invocations) = requirements["scenario_scopes"][scenario].as_u64() else {
                continue;
            };
            for invocation in 1..=invocations {
                let Some(case) = key["cases"].as_array().unwrap().iter().find(|c| {
                    c["invocation"] == invocation
                        && execution.contains(&c["id"])
                        && rule[3].as_array().unwrap().iter().any(|m| {
                            c["site_id"]
                                .as_str()
                                .unwrap()
                                .starts_with(&format!("{}.", m.as_str().unwrap()))
                        })
                }) else {
                    continue;
                };
                let owner = before(
                    (
                        scenario.into(),
                        "inside".into(),
                        case["id"].as_str().unwrap().into(),
                        invocation,
                        None,
                    ),
                    &execution,
                )?;
                captures(
                    &mut expected,
                    owner,
                    site,
                    rule[4].as_str().ok_or(ERROR)?,
                    1,
                    false,
                );
            }
        } else if rule[1] == "case" {
            for case in key["cases"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|c| c["site_id"] == rule[3] && execution.contains(&c["id"]))
            {
                let owner = (
                    scenario.into(),
                    rule[4].as_str().ok_or(ERROR)?.into(),
                    case["id"].as_str().unwrap().into(),
                    case["invocation"].as_u64().ok_or(ERROR)?,
                    None,
                );
                captures(
                    &mut expected,
                    owner,
                    site,
                    rule[6].as_str().ok_or(ERROR)?,
                    rule[5].as_u64().ok_or(ERROR)? as usize,
                    false,
                );
            }
        } else {
            return Err(ERROR.into());
        }
    }
    let mut observed: BTreeMap<CaptureKey, Vec<&Value>> = BTreeMap::new();
    let history = report["helper_history"].as_array().ok_or(ERROR)?;
    for capture in report["file_captures"].as_array().ok_or(ERROR)? {
        let cursor = capture["history_cursor"].as_u64().ok_or(ERROR)? as usize;
        let owner = context(states.get(cursor).ok_or(ERROR)?)?;
        let kind = capture["kind"].as_str().ok_or(ERROR)?;
        let at = capture["at_ns"].as_u64().ok_or(ERROR)?;
        if cursor > 0 && history[cursor - 1]["at_ns"].as_u64().ok_or(ERROR)? > at
            || cursor < history.len() && history[cursor]["at_ns"].as_u64().ok_or(ERROR)? < at
            || capture["case"].as_str()
                != if owner.1 == "inside" {
                    Some(owner.2.as_str())
                } else {
                    None
                }
        {
            return Err(ERROR.into());
        }
        if kind != "constructor" {
            let role = if matches!(
                owner.0.as_str(),
                "seed_cases.run" | "setup_cases.run" | "mode_cases.run" | "binding_cases.run"
            ) && owner.3 == 2
                || owner.2 == "main.c022.p001"
            {
                "served"
            } else {
                "tracer"
            };
            let expected_page = if owner.4.is_some() {
                preparation_pages.get(&owner)
            } else {
                pages[cursor].get(role)
            };
            if expected_page.is_none_or(|p| capture["page"] != *p) {
                return Err(ERROR.into());
            }
        }
        observed
            .entry((
                owner,
                capture["site"].as_str().ok_or(ERROR)?.into(),
                kind.into(),
            ))
            .or_default()
            .push(capture);
    }
    let actual: Counts = observed
        .iter()
        .filter(|((_, _, k), _)| k != "constructor")
        .map(|(k, v)| (k.clone(), v.len()))
        .collect();
    if actual != expected {
        let differences: Vec<_> = expected
            .keys()
            .chain(actual.keys())
            .filter(|k| expected.get(*k) != actual.get(*k))
            .take(3)
            .map(|k| {
                format!(
                    "{k:?}: required {}, observed {}",
                    expected.get(k).unwrap_or(&0),
                    actual.get(k).unwrap_or(&0)
                )
            })
            .collect();
        return Err(format!(
            "{ERROR}: capture census {}",
            differences.join(", ")
        ));
    }
    // Filtering retains the corresponding original dump instance, including repeated equal sites.
    for ((owner, site, kind), stores) in &observed {
        if kind != "browser.store" {
            continue;
        }
        let dumps = observed
            .get(&(owner.clone(), site.clone(), "browser.dump".into()))
            .ok_or(ERROR)?;
        if stores.len() != dumps.len()
            || stores
                .iter()
                .zip(dumps)
                .any(|(s, d)| s["parent"] != d["source"])
        {
            return Err(ERROR.into());
        }
    }
    let mut occurrences = BTreeMap::new();
    let mut previous = 0;
    for comparison in report["file_comparisons"].as_array().ok_or(ERROR)? {
        let cursor = comparison["history_cursor"].as_u64().ok_or(ERROR)? as usize;
        let checked = comparison["check_cursor"].as_u64().ok_or(ERROR)? as usize;
        let at = comparison["at_ns"].as_u64().ok_or(ERROR)?;
        let check_at = comparison["check_ns"].as_u64().ok_or(ERROR)?;
        let owner = context(states.get(cursor).ok_or(ERROR)?)?;
        let site = comparison["site"].as_str().ok_or(ERROR)?;
        let want = comparisons
            .get_mut(&owner)
            .filter(|v| !v.is_empty())
            .ok_or(ERROR)?
            .remove(0);
        let rule = rules.get(site).ok_or(ERROR)?;
        if site != want
            || comparison.as_object().is_none_or(|m| m.len() != 14)
            || comparison["control_ok"] != true
            || comparison["predicate"] != rule["predicate"]
            || comparison["name_ok"] != true
            || at < previous
            || check_at < at
            || check_at > report["duration_ns"].as_u64().ok_or(ERROR)?
            || checked < cursor
            || context(states.get(checked).ok_or(ERROR)?)? != owner
            || comparison["case"].as_str()
                != if owner.1 == "inside" {
                    Some(owner.2.as_str())
                } else {
                    None
                }
        {
            return Err(ERROR.into());
        }
        let changed = contracts.get(&owner).copied().unwrap_or(false);
        if comparison["result"] != !(rule["policy"] == "contracts" && changed) {
            return Err(ERROR.into());
        }
        let n = occurrences
            .entry((owner.clone(), site.to_owned()))
            .or_insert(0usize);
        let control = if rule["policy"] == "variant" {
            serde_json::json!([null, *n + 1])
        } else {
            serde_json::json!([null, null])
        };
        if comparison["controls"] != control {
            return Err(ERROR.into());
        }
        if comparison["check_instance"] != if rule["predicate"] == "" { 0 } else { *n + 1 } {
            return Err(ERROR.into());
        }
        let mut operands = Vec::new();
        for side in ["left", "right"] {
            let operand = &rule[side];
            let mode = operand[2].as_str().ok_or(ERROR)?;
            let capture_owner = if operand[3] == "before" {
                before(owner.clone(), &execution)?
            } else {
                owner.clone()
            };
            let values = observed
                .get(&(
                    capture_owner,
                    operand[0].as_str().ok_or(ERROR)?.into(),
                    operand[1].as_str().ok_or(ERROR)?.into(),
                ))
                .ok_or(ERROR)?;
            let original = *values
                .get(if mode == "each" { *n } else { 0 })
                .ok_or(ERROR)?;
            if mode == "each" && !rule["predicate"].as_str().ok_or(ERROR)?.is_empty() {
                let predicate = operand
                    .get(4)
                    .and_then(Value::as_str)
                    .unwrap_or(rule["predicate"].as_str().ok_or(ERROR)?);
                checkpoint(report, original, &owner.2, predicate, *n + 1)?;
            }
            let input = &comparison[side];
            let unchanged = if rule["policy"] == "contracts" && side == "left" {
                !changed
            } else if rule["policy"] == "variant" && side == "right" {
                *n == 0
            } else if rule["policy"] == "staging" && side == "left" {
                !owner.2.ends_with(".p002")
            } else {
                true
            };
            if input.as_object().is_none_or(|m| m.len() != 5)
                || input["source"] != original["source"]
                || input["site"] != original["site"]
                || input["kind"] != original["kind"]
                || input["page"] != original["page"]
                || input["ok"] != unchanged
                || original["at_ns"].as_u64().ok_or(ERROR)? > at
            {
                return Err(ERROR.into());
            }
            operands.push(original);
        }
        if rule["policy"] != "contracts" {
            let fresh = if rule["left"][2] == "each" { 0 } else { 1 };
            if operands[1 - fresh]["source"].as_u64() >= operands[fresh]["source"].as_u64() {
                return Err(ERROR.into());
            }
        }
        *n += 1;
        previous = at;
    }
    if comparisons.values().any(|v| !v.is_empty()) {
        return Err(ERROR.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn census_and_consumed_comparison_operands_are_independent() {
        let fixture: Value =
            serde_json::from_str(include_str!("../testdata/file-comparisons.json")).unwrap();
        let base = &fixture["report"];
        let check = |r: &Value| validate_with(r, &fixture["key"], &[]);
        check(base).unwrap();
        let mut early = base.clone();
        early["file_captures"][2]["at_ns"] = json!(6);
        early["file_captures"][3]["at_ns"] = json!(6);
        assert!(check(&early).unwrap_err().contains("checkpoint/window"));
        let mut bad = base.clone();
        bad["file_comparisons"] = json!([]);
        assert!(check(&bad).is_err());
        let mut bad = base.clone();
        bad["file_comparisons"][0]["left"] = bad["file_comparisons"][0]["right"].clone();
        assert!(check(&bad).is_err());
        let mut bad = base.clone();
        bad["file_comparisons"][0]["check_instance"] = json!(2);
        assert!(check(&bad).is_err());
        let mut bad = base.clone();
        bad["file_comparisons"][0]["check_cursor"] = json!(6);
        assert!(check(&bad).is_err());
        let mut bad = base.clone();
        bad["file_captures"].as_array_mut().unwrap().drain(..2);
        bad["file_captures"][0]["source"] = json!(1);
        bad["file_captures"][1]["source"] = json!(2);
        bad["file_captures"][1]["parent"] = json!(1);
        assert!(check(&bad).is_err());
        let mut bad = base.clone();
        bad["file_captures"][0]["site"] = json!("file.seed_cases.dump.005");
        bad["file_captures"][1]["site"] = json!("file.seed_cases.dump.005");
        assert!(check(&bad).is_err());
        check(base).unwrap();
    }
}
