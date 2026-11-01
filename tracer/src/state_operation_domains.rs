//! Independent source-call accounting for original State operations.
use crate::{completion, history, reader_checks};
use serde_json::Value;
use std::collections::BTreeSet;
const ERROR: &str = "original State operation source/instance/operand census mismatch";
pub struct Resolved {
    pub source: String,
    pub case: String,
    pub instance: usize,
    pub index: usize,
}
struct Required<'a> {
    case_index: usize,
    phase: usize,
    anchor_index: usize,
    order: u64,
    instance: usize,
    case: &'a Value,
    rule: &'a Value,
    anchor: String,
}
fn pattern(pattern: &str, id: &str) -> bool {
    pattern
        .strip_suffix('*')
        .map_or(pattern == id, |prefix| id.starts_with(prefix))
}
pub fn validate(report: &Value, key: &Value) -> Result<Vec<Resolved>, String> {
    let rules = key["state_operation_rules"].as_array().ok_or(ERROR)?;
    let execution: Vec<_> = if report["mode"] == "full" {
        key["cases"]
            .as_array()
            .ok_or(ERROR)?
            .iter()
            .map(|c| c["id"].clone())
            .collect()
    } else {
        report["plan"]["expected_execution"]
            .as_array()
            .ok_or(ERROR)?
            .clone()
    };
    let cases = key["cases"].as_array().ok_or(ERROR)?;
    let actual_cases = report["cases"].as_array().ok_or(ERROR)?;
    let mut required = Vec::new();
    for rule in rules {
        if rule.as_array().is_none_or(|r| r.len() != 11)
            || !rule[0].is_string()
            || !rule[1].is_string()
            || !matches!(
                rule[2].as_str(),
                Some("run" | "collect" | "goal.drive" | "goal.turn")
            )
            || !rule[3].is_string()
            || rule[4]
                .as_array()
                .is_none_or(|a| a.is_empty() || a.iter().any(|p| !p.is_string()))
            || !matches!(rule[5].as_str(), Some("inside" | "before_case"))
            || !rule[6].is_string()
            || !(matches!(rule[7].as_str(), Some("all" | "odd" | "even"))
                || rule[7].as_array().is_some_and(|a| {
                    !a.is_empty() && a.iter().all(|n| n.as_u64().is_some_and(|n| n > 0))
                }))
            || !rule[8].is_u64()
            || !matches!(rule[9].as_str(), Some("tracer" | "served" | "invocation"))
            || !rule[10].is_u64()
        {
            return Err(ERROR.into());
        }
        if rule[4].as_array().unwrap().iter().any(|p| {
            !cases
                .iter()
                .any(|c| pattern(p.as_str().unwrap(), c["id"].as_str().unwrap()))
        }) {
            return Err(ERROR.into());
        }
        for (case_index, id) in execution.iter().enumerate() {
            let case = cases.iter().find(|c| c["id"] == *id).ok_or(ERROR)?;
            if !rule[4]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| pattern(p.as_str().unwrap(), id.as_str().unwrap()))
            {
                continue;
            }
            let actual = actual_cases.iter().find(|c| c["id"] == *id).ok_or(ERROR)?;
            let assertions = completion::expected_assertions(case, actual, report)?;
            let mut ordinal = 0;
            let mut matched = 0;
            for (anchor_index, anchor) in assertions.iter().enumerate() {
                if anchor.rsplit_once(".i").map(|(s, _)| s) != rule[6].as_str() {
                    continue;
                }
                ordinal += 1;
                let include = match rule[7].as_str() {
                    Some("all") => true,
                    Some("odd") => ordinal % 2 == 1,
                    Some("even") => ordinal % 2 == 0,
                    _ => rule[7].as_array().unwrap().iter().any(|n| n == ordinal),
                };
                if include {
                    matched += 1;
                    required.push(Required {
                        case_index,
                        phase: usize::from(rule[5] == "inside"),
                        anchor_index,
                        order: rule[8].as_u64().unwrap(),
                        instance: matched,
                        case,
                        rule,
                        anchor: anchor.clone(),
                    });
                }
            }
            if matched == 0 {
                return Err(format!("{ERROR}: missing source anchor {}", rule[0]));
            }
        }
    }
    required.sort_by_key(|r| (r.case_index, r.phase, r.anchor_index, r.order));
    let operations = report["state_inputs"]["operations"]
        .as_array()
        .ok_or(ERROR)?;
    let observed: Vec<_> = operations
        .iter()
        .enumerate()
        .filter(|(_, r)| r["kind"] != "reload")
        .collect();
    if observed.len() != required.len() {
        return Err(format!("{ERROR}: missing/extra non-reload invocation"));
    }
    if key["state_operation_pending"]
        .as_array()
        .is_none_or(|p| !p.is_empty())
        && key["coverage"]["complete"] != false
    {
        return Err(format!("{ERROR}: unresolved operation domain"));
    }
    let states = reader_checks::caller_states(report);
    let pages = history::source_page_states(report)?;
    let primary = report["primary_history"].as_array().ok_or(ERROR)?;
    let mut identities = BTreeSet::new();
    let mut result = Vec::new();
    for ((index, row), want) in observed.into_iter().zip(required) {
        let id = want.case["id"].as_str().ok_or(ERROR)?;
        let cursor = row["start_cursor"].as_u64().ok_or(ERROR)? as usize;
        let end_cursor = row["end_cursor"].as_u64().ok_or(ERROR)? as usize;
        let state = states.get(cursor).ok_or(ERROR)?;
        let owner = state.owner.as_ref().ok_or(ERROR)?;
        let before = want.phase == 0;
        let previous = want
            .case_index
            .checked_sub(1)
            .map(|n| execution[n].as_str().unwrap())
            .unwrap_or("");
        let owner_case = if before { previous } else { id };
        let invocation = want.case["invocation"].as_u64().ok_or(ERROR)?;
        let role = if want.rule[9] == "invocation" {
            if invocation == 2 { "served" } else { "tracer" }
        } else {
            want.rule[9].as_str().unwrap()
        };
        if row["site"] != want.rule[1]
            || row["kind"] != want.rule[2]
            || row["case"]
                != if before {
                    Value::Null
                } else {
                    Value::String(id.into())
                }
            || owner.0 != want.rule[3].as_str().unwrap()
            || owner.1 != if before { "after" } else { "inside" }
            || owner.2 != owner_case
            || state.invocation != invocation
            || states
                .get(end_cursor)
                .is_none_or(|s| s.owner != state.owner || s.invocation != state.invocation)
            || row["page"].as_u64() != pages.get(cursor).and_then(|p| p.get(role)).copied()
            || row["script_items"] != want.rule[10]
            || !identities.insert((
                want.rule[0].as_str().unwrap().to_owned(),
                id.to_owned(),
                want.instance,
            ))
        {
            return Err(format!("{ERROR}: {}", want.rule[0]));
        }
        let (lower, upper) = if before {
            let upper = actual_cases.iter().find(|c| c["id"] == id).ok_or(ERROR)?["start_ns"]
                .as_u64()
                .ok_or(ERROR)?;
            let lower = if previous.is_empty() {
                0
            } else {
                actual_cases
                    .iter()
                    .find(|c| c["id"] == previous)
                    .ok_or(ERROR)?["end_ns"]
                    .as_u64()
                    .ok_or(ERROR)?
            };
            (lower, upper)
        } else {
            let position = primary
                .iter()
                .position(|p| p["case"] == id && p["id"] == want.anchor)
                .ok_or(ERROR)?;
            let lower = if position > 0 && primary[position - 1]["case"] == id {
                primary[position - 1]["at_ns"].as_u64().ok_or(ERROR)?
            } else {
                actual_cases.iter().find(|c| c["id"] == id).ok_or(ERROR)?["start_ns"]
                    .as_u64()
                    .ok_or(ERROR)?
            };
            (lower, primary[position]["at_ns"].as_u64().ok_or(ERROR)?)
        };
        if row["start_ns"].as_u64().is_none_or(|t| t < lower)
            || row["end_ns"].as_u64().is_none_or(|t| t > upper)
        {
            return Err(format!("{ERROR}: source checkpoint {}", want.rule[0]));
        }
        if matches!(row["kind"].as_str(), Some("goal.drive" | "goal.turn")) {
            validate_session(
                report,
                row,
                &want.rule[0],
                want.case_index,
                &execution,
                want.instance,
            )?;
        } else if !row["session"].is_null() {
            return Err(ERROR.into());
        }
        result.push(Resolved {
            source: want.rule[0].as_str().unwrap().into(),
            case: id.into(),
            instance: want.instance,
            index,
        });
    }
    Ok(result)
}
fn validate_session(
    report: &Value,
    row: &Value,
    source: &Value,
    case_index: usize,
    execution: &[Value],
    instance: usize,
) -> Result<(), String> {
    let states = reader_checks::caller_states(report);
    let successor = source == "goal.drive.successor";
    let manual = source == "goal.authority.turn";
    let kind = if successor { "rebind" } else { "query" };
    let captures = report[if successor {
        "goal_rebind_inputs"
    } else {
        "goal_session_inputs"
    }]
    .as_array()
    .ok_or(ERROR)?;
    let target = if manual {
        "goal_cases.c001.p001"
    } else {
        execution[case_index].as_str().ok_or(ERROR)?
    };
    let index = execution.iter().position(|id| id == target).ok_or(ERROR)?;
    let previous = index
        .checked_sub(1)
        .map(|i| execution[i].as_str().unwrap())
        .unwrap_or("");
    let cursor = row["start_cursor"].as_u64().ok_or(ERROR)? as usize;
    let original = states.get(cursor).ok_or(ERROR)?;
    let candidates: Vec<_> = captures
        .iter()
        .enumerate()
        .filter(|(_, capture)| {
            capture["start_cursor"]
                .as_u64()
                .and_then(|n| states.get(n as usize))
                .filter(|s| s.invocation == original.invocation)
                .and_then(|s| s.owner.as_ref())
                .filter(|o| original.owner.as_ref().is_some_and(|p| p.0 == o.0))
                .is_some_and(|o| {
                    if successor || manual {
                        o.1 == "after" && o.2 == previous
                    } else {
                        o.1 == "inside" && o.2 == target
                    }
                })
        })
        .collect();
    let n = if successor || manual { 0 } else { instance - 1 };
    let (capture_index, capture) = candidates.get(n).ok_or(ERROR)?;
    if row["session"] != serde_json::json!({"kind":kind,"source":capture_index+1})
        || capture["page"] != row["page"]
        || capture["worker"] != row["worker"]
        || capture["end_ns"].as_u64().ok_or(ERROR)? > row["start_ns"].as_u64().ok_or(ERROR)?
    {
        return Err(format!("{ERROR}: original goal session"));
    }
    Ok(())
}
