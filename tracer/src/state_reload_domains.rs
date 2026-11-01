//! Original reload leaves attach to the existing independent helper source slots.
use crate::reader_checks;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
const ERROR: &str = "original reload source/helper/receiver correspondence mismatch";
type Owner = (String, String, String, u64);
struct Frame {
    call: u64,
    start: usize,
    kind: String,
    source: Option<String>,
    prepare_reload: bool,
}
pub fn validate(report: &Value, key: &Value) -> Result<(), String> {
    // The outer admission validates this independent key projection before result validation.
    let requirements = if report["mode"] == "full" {
        key
    } else {
        &report["plan"]
    };
    let rows = requirements["invocation_root_sequences"]
        .as_array()
        .ok_or(ERROR)?;
    let events = report["helper_history"].as_array().ok_or(ERROR)?;
    let operations = report["state_inputs"]["operations"]
        .as_array()
        .ok_or(ERROR)?;
    let states = reader_checks::caller_states(report);
    let workers = crate::history::worker_states(report);
    let mut roots = BTreeMap::new();
    let mut expected = 0;
    for row in rows {
        let tokens = row["tokens"].as_array().ok_or(ERROR)?;
        let sources = row["reload_sources"].as_array().ok_or(ERROR)?;
        if sources.len() != tokens.len() {
            return Err(ERROR.into());
        }
        for (token, source) in tokens.iter().zip(sources) {
            if !source.is_null() {
                if token != "call:runtime.worker"
                    || !key["state_reload_sites"]
                        .as_array()
                        .ok_or(ERROR)?
                        .contains(source)
                {
                    return Err(ERROR.into());
                }
                expected += 1;
            }
        }
        for domain in row["prepare_domains"].as_array().ok_or(ERROR)? {
            if domain["active"] == true && domain["contracts"] == true {
                expected += 1;
            }
        }
        let owner = (
            row["scenario"].as_str().ok_or(ERROR)?.into(),
            row["owner"].as_str().ok_or(ERROR)?.into(),
            row["case"].as_str().unwrap_or("").into(),
            row["invocation"].as_u64().ok_or(ERROR)?,
        );
        if roots.insert(owner, row).is_some() {
            return Err(ERROR.into());
        }
    }
    let mut positions: BTreeMap<Owner, usize> = BTreeMap::new();
    let mut prepares: BTreeMap<Owner, usize> = BTreeMap::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut required = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if event["event"] == "call_start" || event["event"] == "check" && stack.is_empty() {
            let mut source = None;
            let mut prepare_reload = false;
            if stack.is_empty() {
                let state = states.get(index).ok_or(ERROR)?;
                let owner = state.owner.as_ref().ok_or(ERROR)?;
                let owner = (
                    owner.0.clone(),
                    owner.1.clone(),
                    owner.2.clone(),
                    state.invocation,
                );
                let row = *roots.get(&owner).ok_or(ERROR)?;
                let position = positions.entry(owner.clone()).or_default();
                let token = if event["event"] == "check" {
                    format!("check:{}", event["id"].as_str().ok_or(ERROR)?)
                } else {
                    format!("call:{}", event["kind"].as_str().ok_or(ERROR)?)
                };
                if row["tokens"].get(*position) != Some(&Value::String(token)) {
                    return Err(ERROR.into());
                }
                source = row["reload_sources"][*position].as_str().map(str::to_owned);
                *position += 1;
                if event["kind"] == "binding.prepare" {
                    let ordinal = prepares.entry(owner).or_default();
                    let domain = row["prepare_domains"].get(*ordinal).ok_or(ERROR)?;
                    *ordinal += 1;
                    prepare_reload = domain["active"] == true && domain["contracts"] == true;
                }
            } else if event["kind"] == "runtime.worker"
                && stack.last().unwrap().kind == "binding.prepare"
            {
                if !stack.last().unwrap().prepare_reload {
                    return Err(ERROR.into());
                }
                source = Some(
                    key["state_prepare_reload_site"]
                        .as_str()
                        .ok_or(ERROR)?
                        .into(),
                );
            }
            if event["event"] == "call_start" {
                stack.push(Frame {
                    call: event["call"].as_u64().ok_or(ERROR)?,
                    start: index,
                    kind: event["kind"].as_str().ok_or(ERROR)?.into(),
                    source,
                    prepare_reload,
                });
            }
        } else if event["event"] == "call_end" {
            let frame = stack.pop().ok_or(ERROR)?;
            if event["call"] != frame.call {
                return Err(ERROR.into());
            }
            if let Some(source) = frame.source {
                if frame.kind != "runtime.worker" {
                    return Err(ERROR.into());
                }
                required.push((source, frame.start, index));
            }
        }
    }
    if !stack.is_empty()
        || required.len() != expected
        || roots.iter().any(|(o, r)| {
            positions.get(o).copied().unwrap_or(0) != r["tokens"].as_array().unwrap().len()
        })
    {
        return Err(ERROR.into());
    }
    let mut consumed = BTreeSet::new();
    for (source, start, end) in required {
        let matching: Vec<_> = operations
            .iter()
            .enumerate()
            .filter(|(_, op)| op["kind"] == "reload" && op["start_cursor"] == start)
            .collect();
        if matching.len() != 1 {
            return Err(format!("{ERROR}: {source}"));
        }
        let (index, op) = matching[0];
        if op["site"] != source
            || op["page"] != events[start]["page"]
            || op["worker"].as_u64()
                != workers[start]
                    .get(&op["page"].as_u64().ok_or(ERROR)?)
                    .copied()
            || op["successor"].as_u64()
                != workers[end + 1]
                    .get(&op["page"].as_u64().ok_or(ERROR)?)
                    .copied()
            || op["end_cursor"] != end + 1
            || op["start_ns"]
                .as_u64()
                .is_none_or(|t| t > events[start]["at_ns"].as_u64().unwrap_or(0))
            || op["end_ns"]
                .as_u64()
                .is_none_or(|t| t < events[end]["at_ns"].as_u64().unwrap_or(u64::MAX))
            || !consumed.insert(index)
        {
            return Err(format!("{ERROR}: {source}"));
        }
        if let Some(kind) = match source.as_str() {
            "declaration_cases.rs::reload#1" => Some("declaration.prepare"),
            "delivery_cases.rs::reload#1" => Some("delivery.prepare"),
            _ => None,
        } {
            let matching = report["observer_calls"]
                .as_array()
                .ok_or(ERROR)?
                .iter()
                .filter(|call| {
                    call["kind"] == kind
                        && call["page"] == op["page"]
                        && call["start_ns"]
                            .as_u64()
                            .is_some_and(|t| t <= op["start_ns"].as_u64().unwrap())
                        && call["end_ns"]
                            .as_u64()
                            .is_some_and(|t| t >= op["end_ns"].as_u64().unwrap())
                })
                .count();
            if matching != 1 {
                return Err(ERROR.into());
            }
        }
        if source == "main.rs::reload#18" {
            let matching = report["settle_inputs"]
                .as_array()
                .ok_or(ERROR)?
                .iter()
                .filter(|input| {
                    input["empty"] == false
                        && input["page"] == op["page"]
                        && input["worker"] == op["worker"]
                        && input["start_ns"]
                            .as_u64()
                            .is_some_and(|t| t <= op["start_ns"].as_u64().unwrap())
                        && input["end_ns"]
                            .as_u64()
                            .is_some_and(|t| t >= op["end_ns"].as_u64().unwrap())
                })
                .count();
            if matching != 1 {
                return Err(ERROR.into());
            }
        }
    }
    if operations
        .iter()
        .enumerate()
        .any(|(n, op)| op["kind"] == "reload" && !consumed.contains(&n))
    {
        return Err(format!("{ERROR}: unmatched reload"));
    }
    for input in report["settle_inputs"].as_array().ok_or(ERROR)? {
        let matching = operations
            .iter()
            .filter(|op| {
                op["kind"] == "reload"
                    && op["site"] == "main.rs::reload#18"
                    && op["start_ns"]
                        .as_u64()
                        .is_some_and(|t| t >= input["start_ns"].as_u64().unwrap_or(u64::MAX))
                    && op["end_ns"]
                        .as_u64()
                        .is_some_and(|t| t <= input["end_ns"].as_u64().unwrap_or(0))
            })
            .count();
        if matching != usize::from(input["empty"] == false) {
            return Err(ERROR.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn each_reload_uses_its_own_required_source_and_helper_interval() {
        let fixture: Value =
            serde_json::from_str(include_str!("../testdata/reload-inputs.json")).unwrap();
        let report = &fixture["report"];
        let key = &fixture["inventory"];
        validate(report, key).unwrap();
        for (path, value) in [
            (
                "/state_inputs/operations/0/site",
                json!("main.rs::reload#2"),
            ),
            ("/state_inputs/operations/0/start_cursor", json!(1)),
            ("/state_inputs/operations/0/end_cursor", json!(9)),
            ("/state_inputs/operations/0/page", json!(2)),
            ("/state_inputs/operations/0/worker", json!(2)),
            ("/state_inputs/operations/0/successor", json!(1)),
        ] {
            let mut bad = report.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(validate(&bad, key).is_err(), "{path}");
            validate(report, key).unwrap();
        }
        let mut missing = report.clone();
        missing["state_inputs"]["operations"] = json!([]);
        assert!(validate(&missing, key).is_err());
        let mut duplicate = report.clone();
        let row = duplicate["state_inputs"]["operations"][0].clone();
        duplicate["state_inputs"]["operations"]
            .as_array_mut()
            .unwrap()
            .push(row);
        assert!(validate(&duplicate, key).is_err());
        let mut direct = report.clone();
        direct["plan"]["invocation_root_sequences"][1]["reload_sources"][0] = Value::Null;
        assert!(validate(&direct, key).is_err());
        validate(report, key).unwrap();
    }
}
