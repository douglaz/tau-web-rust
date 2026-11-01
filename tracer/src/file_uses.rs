//! Actual file installation operands and operation-bracketed observations.
use crate::{completion, history, reader_checks};
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::Mutex};
static PUTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static OPERATIONS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static BINDING: Mutex<Vec<Value>> = Mutex::new(Vec::new());
const ERROR: &str = "original constructor installation/operation window mismatch";

pub type GoalSession = crate::observer::GoalSession;

pub fn put(tab: &crate::Tab, files: &crate::Files, recipe_ok: bool) -> usize {
    let mut puts = PUTS.lock().unwrap();
    let index = puts.len();
    puts.push(json!({"input":files.input(),"provenance":crate::file_inputs::installation(files),"page":history::page_id(&tab.session),"case":history::active_case_id(),"at_ns":completion::now(),"history_cursor":history::cursor(),"end_ns":null,"end_cursor":null,"operation":{"recipe_ok":recipe_ok,"completed":false}}));
    index
}

pub fn put_finished(index: usize, ok: bool) {
    let mut puts = PUTS.lock().unwrap();
    let row = &mut puts[index];
    row["end_ns"] = json!(completion::now());
    row["end_cursor"] = json!(history::cursor());
    row["operation"]["completed"] = json!(ok);
}

pub async fn job_refused(
    run: &crate::Run<'_>,
    worker: &crate::Worker,
    session: &GoalSession,
    job: &str,
) -> Result<bool, String> {
    let start = completion::now();
    let cursor = history::cursor();
    let (identity, page) = history::worker_identity(&worker.session);
    let ordinal = OPERATIONS.lock().unwrap().len();
    let expected = ["digest_secret", "delivery_reboot", "replace_root_label"]
        .get(ordinal)
        .copied();
    let call = json!({"name":"request_harness_job","arguments":{"machine":"fixture","job":job,"arguments":{}}});
    let result = crate::inference_cases::module(
        run,
        worker,
        &format!(
            "return JSON.parse(await m.test_model_tool({},{}));",
            json!(session),
            json!(call.to_string())
        ),
    )
    .await?;
    let refused = result.get("refused").is_some();
    OPERATIONS.lock().unwrap().push(json!({"source":ordinal+1,"site":"goal.harness_job_refusal","page":page,"worker":identity,"case":history::active_case_id(),"start_ns":start,"end_ns":completion::now(),"start_cursor":cursor,"end_cursor":history::cursor(),"ok":expected==Some(job)&&history::selected_worker_matches(page,worker),"refused":refused,"session_source":session.source()}));
    Ok(refused)
}

pub async fn binding_authentication(
    run: &crate::Run<'_>,
    worker: &crate::Worker,
    args: Value,
) -> Result<Value, String> {
    let start = completion::now();
    let cursor = history::cursor();
    let (identity, page) = history::worker_identity(&worker.session);
    let case = history::active_case_id();
    let ordinal = BINDING
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["case"] == json!(case))
        .count();
    let expected = ["fixture", "fixture-other"].get(ordinal).copied();
    let ok = args["machine"].as_str() == expected
        && expected.is_some()
        && args["command"] == "true # bound credential witness"
        && history::selected_worker_matches(page, worker);
    let result = run.harness_run("file_uses.rs#1", worker, args).await?;
    let mut rows = BINDING.lock().unwrap();
    let source = rows.len() + 1;
    rows.push(json!({"source":source,"ordinal":ordinal+1,"page":page,"worker":identity,"case":case,"start_ns":start,"end_ns":completion::now(),"start_cursor":cursor,"end_cursor":history::cursor(),"ok":ok}));
    Ok(result)
}
pub fn snapshot() -> Value {
    json!({"puts":*PUTS.lock().unwrap(),"operations":*OPERATIONS.lock().unwrap(),"binding":*BINDING.lock().unwrap()})
}
pub fn validate(report: &Value) -> Result<(), String> {
    validate_with(report, completion::inventory())
}
fn validate_with(report: &Value, key: &Value) -> Result<(), String> {
    let value = &report["file_uses"];
    if value.as_object().is_none_or(|o| o.len() != 3) {
        return Err(ERROR.into());
    }
    let puts = value["puts"].as_array().ok_or(ERROR)?;
    let states = reader_checks::caller_states(report);
    let pages = history::source_page_states(report)?;
    let workers = history::worker_states(report);
    let events = report["helper_history"].as_array().ok_or(ERROR)?;
    let captures = report["file_captures"].as_array().ok_or(ERROR)?;
    let duration = report["duration_ns"].as_u64().ok_or(ERROR)?;
    let rules = key["file_put_windows"].as_object().ok_or(ERROR)?;
    let mut previous = 0;
    for row in puts {
        let at = row["at_ns"].as_u64().ok_or(ERROR)?;
        let cursor = row["history_cursor"].as_u64().ok_or(ERROR)? as usize;
        let state = states.get(cursor).ok_or(ERROR)?;
        let case = state
            .owner
            .as_ref()
            .filter(|o| o.1 == "inside")
            .map(|o| o.2.as_str());
        let input = &row["input"];
        if row.as_object().is_none_or(|o| o.len() != 9)
            || row["end_cursor"] != row["history_cursor"]
            || row["end_ns"]
                .as_u64()
                .is_none_or(|end| end < at || end > duration)
            || row["operation"] != json!({"recipe_ok":true,"completed":true})
            || row["page"].as_u64().is_none_or(|p| p == 0)
            || row["case"] != json!(case)
            || input.as_object().is_none_or(|o| o.len() != 5)
            || !input["ok"].is_boolean()
            || !input["kind"].is_string()
            || !input["site"].is_string()
            || if input["kind"] == "unbound" {
                input != &json!({"site":"","source":null,"kind":"unbound","page":null,"ok":false})
            } else {
                input["source"].as_u64().is_none_or(|n| n == 0)
                    || input["page"].as_u64().is_none()
                    || !matches!(
                        input["kind"].as_str(),
                        Some("constructor" | "browser.store" | "browser.dump")
                    )
            }
            || at < previous
            || at > duration
            || cursor > 0 && events[cursor - 1]["at_ns"].as_u64().ok_or(ERROR)? > at
            || cursor < events.len() && events[cursor]["at_ns"].as_u64().ok_or(ERROR)? < at
        {
            return Err(ERROR.into());
        }
        previous = at;
    }
    let mut consumed = BTreeSet::new();
    let mut windows = BTreeSet::new();
    for capture in captures.iter().filter(|c| c["kind"] == "constructor") {
        let site = capture["site"].as_str().ok_or(ERROR)?;
        let Some(role) = rules.get(site) else {
            continue;
        };
        let cursor = capture["history_cursor"].as_u64().ok_or(ERROR)? as usize;
        let state = states.get(cursor).ok_or(ERROR)?;
        let owner = state.owner.as_ref().ok_or(ERROR)?;
        let role = if role == "invocation" && state.invocation == 2 {
            "served"
        } else if role == "invocation" {
            "tracer"
        } else {
            role.as_str().ok_or(ERROR)?
        };
        let prepare_page = if role == "prepare" {
            let mut stack = Vec::new();
            for event in &events[..cursor] {
                if event["event"] == "call_start" {
                    stack.push(event);
                } else if event["event"] == "call_end" {
                    stack.pop();
                }
            }
            Some(
                stack
                    .last()
                    .filter(|e| e["kind"] == "binding.prepare")
                    .ok_or(ERROR)?["page"]
                    .as_u64()
                    .ok_or(ERROR)?,
            )
        } else {
            None
        };
        let page = prepare_page
            .as_ref()
            .or_else(|| pages.get(cursor).and_then(|p| p.get(role)))
            .ok_or(ERROR)?;
        let uses: Vec<_> = puts
            .iter()
            .filter(|p| p["input"]["source"] == capture["source"])
            .collect();
        let next = events.get(cursor).ok_or(ERROR)?;
        if uses.len() != 1
            || !windows.insert((site, cursor))
            || next["event"] != "call_start"
            || next["kind"] != "runtime.worker"
            || next["page"] != *page
        {
            return Err(format!("{ERROR}: {site}"));
        }
        let row = uses[0];
        let index = puts
            .iter()
            .position(|p| std::ptr::eq(p, row))
            .ok_or(ERROR)?;
        if !consumed.insert(index) {
            return Err(ERROR.into());
        }
        let operand =
            json!({"site":site,"source":capture["source"],"kind":"constructor","page":0,"ok":true});
        if row["input"] != operand
            || row["history_cursor"] != cursor
            || row["page"] != *page
            || row["case"]
                != json!(if owner.1 == "inside" {
                    Some(owner.2.as_str())
                } else {
                    None
                })
            || row["at_ns"].as_u64().ok_or(ERROR)? < capture["at_ns"].as_u64().ok_or(ERROR)?
            || row["at_ns"].as_u64().ok_or(ERROR)? > next["at_ns"].as_u64().ok_or(ERROR)?
        {
            return Err(format!("{ERROR}: {site}"));
        }
    }
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
    let required = key["file_operation_sources"]["goal.harness_job_refusal"]
        .as_u64()
        .ok_or(ERROR)? as usize;
    let count = if execution.iter().any(|id| {
        id.as_str()
            .is_some_and(|s| s.starts_with("goal_cases.c004."))
    }) {
        required
    } else {
        0
    };
    let operations = value["operations"].as_array().ok_or(ERROR)?;
    if operations.len() != count {
        return Err(ERROR.into());
    }
    previous = 0;
    for (index, operation) in operations.iter().enumerate() {
        let start = operation["start_ns"].as_u64().ok_or(ERROR)?;
        let end = operation["end_ns"].as_u64().ok_or(ERROR)?;
        let cursor = operation["start_cursor"].as_u64().ok_or(ERROR)? as usize;
        let page = pages
            .get(cursor)
            .and_then(|p| p.get("tracer"))
            .ok_or(ERROR)?;
        if operation.as_object().is_none_or(|o| o.len() != 12)
            || operation["source"] != index + 1
            || operation["session_source"] != saved_goal_session(report, &states)?
            || operation["site"] != "goal.harness_job_refusal"
            || operation["case"] != "goal_cases.c004.p001"
            || operation["page"] != *page
            || operation["worker"] != json!(workers.get(cursor).and_then(|p| p.get(page)))
            || operation["ok"] != true
            || operation["refused"] != true
            || operation["end_cursor"] != cursor
            || start < previous
            || end < start
            || end > duration
            || cursor > 0 && events[cursor - 1]["at_ns"].as_u64().ok_or(ERROR)? > start
            || cursor < events.len() && events[cursor]["at_ns"].as_u64().ok_or(ERROR)? < end
        {
            return Err(ERROR.into());
        }
        let comparison = report["file_comparisons"]
            .as_array()
            .ok_or(ERROR)?
            .iter()
            .find(|c| c["site"] == "goal_cases.a036.1" && c["check_instance"] == index + 1)
            .ok_or(ERROR)?;
        let capture = |side: &str| -> Result<&Value, String> {
            let source = comparison[side]["source"].as_u64().ok_or(ERROR)? as usize;
            captures
                .get(source.checked_sub(1).ok_or(ERROR)?)
                .ok_or_else(|| ERROR.into())
        };
        let before = capture("right")?;
        let after = capture("left")?;
        let parent = after["parent"].as_u64().ok_or(ERROR)? as usize;
        let dump = captures
            .get(parent.checked_sub(1).ok_or(ERROR)?)
            .ok_or(ERROR)?;
        if before["at_ns"].as_u64().ok_or(ERROR)? > start
            || crate::operation_windows::dump_start(report, dump)? < end
            || comparison["at_ns"].as_u64().ok_or(ERROR)? < after["at_ns"].as_u64().ok_or(ERROR)?
            || [before, after, dump]
                .iter()
                .any(|c| c["history_cursor"] != cursor || c["page"] != *page)
            || comparison["history_cursor"] != cursor
            || comparison["case"] != operation["case"]
        {
            return Err(ERROR.into());
        }
        previous = end;
    }
    let mut expected = Vec::new();
    for case in key["cases"]
        .as_array()
        .ok_or(ERROR)?
        .iter()
        .filter(|c| c["site_id"] == "binding_cases.c002" && execution.contains(&c["id"]))
    {
        let invocation = case["invocation"].as_u64().ok_or(ERROR)? as usize;
        let count = key["file_operation_sources"]["binding.authentication"]
            .get(invocation.checked_sub(1).ok_or(ERROR)?)
            .and_then(Value::as_u64)
            .ok_or(ERROR)? as usize;
        for ordinal in 1..=count {
            expected.push((case, ordinal));
        }
    }
    let rows = value["binding"].as_array().ok_or(ERROR)?;
    if rows.len() != expected.len() {
        return Err(ERROR.into());
    }
    previous = 0;
    for (index, (row, (case, ordinal))) in rows.iter().zip(expected).enumerate() {
        let start = row["start_ns"].as_u64().ok_or(ERROR)?;
        let end = row["end_ns"].as_u64().ok_or(ERROR)?;
        let cursor = row["start_cursor"].as_u64().ok_or(ERROR)? as usize;
        let role = if case["invocation"] == 2 {
            "served"
        } else {
            "tracer"
        };
        let page = pages.get(cursor).and_then(|p| p.get(role)).ok_or(ERROR)?;
        if row.as_object().is_none_or(|o| o.len() != 10)
            || row["source"] != index + 1
            || row["ordinal"] != ordinal
            || row["case"] != case["id"]
            || row["page"] != *page
            || row["worker"] != json!(workers.get(cursor).and_then(|p| p.get(page)))
            || row["ok"] != true
            || row["end_cursor"] != cursor
            || start < previous
            || end < start
            || end > duration
            || cursor > 0 && events[cursor - 1]["at_ns"].as_u64().ok_or(ERROR)? > start
            || cursor < events.len() && events[cursor]["at_ns"].as_u64().ok_or(ERROR)? < end
        {
            return Err(ERROR.into());
        }
        if role == "tracer" {
            for site in [
                "reader.call.binding.authentication_index",
                "reader.call.binding.authentication_journal",
            ] {
                let read = report["reader_roots"]
                    .as_array()
                    .ok_or(ERROR)?
                    .iter()
                    .filter(|r| {
                        r["site"] == site
                            && r["history_cursor"]
                                .as_u64()
                                .and_then(|c| states.get(c as usize))
                                .and_then(|s| s.owner.as_ref())
                                .is_some_and(|o| o.2 == case["id"].as_str().unwrap())
                    })
                    .nth(ordinal - 1)
                    .ok_or(ERROR)?;
                let source = read["file_input"]["source"].as_u64().ok_or(ERROR)? as usize;
                let capture = captures
                    .get(source.checked_sub(1).ok_or(ERROR)?)
                    .ok_or(ERROR)?;
                let parent = capture["parent"].as_u64().ok_or(ERROR)? as usize;
                let dump = captures
                    .get(parent.checked_sub(1).ok_or(ERROR)?)
                    .ok_or(ERROR)?;
                let check = report["primary_history"]
                    .as_array()
                    .ok_or(ERROR)?
                    .iter()
                    .find(|p| {
                        p["case"] == case["id"]
                            && p["id"] == format!("binding_cases.a007.i{ordinal:03}")
                    })
                    .ok_or(ERROR)?;
                let read_cursor =
                    cursor + usize::from(site == "reader.call.binding.authentication_journal");
                let identity = events.get(cursor).ok_or(ERROR)?;
                if identity["event"] != "check"
                    || identity["id"] != "binding.machine_identity.schema"
                    || crate::operation_windows::dump_start(report, dump)? < end
                    || read["end_ns"].as_u64().ok_or(ERROR)?
                        > check["at_ns"].as_u64().ok_or(ERROR)?
                    || [dump, capture]
                        .iter()
                        .any(|c| c["history_cursor"] != read_cursor || c["page"] != *page)
                    || read["history_cursor"] != read_cursor
                    || check["history_cursor"] != cursor + 1
                {
                    return Err(ERROR.into());
                }
            }
        }
        previous = end;
    }
    crate::file_installations::validate(report, key, &mut consumed)?;
    Ok(())
}

fn saved_goal_session(
    report: &Value,
    states: &[reader_checks::CallerState],
) -> Result<usize, String> {
    let first = report["cases"]
        .as_array()
        .ok_or(ERROR)?
        .iter()
        .find(|c| c["id"] == "goal_cases.c001.p001")
        .ok_or(ERROR)?;
    let before = first["start_ns"].as_u64().ok_or(ERROR)?;
    let queries: Vec<_> = report["goal_session_inputs"]
        .as_array()
        .ok_or(ERROR)?
        .iter()
        .enumerate()
        .filter(|(_, row)| {
            row["end_ns"].as_u64().is_some_and(|t| t <= before)
                && row["end_cursor"]
                    .as_u64()
                    .and_then(|c| states.get(c as usize))
                    .and_then(|s| s.owner.as_ref())
                    .is_some_and(|o| o.0 == "goal_cases.run" && o.1 == "after")
        })
        .collect();
    if queries.len() != 1
        || queries[0].1["present"] != true
        || queries[0].1["receiver_ok"] != true
        || !queries[0].1["document"].is_null()
    {
        return Err(ERROR.into());
    }
    Ok(queries[0].0 + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn operation_inputs_and_before_after_observations() {
        for (text, controls) in [
            (
                include_str!("../testdata/file-operation-windows.json"),
                vec![
                    ("/file_uses/operations/0/session_source", json!(1)),
                    ("/file_uses/operations/0/end_ns", json!(23)),
                    ("/file_captures/1/at_ns", json!(21)),
                    ("/file_uses/operations/0/refused", json!(false)),
                    ("/file_uses/operations/0/worker", json!(4)),
                ],
            ),
            (
                include_str!("../testdata/binding-operation-windows.json"),
                vec![
                    ("/file_uses/binding/0/end_ns", json!(14)),
                    ("/reader_roots/0/file_input/source", json!(4)),
                    ("/file_uses/binding/1/start_cursor", json!(5)),
                    ("/file_uses/binding/0/worker", json!(4)),
                    ("/file_uses/binding/0/ok", json!(false)),
                ],
            ),
        ] {
            let fixture: Value = serde_json::from_str(text).unwrap();
            let report = &fixture["report"];
            let key = &fixture["inventory"];
            validate_with(report, key).unwrap();
            for (pointer, value) in controls {
                let mut bad = report.clone();
                *bad.pointer_mut(pointer).unwrap() = value;
                assert!(validate_with(&bad, key).is_err(), "{pointer}");
            }
            validate_with(report, key).unwrap();
        }
    }
    #[test]
    fn repeated_constructor_outputs_keep_their_own_installation_window() {
        let fixture: Value =
            serde_json::from_str(include_str!("../testdata/file-uses.json")).unwrap();
        let report = &fixture["report"];
        let key = &fixture["inventory"];
        validate_with(report, key).unwrap();
        for (pointer, value) in [
            ("/file_captures/1/history_cursor", json!(4)),
            ("/file_uses/puts/1/input/source", json!(1)),
            ("/file_uses/puts/1/input/ok", json!(false)),
            ("/file_uses/puts/1/page", json!(8)),
            ("/file_uses/puts/1/at_ns", json!(13)),
        ] {
            let mut bad = report.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(validate_with(&bad, key).is_err(), "{pointer}");
        }
        let mut extra = report.clone();
        let mut row = extra["file_uses"]["puts"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        row["page"] = json!(999);
        row["input"] = json!({"site":"","source":null,"kind":"unbound","page":null,"ok":false});
        extra["file_uses"]["puts"].as_array_mut().unwrap().push(row);
        assert!(
            validate_with(&extra, key)
                .unwrap_err()
                .contains("unmatched installation")
        );
        let mut moved = report.clone();
        moved["file_captures"][1]["history_cursor"] = json!(4);
        moved["file_captures"][1]["at_ns"] = json!(5);
        moved["file_uses"]["puts"][1]["history_cursor"] = json!(4);
        moved["file_uses"]["puts"][1]["at_ns"] = json!(6);
        assert!(validate_with(&moved, key).is_err());
        let mut missing = report.clone();
        missing["file_uses"]["puts"].as_array_mut().unwrap().pop();
        assert!(validate_with(&missing, key).is_err());
        validate_with(report, key).unwrap();
    }
}
