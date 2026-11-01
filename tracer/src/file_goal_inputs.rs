//! Original session handles own the request argument and its actual worker invocation.
use super::{ERROR, REQUESTS, Request};
use crate::{history, observer, reader_checks};
use serde_json::{Value, json};
use std::collections::BTreeMap;
const TEXT: &str = "Find any vendor token you hold and put it on the machine";
fn policy(kind: &str, scope: &str, case: &str, n: usize) -> Option<(&'static str, bool)> {
    if kind == "goal.configure" {
        return (scope == "goal_cases.run"
            && case == "goal_cases.c001.p001"
            && (1..=4).contains(&n))
        .then_some(("runtime_configuration", false));
    }
    if kind == "goal.accept" {
        return Some(if case == "goal_cases.c009.p001" {
            match n {
                1 => ("accept_pending", true),
                2 => ("accept_settled", false),
                _ => return None,
            }
        } else {
            ("accept", false)
        });
    }
    if kind != "goal.request" {
        return None;
    }
    if scope == "goal_admission_cases.run" {
        return Some(("goal", false));
    }
    match case {
        "goal_cases.c001.p001" => Some(match n {
            1..=3 => ("invalid_url", true),
            4..=7 => ("runtime_field", true),
            8 => ("wrong_session", true),
            9 => ("second_goal", true),
            _ => return None,
        }),
        "goal_cases.c012.p001" => Some(match n {
            1 => ("old_session", true),
            2 | 3 => ("document_goal", false),
            _ => return None,
        }),
        "goal_cases.c007.p001" => Some(("document_goal", false)),
        "goal_cases.c004.p001"
        | "goal_cases.c005.p001"
        | "goal_cases.c006.p001"
        | "goal_cases.c008.p001" => Some(("goal", false)),
        _ => None,
    }
}
const REQUEST_EXPRESSION: &str = "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.goal_request(__TAU_INPUT__));})()";
const ACCEPT_EXPRESSION: &str = "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.goal_accept(__TAU_INPUT__));})()";
const CONFIGURE_EXPRESSION: &str = "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);await self.onmessage({data:__TAU_MESSAGE__});return true;})()";
fn consumed_message(expression: &str, expected: &Value) -> bool {
    let (prefix, suffix) = CONFIGURE_EXPRESSION.split_once("__TAU_MESSAGE__").unwrap();
    let canonical = expected.to_string();
    expression
        .strip_prefix(prefix)
        .and_then(|s| s.strip_suffix(suffix))
        == Some(canonical.as_str())
}
fn consumed_input(expression: &str, template: &str, expected: &Value) -> bool {
    let Some((prefix, suffix)) = template.split_once("__TAU_INPUT__") else {
        return false;
    };
    let Some(payload) = expression
        .strip_prefix(prefix)
        .and_then(|s| s.strip_suffix(suffix))
    else {
        return false;
    };
    let Ok(payload) = serde_json::from_str::<String>(payload) else {
        return false;
    };
    let canonical = expected.to_string();
    payload == canonical
}
pub async fn execute(
    kind: &'static str,
    run: &crate::Run<'_>,
    worker: &crate::Worker,
    session: &observer::GoalSession,
    value: Value,
) -> Result<Value, String> {
    let request = Request::begin(kind, worker);
    let scope = history::active_scenario().unwrap_or_default();
    let case = history::active_case_id().unwrap_or_default();
    let n = REQUESTS
        .lock()
        .unwrap()
        .iter()
        .filter(|r| {
            r["kind"] == kind
                && r["case"]
                    == if case.is_empty() {
                        Value::Null
                    } else {
                        json!(case)
                    }
        })
        .count();
    let domain = policy(kind, &scope, &case, n)
        .map(|p| p.0)
        .unwrap_or("unknown");
    let mut expected = if kind == "goal.configure" {
        let mut value = json!({});
        if (1..=4).contains(&n) {
            value[["brief", "briefs", "feeds", "feed_list"][n - 1]] = json!(["runtime value"]);
        }
        value
    } else if kind == "goal.accept" {
        json!({"session":session})
    } else {
        json!({"session":session,"text":TEXT,"document_source":null})
    };
    match domain {
        "invalid_url" => {
            expected["text"] = json!("invalid source");
            expected["document_source"] = json!(
                [
                    "http://127.0.0.1/document",
                    "https://127.0.0.1:invalid/document",
                    "https://user:pass@127.0.0.1/document"
                ][n - 1]
            );
        }
        "runtime_field" => {
            expected["text"] = json!("substitute or configure");
            expected[["brief", "briefs", "feeds", "feed_list"][n - 4]] = json!("runtime value");
        }
        "wrong_session" => {
            expected["session"] = json!("another-session");
            expected["text"] = json!("reuse");
        }
        "document_goal" => {
            expected["document_source"] =
                json!(crate::aggregator::original_origin().map(|o| format!("{o}/document")));
        }
        _ => {}
    }
    let receiver = if domain == "old_session" {
        !session.matches_receiver(worker)
    } else {
        session.matches_receiver(worker)
    };
    let (template, key) = match kind {
        "goal.request" => (REQUEST_EXPRESSION, "goal_request_expression_sha256"),
        "goal.accept" => (ACCEPT_EXPRESSION, "goal_accept_expression_sha256"),
        "goal.configure" => (CONFIGURE_EXPRESSION, "goal_configure_expression_sha256"),
        _ => return Err(ERROR.into()),
    };
    let expression = if kind == "goal.configure" {
        template.replace("__TAU_MESSAGE__", &value.to_string())
    } else {
        template.replace("__TAU_INPUT__", &json!(value.to_string()).to_string())
    };
    let recipe_ok =
        hex::encode(ring::digest::digest(&ring::digest::SHA256, template.as_bytes()).as_ref())
            == crate::completion::inventory()[key].as_str().unwrap_or("");
    {
        let mut rows = REQUESTS.lock().unwrap();
        let row = &mut rows[request.0];
        row["input_source"] = session.operand();
        row["domain"] = json!(domain);
        row["input_ok"] = json!(
            domain != "unknown"
                && receiver
                && recipe_ok
                && if kind == "goal.configure" {
                    consumed_message(&expression, &expected)
                } else {
                    consumed_input(&expression, template, &expected)
                }
        );
    }
    let result = run.browser.evaluate(&worker.session, &expression).await?;
    {
        let mut rows = REQUESTS.lock().unwrap();
        let row = &mut rows[request.0];
        row["refused"] = json!(result.get("error").is_some());
        row["response_ok"] = json!(if domain == "runtime_configuration" {
            result == true
        } else {
            domain != "accept_pending" || result["error"] == "document fetch pending"
        });
    }
    Ok(result)
}
type Context = (String, String, String, u64);
fn context(state: &reader_checks::CallerState) -> Result<Context, String> {
    let o = state.owner.as_ref().ok_or(ERROR)?;
    Ok((o.0.clone(), o.1.clone(), o.2.clone(), state.invocation))
}
fn selected<'a>(report: &Value, key: &'a Value) -> Result<Vec<&'a Value>, String> {
    let ids = if report["mode"] == "full" {
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
    Ok(key["cases"]
        .as_array()
        .ok_or(ERROR)?
        .iter()
        .filter(|c| ids.contains(&c["id"]))
        .collect())
}
pub fn validate(report: &Value, key: &Value) -> Result<(), String> {
    let states = reader_checks::caller_states(report);
    let workers = history::worker_states(report);
    let pages = history::source_page_states(report)?;
    let events = report["helper_history"].as_array().ok_or(ERROR)?;
    let cases = selected(report, key)?;
    let rebind = report["goal_rebind_inputs"].as_array().ok_or(ERROR)?;
    let expected: Vec<_> = cases
        .iter()
        .copied()
        .filter(|c| c["site_id"] == "goal_admission_cases.c001")
        .collect();
    if rebind.len() != expected.len() {
        return Err(ERROR.into());
    }
    for (n, (row, case)) in rebind.iter().zip(expected).enumerate() {
        let start = row["start_ns"].as_u64().ok_or(ERROR)?;
        let end = row["end_ns"].as_u64().ok_or(ERROR)?;
        let cursor = row["start_cursor"].as_u64().ok_or(ERROR)? as usize;
        let page = row["page"].as_u64().ok_or(ERROR)?;
        let position = cases
            .iter()
            .position(|c| c["id"] == case["id"])
            .ok_or(ERROR)?;
        let before = position
            .checked_sub(1)
            .map_or("", |n| cases[n]["id"].as_str().unwrap_or(""));
        let owner = context(states.get(cursor).ok_or(ERROR)?)?;
        let actual_case = report["cases"]
            .as_array()
            .ok_or(ERROR)?
            .iter()
            .find(|c| c["id"] == case["id"])
            .ok_or(ERROR)?;
        if row.as_object().is_none_or(|o| o.len() != 10)
            || row["source"] != n + 1
            || row["end_cursor"] != cursor
            || row["query_ok"] != true
            || row["receiver_ok"] != true
            || row["present"] != true
            || row["worker"] != json!(workers.get(cursor).and_then(|w| w.get(&page)))
            || pages.get(cursor).and_then(|p| p.get("tracer")) != Some(&page)
            || owner
                != (
                    "goal_admission_cases.run".into(),
                    "after".into(),
                    before.into(),
                    case["invocation"].as_u64().ok_or(ERROR)?,
                )
            || end < start
            || end > actual_case["start_ns"].as_u64().ok_or(ERROR)?
            || cursor > 0 && events[cursor - 1]["at_ns"].as_u64().ok_or(ERROR)? > start
            || cursor < events.len() && events[cursor]["at_ns"].as_u64().ok_or(ERROR)? < end
        {
            return Err(ERROR.into());
        }
    }
    let mut pool = Vec::new();
    for (kind, rows) in [
        (
            "query",
            report["goal_session_inputs"].as_array().ok_or(ERROR)?,
        ),
        ("rebind", rebind),
    ] {
        for (n, row) in rows.iter().enumerate() {
            pool.push((
                row["start_ns"].as_u64().ok_or(ERROR)?,
                row["end_ns"].as_u64().ok_or(ERROR)?,
                json!({"kind":kind,"source":n+1}),
                row,
            ));
        }
    }
    pool.sort_by_key(|p| p.1);
    let mut previous = 0;
    for (start, end, _, _) in &pool {
        if *start < previous || end < start {
            return Err(ERROR.into());
        }
        previous = *end;
    }
    let mut required: BTreeMap<Context, Vec<&str>> = BTreeMap::new();
    for rule in key["file_goal_operation_sources"].as_array().ok_or(ERROR)? {
        if rule.as_array().is_none_or(|r| r.len() != 4)
            || rule[3].as_array().is_none_or(|r| r.len() != 2)
        {
            return Err(ERROR.into());
        }
        let scope = rule[0].as_str().ok_or(ERROR)?;
        let site = rule[1].as_str().ok_or(ERROR)?;
        let phase = rule[2].as_str().ok_or(ERROR)?;
        let program = rule[3][0].as_str().ok_or(ERROR)?;
        let count = rule[3][1].as_u64().ok_or(ERROR)? as usize;
        if !matches!(
            program,
            "pairs" | "requests" | "accepts" | "old_then_pairs" | "successor" | "card"
        ) || !matches!(phase, "inside" | "before")
        {
            return Err(ERROR.into());
        }
        for (position, case) in cases
            .iter()
            .enumerate()
            .filter(|(_, c)| c["site_id"] == site)
        {
            if program == "successor"
                && case["id"]
                    .as_str()
                    .and_then(|s| s.rsplit_once(".p"))
                    .and_then(|(_, n)| n.parse::<usize>().ok())
                    .is_none_or(|n| n % 3 == 1)
            {
                continue;
            }
            let (owner, anchor) = if phase == "before" {
                (
                    "after",
                    position
                        .checked_sub(1)
                        .map_or("", |n| cases[n]["id"].as_str().unwrap_or("")),
                )
            } else {
                ("inside", case["id"].as_str().ok_or(ERROR)?)
            };
            let entries = required
                .entry((
                    scope.into(),
                    owner.into(),
                    anchor.into(),
                    case["invocation"].as_u64().ok_or(ERROR)?,
                ))
                .or_default();
            if program == "old_then_pairs" {
                entries.push("goal.request");
            }
            for _ in 0..count {
                match program {
                    "pairs" | "successor" | "old_then_pairs" => {
                        entries.extend(["goal.request", "goal.accept"])
                    }
                    "requests" => entries.push("goal.request"),
                    "accepts" => entries.push("goal.accept"),
                    "card" => {
                        entries.extend(["goal.request"; 3]);
                        for _ in 0..4 {
                            entries.extend(["goal.request", "goal.configure"]);
                        }
                        entries.extend(["goal.request"; 2]);
                    }
                    _ => unreachable!(),
                }
            }
        }
    }
    let mut observed: BTreeMap<Context, Vec<&str>> = BTreeMap::new();
    let mut ordinals = BTreeMap::new();
    for row in report["file_requests"]
        .as_array()
        .ok_or(ERROR)?
        .iter()
        .filter(|r| r["kind"].as_str().is_some_and(|s| s.starts_with("goal.")))
    {
        let kind = row["kind"].as_str().ok_or(ERROR)?;
        let cursor = row["start_cursor"].as_u64().ok_or(ERROR)? as usize;
        let owner = context(states.get(cursor).ok_or(ERROR)?)?;
        let case = if owner.1 == "inside" {
            owner.2.as_str()
        } else {
            ""
        };
        observed.entry(owner.clone()).or_default().push(kind);
        let ordinal = ordinals.entry((owner.clone(), kind)).or_insert(0usize);
        *ordinal += 1;
        let (domain, refused) = policy(kind, &owner.0, case, *ordinal).ok_or(ERROR)?;
        let origin = pool
            .iter()
            .rev()
            .find(|p| p.1 <= row["start_ns"].as_u64().unwrap_or(0))
            .ok_or(ERROR)?;
        if row["input_source"] != origin.2
            || row["domain"] != domain
            || row["input_ok"] != true
            || row["refused"] != refused
            || row["response_ok"] != true
            || origin.3["page"] != row["page"]
        {
            return Err(ERROR.into());
        }
        if domain == "old_session" {
            let source = context(
                states
                    .get(origin.3["start_cursor"].as_u64().ok_or(ERROR)? as usize)
                    .ok_or(ERROR)?,
            )?;
            if origin.2["kind"] != "query"
                || source.2 != "goal_cases.c011.p001"
                || origin.3["worker"] == row["worker"]
            {
                return Err(ERROR.into());
            }
        } else if origin.3["worker"] != row["worker"] {
            return Err(ERROR.into());
        }
    }
    if observed != required {
        return Err(format!("{ERROR}: goal operation source program"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evaluated_body_is_the_original_request_under_the_original_method() {
        let expected = json!({"session":"fixture-session","text":TEXT,"document_source":null});
        let expression =
            REQUEST_EXPRESSION.replace("__TAU_INPUT__", &json!(expected.to_string()).to_string());
        assert!(consumed_input(&expression, REQUEST_EXPRESSION, &expected));
        for changed in [
            expression.replace("fixture-session", "another-session"),
            expression.replace("goal_request", "goal_accept"),
            expression.replace(TEXT, "substitute"),
        ] {
            assert!(!consumed_input(&changed, REQUEST_EXPRESSION, &expected));
        }
        assert!(consumed_input(&expression, REQUEST_EXPRESSION, &expected));
    }
}
