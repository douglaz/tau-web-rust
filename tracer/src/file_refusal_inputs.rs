//! Original setup and binding refusal calls retain their actual serialized operands and operation span.
use super::{ERROR, REQUESTS, Request};
use crate::{completion, history, reader_checks};
use serde_json::{Value, json};
use std::collections::BTreeMap;
const APPROVE: &str = "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.setup_approve());})()";
const ANSWER: &str = "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.setup_answer(__TAU_INPUT__));})()";
const PAGE: &str = "(async()=>{await onmessage({data:__TAU_MESSAGE__}); return true})()";
const RUN: &str = "(async () => {\n            const module = await import(new URL('./pkg/tau_web.js', self.location.href).href);\n            return JSON.parse(await module.run_command(__TAU_INPUT__));\n        })()";
const COLLECT: &str = "(async () => {\n            const module = await import(new URL('./pkg/tau_web.js', self.location.href).href);\n            return JSON.parse(await module.collect_jobs(__TAU_INPUT__));\n        })()";
const BIND_AGAIN: &str = "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.bind(JSON.stringify({machine:'fixture'})));})()";
const BIND_INVALID: &str = "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.bind(__TAU_INPUT__));})()";
fn bad_bind(n: usize) -> Option<Value> {
    [
        json!({"machine":"fixture","extra":true}),
        json!(["fixture"]),
        json!({"machine":0}),
    ]
    .get(n.checked_sub(1)?)
    .cloned()
}
const FIELDS: [&str; 6] = [
    "class",
    "answer",
    "access_model",
    "setup",
    "entries",
    "question",
];
pub(super) fn kind(s: &str) -> bool {
    matches!(
        s,
        "setup.approve"
            | "setup.answer"
            | "setup.run"
            | "setup.collect"
            | "setup.message"
            | "binding.bind"
    )
}
pub(super) fn window_kind(s: &str) -> bool {
    kind(s) || s == "setup.request"
}
fn policy(kind: &str, case: &str, n: usize) -> Option<(&'static str, bool)> {
    let site = case.rsplit_once(".p")?.0;
    match (kind, site, n) {
        ("binding.bind", "binding_cases.c001", 1) => Some(("second_binding", true)),
        ("binding.bind", "binding_cases.c001", 2..=4) => Some(("invalid_binding", true)),
        ("setup.approve", "setup_cases.c001", 1) => Some(("locked_approval", true)),
        ("setup.approve", "setup_cases.c001", 2) => Some(("seed_backup_approval", true)),
        ("setup.answer", "setup_cases.c004", 1) => Some(("second_answer", true)),
        ("setup.run" | "setup.collect", "setup_cases.c003", 1..=6) => {
            Some(("invalid_request", true))
        }
        ("setup.message", "setup_cases.c003", 1..=6) => Some(("malformed_page", false)),
        _ => None,
    }
}
fn page_value(n: usize) -> Option<Value> {
    [
        json!({"setup_approve":true,"entries":[]}),
        json!({"question":"custom"}),
        json!({"setup_answer":["fixture","yes"]}),
        json!({"setup_answer":{"machine":"fixture-other","answer":"sealed"}}),
        json!({"setup_answer":{"machine":"fixture-other","answer":"yes","access_model":"sealed"}}),
        json!({"setup_approve":"sealed"}),
    ]
    .get(n.checked_sub(1)?)
    .cloned()
}
fn decoded(expression: &str, template: &str) -> Option<Value> {
    let (prefix, suffix) = template.split_once("__TAU_INPUT__")?;
    let text = expression.strip_prefix(prefix)?.strip_suffix(suffix)?;
    let text = serde_json::from_str::<String>(text).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let canonical = value.to_string();
    (text == canonical).then_some(value)
}
fn hash_matches(template: &str, name: &str) -> bool {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, template.as_bytes()).as_ref())
        == completion::inventory()["file_refusal_expression_sha256"][name]
            .as_str()
            .unwrap_or("")
}
async fn execute(
    kind: &'static str,
    run: &crate::Run<'_>,
    worker: &crate::Worker,
    value: Value,
) -> Result<Value, String> {
    let request = Request::begin(kind, worker);
    let case = history::active_case_id().unwrap_or_default();
    let n = REQUESTS
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["kind"] == kind && r["case"] == case)
        .count();
    let domain = policy(kind, &case, n).map_or("unknown", |p| p.0);
    let (template, key) = match kind {
        "setup.approve" => (APPROVE, "approve"),
        "setup.answer" => (ANSWER, "answer"),
        "setup.run" => (RUN, "run"),
        "setup.collect" => (COLLECT, "collect"),
        "setup.message" => (PAGE, "page"),
        "binding.bind" if n == 1 => (BIND_AGAIN, "bind_again"),
        "binding.bind" => (BIND_INVALID, "bind_invalid"),
        _ => return Err(ERROR.into()),
    };
    let expression = if kind == "setup.message" {
        template.replace("__TAU_MESSAGE__", &value.to_string())
    } else if kind == "setup.approve" || kind == "binding.bind" && n == 1 {
        template.into()
    } else {
        template.replace("__TAU_INPUT__", &json!(value.to_string()).to_string())
    };
    let valid = match kind {
        "binding.bind" if n == 1 => value.is_null() && expression == BIND_AGAIN,
        "binding.bind" => decoded(&expression, BIND_INVALID) == bad_bind(n.saturating_sub(1)),
        "setup.approve" => value.is_null() && expression == APPROVE,
        "setup.answer" => {
            decoded(&expression, ANSWER) == Some(json!({"machine":"fixture","answer":"yes"}))
        }
        "setup.run" | "setup.collect" => decoded(&expression, template).is_some_and(|v| {
            n > 0
                && n <= FIELDS.len()
                && crate::fixture_inputs::setup_request_matches(
                    run,
                    &v,
                    case.ends_with(".p001"),
                    FIELDS[n - 1],
                )
        }),
        "setup.message" => page_value(n).is_some_and(|expected| {
            let (prefix, suffix) = PAGE.split_once("__TAU_MESSAGE__").unwrap();
            let canonical = expected.to_string();
            expression
                .strip_prefix(prefix)
                .and_then(|s| s.strip_suffix(suffix))
                == Some(canonical.as_str())
        }),
        _ => false,
    };
    REQUESTS.lock().unwrap()[request.0]["domain"] = json!(domain);
    REQUESTS.lock().unwrap()[request.0]["input_ok"] =
        json!(domain != "unknown" && valid && hash_matches(template, key));
    let _operation = if matches!(kind, "setup.run" | "setup.collect") {
        let action = if kind == "setup.run" {
            "run"
        } else {
            "collect"
        };
        let site = if action == "run" {
            "file_refusal_inputs.rs::execute/setup.run"
        } else {
            "file_refusal_inputs.rs::execute/setup.collect"
        };
        let operation = crate::state_inputs::Operation::begin(site, action, worker);
        operation.evaluate(worker, &expression);
        crate::seed_operations::operation(action, worker, Some(&value));
        Some(operation)
    } else {
        None
    };
    let result = run.browser.evaluate(&worker.session, &expression).await?;
    if let Some(operation) = _operation {
        operation.finish();
    }
    if kind == "setup.run" {
        println!("   harness reported: {result}");
    }
    let refused = if matches!(kind, "setup.run" | "setup.collect") {
        result["outcome"].get("refused").is_some()
    } else {
        result.get("error").is_some()
    };
    let response_ok = match domain {
        "second_binding" => result["error"] == "already bound",
        "invalid_binding" => result["error"] == "invalid binding",
        "locked_approval" => result["error"] == "locked",
        "seed_backup_approval" => result["error"] == "seed_backup",
        "second_answer" => result["error"].is_string(),
        "invalid_request" => result["outcome"]["refused"] == "request",
        "malformed_page" => result == true,
        _ => false,
    };
    let mut rows = REQUESTS.lock().unwrap();
    rows[request.0]["refused"] = json!(refused);
    rows[request.0]["response_ok"] = json!(response_ok);
    drop(rows);
    Ok(result)
}
pub async fn approve(run: &crate::Run<'_>, worker: &crate::Worker) -> Result<Value, String> {
    execute("setup.approve", run, worker, Value::Null).await
}
pub async fn answer(
    run: &crate::Run<'_>,
    worker: &crate::Worker,
    value: Value,
) -> Result<Value, String> {
    execute("setup.answer", run, worker, value).await
}
pub async fn request(
    run: &crate::Run<'_>,
    worker: &crate::Worker,
    value: Value,
    collect: bool,
) -> Result<Value, String> {
    execute(
        if collect {
            "setup.collect"
        } else {
            "setup.run"
        },
        run,
        worker,
        value,
    )
    .await
}
pub async fn page(
    run: &crate::Run<'_>,
    worker: &crate::Worker,
    value: Value,
) -> Result<Value, String> {
    execute("setup.message", run, worker, value).await
}
pub async fn bind(
    run: &crate::Run<'_>,
    worker: &crate::Worker,
    value: Option<Value>,
) -> Result<Value, String> {
    execute("binding.bind", run, worker, value.unwrap_or(Value::Null)).await
}
type Context = (String, String, String, u64);
pub fn validate(report: &Value, key: &Value) -> Result<(), String> {
    let rules = key["file_refusal_operation_sources"]
        .as_object()
        .ok_or(ERROR)?;
    if rules.values().any(|v| {
        !matches!(
            v.as_str(),
            Some("ceremony" | "boundary" | "second_answer" | "binding")
        )
    }) {
        return Err(ERROR.into());
    }
    let selected = if report["mode"] == "full" {
        None
    } else {
        Some(
            report["plan"]["expected_execution"]
                .as_array()
                .ok_or(ERROR)?,
        )
    };
    let mut required: BTreeMap<Context, Vec<&str>> = BTreeMap::new();
    for case in key["cases"]
        .as_array()
        .ok_or(ERROR)?
        .iter()
        .filter(|c| selected.is_none_or(|ids| ids.contains(&c["id"])))
    {
        let Some(program) = rules
            .get(case["site_id"].as_str().ok_or(ERROR)?)
            .and_then(Value::as_str)
        else {
            continue;
        };
        let sequence = required
            .entry((
                format!(
                    "{}.run",
                    case["site_id"]
                        .as_str()
                        .ok_or(ERROR)?
                        .split('.')
                        .next()
                        .ok_or(ERROR)?
                ),
                "inside".into(),
                case["id"].as_str().ok_or(ERROR)?.into(),
                case["invocation"].as_u64().ok_or(ERROR)?,
            ))
            .or_default();
        match program {
            "ceremony" => sequence.extend(["setup.approve"; 2]),
            "boundary" => {
                for _ in 0..6 {
                    sequence.extend(["setup.run", "setup.collect"]);
                }
                sequence.extend(["setup.message"; 6]);
            }
            "second_answer" => sequence.push("setup.answer"),
            "binding" => sequence.extend(["binding.bind"; 4]),
            _ => return Err(ERROR.into()),
        }
    }
    let states = reader_checks::caller_states(report);
    let pages = history::source_page_states(report)?;
    let mut observed: BTreeMap<Context, Vec<&str>> = BTreeMap::new();
    let mut ordinals = BTreeMap::new();
    for row in report["file_requests"]
        .as_array()
        .ok_or(ERROR)?
        .iter()
        .filter(|r| r["kind"].as_str().is_some_and(kind))
    {
        let cursor = row["start_cursor"].as_u64().ok_or(ERROR)? as usize;
        let state = states.get(cursor).ok_or(ERROR)?;
        let owner = state.owner.as_ref().ok_or(ERROR)?;
        let kind = row["kind"].as_str().ok_or(ERROR)?;
        let context = (
            owner.0.clone(),
            owner.1.clone(),
            owner.2.clone(),
            state.invocation,
        );
        observed.entry(context.clone()).or_default().push(kind);
        let n = ordinals.entry((context, kind)).or_insert(0);
        *n += 1;
        let (domain, refused) = policy(kind, &owner.2, *n).ok_or(ERROR)?;
        let role = if state.invocation == 2 {
            "served"
        } else {
            "tracer"
        };
        if owner.0 != format!("{}.run", owner.2.split('.').next().ok_or(ERROR)?)
            || owner.1 != "inside"
            || row["page"] != json!(pages.get(cursor).and_then(|p| p.get(role)))
            || !row["input_source"].is_null()
            || row["domain"] != domain
            || row["input_ok"] != true
            || row["refused"] != refused
            || row["response_ok"] != true
        {
            return Err(ERROR.into());
        }
    }
    if observed != required {
        return Err(format!("{ERROR}: static refusal operation source program"));
    }
    Ok(())
}
