//! Original refusal operations must separate the saved and fresh file observations.
use crate::{completion, history, reader_checks};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

#[path = "file_goal_inputs.rs"]
mod goal_inputs;
#[path = "file_refusal_inputs.rs"]
mod refusal_inputs;
pub use goal_inputs::execute as goal;
pub use refusal_inputs::{
    answer as setup_answer, approve as setup_approve, bind as binding_refusal, page as setup_page,
    request as setup_request,
};

static PENDING: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static REQUESTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
const ERROR: &str = "original file before/operation/after window mismatch";

struct PendingOriginal {
    value: Value,
    source: usize,
    worker: crate::Worker,
}
#[derive(Clone)]
pub struct Pending {
    original: Arc<PendingOriginal>,
    projected: bool,
}
impl Pending {
    pub fn pending(&self) -> Self {
        Self {
            original: self.original.clone(),
            projected: true,
        }
    }
}
impl std::ops::Deref for Pending {
    type Target = Value;
    fn deref(&self) -> &Value {
        if self.projected {
            &self.original.value["sessions"][0]["pending_requirements"]
        } else {
            &self.original.value
        }
    }
}
impl serde::Serialize for Pending {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (**self).serialize(s)
    }
}
pub async fn pending(
    site: &str,
    call: Option<usize>,
    run: &crate::Run<'_>,
    worker: &crate::Worker,
) -> Result<Pending, String> {
    let start = completion::now();
    let cursor = history::cursor();
    crate::seed_operations::operation("inspect", worker, None);
    let value = run
        .browser
        .evaluate(&worker.session, crate::state_inputs::EXPRESSION)
        .await?;
    let query_ok = hex::encode(
        ring::digest::digest(
            &ring::digest::SHA256,
            crate::state_inputs::EXPRESSION.as_bytes(),
        )
        .as_ref(),
    ) == completion::inventory()["state_query_sha256"]
        .as_str()
        .unwrap_or("");
    let (identity, page) = history::worker_identity(&worker.session);
    let mut rows = PENDING.lock().unwrap();
    let source = rows.len() + 1;
    rows.push(json!({"source":source,"site":site,"call":call,"page":page,"worker":identity,"case":history::active_case_id(),"start_ns":start,"end_ns":completion::now(),"start_cursor":cursor,"end_cursor":history::cursor(),"query_ok":query_ok,"receiver_ok":history::selected_worker_matches(page,worker)}));
    Ok(Pending {
        original: Arc::new(PendingOriginal {
            value,
            source,
            worker: worker.clone(),
        }),
        projected: false,
    })
}
pub fn pending_snapshot() -> Value {
    json!(*PENDING.lock().unwrap())
}

const ANSWER_EXPRESSION: &str = "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.requirements_answer(__TAU_INPUT__));})()";
fn consumed_answer(expression: &str) -> Option<Value> {
    let (prefix, suffix) = ANSWER_EXPRESSION.split_once("__TAU_INPUT__")?;
    let payload = expression.strip_prefix(prefix)?.strip_suffix(suffix)?;
    let text = serde_json::from_str::<String>(payload).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let canonical = value.to_string();
    (text == canonical).then_some(value)
}
pub async fn answer(
    run: &crate::Run<'_>,
    worker: &crate::Worker,
    pending: &Pending,
    value: Value,
) -> Result<Value, String> {
    let request = Request::begin("declaration.answer", worker);
    let case = history::active_case_id().unwrap_or_default();
    let ordinal = REQUESTS
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["kind"] == "declaration.answer" && r["case"] == case)
        .count();
    let expression =
        ANSWER_EXPRESSION.replace("__TAU_INPUT__", &json!(value.to_string()).to_string());
    let consumed = consumed_answer(&expression);
    let (domain, valid) = answer_input(
        pending,
        worker,
        &case,
        ordinal,
        consumed.as_ref().unwrap_or(&Value::Null),
    );
    let recipe_ok = hex::encode(
        ring::digest::digest(&ring::digest::SHA256, ANSWER_EXPRESSION.as_bytes()).as_ref(),
    ) == completion::inventory()["declaration_answer_expression_sha256"]
        .as_str()
        .unwrap_or("");
    {
        let mut rows = REQUESTS.lock().unwrap();
        let row = &mut rows[request.0];
        row["input_source"] = json!(pending.original.source);
        row["domain"] = json!(domain);
        row["input_ok"] = json!(valid && recipe_ok);
    }
    let result = run.browser.evaluate(&worker.session, &expression).await?;
    let mut rows = REQUESTS.lock().unwrap();
    rows[request.0]["refused"] = json!(result.get("error").is_some());
    rows[request.0]["response_ok"] = json!(true);
    drop(rows);
    Ok(result)
}

fn answer_input(
    pending: &Pending,
    worker: &crate::Worker,
    case: &str,
    ordinal: usize,
    value: &Value,
) -> (&'static str, bool) {
    let source = &pending.original.value;
    let mut expected = json!({"session":source["sessions"][0]["identity"],"machine":"fixture","candidate":source["sessions"][0]["pending_requirements"]["candidate"],"decision":"approve"});
    let domain = match (case, ordinal) {
        ("declaration_cases.c001.p001", 1) => {
            expected["machine"] = json!("fixture-other");
            "wrong_machine"
        }
        ("declaration_cases.c001.p001", 2) => {
            expected["candidate"] = json!(0);
            "stale_candidate"
        }
        ("declaration_cases.c001.p001", 3) => {
            expected["declaration"] = json!({"version":2,"listeners":{"inbound":[{"proto":"tcp","port":22,"from":"any"}],"outbound":[]},"services":[],"key_material":{"spendable":false,"permitted":[]},"drift_checks":[],"required":[],"default_credentials":"none"});
            "replacement_data"
        }
        ("declaration_cases.c001.p001", 4) => "duplicate_approval",
        ("declaration_cases.c003.p001" | "declaration_cases.c003.p002", 1) => "late_approval",
        _ => "unknown",
    };
    let valid = domain != "unknown"
        && pending.projected
        && pending.original.worker == *worker
        && source["sessions"][0]["identity"].is_string()
        && source["sessions"][0]["pending_requirements"].is_object()
        && *value == expected;
    (domain, valid)
}

pub struct Request(usize);
impl Request {
    pub fn begin(kind: &'static str, worker: &crate::Worker) -> Self {
        let (identity, page) = history::worker_identity(&worker.session);
        let mut rows = REQUESTS.lock().unwrap();
        let index = rows.len();
        rows.push(json!({"source":index+1,"kind":kind,"page":page,"worker":identity,"case":history::active_case_id(),"start_ns":completion::now(),"start_cursor":history::cursor(),"end_ns":null,"end_cursor":null,"receiver_ok":history::selected_worker_matches(page,worker),"input_source":null,"domain":"unverified","input_ok":false,"refused":null,"response_ok":false}));
        Self(index)
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        let mut rows = REQUESTS.lock().unwrap();
        rows[self.0]["end_ns"] = json!(completion::now());
        rows[self.0]["end_cursor"] = json!(history::cursor());
    }
}
pub fn snapshot() -> Value {
    json!(*REQUESTS.lock().unwrap())
}

pub fn validate(report: &Value) -> Result<(), String> {
    validate_with(report, completion::inventory())
}
fn validate_with(report: &Value, key: &Value) -> Result<(), String> {
    let rows = report["file_requests"].as_array().ok_or(ERROR)?;
    let events = report["helper_history"].as_array().ok_or(ERROR)?;
    let states = reader_checks::caller_states(report);
    let workers = history::worker_states(report);
    let duration = report["duration_ns"].as_u64().ok_or(ERROR)?;
    let pending = report["file_pending_inputs"].as_array().ok_or(ERROR)?;
    let pending_rules = key["file_pending_sources"].as_object().ok_or(ERROR)?;
    if pending_rules
        .values()
        .any(|v| !matches!(v.as_str(), Some("initial" | "observer")))
    {
        return Err(ERROR.into());
    }
    let calls = report["observer_calls"].as_array().ok_or(ERROR)?;
    let mut required = BTreeSet::new();
    if report["cases"]
        .as_array()
        .ok_or(ERROR)?
        .iter()
        .any(|c| c["id"] == "declaration_cases.c001.p001")
    {
        required.insert(("declaration.initial.pending".to_owned(), None));
    }
    for (index, call) in calls
        .iter()
        .enumerate()
        .filter(|(_, c)| c["kind"] == "declaration.wait_card")
    {
        required.insert((
            call["site"].as_str().ok_or(ERROR)?.to_owned(),
            Some(index + 1),
        ));
    }
    let mut pending_end = 0;
    for (index, row) in pending.iter().enumerate() {
        let site = row["site"].as_str().ok_or(ERROR)?;
        let call = if row["call"].is_null() {
            None
        } else {
            Some(row["call"].as_u64().ok_or(ERROR)? as usize)
        };
        let start = row["start_ns"].as_u64().ok_or(ERROR)?;
        let end = row["end_ns"].as_u64().ok_or(ERROR)?;
        let cursor = row["start_cursor"].as_u64().ok_or(ERROR)? as usize;
        let page = row["page"].as_u64().ok_or(ERROR)?;
        let rule = pending_rules.get(site).ok_or(ERROR)?;
        let state = states.get(cursor).ok_or(ERROR)?;
        let pending_case = state
            .owner
            .as_ref()
            .filter(|o| o.1 == "inside")
            .map(|o| o.2.as_str());
        if row["case"] != json!(pending_case)
            || start < pending_end
            || cursor > 0 && events[cursor - 1]["at_ns"].as_u64().ok_or(ERROR)? > start
            || cursor < events.len() && events[cursor]["at_ns"].as_u64().ok_or(ERROR)? < end
        {
            return Err(ERROR.into());
        }
        pending_end = end;

        if row.as_object().is_none_or(|o| o.len() != 12)
            || row["source"] != index + 1
            || row["start_cursor"] != row["end_cursor"]
            || start > end
            || end > duration
            || page == 0
            || row["worker"].as_u64().is_none_or(|w| w == 0)
            || row["worker"].as_u64().is_none_or(|w| w == 0)
            || row["query_ok"] != true
            || row["receiver_ok"] != true
            || row["worker"] != json!(workers.get(cursor).and_then(|w| w.get(&page)))
            || !required.remove(&(site.to_owned(), call))
        {
            return Err(ERROR.into());
        }
        if let Some(call) = call {
            let parent = calls.get(call.checked_sub(1).ok_or(ERROR)?).ok_or(ERROR)?;
            let inputs = parent["inputs"].as_array().ok_or(ERROR)?;
            if inputs.len() != 1
                || inputs[0]["page"] != page
                || inputs[0]["worker"] != row["worker"]
                || inputs[0]["history_cursor"] != cursor
                || inputs[0]["at_ns"].as_u64().ok_or(ERROR)? > start
            {
                return Err(ERROR.into());
            }
            if rule != "observer"
                || parent["site"] != site
                || parent["kind"] != "declaration.wait_card"
                || parent["page"] != page
                || parent["start_ns"].as_u64().ok_or(ERROR)? > start
                || parent["end_ns"].as_u64().ok_or(ERROR)? < end
            {
                return Err(ERROR.into());
            }
        } else {
            if rule != "initial" || row["case"] != "declaration_cases.c001.p001" {
                return Err(ERROR.into());
            }
            crate::file_domains::checkpoint(
                report,
                &json!({"at_ns":end,"history_cursor":cursor}),
                "declaration_cases.c001.p001",
                "declaration_cases.a001",
                1,
            )?;
        }
    }
    if !required.is_empty() {
        return Err(ERROR.into());
    }
    let mut previous = 0;
    for (index, row) in rows.iter().enumerate() {
        let start = row["start_ns"].as_u64().ok_or(ERROR)?;
        let end = row["end_ns"].as_u64().ok_or(ERROR)?;
        let cursor = row["start_cursor"].as_u64().ok_or(ERROR)? as usize;
        let owner = states.get(cursor).and_then(|s| s.owner.as_ref());
        let case = owner.filter(|o| o.1 == "inside").map(|o| o.2.as_str());
        let page = row["page"].as_u64().ok_or(ERROR)?;
        if row.as_object().is_none_or(|o| o.len() != 15)
            || row["source"] != index + 1
            || !(matches!(
                row["kind"].as_str(),
                Some("declaration.answer" | "goal.request" | "goal.accept" | "goal.configure")
            ) || row["kind"].as_str().is_some_and(refusal_inputs::kind))
            || row["case"] != json!(case)
            || page == 0
            || row["worker"].as_u64().is_none_or(|w| w == 0)
            || row["worker"] != json!(workers.get(cursor).and_then(|w| w.get(&page)))
            || row["receiver_ok"] != true
            || row["end_cursor"] != cursor
            || start < previous
            || end < start
            || end > duration
            || cursor > 0 && events[cursor - 1]["at_ns"].as_u64().ok_or(ERROR)? > start
            || cursor < events.len() && events[cursor]["at_ns"].as_u64().ok_or(ERROR)? < end
        {
            return Err(ERROR.into());
        }
        if row["kind"] == "declaration.answer" {
            let source = row["input_source"].as_u64().ok_or(ERROR)? as usize;
            let input = pending
                .get(source.checked_sub(1).ok_or(ERROR)?)
                .ok_or(ERROR)?;
            let ordinal = rows[..index + 1]
                .iter()
                .filter(|r| r["kind"] == "declaration.answer" && r["case"] == row["case"])
                .count();
            let domain = match (case, ordinal) {
                (Some("declaration_cases.c001.p001"), 1) => "wrong_machine",
                (Some("declaration_cases.c001.p001"), 2) => "stale_candidate",
                (Some("declaration_cases.c001.p001"), 3) => "replacement_data",
                (Some("declaration_cases.c001.p001"), 4) => "duplicate_approval",
                (Some("declaration_cases.c003.p001" | "declaration_cases.c003.p002"), 1) => {
                    "late_approval"
                }
                _ => return Err(ERROR.into()),
            };
            let site = if domain == "late_approval" {
                "declaration.cancel.wait_card"
            } else {
                "declaration.initial.pending"
            };
            let original_owner = states
                .get(input["start_cursor"].as_u64().ok_or(ERROR)? as usize)
                .ok_or(ERROR)?;
            let owner_ok = if domain == "late_approval" {
                let execution = report["cases"].as_array().ok_or(ERROR)?;
                let index = execution
                    .iter()
                    .position(|c| c["id"] == row["case"])
                    .ok_or(ERROR)?;
                let anchor = index
                    .checked_sub(1)
                    .map_or("", |n| execution[n]["id"].as_str().unwrap_or(""));
                original_owner.invocation == states[cursor].invocation
                    && original_owner
                        .owner
                        .as_ref()
                        .zip(owner)
                        .is_some_and(|(p, r)| p.0 == r.0 && p.1 == "after" && p.2 == anchor)
                    && input["case"].is_null()
            } else {
                input["case"] == row["case"]
            };
            if row["response_ok"] != true
                || row["input_ok"] != true
                || row["refused"] != true
                || row["domain"] != domain
                || input["site"] != site
                || !owner_ok
                || input["page"] != row["page"]
                || input["worker"] != row["worker"]
                || input["end_ns"].as_u64().ok_or(ERROR)? > start
            {
                return Err(ERROR.into());
            }
        }
        previous = end;
    }
    let rules = key["file_request_windows"].as_object().ok_or(ERROR)?;
    if rules.values().any(|v| {
        !v.as_str().is_some_and(refusal_inputs::window_kind)
            && !matches!(
                v.as_str(),
                Some(
                    "declaration.answer"
                        | "goal.request"
                        | "goal.accept"
                        | "goal.configure"
                        | "submit.wrong_unlock"
                )
            )
    }) {
        return Err(ERROR.into());
    }
    let captures = report["file_captures"].as_array().ok_or(ERROR)?;
    let primary = report["primary_history"].as_array().ok_or(ERROR)?;
    let mut consumed = BTreeSet::new();
    for comparison in report["file_comparisons"].as_array().ok_or(ERROR)? {
        let Some(kind) = comparison["site"]
            .as_str()
            .and_then(|s| rules.get(s))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let check_id = format!(
            "{}.i{:03}",
            comparison["predicate"].as_str().ok_or(ERROR)?,
            comparison["check_instance"].as_u64().ok_or(ERROR)?
        );
        let check = primary
            .iter()
            .position(|p| p["case"] == comparison["case"] && p["id"] == check_id)
            .ok_or(ERROR)?;
        let lower = check
            .checked_sub(1)
            .filter(|n| primary[*n]["case"] == comparison["case"])
            .map_or(0, |n| primary[n]["at_ns"].as_u64().unwrap_or(u64::MAX));
        let upper = comparison["at_ns"].as_u64().ok_or(ERROR)?;
        let operations: Vec<_> = if kind == "submit.wrong_unlock" {
            let submissions = report["submissions"].as_array().ok_or(ERROR)?;
            let mut found = Vec::new();
            for (n, event) in events
                .iter()
                .enumerate()
                .filter(|(_, e)| e["event"] == "call_start" && e["kind"] == "runtime.submit")
            {
                let end = events
                    .iter()
                    .find(|e| e["event"] == "call_end" && e["call"] == event["call"])
                    .ok_or(ERROR)?;
                if event["at_ns"].as_u64().ok_or(ERROR)? >= lower
                    && end["at_ns"].as_u64().ok_or(ERROR)? <= upper
                    && states[n]
                        .owner
                        .as_ref()
                        .is_some_and(|o| json!(o.2) == comparison["case"])
                {
                    let submission = submissions
                        .iter()
                        .find(|s| s["call"] == event["call"])
                        .ok_or(ERROR)?;
                    if submission["kind"] != "unlock" || submission["passphrase_role"] != "wrong" {
                        return Err(ERROR.into());
                    }
                    found.push((
                        event["at_ns"].as_u64().ok_or(ERROR)?,
                        end["at_ns"].as_u64().ok_or(ERROR)?,
                        event["page"].as_u64().ok_or(ERROR)?,
                        format!("submit:{}", event["call"]),
                    ));
                }
            }
            found
        } else {
            rows.iter()
                .filter(|r| {
                    (r["kind"] == kind
                        || kind == "setup.request"
                            && matches!(r["kind"].as_str(), Some("setup.run" | "setup.collect")))
                        && r["case"] == comparison["case"]
                        && r["start_ns"].as_u64().is_some_and(|t| t >= lower)
                        && r["end_ns"].as_u64().is_some_and(|t| t <= upper)
                })
                .map(|r| {
                    Ok((
                        r["start_ns"].as_u64().ok_or(ERROR)?,
                        r["end_ns"].as_u64().ok_or(ERROR)?,
                        r["page"].as_u64().ok_or(ERROR)?,
                        format!("request:{}", r["source"]),
                    ))
                })
                .collect::<Result<Vec<_>, String>>()?
        };
        if operations.len() != 1 {
            return Err(format!("{ERROR}: {}", comparison["site"]));
        }
        let (start, end, page, identity) = &operations[0];
        if !consumed.insert(identity.clone()) {
            return Err(ERROR.into());
        }
        let capture = |side: &str| -> Result<&Value, String> {
            captures
                .get(
                    comparison[side]["source"]
                        .as_u64()
                        .ok_or(ERROR)?
                        .checked_sub(1)
                        .ok_or(ERROR)? as usize,
                )
                .ok_or_else(|| ERROR.into())
        };
        let before = capture("right")?;
        let after = capture("left")?;
        let dump = if after["kind"] == "browser.store" {
            captures
                .get(
                    after["parent"]
                        .as_u64()
                        .ok_or(ERROR)?
                        .checked_sub(1)
                        .ok_or(ERROR)? as usize,
                )
                .ok_or(ERROR)?
        } else {
            after
        };
        if before["at_ns"].as_u64().ok_or(ERROR)? > *start
            || crate::operation_windows::dump_start(report, dump)? < *end
            || after["at_ns"].as_u64().ok_or(ERROR)? > upper
            || [before, after, dump].iter().any(|c| c["page"] != *page)
        {
            return Err(format!("{ERROR}: {}", comparison["site"]));
        }
    }
    goal_inputs::validate(report, key)?;
    refusal_inputs::validate(report, key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn consumed_declaration_is_the_actual_serialized_operation() {
        let value = json!({"session":"fixture-session","candidate":3,"machine":"fixture-other","decision":"approve"});
        let expression =
            ANSWER_EXPRESSION.replace("__TAU_INPUT__", &json!(value.to_string()).to_string());
        assert_eq!(consumed_answer(&expression), Some(value.clone()));
        let duplicate=ANSWER_EXPRESSION.replace("__TAU_INPUT__",&json!(r#"{"candidate":3,"decision":"approve","machine":"fixture-other","session":"wrong","session":"fixture-session"}"#).to_string());
        assert!(consumed_answer(&duplicate).is_none());
        assert!(
            consumed_answer(&expression.replace("requirements_answer", "goal_request")).is_none()
        );
        assert_ne!(
            consumed_answer(&expression.replace("fixture-other", "fixture")),
            Some(value)
        );
    }
    #[test]
    fn both_observations_bracket_the_real_request() {
        let fixture: Value =
            serde_json::from_str(include_str!("../testdata/file-refusal-windows.json")).unwrap();
        let report = &fixture["report"];
        let key = &fixture["inventory"];
        validate_with(report, key).unwrap();
        for (pointer, value) in [
            ("/file_captures/1/at_ns", json!(21)),
            ("/file_captures/2/at_ns", json!(20)),
            ("/file_requests/0/end_ns", json!(23)),
            ("/file_requests/0/page", json!(8)),
            ("/file_requests/0/worker", json!(4)),
            ("/file_requests/0/receiver_ok", json!(false)),
            ("/file_requests/0/input_source/source", json!(1)),
            ("/file_requests/0/input_source/source", json!(2.0)),
            ("/file_requests/0/input_source/kind", json!("rebind")),
            ("/file_requests/0/response_ok", json!(false)),
            ("/file_requests/0/input_ok", json!(false)),
            ("/file_requests/0/refused", json!(true)),
            ("/file_comparisons/1/right/source", json!(8)),
        ] {
            let mut bad = report.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(validate_with(&bad, key).is_err(), "{pointer}");
        }
        let mut bad = report.clone();
        bad["file_requests"].as_array_mut().unwrap().pop();
        assert!(validate_with(&bad, key).is_err());
        validate_with(report, key).unwrap();
    }
    #[test]
    fn saved_baseline_precedes_the_unlock_start() {
        let fixture: Value =
            serde_json::from_str(include_str!("../testdata/file-unlock-windows.json")).unwrap();
        let report = &fixture["report"];
        let key = &fixture["inventory"];
        validate_with(report, key).unwrap();
        for (pointer, value) in [
            ("/file_captures/1/at_ns", json!(21)),
            ("/file_captures/2/at_ns", json!(20)),
            ("/submissions/0/passphrase_role", json!("tracer")),
            ("/submissions/0/kind", json!("create")),
        ] {
            let mut bad = report.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(validate_with(&bad, key).is_err(), "{pointer}");
        }
        validate_with(report, key).unwrap();
    }
    #[test]
    fn declaration_inputs_use_the_original_private_session_candidate_and_full_worker() {
        let worker = crate::Worker {
            session: "source-session".into(),
            target: "source-target".into(),
        };
        let pending = Pending {
            original: Arc::new(PendingOriginal {
                value: json!({"sessions":[{"identity":"original-session","pending_requirements":{"candidate":17}}]}),
                source: 1,
                worker: worker.clone(),
            }),
            projected: true,
        };
        let valid = json!({"session":"original-session","machine":"fixture-other","candidate":17,"decision":"approve"});
        assert!(answer_input(&pending, &worker, "declaration_cases.c001.p001", 1, &valid).1);
        for (field, value) in [
            ("session", json!("older-session")),
            ("machine", json!("fixture")),
            ("candidate", json!(19)),
            ("decision", json!("reject")),
        ] {
            let mut bad = valid.clone();
            bad[field] = value;
            assert!(
                !answer_input(&pending, &worker, "declaration_cases.c001.p001", 1, &bad).1,
                "{field}"
            );
        }
        let mut wrong = worker.clone();
        wrong.target = "different-target".into();
        assert!(!answer_input(&pending, &wrong, "declaration_cases.c001.p001", 1, &valid).1);
        assert!(!answer_input(&pending, &worker, "declaration_cases.c001.p001", 5, &valid).1);
    }

    #[test]
    fn original_pending_source_and_finite_refusal_domains() {
        for text in [
            include_str!("../testdata/declaration-refusal-inputs.json"),
            include_str!("../testdata/declaration-late-inputs.json"),
        ] {
            let fixture: Value = serde_json::from_str(text).unwrap();
            let report = &fixture["report"];
            let key = &fixture["inventory"];
            validate_with(report, key).unwrap();
            for (pointer, value) in [
                ("/file_pending_inputs/0/query_ok", json!(false)),
                ("/file_pending_inputs/0/worker", json!(4)),
                ("/file_pending_inputs/0/end_ns", json!(21)),
                ("/file_requests/0/input_source", json!(2)),
                ("/file_requests/0/input_ok", json!(false)),
                ("/file_requests/0/refused", json!(false)),
                ("/file_requests/0/domain", json!("stale_candidate")),
            ] {
                let mut bad = report.clone();
                *bad.pointer_mut(pointer).unwrap() = value;
                assert!(validate_with(&bad, key).is_err(), "{pointer}");
            }
            validate_with(report, key).unwrap();
        }
    }
}
