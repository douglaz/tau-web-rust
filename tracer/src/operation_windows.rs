//! Source-specific operation spans for comparisons that retain a pre-operation file baseline.
use crate::{completion, history, reader_checks};
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::Mutex};

struct ExpectedCall {
    session: Option<String>,
    method: String,
    params: Value,
}
struct Private {
    calls: Vec<ExpectedCall>,
    matched: usize,
    active: bool,
}
struct QueryPrivate {
    session: String,
    expression: String,
    active: bool,
    matched: bool,
}
static QUERY_PRIVATE: Mutex<Vec<QueryPrivate>> = Mutex::new(Vec::new());
static QUERIES: Mutex<Vec<Value>> = Mutex::new(Vec::new());
pub struct DumpQuery(usize);
pub fn dump_query(tab: &crate::Tab, expression: &str) -> DumpQuery {
    let mut private = QUERY_PRIVATE.lock().unwrap();
    let mut rows = QUERIES.lock().unwrap();
    let index = rows.len();
    private.push(QueryPrivate {
        session: tab.session.clone(),
        expression: expression.into(),
        active: true,
        matched: false,
    });
    let query_ok =
        hex::encode(ring::digest::digest(&ring::digest::SHA256, expression.as_bytes()).as_ref())
            == completion::inventory()["file_dump_expression_sha256"]
                .as_str()
                .unwrap_or("");
    rows.push(json!({"source":null,"page":history::page_id(&tab.session),"start_ns":null,"end_ns":null,"start_cursor":null,"end_cursor":null,"query_ok":query_ok,"completed":false}));
    DumpQuery(index)
}
impl DumpQuery {
    pub fn finish(self, source: usize) {
        let private = QUERY_PRIVATE.lock().unwrap();
        let mut rows = QUERIES.lock().unwrap();
        rows[self.0]["source"] = json!(source);
        rows[self.0]["completed"] = json!(private[self.0].matched);
    }
}
impl Drop for DumpQuery {
    fn drop(&mut self) {
        QUERY_PRIVATE.lock().unwrap()[self.0].active = false;
    }
}
pub fn original_dump_matches(
    source: usize,
    page: u64,
    original: &crate::cdp::OriginalEvaluation,
) -> bool {
    let private = QUERY_PRIVATE.lock().unwrap();
    let rows = QUERIES.lock().unwrap();
    let matching: Vec<_> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row["source"] == source)
        .collect();
    if matching.len() != 1 {
        return false;
    }
    let (index, row) = matching[0];
    row["page"] == page
        && row["completed"] == true
        && row["query_ok"] == true
        && original.matches(&private[index].session, crate::DUMP)
        && row["start_ns"]
            .as_u64()
            .zip(row["end_ns"].as_u64())
            .zip(row["start_cursor"].as_u64())
            .is_some_and(|((start, end), cursor)| {
                row["end_cursor"] == cursor && original.encloses(start, end, cursor as usize)
            })
}
#[cfg(test)]
pub fn test_dump_source(source: usize, page: u64) {
    let mut private = QUERY_PRIVATE.lock().unwrap();
    let mut rows = QUERIES.lock().unwrap();
    private.push(QueryPrivate {
        session: "fixture".into(),
        expression: crate::DUMP.into(),
        active: false,
        matched: true,
    });
    rows.push(json!({"source":source,"page":page,"start_ns":0,"end_ns":0,"start_cursor":0,"end_cursor":0,"query_ok":true,"completed":true}));
}
pub fn dump_queries() -> Value {
    json!(*QUERIES.lock().unwrap())
}

static PRIVATE: Mutex<Vec<Private>> = Mutex::new(Vec::new());
static ROWS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
const ERROR: &str = "original operation/file observation window mismatch";

pub struct Operation(usize);
impl Operation {
    pub fn begin(site: &'static str, worker: &crate::Worker, input_ok: bool) -> Self {
        let (worker_id, page) = history::worker_identity(&worker.session);
        let mut private = PRIVATE.lock().unwrap();
        let mut rows = ROWS.lock().unwrap();
        let index = rows.len();
        private.push(Private {
            calls: Vec::new(),
            matched: 0,
            active: true,
        });
        rows.push(json!({"site":site,"source":index+1,"case":history::active_case_id(),"page":page,"worker":worker_id,"receiver_ok":history::selected_worker_matches(page,worker),"input_ok":input_ok,"completed":false,"call_count":0,"timeout_ns":null,"start_ns":completion::now(),"start_cursor":history::cursor(),"end_ns":null,"end_cursor":null}));
        Self(index)
    }
    pub fn expect(&self, session: Option<&str>, method: &str, params: Value) {
        PRIVATE.lock().unwrap()[self.0].calls.push(ExpectedCall {
            session: session.map(str::to_owned),
            method: method.into(),
            params,
        });
    }
    pub fn evaluate(&self, worker: &crate::Worker, expression: &str) {
        self.expect(
            Some(&worker.session),
            "Runtime.evaluate",
            json!({"expression":expression,"awaitPromise":true,"returnByValue":true}),
        );
    }
    pub fn module(&self, worker: &crate::Worker, body: &str) {
        self.evaluate(worker, &format!("(async()=>{{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);{body}}})()"));
    }
    pub fn run(&self, worker: &crate::Worker, args: &Value) {
        self.evaluate(worker, &original_run_expression(args));
    }
    pub fn page(&self, session: &str, expression: &str) {
        self.expect(
            Some(session),
            "Runtime.evaluate",
            json!({"expression":expression,"awaitPromise":true,"returnByValue":true}),
        );
    }
    pub async fn timeout<F: std::future::Future>(
        &self,
        duration: std::time::Duration,
        future: F,
    ) -> Result<F::Output, tokio::time::error::Elapsed> {
        ROWS.lock().unwrap()[self.0]["timeout_ns"] = json!(duration.as_nanos() as u64);
        tokio::time::timeout(duration, future).await
    }
    pub fn finish(self) {
        let private = PRIVATE.lock().unwrap();
        let p = &private[self.0];
        ROWS.lock().unwrap()[self.0]["completed"] =
            json!(!p.calls.is_empty() && p.matched == p.calls.len());
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        PRIVATE.lock().unwrap()[self.0].active = false;
    }
}
pub fn ordinal(site: &str) -> usize {
    let case = json!(history::active_case_id());
    ROWS.lock()
        .unwrap()
        .iter()
        .filter(|r| r["site"] == site && r["case"] == case)
        .count()
}
pub fn original_request(run: &crate::Run<'_>, machine: &str) -> Value {
    json!({"machine":machine,"relay":run.relay.url,"host":"127.0.0.1","port":if machine=="fixture-other" {run.sshd_other.port} else {run.sshd.port},"user":crate::SSH_USER,"command":crate::COMMAND,"fail_append":false,"tamper_auth":false})
}

pub fn original_run_expression(args: &Value) -> String {
    let request = json!(args.to_string());
    format!(
        "(async () => {{\n            const module = await import(new URL('./pkg/tau_web.js', self.location.href).href);\n            return JSON.parse(await module.run_command({request}));\n        }})()"
    )
}

/// Observe the exact request handed to CDP, without exporting its private operands.
pub struct Call {
    operations: Vec<usize>,
    queries: Vec<usize>,
}
pub fn call(session: Option<&str>, method: &str, params: &Value) -> Call {
    let mut private = PRIVATE.lock().unwrap();
    let mut rows = ROWS.lock().unwrap();
    let mut found = Vec::new();
    for (index, p) in private.iter_mut().enumerate().filter(|(_, p)| p.active) {
        if let Some(expected) = p.calls.get(p.matched)
            && expected.session.as_deref() == session
            && expected.method == method
            && expected.params == *params
        {
            if p.matched == 0 {
                rows[index]["start_ns"] = json!(completion::now());
                rows[index]["start_cursor"] = json!(history::cursor());
            }
            p.matched += 1;
            rows[index]["call_count"] = json!(p.matched);
            found.push(index);
        } else if p.calls.iter().any(|expected| {
            expected.session.as_deref() == session
                && expected.method == method
                && expected.params == *params
        }) {
            // An original dispatch repeated or reordered inside its source invocation is not
            // unrelated observation work. Keep the real call, but refuse its evidence.
            rows[index]["input_ok"] = json!(false);
        }
    }
    drop(rows);
    drop(private);
    let mut queries = Vec::new();
    let mut private = QUERY_PRIVATE.lock().unwrap();
    let mut rows = QUERIES.lock().unwrap();
    for (index, p) in private.iter_mut().enumerate().filter(|(_, p)| p.active) {
        if Some(p.session.as_str()) == session
            && method == "Runtime.evaluate"
            && *params
                == json!({"expression":p.expression,"awaitPromise":true,"returnByValue":true})
        {
            if p.matched {
                rows[index]["query_ok"] = json!(false);
            }
            p.matched = true;
            rows[index]["start_ns"] = json!(completion::now());
            rows[index]["start_cursor"] = json!(history::cursor());
            queries.push(index);
        }
    }
    Call {
        operations: found,
        queries,
    }
}
impl Drop for Call {
    fn drop(&mut self) {
        let mut rows = ROWS.lock().unwrap();
        for index in &self.operations {
            rows[*index]["end_ns"] = json!(completion::now());
            rows[*index]["end_cursor"] = json!(history::cursor());
        }
        drop(rows);
        let mut rows = QUERIES.lock().unwrap();
        for index in &self.queries {
            rows[*index]["end_ns"] = json!(completion::now());
            rows[*index]["end_cursor"] = json!(history::cursor());
        }
    }
}
pub fn snapshot() -> Value {
    json!(*ROWS.lock().unwrap())
}
pub fn validate(report: &Value) -> Result<(), String> {
    validate_with(report, completion::inventory())
}
fn validate_with(report: &Value, key: &Value) -> Result<(), String> {
    let rows = report["operation_windows"].as_array().ok_or(ERROR)?;
    let rules = key["file_action_windows"].as_object().ok_or(ERROR)?;
    let comparisons_key = key["file_comparison_sources"].as_object().ok_or(ERROR)?;
    let relations = key["file_comparison_relations"].as_object().ok_or(ERROR)?;
    if comparisons_key.len() != relations.len() {
        return Err(format!("{ERROR}: unclassified comparison"));
    }
    for site in comparisons_key.keys() {
        match relations.get(site).and_then(Value::as_str) {
            Some("request") if key["file_request_windows"].get(site).is_some() => {}
            Some("action") if rules.contains_key(site) => {}
            Some("goal_refusal")
                if site == "goal_cases.a036.1"
                    && key["file_operation_sources"]["goal.harness_job_refusal"]
                        .as_u64()
                        .is_some_and(|n| n > 0) => {}
            Some("canonical_transform")
                if matches!(
                    site.as_str(),
                    "binding.contracts.observe" | "binding.contracts.branch"
                ) => {}
            // These original helper/query relationships are explicitly unverified. They
            // remain available for incomplete targeted diagnostics, never full credit.
            Some("pending_query") if key["coverage"]["complete"] == false => {}
            _ => {
                return Err(format!(
                    "{ERROR}: unclassified or unverified comparison {site}"
                ));
            }
        }
    }
    let states = reader_checks::caller_states(report);
    let workers = history::worker_states(report);
    let pages = history::source_page_states(report)?;
    let events = report["helper_history"].as_array().ok_or(ERROR)?;
    let captures = report["file_captures"].as_array().ok_or(ERROR)?;
    let comparisons = report["file_comparisons"].as_array().ok_or(ERROR)?;
    let duration = report["duration_ns"].as_u64().ok_or(ERROR)?;
    let queries = report["file_dump_queries"].as_array().ok_or(ERROR)?;
    let dumps: Vec<_> = captures
        .iter()
        .filter(|c| c["kind"] == "browser.dump")
        .collect();
    if queries.len() != dumps.len() {
        return Err(ERROR.into());
    }
    let mut previous = 0;
    for (query, capture) in queries.iter().zip(dumps) {
        let start = query["start_ns"].as_u64().ok_or(ERROR)?;
        let end = query["end_ns"].as_u64().ok_or(ERROR)?;
        let cursor = query["start_cursor"].as_u64().ok_or(ERROR)? as usize;
        let until = query["end_cursor"].as_u64().ok_or(ERROR)? as usize;
        if query.as_object().is_none_or(|o| o.len() != 8)
            || query["source"] != capture["source"]
            || query["page"] != capture["page"]
            || query["query_ok"] != true
            || query["completed"] != true
            || start < previous
            || end < start
            || end > capture["at_ns"].as_u64().ok_or(ERROR)?
            || cursor > until
            || until > events.len()
            || until > capture["history_cursor"].as_u64().ok_or(ERROR)? as usize
            || states.get(cursor).is_none_or(|s| {
                states
                    .get(until)
                    .is_none_or(|e| e.owner != s.owner || e.invocation != s.invocation)
            })
            || cursor > 0 && events[cursor - 1]["at_ns"].as_u64().ok_or(ERROR)? > start
            || until < events.len() && events[until]["at_ns"].as_u64().ok_or(ERROR)? < end
        {
            return Err(format!("{ERROR}: original dump query"));
        }
        previous = end;
    }
    let mut previous = 0;
    for (index, row) in rows.iter().enumerate() {
        let start = row["start_ns"].as_u64().ok_or(ERROR)?;
        let end = row["end_ns"].as_u64().ok_or(ERROR)?;
        let cursor = row["start_cursor"].as_u64().ok_or(ERROR)? as usize;
        let until = row["end_cursor"].as_u64().ok_or(ERROR)? as usize;
        let page = row["page"].as_u64().ok_or(ERROR)?;
        let state = states.get(cursor).ok_or(ERROR)?;
        let owner = state.owner.as_ref().ok_or(ERROR)?;
        if row.as_object().is_none_or(|r| r.len() != 14)
            || row["source"] != index + 1
            || !row["site"].is_string()
            || row["case"]
                != json!(if owner.1 == "inside" {
                    Some(owner.2.as_str())
                } else {
                    None
                })
            || row["receiver_ok"] != true
            || row["input_ok"] != true
            || row["completed"] != true
            || page == 0
            || row["worker"].as_u64().is_none_or(|w| w == 0)
            || row["worker"] != json!(workers.get(cursor).and_then(|w| w.get(&page)))
            || start < previous
            || end <= start
            || end > duration
            || until < cursor
            || until > events.len()
            || states
                .get(until)
                .is_none_or(|s| s.owner != state.owner || s.invocation != state.invocation)
            || cursor > 0 && events[cursor - 1]["at_ns"].as_u64().ok_or(ERROR)? > start
            || until < events.len() && events[until]["at_ns"].as_u64().ok_or(ERROR)? < end
        {
            return Err(ERROR.into());
        }
        previous = end;
    }
    let mut consumed = BTreeSet::new();
    for comparison in comparisons {
        let Some(rule) = comparison["site"].as_str().and_then(|s| rules.get(s)) else {
            continue;
        };
        if rule.as_array().is_none_or(|r| r.len() != 3)
            || !matches!(rule[0].as_str(), Some("left" | "right"))
            || !matches!(rule[1].as_str(), Some("same" | "successor"))
            || rule[2].as_array().is_none_or(|r| r.is_empty())
        {
            return Err(ERROR.into());
        }
        let side = rule[0].as_str().ok_or(ERROR)?;
        let capture = |side: &str| -> Result<&Value, String> {
            let n = comparison[side]["source"].as_u64().ok_or(ERROR)?;
            captures
                .get(n.checked_sub(1).ok_or(ERROR)? as usize)
                .ok_or_else(|| ERROR.into())
        };
        let before = capture(side)?;
        let after = capture(if side == "left" { "right" } else { "left" })?;
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
        let check_cursor = comparison["history_cursor"].as_u64().ok_or(ERROR)? as usize;
        let check_state = states.get(check_cursor).ok_or(ERROR)?;
        let check_owner = check_state.owner.as_ref().ok_or(ERROR)?;
        let instance = comparison["check_instance"].as_u64().ok_or(ERROR)? as usize;
        let mut prior_end = before["at_ns"].as_u64().ok_or(ERROR)?;
        for descriptor in rule[2].as_array().ok_or(ERROR)? {
            if descriptor.as_array().is_none_or(|d| d.len() != 4)
                || !matches!(descriptor[1].as_str(), Some("once" | "each"))
                || !matches!(descriptor[2].as_str(), Some("inside" | "before"))
            {
                return Err(ERROR.into());
            }
            let matching: Vec<_> = rows
                .iter()
                .enumerate()
                .filter(|(_, row)| {
                    let Some(state) = row["start_cursor"]
                        .as_u64()
                        .and_then(|c| states.get(c as usize))
                    else {
                        return false;
                    };
                    let Some(owner) = state.owner.as_ref() else {
                        return false;
                    };
                    row["site"] == descriptor[0]
                        && state.invocation == check_state.invocation
                        && owner.0 == check_owner.0
                        && if descriptor[2] == "inside" {
                            owner.1 == "inside" && owner.2 == check_owner.2
                        } else {
                            let execution = report["cases"].as_array();
                            execution
                                .and_then(|e| {
                                    e.iter()
                                        .position(|c| c["id"] == comparison["case"])
                                        .map(|n| (e, n))
                                })
                                .is_some_and(|(e, n)| {
                                    owner.1 == "after"
                                        && owner.2
                                            == n.checked_sub(1)
                                                .map_or("", |i| e[i]["id"].as_str().unwrap_or(""))
                                })
                        }
                })
                .collect();
            let n = if descriptor[1] == "once" {
                0
            } else {
                instance.checked_sub(1).ok_or(ERROR)?
            };
            let (index, operation) = matching.get(n).ok_or(ERROR)?;
            let expected_calls = if descriptor[3] == "seed.trigger" {
                let slot = comparison["case"]
                    .as_str()
                    .and_then(|s| s.rsplit_once(".p"))
                    .and_then(|(_, n)| n.parse::<usize>().ok())
                    .ok_or(ERROR)?;
                match (slot - 1) % 6 {
                    1 => 4,
                    5 => 2,
                    _ => 1,
                }
            } else {
                descriptor[3].as_u64().ok_or(ERROR)? as usize
            };
            if expected_calls == 0
                || operation["call_count"] != expected_calls
                || operation["timeout_ns"]
                    != key["file_action_timeouts"]
                        .get(descriptor[0].as_str().ok_or(ERROR)?)
                        .cloned()
                        .unwrap_or(Value::Null)
            {
                return Err(ERROR.into());
            }
            if descriptor[1] == "each" && instance > 1 {
                let previous = comparisons
                    .iter()
                    .find(|c| {
                        c["site"] == comparison["site"]
                            && c["case"] == comparison["case"]
                            && c["check_instance"] == instance - 1
                    })
                    .ok_or(ERROR)?;
                if operation["start_ns"].as_u64().ok_or(ERROR)?
                    < previous["at_ns"].as_u64().ok_or(ERROR)?
                {
                    return Err(ERROR.into());
                }
            }
            let start = operation["start_ns"].as_u64().ok_or(ERROR)?;
            let end = operation["end_ns"].as_u64().ok_or(ERROR)?;
            if start < prior_end
                || end > dump_start(report, dump)?
                || before["page"] != operation["page"]
                || rule[1] == "same" && after["page"] != operation["page"]
            {
                return Err(format!("{ERROR}: {}", comparison["site"]));
            }
            let at = after["history_cursor"].as_u64().ok_or(ERROR)? as usize;
            let role = if check_owner.0 == "seed_cases.run" && check_state.invocation == 2 {
                "served"
            } else {
                "tracer"
            };
            if rule[1] == "successor"
                && after["page"].as_u64() != pages.get(at).and_then(|p| p.get(role)).copied()
            {
                return Err(ERROR.into());
            }
            consumed.insert(*index);
            prior_end = end;
        }
    }
    for used in report["state_inputs"]["uses"].as_array().ok_or(ERROR)? {
        let Some(site) = used["predicate"]
            .as_str()
            .and_then(|p| key["state_comparison_sources"][p]["operation"].as_str())
            .and_then(|s| s.strip_prefix("window:"))
        else {
            continue;
        };
        let count = key["state_operation_windows"][site]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or(ERROR)?;
        let matching: Vec<_> = rows
            .iter()
            .enumerate()
            .filter(|(_, r)| r["site"] == site && r["case"] == used["case"])
            .collect();
        let instance = used["instance"].as_u64().filter(|n| *n > 0).ok_or(ERROR)? as usize;
        let (index, row) = matching.get(instance - 1).ok_or(ERROR)?;
        if row["call_count"] != count
            || row["timeout_ns"]
                != key["file_action_timeouts"]
                    .get(site)
                    .cloned()
                    .unwrap_or(Value::Null)
        {
            return Err(ERROR.into());
        }
        consumed.insert(*index);
    }
    if consumed.len() != rows.len() {
        return Err(format!("{ERROR}: unmatched operation"));
    }
    Ok(())
}

pub fn dump_start(report: &Value, dump: &Value) -> Result<u64, String> {
    let queries = report["file_dump_queries"].as_array().ok_or(ERROR)?;
    let mut matches = queries.iter().filter(|q| q["source"] == dump["source"]);
    let query = matches.next().ok_or(ERROR)?;
    let start = query["start_ns"].as_u64().ok_or(ERROR)?;
    let end = query["end_ns"].as_u64().ok_or(ERROR)?;
    if end < start || end > dump["at_ns"].as_u64().ok_or(ERROR)? || matches.next().is_some() {
        return Err(ERROR.into());
    }
    Ok(start)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_dump_must_belong_to_its_exact_query_invocation() {
        let cap = crate::cdp::test_dump_original(json!({}));
        test_dump_source(900_001, 1);
        assert!(original_dump_matches(900_001, 1, &cap));
        {
            let mut rows = QUERIES.lock().unwrap();
            let row = rows.iter_mut().find(|r| r["source"] == 900_001).unwrap();
            row["start_ns"] = json!(1);
            row["end_ns"] = json!(1);
        }
        assert!(!original_dump_matches(900_001, 1, &cap));
        {
            let mut rows = QUERIES.lock().unwrap();
            let row = rows.iter_mut().find(|r| r["source"] == 900_001).unwrap();
            row["start_ns"] = json!(0);
            row["end_ns"] = json!(0);
        }
        assert!(original_dump_matches(900_001, 1, &cap));
        assert!(!original_dump_matches(900_001, 2, &cap));
    }
    #[test]
    fn each_real_operation_separates_its_original_saved_and_fresh_observations() {
        let f: Value =
            serde_json::from_str(include_str!("../testdata/operation-windows.json")).unwrap();
        let report = &f["report"];
        let key = &f["inventory"];
        validate_with(report, key).unwrap();
        for (pointer, value) in [
            ("/file_captures/1/at_ns", json!(21)),
            ("/file_captures/2/at_ns", json!(20)),
            ("/file_dump_queries/1/start_ns", json!(20)),
            ("/operation_windows/1/start_ns", json!(19)),
            ("/operation_windows/1/page", json!(8)),
            ("/operation_windows/1/worker", json!(4)),
            ("/operation_windows/1/input_ok", json!(false)),
            ("/operation_windows/1/completed", json!(false)),
            ("/operation_windows/1/call_count", json!(2)),
            ("/operation_windows/1/end_cursor", json!(12)),
        ] {
            let mut bad = report.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(validate_with(&bad, key).is_err(), "{pointer}");
        }
        let mut duplicate = report.clone();
        duplicate["operation_windows"][1] = duplicate["operation_windows"][0].clone();
        duplicate["operation_windows"][1]["source"] = json!(2);
        assert!(validate_with(&duplicate, key).is_err());
        for action in ["missing", "extra", "order"] {
            let mut bad = report.clone();
            let rows = bad["operation_windows"].as_array_mut().unwrap();
            match action {
                "missing" => {
                    rows.pop();
                }
                "extra" => rows.push(rows[2].clone()),
                _ => rows.swap(0, 1),
            }
            assert!(validate_with(&bad, key).is_err(), "{action}");
        }
        let mut left = report.clone();
        for row in left["file_comparisons"].as_array_mut().unwrap() {
            let before = row["right"].clone();
            row["right"] = row["left"].clone();
            row["left"] = before;
        }
        let mut left_key = key.clone();
        left_key["file_action_windows"]["goal_cases.a008.1"][0] = json!("left");
        validate_with(&left, &left_key).unwrap();
        assert!(validate_with(&left, key).is_err());
        let mut empty = key.clone();
        empty["file_action_windows"]["goal_cases.a008.1"][2] = json!([]);
        assert!(validate_with(report, &empty).is_err());
        validate_with(report, key).unwrap();
    }
}
