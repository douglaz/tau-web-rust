//! Original fixture request-counter baselines, dispatches and same-attempt comparisons.
use super::{Run, Tab, Worker, completion, history, observer};
use serde_json::{Value, json};
use std::sync::Mutex;
struct Source {
    site: &'static str,
    path: String,
    target: usize,
    value: Value,
    used: bool,
}
static SOURCES: Mutex<Vec<Source>> = Mutex::new(Vec::new());
use std::sync::atomic::{AtomicUsize, Ordering};
static UNMATCHED: AtomicUsize = AtomicUsize::new(0);
fn record_count(count: usize) {
    if count != 1 {
        UNMATCHED.fetch_add(1, Ordering::Relaxed);
    }
}

fn path(site: &str) -> &str {
    match site {
        "inference.late_mint.wait" => "/keys",
        "inference.withheld_sweep.wait" | "inference.bounded_revoke.wait" => "/revoke",
        "inference.held_completion.wait"
        | "lifecycle.boundaries.wait_completion"
        | "lifecycle.aggregate_cap.wait_completion" => "/completion",
        _ => "",
    }
}
pub fn baseline(site: &'static str, run: &Run<'_>, actual_path: &str) -> usize {
    let start = completion::now();
    let cursor = history::cursor();
    let before = run.aggregator.count(actual_path);
    let mut sources = SOURCES.lock().unwrap();
    let id = sources.len() + 1;
    sources.push(Source{site,path:actual_path.into(),target:before+1,used:false,value:json!({"source":id,"site":site,"path_ok":actual_path==path(site)&&!path(site).is_empty(),"capture":{"start_ns":start,"end_ns":completion::now(),"history_cursor":cursor},"bindings":[],"triggers":[],"uses":[],"matches":[]})});
    before
}
pub fn bind(site: &str, actual_path: &str, target: usize) {
    let mut sources = SOURCES.lock().unwrap();
    let selected: Vec<_> = sources
        .iter()
        .enumerate()
        .filter(|(_, s)| s.site == site && !s.used)
        .map(|(i, _)| i)
        .collect();
    record_count(selected.len());
    let unique = selected.len() == 1;
    for i in selected {
        let s = &mut sources[i];
        let ok = unique && s.path == actual_path && s.target == target;
        s.value["bindings"]
            .as_array_mut()
            .unwrap()
            .push(json!({"ok":ok,"at_ns":completion::now(),"history_cursor":history::cursor()}));
    }
}
fn start(worker: &Worker, ok: bool) -> (u64, usize, Value) {
    let (worker_id, page) = history::worker_identity(&worker.session);
    (
        completion::now(),
        history::cursor(),
        json!({"worker":worker_id,"page":page,"ok":ok&&observer::source_worker_matches(worker)}),
    )
}
fn triggered(site: &str, start: (u64, usize, Value)) {
    let mut sources = SOURCES.lock().unwrap();
    let count = sources.iter().filter(|s| s.site == site && !s.used).count();
    record_count(count);
    for s in sources.iter_mut().filter(|s| s.site == site && !s.used) {
        let mut value = start.2.clone();
        value["ok"] = json!(value["ok"] == true && count == 1);
        value["start_ns"] = json!(start.0);
        value["end_ns"] = json!(completion::now());
        value["start_cursor"] = json!(start.1);
        value["end_cursor"] = json!(history::cursor());
        s.value["triggers"].as_array_mut().unwrap().push(value);
    }
}
fn expression(site: &str) -> String {
    match site {
 "inference.held_completion.wait"=>format!("self.heldCompletion=m.inference_request({});return true;",json!(json!({"machine":"fixture","messages":[{"role":"user","content":"held completion"}]}).to_string())),
 "inference.bounded_revoke.wait"=>"self.boundedEnd=m.end_sessions();return true;".into(),
 "inference.late_mint.wait"=>format!("self.lateMint=m.inference_request({});return true;",json!(json!({"machine":"fixture","messages":[{"role":"user","content":"late mint"}]}).to_string())),
 "lifecycle.boundaries.wait_completion"=>"self.pendingLifecycle=m.inference_request(JSON.stringify({machine:'fixture',messages:[{role:'user',content:'late fixture turn'}]}));self.oldGeneration=m.publication_generation();return true;".into(),
 "lifecycle.aggregate_cap.wait_completion"=>"self.capInFlight=m.inference_request(JSON.stringify({machine:'fixture',messages:[{role:'user',content:'in flight charge'}]}));return true;".into(),_=>String::new()}
}
pub async fn module(
    site: &'static str,
    run: &Run<'_>,
    worker: &Worker,
    actual: &str,
) -> Result<Value, String> {
    let expected = expression(site);
    let start = start(worker, !expected.is_empty() && actual == expected);
    let result = super::inference_cases::module(run, worker, actual).await;
    triggered(site, start);
    result
}
pub async fn unlock(
    site: &'static str,
    run: &Run<'_>,
    tab: &Tab,
    worker: &Worker,
    kind: &str,
    pass: &str,
) -> Result<super::view_inputs::View, String> {
    let start = start(
        worker,
        site == "inference.withheld_sweep.wait"
            && kind == "unlock"
            && pass == super::PASSPHRASE
            && history::page_id(&tab.session) == history::worker_identity(&worker.session).1,
    );
    let result = run.submit(tab, kind, pass).await;
    triggered(site, start);
    result
}
pub fn use_input(site: &str, call: usize, actual_path: &str, target: usize) -> bool {
    let mut sources = SOURCES.lock().unwrap();
    let selected: Vec<_> = sources
        .iter()
        .enumerate()
        .filter(|(_, s)| s.site == site && !s.used)
        .map(|(i, _)| i)
        .collect();
    record_count(selected.len());
    let unique = selected.len() == 1;
    let mut all = unique;
    for i in selected {
        let s = &mut sources[i];
        let ok = unique && s.path == actual_path && s.target == target;
        s.used = true;
        all &= ok;
        s.value["uses"].as_array_mut().unwrap().push(json!({"call":call,"ok":ok,"at_ns":completion::now(),"history_cursor":history::cursor()}));
    }
    all
}
pub fn ready(call: usize, run: &Run<'_>, actual_path: &str, target: usize, attempt: usize) -> bool {
    let before = completion::now();
    let count = run.aggregator.count(actual_path);
    let ready = count >= target;
    let mut sources = SOURCES.lock().unwrap();
    record_count(
        sources
            .iter()
            .filter(|s| {
                s.value["uses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|u| u["call"] == call)
            })
            .count(),
    );
    for s in sources.iter_mut().filter(|s| {
        s.value["uses"]
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["call"] == call)
    }) {
        let ok = s.path == actual_path && s.target == target;
        s.value["matches"].as_array_mut().unwrap().push(json!({"attempt":attempt,"ok":ok,"ready":ready,"start_ns":before,"end_ns":completion::now(),"history_cursor":history::cursor()}));
    }
    ready
}
pub fn snapshot() -> Value {
    json!(
        SOURCES
            .lock()
            .unwrap()
            .iter()
            .map(|s| &s.value)
            .collect::<Vec<_>>()
    )
}
pub fn unbound() -> usize {
    SOURCES.lock().unwrap().iter().filter(|s| !s.used).count() + UNMATCHED.load(Ordering::Relaxed)
}
fn owner_position(site: &str) -> Option<(&str, &str, usize, usize)> {
    match site {
        "inference.held_completion.wait" => {
            Some(("inference_cases.run", "inference_cases.c005.p001", 0, 0))
        }
        "inference.late_mint.wait" => {
            Some(("inference_cases.run", "inference_cases.c009.p001", 1, 1))
        }
        "inference.withheld_sweep.wait" => {
            Some(("inference_cases.run", "inference_cases.c011.p001", 2, 3))
        }
        "inference.bounded_revoke.wait" => {
            Some(("inference_cases.run", "inference_cases.c012.p001", 0, 0))
        }
        "lifecycle.boundaries.wait_completion" => {
            Some(("lifecycle_cases.run", "lifecycle_cases.c004.p001", 0, 0))
        }
        "lifecycle.aggregate_cap.wait_completion" => {
            Some(("lifecycle_cases.run", "lifecycle_cases.c009.p001", 0, 0))
        }
        _ => None,
    }
}
pub fn validate(report: &Value) -> Result<(), String> {
    let fail = || "original counter baseline/dispatch/use history mismatch".to_string();
    if report["counter_unbound_inputs"].as_u64() != Some(0) {
        return Err(fail());
    }
    let sources = report["counter_inputs"].as_array().ok_or_else(fail)?;
    let calls = report["observer_calls"].as_array().ok_or_else(fail)?;
    let expected: Vec<_> = calls
        .iter()
        .enumerate()
        .filter(|(_, c)| c["kind"] == "inference.wait_count")
        .collect();
    if sources.len() != expected.len() {
        return Err(fail());
    }
    let states = super::reader_checks::caller_states(report);
    let positions = observer::source_positions(report);
    let pages = history::source_page_states(report)?;
    let workers = history::worker_states(report);
    let history_events = report["helper_history"].as_array().ok_or_else(fail)?;
    let within = |value: &Value, at: u64| {
        let Some(index) = value
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .filter(|i| *i <= history_events.len())
        else {
            return false;
        };
        (index == 0 || history_events[index - 1]["at_ns"].as_u64().unwrap() <= at)
            && (index == history_events.len()
                || history_events[index]["at_ns"].as_u64().unwrap() >= at)
    };
    let mut previous = 0;
    for (index, (s, (call_index, c))) in sources.iter().zip(expected).enumerate() {
        if s.as_object().is_none_or(|o| o.len() != 8)
            || s["source"].as_u64() != Some((index + 1) as u64)
            || s["site"] != c["site"]
            || s["path_ok"] != true
            || !s["path_ok"].is_boolean()
        {
            return Err(fail());
        }
        let site = s["site"].as_str().ok_or_else(fail)?;
        let (scenario, case, capture_position, use_position) =
            owner_position(site).ok_or_else(fail)?;
        let scenario = if site == "lifecycle.boundaries.wait_completion"
            && states[c["start_cursor"].as_u64().unwrap() as usize]
                .owner
                .as_ref()
                .is_some_and(|o| o.0 == "lifecycle_cases.selected")
        {
            "lifecycle_cases.selected"
        } else {
            scenario
        };
        let owner = Some((scenario.into(), "inside".into(), case.into()));
        let cap = &s["capture"];
        let start = cap["start_ns"].as_u64().ok_or_else(fail)?;
        let end = cap["end_ns"].as_u64().ok_or_else(fail)?;
        let cursor = cap["history_cursor"].as_u64().ok_or_else(fail)? as usize;
        if cap.as_object().is_none_or(|o| o.len() != 3)
            || start < previous
            || start > end
            || cursor >= states.len()
            || states[cursor].owner != owner
            || positions[cursor] != (capture_position, true)
            || !within(&cap["history_cursor"], start)
            || !within(&cap["history_cursor"], end)
        {
            return Err(fail());
        }
        let bindings = s["bindings"].as_array().ok_or_else(fail)?;
        let triggers = s["triggers"].as_array().ok_or_else(fail)?;
        let uses = s["uses"].as_array().ok_or_else(fail)?;
        if bindings.len() != 1 || triggers.len() != 1 || uses.len() != 1 {
            return Err(fail());
        }
        let b = &bindings[0];
        let t = &triggers[0];
        let u = &uses[0];
        let bound = b["at_ns"].as_u64().ok_or_else(fail)?;
        let ts = t["start_ns"].as_u64().ok_or_else(fail)?;
        let te = t["end_ns"].as_u64().ok_or_else(fail)?;
        let tc = t["start_cursor"].as_u64().ok_or_else(fail)? as usize;
        let ec = t["end_cursor"].as_u64().ok_or_else(fail)? as usize;
        let used = u["at_ns"].as_u64().ok_or_else(fail)?;
        let cc = c["start_cursor"].as_u64().unwrap() as usize;
        if !within(&b["history_cursor"], bound)
            || !within(&t["start_cursor"], ts)
            || !within(&t["end_cursor"], te)
            || !within(&u["history_cursor"], used)
        {
            return Err(fail());
        }
        if b.as_object().is_none_or(|o| o.len() != 3)
            || b["ok"] != true
            || b["history_cursor"] != cap["history_cursor"]
            || end > bound
            || bound > ts
            || ts > te
            || te > c["start_ns"].as_u64().unwrap()
            || tc >= states.len()
            || ec >= states.len()
            || states[tc].owner != owner
            || states[ec].owner != owner
            || positions[tc] != (capture_position, true)
            || positions[ec] != (use_position, true)
            || t.as_object().is_none_or(|o| o.len() != 7)
            || t["ok"] != true
            || !t["ok"].is_boolean()
        {
            return Err(fail());
        }
        let page = t["page"].as_u64().ok_or_else(fail)?;
        let worker = t["worker"].as_u64().ok_or_else(fail)?;
        if pages[tc].get("tracer") != Some(&page)
            || workers[tc].get(&page) != Some(&worker)
            || pages[ec].get("tracer") != Some(&page)
            || workers[ec].get(&page) != Some(&worker)
            || u.as_object().is_none_or(|o| o.len() != 4)
            || u["ok"] != true
            || !u["ok"].is_boolean()
            || u["call"].as_u64() != Some((call_index + 1) as u64)
            || u["history_cursor"] != c["start_cursor"]
            || used < c["start_ns"].as_u64().unwrap()
            || used > c["end_ns"].as_u64().unwrap()
            || states[cc].owner != owner
            || positions[cc] != (use_position, true)
        {
            return Err(fail());
        }
        let matches = s["matches"].as_array().ok_or_else(fail)?;
        let polls = c["polls"].as_array().unwrap();
        if matches.len() != polls.len() {
            return Err(fail());
        }
        for (m, p) in matches.iter().zip(polls) {
            let ms = m["start_ns"].as_u64().ok_or_else(fail)?;
            let me = m["end_ns"].as_u64().ok_or_else(fail)?;
            if m.as_object().is_none_or(|o| o.len() != 6)
                || m["attempt"] != p["attempt"]
                || !m["attempt"].is_u64()
                || m["ok"] != true
                || !m["ok"].is_boolean()
                || m["ready"] != p["ready"]
                || !m["ready"].is_boolean()
                || ms < p["start_ns"].as_u64().unwrap()
                || ms > me
                || me > p["end_ns"].as_u64().unwrap()
                || m["history_cursor"] != p["start_cursor"]
                || !within(&m["history_cursor"], ms)
                || !within(&m["history_cursor"], me)
            {
                return Err(fail());
            }
        }
        if polls
            .first()
            .is_none_or(|p| used > p["start_ns"].as_u64().unwrap())
        {
            return Err(fail());
        }
        previous = c["end_ns"].as_u64().unwrap();
    }
    Ok(())
}
