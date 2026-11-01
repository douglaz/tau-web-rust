//! Source identities and actual operands for the three original dynamic session waits.
use super::{Run, Tab, Worker, completion, history, observer};
use serde_json::{Value, json};
use std::sync::Mutex;
#[derive(Clone)]
pub struct Session {
    raw: String,
    source: usize,
}
impl std::ops::Deref for Session {
    type Target = str;
    fn deref(&self) -> &str {
        session_borrow(self);
        &self.raw
    }
}
impl std::fmt::Display for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        session_borrow(self);
        self.raw.fmt(f)
    }
}
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        session_borrow(self);
        self.raw.fmt(f)
    }
}
impl serde::Serialize for Session {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        session_borrow(self);
        self.raw.serialize(s)
    }
}
impl PartialEq<Session> for Value {
    fn eq(&self, s: &Session) -> bool {
        session_borrow(s);
        self == &s.raw
    }
}
struct Query {
    attempt: usize,
    value: Value,
    used: bool,
}
struct Source {
    site: &'static str,
    raw: Option<String>,
    worker: Worker,
    value: Value,
    call: Option<usize>,
    queries: Vec<Query>,
    inspects: Vec<Query>,
}
static SOURCES: Mutex<Vec<Source>> = Mutex::new(Vec::new());
use std::sync::atomic::{AtomicUsize, Ordering};
static UNMATCHED: AtomicUsize = AtomicUsize::new(0);
fn session_borrow(session: &Session) {
    let sources = SOURCES.lock().unwrap();
    let valid = session.source == sources.len()
        && session.source > 0
        && sources
            .last()
            .is_some_and(|s| s.raw.as_deref() == Some(&session.raw));
    if !valid {
        UNMATCHED.fetch_add(1, Ordering::Relaxed);
    }
}
fn record_count(count: usize) {
    if count != 1 {
        UNMATCHED.fetch_add(1, Ordering::Relaxed);
    }
}

const HIDDEN: &str = "lifecycle.hidden_goal.done";
pub fn supported(site: &str) -> bool {
    matches!(
        site,
        "lifecycle.hidden_goal.done"
            | "lifecycle_repairs.document.pending_cleared"
            | "lifecycle_repairs.source_append.completed"
    )
}
pub async fn state(site: &'static str, run: &Run<'_>, worker: &Worker) -> Result<Value, String> {
    let start = completion::now();
    let cursor = history::cursor();
    let value = run.inspect(worker).await?;
    let raw = if site == HIDDEN {
        value["sessions"][0]["identity"].as_str()
    } else {
        value["sessions"]
            .as_array()
            .and_then(|s| s.iter().find(|s| s["bound_set"] == json!(["fixture"])))
            .and_then(|s| s["identity"].as_str())
    }
    .map(str::to_owned);
    let (worker_id, page) = history::worker_identity(&worker.session);
    let mut sources = SOURCES.lock().unwrap();
    let id = sources.len() + 1;
    sources.push(Source{site,raw,worker:worker.clone(),call:None,queries:Vec::new(),inspects:Vec::new(),value:json!({"source":id,"site":site,"capture":{"worker":worker_id,"page":page,"ok":supported(site)&&observer::source_worker_matches(worker),"start_ns":start,"end_ns":completion::now(),"start_cursor":cursor,"end_cursor":history::cursor()},"selections":[],"triggers":[],"uses":[],"queries":[],"predicates":[]})});
    Ok(value)
}
pub fn selected(site: &str, raw: String) -> Session {
    let mut sources = SOURCES.lock().unwrap();
    let ids: Vec<_> = sources
        .iter()
        .enumerate()
        .filter(|(_, s)| s.site == site && s.call.is_none())
        .map(|(i, _)| i)
        .collect();
    record_count(ids.len());
    let unique = ids.len() == 1;
    let mut origin = 0;
    for id in ids {
        let s = &mut sources[id];
        let ok = unique && s.raw.as_deref() == Some(raw.as_str());
        s.value["selections"]
            .as_array_mut()
            .unwrap()
            .push(json!({"ok":ok,"at_ns":completion::now(),"history_cursor":history::cursor()}));
        origin = id + 1;
    }
    Session {
        raw,
        source: origin,
    }
}
pub async fn entry(site: &str, run: &Run<'_>, tab: &Tab, actual: &str) -> Result<Value, String> {
    let start = completion::now();
    let cursor = history::cursor();
    let page = history::page_id(&tab.session);
    let expected = {
        let sources = SOURCES.lock().unwrap();
        let matches: Vec<_> = sources
            .iter()
            .filter(|s| s.site == site && s.call.is_none())
            .collect();
        record_count(matches.len());
        if matches.len() != 1 {
            None
        } else {
            let s = matches[0];
            s.raw.as_ref().map(|raw|if site==HIDDEN {format!("(()=>{{const card=document.querySelector('[data-goal-card=\"{}\"]');card.querySelector('[data-goal-text]').value='Read the fixture service output';card.querySelector('[data-goal-enter]').click();return true;}})()",raw)}else{let text=if site=="lifecycle_repairs.document.pending_cleared"{"Read the scheduled document"}else{"Read after source append"};let source=format!("{}/document",run.aggregator.origin);format!("(()=>{{const card=document.querySelector('[data-machine=fixture]');card.querySelector('[data-goal-text]').value='{text}';card.querySelector('[data-document-source]').value={};card.querySelector('[data-goal-enter]').click();return true;}})()",json!(source))})
        }
    };
    let result = run.browser.evaluate(&tab.session, actual).await;
    let mut sources = SOURCES.lock().unwrap();
    for s in sources
        .iter_mut()
        .filter(|s| s.site == site && s.call.is_none())
    {
        let ok = expected.as_deref() == Some(actual) && s.value["capture"]["page"] == page;
        s.value["triggers"].as_array_mut().unwrap().push(json!({"page":page,"ok":ok,"start_ns":start,"end_ns":completion::now(),"start_cursor":cursor,"end_cursor":history::cursor()}));
    }
    result
}
pub fn use_input(site: &str, call: usize) {
    let mut sources = SOURCES.lock().unwrap();
    record_count(
        sources
            .iter()
            .filter(|s| s.site == site && s.call.is_none())
            .count(),
    );
    for s in sources
        .iter_mut()
        .filter(|s| s.site == site && s.call.is_none())
    {
        s.call = Some(call);
        s.value["uses"].as_array_mut().unwrap().push(
            json!({"call":call,"at_ns":completion::now(),"history_cursor":history::cursor()}),
        );
    }
}
pub fn candidate(call: usize, attempt: usize, state: &Value) {
    let mut sources = SOURCES.lock().unwrap();
    record_count(
        sources
            .iter()
            .filter(|s| {
                s.call == Some(call) && s.site == "lifecycle_repairs.source_append.completed"
            })
            .count(),
    );
    for s in sources
        .iter_mut()
        .filter(|s| s.call == Some(call) && s.site == "lifecycle_repairs.source_append.completed")
    {
        s.inspects.push(Query {
            attempt,
            value: state.clone(),
            used: false,
        });
    }
}
pub fn query(
    source: (usize, usize),
    session: &Session,
    receiver: (Option<&Worker>, &str),
    result: (&str, &Value, u64),
) {
    let (call, attempt) = source;
    let (worker, page) = receiver;
    let (actual, value, start) = result;
    let mut sources = SOURCES.lock().unwrap();
    record_count(sources.iter().filter(|s| s.call == Some(call)).count());
    for (index, s) in sources
        .iter_mut()
        .enumerate()
        .filter(|(_, s)| s.call == Some(call))
    {
        let expected=s.raw.as_ref().map(|raw|if s.site==HIDDEN {format!("document.querySelector('[data-goal-outcome=\"{}\"]')?.textContent.includes('done')??false",raw)}else{format!("return JSON.parse(m.test_document_state({}));",json!(raw))});
        let ok = session.source == index + 1
            && s.raw.as_deref() == Some(&session.raw)
            && expected.as_deref() == Some(actual)
            && worker.is_none_or(|worker| worker == &s.worker)
            && worker
                .map(|w| history::worker_identity(&w.session).1)
                .unwrap_or_else(|| history::page_id(page))
                == s.value["capture"]["page"];
        s.queries.push(Query {
            attempt,
            value: value.clone(),
            used: false,
        });
        s.value["queries"].as_array_mut().unwrap().push(json!({"attempt":attempt,"ok":ok,"start_ns":start,"end_ns":completion::now(),"history_cursor":history::cursor()}));
    }
}
pub fn predicate(
    hidden: bool,
    call: usize,
    attempt: usize,
    session: &Session,
    document: &Value,
    state: Option<&Value>,
) -> bool {
    let ready = if hidden {
        *document == true
    } else if let Some(state) = state {
        state["goals"]
            .as_array()
            .is_some_and(|gs| gs.iter().any(|g| g["session"] == session.raw))
            && document["pending"] == false
    } else {
        document["pending"] == false
    };
    let mut sources = SOURCES.lock().unwrap();
    record_count(sources.iter().filter(|s| s.call == Some(call)).count());
    for (index, s) in sources
        .iter_mut()
        .enumerate()
        .filter(|(_, s)| s.call == Some(call))
    {
        let query_ids: Vec<_> = s
            .queries
            .iter()
            .enumerate()
            .filter(|(_, q)| q.attempt == attempt && !q.used)
            .map(|(i, _)| i)
            .collect();
        let mut ok = session.source == index + 1
            && s.raw.as_deref() == Some(&session.raw)
            && query_ids.len() == 1
            && s.queries[query_ids[0]].value == *document;
        for id in query_ids {
            s.queries[id].used = true;
        }
        let inspect_ids: Vec<_> = s
            .inspects
            .iter()
            .enumerate()
            .filter(|(_, q)| q.attempt == attempt && !q.used)
            .map(|(i, _)| i)
            .collect();
        if let Some(state) = state {
            ok &= inspect_ids.len() == 1 && s.inspects[inspect_ids[0]].value == *state;
        } else {
            ok &= inspect_ids.is_empty();
        }
        for id in inspect_ids {
            s.inspects[id].used = true;
        }
        s.value["predicates"].as_array_mut().unwrap().push(json!({"attempt":attempt,"ok":ok,"ready":ready,"at_ns":completion::now(),"history_cursor":history::cursor()}));
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
    SOURCES
        .lock()
        .unwrap()
        .iter()
        .map(|s| {
            usize::from(s.call.is_none())
                + s.queries.iter().filter(|q| !q.used).count()
                + s.inspects.iter().filter(|q| !q.used).count()
        })
        .sum::<usize>()
        + UNMATCHED.load(Ordering::Relaxed)
}
pub fn validate(report: &Value) -> Result<(), String> {
    let fail = || "original dynamic session source/trigger/operand mismatch".to_string();
    if report["session_operand_unbound"].as_u64() != Some(0) {
        return Err(fail());
    }
    let rows = report["session_operands"].as_array().ok_or_else(fail)?;
    let calls = report["observer_calls"].as_array().ok_or_else(fail)?;
    let expected: Vec<_> = calls
        .iter()
        .enumerate()
        .filter(|(_, c)| c["site"].as_str().is_some_and(supported))
        .collect();
    if rows.len() != expected.len() {
        return Err(fail());
    }
    let states = super::reader_checks::caller_states(report);
    let positions = observer::source_positions(report);
    let pages = history::source_page_states(report)?;
    let workers = history::worker_states(report);
    let events = report["helper_history"].as_array().unwrap();
    let mut previous = 0;
    for (index, (row, (call_index, c))) in rows.iter().zip(expected).enumerate() {
        let site = c["site"].as_str().unwrap();
        let hidden = site == HIDDEN;
        let cp = if hidden { 0 } else { 6 };
        let bp = if hidden { 0 } else { 7 };
        let up = if site == "lifecycle_repairs.document.pending_cleared" {
            8
        } else {
            bp
        };
        let cc = c["start_cursor"].as_u64().unwrap() as usize;
        let owner = &states[cc].owner;
        let check = |v: &Value, t: u64, p: usize| -> Result<usize, String> {
            let cursor = v.as_u64().ok_or_else(fail)? as usize;
            if cursor >= states.len()
                || states[cursor].owner != *owner
                || positions[cursor] != (p, true)
                || cursor > 0 && events[cursor - 1]["at_ns"].as_u64().unwrap() > t
                || cursor < events.len() && events[cursor]["at_ns"].as_u64().unwrap() < t
            {
                return Err(fail());
            }
            Ok(cursor)
        };
        if row.as_object().is_none_or(|o| o.len() != 8)
            || row["source"].as_u64() != Some((index + 1) as u64)
            || row["site"] != c["site"]
        {
            return Err(fail());
        }
        let cap = &row["capture"];
        if cap.as_object().is_none_or(|o| o.len() != 7)
            || cap["ok"] != true
            || !cap["ok"].is_boolean()
        {
            return Err(fail());
        }
        let start = cap["start_ns"].as_u64().ok_or_else(fail)?;
        let end = cap["end_ns"].as_u64().ok_or_else(fail)?;
        let cursor = check(&cap["start_cursor"], start, cp)?;
        let last = check(&cap["end_cursor"], end, cp)?;
        let worker = cap["worker"].as_u64().ok_or_else(fail)?;
        let page = cap["page"].as_u64().ok_or_else(fail)?;
        if start < previous
            || start > end
            || cursor != last
            || pages[cursor].get("tracer") != Some(&page)
            || workers[cursor].get(&page) != Some(&worker)
        {
            return Err(fail());
        }
        let selections = row["selections"].as_array().ok_or_else(fail)?;
        let triggers = row["triggers"].as_array().ok_or_else(fail)?;
        let uses = row["uses"].as_array().ok_or_else(fail)?;
        if selections.len() != 1 || triggers.len() != 1 || uses.len() != 1 {
            return Err(fail());
        }
        let b = &selections[0];
        let t = &triggers[0];
        let u = &uses[0];
        let bound = b["at_ns"].as_u64().ok_or_else(fail)?;
        check(&b["history_cursor"], bound, bp)?;
        let ts = t["start_ns"].as_u64().ok_or_else(fail)?;
        let te = t["end_ns"].as_u64().ok_or_else(fail)?;
        let tc = check(&t["start_cursor"], ts, bp)?;
        let ec = check(&t["end_cursor"], te, bp)?;
        let used = u["at_ns"].as_u64().ok_or_else(fail)?;
        if b.as_object().is_none_or(|o| o.len() != 3)
            || b["ok"] != true
            || !b["ok"].is_boolean()
            || end > bound
            || bound > ts
            || ts > te
            || te > c["start_ns"].as_u64().unwrap()
            || t.as_object().is_none_or(|o| o.len() != 6)
            || t["ok"] != true
            || !t["ok"].is_boolean()
            || t["page"] != page
            || tc != ec
            || u.as_object().is_none_or(|o| o.len() != 3)
            || u["call"].as_u64() != Some((call_index + 1) as u64)
            || u["history_cursor"] != c["start_cursor"]
            || positions[cc] != (up, true)
            || used < c["start_ns"].as_u64().unwrap()
            || used > c["end_ns"].as_u64().unwrap()
        {
            return Err(fail());
        }
        if hidden {
            let recorded: Vec<_> = calls
                .iter()
                .filter(|r| {
                    r["site"] == "lifecycle.hidden_goal.recorded"
                        && states[r["start_cursor"].as_u64().unwrap() as usize].owner == *owner
                })
                .collect();
            if recorded.len() != 1
                || te > recorded[0]["start_ns"].as_u64().unwrap()
                || recorded[0]["end_ns"].as_u64().unwrap() > c["start_ns"].as_u64().unwrap()
            {
                return Err(fail());
            }
        }
        let queries = row["queries"].as_array().ok_or_else(fail)?;
        let predicates = row["predicates"].as_array().ok_or_else(fail)?;
        let polls = c["polls"].as_array().unwrap();
        if queries.len() != polls.len()
            || predicates.len() != polls.len()
            || polls
                .first()
                .is_none_or(|p| used > p["start_ns"].as_u64().unwrap())
        {
            return Err(fail());
        }
        for ((q, r), p) in queries.iter().zip(predicates).zip(polls) {
            let qs = q["start_ns"].as_u64().ok_or_else(fail)?;
            let qe = q["end_ns"].as_u64().ok_or_else(fail)?;
            let at = r["at_ns"].as_u64().ok_or_else(fail)?;
            if q.as_object().is_none_or(|o| o.len() != 5)
                || r.as_object().is_none_or(|o| o.len() != 5)
                || q["ok"] != true
                || !q["ok"].is_boolean()
                || r["ok"] != true
                || !r["ok"].is_boolean()
                || q["attempt"] != p["attempt"]
                || !q["attempt"].is_u64()
                || r["attempt"] != p["attempt"]
                || !r["attempt"].is_u64()
                || r["ready"] != p["ready"]
                || !r["ready"].is_boolean()
                || qs < p["start_ns"].as_u64().unwrap()
                || qs > qe
                || qe > at
                || at > p["end_ns"].as_u64().unwrap()
                || q["history_cursor"] != p["start_cursor"]
                || r["history_cursor"] != p["start_cursor"]
            {
                return Err(fail());
            }
        }
        previous = c["end_ns"].as_u64().unwrap();
    }
    Ok(())
}
