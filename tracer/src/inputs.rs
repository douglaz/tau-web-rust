//! Private original input lifetimes. Receipts contain identity and equality, never values.
use super::{completion, history};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Clone)]
pub struct Session {
    raw: String,
    source: usize,
}
impl Session {
    pub fn original_matches(&self) -> bool {
        SOURCES
            .lock()
            .unwrap()
            .get(self.source.saturating_sub(1))
            .is_some_and(|s| matches!(&s.raw, Raw::Session(raw) if raw == &self.raw))
    }
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
impl PartialEq<&Session> for Value {
    fn eq(&self, s: &&Session) -> bool {
        session_borrow(s);
        self == &s.raw
    }
}

enum Raw {
    Json(Value),
    Files(super::reader::Files),
    Session(String),
}
struct Source {
    kind: &'static str,
    site: String,
    raw: Raw,
    consumed: bool,
}
static SOURCES: Mutex<Vec<Source>> = Mutex::new(Vec::new());
static PENDING: Mutex<BTreeMap<(&'static str, String), Vec<usize>>> = Mutex::new(BTreeMap::new());
static EVENTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static CURRENT: Mutex<Option<usize>> = Mutex::new(None);
use std::sync::atomic::{AtomicUsize, Ordering};
static UNMATCHED: AtomicUsize = AtomicUsize::new(0);
fn session_borrow(session: &Session) {
    let sources = SOURCES.lock().unwrap();
    let valid = *CURRENT.lock().unwrap() == Some(session.source)
        && sources
            .get(session.source.saturating_sub(1))
            .is_some_and(|s| !s.consumed && matches!(&s.raw,Raw::Session(raw)if raw==&session.raw));
    if !valid {
        UNMATCHED.fetch_add(1, Ordering::Relaxed);
    }
}

struct Candidate {
    raw: Option<String>,
    at: u64,
    cursor: usize,
}
static CANDIDATES: Mutex<BTreeMap<usize, Vec<Candidate>>> = Mutex::new(BTreeMap::new());
fn event(mut v: Value) {
    v["at_ns"] = json!(completion::now());
    v["history_cursor"] = json!(history::cursor());
    EVENTS.lock().unwrap().push(v);
}
fn capture(
    kind: &'static str,
    site: &str,
    raw: Raw,
    call: Option<usize>,
    ok: bool,
    query: Option<Value>,
) -> usize {
    let mut sources = SOURCES.lock().unwrap();
    let id = sources.len() + 1;
    sources.push(Source {
        kind,
        site: site.into(),
        raw,
        consumed: false,
    });
    event(
        json!({"event":"capture","source":id,"kind":kind,"site":site,"call":call,"ok":ok,"query":query}),
    );
    id
}
pub fn value_input(kind: &'static str, site: &str, value: Value) {
    let id = capture(kind, site, Raw::Json(value), None, true, None);
    PENDING
        .lock()
        .unwrap()
        .entry((kind, site.into()))
        .or_default()
        .push(id);
}
pub fn files_input(site: &str, files: &super::reader::Files) {
    let id = capture("files", site, Raw::Files(files.clone()), None, true, None);
    PENDING
        .lock()
        .unwrap()
        .entry(("files", site.into()))
        .or_default()
        .push(id);
}
fn use_input(kind: &'static str, site: &str, call: usize, test: impl Fn(&Raw) -> bool) -> bool {
    let ids = PENDING
        .lock()
        .unwrap()
        .remove(&(kind, site.into()))
        .unwrap_or_default();
    let mut sources = SOURCES.lock().unwrap();
    let ok = ids.len() == 1 && test(&sources[ids[0] - 1].raw);
    for id in ids {
        let s = &mut sources[id - 1];
        let matches = ok && !s.consumed && s.kind == kind && s.site == site;
        s.consumed = true;
        event(json!({"event":"use","source":id,"kind":kind,"site":site,"call":call,"ok":matches}));
    }
    ok
}
pub fn value_matches(kind: &'static str, site: &str, call: usize, v: Value) -> bool {
    use_input(kind, site, call, |raw| matches!(raw,Raw::Json(x) if *x==v))
}
pub fn files_match(site: &str, call: usize, v: &super::reader::Files) -> bool {
    use_input(
        "files",
        site,
        call,
        |raw| matches!(raw,Raw::Files(x) if x==v),
    )
}
pub fn candidate(call: usize, state: &Value) {
    let raw = state["sessions"]
        .as_array()
        .and_then(|sessions| {
            sessions
                .iter()
                .find(|s| s["session_state"] != "ended" && s["bound_set"] == json!(["fixture"]))
        })
        .and_then(|s| s["identity"].as_str())
        .map(str::to_owned);
    CANDIDATES
        .lock()
        .unwrap()
        .entry(call)
        .or_default()
        .push(Candidate {
            raw,
            at: completion::now(),
            cursor: history::cursor(),
        });
}
fn retire(next: Option<usize>) {
    let current = CURRENT.lock().unwrap().take();
    if let Some(id) = current {
        SOURCES.lock().unwrap()[id - 1].consumed = true;
        event(json!({"event":"retire","source":id,"next":next}));
    }
}
pub fn session_input(call: usize, site: &str, raw: &str) -> Session {
    let candidates = CANDIDATES.lock().unwrap().remove(&call).unwrap_or_default();
    let ok = candidates
        .last()
        .is_some_and(|v| v.raw.as_deref() == Some(raw));
    let query=candidates.last().map(|last|json!({"at_ns":last.at,"history_cursor":last.cursor,"queries":candidates.iter().map(|v|json!({"at_ns":v.at,"history_cursor":v.cursor,"present":v.raw.is_some()})).collect::<Vec<_>>()}));
    let next = SOURCES.lock().unwrap().len() + 1;
    retire(Some(next));
    let id = capture(
        "session",
        site,
        Raw::Session(raw.into()),
        Some(call),
        ok,
        query,
    );
    *CURRENT.lock().unwrap() = Some(id);
    Session {
        raw: raw.into(),
        source: id,
    }
}
pub fn session_matches(call: usize, site: &str, s: &Session) -> bool {
    let sources = SOURCES.lock().unwrap();
    let ok = *CURRENT.lock().unwrap() == Some(s.source)
        && sources
            .get(s.source - 1)
            .is_some_and(|v| matches!(&v.raw,Raw::Session(raw) if raw==&s.raw));
    event(
        json!({"event":"use","source":s.source,"kind":"session","site":site,"call":call,"ok":ok}),
    );
    ok
}
pub fn finish() {
    retire(None);
}
pub fn snapshot() -> Value {
    json!(*EVENTS.lock().unwrap())
}
pub fn unbound() -> usize {
    SOURCES
        .lock()
        .unwrap()
        .iter()
        .filter(|s| !s.consumed)
        .count()
        + CANDIDATES.lock().unwrap().len()
        + UNMATCHED.load(Ordering::Relaxed)
}

pub fn validate(report: &Value) -> Result<(), String> {
    let fail = || "original input capture/use/lifetime mismatch".to_string();
    if report["original_unbound_inputs"].as_u64() != Some(0) {
        return Err(fail());
    }
    let events = report["original_input_history"]
        .as_array()
        .ok_or_else(fail)?;
    let calls = report["observer_calls"].as_array().ok_or_else(fail)?;
    let states = super::reader_checks::caller_states(report);
    let history_events = report["helper_history"].as_array().ok_or_else(fail)?;
    let positions = super::observer::source_positions(report);
    let mut sources: Vec<&Value> = Vec::new();
    let mut uses: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    let mut consumed = std::collections::BTreeSet::new();
    let mut current = None;
    let mut retired = None;
    let mut previous = 0;
    for (event_index, e) in events.iter().enumerate() {
        let at = e["at_ns"].as_u64().ok_or_else(fail)?;
        let cursor = e["history_cursor"].as_u64().ok_or_else(fail)? as usize;
        if at < previous
            || at > report["duration_ns"].as_u64().ok_or_else(fail)?
            || cursor >= states.len()
        {
            return Err(fail());
        }
        if cursor > 0 && history_events[cursor - 1]["at_ns"].as_u64().unwrap() > at
            || cursor < history_events.len()
                && history_events[cursor]["at_ns"].as_u64().unwrap() < at
        {
            return Err(fail());
        }
        previous = at;
        let source = e["source"].as_u64().ok_or_else(fail)? as usize;
        if retired.is_some() && (e["event"] != "capture" || e["kind"] != "session") {
            return Err(fail());
        }
        match e["event"].as_str() {
            Some("capture") => {
                if e.as_object().is_none_or(|o| {
                    o.len() != 9
                        || ![
                            "event",
                            "source",
                            "kind",
                            "site",
                            "call",
                            "ok",
                            "query",
                            "at_ns",
                            "history_cursor",
                        ]
                        .iter()
                        .all(|k| o.contains_key(*k))
                }) || source != sources.len() + 1
                    || e["ok"] != true
                    || !e["ok"].is_boolean()
                {
                    return Err(fail());
                }
                if retired.is_some_and(|id| id != source) {
                    return Err(fail());
                }
                retired = None;
                if e["kind"] == "session" {
                    if current.is_some() {
                        return Err(fail());
                    }
                    let id = e["call"].as_u64().ok_or_else(fail)? as usize;
                    let c = calls
                        .get(id.checked_sub(1).ok_or_else(fail)?)
                        .ok_or_else(fail)?;
                    if e["site"] != c["site"]
                        || !matches!(
                            c["kind"].as_str(),
                            Some("declaration.prepare" | "delivery.prepare")
                        )
                        || at < c["start_ns"].as_u64().unwrap()
                        || at > c["end_ns"].as_u64().unwrap()
                    {
                        return Err(fail());
                    }
                    let start = c["start_cursor"].as_u64().unwrap() as usize;
                    let offset = if c["kind"] == "declaration.prepare" {
                        3
                    } else {
                        2
                    };
                    let q = &e["query"];
                    let qc = q["history_cursor"].as_u64().ok_or_else(fail)? as usize;
                    let qt = q["at_ns"].as_u64().ok_or_else(fail)?;
                    if q.as_object().is_none_or(|o| o.len() != 3)
                        || qc >= states.len()
                        || qc > cursor
                        || qt > at
                        || qt < c["start_ns"].as_u64().unwrap()
                        || states[cursor].owner != states[start].owner
                        || positions[cursor] != (positions[start].0 + offset, true)
                    {
                        return Err(fail());
                    }
                    let query_call = if c["kind"] == "declaration.prepare" {
                        calls
                            .iter()
                            .find(|child| {
                                child["parent"] == id
                                    && child["kind"] == "declaration.prepare.binding"
                            })
                            .ok_or_else(fail)?
                    } else {
                        c
                    };
                    let queries = q["queries"].as_array().ok_or_else(fail)?;
                    let polls = query_call["polls"].as_array().ok_or_else(fail)?;
                    if queries.len() != polls.len() {
                        return Err(fail());
                    }
                    for (query, poll) in queries.iter().zip(polls) {
                        let t = query["at_ns"].as_u64().ok_or_else(fail)?;
                        let cursor = query["history_cursor"].as_u64().ok_or_else(fail)?;
                        if query.as_object().is_none_or(|o| o.len() != 3)
                            || !query["present"].is_boolean()
                            || query["present"] != poll["ready"]
                            || t < poll["start_ns"].as_u64().unwrap()
                            || t > poll["end_ns"].as_u64().unwrap()
                            || cursor < poll["start_cursor"].as_u64().unwrap()
                            || cursor > poll["end_cursor"].as_u64().unwrap()
                        {
                            return Err(fail());
                        }
                    }
                    if queries.last().is_none_or(|v| {
                        v["at_ns"] != q["at_ns"] || v["history_cursor"] != q["history_cursor"]
                    }) {
                        return Err(fail());
                    }
                    let poll = query_call["polls"]
                        .as_array()
                        .and_then(|p| p.last())
                        .ok_or_else(fail)?;
                    if poll["ready"] != true
                        || qt < poll["start_ns"].as_u64().unwrap()
                        || qt > poll["end_ns"].as_u64().unwrap()
                    {
                        return Err(fail());
                    }
                    uses.entry(id).or_default().push("produce_session".into());
                    current = Some(source);
                } else if !matches!(
                    e["kind"].as_str(),
                    Some("files" | "declaration" | "measurement")
                ) || !e["call"].is_null()
                    || !e["query"].is_null()
                {
                    return Err(fail());
                }
                sources.push(e);
            }
            Some("use") => {
                if e.as_object().is_none_or(|o| {
                    o.len() != 8
                        || ![
                            "event",
                            "source",
                            "kind",
                            "site",
                            "call",
                            "ok",
                            "at_ns",
                            "history_cursor",
                        ]
                        .iter()
                        .all(|k| o.contains_key(*k))
                }) || e["ok"] != true
                    || !e["ok"].is_boolean()
                {
                    return Err(fail());
                }
                let cap = sources
                    .get(source.checked_sub(1).ok_or_else(fail)?)
                    .ok_or_else(fail)?;
                let id = e["call"].as_u64().ok_or_else(fail)? as usize;
                let c = calls
                    .get(id.checked_sub(1).ok_or_else(fail)?)
                    .ok_or_else(fail)?;
                if e["kind"] != cap["kind"]
                    || e["site"] != c["site"]
                    || at < c["start_ns"].as_u64().unwrap()
                    || at > c["end_ns"].as_u64().unwrap()
                    || e["history_cursor"] != c["start_cursor"]
                    || c["polls"].as_array().is_some_and(|p| {
                        p.first()
                            .is_some_and(|p| at > p["start_ns"].as_u64().unwrap())
                    })
                {
                    return Err(fail());
                }
                if e["kind"] == "session" {
                    if current != Some(source) {
                        return Err(fail());
                    }
                } else {
                    let start = c["start_cursor"].as_u64().unwrap() as usize;
                    let cc = cap["history_cursor"].as_u64().unwrap() as usize;
                    if !consumed.insert(source)
                        || cap["site"] != c["site"]
                        || cap["at_ns"].as_u64().unwrap() > c["start_ns"].as_u64().unwrap()
                        || states[cc].owner != states[start].owner
                        || positions[cc] != positions[start]
                        || cc > start
                    {
                        return Err(fail());
                    }
                }
                uses.entry(id)
                    .or_default()
                    .push(e["kind"].as_str().ok_or_else(fail)?.into());
            }
            Some("retire") => {
                if e.as_object().is_none_or(|o| {
                    o.len() != 5
                        || !["event", "source", "next", "at_ns", "history_cursor"]
                            .iter()
                            .all(|k| o.contains_key(*k))
                }) || current != Some(source)
                    || !consumed.insert(source)
                    || retired.is_some()
                {
                    return Err(fail());
                }
                current = None;
                if e["next"].is_null() {
                    if event_index + 1 != events.len()
                        || cursor + 1 != states.len()
                        || calls.iter().any(|c| c["end_ns"].as_u64().unwrap() > at)
                    {
                        return Err(fail());
                    }
                } else if e["next"].as_u64() != Some((sources.len() + 1) as u64) {
                    return Err(fail());
                }
                if !e["next"].is_null() {
                    retired = Some(e["next"].as_u64().ok_or_else(fail)? as usize);
                }
            }
            _ => return Err(fail()),
        }
    }
    if current.is_some() || retired.is_some() || consumed.len() != sources.len() {
        return Err(fail());
    }
    for (index, c) in calls.iter().enumerate() {
        let expected: Vec<String> = match c["kind"].as_str() {
            Some("declaration.prepare") => vec!["files", "produce_session"],
            Some("delivery.prepare") => vec!["declaration", "produce_session"],
            Some("delivery.check") => vec!["measurement", "session"],
            Some(
                "declaration.prepare.goal_card"
                | "declaration.wait_card"
                | "declaration.wait_proposal_or_outcome"
                | "declaration.outcome",
            ) => vec!["session"],
            _ => vec![],
        }
        .into_iter()
        .map(str::to_owned)
        .collect();
        if uses.remove(&(index + 1)).unwrap_or_default() != expected {
            return Err(fail());
        }
    }
    if !uses.is_empty() {
        return Err(fail());
    }
    Ok(())
}
