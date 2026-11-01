//! Original fixture key extraction, lifecycle dispatch, refusal and terminal operands.
use super::{Run, Tab, Worker, completion, history, observer};
use serde_json::{Value, json};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
pub struct Key {
    raw: String,
    source: Option<usize>,
}
impl std::ops::Deref for Key {
    type Target = str;
    fn deref(&self) -> &str {
        borrow(self);
        &self.raw
    }
}
impl serde::Serialize for Key {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        borrow(self);
        self.raw.serialize(s)
    }
}
pub struct Id {
    raw: String,
    source: Option<usize>,
}
struct Candidate {
    attempt: usize,
    value: Value,
    used: bool,
}
struct Source {
    site: &'static str,
    raw: String,
    id: String,
    worker: Worker,
    value: Value,
    retired: bool,
    terminal: Option<usize>,
    candidates: Vec<Candidate>,
}
static SOURCES: Mutex<Vec<Source>> = Mutex::new(Vec::new());
static UNMATCHED: AtomicUsize = AtomicUsize::new(0);
fn unmatched() {
    UNMATCHED.fetch_add(1, Ordering::Relaxed);
}
fn with_key(key: &Key, f: impl FnOnce(&mut Source, usize)) {
    let mut sources = SOURCES.lock().unwrap();
    if let Some(index) = key.source.and_then(|id| id.checked_sub(1))
        && let Some(s) = sources.get_mut(index)
    {
        f(s, index + 1);
    } else {
        unmatched();
    }
}
fn borrow(key: &Key) {
    if key.source.is_none() {
        return;
    }
    with_key(key, |s, _| {
        let ok = !s.retired && s.raw == key.raw;
        if !ok {
            unmatched();
        }
        s.value["borrows"]
            .as_array_mut()
            .unwrap()
            .push(json!({"ok":ok,"at_ns":completion::now(),"history_cursor":history::cursor()}));
    });
}
pub fn last(site: Option<&'static str>, run: &Run<'_>, worker: &Worker) -> Key {
    let start = completion::now();
    let cursor = history::cursor();
    run.aggregator.observe_receiver();
    let state = run.aggregator.state.lock().unwrap();
    let actual = state.keys.last().unwrap().value.clone();
    let original = state.keys.last().unwrap();
    let source=site.map(|site|{let(worker_id,page)=history::worker_identity(&worker.session);let mut sources=SOURCES.lock().unwrap();let id=sources.len()+1;sources.push(Source{site,raw:original.value.clone(),id:original.id.clone(),worker:worker.clone(),retired:false,terminal:None,candidates:Vec::new(),value:json!({"source":id,"site":site,"capture":{"ok":actual==original.value&&observer::source_worker_matches(worker),"worker":worker_id,"page":page,"start_ns":start,"end_ns":completion::now(),"start_cursor":cursor,"end_cursor":history::cursor()},"bindings":[],"triggers":[],"uses":[],"matches":[],"ids":[],"terminal_inputs":[],"terminal_matches":[],"final_uses":[],"borrows":[],"retirements":[]})});id});
    Key {
        raw: actual,
        source,
    }
}
pub fn bind(site: &str, key: &Key) {
    with_key(key, |s, _| {
        let ok = !s.retired && s.site == site && s.raw == key.raw;
        s.value["bindings"]
            .as_array_mut()
            .unwrap()
            .push(json!({"ok":ok,"at_ns":completion::now(),"history_cursor":history::cursor()}));
    });
}
pub fn use_input(site: &str, key: &Key, call: usize) -> bool {
    let mut ok = false;
    with_key(key, |s, _| {
        ok = !s.retired && s.site == site && s.raw == key.raw;
        s.value["uses"].as_array_mut().unwrap().push(json!({"call":call,"ok":ok,"at_ns":completion::now(),"history_cursor":history::cursor()}));
    });
    ok
}
pub fn refused(call: usize, attempt: usize, run: &Run<'_>, key: &Key) -> bool {
    let start = completion::now();
    run.aggregator.observe_receiver();
    let ready = !run.aggregator.state.lock().unwrap().accepts(&key.raw);
    with_key(key, |s, _| {
        let ok = !s.retired
            && s.raw == key.raw
            && s.value["uses"]
                .as_array()
                .unwrap()
                .iter()
                .any(|u| u["call"] == call);
        s.value["matches"].as_array_mut().unwrap().push(json!({"call":call,"attempt":attempt,"ok":ok,"ready":ready,"start_ns":start,"end_ns":completion::now(),"history_cursor":history::cursor()}));
    });
    ready
}
struct Trigger {
    source: Option<(usize, usize)>,
    slot: &'static str,
}
impl Drop for Trigger {
    fn drop(&mut self) {
        if let Some((id, index)) = self.source {
            let mut sources = SOURCES.lock().unwrap();
            let t = &mut sources[id - 1].value[self.slot][index];
            t["end_ns"] = json!(completion::now());
            t["end_cursor"] = json!(history::cursor());
        }
    }
}
fn trigger(
    kind: &str,
    key: &Key,
    tab: &Tab,
    worker: Option<&Worker>,
    arguments_ok: bool,
) -> Trigger {
    let mut origin = None;
    with_key(key, |s, id| {
        let page = history::page_id(&tab.session);
        let (worker_id, worker_page) = history::worker_identity(&s.worker.session);
        let ok = !s.retired
            && s.raw == key.raw
            && page == worker_page
            && worker.is_none_or(|w| w == &s.worker)
            && arguments_ok;
        let index = s.value["triggers"].as_array().unwrap().len();
        s.value["triggers"].as_array_mut().unwrap().push(json!({"kind":kind,"ok":ok,"worker":worker_id,"page":page,"start_ns":completion::now(),"end_ns":null,"start_cursor":history::cursor(),"end_cursor":null}));
        origin = Some((id, index));
    });
    Trigger {
        source: origin,
        slot: "triggers",
    }
}
pub async fn crash(run: &Run<'_>, tab: &Tab, key: &Key) -> Result<(), String> {
    let _trigger = trigger("crash", key, tab, None, true);
    super::inference_cases::crash(run, tab).await
}
pub async fn reload(
    run: &Run<'_>,
    tab: &Tab,
    worker: &Worker,
    key: &Key,
) -> Result<Worker, String> {
    let _trigger = trigger("reload", key, tab, Some(worker), true);
    run.reload("key_inputs.rs::reload#1", tab, worker).await
}
pub async fn page_crash(
    run: &Run<'_>,
    tab: &Tab,
    key: &Key,
    method: &str,
    args: Value,
) -> Result<Value, String> {
    let _trigger = trigger(
        "page-crash",
        key,
        tab,
        None,
        method == "Page.crash" && args == json!({}),
    );
    run.browser.call(Some(&tab.session), method, args).await
}
fn source_id(run: &Run<'_>, key: &Key) -> String {
    run.aggregator.observe_receiver();
    let actual = run
        .aggregator
        .state
        .lock()
        .unwrap()
        .keys
        .iter()
        .find(|k| k.value == key.raw)
        .unwrap()
        .id
        .clone();
    with_key(key, |s, _| {
        let ok = !s.retired
            && matches!(
                s.site,
                "inference.core_sweep.wait" | "inference.reload_sweep.wait"
            )
            && s.raw == key.raw
            && s.id == actual;
        s.value["ids"]
            .as_array_mut()
            .unwrap()
            .push(json!({"ok":ok,"at_ns":completion::now(),"history_cursor":history::cursor()}));
    });
    actual
}
pub fn id(run: &Run<'_>, key: &Key) -> Id {
    Id {
        raw: source_id(run, key),
        source: key.source,
    }
}
pub fn reload_id(run: &Run<'_>, key: &Key) -> String {
    source_id(run, key)
}
pub fn terminal_input(call: usize) {
    let mut sources = SOURCES.lock().unwrap();
    let ids: Vec<_> = sources
        .iter()
        .enumerate()
        .filter(|(_, s)| s.site == "inference.core_sweep.wait" && !s.retired)
        .map(|(i, _)| i)
        .collect();
    if ids.len() != 1 {
        unmatched();
    }
    for id in ids {
        let s = &mut sources[id];
        s.terminal = Some(call);
        s.value["terminal_inputs"].as_array_mut().unwrap().push(
            json!({"call":call,"at_ns":completion::now(),"history_cursor":history::cursor()}),
        );
    }
}
pub fn candidate(call: usize, attempt: usize, state: &Value) {
    let mut sources = SOURCES.lock().unwrap();
    let mut count = 0;
    for s in sources.iter_mut().filter(|s| s.terminal == Some(call)) {
        count += 1;
        s.candidates.push(Candidate {
            attempt,
            value: state.clone(),
            used: false,
        });
    }
    if count != 1 {
        unmatched();
    }
}
pub fn terminal(call: usize, attempt: usize, id: &Id, state: &Value) -> bool {
    let ready = state["inference_calls"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| {
            c["kind"] == "revoke"
                && c["intent"]["revoke"]["key_id"] == id.raw
                && c["state"] == "finished"
        });
    let mut sources = SOURCES.lock().unwrap();
    let mut count = 0;
    for (index, s) in sources
        .iter_mut()
        .enumerate()
        .filter(|(_, s)| s.terminal == Some(call))
    {
        count += 1;
        let candidates: Vec<_> = s
            .candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| c.attempt == attempt && !c.used)
            .map(|(i, _)| i)
            .collect();
        let ok = !s.retired
            && id.source == Some(index + 1)
            && s.id == id.raw
            && candidates.len() == 1
            && s.candidates[candidates[0]].value == *state;
        for i in candidates {
            s.candidates[i].used = true;
        }
        s.value["terminal_matches"].as_array_mut().unwrap().push(json!({"attempt":attempt,"ok":ok,"ready":ready,"at_ns":completion::now(),"history_cursor":history::cursor()}));
    }
    if count != 1 {
        unmatched();
    }
    ready
}
fn final_use(key: &Key, kind: &str) -> Trigger {
    let mut origin = None;
    with_key(key, |s, id| {
        let ok = !s.retired && s.raw == key.raw;
        let index = s.value["final_uses"].as_array().unwrap().len();
        s.value["final_uses"].as_array_mut().unwrap().push(json!({"kind":kind,"ok":ok,"start_ns":completion::now(),"end_ns":null,"start_cursor":history::cursor(),"end_cursor":null}));
        origin = Some((id, index));
    });
    Trigger {
        source: origin,
        slot: "final_uses",
    }
}
pub async fn final_status(run: &Run<'_>, key: &Key, kind: &str) -> Result<u16, String> {
    let _operation = final_use(key, kind);
    run.aggregator.key_status(&key.raw).await
}
pub async fn expiry(run: &Run<'_>, key: &Key, case: &mut super::Case) -> Result<(), String> {
    let _operation = final_use(key, "expiry");
    super::inference_cases::check_expiry(run, &key.raw, case).await
}
pub fn retire(key: &Key, reason: &str) {
    with_key(key, |s, _| {
        s.value["retirements"].as_array_mut().unwrap().push(
            json!({"reason":reason,"at_ns":completion::now(),"history_cursor":history::cursor()}),
        );
        s.retired = true;
    });
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
        .map(|s| usize::from(!s.retired) + s.candidates.iter().filter(|c| !c.used).count())
        .sum::<usize>()
        + UNMATCHED.load(Ordering::Relaxed)
}
pub fn validate(report: &Value) -> Result<(), String> {
    let fail = || "original key capture/trigger/lifetime/operand mismatch".to_string();
    if report["key_unbound_inputs"].as_u64() != Some(0) {
        return Err(fail());
    }
    let rows = report["key_inputs"].as_array().ok_or_else(fail)?;
    let cases = report["cases"].as_array().unwrap();
    let calls = report["observer_calls"].as_array().unwrap();
    let expected: Vec<_> = cases
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            matches!(
                c["id"].as_str(),
                Some(
                    "inference_cases.c006.p001"
                        | "inference_cases.c007.p004"
                        | "inference_cases.c008.p001"
                        | "inference_cases.c008.p002"
                )
            )
        })
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
    for (index, (row, (case_index, case))) in rows.iter().zip(expected).enumerate() {
        let case_id = case["id"].as_str().unwrap();
        let core = case_id == "inference_cases.c006.p001";
        let reload = case_id == "inference_cases.c007.p004";
        let site = if core {
            "inference.core_sweep.wait"
        } else if reload {
            "inference.reload_sweep.wait"
        } else {
            "inference.crash_sweep.wait"
        };
        let inside = Some((
            "inference_cases.run".into(),
            "inside".into(),
            case_id.into(),
        ));
        let capture_owner = if core {
            inside.clone()
        } else {
            Some((
                "inference_cases.run".into(),
                "after".into(),
                cases[case_index - 1]["id"].as_str().unwrap().into(),
            ))
        };
        let capture_pos = if core {
            0
        } else if reload {
            5
        } else {
            4
        };
        let point = |cursor: &Value,
                     at: u64,
                     owner: &Option<(String, String, String)>,
                     pos: usize|
         -> Result<usize, String> {
            let i = cursor.as_u64().ok_or_else(fail)? as usize;
            if i >= states.len()
                || states[i].owner != *owner
                || positions[i] != (pos, true)
                || i > 0 && events[i - 1]["at_ns"].as_u64().unwrap() > at
                || i < events.len() && events[i]["at_ns"].as_u64().unwrap() < at
            {
                return Err(fail());
            }
            Ok(i)
        };
        if row.as_object().is_none_or(|o| o.len() != 13)
            || row["source"].as_u64() != Some((index + 1) as u64)
            || row["site"] != site
        {
            return Err(fail());
        }
        let cap = &row["capture"];
        let cs = cap["start_ns"].as_u64().ok_or_else(fail)?;
        let ce = cap["end_ns"].as_u64().ok_or_else(fail)?;
        let cc = point(&cap["start_cursor"], cs, &capture_owner, capture_pos)?;
        let ec = point(&cap["end_cursor"], ce, &capture_owner, capture_pos)?;
        let worker = cap["worker"].as_u64().ok_or_else(fail)?;
        let page = cap["page"].as_u64().ok_or_else(fail)?;
        if cap.as_object().is_none_or(|o| o.len() != 7)
            || cap["ok"] != true
            || !cap["ok"].is_boolean()
            || cs < previous
            || cs > ce
            || cc != ec
            || pages[cc].get("tracer") != Some(&page)
            || workers[cc].get(&page) != Some(&worker)
            || !core && ce > case["start_ns"].as_u64().unwrap()
            || core && cs < case["start_ns"].as_u64().unwrap()
        {
            return Err(fail());
        }
        let b = row["bindings"].as_array().ok_or_else(fail)?;
        let t = row["triggers"].as_array().ok_or_else(fail)?;
        let retire = row["retirements"].as_array().ok_or_else(fail)?;
        if b.len() != 1 || t.len() != 1 || retire.len() != 1 {
            return Err(fail());
        }
        let b = &b[0];
        let t = &t[0];
        let r = &retire[0];
        let bound = b["at_ns"].as_u64().ok_or_else(fail)?;
        point(
            &b["history_cursor"],
            bound,
            if reload { &inside } else { &capture_owner },
            if reload { 1 } else { capture_pos },
        )?;
        let ts = t["start_ns"].as_u64().ok_or_else(fail)?;
        let te = t["end_ns"].as_u64().ok_or_else(fail)?;
        let tc = point(&t["start_cursor"], ts, &inside, 0)?;
        point(&t["end_cursor"], te, &inside, usize::from(reload))?;
        if b.as_object().is_none_or(|o| o.len() != 3)
            || b["ok"] != true
            || !b["ok"].is_boolean()
            || t.as_object().is_none_or(|o| o.len() != 8)
            || t["ok"] != true
            || !t["ok"].is_boolean()
            || t["kind"]
                != if core {
                    "crash"
                } else if reload {
                    "reload"
                } else {
                    "page-crash"
                }
            || t["worker"] != worker
            || t["page"] != page
            || pages[tc].get("tracer") != Some(&page)
            || workers[tc].get(&page) != Some(&worker)
            || ce > ts
            || ts > te
            || reload && te > bound
            || !reload && (ce > bound || bound > ts)
        {
            return Err(fail());
        }
        let reason = if reload {
            match case["branches"]["reload-revoke"].as_str() {
                Some("absent") => "used",
                Some("pending") => "pending",
                Some("finished") => "finished",
                _ => return Err(fail()),
            }
        } else {
            "used"
        };
        let used = reason == "used";
        let uses = row["uses"].as_array().ok_or_else(fail)?;
        let matches = row["matches"].as_array().ok_or_else(fail)?;
        let wait: Vec<_> = calls
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                c["site"] == site
                    && states[c["start_cursor"].as_u64().unwrap() as usize].owner == inside
            })
            .collect();
        if wait.len() != usize::from(used) || uses.len() != usize::from(used) {
            return Err(fail());
        }
        let mut last = te.max(bound);
        if used {
            let (call_index, c) = wait[0];
            let u = &uses[0];
            let at = u["at_ns"].as_u64().ok_or_else(fail)?;
            point(
                &c["start_cursor"],
                c["start_ns"].as_u64().unwrap(),
                &inside,
                4,
            )?;
            if u.as_object().is_none_or(|o| o.len() != 4)
                || u["ok"] != true
                || !u["ok"].is_boolean()
                || u["call"].as_u64() != Some((call_index + 1) as u64)
                || u["history_cursor"] != c["start_cursor"]
                || c["start_ns"].as_u64().unwrap() < last
                || at < c["start_ns"].as_u64().unwrap()
            {
                return Err(fail());
            }
            let polls = c["polls"].as_array().unwrap();
            if matches.len() != polls.len()
                || polls
                    .first()
                    .is_none_or(|p| at > p["start_ns"].as_u64().unwrap())
            {
                return Err(fail());
            }
            for (m, p) in matches.iter().zip(polls) {
                let start = m["start_ns"].as_u64().ok_or_else(fail)?;
                let end = m["end_ns"].as_u64().ok_or_else(fail)?;
                if m.as_object().is_none_or(|o| o.len() != 7)
                    || m["call"] != u["call"]
                    || m["attempt"] != p["attempt"]
                    || !m["attempt"].is_u64()
                    || m["ok"] != true
                    || !m["ok"].is_boolean()
                    || m["ready"] != p["ready"]
                    || !m["ready"].is_boolean()
                    || start < p["start_ns"].as_u64().unwrap()
                    || start > end
                    || end > p["end_ns"].as_u64().unwrap()
                    || m["history_cursor"] != p["start_cursor"]
                {
                    return Err(fail());
                }
            }
            last = c["end_ns"].as_u64().unwrap();
        } else if !matches.is_empty() {
            return Err(fail());
        }
        let ids = row["ids"].as_array().ok_or_else(fail)?;
        if ids.len() != usize::from(core || reload) {
            return Err(fail());
        }
        if let Some(id) = ids.first() {
            let at = id["at_ns"].as_u64().ok_or_else(fail)?;
            point(&id["history_cursor"], at, &inside, if core { 4 } else { 1 })?;
            if id.as_object().is_none_or(|o| o.len() != 3)
                || id["ok"] != true
                || !id["ok"].is_boolean()
                || core && at < last
                || reload && (at < te || at > bound)
            {
                return Err(fail());
            }
            if core {
                last = at;
            }
        }
        let inputs = row["terminal_inputs"].as_array().ok_or_else(fail)?;
        let terminal = row["terminal_matches"].as_array().ok_or_else(fail)?;
        if inputs.len() != usize::from(core) {
            return Err(fail());
        }
        if core {
            let found: Vec<_> = calls
                .iter()
                .enumerate()
                .filter(|(_, c)| {
                    c["site"] == "inference.core.revoke_terminal"
                        && states[c["start_cursor"].as_u64().unwrap() as usize].owner == inside
                })
                .collect();
            if found.len() != 1 {
                return Err(fail());
            }
            let (ci, c) = found[0];
            let u = &inputs[0];
            let at = u["at_ns"].as_u64().ok_or_else(fail)?;
            if u.as_object().is_none_or(|o| o.len() != 3)
                || u["call"].as_u64() != Some((ci + 1) as u64)
                || u["history_cursor"] != c["start_cursor"]
                || last > c["start_ns"].as_u64().unwrap()
                || at < c["start_ns"].as_u64().unwrap()
            {
                return Err(fail());
            }
            let polls = c["polls"].as_array().unwrap();
            if terminal.len() != polls.len()
                || polls
                    .first()
                    .is_none_or(|p| at > p["start_ns"].as_u64().unwrap())
            {
                return Err(fail());
            }
            for (m, p) in terminal.iter().zip(polls) {
                let at = m["at_ns"].as_u64().ok_or_else(fail)?;
                if m.as_object().is_none_or(|o| o.len() != 5)
                    || m["attempt"] != p["attempt"]
                    || !m["attempt"].is_u64()
                    || m["ok"] != true
                    || !m["ok"].is_boolean()
                    || m["ready"] != p["ready"]
                    || !m["ready"].is_boolean()
                    || at < p["start_ns"].as_u64().unwrap()
                    || at > p["end_ns"].as_u64().unwrap()
                    || m["history_cursor"] != p["start_cursor"]
                {
                    return Err(fail());
                }
            }
            last = c["end_ns"].as_u64().unwrap();
        } else if !terminal.is_empty() {
            return Err(fail());
        }
        let borrows = row["borrows"].as_array().ok_or_else(fail)?;
        let borrow_positions = if core {
            vec![0]
        } else if reload {
            vec![1, 4]
        } else if case_id == "inference_cases.c008.p001" {
            vec![0, 4]
        } else {
            vec![0, 1, 4]
        };
        if borrows.len() != borrow_positions.len() {
            return Err(fail());
        }
        let mut prior_borrow = te;
        for (borrow, position) in borrows.iter().zip(borrow_positions) {
            let at = borrow["at_ns"].as_u64().ok_or_else(fail)?;
            point(&borrow["history_cursor"], at, &inside, position)?;
            if borrow.as_object().is_none_or(|o| o.len() != 3)
                || borrow["ok"] != true
                || !borrow["ok"].is_boolean()
                || at < prior_borrow
                || reload && position == 1 && at < bound
                || position == 4 && at < last
            {
                return Err(fail());
            }
            prior_borrow = at;
        }
        let final_uses = row["final_uses"].as_array().ok_or_else(fail)?;
        if final_uses.len() != 1 {
            return Err(fail());
        }
        let f = &final_uses[0];
        let fs = f["start_ns"].as_u64().ok_or_else(fail)?;
        let fe = f["end_ns"].as_u64().ok_or_else(fail)?;
        point(&f["start_cursor"], fs, &inside, 4)?;
        point(&f["end_cursor"], fe, &inside, 4)?;
        if f.as_object().is_none_or(|o| o.len() != 6)
            || f["ok"] != true
            || !f["ok"].is_boolean()
            || f["kind"]
                != if core {
                    "core-status"
                } else if reload {
                    "expiry"
                } else {
                    "crash-status"
                }
            || fs < last.max(prior_borrow)
            || fs > fe
        {
            return Err(fail());
        }
        last = fe;
        let at = r["at_ns"].as_u64().ok_or_else(fail)?;
        point(&r["history_cursor"], at, &inside, 4)?;
        if r.as_object().is_none_or(|o| o.len() != 3)
            || r["reason"] != reason
            || at < last
            || at > case["end_ns"].as_u64().unwrap()
        {
            return Err(fail());
        }
        previous = at;
    }
    Ok(())
}
