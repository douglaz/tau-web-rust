//! Original serial observations, with source caller trees and unchanged polling windows.
use super::{completion, history, json, reader_checks};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Mutex;

static CALLS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static HOLDER_INPUTS: Mutex<Vec<(super::Worker, Value)>> = Mutex::new(Vec::new());
static CLASS_INPUTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
pub fn class_snapshot() -> Value {
    json!(*CLASS_INPUTS.lock().unwrap())
}
pub fn holder_source(worker: &super::Worker) {
    let (identity, page) = history::worker_identity(&worker.session);
    let input = json!({"worker":identity,"page":page,"worker_ok":source_worker_matches(worker),"at_ns":completion::now(),"history_cursor":history::cursor()});
    HOLDER_INPUTS.lock().unwrap().push((worker.clone(), input));
}
pub async fn class_source(
    run: &super::Run<'_>,
    tab: &super::Tab,
    machine: &str,
    answer: &str,
) -> Result<Value, String> {
    let start = completion::now();
    let cursor = history::cursor();
    let page = history::page_id(&tab.session);
    let selector = format!("[data-machine='{machine}'] [data-answer='{answer}']");
    let expected = match (machine, answer) {
        ("fixture", "not_sure") => "[data-machine='fixture'] [data-answer='not_sure']",
        ("fixture-other", "no") => "[data-machine='fixture-other'] [data-answer='no']",
        _ => "",
    };
    super::setup_cases::click(run, tab, &selector).await?;
    let mut inputs = CLASS_INPUTS.lock().unwrap();
    let input = json!({"source":inputs.len()+1,"machine":match machine {"fixture"=>"first","fixture-other"=>"second",_=>"unknown"},"answer":answer,"page":page,"start_ns":start,"end_ns":completion::now(),"start_cursor":cursor,"end_cursor":history::cursor(),"selector_ok":selector==expected&&!expected.is_empty()});
    inputs.push(input.clone());
    Ok(input)
}
static GOAL_ENDS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static PENDING_GOAL_ENDS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
pub fn goal_end_snapshot() -> Value {
    json!(*GOAL_ENDS.lock().unwrap())
}
pub async fn goal_end(
    run: &super::Run<'_>,
    worker: &super::Worker,
    expression: &str,
) -> Result<Value, String> {
    let start = completion::now();
    let cursor = history::cursor();
    let (worker_id, page) = history::worker_identity(&worker.session);
    let expected = "await m.end_sessions();return await Promise.race([self.activeGoal.then(()=>true),new Promise(r=>setTimeout(()=>r(false),1000))]);";
    let ok = expression == expected && source_worker_matches(worker);
    let result = super::inference_cases::module(run, worker, expression).await;
    let mut sources = GOAL_ENDS.lock().unwrap();
    let input = json!({"source":sources.len()+1,"worker":worker_id,"page":page,"input_ok":ok,"start_ns":start,"end_ns":completion::now(),"start_cursor":cursor,"end_cursor":history::cursor()});
    sources.push(input.clone());
    PENDING_GOAL_ENDS.lock().unwrap().push(input);
    result
}
static PRIOR_VIEWS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
use std::sync::atomic::{AtomicU64, Ordering};
static ARGUMENT_ORDER: AtomicU64 = AtomicU64::new(0);
fn argument_order() -> u64 {
    ARGUMENT_ORDER.fetch_add(1, Ordering::Relaxed) + 1
}
struct SourceArgument {
    value: Value,
    input: Value,
    at_ns: u64,
    cursor: usize,
    order: u64,
}
static SOURCE_ARGUMENTS: Mutex<BTreeMap<(&'static str, &'static str), Vec<SourceArgument>>> =
    Mutex::new(BTreeMap::new());
static ARGUMENT_TRIGGERS: Mutex<BTreeMap<&'static str, Vec<Value>>> = Mutex::new(BTreeMap::new());
pub fn source_argument(site: &'static str, name: &'static str, value: usize) {
    let input = json!({"value":value,"queries":take_document_queries(site,name)});
    SOURCE_ARGUMENTS
        .lock()
        .unwrap()
        .entry((site, name))
        .or_default()
        .push(SourceArgument {
            value: json!(value),
            input,
            at_ns: completion::now(),
            cursor: history::cursor(),
            order: argument_order(),
        });
}
static DOCUMENT_QUERIES: Mutex<BTreeMap<String, Vec<Value>>> = Mutex::new(BTreeMap::new());
fn take_document_queries(site: &str, name: &str) -> Vec<Value> {
    DOCUMENT_QUERIES
        .lock()
        .unwrap()
        .remove(&format!("{site}:{name}"))
        .unwrap_or_default()
}
pub fn document_counter(site: &str, name: &str, run: &super::Run<'_>) -> usize {
    let start = completion::now();
    let cursor = history::cursor();
    let receiver_ok = run.aggregator.observe_receiver();
    let (kind, value) = match (site, name) {
        ("goal.document.pending_sent", "from") | ("goal.document.active_sent", "before") => (
            "requests",
            run.aggregator
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.starts_with(b"GET /document"))
                .count(),
        ),
        ("goal.document.connection_closed", "closes") => (
            "closes",
            run.aggregator.state.lock().unwrap().document_closes,
        ),
        _ => ("unknown", 0),
    };
    let query = json!({"kind":kind,"value":value,"receiver_ok":receiver_ok,"start_ns":start,"end_ns":completion::now(),"start_cursor":cursor,"end_cursor":history::cursor()});
    DOCUMENT_QUERIES
        .lock()
        .unwrap()
        .entry(format!("{site}:{name}"))
        .or_default()
        .push(query);
    value
}
pub fn unbound_arguments() -> Value {
    json!({"values":SOURCE_ARGUMENTS.lock().unwrap().iter().map(|((site,name),values)|json!({"site":site,"name":name,"captures":values.len()})).collect::<Vec<_>>(),"workers":HOLDER_INPUTS.lock().unwrap().len(),"goal_ends":PENDING_GOAL_ENDS.lock().unwrap().len(),"document_sessions":DOCUMENT_SESSIONS.lock().unwrap().len(),"document_queries":DOCUMENT_QUERIES.lock().unwrap().values().map(Vec::len).sum::<usize>(),"triggers":ARGUMENT_TRIGGERS.lock().unwrap().iter().map(|(site,values)|json!({"site":site,"captures":values.len()})).collect::<Vec<_>>()})
}
struct DocumentSession {
    raw: String,
    worker: super::Worker,
    source: usize,
    capture: Value,
}
static DOCUMENT_SESSIONS: Mutex<BTreeMap<&'static str, DocumentSession>> =
    Mutex::new(BTreeMap::new());
static DOCUMENT_SESSION_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static GOAL_SESSION_INPUTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
pub fn goal_session_inputs() -> Value {
    json!(*GOAL_SESSION_INPUTS.lock().unwrap())
}
/// The original session value and its query source travel together across resets.
#[derive(Clone, Debug)]
pub struct GoalSession {
    raw: String,
    source: usize,
    kind: &'static str,
    worker: super::Worker,
}
impl GoalSession {
    pub fn source(&self) -> usize {
        self.source
    }
    pub fn operand(&self) -> Value {
        json!({"kind":self.kind,"source":self.source})
    }
    pub fn matches_receiver(&self, worker: &super::Worker) -> bool {
        self.worker == *worker
    }
}
impl std::ops::Deref for GoalSession {
    type Target = str;
    fn deref(&self) -> &str {
        &self.raw
    }
}
impl std::fmt::Display for GoalSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.raw, f)
    }
}
impl serde::Serialize for GoalSession {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.raw, s)
    }
}

pub async fn goal_session(
    run: &super::Run<'_>,
    worker: &super::Worker,
    document: Option<&'static str>,
) -> Result<GoalSession, String> {
    let start = completion::now();
    let from = history::cursor();
    let (identity, page) = history::worker_identity(&worker.session);
    let receiver_ok = source_worker_matches(worker);
    super::seed_operations::operation("inspect", worker, None);
    let state = run
        .browser
        .evaluate(&worker.session, super::state_inputs::EXPRESSION)
        .await?;
    let query_ok = hex::encode(
        ring::digest::digest(
            &ring::digest::SHA256,
            super::state_inputs::EXPRESSION.as_bytes(),
        )
        .as_ref(),
    ) == completion::inventory()["state_query_sha256"]
        .as_str()
        .unwrap_or("");
    let session = state["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["bound_set"] == json!(["fixture"]))
        .unwrap()["identity"]
        .as_str()
        .map(str::to_owned)
        .ok_or("session");
    let end = completion::now();
    let until = history::cursor();
    let mut queries = GOAL_SESSION_INPUTS.lock().unwrap();
    let query = queries.len() + 1;
    queries.push(json!({"worker":identity,"page":page,"receiver_ok":receiver_ok,"present":session.is_ok(),"document":document,"start_ns":start,"end_ns":end,"start_cursor":from,"end_cursor":until,"query_ok":query_ok}));
    drop(queries);
    let session = session?;
    if let Some(site) = document {
        let source = DOCUMENT_SESSION_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        let value = DocumentSession {
            raw: session.clone(),
            worker: worker.clone(),
            source,
            capture: json!({"at_ns":end,"history_cursor":until,"worker":identity,"page":page,"worker_ok":receiver_ok,"query":query}),
        };
        assert!(
            DOCUMENT_SESSIONS
                .lock()
                .unwrap()
                .insert(site, value)
                .is_none(),
            "one original document session per source trigger"
        );
    }
    Ok(GoalSession {
        raw: session,
        source: query,
        kind: "query",
        worker: worker.clone(),
    })
}
static REBIND_INPUTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
pub fn rebind_inputs() -> Value {
    json!(*REBIND_INPUTS.lock().unwrap())
}
pub struct GoalRebind {
    value: Value,
    source: usize,
    worker: super::Worker,
}
impl std::ops::Deref for GoalRebind {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.value
    }
}
impl GoalRebind {
    pub fn current(&self) -> Result<GoalSession, String> {
        Ok(GoalSession {
            raw: self.value["current"]
                .as_str()
                .ok_or("current session")?
                .to_owned(),
            source: self.source,
            kind: "rebind",
            worker: self.worker.clone(),
        })
    }
}
const REBIND_EXPRESSION: &str = "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);self.releaseRebind();return JSON.parse(await self.rebindWork);})()";
pub async fn goal_rebind(
    run: &super::Run<'_>,
    worker: &super::Worker,
) -> Result<GoalRebind, String> {
    let start = completion::now();
    let cursor = history::cursor();
    let (identity, page) = history::worker_identity(&worker.session);
    let value = run
        .browser
        .evaluate(&worker.session, REBIND_EXPRESSION)
        .await?;
    let query_ok = hex::encode(
        ring::digest::digest(&ring::digest::SHA256, REBIND_EXPRESSION.as_bytes()).as_ref(),
    ) == completion::inventory()["goal_rebind_query_sha256"]
        .as_str()
        .unwrap_or("");
    let mut rows = REBIND_INPUTS.lock().unwrap();
    let source = rows.len() + 1;
    rows.push(json!({"source":source,"page":page,"worker":identity,"start_ns":start,"end_ns":completion::now(),"start_cursor":cursor,"end_cursor":history::cursor(),"present":value["current"].is_string(),"receiver_ok":history::selected_worker_matches(page,worker),"query_ok":query_ok}));
    Ok(GoalRebind {
        value,
        source,
        worker: worker.clone(),
    })
}

pub async fn module_trigger(
    sites: &[&'static str],
    run: &super::Run<'_>,
    worker: &super::Worker,
    expression: &str,
) -> Result<Value, String> {
    let (worker_id, page) = history::worker_identity(&worker.session);
    let (tag, text, slot) = if sites == ["goal.document.pending_sent"] {
        ("pending", "goal awaiting document", "pendingGoal")
    } else if sites
        == [
            "goal.document.active_sent",
            "goal.document.connection_closed",
        ]
    {
        ("active", "goal awaiting a document", "activeGoal")
    } else {
        ("unknown", "", "")
    };
    let source = DOCUMENT_SESSIONS.lock().unwrap().remove(tag);
    let expected=source.as_ref().map(|source| {
        let request=json!({"session":source.raw,"text":text,"document_source":format!("{}/document",run.aggregator.origin)});
        format!("self.{slot}=m.goal_request({});return true;",json!(request.to_string()))
    });
    let dispatch_ok = source
        .as_ref()
        .is_some_and(|source| source.worker == *worker)
        && expected.as_deref() == Some(expression)
        && source_worker_matches(worker);
    let input = json!({"at_ns":completion::now(),"history_cursor":history::cursor(),"worker":worker_id,"page":page,"order":argument_order(),"dispatch_ok":dispatch_ok,"session_source":source.as_ref().map(|s|s.source),"session_capture":source.as_ref().map(|s|&s.capture)});
    for site in sites {
        ARGUMENT_TRIGGERS
            .lock()
            .unwrap()
            .entry(site)
            .or_default()
            .push(input.clone());
    }
    super::inference_cases::module(run, worker, expression).await
}

const COMPLETED_READS: &str = "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return m.test_completed_reads();})()";

/// Observe the original query and its returned Value once, before taking the writer.
pub async fn original_completed_reads(
    run: &super::Run<'_>,
    worker: &super::Worker,
    expression: &str,
    capture: bool,
) -> Result<Value, String> {
    let start = completion::now();
    let start_cursor = history::cursor();
    let (worker_id, page) = history::worker_identity(&worker.session);
    let receiver_ok = history::selected_worker_matches(page, worker);
    let value = run.browser.evaluate(&worker.session, expression).await?;
    if capture {
        SOURCE_ARGUMENTS.lock().unwrap().entry(("hold.writer.read_completed", "reads_before")).or_default().push(SourceArgument {
            value: value.clone(),
            input: json!({"worker":worker_id,"page":page,"query_ok":expression==COMPLETED_READS,"receiver_ok":receiver_ok,"start_ns":start,"start_cursor":start_cursor}),
            at_ns: completion::now(),
            cursor: history::cursor(),
            order: argument_order(),
        });
    }
    Ok(value)
}

pub async fn writer_trigger(
    run: &super::Run<'_>,
    worker: &super::Worker,
    expression: &str,
) -> Result<Value, String> {
    let (worker_id, page) = history::worker_identity(&worker.session);
    let dispatch_ok = expression
        == "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);let ready;const acquired=new Promise(r=>ready=r);self.__writer=m.test_writer(new Promise(r=>self.__releaseWriter=r),ready);await acquired;})()";
    let input = json!({"at_ns":completion::now(),"history_cursor":history::cursor(),"worker":worker_id,"page":page,"order":argument_order(),"dispatch_ok":dispatch_ok});
    ARGUMENT_TRIGGERS
        .lock()
        .unwrap()
        .entry("hold.writer.read_completed")
        .or_default()
        .push(input);
    run.browser.evaluate(&worker.session, expression).await
}

pub async fn original_view(
    site: &'static str,
    run: &super::Run<'_>,
    tab: &super::Tab,
) -> Result<super::view_inputs::View, String> {
    let start = completion::now();
    let cursor = history::cursor();
    let page = history::page_id(&tab.session);
    let index = PRIOR_VIEWS.lock().unwrap().len() + 1;
    let value = super::view_inputs::read(
        super::view_inputs::Origin::Prior { site, index },
        run,
        tab,
        super::VIEW,
    )
    .await?;
    PRIOR_VIEWS.lock().unwrap().push(json!({"site":site,"page":page,"view_source":value.id(),"start_ns":start,"end_ns":completion::now(),"start_cursor":cursor,"end_cursor":history::cursor()}));
    Ok(value)
}
pub fn source_worker_matches(worker: &super::Worker) -> bool {
    let (_, page) = history::worker_identity(&worker.session);
    history::selected_worker_matches(page, worker)
}
pub fn prior_snapshot() -> Value {
    json!(*PRIOR_VIEWS.lock().unwrap())
}

static SUBMISSIONS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static RUNTIME_INPUTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static BINDING_INPUTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static SECOND_WORKER_INPUTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
pub async fn second_worker_locked(
    run: &super::Run<'_>,
    worker: &super::Worker,
) -> Result<bool, String> {
    let start = completion::now();
    let from = history::cursor();
    let (identity, page) = history::worker_identity(&worker.session);
    let receiver_ok = source_worker_matches(worker);
    let value = run.inspect(worker).await?;
    let locked = value["state"] == "locked";
    SECOND_WORKER_INPUTS.lock().unwrap().push(json!({"worker":identity,"page":page,"receiver_ok":receiver_ok,"locked":locked,"start_ns":start,"end_ns":completion::now(),"start_cursor":from,"end_cursor":history::cursor()}));
    Ok(locked)
}
pub fn second_worker_inputs() -> Value {
    json!(*SECOND_WORKER_INPUTS.lock().unwrap())
}
static WORKER_EXCLUSIONS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static DISPLAYED_WORDS: Mutex<BTreeMap<u64, String>> = Mutex::new(BTreeMap::new());
static DISPLAYED_CAPTURES: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static DISPLAYED_ORIGINALS: Mutex<BTreeMap<u64, String>> = Mutex::new(BTreeMap::new());
static DISPLAYED_USES: Mutex<Vec<Value>> = Mutex::new(Vec::new());

/// A phrase can only originate from the unchanged DOM result. No writable string
/// escapes; comparisons also bind both displayed operands to their original queries.
pub struct DisplayedPhrase {
    original: crate::cdp::OriginalEvaluation,
    call: u64,
    value: String,
}
impl DisplayedPhrase {
    fn used(&self, other: Option<u64>, partner: Value, result: bool) -> usize {
        let ok = self.original.as_str() == Some(self.value.as_str())
            && DISPLAYED_ORIGINALS.lock().unwrap().get(&self.call) == Some(&self.value);
        let mut rows = DISPLAYED_USES.lock().unwrap();
        let index = rows.len();
        rows.push(json!({"call":self.call,"other":other,"partner":partner,"result":result,"ok":ok,"case":history::active_case_id(),"at_ns":completion::now(),"history_cursor":history::cursor(),"predicate":null,"instance":null,"check_ns":null,"check_cursor":null}));
        index
    }
}
impl std::ops::Deref for DisplayedPhrase {
    type Target = str;
    fn deref(&self) -> &str {
        &self.value
    }
}
impl DisplayedPhrase {
    pub fn same_as(&self, other: &Self) -> DisplayedComparison {
        let result = self.value == other.value;
        let first = self.used(Some(other.call), Value::Null, result);
        let second = other.used(Some(self.call), Value::Null, result);
        DisplayedComparison {
            holds: result,
            uses: vec![first, second],
        }
    }
}
pub struct CollisionPhrase {
    value: String,
    index: usize,
}
pub fn collision_phrase(index: usize, value: &str) -> CollisionPhrase {
    CollisionPhrase {
        value: value.into(),
        index,
    }
}
impl CollisionPhrase {
    fn operand(&self) -> Value {
        let expected = self.index.checked_sub(1).and_then(|n| {
            include_str!("../../tests/vectors/seed-backup-collisions.txt")
                .lines()
                .nth(n)
        });
        json!({"kind":"collision","index":self.index,"ok":expected==Some(self.value.as_str())})
    }
}
impl DisplayedPhrase {
    pub fn collision(&self, other: &CollisionPhrase) -> DisplayedComparison {
        let result = self.value == other.value;
        let index = self.used(None, other.operand(), result);
        DisplayedComparison {
            holds: result,
            uses: vec![index],
        }
    }
}
impl DisplayedPhrase {
    pub fn mnemonic(&self, other: &crate::reader::Mnemonic) -> DisplayedComparison {
        let result = self.value == other.value();
        let index = self.used(None, other.operand(), result);
        DisplayedComparison {
            holds: result,
            uses: vec![index],
        }
    }
}
#[must_use]
pub struct DisplayedComparison {
    holds: bool,
    uses: Vec<usize>,
}
impl DisplayedComparison {
    pub fn continues(&self) -> bool {
        self.holds
    }
    pub fn checked(self, binding: &crate::predicate_inputs::Primary) -> bool {
        let (predicate, instance, at, cursor) = binding.coordinates();
        let case = history::active_case_id();
        let mut rows = DISPLAYED_USES.lock().unwrap();
        let mut ok = true;
        for index in self.uses {
            let row = &mut rows[index];
            if row["case"] != json!(case)
                || row["result"] != self.holds
                || !row["check_ns"].is_null()
            {
                ok = false;
                continue;
            }
            row["predicate"] = json!(predicate);
            row["instance"] = json!(instance);
            row["check_ns"] = json!(at);
            row["check_cursor"] = json!(cursor);
        }
        ok
    }
}

pub fn displayed_word_uses() -> Value {
    json!(*DISPLAYED_USES.lock().unwrap())
}
// Inputs are captured at their original callers and consumed at the original helper entry.
fn active_call() -> (usize, String) {
    let index = ACTIVE.with_borrow(|a| *a.last().expect("input inside original observer"));
    (
        index + 1,
        CALLS.lock().unwrap()[index]["site"]
            .as_str()
            .unwrap()
            .into(),
    )
}
pub fn measurement_input(site: &'static str, v: &Value) {
    super::inputs::value_input("measurement", site, v.clone());
}
pub fn declaration_input(site: &'static str, v: &Option<Value>) {
    super::inputs::value_input(
        "declaration",
        site,
        json!({"present":v.is_some(),"value":v}),
    );
}
pub fn files_input(site: &'static str, v: &super::reader::Files) {
    super::inputs::files_input(site, v);
}
pub fn measurement_matches(site: &'static str, v: &Value) -> bool {
    super::inputs::value_matches("measurement", site, active_call().0, v.clone())
}
pub fn declaration_matches(site: &'static str, v: &Option<Value>) -> bool {
    super::inputs::value_matches(
        "declaration",
        site,
        active_call().0,
        json!({"present":v.is_some(),"value":v}),
    )
}
pub fn files_match(site: &'static str, v: &super::reader::Files) -> bool {
    super::inputs::files_match(site, active_call().0, v)
}

pub async fn displayed_words(
    run: &super::Run<'_>,
    tab: &super::Tab,
    expression: &str,
) -> Result<DisplayedPhrase, String> {
    let start = completion::now();
    let cursor = history::cursor();
    let value = run
        .browser
        .evaluate_original(&tab.session, expression)
        .await?;
    let page = history::page_id(&tab.session);
    let index = ACTIVE.with_borrow(|active| active.last().copied());
    let original = index.is_some_and(|index| {
        let calls = CALLS.lock().unwrap();
        calls[index]["kind"] == "seed.phrase" && calls[index]["page"] == page
    });
    let call = index.map(|index| index as u64 + 1);
    let mut captures = DISPLAYED_CAPTURES.lock().unwrap();
    let original = original
        && value.within(start,cursor)
        && value.matches(&tab.session, "Array.from(document.querySelectorAll('#tau-seed-backup-words li'), n=>n.textContent).join(' ')")
        && value.is_string()
        && !captures
            .iter()
            .any(|capture| capture["call"].as_u64() == call);
    captures.push(json!({"call":call,"page":page,"ok":original,"at_ns":completion::now(),"history_cursor":history::cursor()}));
    if original {
        let raw = value.as_str().unwrap().to_owned();
        DISPLAYED_WORDS.lock().unwrap().insert(page, raw.clone());
        DISPLAYED_ORIGINALS
            .lock()
            .unwrap()
            .insert(call.unwrap(), raw);
    }
    let words = value.as_str().ok_or("no displayed words")?.to_owned();
    Ok(DisplayedPhrase {
        original: value,
        call: call.unwrap_or(0),
        value: words,
    })
}
pub fn displayed_word_captures() -> Value {
    json!(*DISPLAYED_CAPTURES.lock().unwrap())
}
fn validate_displayed_words(report: &Value) -> Result<(), String> {
    let error = "original displayed phrase capture census/receiver/window mismatch";
    let calls = report["observer_calls"].as_array().ok_or(error)?;
    let captures = report["displayed_word_captures"].as_array().ok_or(error)?;
    let expected: Vec<_> = calls
        .iter()
        .enumerate()
        .filter(|(_, call)| call["kind"] == "seed.phrase")
        .collect();
    if captures.len() != expected.len() {
        return Err(error.into());
    }
    let mut previous = (0, 0);
    for (capture, (index, call)) in captures.iter().zip(expected) {
        let keys = ["call", "page", "ok", "at_ns", "history_cursor"];
        let at = capture["at_ns"].as_u64().ok_or(error)?;
        let cursor = capture["history_cursor"].as_u64().ok_or(error)?;
        let start = call["start_ns"].as_u64().ok_or(error)?;
        let end = call["end_ns"].as_u64().ok_or(error)?;
        let from = call["start_cursor"].as_u64().ok_or(error)?;
        let until = call["end_cursor"].as_u64().ok_or(error)?;
        if !capture.as_object().is_some_and(|fields| {
            fields.len() == keys.len() && keys.iter().all(|key| fields.contains_key(*key))
        }) || capture["call"].as_u64() != Some(index as u64 + 1)
            || capture["page"].as_u64().is_none()
            || capture["page"] != call["page"]
            || capture["ok"] != true
            || !(start..=end).contains(&at)
            || !(from..=until).contains(&cursor)
            || at < previous.0
            || cursor < previous.1
        {
            return Err(error.into());
        }
        previous = (at, cursor);
    }
    let domains = completion::inventory()["displayed_phrase_comparisons"]
        .as_object()
        .ok_or(error)?;
    for rule in domains.values() {
        let operands = rule["operands"].as_array().ok_or(error)?;
        if rule.as_object().is_none_or(|o| {
            o.len() != 3
                || ["operands", "predicate", "partner"]
                    .iter()
                    .any(|k| !o.contains_key(*k))
        }) || operands.len() > 2
            || operands.iter().any(|o| !o.is_string())
            || (operands.is_empty() && !rule["predicate"].is_null())
            || (!operands.is_empty() && !rule["predicate"].is_string())
            || (!rule["partner"].is_null()
                && !matches!(rule["partner"].as_array().map(Vec::as_slice),Some([kind]) if kind=="collision")
                && !rule["partner"].as_array().is_some_and(|a| {
                    a.len() == 3 && a[0] == "reader" && a[1].is_string() && a[2].is_string()
                }))
        {
            return Err(error.into());
        }
    }
    let cases = report["cases"].as_array().ok_or(error)?;
    let history = report["helper_history"].as_array().ok_or(error)?;
    let primary = report["primary_history"].as_array().ok_or(error)?;
    let mut expected_uses = Vec::new();
    for (index, call) in calls
        .iter()
        .enumerate()
        .filter(|(_, c)| c["kind"] == "seed.phrase")
    {
        let rule = domains
            .get(call["site"].as_str().ok_or(error)?)
            .ok_or(error)?;
        let case = cases
            .iter()
            .find(|c| {
                c["start_ns"].as_u64() <= call["start_ns"].as_u64()
                    && call["end_ns"].as_u64() <= c["end_ns"].as_u64()
            })
            .ok_or(error)?;
        let sources = rule["operands"]
            .as_array()
            .ok_or(error)?
            .iter()
            .map(|operand| {
                if operand == "self" {
                    Ok(index + 1)
                } else {
                    calls[..index]
                        .iter()
                        .rposition(|prior| {
                            prior["site"] == *operand
                                && case["start_ns"].as_u64() <= prior["start_ns"].as_u64()
                        })
                        .map(|n| n + 1)
                        .ok_or(error)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (position, source) in sources.iter().enumerate() {
            let other = if sources.len() == 2 {
                Some(sources[1 - position])
            } else {
                None
            };
            expected_uses.push((
                *source,
                other,
                call,
                case,
                &rule["predicate"],
                &rule["partner"],
            ));
        }
    }
    let uses = report["displayed_word_uses"].as_array().ok_or(error)?;
    if uses.len() != expected_uses.len() {
        return Err(error.into());
    }
    let mut previous = (0, 0);
    for (used, (source, other, call, case, predicate, reader)) in uses.iter().zip(expected_uses) {
        let at = used["at_ns"].as_u64().ok_or(error)?;
        let cursor = used["history_cursor"].as_u64().ok_or(error)?;
        let checked = primary
            .iter()
            .find(|p| {
                p["case"] == case["id"]
                    && p["id"] == format!("{}.i001", predicate.as_str().unwrap_or(""))
            })
            .ok_or(error)?;
        let expected_partner = if reader.is_null() {
            Value::Null
        } else if reader[0] == "collision" {
            let all = completion::inventory()["cases"].as_array().ok_or(error)?;
            let original = all
                .iter()
                .find(|c| c["id"] == case["id"] && c["site_id"] == "seed_cases.c001")
                .ok_or(error)?;
            let index = all
                .iter()
                .filter(|c| {
                    c["site_id"] == original["site_id"] && c["invocation"] == original["invocation"]
                })
                .position(|c| c["id"] == case["id"])
                .ok_or(error)?
                + 1;
            json!({"kind":"collision","index":index,"ok":true})
        } else {
            let roots = report["reader_roots"].as_array().ok_or(error)?;
            let found = roots
                .iter()
                .enumerate()
                .filter(|(_, r)| {
                    r["site"] == reader[1]
                        && r["start_ns"].as_u64() >= case["start_ns"].as_u64()
                        && r["end_ns"].as_u64().is_some_and(|end| end <= at)
                })
                .collect::<Vec<_>>();
            if found.len() != 1 {
                return Err(error.into());
            }
            json!({"kind":"reader","source":found[0].0+1,"site":reader[2],"ok":true})
        };
        let keys = [
            "partner",
            "call",
            "other",
            "result",
            "ok",
            "case",
            "at_ns",
            "history_cursor",
            "predicate",
            "instance",
            "check_ns",
            "check_cursor",
        ];
        if used
            .as_object()
            .is_none_or(|o| o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)))
            || used["call"] != source
            || used["other"] != json!(other)
            || used["partner"] != expected_partner
            || used["result"] != true
            || used["ok"] != true
            || used["case"] != case["id"]
            || used["predicate"] != *predicate
            || used["instance"] != 1
            || used["check_ns"] != checked["at_ns"]
            || used["check_cursor"] != checked["history_cursor"]
            || at < call["end_ns"].as_u64().ok_or(error)?
            || at > checked["at_ns"].as_u64().ok_or(error)?
            || checked["at_ns"].as_u64().ok_or(error)? > case["end_ns"].as_u64().ok_or(error)?
            || cursor > checked["history_cursor"].as_u64().ok_or(error)?
            || cursor < call["end_cursor"].as_u64().ok_or(error)?
            || history
                .get(cursor.wrapping_sub(1) as usize)
                .is_none_or(|e| e["at_ns"].as_u64().is_none_or(|n| n > at))
            || history
                .get(cursor as usize)
                .is_none_or(|e| e["at_ns"].as_u64().is_none_or(|n| n < at))
            || at < previous.0
            || cursor < previous.1
        {
            return Err(error.into());
        }
        previous = (at, cursor);
    }
    Ok(())
}

pub fn reentry_matches(site: &str, page: &str, words: &str) -> bool {
    let Some(case) = history::active_case_id() else {
        return false;
    };
    let Some(row) = completion::inventory()["reentry_sources"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["case"] == case))
    else {
        return false;
    };
    let Some(input) = row["calls"]
        .as_array()
        .and_then(|calls| calls.iter().find(|c| c["site"] == site))
    else {
        return false;
    };
    let expected = match input["words_role"].as_str() {
        Some("collision.next_control" | "collision.current_control") => input["input_source_index"]
            .as_u64()
            .and_then(|i| {
                include_str!("../../tests/vectors/seed-backup-collisions.txt")
                    .lines()
                    .nth(i as usize)
            })
            .map(str::to_owned),
        Some("fixed_valid_mismatch") => bip39::Mnemonic::from_entropy(&[17; 16])
            .ok()
            .map(|m| m.to_string()),
        Some("displayed.exact") => DISPLAYED_WORDS
            .lock()
            .unwrap()
            .get(&history::page_id(page))
            .cloned(),
        Some("displayed.with_source_whitespace") => DISPLAYED_WORDS
            .lock()
            .unwrap()
            .get(&history::page_id(page))
            .map(|m| format!("  {}\n", m.replace(' ', "\t"))),
        _ => None,
    };
    expected.as_deref() == Some(words)
}

pub fn passphrase_role(passphrase: &str) -> &'static str {
    match passphrase {
        super::PASSPHRASE => "store.primary",
        super::SERVED_PASSPHRASE => "store.served",
        super::WRONG_PASSPHRASE => "wrong",
        super::HOST_PASSPHRASE => "store.host",
        "fifteen chars!!" => "creation.short",
        _ => "unknown",
    }
}
fn runtime_input(call: u64, parameters: Value) {
    RUNTIME_INPUTS.lock().unwrap().push(json!({"call":call,"parameters":parameters,"at_ns":completion::now(),"history_cursor":history::cursor()}));
}
pub struct WorkerExclusion {
    call: u64,
    page: u64,
    old: Option<super::Worker>,
}
pub(super) struct WorkerCandidate {
    call: u64,
    page: u64,
    cursor: usize,
    worker: super::Worker,
}
impl std::ops::Deref for WorkerCandidate {
    type Target = super::Worker;
    fn deref(&self) -> &super::Worker {
        &self.worker
    }
}
impl WorkerCandidate {
    pub(super) fn selection(&self, call: u64, page: u64, cursor: usize) -> (&super::Worker, bool) {
        (
            &self.worker,
            self.call == call && self.page == page && self.cursor.checked_add(1) == Some(cursor),
        )
    }
}
impl WorkerExclusion {
    fn original(&self, old: Option<&super::Worker>) -> bool {
        self.old.as_ref() == old
            && old.is_none_or(|worker| history::selected_worker_matches(self.page, worker))
    }
    fn excludes(&self, worker: &super::Worker, old: Option<&super::Worker>) -> (bool, bool) {
        (Some(worker) != old, self.original(old))
    }
    /// Evaluate the original full-operand predicate and bind the operand it consumed.
    pub fn candidate(
        &self,
        run: &super::Run<'_>,
        tab: &super::Tab,
        old: Option<&super::Worker>,
    ) -> Option<WorkerCandidate> {
        let live = run.live_workers(tab);
        let (candidate, original) = match live.as_slice() {
            [worker] => {
                let (ready, original) = self.excludes(worker, old);
                (
                    ready.then(|| WorkerCandidate {
                        call: self.call,
                        page: self.page,
                        cursor: history::cursor(),
                        worker: worker.clone(),
                    }),
                    original,
                )
            }
            _ => (None, self.original(old)),
        };
        WORKER_EXCLUSIONS.lock().unwrap().push(json!({"call":self.call,"page":self.page,"ok":original && history::page_id(&tab.session) == self.page,"ready":candidate.is_some(),"at_ns":completion::now(),"history_cursor":history::cursor()}));
        candidate
    }
}
pub fn worker_exclusions() -> Value {
    json!(*WORKER_EXCLUSIONS.lock().unwrap())
}
pub fn worker_input(
    call: u64,
    page: &str,
    old: Option<&super::Worker>,
    in_use: bool,
) -> WorkerExclusion {
    let page = history::page_id(page);
    let role = match old {
        None => "none",
        Some(old) if history::selected_worker_matches(page, old) => "source_entry_current",
        Some(_) => "unknown",
    };
    runtime_input(call, json!({"old":role,"in_use":in_use}));
    WorkerExclusion {
        call,
        page,
        old: old.cloned(),
    }
}
pub fn settled_input(call: u64, in_use: bool) {
    runtime_input(call, json!({"in_use":in_use}));
}
pub fn prepare_input(call: u64, passphrase: &str) {
    runtime_input(call, json!({"passphrase_role":passphrase_role(passphrase)}));
}
pub fn runtime_snapshot() -> Value {
    json!(*RUNTIME_INPUTS.lock().unwrap())
}
pub fn binding_input(call: u64, slot: usize, name: &str) {
    let role = match name {
        "fixture" => "machine.first",
        "fixture-other" => "machine.second",
        "unpinned" => "machine.unpinned",
        _ => "unknown",
    };
    BINDING_INPUTS.lock().unwrap().push(json!({"call":call,"slot":slot,"role":role,"at_ns":completion::now(),"history_cursor":history::cursor()}));
}
pub fn binding_snapshot() -> Value {
    json!(*BINDING_INPUTS.lock().unwrap())
}

pub fn submission(call: u64, kind: &str, role: &'static str, cleared: bool) {
    let kind = match kind {
        "create" => "create",
        "unlock" => "unlock",
        _ => "unknown",
    };
    SUBMISSIONS.lock().unwrap().push(json!({"call":call,"kind":kind,"passphrase_role":role,"cleared":cleared,"at_ns":completion::now(),"history_cursor":history::cursor()}));
}
pub fn submission_snapshot() -> Value {
    json!(*SUBMISSIONS.lock().unwrap())
}

/// Capture the source's original pre-trigger baseline, never a completed poll's count.
pub fn counter_input(site: &'static str, path: &str, target: usize) {
    super::counter_inputs::bind(site, path, target);
}
pub fn counter_matches(site: &str, path: &str, target: usize) -> bool {
    super::counter_inputs::use_input(site, active_call().0, path, target)
}
pub fn key_input(site: &'static str, key: &super::key_inputs::Key) {
    super::key_inputs::bind(site, key);
}
pub fn key_matches(site: &str, key: &super::key_inputs::Key) -> bool {
    super::key_inputs::use_input(site, key, active_call().0)
}
pub fn session_input(session: &str) -> super::inputs::Session {
    let (call, site) = active_call();
    super::inputs::session_input(call, &site, session)
}
pub fn session_matches(session: &super::inputs::Session) -> bool {
    let (call, site) = active_call();
    super::inputs::session_matches(call, &site, session)
}
thread_local! {
    static ACTIVE: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

pub struct Call {
    index: usize,
    arguments: BTreeMap<&'static str, Vec<SourceArgument>>,
    job_candidate: RefCell<(Option<u64>, Option<String>)>,
    holder: Option<super::Worker>,
}
impl Call {
    pub fn begin(
        site: &'static str,
        kind: &'static str,
        page: Option<&str>,
        domain: Value,
    ) -> Self {
        let arguments: BTreeMap<_, _> = {
            let mut pending = SOURCE_ARGUMENTS.lock().unwrap();
            let keys: Vec<_> = pending
                .keys()
                .filter(|(source, _)| *source == site)
                .copied()
                .collect();
            keys.into_iter()
                .map(|key| (key.1, pending.remove(&key).unwrap()))
                .collect()
        };
        let argument_domains: Vec<_> = arguments.iter().map(|(name,values)|json!({"name":name,"captures":values.iter().map(|v|json!({"at_ns":v.at_ns,"history_cursor":v.cursor,"order":v.order,"input":v.input})).collect::<Vec<_>>()})).collect();
        let argument_triggers = ARGUMENT_TRIGGERS
            .lock()
            .unwrap()
            .remove(site)
            .unwrap_or_default();
        let holder_values = if site == "main.writer.holder_and_waiter" {
            std::mem::take(&mut *HOLDER_INPUTS.lock().unwrap())
        } else {
            Vec::new()
        };
        let holder = if holder_values.len() == 1 {
            Some(holder_values[0].0.clone())
        } else {
            None
        };
        let mut holder_inputs: Vec<_> = holder_values.into_iter().map(|(_, value)| value).collect();
        if site == "goal.document.connection_closed" {
            holder_inputs.extend(std::mem::take(&mut *PENDING_GOAL_ENDS.lock().unwrap()));
        }
        let mut calls = CALLS.lock().unwrap();
        let index = calls.len();
        let parent = ACTIVE.with_borrow(|a| a.last().copied());
        calls.push(json!({"site":site,"kind":kind,"domain":domain,"domain_captures":0,"argument_domains":argument_domains,"argument_triggers":argument_triggers,"argument_matches":[],"causal_input":holder_inputs,"causal_result":[],"causal_matches":[],"page":page.map(history::page_id),"parent":parent.map(|i|i+1),"children":[],"polls":[],"facts":[],"inputs":[],"page_inputs":[],"start_ns":completion::now(),"end_ns":null,"start_cursor":history::cursor(),"end_cursor":null}));
        if let Some(parent) = parent {
            calls[parent]["children"]
                .as_array_mut()
                .unwrap()
                .push(json!(index + 1));
        }
        ACTIVE.with_borrow_mut(|a| a.push(index));
        if site == "inference.core.revoke_terminal" {
            super::key_inputs::terminal_input(index + 1);
        }
        if super::session_operands::supported(site) {
            super::session_operands::use_input(site, index + 1);
        }
        Self {
            index,
            arguments,
            job_candidate: RefCell::new((None, None)),
            holder,
        }
    }
    pub(super) fn original_attempt(&self) -> usize {
        CALLS.lock().unwrap()[self.index]["polls"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["attempt"]
            .as_u64()
            .unwrap() as usize
    }
    pub async fn session_document(
        &self,
        run: &super::Run<'_>,
        worker: &super::Worker,
        session: &super::session_operands::Session,
    ) -> Result<Value, String> {
        let expression = format!(
            "return JSON.parse(m.test_document_state({}));",
            json!(session)
        );
        let start = completion::now();
        let value = self.module(run, worker, &expression).await?;
        super::session_operands::query(
            (self.index + 1, self.original_attempt()),
            session,
            (Some(worker), &worker.session),
            (&expression, &value, start),
        );
        Ok(value)
    }
    pub fn session_predicate(
        &self,
        session: &super::session_operands::Session,
        document: &Value,
        state: Option<&Value>,
    ) -> bool {
        super::session_operands::predicate(
            false,
            self.index + 1,
            self.original_attempt(),
            session,
            document,
            state,
        )
    }
    pub async fn session_hidden_done(
        &self,
        run: &super::Run<'_>,
        page: &str,
        session: &super::session_operands::Session,
    ) -> Result<bool, String> {
        let expression = format!(
            "document.querySelector('[data-goal-outcome=\"{}\"]')?.textContent.includes('done')??false",
            session
        );
        let start = completion::now();
        self.page_input(page, "source");
        let value = run.browser.evaluate(page, &expression).await?;
        super::session_operands::query(
            (self.index + 1, self.original_attempt()),
            session,
            (None, page),
            (&expression, &value, start),
        );
        Ok(super::session_operands::predicate(
            true,
            self.index + 1,
            self.original_attempt(),
            session,
            &value,
            None,
        ))
    }
    pub fn key_refused(
        &self,
        run: &super::Run<'_>,
        key: &super::key_inputs::Key,
        attempt: usize,
    ) -> bool {
        super::key_inputs::refused(self.index + 1, attempt, run, key)
    }
    pub fn key_terminal(&self, id: &super::key_inputs::Id, state: &Value) -> bool {
        super::key_inputs::terminal(self.index + 1, self.original_attempt(), id, state)
    }
    pub fn ssh_counter(
        &self,
        sshd: &super::fixtures::Sshd,
        field: &str,
        counter: &std::sync::Arc<std::sync::atomic::AtomicU32>,
    ) -> u32 {
        let (value, mut input) = super::causal::ssh_counter(sshd, field, counter);
        input["name"] = json!("ssh_counter");
        input["attempt"] = json!(self.original_attempt());
        CALLS.lock().unwrap()[self.index]["causal_matches"]
            .as_array_mut()
            .unwrap()
            .push(input);
        value
    }
    pub fn id(&self) -> usize {
        self.index + 1
    }
    pub fn fixture_predicate(&self, operands: Value, ready: bool) -> bool {
        let attempt = self.original_attempt();
        let mut calls = CALLS.lock().unwrap();
        calls[self.index]["causal_matches"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "name":"fixture_predicate","operands":operands,"ready":ready,
                "attempt":attempt,
                "at_ns":completion::now(),"history_cursor":history::cursor()
            }));
        ready
    }
    pub fn counter_ready(
        &self,
        run: &super::Run<'_>,
        path: &str,
        target: usize,
        attempt: usize,
    ) -> bool {
        super::counter_inputs::ready(self.index + 1, run, path, target, attempt)
    }
    pub fn causal_input(&self, value: Value) {
        CALLS.lock().unwrap()[self.index]["causal_input"]
            .as_array_mut()
            .unwrap()
            .push(value);
    }
    pub fn causal_result(&self, value: Value) {
        CALLS.lock().unwrap()[self.index]["causal_result"]
            .as_array_mut()
            .unwrap()
            .push(value);
    }
    pub fn begin_worker(
        site: &'static str,
        kind: &'static str,
        worker: &super::Worker,
        domain: Value,
    ) -> Self {
        let call = Self::begin(site, kind, None, domain);
        let (_, page) = history::worker_identity(&worker.session);
        CALLS.lock().unwrap()[call.index]["page"] = json!(page);
        call
    }
    pub fn counter_greater(&self, name: &'static str, observed: usize, before: usize) -> bool {
        let site = CALLS.lock().unwrap()[self.index]["site"]
            .as_str()
            .unwrap()
            .to_owned();
        let queries = take_document_queries(&site, name);
        let ready = observed > before;
        let ok = self
            .arguments
            .get(name)
            .is_some_and(|v| v.len() == 1 && v[0].value == json!(before));
        let at = completion::now();
        let cursor = history::cursor();
        let mut calls = CALLS.lock().unwrap();
        let call = &mut calls[self.index];
        let attempt = call["polls"]
            .as_array()
            .and_then(|v| v.last())
            .map(|p| p["attempt"].clone());
        call["argument_matches"].as_array_mut().unwrap().push(json!({"name":name,"ok":ok,"ready":ready,"attempt":attempt,"at_ns":at,"history_cursor":cursor,"observed":observed,"before":before,"queries":queries}));
        ready
    }
    pub async fn completed_reads_differ(
        &self,
        run: &super::Run<'_>,
        worker: &super::Worker,
        expression: &str,
        before: &Value,
    ) -> Result<bool, String> {
        let observed = self.worker_evaluate(run, worker, expression).await?;
        let ready = observed != *before;
        let ok = expression == COMPLETED_READS
            && self
                .arguments
                .get("reads_before")
                .is_some_and(|v| v.len() == 1 && v[0].value == *before);
        let mut calls = CALLS.lock().unwrap();
        let call = &mut calls[self.index];
        let attempt = call["polls"]
            .as_array()
            .and_then(|v| v.last())
            .map(|p| p["attempt"].clone());
        call["argument_matches"].as_array_mut().unwrap().push(json!({"name":"reads_before","ok":ok,"ready":ready,"attempt":attempt,"at_ns":completion::now(),"history_cursor":history::cursor()}));
        Ok(ready)
    }
    fn causal_match(&self, name: &'static str, ok: bool, ready: bool) -> bool {
        let mut calls = CALLS.lock().unwrap();
        let call = &mut calls[self.index];
        let attempt = call["polls"]
            .as_array()
            .and_then(|v| v.last())
            .map(|p| p["attempt"].clone());
        call["causal_matches"].as_array_mut().unwrap().push(json!({"name":name,"ok":ok,"ready":ready,"attempt":attempt,"at_ns":completion::now(),"history_cursor":history::cursor()}));
        ready
    }
    pub fn job_marker(
        &self,
        sshd: &super::fixtures::Sshd,
        source: usize,
        id: &str,
        file: &str,
        prefix: &[u8],
    ) -> bool {
        let ok = super::causal::fixture_role(sshd) == "primary"
            && super::causal::job_is(source + 1, id)
            && file == "stdout"
            && prefix == b"started\n";
        self.causal_match(
            "marker",
            ok,
            std::fs::read(sshd.machine.path(id, file)).is_ok_and(|b| b.starts_with(prefix)),
        )
    }
    pub fn class_ready(&self, state: &Value, machine: &str) -> bool {
        let role = match machine {
            "fixture" => "first",
            "fixture-other" => "second",
            _ => "unknown",
        };
        let ok = CALLS.lock().unwrap()[self.index]["causal_input"][0]["machine"] == role
            && role != "unknown";
        let ready = state["setup"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["entry"]["machine"] == machine && !m["class"].is_null());
        self.causal_match("class_machine", ok, ready)
    }
    pub fn holder_and_waiter(
        &self,
        one: &impl Fn(&super::Tab) -> Option<super::Worker>,
        tabs: (&super::Tab, &super::Tab),
        worker: &super::Worker,
        views: &(super::view_inputs::View, super::view_inputs::View),
        states: [Option<&str>; 2],
    ) -> bool {
        let inputs = CALLS.lock().unwrap();
        let call = &inputs[self.index];
        let pages = call["page_inputs"].as_array().unwrap();
        let ok = self.holder.as_ref() == Some(worker)
            && pages.len() >= 2
            && pages[pages.len() - 2]["page"] == history::page_id(&tabs.0.session)
            && pages[pages.len() - 1]["page"] == history::page_id(&tabs.1.session)
            && call["causal_input"][0]["page"] == history::page_id(&tabs.0.session);
        drop(inputs);
        let ready = one(tabs.0).is_some_and(|w| w == *worker)
            && one(tabs.1).is_some()
            && views.0["status"] == "ready"
            && views.1["status"] == "ready"
            && states == [Some("unlocked"), Some("in-use")];
        super::view_inputs::holder_ready(
            self.index + 1,
            self.original_attempt(),
            views,
            states,
            ready,
        );
        self.causal_match("holder", ok, ready)
    }
    pub fn job_result(&self, source: usize, call: u64, id: String) -> (u64, String) {
        let candidate = self.job_candidate.borrow();
        self.causal_result(super::causal::produced(
            source,
            &id,
            self.id(),
            call,
            (candidate.0, candidate.1.as_deref()),
        ));
        (call, id)
    }
    pub fn job_newer(&self, call: u64, previous: u64) -> bool {
        let source = CALLS.lock().unwrap()[self.index]["causal_input"][0]["source"]
            .as_u64()
            .unwrap() as usize;
        self.causal_match(
            "newer",
            self.job_candidate.borrow().0 == Some(call)
                && super::causal::previous_is(source, previous),
            call > previous,
        )
    }
    pub fn job_contains(&self, sshd: &super::fixtures::Sshd, id: &str) -> bool {
        let ok = super::causal::fixture_role(sshd) == "primary"
            && self.job_candidate.borrow().1.as_deref() == Some(id);
        self.causal_match("contains", ok, sshd.machine.observe().contains_key(id))
    }
    pub fn job_ended(&self, sshd: &super::fixtures::Sshd, id: &str) -> bool {
        let source = CALLS.lock().unwrap()[self.index]["causal_input"][0]["source"]
            .as_u64()
            .unwrap_or(0) as usize;
        let ok =
            super::causal::fixture_role(sshd) == "primary" && super::causal::job_is(source, id);
        self.causal_match(
            "ended",
            ok,
            sshd.machine
                .observe()
                .get(id)
                .is_some_and(|j| j.ended.is_some()),
        )
    }
    pub fn job_exit(&self, sshd: &super::fixtures::Sshd, id: &str) -> bool {
        let source = CALLS.lock().unwrap()[self.index]["causal_input"][0]["source"]
            .as_u64()
            .unwrap_or(0) as usize;
        let ok =
            super::causal::fixture_role(sshd) == "primary" && super::causal::job_is(source, id);
        self.causal_match("exit", ok, sshd.machine.path(id, "exit").is_file())
    }
    pub fn domain(&self, domain: Value) {
        let mut calls = CALLS.lock().unwrap();
        let call = &mut calls[self.index];
        call["domain"] = domain;
        call["domain_captures"] = json!(call["domain_captures"].as_u64().unwrap() + 1);
    }
    pub fn attempt(&self, attempt: usize) {
        CALLS.lock().unwrap()[self.index]["polls"].as_array_mut().unwrap().push(json!({"attempt":attempt,"ready":null,"start_ns":completion::now(),"end_ns":null,"start_cursor":history::cursor(),"end_cursor":null}));
    }
    pub fn view_poll(&self, attempt: usize, view: &super::view_inputs::View) -> bool {
        let site = CALLS.lock().unwrap()[self.index]["site"]
            .as_str()
            .unwrap()
            .to_owned();
        self.poll(
            attempt,
            super::view_inputs::observer_ready(&site, self.index + 1, attempt, view),
        )
    }
    pub fn fact(&self, field: &'static str, value: bool) -> bool {
        CALLS.lock().unwrap()[self.index]["facts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":field,"ok":value}));
        value
    }
    fn page_input(&self, session: &str, slot: &'static str) {
        CALLS.lock().unwrap()[self.index]["page_inputs"].as_array_mut().unwrap().push(json!({"slot":slot,"page":history::page_id(session),"at_ns":completion::now(),"history_cursor":history::cursor()}));
    }
    pub async fn page_evaluate(
        &self,
        run: &super::Run<'_>,
        session: &str,
        expression: &str,
    ) -> Result<Value, String> {
        self.page_input(session, "source");
        run.browser.evaluate(session, expression).await
    }
    pub async fn page_predicate(
        &self,
        run: &super::Run<'_>,
        session: &str,
        expression: &str,
    ) -> Result<super::page_queries::PageValue, String> {
        self.page_input(session, "source");
        let site = CALLS.lock().unwrap()[self.index]["site"]
            .as_str()
            .unwrap()
            .to_owned();
        super::page_queries::evaluate(
            self.index + 1,
            &site,
            self.original_attempt(),
            run,
            session,
            expression,
        )
        .await
    }
    pub async fn worker_evaluate(
        &self,
        run: &super::Run<'_>,
        worker: &super::Worker,
        expression: &str,
    ) -> Result<Value, String> {
        self.input(worker);
        run.browser.evaluate(&worker.session, expression).await
    }
    pub async fn view(
        &self,
        run: &super::Run<'_>,
        tab: &super::Tab,
        slot: &'static str,
    ) -> Result<super::view_inputs::View, String> {
        self.page_input(&tab.session, slot);
        super::view_inputs::read(
            super::view_inputs::Origin::Observer {
                call: self.index + 1,
                attempt: self.original_attempt(),
                slot,
            },
            run,
            tab,
            super::VIEW,
        )
        .await
    }
    pub async fn module(
        &self,
        run: &super::Run<'_>,
        worker: &super::Worker,
        script: &str,
    ) -> Result<Value, String> {
        self.input(worker);
        super::inference_cases::module(run, worker, script).await
    }
    fn input(&self, worker: &super::Worker) {
        let (identity, page) = history::worker_identity(&worker.session);
        CALLS.lock().unwrap()[self.index]["inputs"].as_array_mut().unwrap().push(json!({"worker":identity,"page":page,"at_ns":completion::now(),"history_cursor":history::cursor()}));
    }
    pub async fn pending(
        &self,
        run: &super::Run<'_>,
        worker: &super::Worker,
    ) -> Result<super::file_windows::Pending, String> {
        self.input(worker);
        let site = CALLS.lock().unwrap()[self.index]["site"]
            .as_str()
            .unwrap()
            .to_owned();
        super::file_windows::pending(&site, Some(self.index + 1), run, worker).await
    }
    pub async fn inspect(
        &self,
        run: &super::Run<'_>,
        worker: &super::Worker,
    ) -> Result<Value, String> {
        self.input(worker);
        let state = run.inspect(worker).await?;
        if CALLS.lock().unwrap()[self.index]["kind"] == "job.wait_launch" {
            let last = state["calls"].as_array().and_then(|c| c.last());
            let candidate = (
                last.and_then(|c| c["call"].as_u64()),
                last.and_then(|c| c["job"].as_str()).map(str::to_owned),
            );
            let typed = candidate.0.is_some() && candidate.1.is_some();
            *self.job_candidate.borrow_mut() = candidate;
            self.causal_match("candidate", true, typed);
        }
        {
            let calls = CALLS.lock().unwrap();
            let c = &calls[self.index];
            if c["site"] == "inference.core.revoke_terminal" {
                super::key_inputs::candidate(
                    self.index + 1,
                    c["polls"]
                        .as_array()
                        .unwrap()
                        .last()
                        .and_then(|p| p["attempt"].as_u64())
                        .unwrap_or(0) as usize,
                    &state,
                );
            }
            if c["site"] == "lifecycle_repairs.source_append.completed" {
                super::session_operands::candidate(
                    self.index + 1,
                    c["polls"].as_array().unwrap().last().unwrap()["attempt"]
                        .as_u64()
                        .unwrap() as usize,
                    &state,
                );
            }
            if c["kind"] == "declaration.prepare.binding" {
                super::inputs::candidate(c["parent"].as_u64().unwrap() as usize, &state);
            } else if c["kind"] == "delivery.prepare" {
                super::inputs::candidate(self.index + 1, &state);
            }
        }
        Ok(state)
    }
}
impl Drop for Call {
    fn drop(&mut self) {
        let mut calls = CALLS.lock().unwrap();
        calls[self.index]["end_ns"] = json!(completion::now());
        calls[self.index]["end_cursor"] = json!(history::cursor());
        ACTIVE.with_borrow_mut(|a| assert_eq!(a.pop(), Some(self.index)));
    }
}
pub fn current_source() -> Option<(String, usize)> {
    let index = ACTIVE.with_borrow(|a| a.last().copied())?;
    let calls = CALLS.lock().unwrap();
    let site = calls[index]["site"].as_str()?;
    let ordinal = calls[..=index].iter().filter(|c| c["site"] == site).count();
    Some((site.to_owned(), ordinal))
}

pub fn snapshot() -> Value {
    json!(*CALLS.lock().unwrap())
}

type Owner = (String, String, String);
fn owner(row: &Value) -> Owner {
    (
        row["scenario"].as_str().unwrap().into(),
        row["owner"].as_str().unwrap().into(),
        row["case"].as_str().unwrap_or("").into(),
    )
}

fn expected(report: &Value) -> Result<BTreeMap<Owner, Vec<Value>>, String> {
    let inventory = completion::inventory();
    let rows = if report["mode"] == "full" {
        &inventory["invocation_observer_sequences"]
    } else {
        &report["plan"]["invocation_observer_sequences"]
    };
    let mut result = BTreeMap::new();
    for row in rows
        .as_array()
        .ok_or("missing observer source caller trees")?
    {
        let mut calls = Vec::new();
        for node in row["calls"].as_array().unwrap() {
            if node["if"] == "reload_raw_revoke_absent" {
                let read = report["reader_roots"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|r| r["site"] == "reader.call.inference.reload_revoke")
                    .ok_or("missing observer raw journal input")?;
                let state = read["auxiliary_inputs"]["reload_revoke"]
                    .as_str()
                    .ok_or("missing observer independent revoke domain")?;
                if state == "absent" {
                    calls.push(node["then"].clone());
                }
            } else {
                calls.push(node.clone());
            }
        }
        for node in &mut calls {
            node["invocation"] = row["invocation"].clone();
        }
        result
            .entry(owner(row))
            .or_insert_with(Vec::new)
            .extend(calls);
    }
    if matches!(
        report["plan"]["name"].as_str(),
        Some("hold.union" | "inference.session-end.selection")
    ) {
        let execution = report["plan"]["expected_execution"]
            .as_array()
            .ok_or("missing admitted direct observer execution")?;
        for row in inventory["direct_observer_source_rows"]
            .as_array()
            .ok_or("missing composed direct observer source")?
        {
            let Some(index) = execution.iter().position(|c| c == &row["case"]) else {
                continue;
            };
            let mut projected = row.clone();
            if row["position"] == "before" {
                projected["owner"] = json!("after");
                projected["case"] = index
                    .checked_sub(1)
                    .map(|i| execution[i].clone())
                    .unwrap_or(json!(""));
            } else {
                projected["owner"] = row["position"].clone();
            }
            let calls = result.entry(owner(&projected)).or_default();
            let position = if let Some(before) = row["before_existing_site"].as_str() {
                calls
                    .iter()
                    .position(|c| before.split('|').any(|s| c["site"] == s))
                    .ok_or("missing source direct observer preceding anchor")?
            } else if let Some(after) = row["after_existing_site"].as_str() {
                calls
                    .iter()
                    .position(|c| after.split('|').any(|s| c["site"] == s))
                    .map(|i| i + 1)
                    .ok_or("missing source direct observer following anchor")?
            } else {
                calls.len()
            };
            calls.splice(
                position..position,
                row["calls"].as_array().unwrap().iter().map(|node| {
                    let mut node = node.clone();
                    node["invocation"] = json!(1);
                    node
                }),
            );
        }
    }
    Ok(result)
}

pub(super) fn source_positions(report: &Value) -> Vec<(usize, bool)> {
    let states = reader_checks::caller_states(report);
    let mut positions: BTreeMap<Owner, usize> = BTreeMap::new();
    let mut depth = 0;
    let mut result = vec![(0, true)];
    for (index, event) in report["helper_history"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        if event["event"] == "call_start" {
            depth += 1;
        } else if event["event"] == "call_end" {
            depth -= 1;
            if depth == 0 {
                *positions
                    .entry(states[index].owner.clone().unwrap())
                    .or_default() += 1;
            }
        } else if event["event"] == "check" && depth == 0 {
            *positions
                .entry(states[index + 1].owner.clone().unwrap())
                .or_default() += 1;
        }
        let position = states[index + 1]
            .owner
            .as_ref()
            .and_then(|o| positions.get(o))
            .copied()
            .unwrap_or(0);
        result.push((position, depth == 0));
    }
    result
}
fn causal_expected(report: &Value) -> Result<BTreeMap<Owner, Vec<Value>>, String> {
    let inventory = completion::inventory();
    let execution: Vec<_> = if report["mode"] == "full" {
        inventory["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].clone())
            .collect()
    } else {
        report["plan"]["expected_execution"]
            .as_array()
            .unwrap()
            .clone()
    };
    let mut result: BTreeMap<Owner, Vec<Value>> = BTreeMap::new();
    for row in inventory["causal_observer_sources"]
        .as_array()
        .ok_or("missing causal observer source program")?
    {
        let mut source = row.clone();
        if row["position"] == "cleanup" {
            source["owner"] = json!("cleanup");
            result
                .entry(owner(&source))
                .or_default()
                .extend(row["calls"].as_array().unwrap().iter().cloned());
            continue;
        }
        let Some(index) = execution.iter().position(|c| c == &row["case"]) else {
            continue;
        };
        if row["position"] == "before" {
            source["owner"] = json!("after");
            source["case"] = index
                .checked_sub(1)
                .map(|i| execution[i].clone())
                .unwrap_or(json!(""));
        } else {
            source["owner"] = row["position"].clone();
        }
        result
            .entry(owner(&source))
            .or_default()
            .extend(row["calls"].as_array().unwrap().iter().cloned());
    }
    for calls in result.values_mut() {
        calls.sort_by_key(|c| c["root_start"].as_u64().unwrap());
    }
    Ok(result)
}

struct Validation<'a> {
    report: &'a Value,
    states: Vec<reader_checks::CallerState>,
    pages: Vec<BTreeMap<String, u64>>,
    workers: Vec<BTreeMap<u64, u64>>,
    prior_used: RefCell<Vec<bool>>,
    positions: Vec<(usize, bool)>,
    job_producers: RefCell<BTreeMap<u64, (Value, Value)>>,
    class_inputs: RefCell<Vec<Value>>,
    goal_end_inputs: RefCell<Vec<Value>>,
    argument_trigger_groups: RefCell<BTreeMap<(Owner, String), Value>>,
    argument_group_sites: RefCell<BTreeMap<(Owner, String), Vec<String>>>,
    argument_captures: RefCell<Vec<Value>>,
}
impl Validation<'_> {
    fn direct_operand(&self, call: &Value, node: &Value, owner: &Owner) -> Result<bool, String> {
        let site = node["site"].as_str().unwrap();
        if site == "goal.document.connection_closed" {
            let inputs = call["causal_input"]
                .as_array()
                .ok_or("missing original end dispatch")?;
            if inputs.len() != 1
                || call["causal_result"] != json!([])
                || call["causal_matches"] != json!([])
            {
                return Err("original end dispatch multiplicity mismatch".into());
            }
            let input = &inputs[0];
            let n = self.goal_end_inputs.borrow().len();
            if input.as_object().is_none_or(|o| o.len() != 8)
                || input["source"].as_u64() != Some((n + 1) as u64)
                || input["input_ok"] != true
                || !input["input_ok"].is_boolean()
                || self.report["goal_end_inputs"].get(n) != Some(input)
            {
                return Err("original end dispatch source mismatch".into());
            }
            self.goal_end_inputs.borrow_mut().push(input.clone());
            let start = input["start_ns"]
                .as_u64()
                .ok_or("invalid original end start")?;
            let end = input["end_ns"]
                .as_u64()
                .ok_or("invalid original end finish")?;
            let cursor = self.cursor(&input["start_cursor"], start, owner)?;
            let last = self.cursor(&input["end_cursor"], end, owner)?;
            let calls = self.report["observer_calls"].as_array().unwrap();
            let prior: Vec<_> = calls
                .iter()
                .filter(|c| {
                    c["site"] == "goal.document.active_sent"
                        && self.states[c["start_cursor"].as_u64().unwrap() as usize]
                            .owner
                            .as_ref()
                            == Some(owner)
                })
                .collect();
            let page = input["page"].as_u64().ok_or("invalid original end page")?;
            let worker = input["worker"]
                .as_u64()
                .ok_or("invalid original end worker")?;
            if prior.len() != 1
                || prior[0]["end_ns"].as_u64().unwrap() > start
                || start > end
                || end > call["start_ns"].as_u64().unwrap()
                || input["start_cursor"] != prior[0]["end_cursor"]
                || cursor != last
                || input["end_cursor"] != call["start_cursor"]
                || self.pages[cursor].get("tracer") != Some(&page)
                || self.workers[cursor].get(&page) != Some(&worker)
                || call["page"] != page
                || call["argument_triggers"][0]["worker"] != worker
            {
                return Err("original end dispatch source order mismatch".into());
            }
            return Ok(true);
        }

        if !matches!(
            site,
            "setup.class.answer_applied" | "main.writer.holder_and_waiter"
        ) {
            return Ok(false);
        }
        let inputs = call["causal_input"]
            .as_array()
            .ok_or("missing original direct operands")?;
        if inputs.len() != 1 || call["causal_result"] != json!([]) {
            return Err("original direct operand capture multiplicity mismatch".into());
        }
        let input = &inputs[0];
        if site == "setup.class.answer_applied" {
            if input.as_object().is_none_or(|v| {
                v.len() != 9
                    || ![
                        "source",
                        "machine",
                        "answer",
                        "page",
                        "start_ns",
                        "end_ns",
                        "start_cursor",
                        "end_cursor",
                        "selector_ok",
                    ]
                    .iter()
                    .all(|k| v.contains_key(*k))
            }) || input["machine"] != node["domain"]["machine"]
                || input["answer"] != node["domain"]["answer"]
                || input["selector_ok"] != true
            {
                return Err("original class answer dispatch input mismatch".into());
            }
            let index = self.class_inputs.borrow().len();
            let triggers = self.report["class_inputs"]
                .as_array()
                .ok_or("missing original class trigger census")?;
            if input["source"] != index + 1 || triggers.get(index) != Some(input) {
                return Err("original class trigger multiplicity/order mismatch".into());
            }
            self.class_inputs.borrow_mut().push(input.clone());
            let start = input["start_ns"]
                .as_u64()
                .ok_or("invalid original class input time")?;
            let end = input["end_ns"]
                .as_u64()
                .ok_or("invalid original class dispatch end")?;
            let cursor = self.cursor(&input["start_cursor"], start, owner)?;
            self.cursor(&input["end_cursor"], end, owner)?;
            if start > end
                || end > call["start_ns"].as_u64().unwrap()
                || input["start_cursor"] != input["end_cursor"]
                || input["end_cursor"] != call["start_cursor"]
                || self.pages[cursor]
                    .get(node["page_role"].as_str().unwrap())
                    .is_none_or(|p| input["page"] != *p)
            {
                return Err("original class dispatch source lineage mismatch".into());
            }
        } else {
            if input.as_object().is_none_or(|v| {
                v.len() != 5
                    || !["at_ns", "history_cursor", "worker", "page", "worker_ok"]
                        .iter()
                        .all(|k| v.contains_key(*k))
            }) || input["worker_ok"] != true
            {
                return Err("invalid original holder Worker capture".into());
            }
            let at = input["at_ns"]
                .as_u64()
                .ok_or("invalid holder operand capture time")?;
            let cursor = self.cursor(&input["history_cursor"], at, owner)?;
            let start_cursor = call["start_cursor"].as_u64().unwrap() as usize;
            let event = self.report["helper_history"]
                .get(cursor)
                .ok_or("holder capture without original page birth")?;
            let page = input["page"]
                .as_u64()
                .ok_or("invalid original holder page")?;
            if self.positions[cursor] != (0, true)
                || self.positions[start_cursor] != (1, true)
                || event["event"] != "call_start"
                || event["kind"] != "runtime.worker"
                || event["at_ns"].as_u64().unwrap() < at
                || self.pages[cursor].get("tracer") != Some(&page)
                || self.workers[cursor]
                    .get(&page)
                    .is_none_or(|w| input["worker"] != *w)
                || call["page"] != page
            {
                return Err("original holder Worker capture/birth lineage mismatch".into());
            }
        }
        let matches = call["causal_matches"]
            .as_array()
            .ok_or("missing original direct operand uses")?;
        let polls = call["polls"].as_array().unwrap();
        if matches.len() != polls.len() {
            return Err("original direct operand use multiplicity mismatch".into());
        }
        let name = if site == "setup.class.answer_applied" {
            "class_machine"
        } else {
            "holder"
        };
        for (value, poll) in matches.iter().zip(polls) {
            let at = value["at_ns"]
                .as_u64()
                .ok_or("invalid direct operand use time")?;
            self.cursor(&value["history_cursor"], at, owner)?;
            if value.as_object().is_none_or(|v| {
                v.len() != 6
                    || !["name", "ok", "ready", "attempt", "at_ns", "history_cursor"]
                        .iter()
                        .all(|k| v.contains_key(*k))
            }) || value["name"] != name
                || value["ok"] != true
                || value["ready"] != poll["ready"]
                || value["attempt"] != poll["attempt"]
                || at < poll["start_ns"].as_u64().unwrap()
                || at > poll["end_ns"].as_u64().unwrap()
            {
                return Err("original direct operand predicate/attempt mismatch".into());
            }
        }
        Ok(true)
    }

    fn job_receiver(
        &self,
        value: &Value,
        owner: &Owner,
        position: u64,
        query: bool,
    ) -> Result<(u64, usize), String> {
        let keys = if query {
            vec![
                "worker",
                "page",
                "worker_ok",
                "at_ns",
                "history_cursor",
                "end_ns",
                "end_cursor",
            ]
        } else {
            vec![
                "worker",
                "page",
                "worker_ok",
                "at_ns",
                "history_cursor",
                "input_ok",
            ]
        };
        if value
            .as_object()
            .is_none_or(|v| v.len() != keys.len() || keys.iter().any(|k| !v.contains_key(*k)))
        {
            return Err("invalid causal job source input schema".into());
        }
        let at = value["at_ns"]
            .as_u64()
            .ok_or("invalid causal source time")?;
        let cursor = self.cursor(&value["history_cursor"], at, owner)?;
        let page = value["page"].as_u64().ok_or("invalid causal source page")?;
        if value["worker_ok"] != true
            || !query && value["input_ok"] != true
            || self.positions[cursor] != (position as usize, true)
            || self.pages[cursor].get("tracer") != Some(&page)
            || self.workers[cursor]
                .get(&page)
                .is_none_or(|w| value["worker"] != *w)
        {
            return Err("causal job source receiver/history mismatch".into());
        }
        if query {
            let end = value["end_ns"]
                .as_u64()
                .ok_or("invalid causal baseline query end")?;
            self.cursor(&value["end_cursor"], end, owner)?;
            if end < at || value["end_cursor"] != value["history_cursor"] {
                return Err("causal baseline query crosses source history".into());
            }
        }
        Ok((at, cursor))
    }
    fn job_input(
        &self,
        index: usize,
        call: &Value,
        node: &Value,
        owner: &Owner,
    ) -> Result<(), String> {
        if self.direct_operand(call, node, owner)? {
            return Ok(());
        }
        let kind = node["kind"].as_str().unwrap();
        if kind == "fixture.ssh_ended" || node["site"] == "session.closed.ssh" {
            if call["causal_input"] != json!([]) || call["causal_result"] != json!([]) {
                return Err("unexpected original SSH counter input".into());
            }
            let matches = call["causal_matches"]
                .as_array()
                .ok_or("missing original SSH counter observations")?;
            let polls = call["polls"].as_array().unwrap();
            if matches.len() != polls.len() * 2 {
                return Err("original SSH counter multiplicity mismatch".into());
            }
            for (pair, poll) in matches.as_chunks::<2>().0.iter().zip(polls) {
                let mut prior = poll["start_ns"].as_u64().unwrap();
                let mut values = Vec::new();
                let fields = if kind == "fixture.ssh_ended" {
                    ["ended", "accepted"]
                } else {
                    ["accepted", "ended"]
                };
                let role = if kind == "fixture.ssh_ended" {
                    node["domain"]["fixture"].as_str().unwrap()
                } else {
                    "primary"
                };
                for (input, field) in pair.iter().zip(fields) {
                    let at = input["at_ns"]
                        .as_u64()
                        .ok_or("invalid original SSH counter time")?;
                    let value = input["value"]
                        .as_u64()
                        .filter(|v| *v <= u32::MAX as u64)
                        .ok_or("invalid original SSH counter value")?;
                    if input.as_object().is_none_or(|o| {
                        o.len() != 8
                            || ![
                                "name",
                                "attempt",
                                "field",
                                "role",
                                "receiver_ok",
                                "value",
                                "at_ns",
                                "history_cursor",
                            ]
                            .iter()
                            .all(|k| o.contains_key(*k))
                    }) || input["name"] != "ssh_counter"
                        || input["field"] != field
                        || input["role"] != role
                        || input["receiver_ok"] != true
                        || !input["receiver_ok"].is_boolean()
                        || input["attempt"] != poll["attempt"]
                        || !input["attempt"].is_u64()
                        || at < prior
                        || at > poll["end_ns"].as_u64().unwrap()
                        || input["history_cursor"] != poll["start_cursor"]
                    {
                        return Err("original SSH counter receiver/window/order mismatch".into());
                    }
                    prior = at;
                    values.push(value);
                }
                if poll["ready"] != json!(values[0] == values[1]) {
                    return Err("original SSH ended/accepted comparison mismatch".into());
                }
            }
            return Ok(());
        }

        if kind == "fixture.wait" {
            if call["causal_input"] != json!([]) || call["causal_result"] != json!([]) {
                return Err("unexpected original fixture predicate inputs".into());
            }
            let matches = call["causal_matches"]
                .as_array()
                .ok_or("missing original fixture predicate operands")?;
            let polls = call["polls"].as_array().unwrap();
            if matches.len() != polls.len() {
                return Err("original fixture predicate multiplicity mismatch".into());
            }
            for (input, poll) in matches.iter().zip(polls) {
                let at = input["at_ns"]
                    .as_u64()
                    .ok_or("invalid original fixture predicate time")?;
                self.cursor(&input["history_cursor"], at, owner)?;
                if input.as_object().is_none_or(|o| {
                    o.len() != 6
                        || [
                            "name",
                            "operands",
                            "ready",
                            "attempt",
                            "at_ns",
                            "history_cursor",
                        ]
                        .iter()
                        .any(|k| !o.contains_key(*k))
                }) || input["name"] != "fixture_predicate"
                    || input["attempt"] != poll["attempt"]
                    || !input["attempt"].is_u64()
                    || !input["ready"].is_boolean()
                    || at < poll["start_ns"].as_u64().unwrap()
                    || at > poll["end_ns"].as_u64().unwrap()
                    || input["history_cursor"] != poll["start_cursor"]
                {
                    return Err("original fixture predicate receiver/window/order mismatch".into());
                }
                let ready = super::fixture_predicates::replay(
                    node["site"].as_str().unwrap(),
                    &input["operands"],
                )?;
                if input["ready"] != ready || poll["ready"] != ready {
                    return Err("original fixture whole predicate mismatch".into());
                }
            }
            return Ok(());
        }

        let marker = node["site"] == "job.mismatch.start_observed";
        let inputs = call["causal_input"]
            .as_array()
            .ok_or("missing causal input captures")?;
        let results = call["causal_result"]
            .as_array()
            .ok_or("missing causal producer captures")?;
        if !matches!(kind, "job.wait_launch" | "job.wait_end") && !marker {
            if !inputs.is_empty() || !results.is_empty() || call["causal_matches"] != json!([]) {
                return Err("unexpected causal job operands".into());
            }
            return Ok(());
        }
        let launch = kind == "job.wait_launch";
        if inputs.len() != 1 || results.len() != usize::from(launch) {
            return Err("causal job capture/producer write multiplicity mismatch".into());
        }
        let input = &inputs[0];
        let produced = results.first().unwrap_or(&Value::Null);
        let keys = if launch {
            vec![
                "source",
                "source_job",
                "occurrence",
                "origin",
                "capture",
                "trigger",
                "input_ok",
            ]
        } else {
            vec![
                "source",
                "source_job",
                "occurrence",
                "origin",
                "producer",
                "input_ok",
                "capture",
                "trigger",
            ]
        };
        if input
            .as_object()
            .is_none_or(|v| v.len() != keys.len() || keys.iter().any(|k| !v.contains_key(*k)))
            || input["input_ok"] != true
            || input["source_job"] != node["source_job"]
            || input["occurrence"] != node["occurrence"]
        {
            return Err("causal job original input/occurrence mismatch".into());
        }
        let source = input["source"]
            .as_u64()
            .ok_or("invalid causal source identity")?;
        let holding = node["source_job"] == "goal_admission.holding_job";
        if launch || holding {
            if source != self.job_producers.borrow().len() as u64 + 1 {
                return Err("causal job source multiplicity/order mismatch".into());
            }
            let position = node["root_start"].as_u64().unwrap();
            let (capture, _) = self.job_receiver(&input["capture"], owner, position, true)?;
            let trigger_position = if holding {
                position
                    .checked_sub(1)
                    .ok_or("missing holding job prerequisite")?
            } else {
                position
            };
            let (trigger, _) =
                self.job_receiver(&input["trigger"], owner, trigger_position, false)?;
            let capture_end = input["capture"]["end_ns"].as_u64().unwrap();
            let start = call["start_ns"].as_u64().unwrap();
            if input["capture"]["page"] != input["trigger"]["page"]
                || input["capture"]["worker"] != input["trigger"]["worker"]
                || if holding {
                    trigger > capture || capture_end > start || input["origin"] != "holding"
                } else {
                    capture_end > trigger
                        || trigger > start
                        || input["origin"] != node["previous_origin"]
                }
            {
                return Err("causal job original capture/dispatch lineage mismatch".into());
            }
            let result = if holding {
                &input["producer"]
            } else {
                produced
            };
            if result.as_object().is_none_or(|v| {
                v.len() != 5
                    || !["source", "call", "at_ns", "history_cursor", "input_ok"]
                        .iter()
                        .all(|k| v.contains_key(*k))
            }) || result["source"] != source
                || result["input_ok"] != true
                || if holding {
                    !result["call"].is_null() || !produced.is_null()
                } else {
                    result["call"] != index + 1
                }
            {
                return Err("invalid causal job original producer schema".into());
            }
            let at = result["at_ns"]
                .as_u64()
                .ok_or("invalid causal job producer time")?;
            let cursor = self.cursor(&result["history_cursor"], at, owner)?;
            let (low, high) = if holding {
                (capture_end, start)
            } else {
                (
                    call["polls"].as_array().unwrap().last().unwrap()["end_ns"]
                        .as_u64()
                        .unwrap(),
                    call["end_ns"].as_u64().unwrap(),
                )
            };
            if at < low || at > high || self.positions[cursor] != (position as usize, true) {
                return Err("causal job producer crosses original observation".into());
            }
            self.job_producers.borrow_mut().insert(
                source,
                (
                    json!({"source_job":node["source_job"],"occurrence":node["occurrence"]}),
                    result.clone(),
                ),
            );
        } else {
            let producers = self.job_producers.borrow();
            let (origin, result) = producers
                .get(&source)
                .ok_or("job end without original admitted producer")?;
            if input["origin"] != "launch"
                || input["source_job"] != origin["source_job"]
                || input["occurrence"] != origin["occurrence"]
                || input["producer"] != *result
                || !input["capture"].is_null()
                || !input["trigger"].is_null()
                || !produced.is_null()
                || result["at_ns"].as_u64().unwrap() > call["start_ns"].as_u64().unwrap()
            {
                return Err("job end original producer/identity lineage mismatch".into());
            }
        }
        let matches = call["causal_matches"]
            .as_array()
            .ok_or("missing causal job predicate operands")?;
        let mut cursor = 0;
        let mut previous = call["start_ns"].as_u64().unwrap();
        for poll in call["polls"].as_array().unwrap() {
            let names = if launch {
                &["candidate", "newer", "contains"][..]
            } else if marker {
                &["marker"][..]
            } else {
                &["ended", "exit"][..]
            };
            let mut result = false;
            for (ordinal, name) in names.iter().enumerate() {
                if ordinal > 0 && !result {
                    break;
                }
                let value = matches
                    .get(cursor)
                    .ok_or("missing causal job short-circuit operand")?;
                cursor += 1;
                let at = value["at_ns"]
                    .as_u64()
                    .ok_or("invalid causal job operand time")?;
                self.cursor(&value["history_cursor"], at, owner)?;
                if value.as_object().is_none_or(|v| {
                    v.len() != 6
                        || !["name", "ok", "ready", "attempt", "at_ns", "history_cursor"]
                            .iter()
                            .all(|k| v.contains_key(*k))
                }) || value["name"] != *name
                    || value["ok"] != true
                    || value["attempt"] != poll["attempt"]
                    || at < previous
                    || at < poll["start_ns"].as_u64().unwrap()
                    || at > poll["end_ns"].as_u64().unwrap()
                {
                    return Err("causal job original operand/attempt mismatch".into());
                }
                result = value["ready"]
                    .as_bool()
                    .ok_or("invalid causal job operand result")?;
                previous = at;
            }
            if poll["ready"] != result {
                return Err("causal job whole original predicate mismatch".into());
            }
        }
        if cursor != matches.len() {
            return Err("extra causal job predicate operands".into());
        }
        Ok(())
    }

    fn argument_census(&self) -> Result<(), String> {
        let mut actual = self.argument_captures.borrow().clone();
        for ((owner, group), trigger) in self.argument_trigger_groups.borrow().iter() {
            let sites = self
                .argument_group_sites
                .borrow()
                .get(&(owner.clone(), group.clone()))
                .cloned()
                .ok_or("missing source trigger membership")?;
            actual.push(json!({"order":trigger["order"],"at_ns":trigger["at_ns"],"event":{"case":&owner.2,"kind":"trigger","group":group,"sites":sites}}));
        }
        actual.sort_by_key(|event| event["order"].as_u64().unwrap());
        let inventory = completion::inventory();
        let execution: Vec<_> = if self.report["mode"] == "full" {
            inventory["cases"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c["id"].clone())
                .collect()
        } else {
            self.report["plan"]["expected_execution"]
                .as_array()
                .unwrap()
                .clone()
        };
        let mut expected = Vec::new();
        for row in inventory["argument_source_events"]
            .as_array()
            .ok_or("missing independently expected source argument events")?
        {
            if execution.contains(&row["case"]) {
                for event in row["events"].as_array().unwrap() {
                    let mut event = event.clone();
                    event["case"] = row["case"].clone();
                    expected.push(event);
                }
            }
        }
        if actual.len() != expected.len() {
            return Err("original source argument event multiplicity mismatch".into());
        }
        let mut previous = 0;
        for (index, (got, want)) in actual.iter().zip(expected).enumerate() {
            let at = got["at_ns"].as_u64().unwrap();
            if got["order"] != index + 1 || got["event"] != want || at < previous {
                return Err("original source argument event order/broadcast mismatch".into());
            }
            previous = at;
        }
        Ok(())
    }
    fn document_query(
        &self,
        queries: &Value,
        node: &Value,
        owner: &Owner,
        window: (u64, u64),
        cursor: &Value,
    ) -> Result<u64, String> {
        let queries = queries
            .as_array()
            .ok_or("missing original document counter query")?;
        if queries.len() != 1 {
            return Err("original document counter query multiplicity mismatch".into());
        }
        let query = &queries[0];
        let keys = [
            "kind",
            "value",
            "receiver_ok",
            "start_ns",
            "end_ns",
            "start_cursor",
            "end_cursor",
        ];
        let start = query["start_ns"]
            .as_u64()
            .ok_or("invalid original document counter query time")?;
        let end = query["end_ns"]
            .as_u64()
            .ok_or("invalid original document counter query time")?;
        let value = query["value"]
            .as_u64()
            .ok_or("invalid original document counter query value")?;
        let kind = if node["site"] == "goal.document.connection_closed" {
            "closes"
        } else {
            "requests"
        };
        if query
            .as_object()
            .is_none_or(|o| o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)))
            || query["kind"] != kind
            || query["receiver_ok"] != true
            || start < window.0
            || start > end
            || end > window.1
            || query["start_cursor"] != *cursor
            || query["end_cursor"] != *cursor
        {
            return Err("original document counter receiver/role/window mismatch".into());
        }
        self.cursor(&query["start_cursor"], start, owner)?;
        self.cursor(&query["end_cursor"], end, owner)?;
        Ok(value)
    }
    fn arguments(&self, call: &Value, node: &Value, owner: &Owner) -> Result<(), String> {
        fn fields(value: &Value, names: &[&str]) -> bool {
            value.as_object().is_some_and(|o| {
                o.len() == names.len() && names.iter().all(|name| o.contains_key(*name))
            })
        }
        let document = matches!(
            node["site"].as_str(),
            Some(
                "goal.document.pending_sent"
                    | "goal.document.active_sent"
                    | "goal.document.connection_closed"
            )
        );
        let names = node["argument_names"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let domains = call["argument_domains"]
            .as_array()
            .ok_or("missing source argument origins")?;
        let triggers = call["argument_triggers"]
            .as_array()
            .ok_or("missing source argument trigger")?;
        if domains.len() != names.len() || triggers.len() != usize::from(!names.is_empty()) {
            return Err("original source argument capture multiplicity mismatch".into());
        }
        if let Some(trigger) = triggers.first() {
            let fields_expected: &[&str] = if node["site"] == "hold.writer.read_completed" {
                &[
                    "at_ns",
                    "history_cursor",
                    "page",
                    "worker",
                    "order",
                    "dispatch_ok",
                ]
            } else {
                &[
                    "at_ns",
                    "history_cursor",
                    "page",
                    "worker",
                    "order",
                    "dispatch_ok",
                    "session_source",
                    "session_capture",
                ]
            };
            if !fields(trigger, fields_expected)
                || node["site"] == "hold.writer.read_completed" && trigger["dispatch_ok"] != true
            {
                return Err("invalid original source argument trigger schema".into());
            }
            if node["site"] != "hold.writer.read_completed" {
                let inventory = completion::inventory();
                let execution: Vec<_> = if self.report["mode"] == "full" {
                    inventory["cases"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|c| c["id"].clone())
                        .collect()
                } else {
                    self.report["plan"]["expected_execution"]
                        .as_array()
                        .unwrap()
                        .clone()
                };
                let target = if node["site"] == "goal.document.pending_sent" {
                    "goal_cases.c009.p001"
                } else {
                    "goal_cases.c011.p001"
                };
                let documents: Vec<_> = ["goal_cases.c009.p001", "goal_cases.c011.p001"]
                    .into_iter()
                    .filter(|id| execution.iter().any(|c| c == id))
                    .collect();
                let source = documents
                    .iter()
                    .position(|id| *id == target)
                    .ok_or("missing original document trigger source")?
                    + 1;
                let capture = &trigger["session_capture"];
                if trigger["dispatch_ok"] != true
                    || trigger["session_source"] != source
                    || !trigger["session_source"].is_u64()
                    || !fields(
                        capture,
                        &[
                            "at_ns",
                            "history_cursor",
                            "worker",
                            "page",
                            "worker_ok",
                            "query",
                        ],
                    )
                    || capture["worker_ok"] != true
                    || capture["worker"] != trigger["worker"]
                    || capture["page"] != trigger["page"]
                    || capture["history_cursor"] != trigger["history_cursor"]
                    || capture["at_ns"]
                        .as_u64()
                        .is_none_or(|at| trigger["at_ns"].as_u64().is_none_or(|end| at > end))
                {
                    return Err("original goal document dispatch payload/source mismatch".into());
                }
                let query = capture["query"]
                    .as_u64()
                    .and_then(|id| id.checked_sub(1))
                    .and_then(|index| self.report["goal_session_inputs"].get(index as usize))
                    .ok_or("missing original goal document session query")?;
                if query["end_ns"] != capture["at_ns"]
                    || query["end_cursor"] != capture["history_cursor"]
                    || query["worker"] != capture["worker"]
                    || query["page"] != capture["page"]
                    || query["document"]
                        != if target == "goal_cases.c009.p001" {
                            "pending"
                        } else {
                            "active"
                        }
                {
                    return Err("original goal document query/capture mismatch".into());
                }
                self.cursor(
                    &capture["history_cursor"],
                    capture["at_ns"].as_u64().unwrap(),
                    owner,
                )?;
            }
            let at = trigger["at_ns"]
                .as_u64()
                .ok_or("invalid source argument trigger time")?;
            let cursor = self.cursor(&trigger["history_cursor"], at, owner)?;
            let trigger_order = trigger["order"]
                .as_u64()
                .ok_or("invalid source trigger order")?;
            let page = trigger["page"]
                .as_u64()
                .ok_or("invalid source argument trigger page")?;
            if at > call["start_ns"].as_u64().unwrap()
                || trigger["history_cursor"] != call["start_cursor"]
                || self.pages[cursor].get(node["page_role"].as_str().unwrap()) != Some(&page)
                || self.workers[cursor]
                    .get(&page)
                    .is_none_or(|worker| trigger["worker"] != *worker)
            {
                return Err("original source argument trigger lineage mismatch".into());
            }
            let group = node["argument_trigger_group"]
                .as_str()
                .ok_or("missing source argument trigger group")?;
            self.argument_group_sites
                .borrow_mut()
                .entry((owner.clone(), group.into()))
                .or_default()
                .push(call["site"].as_str().unwrap().into());
            let previous = self
                .argument_trigger_groups
                .borrow_mut()
                .insert((owner.clone(), group.into()), trigger.clone());
            if previous.is_some_and(|old| old != *trigger) {
                return Err("original source argument trigger group changed".into());
            }
            for (domain, name) in domains.iter().zip(&names) {
                let captures = domain["captures"]
                    .as_array()
                    .ok_or("missing original source argument captures")?;
                if !fields(domain, &["name", "captures"])
                    || domain["name"] != *name
                    || captures.len() != 1
                    || !fields(&captures[0], &["at_ns", "history_cursor", "order", "input"])
                {
                    return Err("original source argument origin schema mismatch".into());
                }
                let capture = &captures[0];
                let before = capture["at_ns"]
                    .as_u64()
                    .ok_or("invalid source argument capture time")?;
                self.cursor(&capture["history_cursor"], before, owner)?;
                if node["site"] != "hold.writer.read_completed"
                    && trigger["session_capture"]["at_ns"].as_u64().unwrap() > before
                {
                    return Err("original document session query follows counter capture".into());
                }
                if before > at
                    || capture["history_cursor"] != trigger["history_cursor"]
                    || capture["order"]
                        .as_u64()
                        .is_none_or(|order| order >= trigger_order)
                {
                    return Err(
                        "original source argument capture is not before its source trigger".into(),
                    );
                }
                let input = &capture["input"];
                if node["site"] == "hold.writer.read_completed" {
                    let query_start = input["start_ns"]
                        .as_u64()
                        .ok_or("invalid original baseline query time")?;
                    let query_cursor = self.cursor(&input["start_cursor"], query_start, owner)?;
                    let page = input["page"]
                        .as_u64()
                        .ok_or("invalid original baseline query page")?;
                    if !fields(
                        input,
                        &[
                            "worker",
                            "page",
                            "query_ok",
                            "receiver_ok",
                            "start_ns",
                            "start_cursor",
                        ],
                    ) || query_start > before
                        || input["start_cursor"] != capture["history_cursor"]
                        || input["query_ok"] != true
                        || input["receiver_ok"] != true
                        || self.pages[query_cursor].get(node["page_role"].as_str().unwrap())
                            != Some(&page)
                        || self.workers[query_cursor]
                            .get(&page)
                            .is_none_or(|w| input["worker"] != *w)
                    {
                        return Err(
                            "original completed-read baseline query lineage mismatch".into()
                        );
                    }
                } else if document {
                    if !fields(input, &["value", "queries"]) {
                        return Err("invalid original document counter baseline schema".into());
                    }
                    let value = self.document_query(
                        &input["queries"],
                        node,
                        owner,
                        (
                            trigger["session_capture"]["at_ns"].as_u64().unwrap(),
                            before,
                        ),
                        &capture["history_cursor"],
                    )?;
                    if input["value"].as_u64() != Some(value) {
                        return Err("original document counter baseline substitution".into());
                    }
                } else if !input.is_null() {
                    return Err("unexpected source argument query input".into());
                }
                self.argument_captures.borrow_mut().push(json!({"order":capture["order"],"at_ns":before,"event":{"case":&owner.2,"kind":"capture","site":call["site"],"name":name}}));
            }
        }
        let polls = call["polls"].as_array().unwrap();
        let actual = call["argument_matches"]
            .as_array()
            .ok_or("missing original source argument uses")?;
        if actual.len() != polls.len() * names.len() {
            return Err("original source argument use multiplicity mismatch".into());
        }
        for (index, input) in actual.iter().enumerate() {
            let poll = &polls[index / names.len()];
            let name = &names[index % names.len()];
            let at = input["at_ns"]
                .as_u64()
                .ok_or("invalid source argument use time")?;
            self.cursor(&input["history_cursor"], at, owner)?;
            if !fields(
                input,
                if document {
                    &[
                        "name",
                        "ok",
                        "ready",
                        "attempt",
                        "at_ns",
                        "history_cursor",
                        "observed",
                        "before",
                        "queries",
                    ]
                } else {
                    &["name", "ok", "ready", "attempt", "at_ns", "history_cursor"]
                },
            ) || input["name"] != *name
                || input["ok"] != true
                || input["ready"] != poll["ready"]
                || input["attempt"] != poll["attempt"]
                || at < poll["start_ns"].as_u64().unwrap()
                || at > poll["end_ns"].as_u64().unwrap()
            {
                return Err("original source argument use/attempt mismatch".into());
            }
            if document {
                let observed = self.document_query(
                    &input["queries"],
                    node,
                    owner,
                    (poll["start_ns"].as_u64().unwrap(), at),
                    &input["history_cursor"],
                )?;
                let before = input["before"]
                    .as_u64()
                    .ok_or("invalid original document counter baseline")?;
                let capture = &domains[index % names.len()]["captures"][0];
                if input["observed"].as_u64() != Some(observed)
                    || capture["input"]["value"].as_u64() != Some(before)
                    || input["ready"] != json!(observed > before)
                {
                    return Err("original document counter whole predicate mismatch".into());
                }
            }
        }
        Ok(())
    }
    fn cursor(&self, cursor: &Value, at: u64, expected: &Owner) -> Result<usize, String> {
        let cursor = cursor
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or("invalid observer history cursor")?;
        let state = self
            .states
            .get(cursor)
            .ok_or("observer outside caller history")?;
        let events = self.report["helper_history"].as_array().unwrap();
        let cleanup = expected.0.is_empty() && expected.1 == "cleanup" && expected.2.is_empty();
        if (if cleanup {
            state.owner.is_some()
        } else {
            state.owner.as_ref() != Some(expected)
        }) || cursor
            .checked_sub(1)
            .is_some_and(|i| events[i]["at_ns"].as_u64().unwrap() > at)
            || events
                .get(cursor)
                .is_some_and(|e| e["at_ns"].as_u64().unwrap() < at)
        {
            return Err("observer source caller/history mismatch".into());
        }
        if cleanup {
            let phase = self.report["timings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["phase"] == "cleanup")
                .ok_or("missing original cleanup phase")?;
            if cursor != events.len()
                || at < phase["start_ns"].as_u64().unwrap()
                || at > phase["end_ns"].as_u64().unwrap()
            {
                return Err("cleanup observer outside original phase".into());
            }
        }
        Ok(cursor)
    }

    fn call(
        &self,
        index: usize,
        node: &Value,
        expected_owner: &Owner,
        parent: Option<usize>,
        visited: &mut [bool],
    ) -> Result<(), String> {
        let calls = self.report["observer_calls"].as_array().unwrap();
        let call = calls.get(index).ok_or("missing observer child instance")?;
        if std::mem::replace(
            visited.get_mut(index).ok_or("invalid observer index")?,
            true,
        ) {
            return Err("duplicate observer instance".into());
        }
        let start = call["start_ns"].as_u64().ok_or("invalid observer start")?;
        let end = call["end_ns"].as_u64().ok_or("invalid observer end")?;
        let fields = [
            "site",
            "kind",
            "domain",
            "domain_captures",
            "argument_domains",
            "argument_triggers",
            "argument_matches",
            "causal_input",
            "causal_result",
            "causal_matches",
            "page",
            "parent",
            "children",
            "polls",
            "facts",
            "inputs",
            "page_inputs",
            "start_ns",
            "end_ns",
            "start_cursor",
            "end_cursor",
        ];
        if call
            .as_object()
            .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)))
            || start > end
            || end > self.report["duration_ns"].as_u64().unwrap()
            || call["site"] != node["site"]
            || call["kind"] != node["kind"]
            || call["domain"] != node["domain"]
            || call["parent"] != json!(parent.map(|i| i + 1))
        {
            return Err(format!(
                "observer source invocation/parameter mismatch: {}",
                node["site"]
            ));
        }
        let cursor = self.cursor(&call["start_cursor"], start, expected_owner)?;
        let end_cursor = self.cursor(&call["end_cursor"], end, expected_owner)?;
        if let Some(position) = node["root_start"].as_u64()
            && (self.positions[cursor] != (position as usize, true)
                || self.positions[end_cursor]
                    != (node["root_end"].as_u64().unwrap() as usize, true))
        {
            return Err("causal observer original helper position mismatch".into());
        }
        let kind = node["kind"].as_str().unwrap();
        if call["domain_captures"] != usize::from(kind == "setup.approve") {
            return Err("observer input capture multiplicity mismatch".into());
        }
        if kind.starts_with("inference.")
            || kind == "job.wait_end"
            || kind.starts_with("fixture.")
            || kind == "session.closed"
        {
            if !call["page"].is_null() {
                return Err("fixture observer has an invented browser input".into());
            }
        } else {
            let role = node["page_role"].as_str().unwrap();
            let page = self.pages[cursor]
                .get(role)
                .copied()
                .ok_or("observer before source page birth")?;
            if call["page"] != page {
                return Err("observer source page lineage mismatch".into());
            }
        }
        if node["page_input_phase"] == "after_false" {
            let prior = self.report["observer_prior_inputs"]
                .as_array()
                .ok_or("missing original initial view inputs")?;
            let matches: Vec<_> = prior
                .iter()
                .enumerate()
                .filter(|(_, p)| {
                    p["site"] == node["site"] && p["end_cursor"] == call["start_cursor"]
                })
                .collect();
            if matches.len() != 1 {
                return Err("missing/extra original initial view input".into());
            }
            let (index, input) = matches[0];
            if std::mem::replace(&mut self.prior_used.borrow_mut()[index], true) {
                return Err("reused original initial view input".into());
            }
            let at = input["start_ns"]
                .as_u64()
                .ok_or("invalid initial view start")?;
            let done = input["end_ns"].as_u64().ok_or("invalid initial view end")?;
            let cursor = self.cursor(&input["start_cursor"], at, expected_owner)?;
            self.cursor(&input["end_cursor"], done, expected_owner)?;
            if input.as_object().is_none_or(|o| {
                o.len() != 7
                    || ![
                        "site",
                        "page",
                        "view_source",
                        "start_ns",
                        "end_ns",
                        "start_cursor",
                        "end_cursor",
                    ]
                    .iter()
                    .all(|k| o.contains_key(*k))
            }) || at > done
                || done > start
                || input["start_cursor"] != input["end_cursor"]
                || self.pages[cursor]
                    .get(node["page_role"].as_str().unwrap())
                    .is_none_or(|p| input["page"] != *p)
            {
                return Err("original initial view source input mismatch".into());
            }
        }
        let polls = call["polls"]
            .as_array()
            .ok_or("missing observer attempts")?;
        let bound = match kind {
            "serial.observation" | "fixture.wait" | "fixture.ssh_ended" => {
                node["domain"]["bound"].as_u64().unwrap() as usize
            }
            "seed.wait_stage"
            | "setup.approve"
            | "declaration.prepare.binding"
            | "declaration.prepare.goal_card"
            | "declaration.wait_card"
            | "declaration.wait_proposal_or_outcome"
            | "declaration.outcome"
            | "delivery.prepare"
            | "delivery.check"
            | "delivery.card" => 300,
            "job.wait_launch" => 300,
            "job.wait_end" => 1000,
            "inference.wait_count" | "inference.wait_refused" => 100,
            _ => 0,
        };
        let mut previous = start;
        if bound == 0 && !polls.is_empty() || bound > 0 && (polls.is_empty() || polls.len() > bound)
        {
            return Err("observer source attempt domain mismatch".into());
        }
        for (n, poll) in polls.iter().enumerate() {
            let at = poll["start_ns"]
                .as_u64()
                .ok_or("invalid observer attempt time")?;
            let done = poll["end_ns"]
                .as_u64()
                .ok_or("missing observer predicate result")?;
            let interval = match kind {
                "serial.observation" => {
                    node["domain"]["false_sleep_ms"].as_u64().unwrap() * 1_000_000
                }
                "seed.wait_stage"
                | "setup.approve"
                | "inference.wait_count"
                | "inference.wait_refused"
                | "fixture.wait"
                | "fixture.ssh_ended" => 50_000_000,
                "job.wait_launch" | "job.wait_end" => 10_000_000,
                _ => 20_000_000,
            };
            if n > 0 && at.saturating_sub(previous) < interval {
                return Err("observer original failed-attempt observation window shortened".into());
            }
            let ready = poll["ready"]
                .as_bool()
                .ok_or("invalid observer predicate result type")?;
            let ready_domain = if matches!(
                kind,
                "serial.observation" | "fixture.wait" | "fixture.ssh_ended"
            ) {
                if n + 1 < polls.len() {
                    !ready
                } else {
                    ready || (node["domain"]["requires_ready"] == false && polls.len() == bound)
                }
            } else {
                ready == (n + 1 == polls.len())
            };
            if poll.as_object().is_none_or(|o| o.len() != 6)
                || poll["attempt"] != n + 1
                || !ready_domain
                || at < previous
                || done < at
                || done > end
            {
                return Err("observer predicate/attempt/termination mismatch".into());
            }
            self.cursor(&poll["start_cursor"], at, expected_owner)?;
            self.cursor(&poll["end_cursor"], done, expected_owner)?;
            previous = done;
        }
        if matches!(
            kind,
            "serial.observation" | "fixture.wait" | "fixture.ssh_ended"
        ) && polls.last().is_some_and(|p| p["ready"] == false)
        {
            let last = polls.last().unwrap()["end_ns"].as_u64().unwrap();
            let interval = node["domain"]["false_sleep_ms"].as_u64().unwrap() * 1_000_000;
            if end.saturating_sub(last) < interval {
                return Err("observer original exhausted-attempt sleep shortened".into());
            }
        }
        let inputs = call["inputs"]
            .as_array()
            .ok_or("missing observer actual worker inputs")?;
        let input_count = match kind {
            "serial.observation" => {
                polls.len() * node["worker_inputs_per_poll"].as_u64().unwrap() as usize
            }
            "setup.approve" | "delivery.check" => polls.len() + 1,
            "declaration.prepare.binding" | "delivery.prepare" | "job.wait_launch" => polls.len(),
            "declaration.prepare" | "declaration.wait_card" => 1,
            _ => 0,
        };
        if inputs.len() != input_count {
            return Err("observer original worker input multiplicity mismatch".into());
        }
        let mut previous_input = start;
        for (index, input) in inputs.iter().enumerate() {
            let at = input["at_ns"]
                .as_u64()
                .ok_or("invalid observer input time")?;
            let cursor = self.cursor(&input["history_cursor"], at, expected_owner)?;
            let page = input["page"]
                .as_u64()
                .ok_or("invalid observer worker page")?;
            if input.as_object().is_none_or(|o| {
                o.len() != 4
                    || !["at_ns", "history_cursor", "page", "worker"]
                        .iter()
                        .all(|k| o.contains_key(*k))
            }) || at < previous_input
                || at > end
                || self.pages[cursor].get(node["page_role"].as_str().unwrap()) != Some(&page)
                || self.workers[cursor]
                    .get(&page)
                    .is_none_or(|w| input["worker"] != *w)
            {
                return Err("observer actual source worker/page input mismatch".into());
            }
            let poll_index = match kind {
                "serial.observation" => {
                    Some(index / node["worker_inputs_per_poll"].as_u64().unwrap() as usize)
                }
                "setup.approve" | "delivery.check" => index.checked_sub(1),
                "declaration.prepare.binding" | "delivery.prepare" | "job.wait_launch" => {
                    Some(index)
                }
                _ => None,
            };
            if let Some(poll) = poll_index.and_then(|i| polls.get(i)) {
                if at < poll["start_ns"].as_u64().unwrap() || at > poll["end_ns"].as_u64().unwrap()
                {
                    return Err("observer input outside original attempt".into());
                }
            } else if matches!(kind, "setup.approve" | "delivery.check")
                && at > polls[0]["start_ns"].as_u64().unwrap()
                || kind == "declaration.wait_card"
                    && at < polls.last().unwrap()["end_ns"].as_u64().unwrap()
            {
                return Err("observer initial/final input chronology mismatch".into());
            }
            previous_input = at;
        }
        let page_inputs = call["page_inputs"]
            .as_array()
            .ok_or("missing original page query inputs")?;
        let mut expected_inputs = Vec::new();
        if kind == "serial.observation" {
            let specs = node["page_inputs_per_poll"]
                .as_array()
                .ok_or("missing source page query specification")?;
            for (index, poll) in polls.iter().enumerate() {
                if node["page_input_phase"] == "before_predicate" || poll["ready"] == false {
                    for spec in specs {
                        expected_inputs.push((index, spec));
                    }
                }
            }
        }
        if page_inputs.len() != expected_inputs.len() {
            return Err("original page query input multiplicity mismatch".into());
        }
        let mut previous_page_input = start;
        for (input, (index, spec)) in page_inputs.iter().zip(expected_inputs) {
            let at = input["at_ns"]
                .as_u64()
                .ok_or("invalid page query input time")?;
            let cursor = self.cursor(&input["history_cursor"], at, expected_owner)?;
            let role = spec["page_role"].as_str().unwrap();
            if input.as_object().is_none_or(|o| {
                o.len() != 4
                    || !["slot", "page", "at_ns", "history_cursor"]
                        .iter()
                        .all(|k| o.contains_key(*k))
            }) || input["slot"] != spec["slot"]
                || at < previous_page_input
                || at > end
                || self.pages[cursor]
                    .get(role)
                    .is_none_or(|page| input["page"] != *page)
            {
                return Err("original page query source input mismatch".into());
            }
            let poll = &polls[index];
            let (low, high) = if node["page_input_phase"] == "before_predicate" {
                (
                    poll["start_ns"].as_u64().unwrap(),
                    poll["end_ns"].as_u64().unwrap(),
                )
            } else {
                (
                    poll["end_ns"]
                        .as_u64()
                        .unwrap()
                        .checked_add(node["domain"]["false_sleep_ms"].as_u64().unwrap() * 1_000_000)
                        .ok_or("original page query window overflow")?,
                    polls
                        .get(index + 1)
                        .map(|p| p["start_ns"].as_u64().unwrap())
                        .unwrap_or(end),
                )
            };
            if at < low || at > high {
                return Err("original page query crosses source observation window".into());
            }
            previous_page_input = at;
        }
        self.arguments(call, node, expected_owner)?;
        self.job_input(index, call, node, expected_owner)?;
        let facts = match kind {
            "job.wait_end" | "fixture.wait" | "fixture.ssh_ended" | "fixture.settle"
            | "session.closed" => json!([{"id":"fixture_input","ok":true}]),
            "declaration.prepare" => {
                json!([{"id":"files_input","ok":true},{"id":"account_absent","ok":true}])
            }
            "seed.reenter" => {
                json!([{"id":"words_input","ok":true},{"id":"field_cleared","ok":true}])
            }
            "declaration.prepare.confirmation" => json!([{"id":"confirmed","ok":true}]),
            "inference.wait_count" => json!([{"id":"counter_input","ok":true}]),
            "inference.wait_refused" => json!([{"id":"key_input","ok":true}]),
            "declaration.prepare.goal_card"
            | "declaration.wait_card"
            | "declaration.wait_proposal_or_outcome"
            | "declaration.outcome" => json!([{"id":"session_input","ok":true}]),
            "delivery.check" => {
                json!([{"id":"measurement_input","ok":true},{"id":"session_input","ok":true}])
            }
            "delivery.prepare" => json!([{"id":"declaration_input","ok":true}]),
            _ => json!([]),
        };
        if call["facts"] != facts {
            return Err("observer original predicate completion mismatch".into());
        }
        let children = call["children"]
            .as_array()
            .ok_or("missing observer child tree")?;
        let expected_children = node["children"].as_array().unwrap();
        if children.len() != expected_children.len() {
            return Err("missing/extra observer child invocation".into());
        }
        let mut previous = start;
        for (child, node) in children.iter().zip(expected_children) {
            let child_index = child
                .as_u64()
                .and_then(|v| usize::try_from(v).ok())
                .and_then(|v| v.checked_sub(1))
                .ok_or("invalid observer child ordinal")?;
            let actual = calls
                .get(child_index)
                .ok_or("observer child outside capture")?;
            if actual["start_ns"].as_u64().is_none_or(|at| at < previous)
                || actual["end_ns"].as_u64().is_none_or(|at| at > end)
            {
                return Err("observer child chronology mismatch".into());
            }
            self.call(child_index, node, expected_owner, Some(index), visited)?;
            previous = actual["end_ns"].as_u64().unwrap();
        }
        if kind == "declaration.prepare" {
            let at = inputs[0]["at_ns"].as_u64().unwrap();
            let binding = &calls[children[0].as_u64().unwrap() as usize - 1];
            let confirmation = &calls[children[1].as_u64().unwrap() as usize - 1];
            if at < binding["end_ns"].as_u64().unwrap()
                || at > confirmation["start_ns"].as_u64().unwrap()
            {
                return Err(
                    "declaration account input crosses original binding/confirmation history"
                        .into(),
                );
            }
        }
        Ok(())
    }
}

pub fn validate(report: &Value) -> Result<(), String> {
    super::logical_checks::validate(report)?;
    if report["aggregator_inputs"] != json!({"registrations":1,"unmatched":0}) {
        return Err("original aggregator receiver mismatch".into());
    }
    if report["observer_unbound_arguments"]
        != json!({"values":[],"triggers":[],"workers":0,"goal_ends":0,"document_sessions":0,"document_queries":0})
    {
        return Err("unbound original source argument capture or trigger".into());
    }
    if report["causal_unbound_jobs"] != json!(0) {
        return Err("unbound causal job input/dispatch/producer".into());
    }
    validate_runtime_inputs(report)?;
    validate_submissions(report)?;
    validate_displayed_words(report)?;
    let calls = report["observer_calls"]
        .as_array()
        .ok_or("missing serial observer completions")?;
    let use_calls: Vec<_> = calls
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            matches!(c["kind"].as_str(), Some("job.wait_launch" | "job.wait_end"))
                || c["site"] == "job.mismatch.start_observed"
        })
        .map(|(i, _)| i + 1)
        .collect();
    if report["causal_use_calls"] != json!(use_calls) {
        return Err("causal job source use multiplicity/order mismatch".into());
    }
    let mut expected = expected(report)?;
    let mut causal_expected = causal_expected(report)?;
    let mut pages = history::source_page_states(report)?;
    let states = reader_checks::caller_states(report);
    let mut prior = None;
    let mut last = None;
    for (index, state) in pages.iter_mut().enumerate() {
        if let Some(page) = state.get("tracer").copied() {
            if let Some(old) = last
                && old != page
                && states[index].owner.as_ref().is_some_and(|o| {
                    o.0 == "main.run" && o.1 == "inside" && o.2 == "main.c020.p001"
                })
            {
                prior = Some(old);
            }
            last = Some(page);
        }
        if let Some(page) = prior {
            state.insert("prior_tracer_at_main_c020_birth".into(), page);
        }
    }
    let validation = Validation {
        report,
        states: reader_checks::caller_states(report),
        pages,
        workers: history::worker_states(report),
        argument_trigger_groups: RefCell::new(BTreeMap::new()),
        argument_group_sites: RefCell::new(BTreeMap::new()),
        argument_captures: RefCell::new(Vec::new()),
        positions: source_positions(report),
        job_producers: RefCell::new(BTreeMap::new()),
        class_inputs: RefCell::new(Vec::new()),
        goal_end_inputs: RefCell::new(Vec::new()),
        prior_used: RefCell::new(vec![
            false;
            report["observer_prior_inputs"]
                .as_array()
                .ok_or("missing original initial view inputs")?
                .len()
        ]),
    };
    let mut visited = vec![false; calls.len()];
    let mut previous = 0;
    for (index, call) in calls
        .iter()
        .enumerate()
        .filter(|(_, c)| c["parent"].is_null())
    {
        let cursor = call["start_cursor"]
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or("invalid observer root cursor")?;
        let owner = validation
            .states
            .get(cursor)
            .and_then(|s| s.owner.clone())
            .or_else(|| {
                (call["kind"] == "fixture.ssh_ended" && cursor == validation.states.len() - 1)
                    .then(|| ("".into(), "cleanup".into(), "".into()))
            })
            .ok_or("observer root without caller")?;
        let expected = if call["kind"].as_str().is_some_and(|k| {
            k.starts_with("job.")
                || k.starts_with("fixture.")
                || k == "session.closed"
                || k == "main.lock_command"
        }) {
            &mut causal_expected
        } else {
            &mut expected
        };
        let want = expected
            .get_mut(&owner)
            .and_then(|v| (!v.is_empty()).then(|| v.remove(0)))
            .ok_or("missing/extra observer root caller")?;
        let finish = call["end_cursor"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or("invalid observer invocation cursor")?;
        let invocation = validation.states[cursor].invocation;
        if validation
            .states
            .get(finish)
            .is_none_or(|s| s.invocation != invocation)
            || (!want["invocation"].is_null() && want["invocation"] != invocation)
        {
            return Err("observer source invocation mismatch".into());
        }
        if call["start_ns"].as_u64().is_none_or(|at| at < previous) {
            return Err("observer root execution order mismatch".into());
        }
        validation.call(index, &want, &owner, None, &mut visited)?;
        previous = call["end_ns"].as_u64().unwrap();
    }
    if validation.prior_used.borrow().iter().any(|v| !v) {
        return Err("extra original initial view input".into());
    }
    let mut previous_view_end = 0;
    for input in report["observer_prior_inputs"].as_array().unwrap() {
        if input["start_ns"].as_u64().unwrap() < previous_view_end {
            return Err("original initial view input order mismatch".into());
        }
        previous_view_end = input["end_ns"].as_u64().unwrap();
    }
    if visited.contains(&false)
        || expected.values().any(|v| !v.is_empty())
        || causal_expected.values().any(|v| !v.is_empty())
    {
        return Err("missing/extra whole serial observer invocation".into());
    }
    let execution: Vec<_> = if report["mode"] == "full" {
        completion::inventory()["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].clone())
            .collect()
    } else {
        report["plan"]["expected_execution"]
            .as_array()
            .unwrap()
            .clone()
    };
    for edge in completion::inventory()["causal_order_edges"]
        .as_array()
        .unwrap()
    {
        if !execution.contains(&edge["case"]) {
            continue;
        }
        let source_owner = (
            edge["scenario"].as_str().unwrap().to_owned(),
            "inside".to_owned(),
            edge["case"].as_str().unwrap().to_owned(),
        );
        let select = |site: &Value| {
            calls
                .iter()
                .filter(|c| {
                    c["site"] == *site
                        && validation.states[c["start_cursor"].as_u64().unwrap() as usize]
                            .owner
                            .as_ref()
                            == Some(&source_owner)
                })
                .collect::<Vec<_>>()
        };
        let first = select(&edge["before"]);
        let second = select(&edge["after"]);
        if first.len() != 1
            || second.len() != 1
            || first[0]["end_ns"].as_u64().unwrap() > second[0]["start_ns"].as_u64().unwrap()
        {
            return Err("causal observer original cross-family order mismatch".into());
        }
    }
    if report["class_inputs"]
        .as_array()
        .is_none_or(|v| v.len() != validation.class_inputs.borrow().len())
    {
        return Err("extra original class dispatch capture".into());
    }
    super::inputs::validate(report)?;
    super::counter_inputs::validate(report)?;
    super::session_operands::validate(report)?;
    super::key_inputs::validate(report)?;
    super::fixture_inputs::validate(report)?;
    if report["goal_end_inputs"]
        .as_array()
        .is_none_or(|v| v.len() != validation.goal_end_inputs.borrow().len())
    {
        return Err("extra original end dispatch".into());
    }
    validation.argument_census()?;
    Ok(())
}

fn validate_submissions(report: &Value) -> Result<(), String> {
    let inventory = completion::inventory();
    let mut default_unlock = false;
    let rows = if report["mode"] == "full" {
        &inventory["submission_sources"]
    } else if report["plan"]["name"] == "inference.session-end.selection" {
        default_unlock = true;
        &Value::Null
    } else {
        &report["plan"]["submission_sources"]
    };
    let mut kinds = BTreeMap::new();
    let mut roles = BTreeMap::new();
    if let Some(rows) = rows.as_array() {
        for row in rows {
            for (position, role) in row["roles"].as_object().unwrap() {
                roles.insert(
                    (
                        owner(row),
                        position.parse::<usize>().map_err(|e| e.to_string())?,
                    ),
                    role.as_str().unwrap(),
                );
            }
            for (position, kind) in row["kinds"].as_object().unwrap() {
                kinds.insert(
                    (
                        owner(row),
                        position.parse::<usize>().map_err(|e| e.to_string())?,
                    ),
                    kind.as_str().unwrap(),
                );
            }
        }
    }
    let events = report["helper_history"].as_array().unwrap();
    let states = reader_checks::caller_states(report);
    let mut stack = Vec::new();
    let mut positions: BTreeMap<Owner, usize> = BTreeMap::new();
    let mut expected = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if event["event"] == "call_start" {
            let source_owner = states[index + 1]
                .owner
                .as_ref()
                .ok_or("submission without source owner")?;
            let root = stack.is_empty();
            if event["kind"] == "runtime.submit" {
                let role = if root {
                    roles
                        .get(&(
                            source_owner.clone(),
                            positions.get(source_owner).copied().unwrap_or(0),
                        ))
                        .copied()
                        .or(default_unlock.then_some("store.primary"))
                        .ok_or("missing independent submission passphrase role")?
                } else {
                    prepare_passphrase(source_owner)
                };
                let kind = if root {
                    let position = positions.get(source_owner).copied().unwrap_or(0);
                    kinds
                        .get(&(source_owner.clone(), position))
                        .copied()
                        .or(default_unlock.then_some("unlock"))
                        .ok_or("missing independent submission kind")?
                } else {
                    if stack.last() != Some(&"binding.prepare") {
                        return Err("submission outside original parent".into());
                    }
                    "unlock"
                };
                expected.push((
                    event["call"].as_u64().unwrap(),
                    kind,
                    role,
                    index + 1,
                    event["at_ns"].as_u64().unwrap(),
                    events.get(index + 1).ok_or("incomplete submission")?["at_ns"]
                        .as_u64()
                        .unwrap(),
                ));
            }
            if root {
                *positions.entry(source_owner.clone()).or_default() += 1;
            }
            stack.push(event["kind"].as_str().unwrap());
        } else if event["event"] == "call_end" {
            stack.pop();
        } else if event["event"] == "check" && stack.is_empty() {
            *positions
                .entry(states[index + 1].owner.as_ref().unwrap().clone())
                .or_default() += 1;
        }
    }
    let actual = report["submissions"]
        .as_array()
        .ok_or("missing submission field observations")?;
    if actual.len() != expected.len() {
        return Err("missing/extra/duplicate submission field observation".into());
    }
    for (row, (call, kind, role, cursor, start, end)) in actual.iter().zip(expected) {
        if row.as_object().is_none_or(|o| {
            o.len() != 6
                || ![
                    "call",
                    "kind",
                    "passphrase_role",
                    "cleared",
                    "at_ns",
                    "history_cursor",
                ]
                .iter()
                .all(|k| o.contains_key(*k))
        }) || row["call"] != call
            || row["kind"] != kind
            || row["passphrase_role"] != role
            || row["history_cursor"] != cursor
            || !row["cleared"].is_boolean()
            || row["at_ns"]
                .as_u64()
                .is_none_or(|at| at < start || at > end)
        {
            return Err("submission original parameter/field/history mismatch".into());
        }
    }
    for case in report["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["site_id"] == "main.c022")
    {
        let start = case["start_ns"].as_u64().unwrap();
        if actual
            .iter()
            .any(|s| s["at_ns"].as_u64().unwrap() <= start && s["cleared"] != true)
        {
            return Err("submission field history contradicts original aggregate assertion".into());
        }
    }
    // The original accumulator and its later Case own whether a false clearing
    // observation fails. Targeted projections do not acquire a new immediate error.
    Ok(())
}

fn prepare_passphrase(owner: &Owner) -> &'static str {
    if owner == &("main.run".into(), "inside".into(), "main.c001.p001".into())
        || owner.0 == "binding_cases.run" && owner.2.ends_with(".p002")
        || owner
            == &(
                "mode_cases.run".into(),
                "after".into(),
                "mode_cases.c001.p001".into(),
            )
    {
        "store.served"
    } else {
        "store.primary"
    }
}

fn validate_runtime_inputs(report: &Value) -> Result<(), String> {
    validate_worker_exclusions(report)?;
    validate_second_worker(report)?;
    validate_goal_sessions(report)?;
    let inv = completion::inventory();
    let canonical = if report["mode"] == "full" {
        Some(inv)
    } else if matches!(
        report["plan"]["name"].as_str(),
        Some("hold.union" | "inference.session-end.selection")
    ) {
        None
    } else {
        Some(&report["plan"])
    };
    let requirements = if report["mode"] == "full" {
        inv
    } else {
        &report["plan"]
    };
    let mut arguments = BTreeMap::new();
    if let Some(source) = canonical {
        for row in source["runtime_source_domains"]
            .as_array()
            .ok_or("missing runtime parameter source domains")?
        {
            for (position, parameters) in row["arguments"].as_object().unwrap() {
                arguments.insert(
                    (
                        owner(row),
                        position.parse::<usize>().map_err(|e| e.to_string())?,
                    ),
                    parameters.clone(),
                );
            }
        }
    }
    let states = reader_checks::caller_states(report);
    let events = report["helper_history"].as_array().unwrap();
    let mut positions: BTreeMap<Owner, usize> = BTreeMap::new();
    let mut stack: Vec<(u64, &str)> = Vec::new();
    let mut worker_arguments: BTreeMap<u64, bool> = BTreeMap::new();
    let mut expected = Vec::new();
    let mut bindings = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if event["event"] == "call_start" {
            let kind = event["kind"].as_str().unwrap();
            let id = event["call"].as_u64().unwrap();
            let source_owner = states[index + 1]
                .owner
                .as_ref()
                .ok_or("runtime input without source owner")?;
            let root = stack.is_empty();
            let position = positions.get(source_owner).copied().unwrap_or(0);
            let parameters = match kind {
                "binding.prepare" => {
                    Some(json!({"passphrase_role":prepare_passphrase(source_owner)}))
                }
                "runtime.worker" | "runtime.settled" if root => {
                    if let Some(parameters) = arguments.get(&(source_owner.clone(), position)) {
                        Some(parameters.clone())
                    } else if canonical.is_none() {
                        let row = requirements["helper_owner_sequences"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|r| owner(r) == *source_owner)
                            .ok_or("missing composed runtime source")?;
                        Some(if kind == "runtime.worker" {
                            json!({"old":if row["page_operations"][position].as_str().unwrap().starts_with("new:") {"none"} else {"source_entry_current"},"in_use":false})
                        } else {
                            json!({"in_use":false})
                        })
                    } else {
                        return Err("missing original runtime argument occurrence".into());
                    }
                }
                "runtime.worker" => {
                    if stack.last().map(|p| p.1) != Some("binding.prepare") {
                        return Err("runtime worker outside original parent".into());
                    }
                    Some(json!({"old":"source_entry_current","in_use":false}))
                }
                "runtime.settled" => {
                    let (parent, parent_kind) =
                        stack.last().ok_or("settled input without parent")?;
                    let in_use = match *parent_kind {
                        "runtime.worker" => *worker_arguments
                            .get(parent)
                            .ok_or("missing original parent in_use")?,
                        "runtime.submit" => false,
                        _ => return Err("settled outside original parameter parent".into()),
                    };
                    Some(json!({"in_use":in_use}))
                }
                _ => None,
            };
            if let Some(parameters) = parameters {
                if kind == "runtime.worker" {
                    worker_arguments.insert(id, parameters["in_use"].as_bool().unwrap());
                }
                expected.push((
                    id,
                    parameters,
                    index + 1,
                    event["at_ns"].as_u64().unwrap(),
                    events.get(index + 1).ok_or("incomplete runtime input")?["at_ns"]
                        .as_u64()
                        .unwrap(),
                ));
            }
            if root {
                *positions.entry(source_owner.clone()).or_default() += 1;
            }
            stack.push((id, kind));
        } else if event["event"] == "call_end" {
            stack.pop();
        } else if event["event"] == "check" && stack.is_empty() {
            *positions
                .entry(states[index + 1].owner.as_ref().unwrap().clone())
                .or_default() += 1;
        } else if event["event"] == "binding_input" {
            let slot = event["slot"].as_u64().unwrap();
            let role = match slot {
                1 => "machine.first",
                2 => "machine.second",
                3 => "machine.unpinned",
                _ => return Err("unsupported source binding role".into()),
            };
            bindings.push((
                event["call"].as_u64().unwrap(),
                slot,
                role,
                index,
                events[index - 1]["at_ns"].as_u64().unwrap(),
                event["at_ns"].as_u64().unwrap(),
            ));
        }
    }
    let actual = report["runtime_inputs"]
        .as_array()
        .ok_or("missing original runtime input receipts")?;
    if actual.len() != expected.len() {
        return Err("missing/extra/duplicate runtime argument occurrence".into());
    }
    for (row, (id, parameters, cursor, start, end)) in actual.iter().zip(expected) {
        if row.as_object().is_none_or(|o| {
            o.len() != 4
                || !["call", "parameters", "at_ns", "history_cursor"]
                    .iter()
                    .all(|k| o.contains_key(*k))
        }) || row["call"] != id
            || row["parameters"] != parameters
            || row["history_cursor"] != cursor
            || row["at_ns"]
                .as_u64()
                .is_none_or(|at| at < start || at > end)
        {
            return Err("original runtime parameter/caller/history mismatch".into());
        }
    }
    let actual = report["binding_inputs"]
        .as_array()
        .ok_or("missing original binding role receipts")?;
    if actual.len() != bindings.len() {
        return Err("missing/extra/duplicate binding role occurrence".into());
    }
    for (row, (id, slot, role, cursor, start, end)) in actual.iter().zip(bindings) {
        if row.as_object().is_none_or(|o| {
            o.len() != 5
                || !["call", "slot", "role", "at_ns", "history_cursor"]
                    .iter()
                    .all(|k| o.contains_key(*k))
        }) || row["call"] != id
            || row["slot"] != slot
            || row["role"] != role
            || row["history_cursor"] != cursor
            || row["at_ns"]
                .as_u64()
                .is_none_or(|at| at < start || at > end)
        {
            return Err("original binding parameter/role/occurrence/history mismatch".into());
        }
    }
    Ok(())
}

fn validate_second_worker(report: &Value) -> Result<(), String> {
    let error = "original second Worker query/branch/receiver/history mismatch";
    let expected: Vec<_> = report["cases"]
        .as_array()
        .ok_or(error)?
        .iter()
        .filter(|c| c["site_id"] == "lifecycle_cases.c001")
        .collect();
    let actual = report["second_worker_inputs"].as_array().ok_or(error)?;
    if actual.len() != expected.len() {
        return Err(error.into());
    }
    let pages = history::source_page_states(report)?;
    let workers = history::worker_states(report);
    let states = reader_checks::caller_states(report);
    let events = report["helper_history"].as_array().ok_or(error)?;
    for (row, case) in actual.iter().zip(expected) {
        let keys = [
            "worker",
            "page",
            "receiver_ok",
            "locked",
            "start_ns",
            "end_ns",
            "start_cursor",
            "end_cursor",
        ];
        let start = row["start_ns"].as_u64().ok_or(error)?;
        let end = row["end_ns"].as_u64().ok_or(error)?;
        let from = row["start_cursor"].as_u64().ok_or(error)? as usize;
        let until = row["end_cursor"].as_u64().ok_or(error)? as usize;
        let page = row["page"].as_u64().ok_or(error)?;
        if row
            .as_object()
            .is_none_or(|o| o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)))
            || !row["locked"].is_boolean()
            || row["receiver_ok"] != true
            || row["worker"]
                .as_u64()
                .is_none_or(|w| w == 0 || workers.get(from).and_then(|s| s.get(&page)) != Some(&w))
            || pages.get(from).and_then(|s| s.get("temporary")) != Some(&page)
            || from != until
            || start > end
            || case["start_ns"].as_u64().is_none_or(|at| at > start)
            || case["end_ns"].as_u64().is_none_or(|at| at < end)
            || events
                .get(from.wrapping_sub(1))
                .is_none_or(|e| e["at_ns"].as_u64().is_none_or(|at| at > start))
            || events
                .get(until)
                .is_none_or(|e| e["at_ns"].as_u64().is_none_or(|at| at < end))
            || states
                .get(from)
                .and_then(|s| s.owner.as_ref())
                .is_none_or(|o| o.1 != "inside" || o.2 != case["id"])
            || case["branches"]["second-worker"]
                != if row["locked"] == true {
                    "locked"
                } else {
                    "unopened"
                }
        {
            return Err(error.into());
        }
    }
    Ok(())
}

fn validate_worker_exclusions(report: &Value) -> Result<(), String> {
    let error = "original Worker exclusion operand/caller/history mismatch";
    let events = report["helper_history"].as_array().ok_or(error)?;
    let mut workers = BTreeMap::new();
    let mut expected = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if event["event"] == "call_start" && event["kind"] == "runtime.worker" {
            workers.insert(event["call"].as_u64().ok_or(error)?, &event["page"]);
        }
        if event["event"] == "poll"
            && let Some(page) = event["call"].as_u64().and_then(|id| workers.get(&id))
        {
            let before = events.get(index.wrapping_sub(1)).ok_or(error)?;
            if before["event"] != "attempt" || before["call"] != event["call"] {
                return Err(error.into());
            }
            expected.push((index, event, *page, before));
        }
    }
    let actual = report["worker_exclusions"].as_array().ok_or(error)?;
    if actual.len() != expected.len() {
        return Err(error.into());
    }
    for (row, (cursor, event, page, before)) in actual.iter().zip(expected) {
        let keys = ["call", "page", "ok", "ready", "at_ns", "history_cursor"];
        if row.as_object().is_none_or(|fields| {
            fields.len() != keys.len() || keys.iter().any(|key| !fields.contains_key(*key))
        }) || row["call"] != event["call"]
            || row["page"] != *page
            || row["ok"] != true
            || !row["ready"].is_boolean()
            || row["ready"] != event["ready"]
            || row["history_cursor"] != cursor
            || row["at_ns"].as_u64().is_none_or(|at| {
                before["at_ns"].as_u64().is_none_or(|start| at < start)
                    || event["at_ns"].as_u64().is_none_or(|end| at > end)
            })
        {
            return Err(error.into());
        }
    }
    Ok(())
}

fn validate_goal_sessions(report: &Value) -> Result<(), String> {
    let error = "original goal session query/source/receiver/history mismatch";
    let requirements = if report["mode"] == "full" {
        completion::inventory()
    } else {
        &report["plan"]
    };
    let mut wanted = BTreeMap::new();
    for row in requirements["helper_owner_sequences"]
        .as_array()
        .ok_or(error)?
    {
        if !matches!(
            row["scenario"].as_str(),
            Some("goal_cases.run" | "goal_admission_cases.run")
        ) {
            continue;
        }
        for (index, token) in row["tokens"].as_array().ok_or(error)?.iter().enumerate() {
            if token != "call:binding.prepare"
                || row["case"] == "goal_cases.c012.p001" && index == 2
            {
                continue;
            }
            let document = match row["case"].as_str() {
                Some("goal_cases.c009.p001") => Some("pending"),
                Some("goal_cases.c011.p001") => Some("active"),
                _ => None,
            };
            wanted.insert((owner(row), index + 1), document);
        }
    }
    let count = wanted.len();
    let events = report["helper_history"].as_array().ok_or(error)?;
    let states = reader_checks::caller_states(report);
    let positions = source_positions(report);
    let pages = history::source_page_states(report)?;
    let workers = history::worker_states(report);
    let mut stack = Vec::new();
    let mut expected = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if event["event"] == "call_start" {
            stack.push(event);
        } else if event["event"] == "call_end" {
            let start = stack.pop().ok_or(error)?;
            if stack.is_empty() && start["kind"] == "binding.prepare" {
                let source = states[index].owner.as_ref().ok_or(error)?;
                if let Some(document) = wanted.remove(&(source.clone(), positions[index + 1].0)) {
                    expected.push((index + 1, start["page"].as_u64().ok_or(error)?, document));
                }
            }
        }
    }
    let actual = report["goal_session_inputs"].as_array().ok_or(error)?;
    if !wanted.is_empty() || actual.len() != count || expected.len() != count {
        return Err(error.into());
    }
    let mut previous = 0;
    for (row, (cursor, page, document)) in actual.iter().zip(expected) {
        let keys = [
            "worker",
            "page",
            "receiver_ok",
            "query_ok",
            "present",
            "document",
            "start_ns",
            "end_ns",
            "start_cursor",
            "end_cursor",
        ];
        let start = row["start_ns"].as_u64().ok_or(error)?;
        let end = row["end_ns"].as_u64().ok_or(error)?;
        if row
            .as_object()
            .is_none_or(|o| o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)))
            || row["start_cursor"] != cursor
            || row["end_cursor"] != cursor
            || row["page"] != page
            || row["receiver_ok"] != true
            || row["query_ok"] != true
            || row["present"] != true
            || row["document"] != json!(document)
            || workers[cursor]
                .get(&page)
                .is_none_or(|worker| row["worker"] != *worker)
            || pages[cursor].get("tracer") != Some(&page)
            || start < previous
            || start > end
            || events[cursor - 1]["at_ns"]
                .as_u64()
                .is_none_or(|at| at > start)
            || events
                .get(cursor)
                .is_none_or(|e| e["at_ns"].as_u64().is_none_or(|at| at < end))
        {
            return Err(error.into());
        }
        previous = end;
    }
    Ok(())
}

#[cfg(test)]
mod provenance_tests {
    use super::*;
    #[test]
    fn changing_both_phrase_copies_cannot_rewrite_the_transport_return() {
        let phrase = |call| DisplayedPhrase {
            original: crate::cdp::test_original(json!("fixture words")),
            call,
            value: " fixture words ".into(),
        };
        let first = phrase(800_001);
        let reopened = phrase(800_002);
        {
            let mut originals = DISPLAYED_ORIGINALS.lock().unwrap();
            originals.insert(first.call, first.value.clone());
            originals.insert(reopened.call, reopened.value.clone());
        }
        let result = reopened.same_as(&first);
        assert!(result.continues());
        let uses = DISPLAYED_USES.lock().unwrap();
        for index in &result.uses {
            assert_eq!(uses[*index]["result"], true);
            assert_eq!(uses[*index]["ok"], false);
        }
        drop(uses);
        drop(result);
    }
    #[test]
    fn collision_partner_is_the_original_fixed_control() {
        let first = include_str!("../../tests/vectors/seed-backup-collisions.txt")
            .lines()
            .next()
            .unwrap();
        assert_eq!(collision_phrase(1, first).operand()["ok"], true);
        assert_eq!(collision_phrase(0, first).operand()["ok"], false);
        assert_eq!(collision_phrase(2, first).operand()["ok"], false);
        assert_eq!(
            collision_phrase(1, &format!(" {first} ")).operand()["ok"],
            false
        );
    }
    #[test]
    fn displayed_comparisons_require_each_original_query_operand() {
        let report = json!({"observer_calls":[
            {"kind":"seed.phrase","site":"seed.failed_append.initial_phrase","page":1,"start_ns":10,"end_ns":20,"start_cursor":1,"end_cursor":1},
            {"kind":"seed.phrase","site":"seed.failed_append.reopened_phrase","page":1,"start_ns":50,"end_ns":60,"start_cursor":1,"end_cursor":1}],
            "displayed_word_captures":[{"call":1,"page":1,"ok":true,"at_ns":15,"history_cursor":1},{"call":2,"page":1,"ok":true,"at_ns":55,"history_cursor":1}],
            "displayed_word_uses":[{"call":2,"other":1,"partner":null,"result":true,"ok":true,"at_ns":70,"history_cursor":1,"case":"seed_cases.c004.p001","predicate":"seed_cases.a029","instance":1,"check_ns":80,"check_cursor":1},{"call":1,"other":2,"partner":null,"result":true,"ok":true,"at_ns":71,"history_cursor":1,"case":"seed_cases.c004.p001","predicate":"seed_cases.a029","instance":1,"check_ns":80,"check_cursor":1}],
            "primary_history":[{"case":"seed_cases.c004.p001","id":"seed_cases.a029.i001","at_ns":80,"history_cursor":1}],
            "cases":[{"id":"seed_cases.c004.p001","start_ns":0,"end_ns":100}],"helper_history":[{"at_ns":0},{"at_ns":100}]});
        assert!(validate_displayed_words(&report).is_ok());
        for field in ["displayed_word_captures", "displayed_word_uses"] {
            let mut bad = report.clone();
            bad[field][0]["ok"] = json!(false);
            assert!(validate_displayed_words(&bad).is_err());
            let mut bad = report.clone();
            bad[field].as_array_mut().unwrap().pop();
            assert!(validate_displayed_words(&bad).is_err());
            let mut bad = report.clone();
            let duplicate = bad[field][0].clone();
            bad[field].as_array_mut().unwrap().push(duplicate);
            assert!(validate_displayed_words(&bad).is_err());
            assert!(validate_displayed_words(&report).is_ok());
        }
        let mut bad = report.clone();
        bad["displayed_word_uses"][1]["call"] = json!(2);
        assert!(validate_displayed_words(&bad).is_err());
        for (field, value) in [
            ("result", json!(false)),
            ("other", json!(2)),
            ("predicate", json!("seed_cases.a018")),
            ("check_ns", json!(81)),
            ("instance", json!(2)),
        ] {
            let mut bad = report.clone();
            bad["displayed_word_uses"][0][field] = value;
            assert!(validate_displayed_words(&bad).is_err(), "{field}");
        }
        let mut read = report.clone();
        read["observer_calls"].as_array_mut().unwrap().truncate(1);
        read["observer_calls"][0]["site"] = json!("seed.create.initial_phrase");
        read["displayed_word_captures"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        read["displayed_word_uses"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        read["displayed_word_uses"][0]["call"] = json!(1);
        read["displayed_word_uses"][0]["other"] = Value::Null;
        read["displayed_word_uses"][0]["predicate"] = json!("seed_cases.a014");
        read["displayed_word_uses"][0]["partner"] = json!({"kind":"reader","source":1,"site":"reader.aux.call.seed.created.mnemonic","ok":true});
        read["primary_history"][0]["id"] = json!("seed_cases.a014.i001");
        read["reader_roots"] =
            json!([{"site":"reader.call.seed.created","start_ns":25,"end_ns":60}]);
        validate_displayed_words(&read).unwrap();
        for (field, value) in [
            ("source", json!(2)),
            (
                "site",
                json!("reader.aux.call.seed.envelope_finished.mnemonic"),
            ),
            ("ok", json!(false)),
        ] {
            let mut bad = read.clone();
            bad["displayed_word_uses"][0]["partner"][field] = value;
            assert!(validate_displayed_words(&bad).is_err(), "{field}");
        }
        validate_displayed_words(&read).unwrap();
        let mut collision = read.clone();
        let id = "seed_cases.c001.p001";
        collision["cases"][0]["id"] = json!(id);
        collision["observer_calls"][0]["site"] = json!("seed.collision.initial_phrase");
        collision["displayed_word_uses"][0]["case"] = json!(id);
        collision["displayed_word_uses"][0]["predicate"] = json!("seed_cases.a001");
        collision["displayed_word_uses"][0]["partner"] =
            json!({"kind":"collision","index":1,"ok":true});
        collision["primary_history"][0]["case"] = json!(id);
        collision["primary_history"][0]["id"] = json!("seed_cases.a001.i001");
        collision["reader_roots"] = json!([]);
        validate_displayed_words(&collision).unwrap();
        for (field, value) in [
            ("index", json!(2)),
            ("ok", json!(false)),
            ("kind", json!("reader")),
        ] {
            let mut bad = collision.clone();
            bad["displayed_word_uses"][0]["partner"][field] = value;
            assert!(validate_displayed_words(&bad).is_err(), "{field}");
        }
    }
    #[test]
    fn worker_exclusion_requires_the_actual_operand_at_every_poll() {
        let report = json!({"helper_history":[
            {"event":"call_start","kind":"runtime.worker","call":1,"page":2,"at_ns":0},
            {"event":"attempt","call":1,"at_ns":10}, {"event":"poll","call":1,"ready":true,"at_ns":20}],
            "worker_exclusions":[{"call":1,"page":2,"ok":true,"ready":true,"at_ns":15,"history_cursor":2}]});
        assert!(validate_worker_exclusions(&report).is_ok());
        for (field, value) in [
            ("ok", json!(false)),
            ("page", json!(1)),
            ("call", json!(2)),
            ("history_cursor", json!(1)),
            ("at_ns", json!(21)),
        ] {
            let mut bad = report.clone();
            bad["worker_exclusions"][0][field] = value;
            assert!(validate_worker_exclusions(&bad).is_err(), "{field}");
            assert!(validate_worker_exclusions(&report).is_ok());
        }
        let mut bad = report.clone();
        bad["worker_exclusions"] = json!([]);
        assert!(validate_worker_exclusions(&bad).is_err());
    }
}

// A case can pass a computed result, but cannot consume its receipt before this poll.
pub(crate) mod poll_boundary {
    use super::*;
    pub struct Binding {
        call: usize,
        attempt: usize,
    }
    impl Binding {
        pub fn coordinates(&self) -> (usize, usize) {
            (self.call, self.attempt)
        }
    }
    impl Call {
        pub fn poll(&self, attempt: usize, ready: impl Into<crate::page_queries::Poll>) -> bool {
            let binding = Binding {
                call: self.index + 1,
                attempt,
            };
            let ready = ready.into().consume(&binding);
            let mut calls = CALLS.lock().unwrap();
            let poll = calls[self.index]["polls"]
                .as_array_mut()
                .unwrap()
                .last_mut()
                .expect("source attempt precedes predicate evaluation");
            assert_eq!(poll["attempt"], attempt);
            // Keep duplicate completions visible rather than overwriting a previous result.
            assert!(
                poll["ready"].is_null(),
                "one result per original observation attempt"
            );
            poll["ready"] = json!(ready);
            poll["end_ns"] = json!(completion::now());
            poll["end_cursor"] = json!(history::cursor());
            ready
        }
    }
}
