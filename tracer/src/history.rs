//! Serial helper ownership and observation history. Names and credentials stay in memory.
use super::{completion, json};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

#[derive(Default)]
struct State {
    active: bool,
    events: Vec<Value>,
    next_call: u64,
    next_worker: u64,
    pages: BTreeMap<String, u64>,
    workers: BTreeMap<String, (u64, u64)>,
    current_workers: BTreeMap<u64, u64>,
    selected_workers: BTreeMap<u64, super::Worker>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

pub fn start() {
    *STATE.lock().unwrap() = Some(State {
        active: true,
        ..State::default()
    });
}

pub fn event(mut value: Value) -> u64 {
    let at = completion::now();
    if let Some(state) = STATE.lock().unwrap().as_mut().filter(|s| s.active) {
        value["at_ns"] = json!(at);
        state.events.push(value);
    }
    at
}

pub fn snapshot() -> Value {
    json!(
        STATE
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| &s.events)
            .cloned()
            .unwrap_or_default()
    )
}

pub fn cursor() -> usize {
    STATE.lock().unwrap().as_ref().map_or(0, |s| s.events.len())
}

pub fn active_scenario() -> Option<String> {
    let state = STATE.lock().unwrap();
    let state = state.as_ref()?;
    let mut depth = 0;
    for event in state.events.iter().rev() {
        if event["event"] == "scenario_end" {
            depth += 1;
        } else if event["event"] == "scenario_start" {
            if depth == 0 {
                return event["id"].as_str().map(str::to_owned);
            }
            depth -= 1;
        }
    }
    None
}

pub fn active_case_id() -> Option<String> {
    STATE.lock().unwrap().as_ref().and_then(|s| {
        s.events
            .iter()
            .rev()
            .find(|e| e["event"] == "case_start" || e["event"] == "case_end")
            .filter(|e| e["event"] == "case_start")
            .and_then(|e| e["id"].as_str())
            .map(str::to_owned)
    })
}

pub fn page_id(session: &str) -> u64 {
    STATE
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|s| s.pages.get(session).copied())
        .unwrap_or(0)
}

pub fn worker_identity(session: &str) -> (u64, u64) {
    STATE
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|s| s.workers.get(session).copied())
        .unwrap_or((0, 0))
}

/// Full original selection operands stay private; only source ordinals enter evidence.
pub fn selected_worker_matches(page: u64, worker: &super::Worker) -> bool {
    STATE
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|state| state.selected_workers.get(&page) == Some(worker))
}

pub fn worker_states(report: &Value) -> Vec<BTreeMap<u64, u64>> {
    let mut workers = BTreeMap::new();
    let mut calls = BTreeMap::new();
    let mut result = vec![workers.clone()];
    for event in report["helper_history"].as_array().unwrap() {
        if event["event"] == "call_start" {
            calls.insert(
                event["call"].as_u64().unwrap(),
                event["page"].as_u64().unwrap(),
            );
        }
        if event["event"] == "worker_selected" {
            let page = calls[&event["call"].as_u64().unwrap()];
            workers.insert(page, event["worker"].as_u64().unwrap());
        }
        result.push(workers.clone());
    }
    result
}

/// Page-role assignments already justified by the independent source owner program.
pub fn source_page_states(report: &Value) -> Result<Vec<BTreeMap<String, u64>>, String> {
    let requirements = if report["mode"] == "full" {
        completion::inventory()
    } else {
        &report["plan"]
    };
    let states = super::reader_checks::caller_states(report);
    let mut pages = BTreeMap::new();
    let mut result = vec![pages.clone()];
    let mut positions: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    let mut depth = 0;
    for (index, event) in report["helper_history"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        if event["event"] == "call_start" {
            if depth == 0 {
                let owner = states[index + 1]
                    .owner
                    .as_ref()
                    .ok_or("page source without owner")?;
                let position = positions.entry(owner.clone()).or_default();
                let row = requirements["helper_owner_sequences"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|r| {
                        r["scenario"] == owner.0
                            && r["owner"] == owner.1
                            && r["case"].as_str().unwrap_or("") == owner.2
                    })
                    .ok_or("missing observer source page row")?;
                let operation = row["page_operations"]
                    .get(*position)
                    .and_then(Value::as_str)
                    .ok_or("missing observer source page operation")?;
                if let Some(role) = operation.strip_prefix("new:") {
                    if role == "tracer"
                        && let Some(old) = pages.get(role).copied()
                        && old != event["page"].as_u64().unwrap()
                        && owner.0 == "main.run"
                        && owner.1 == "inside"
                        && owner.2 == "main.c020.p001"
                    {
                        pages.insert("prior_tracer_at_main_c020_birth".into(), old);
                    }
                    pages.insert(role.into(), event["page"].as_u64().unwrap());
                }
                *position += 1;
            }
            depth += 1;
        } else if event["event"] == "call_end" {
            depth -= 1;
        } else if event["event"] == "check" && depth == 0 {
            let owner = states[index + 1]
                .owner
                .as_ref()
                .ok_or("page source check without owner")?;
            *positions.entry(owner.clone()).or_default() += 1;
        }
        result.push(pages.clone());
    }
    Ok(result)
}

pub struct Call {
    id: u64,
}

impl Call {
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn page(kind: &'static str, page: &str) -> Self {
        let mut state = STATE.lock().unwrap();
        let Some(state) = state.as_mut() else {
            return Self { id: 0 };
        };
        let next = state.pages.len() as u64 + 1;
        let page = *state.pages.entry(page.into()).or_insert(next);
        let worker = if kind == "runtime.worker" {
            0
        } else {
            state.current_workers.get(&page).copied().unwrap_or(0)
        };
        Self::begin(state, kind, page, worker)
    }

    pub fn worker(kind: &'static str, worker: &str) -> Self {
        let mut state = STATE.lock().unwrap();
        let Some(state) = state.as_mut() else {
            return Self { id: 0 };
        };
        let (worker, page) = state.workers.get(worker).copied().unwrap_or((0, 0));
        Self::begin(state, kind, page, worker)
    }

    fn begin(state: &mut State, kind: &str, page: u64, worker: u64) -> Self {
        state.next_call += 1;
        let id = state.next_call;
        state.events.push(json!({"event":"call_start","call":id,"kind":kind,"page":page,"worker":worker,"at_ns":completion::now()}));
        Self { id }
    }

    pub fn select(&self, candidate: &super::observer::WorkerCandidate) {
        let mut state = STATE.lock().unwrap();
        let Some(state) = state.as_mut() else {
            return;
        };
        let page = state
            .events
            .iter()
            .rev()
            .find(|e| e["event"] == "call_start" && e["call"] == self.id)
            .unwrap()["page"]
            .as_u64()
            .unwrap();
        state.next_worker += 1;
        let slot = state.next_worker;
        let (worker, operand_ok) = candidate.selection(self.id, page, state.events.len());
        state.workers.insert(worker.session.clone(), (slot, page));
        state.current_workers.insert(page, slot);
        state.selected_workers.insert(page, worker.clone());
        state.events.push(json!({"event":"worker_selected","call":self.id,"worker":slot,"operand_ok":operand_ok,"at_ns":completion::now()}));
    }

    pub fn poll(&self, ready: bool) -> bool {
        self.observe("poll", json!({"ready":ready}));
        ready
    }

    pub fn attempt(&self, ordinal: usize) {
        self.observe("attempt", json!({"ordinal":ordinal}));
    }

    pub fn observe(&self, kind: &str, mut value: Value) {
        value["event"] = json!(kind);
        value["call"] = json!(self.id);
        event(value);
    }

    pub fn predicate<T, E>(&self, id: &'static str, result: Result<T, E>) -> Result<T, E> {
        self.observe("predicate", json!({"id":id,"ok":result.is_ok()}));
        result
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        event(json!({"event":"call_end","call":self.id}));
    }
}

#[derive(Default)]
struct Frame {
    id: u64,
    kind: String,
    page: u64,
    worker: u64,
    checks: Vec<String>,
    steps: Vec<String>,
    polls: Vec<bool>,
    poll_times: Vec<u64>,
    attempt_times: Vec<u64>,
    attempts: usize,
    input: Option<Value>,
    contracts: Option<bool>,
    pass: Option<bool>,
    bindings: Vec<bool>,
    owner: Option<(String, String, String, u64)>,
}

/// Validate the serial trace against independently specified helper grammars, report
/// owners and worker lifetimes. Neither counts nor timestamps alone establish history.
pub fn validate(report: &Value) -> Result<(), String> {
    let events = report["helper_history"]
        .as_array()
        .ok_or("missing helper caller/history")?;
    let prerequisites = report["prerequisites"]
        .as_array()
        .ok_or("missing prerequisites")?;
    let cases = report["cases"].as_array().ok_or("missing cases")?;
    let scopes = report["scenario_spans"]
        .as_array()
        .ok_or("missing scopes")?;
    let mut calls: Vec<Frame> = Vec::new();
    let mut scenarios: Vec<(&Value, u64, u64)> = Vec::new();
    let mut case: Option<&Value> = None;
    let mut ready: BTreeMap<u64, u64> = BTreeMap::new();
    let mut next_call = 0;
    let mut next_worker = 0;
    let mut next_case = 0;
    let mut next_scope = 0;
    let mut next_check = 0;
    let mut previous = 0;
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut roots: BTreeMap<(String, String, String, u64), Vec<String>> = BTreeMap::new();
    let mut preparations: BTreeMap<(String, String, String, u64), Vec<Value>> = BTreeMap::new();
    let requirements = if report["mode"] == "full" {
        completion::inventory()
    } else {
        &report["plan"]
    };
    let mut page_roles: BTreeMap<String, u64> = BTreeMap::new();
    let mut born_pages = BTreeSet::new();
    for event in events {
        let at = event["at_ns"]
            .as_u64()
            .ok_or("invalid helper history time")?;
        if at < previous || at > report["duration_ns"].as_u64().ok_or("missing duration")? {
            return Err("helper history order/time mismatch".into());
        }
        previous = at;
        let kind = event["event"]
            .as_str()
            .ok_or("missing helper history event")?;
        let fields: &[&str] = match kind {
            "scenario_start" | "scenario_end" => &["event", "id", "invocation", "at_ns"],
            "case_start" | "case_end" => &["event", "id", "at_ns"],
            "call_start" => &["event", "call", "kind", "page", "worker", "at_ns"],
            "call_end" => &["event", "call", "at_ns"],
            "worker_selected" => &["event", "call", "worker", "operand_ok", "at_ns"],
            "predicate" => &["event", "call", "id", "ok", "at_ns"],
            "logical_check" => &["event", "id", "instance", "ok", "at_ns"],
            "check" => &["event", "id", "instance", "ordinal", "at_ns"],
            "poll" => &["event", "call", "ready", "at_ns"],
            "attempt" => &["event", "call", "ordinal", "at_ns"],
            "retry" => &["event", "call", "at_ns"],
            "prepare_input" => &["event", "call", "active", "classes", "at_ns"],
            "contracts" => &["event", "call", "changed", "at_ns"],
            "pass" => &["event", "call", "needed", "at_ns"],
            "binding_input" => &["event", "call", "slot", "bound", "at_ns"],
            _ => return Err("unknown helper history event".into()),
        };
        if event
            .as_object()
            .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)))
        {
            return Err("invalid helper history schema".into());
        }
        match kind {
            "scenario_start" => {
                if !calls.is_empty() || case.is_some() {
                    return Err("scenario boundary crosses active case/helper".into());
                }
                scenarios.push((
                    &event["id"],
                    at,
                    event["invocation"]
                        .as_u64()
                        .filter(|i| *i > 0)
                        .ok_or("missing scenario invocation")?,
                ));
            }
            "scenario_end" => {
                if !calls.is_empty() || case.is_some() {
                    return Err("scenario boundary crosses active case/helper".into());
                }
                let (id, start, invocation) =
                    scenarios.pop().ok_or("scenario history underflow")?;
                if id != &event["id"]
                    || event["invocation"] != invocation
                    || scopes.get(next_scope)
                        != Some(
                            &json!({"id":id,"invocation":invocation,"start_ns":start,"end_ns":at}),
                        )
                {
                    return Err("scenario caller/history mismatch".into());
                }
                next_scope += 1;
            }
            "case_start" => {
                if case.is_some()
                    || !calls.is_empty()
                    || cases
                        .get(next_case)
                        .is_none_or(|c| c["id"] != event["id"] || c["start_ns"] != at)
                {
                    return Err("case caller/history mismatch".into());
                }
                case = cases.get(next_case);
                let module = case.unwrap()["site_id"]
                    .as_str()
                    .ok_or("missing case source owner")?
                    .split('.')
                    .next()
                    .unwrap();
                if scenarios.last().is_none_or(|(id, _, invocation)| {
                    completion::inventory()["cases"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|s| s["id"] == case.unwrap()["id"])
                        .is_none_or(|s| s["invocation"] != *invocation)
                        || id
                            .as_str()
                            .is_none_or(|id| !id.starts_with(&format!("{module}.")))
                }) {
                    return Err("case transplanted across scenario owner".into());
                }
            }
            "case_end" => {
                let owner = case.take().ok_or("case history underflow")?;
                if !calls.is_empty() || owner["id"] != event["id"] || owner["end_ns"] != at {
                    return Err("case caller/history boundary mismatch".into());
                }
                next_case += 1;
            }
            "call_start" => {
                if scenarios.is_empty() {
                    return Err("helper has no scenario owner".into());
                }
                next_call += 1;
                if event["call"] != next_call {
                    return Err("helper call ordinal mismatch".into());
                }
                let name = event["kind"].as_str().ok_or("missing helper kind")?;
                if ![
                    "runtime.worker",
                    "runtime.settled",
                    "runtime.submit",
                    "binding.prepare",
                    "binding.fixture_class.ready",
                    "binding.page.bound",
                ]
                .contains(&name)
                {
                    return Err("unknown helper caller".into());
                }
                let page = event["page"]
                    .as_u64()
                    .filter(|p| *p > 0)
                    .ok_or("missing helper page owner")?;
                let worker = event["worker"]
                    .as_u64()
                    .ok_or("missing helper worker owner")?;
                if name == "runtime.worker" && worker != 0 {
                    return Err("worker creation has a foreign selected owner".into());
                }
                if name.starts_with("binding.") && ready.get(&page) != Some(&worker) {
                    return Err(
                        "binding before its worker readiness or foreign worker owner".into(),
                    );
                }
                if name == "runtime.submit" && ready.get(&page) != Some(&worker) {
                    return Err("submission before page worker readiness".into());
                }
                if name == "runtime.settled" {
                    let expected = calls
                        .last()
                        .filter(|p| p.kind == "runtime.worker")
                        .map(|p| p.worker)
                        .or_else(|| ready.get(&page).copied());
                    if expected != Some(worker) || worker == 0 {
                        return Err("store observation has a foreign worker owner".into());
                    }
                }
                if ["binding.fixture_class.ready", "binding.page.bound"].contains(&name)
                    && calls
                        .last()
                        .is_none_or(|p| p.kind != "binding.prepare" || p.page != page)
                {
                    return Err("binding wait outside owning preparation".into());
                }
                let owner = if name == "binding.prepare" {
                    if !calls.is_empty() {
                        return Err("preparation outside source root caller".into());
                    }
                    Some(owner_key(&scenarios, case, cases, next_case)?)
                } else {
                    None
                };
                if let Some(parent) = calls.last_mut() {
                    if parent.page != page {
                        return Err("helper transplanted across page owner".into());
                    }
                    parent.steps.push(format!("call:{name}"));
                } else {
                    let key = owner_key(&scenarios, case, cases, next_case)?;
                    let position = roots.get(&key).map_or(0, Vec::len);
                    let row = requirements["invocation_root_sequences"]
                        .as_array()
                        .ok_or("missing source page lineage")?
                        .iter()
                        .find(|r| {
                            r["scenario"] == key.0
                                && r["owner"] == key.1
                                && r["case"].as_str().unwrap_or("") == key.2
                                && r["invocation"] == key.3
                        })
                        .ok_or("helper has no source page lineage owner")?;
                    let operation = row["page_operations"]
                        .get(position)
                        .and_then(Value::as_str)
                        .ok_or("missing source page lineage occurrence")?;
                    if let Some(role) = operation.strip_prefix("new:") {
                        if name != "runtime.worker"
                            || page != born_pages.len() as u64 + 1
                            || !born_pages.insert(page)
                        {
                            return Err("source page lineage birth mismatch".into());
                        }
                        page_roles.insert(role.into(), page);
                    } else if page_roles.get(operation) != Some(&page) {
                        return Err("source page lineage relationship mismatch".into());
                    }
                    root_token(
                        &mut roots,
                        &scenarios,
                        case,
                        cases,
                        next_case,
                        format!("call:{name}"),
                    )?;
                }
                *counts.entry(name.into()).or_default() += 1;
                calls.push(Frame {
                    id: next_call,
                    kind: name.into(),
                    page,
                    worker,
                    owner,
                    ..Frame::default()
                });
            }
            "call_end" => {
                let frame = calls.pop().ok_or("helper history underflow")?;
                if event["call"] != frame.id {
                    return Err("helper caller/history crossing".into());
                }
                validate_frame(&frame)?;
                if let Some(owner) = frame.owner {
                    let input = frame.input.as_ref().ok_or("missing preparation input")?;
                    preparations.entry(owner).or_default().push(json!({
                        "active":input["active"],"classes":input["classes"],
                        "contracts":frame.contracts,"pass":frame.pass,"bindings":frame.bindings
                    }));
                }
            }
            "logical_check" => {
                if !calls.is_empty()
                    || !event["id"].is_string()
                    || !event["instance"].is_string()
                    || event["ok"] != true
                {
                    return Err(
                        "original logical predicate failed or crossed a helper frame".into(),
                    );
                }
            }
            "predicate" => {
                let frame = calls.last_mut().ok_or("logical predicate without caller")?;
                let id = event["id"]
                    .as_str()
                    .ok_or("missing logical predicate identity")?;
                if frame.kind != "binding.prepare"
                    || event["call"] != frame.id
                    || event["ok"] != true
                    || !matches!(
                        id,
                        "binding.prepare.setup_array" | "binding.prepare.machine_name"
                    )
                {
                    return Err("helper logical predicate mismatch".into());
                }
                frame.steps.push(format!("predicate:{id}"));
            }
            "worker_selected" => {
                let frame = calls.last_mut().ok_or("worker selection without caller")?;
                next_worker += 1;
                if frame.kind != "runtime.worker"
                    || event["call"] != frame.id
                    || event["worker"] != next_worker
                    || event["operand_ok"] != true
                    || frame.polls.last() != Some(&true)
                {
                    return Err("worker selection history mismatch".into());
                }
                frame.worker = next_worker;
                frame.steps.push("selected".into());
            }
            "check" => {
                let check = prerequisites
                    .get(next_check)
                    .ok_or("extra prerequisite history")?;
                if event["id"] != check["id"]
                    || event["instance"] != check["instance"]
                    || event["ordinal"] != next_check + 1
                    || scenarios.is_empty()
                {
                    return Err("prerequisite caller/history order mismatch".into());
                }
                next_check += 1;
                let id = check["id"].as_str().ok_or("missing prerequisite id")?;
                let required = match id {
                    "runtime.worker.ready" => Some("runtime.worker"),
                    "runtime.store.ready_nontransient" | "runtime.store.not_failed" => {
                        Some("runtime.settled")
                    }
                    "binding.fixture_class.ready" | "binding.page.bound" => Some(id),
                    "binding.pass.allocation_identity" => Some("binding.prepare"),
                    _ => None,
                };
                if let Some(required) = required
                    && calls.last().is_none_or(|f| f.kind != required)
                {
                    return Err("prerequisite outside independently expected owning call".into());
                }
                if let Some(frame) = calls.last_mut() {
                    frame.checks.push(id.into());
                    frame.steps.push(format!("check:{id}"));
                    if id == "runtime.worker.ready" {
                        ready.insert(frame.page, frame.worker);
                    }
                } else {
                    root_token(
                        &mut roots,
                        &scenarios,
                        case,
                        cases,
                        next_case,
                        format!("check:{id}"),
                    )?;
                }
            }
            "poll" | "attempt" | "retry" | "prepare_input" | "contracts" | "pass"
            | "binding_input" => {
                let frame = calls.last_mut().ok_or("helper input without caller")?;
                if event["call"] != frame.id {
                    return Err("helper input foreign caller".into());
                }
                match kind {
                    "attempt" if event["ordinal"] == frame.attempts + 1 && frame.attempts < 300 => {
                        frame.attempts += 1;
                        frame.attempt_times.push(at);
                        frame.steps.push("attempt".into());
                    }
                    "retry"
                        if frame.kind == "runtime.worker" && frame.polls.last() == Some(&true) =>
                    {
                        frame.steps.push("retry".into());
                    }
                    "poll" => {
                        frame.poll_times.push(at);
                        frame
                            .polls
                            .push(event["ready"].as_bool().ok_or("invalid poll result")?);
                        frame.steps.push("poll".into());
                    }
                    "prepare_input" if frame.kind == "binding.prepare" && frame.input.is_none() => {
                        frame.input = Some(event.clone());
                        frame.steps.push("input".into());
                    }
                    "contracts" if frame.kind == "binding.prepare" && frame.contracts.is_none() => {
                        frame.contracts =
                            Some(event["changed"].as_bool().ok_or("invalid contract input")?);
                        frame.steps.push("contracts".into());
                    }
                    "pass" if frame.kind == "binding.prepare" && frame.pass.is_none() => {
                        frame.pass = Some(event["needed"].as_bool().ok_or("invalid pass input")?);
                        frame.steps.push("pass".into());
                    }
                    "binding_input"
                        if frame.kind == "binding.prepare"
                            && event["slot"] == frame.bindings.len() + 1 =>
                    {
                        frame
                            .bindings
                            .push(event["bound"].as_bool().ok_or("invalid binding input")?);
                        frame.steps.push("binding_input".into());
                    }
                    _ => return Err("duplicate or inapplicable helper input".into()),
                }
            }
            _ => return Err("unknown helper history event".into()),
        }
    }
    let mut expected = BTreeMap::new();
    for row in requirements["invocation_root_sequences"]
        .as_array()
        .ok_or("missing source caller/history productions")?
    {
        let key = (
            row["scenario"].as_str().unwrap().to_string(),
            row["owner"].as_str().unwrap().to_string(),
            row["case"].as_str().unwrap_or("").to_string(),
            row["invocation"]
                .as_u64()
                .ok_or("missing expected source invocation")?,
        );
        let tokens = row["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        if expected.insert(key, tokens).is_some() {
            return Err("duplicate expected caller/history owner".into());
        }
    }
    if roots != expected {
        let key = roots
            .keys()
            .chain(expected.keys())
            .find(|key| roots.get(*key) != expected.get(*key))
            .unwrap();
        return Err(format!(
            "source caller/history owner sequence mismatch: {key:?}"
        ));
    }
    let mut expected_preparations = BTreeMap::new();
    for row in requirements["invocation_root_sequences"]
        .as_array()
        .unwrap()
    {
        let domains = row["prepare_domains"]
            .as_array()
            .ok_or("missing source preparation domains")?;
        if domains.len()
            != row["tokens"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|token| *token == "call:binding.prepare")
                .count()
        {
            return Err("invalid source preparation domains".into());
        }
        if !domains.is_empty() {
            expected_preparations.insert(
                (
                    row["scenario"].as_str().unwrap().to_string(),
                    row["owner"].as_str().unwrap().to_string(),
                    row["case"].as_str().unwrap_or("").to_string(),
                    row["invocation"]
                        .as_u64()
                        .ok_or("missing expected preparation invocation")?,
                ),
                domains.clone(),
            );
        }
    }
    if preparations != expected_preparations {
        return Err("source preparation applicability/history mismatch".into());
    }
    if !calls.is_empty()
        || !scenarios.is_empty()
        || case.is_some()
        || next_case != cases.len()
        || next_scope != scopes.len()
        || next_check != prerequisites.len()
    {
        return Err("incomplete helper caller/history".into());
    }
    for (kind, id) in [
        ("runtime.worker", "runtime.worker.ready"),
        ("runtime.settled", "runtime.store.ready_nontransient"),
        ("binding.fixture_class.ready", "binding.fixture_class.ready"),
        ("binding.page.bound", "binding.page.bound"),
    ] {
        if counts.get(kind).copied().unwrap_or(0)
            != report["prerequisite_requests"][id].as_u64().unwrap_or(0)
        {
            return Err("missing logical helper call/history".into());
        }
    }
    Ok(())
}

/// Fixed multiplicities follow the independent root placements and the original preparation
/// inputs. Poll multiplicity is separately bounded by each original settled invocation.
pub fn expected_prerequisites(requirements: &Value) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    let mut add = |id: &str, n: u64| {
        *counts.entry(id.to_owned()).or_default() += n;
    };
    for row in requirements["helper_owner_sequences"].as_array().unwrap() {
        let mut preparations = row["prepare_domains"].as_array().unwrap().iter();
        for token in row["tokens"].as_array().unwrap() {
            let token = token.as_str().unwrap();
            if let Some(id) = token.strip_prefix("check:") {
                add(id, 1);
                continue;
            }
            match token {
                "call:runtime.worker" => {
                    add("runtime.worker.ready", 1);
                    add("runtime.store.ready_nontransient", 1);
                }
                "call:runtime.submit" | "call:runtime.settled" => {
                    add("runtime.store.ready_nontransient", 1)
                }
                "call:binding.prepare" => {
                    let p = preparations.next().unwrap();
                    if p["active"] != true {
                        continue;
                    }
                    if p["contracts"] == true {
                        add("runtime.worker.ready", 1);
                        add("runtime.store.ready_nontransient", 2);
                    }
                    add(
                        "binding.fixture_class.ready",
                        p["classes"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .filter(|v| **v == true)
                            .count() as u64,
                    );
                    add(
                        "binding.page.bound",
                        p["bindings"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .filter(|v| **v == false)
                            .count() as u64,
                    );
                    if p["pass"] == true {
                        add("binding.pass.allocation_identity", 1);
                    }
                }
                _ => panic!("unknown independent prerequisite root: {token}"),
            }
        }
    }
    counts
}

fn root_token(
    roots: &mut BTreeMap<(String, String, String, u64), Vec<String>>,
    scenarios: &[(&Value, u64, u64)],
    case: Option<&Value>,
    cases: &[Value],
    next_case: usize,
    token: String,
) -> Result<(), String> {
    roots
        .entry(owner_key(scenarios, case, cases, next_case)?)
        .or_default()
        .push(token);
    Ok(())
}

fn owner_key(
    scenarios: &[(&Value, u64, u64)],
    case: Option<&Value>,
    cases: &[Value],
    next_case: usize,
) -> Result<(String, String, String, u64), String> {
    let scenario = scenarios
        .last()
        .and_then(|(id, _, _)| id.as_str())
        .ok_or("root helper without scenario owner")?;
    let owner = if case.is_some() { "inside" } else { "after" };
    let anchor = case
        .or_else(|| next_case.checked_sub(1).and_then(|i| cases.get(i)))
        .and_then(|c| c["id"].as_str())
        .unwrap_or("");
    Ok((
        scenario.into(),
        owner.into(),
        anchor.into(),
        scenarios.last().unwrap().2,
    ))
}

fn validate_frame(frame: &Frame) -> Result<(), String> {
    if frame.attempts != frame.polls.len() {
        return Err("helper polling grammar mismatch: independent attempt domain".into());
    }
    let expected: Vec<String> = match frame.kind.as_str() {
        "runtime.worker" => {
            if frame.polls.is_empty()
                || frame.polls.len() > 300
                || frame.polls.last() != Some(&true)
                || frame.worker == 0
            {
                return Err("worker selection poll history incomplete".into());
            }
            let mut steps = Vec::new();
            for (index, ready) in frame.polls.iter().enumerate() {
                steps.extend(["attempt", "poll"].map(String::from));
                if index + 1 < frame.polls.len() && *ready {
                    steps.push("retry".into());
                }
            }
            steps.extend(
                [
                    "selected",
                    "call:runtime.settled",
                    "check:runtime.worker.ready",
                ]
                .map(String::from),
            );
            steps
        }
        "runtime.settled" => {
            if frame.polls.is_empty()
                || frame.polls.len() > 300
                || frame.polls.last() != Some(&true)
                || frame.polls[..frame.polls.len() - 1].iter().any(|v| *v)
            {
                return Err("store readiness poll/termination history incomplete".into());
            }
            let mut steps = Vec::new();
            for _ in &frame.polls {
                steps.extend(
                    ["attempt", "check:runtime.store.not_failed", "poll"].map(String::from),
                );
            }
            steps.push("check:runtime.store.ready_nontransient".into());
            steps
        }
        "runtime.submit" => vec!["call:runtime.settled".into()],
        "binding.fixture_class.ready" | "binding.page.bound" => {
            if frame.polls.is_empty()
                || frame.polls.len() > 300
                || frame.polls.last() != Some(&true)
                || frame.polls[..frame.polls.len() - 1].iter().any(|v| *v)
            {
                return Err("binding predicate poll/termination history incomplete".into());
            }
            let mut steps = Vec::new();
            for _ in &frame.polls {
                steps.extend(["attempt", "poll"].map(String::from));
            }
            steps.push(format!("check:{}", frame.kind));
            steps
        }
        "binding.prepare" => {
            let input = frame
                .input
                .as_ref()
                .ok_or("missing independent preparation input")?;
            if !input["active"]
                .as_bool()
                .ok_or("invalid preparation applicability")?
            {
                if !input["classes"].is_null()
                    && input["classes"]
                        .as_array()
                        .is_none_or(|a| a.iter().any(|v| !v.is_boolean()))
                {
                    return Err("invalid inactive preparation domain".into());
                }
                if frame.contracts.is_some() || frame.pass.is_some() || !frame.bindings.is_empty() {
                    return Err("inactive preparation has later inputs".into());
                }
                vec!["input".into()]
            } else {
                let classes = input["classes"]
                    .as_array()
                    .ok_or("missing preparation machine domain")?;
                let mut steps = vec![
                    "input".into(),
                    "predicate:binding.prepare.setup_array".into(),
                ];
                for value in classes {
                    if value.as_bool().ok_or("invalid class domain")? {
                        steps.push("predicate:binding.prepare.machine_name".into());
                        steps.push("call:binding.fixture_class.ready".into());
                    }
                }
                steps.push("contracts".into());
                if frame.contracts.ok_or("missing contract-change input")? {
                    steps.extend(["call:runtime.worker", "call:runtime.submit"].map(String::from));
                }
                if classes.is_empty() {
                    if frame.pass.is_some() || !frame.bindings.is_empty() {
                        return Err("empty preparation has page inputs".into());
                    }
                } else {
                    steps.push("pass".into());
                    if frame.pass.ok_or("missing pass applicability input")? {
                        steps.push("check:binding.pass.allocation_identity".into());
                    }
                    if frame.bindings.len() != classes.len() {
                        return Err("incomplete preparation binding domain".into());
                    }
                    for bound in &frame.bindings {
                        steps.push("binding_input".into());
                        if !bound {
                            steps.push("call:binding.page.bound".into());
                        }
                    }
                }
                steps
            }
        }
        _ => return Err("unknown helper grammar".into()),
    };
    if frame.steps != expected {
        return Err(format!(
            "helper caller/history grammar mismatch: {}",
            frame.kind
        ));
    }
    let interval = match frame.kind.as_str() {
        "runtime.worker" | "runtime.settled" => 100_000_000,
        "binding.fixture_class.ready" | "binding.page.bound" => 50_000_000,
        _ => 0,
    };
    for index in 1..frame.polls.len() {
        if !frame.polls[index - 1]
            && frame.attempt_times[index].saturating_sub(frame.poll_times[index - 1]) < interval
        {
            return Err("helper original failed-attempt observation window shortened".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn neighbor() -> Value {
        serde_json::from_str(include_str!("../testdata/helper-history.json")).unwrap()
    }

    #[test]
    fn repeated_scenario_boundary_cannot_reassign_a_case() {
        let base: Value =
            serde_json::from_str(include_str!("../testdata/invocation-boundary.json")).unwrap();
        validate(&base).unwrap();
        let mut moved = base.clone();
        let events = moved["helper_history"].as_array_mut().unwrap();
        let end = events.remove(3);
        let start = events.remove(3);
        let mut end = end;
        end["at_ns"] = json!(2);
        let mut start = start;
        start["at_ns"] = json!(2);
        events.insert(1, end);
        events.insert(2, start);
        moved["scenario_spans"][0]["end_ns"] = json!(2);
        moved["scenario_spans"][1]["start_ns"] = json!(2);
        assert!(validate(&moved).unwrap_err().contains("scenario owner"));
        validate(&base).unwrap();
    }

    #[test]
    fn required_caller_and_poll_history() {
        let base = neighbor();
        validate(&base).unwrap();
        let mut sorted = base.clone();
        sorted["prerequisites"]
            .as_array_mut()
            .unwrap()
            .sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        assert!(
            validate(&sorted)
                .unwrap_err()
                .contains("caller/history order")
        );

        let mut foreign = base.clone();
        let wait = foreign["helper_history"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["event"] == "call_start" && e["kind"] == "binding.page.bound")
            .unwrap();
        wait["worker"] = json!(2);
        assert!(
            validate(&foreign)
                .unwrap_err()
                .contains("foreign worker owner")
        );

        let mut missing_poll = base.clone();
        let events = missing_poll["helper_history"].as_array_mut().unwrap();
        let poll = events
            .iter()
            .position(|e| e["event"] == "poll" && e["call"] == 2)
            .unwrap();
        events.remove(poll);
        assert!(
            validate(&missing_poll)
                .unwrap_err()
                .contains("grammar mismatch")
        );

        let mut early_return = base.clone();
        early_return["helper_history"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["event"] == "poll" && e["call"] == 2)
            .unwrap()["ready"] = json!(true);
        assert!(
            validate(&early_return)
                .unwrap_err()
                .contains("termination history")
        );

        let mut omitted_domain = base.clone();
        omitted_domain["helper_history"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["event"] == "prepare_input")
            .unwrap()["classes"] = json!([true]);
        assert!(
            validate(&omitted_domain)
                .unwrap_err()
                .contains("binding domain")
        );
        validate(&base).unwrap();
    }

    #[test]
    fn scenario_cannot_end_inside_its_helper() {
        let mut bad = neighbor();
        let events = bad["helper_history"].as_array_mut().unwrap();
        let mut end = events.pop().unwrap();
        let before = events.len() - 1;
        end["at_ns"] = events[before]["at_ns"].clone();
        let end_at = end["at_ns"].clone();
        events.insert(before, end);
        bad["scenario_spans"][0]["end_ns"] = end_at;
        assert!(
            validate(&bad)
                .unwrap_err()
                .contains("scenario boundary crosses active case/helper")
        );
    }

    #[test]
    fn source_page_lifetime_distinguishes_reload_from_replacement() {
        let reload: Value =
            serde_json::from_str(include_str!("../testdata/helper-page-reload.json")).unwrap();
        let replacement: Value =
            serde_json::from_str(include_str!("../testdata/helper-page-replacement.json")).unwrap();
        validate(&reload).unwrap();
        validate(&replacement).unwrap();
        let mut transplanted = reload.clone();
        for event in transplanted["helper_history"].as_array_mut().unwrap() {
            if event["event"] == "call_start" && event["call"].as_u64().unwrap() >= 3 {
                event["page"] = json!(2);
            }
        }
        assert!(
            validate(&transplanted)
                .unwrap_err()
                .contains("source page lineage relationship")
        );
        let mut reused = replacement;
        for event in reused["helper_history"].as_array_mut().unwrap() {
            if event["event"] == "call_start" && event["call"].as_u64().unwrap() >= 3 {
                event["page"] = json!(1);
            }
        }
        assert!(
            validate(&reused)
                .unwrap_err()
                .contains("source page lineage birth")
        );
    }
}
