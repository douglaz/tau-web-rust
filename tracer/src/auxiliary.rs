//! Owned helper invocations. Input values remain private; only finite source aliases leave.
use super::{completion, json, reader_checks};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Clone, Copy)]
enum Origin {
    Root(usize),
    Standalone(usize),
}
thread_local! {
    static CURRENT: RefCell<Option<Origin>> = const { RefCell::new(None) };
    static CONTEXT: RefCell<Vec<Value>> = const { RefCell::new(Vec::new()) };
    static PHRASE: RefCell<Option<String>> = const { RefCell::new(None) };
}
static COUNTS: Mutex<BTreeMap<(bool, usize, &'static str), usize>> = Mutex::new(BTreeMap::new());
static STANDALONE: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static INPUTS: Mutex<BTreeMap<usize, RootInput>> = Mutex::new(BTreeMap::new());
static DISPLAYED: Mutex<Vec<String>> = Mutex::new(Vec::new());
static LEAKAGE_CAPTURES: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static LEAKAGE_ORIGINALS: Mutex<Vec<Vec<Value>>> = Mutex::new(Vec::new());
static LEAKAGE_USES: Mutex<Vec<Value>> = Mutex::new(Vec::new());
pub struct Messages {
    raw: Vec<Value>,
    source: usize,
}
impl Messages {
    pub fn bind_domain(&self) {
        let ok = LEAKAGE_ORIGINALS
            .lock()
            .unwrap()
            .get(self.source.saturating_sub(1))
            == Some(&self.raw);
        LEAKAGE_USES.lock().unwrap().push(json!({"source":self.source,"ok":ok,"at_ns":completion::now(),"history_cursor":super::history::cursor()}));
    }
}
impl std::ops::Deref for Messages {
    type Target = [Value];
    fn deref(&self) -> &[Value] {
        &self.raw
    }
}
impl<'a> IntoIterator for &'a Messages {
    type Item = &'a Value;
    type IntoIter = std::slice::Iter<'a, Value>;
    fn into_iter(self) -> Self::IntoIter {
        self.raw.iter()
    }
}
pub fn leakage_messages(run: &super::Run<'_>) -> Messages {
    capture_messages(&run.messages, || run.aggregator.observe_receiver())
}
fn capture_messages(query: &RefCell<Vec<Value>>, receiver: impl FnOnce() -> bool) -> Messages {
    let start = completion::now();
    let cursor = super::history::cursor();
    let raw = query.borrow().clone();
    let mut originals = LEAKAGE_ORIGINALS.lock().unwrap();
    let source = originals.len() + 1;
    originals.push(raw.clone());
    drop(originals);
    let messages = Messages { raw, source };
    let mut captures = LEAKAGE_CAPTURES.lock().unwrap();
    let ok = captures.is_empty() && receiver() && super::history::active_case_id().is_none();
    captures
        .push(json!({"start_ns":start,"end_ns":completion::now(),"history_cursor":cursor,"ok":ok}));
    if ok {
        displayed_inputs(&messages);
    }
    messages
}
pub fn leakage_input_captures() -> Value {
    json!(*LEAKAGE_CAPTURES.lock().unwrap())
}
pub fn leakage_input_uses() -> Value {
    json!(*LEAKAGE_USES.lock().unwrap())
}

// These original inputs are never serialized, logged, or used to construct public IDs.
struct RootInput {
    events: Vec<Value>,
    records: Vec<u8>,
    phrase: Option<String>,
    passphrase: String,
    wrapping_key: [u8; 32],
    data_key: [u8; 32],
}

fn record_digest(records: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    for (number, bytes) in records {
        digest.update(&number.to_le_bytes());
        digest.update(&(bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    digest.finish().as_ref().to_vec()
}

fn displayed_inputs(messages: &Messages) {
    *DISPLAYED.lock().unwrap() = messages
        .iter()
        .filter_map(|m| {
            m.pointer("/from/seed_backup_display")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
}

fn slot_index(slot: &str) -> Option<usize> {
    CONTEXT.with_borrow(|context| {
        context
            .iter()
            .rev()
            .find(|v| v["slot"] == slot)
            .and_then(|v| v["index"].as_u64())
            .map(|i| i as usize)
    })
}

fn expected_phrase(caller: &str, origin: usize) -> Option<String> {
    if caller == "reader.aux.call.absence.fixture.role_key" {
        let index = slot_index("reader.aux.absence_phrase")?;
        return std::iter::once("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
            .chain(include_str!("../../tests/vectors/seed-backup-collisions.txt").lines()).nth(index).map(str::to_owned);
    }
    let displayed_slot = match caller {
        "reader.aux.call.main.displayed.mnemonic_needles" => Some("reader.aux.main_displayed_row"),
        "reader.aux.call.main.leakage.displayed_seed_needles" => {
            Some("reader.aux.main_displayed_seed")
        }
        _ => None,
    };
    if let Some(slot) = displayed_slot {
        return DISPLAYED.lock().unwrap().get(slot_index(slot)?).cloned();
    }
    if origin > 0 {
        let current = INPUTS
            .lock()
            .unwrap()
            .get(&origin)
            .and_then(|r| r.phrase.clone());
        if caller == "reader.aux.call.main.leakage.earlier_seed_id" {
            return DISPLAYED
                .lock()
                .unwrap()
                .iter()
                .find(|p| Some(*p) != current.as_ref())
                .cloned();
        }
        return current;
    }
    PHRASE.with_borrow(Clone::clone)
}

pub fn mnemonic_input(phrase: &str) {
    let matches = PHRASE.with_borrow(|p| p.as_deref() == Some(phrase));
    record("reader.aux.mnemonic_input", matches);
}

pub fn opened_input(origin: usize, records: &[(u64, Vec<u8>)]) {
    let matches = INPUTS
        .lock()
        .unwrap()
        .get(&origin)
        .is_some_and(|r| r.records == record_digest(records));
    record("reader.aux.origin_input", matches);
}

pub fn needles_input(opened: &super::reader::Opened, passphrase: &str) {
    let matches = INPUTS
        .lock()
        .unwrap()
        .get(&opened.origin())
        .is_some_and(|r| {
            r.passphrase == passphrase
                && r.wrapping_key == opened.wrapping_key
                && r.data_key == opened.data_key
                && r.records == record_digest(&opened.records)
        });
    record("reader.aux.needles_input", matches);
}

pub fn push_slot(slot: &'static str, index: usize) {
    CONTEXT.with_borrow_mut(|v| v.push(json!({"slot":slot,"index":index})));
}
pub fn pop_slot() {
    CONTEXT.with_borrow_mut(|v| {
        v.pop().expect("active helper input occurrence");
    });
}

pub fn record(id: &'static str, ok: bool) {
    let Some(origin) = CURRENT.with_borrow(|o| *o) else {
        return;
    };
    let (standalone, index) = match origin {
        Origin::Root(i) => (false, i),
        Origin::Standalone(i) => (true, i),
    };
    let mut counts = COUNTS.lock().unwrap();
    let n = counts.entry((standalone, index, id)).or_default();
    *n += 1;
    let guard=CONTEXT.with_borrow(|context| json!({"id":id,"instance":format!("{id}.i{n:03}"),"ok":ok,"context":context,"at_ns":completion::now(),"history_cursor":super::history::cursor()}));
    if standalone {
        STANDALONE.lock().unwrap()[index]["guards"]
            .as_array_mut()
            .unwrap()
            .push(guard);
    } else {
        reader_checks::append_auxiliary(index, guard);
    }
}

fn end_id(family: &str) -> &'static str {
    match family {
        "reader.aux.mnemonic" => "reader.aux.mnemonic.end",
        "reader.aux.opened_seed_id" => "reader.aux.opened_seed_id.end",
        "reader.aux.seed_backups" => "reader.aux.seed_backups.end",
        "reader.aux.passes" => "reader.aux.passes.end",
        "reader.aux.needles" => "reader.aux.needles.end",
        "reader.aux.seed_needles" => "reader.aux.seed_needles.end",
        "reader.aux.seed_secrets" => "reader.aux.seed_secrets.end",
        "reader.aux.seed_id" => "reader.aux.seed_id.end",
        "reader.aux.mnemonic_needles" => "reader.aux.mnemonic_needles.end",
        "reader.aux.role_key" => "reader.aux.role_key.end",
        "reader.aux.setup_events" => "reader.aux.setup_events.end",
        "reader.aux.main_displayed" => "reader.aux.main_displayed.end",
        "reader.aux.absence" => "reader.aux.absence.end",
        "reader.aux.prepare_enrolment" => "reader.aux.prepare_enrolment.end",
        "reader.aux.machine_index" => "reader.aux.machine_index.end",
        "reader.aux.binding_intent" => "reader.aux.binding_intent.end",
        _ => "reader.aux.unknown.end",
    }
}

pub struct Call {
    previous: Option<Origin>,
    previous_phrase: Option<String>,
    end: &'static str,
    caller_scope: bool,
}
impl Call {
    pub fn begin(caller: &'static str, family: &'static str, origin: usize) -> Self {
        let phrase = expected_phrase(caller, origin);
        let previous_phrase = PHRASE.with_borrow_mut(|p| std::mem::replace(p, phrase));
        let previous = CURRENT.with_borrow_mut(|current| {
            let previous = *current;
            if origin > 0 {
                *current = Some(Origin::Root(origin));
            }
            previous
        });
        record(caller, true);
        push_slot(caller, 0);
        record(family, true);
        Self {
            previous,
            previous_phrase,
            end: end_id(family),
            caller_scope: true,
        }
    }
}
impl Drop for Call {
    fn drop(&mut self) {
        record(self.end, true);
        if self.caller_scope {
            pop_slot();
        }
        CURRENT.with_borrow_mut(|current| *current = self.previous);
        PHRASE.with_borrow_mut(|p| *p = self.previous_phrase.take());
    }
}

pub struct Standalone {
    previous: Option<Origin>,
    previous_phrase: Option<String>,
    index: usize,
}
pub fn standalone(site: &'static str, domain: Value) -> Standalone {
    let phrase = if site == "reader.aux.constructor" {
        match domain["caller"].as_str().unwrap_or("") {
            "reader.aux.call.main.no_pin_setup" | "reader.aux.call.main.no_pass_setup" | "reader.aux.call.hold.setup" | "reader.aux.call.mode.setup" | "reader.aux.call.inference.sent_read_setup" | "reader.aux.call.session_end.setup" | "reader.aux.call.lifecycle.setup" => INPUTS.lock().unwrap().get(&reader_checks::last_origin()).and_then(|r| r.phrase.clone()),
            _ => Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into()),
        }
    } else {
        None
    };
    let previous_phrase = PHRASE.with_borrow_mut(|p| std::mem::replace(p, phrase));
    let mut values = STANDALONE.lock().unwrap();
    let index = values.len();
    values.push(json!({"site":site,"domain":domain,"guards":[],"start_ns":completion::now(),"end_ns":null,"history_cursor":super::history::cursor()}));
    let previous = CURRENT.with_borrow_mut(|current| current.replace(Origin::Standalone(index)));
    Standalone {
        previous,
        previous_phrase,
        index,
    }
}
impl Drop for Standalone {
    fn drop(&mut self) {
        STANDALONE.lock().unwrap()[self.index]["end_ns"] = json!(completion::now());
        CURRENT.with_borrow_mut(|current| *current = self.previous);
        PHRASE.with_borrow_mut(|p| *p = self.previous_phrase.take());
    }
}
pub fn snapshot() -> Value {
    json!(*STANDALONE.lock().unwrap())
}

pub fn register(
    origin: usize,
    records: &[(u64, Vec<u8>)],
    passphrase: &str,
    wrapping_key: [u8; 32],
    data_key: [u8; 32],
    events: Vec<Value>,
) {
    let phrase = records
        .first()
        .and_then(|(_, bytes)| crate::journal::event(bytes).ok())
        .and_then(|v| {
            v.pointer("/seed/mnemonic")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    INPUTS.lock().unwrap().insert(
        origin,
        RootInput {
            events,
            records: record_digest(records),
            phrase,
            passphrase: passphrase.into(),
            wrapping_key,
            data_key,
        },
    );
    reader_checks::set_auxiliary_inputs(
        origin,
        super::semantic_domains::auxiliary::auxiliary_raw_root(records, None),
    );
}

pub fn original_events(site: &str, pass: &str) -> Option<Vec<Value>> {
    INPUTS
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(origin, _)| reader_checks::origin_site(**origin).as_deref() == Some(site))
        .filter(|(_, input)| input.passphrase == pass)
        .map(|(_, input)| input.events.clone())
}
pub fn latest_setup_caller() -> Option<String> {
    STANDALONE
        .lock()
        .unwrap()
        .last()?
        .pointer("/domain/caller")?
        .as_str()
        .map(str::to_owned)
}

pub fn original_phrase_matches(origin: usize, phrase: &str) -> bool {
    INPUTS
        .lock()
        .unwrap()
        .get(&origin)
        .and_then(|input| input.phrase.as_deref())
        == Some(phrase)
}
pub fn original_events_match(origin: usize, events: &[Value]) -> bool {
    INPUTS
        .lock()
        .unwrap()
        .get(&origin)
        .is_some_and(|input| input.events == events)
}

type Owner = (String, String, String);

fn owner(row: &Value) -> Owner {
    (
        row["scenario"].as_str().unwrap().into(),
        row["owner"].as_str().unwrap().into(),
        row["case"].as_str().unwrap_or("").into(),
    )
}

fn constructor_root(caller: &str) -> Option<&'static str> {
    match caller {
        "reader.aux.call.main.no_pin_setup" => Some("reader.call.main.pre_no_pin"),
        "reader.aux.call.main.no_pass_setup" => Some("reader.call.main.pre_no_pass"),
        "reader.aux.call.hold.setup" => Some("reader.call.hold.original"),
        "reader.aux.call.mode.setup" => Some("reader.call.mode.original"),
        "reader.aux.call.inference.sent_read_setup" => {
            Some("reader.call.inference.sent_read_original")
        }
        "reader.aux.call.session_end.setup" => Some("reader.call.session_end.original"),
        "reader.aux.call.lifecycle.setup" => Some("reader.call.lifecycle.original"),
        _ => None,
    }
}

pub(super) fn constructor_domains(
    report: &Value,
) -> Result<BTreeMap<Owner, Vec<(u64, Value)>>, String> {
    let inventory = completion::inventory();
    let requirements = if report["mode"] == "full" {
        inventory
    } else {
        &report["plan"]
    };
    let execution: Vec<&str> = if report["mode"] == "full" {
        inventory["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap())
            .collect()
    } else {
        requirements["expected_execution"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect()
    };
    let mut result: BTreeMap<Owner, Vec<(u64, Value)>> = BTreeMap::new();
    let mut rules: Vec<_> = inventory["auxiliary_constructor_rules"]
        .as_array()
        .ok_or("missing constructor caller rules")?
        .iter()
        .collect();
    rules.sort_by_key(|r| r["within_owner_order"].as_u64().unwrap());
    for rule in rules {
        let include = &rule["include_if"];
        let mut anchor = rule["case"].as_str().unwrap();
        if let Some(case) = include["case"].as_str() {
            if !execution.contains(&case) {
                continue;
            }
        } else if let Some(prefix) = include["any_module"]
            .as_str()
            .or(include["any_site"].as_str())
        {
            let Some(first) = execution
                .iter()
                .find(|c| c.starts_with(&format!("{prefix}.")))
            else {
                continue;
            };
            anchor = first;
        } else if let Some(scenario) = include["scenario"].as_str() {
            if requirements["scenario_scopes"].get(scenario).is_none() {
                continue;
            }
            anchor = execution
                .iter()
                .find(|c| c.starts_with(&format!("{}.", scenario.split('.').next().unwrap())))
                .ok_or("missing constructor scenario projection")?;
        } else if let Some(prefix) = include["targeted_plan_prefix"].as_str() {
            if report["mode"] != "targeted"
                || !requirements["name"].as_str().unwrap().starts_with(prefix)
            {
                continue;
            }
        } else {
            return Err("invalid constructor source rule".into());
        }
        let invocation = if anchor.is_empty() && rule["scenario"] == "main.run" {
            1
        } else {
            inventory["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["id"] == anchor)
                .ok_or("missing constructor invocation anchor")?["invocation"]
                .as_u64()
                .ok_or("invalid constructor invocation")?
        };
        let mut position = rule["position"].as_str().unwrap();
        if position == "before" {
            let index = execution
                .iter()
                .position(|c| *c == anchor)
                .ok_or("constructor outside selected source")?;
            position = "after";
            anchor = index.checked_sub(1).map_or("", |i| execution[i]);
        }
        result
            .entry((
                rule["scenario"].as_str().unwrap().into(),
                position.into(),
                anchor.into(),
            ))
            .or_default()
            .push((
                invocation,
                super::semantic_domains::auxiliary::auxiliary_constructor(
                    rule["caller"].as_str().unwrap(),
                    rule["roster"].as_str().unwrap(),
                ),
            ));
    }
    Ok(result)
}

fn validate_guards(
    report: &Value,
    guards: &Value,
    rule: &str,
    domain: &Value,
    bounds: (u64, u64, Option<&Owner>, Option<usize>),
    states: &[reader_checks::CallerState],
) -> Result<(), String> {
    let (start, end, expected_owner, expected_prepare) = bounds;
    let guards = guards
        .as_array()
        .ok_or("missing auxiliary predicate completions")?;
    let expected = super::semantic::program(rule, domain, guards.len())?;
    if guards.len() != expected.len() {
        return Err("auxiliary assertion inventory mismatch: cardinality".into());
    }
    let history = report["helper_history"]
        .as_array()
        .ok_or("missing auxiliary caller history")?;
    let mut counts = BTreeMap::new();
    let mut previous = start;
    for (guard, (id, context)) in guards.iter().zip(expected) {
        let count = counts.entry(id).or_insert(0usize);
        *count += 1;
        let at = guard["at_ns"]
            .as_u64()
            .ok_or("invalid auxiliary predicate timing")?;
        let cursor = guard["history_cursor"]
            .as_u64()
            .and_then(|c| usize::try_from(c).ok())
            .ok_or("invalid auxiliary history cursor")?;
        let state = states
            .get(cursor)
            .ok_or("auxiliary history cursor outside execution")?;
        if guard.as_object().is_none_or(|o| o.len() != 6)
            || guard["id"] != id
            || guard["instance"] != format!("{id}.i{count:03}")
            || guard["ok"] != true
            || guard["context"] != json!(context)
            || at < previous
            || at > end
            || cursor
                .checked_sub(1)
                .is_some_and(|i| history[i]["at_ns"].as_u64().unwrap() > at)
            || history
                .get(cursor)
                .is_some_and(|e| e["at_ns"].as_u64().unwrap() < at)
            || state.owner.as_ref() != expected_owner
            || state.prepare != expected_prepare
        {
            return Err(format!(
                "auxiliary predicate/caller/input/history mismatch: {id}"
            ));
        }
        previous = at;
    }
    Ok(())
}

pub fn validate(report: &Value) -> Result<(), String> {
    validate_leakage_capture(report)?;
    let sources = reader_checks::resolve_callers(report)?;
    let states = reader_checks::caller_states(report);
    let inventory = completion::inventory();
    let requirements = if report["mode"] == "full" {
        inventory
    } else {
        &report["plan"]
    };
    let duration = report["duration_ns"]
        .as_u64()
        .ok_or("missing auxiliary duration")?;
    let standalone = report["auxiliary_calls"]
        .as_array()
        .ok_or("missing standalone auxiliary completions")?;
    let mut constructors = constructor_domains(report)?;
    let mut preview = None;
    let mut previous = 0;
    for call in standalone {
        let start = call["start_ns"]
            .as_u64()
            .ok_or("invalid auxiliary call start")?;
        let end = call["end_ns"]
            .as_u64()
            .ok_or("invalid auxiliary call end")?;
        let cursor = call["history_cursor"]
            .as_u64()
            .and_then(|c| usize::try_from(c).ok())
            .ok_or("invalid auxiliary caller cursor")?;
        let state = states
            .get(cursor)
            .ok_or("auxiliary caller outside history")?;
        if call.as_object().is_none_or(|o| o.len() != 6)
            || start < previous
            || end < start
            || end > duration
        {
            return Err("standalone auxiliary timing/schema mismatch".into());
        }
        previous = end;
        let source_owner = state
            .owner
            .as_ref()
            .ok_or("auxiliary constructor without source owner")?;
        let events = report["helper_history"].as_array().unwrap();
        if state.prepare.is_some()
            || state.prepares_started != 0
            || cursor
                .checked_sub(1)
                .is_some_and(|i| events[i]["at_ns"].as_u64().unwrap() > start)
            || events
                .get(cursor)
                .is_some_and(|e| e["at_ns"].as_u64().unwrap() < end)
        {
            return Err("standalone auxiliary source preparation/history mismatch".into());
        }
        let (rule, domain) = match call["site"].as_str() {
            Some("reader.aux.constructor") => {
                let (invocation, expected) = constructors
                    .get_mut(source_owner)
                    .and_then(|v| (!v.is_empty()).then(|| v.remove(0)))
                    .ok_or("missing/extra constructor source caller")?;
                if state.invocation != invocation
                    || call["domain"] != expected
                    || !super::semantic::domain_matches(&call["domain"], "reader.aux.constructor")
                {
                    return Err("constructor source caller/parameter mismatch".into());
                }
                if let Some(site) = constructor_root(expected["caller"].as_str().unwrap()) {
                    let (index, _) = sources
                        .iter()
                        .enumerate()
                        .find(|(_, s)| {
                            s.site == site
                                && &s.owner == source_owner
                                && s.invocation == state.invocation
                        })
                        .ok_or("missing constructor source reader")?;
                    let read = &report["reader_roots"][index];
                    if read["end_ns"].as_u64().unwrap() > start
                        || report["reader_roots"]
                            .as_array()
                            .unwrap()
                            .get(index + 1)
                            .is_some_and(|r| r["start_ns"].as_u64().unwrap() < end)
                    {
                        return Err("constructor source reader chronology mismatch".into());
                    }
                }
                ("reader.aux.constructor", expected)
            }
            Some("reader.aux.main_displayed") => {
                let execution: Vec<&str> = if report["mode"] == "full" {
                    inventory["cases"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|c| c["id"].as_str().unwrap())
                        .collect()
                } else {
                    requirements["expected_execution"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|c| c.as_str().unwrap())
                        .collect()
                };
                let index = execution
                    .iter()
                    .position(|c| *c == "main.c022.p001")
                    .ok_or("displayed source outside selection")?;
                let expected_owner = (
                    "main.run".into(),
                    "after".into(),
                    index.checked_sub(1).map_or("", |i| execution[i]).into(),
                );
                if state.invocation != 1
                    || preview.is_some()
                    || source_owner != &expected_owner
                    || !super::semantic::domain_matches(&call["domain"], "reader.aux.preview")
                {
                    return Err("displayed input source domain mismatch".into());
                }
                preview = Some(call["domain"]["displayed"].clone());
                ("reader.aux.main_displayed", call["domain"].clone())
            }
            _ => return Err("unknown standalone auxiliary source".into()),
        };
        validate_guards(
            report,
            &call["guards"],
            rule,
            &domain,
            (start, end, Some(source_owner), state.prepare),
            &states,
        )?;
    }
    let expects_preview = report["cases"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["id"] == "main.c022.p001");
    if constructors.values().any(|v| !v.is_empty()) || expects_preview != preview.is_some() {
        return Err("missing whole standalone auxiliary source caller".into());
    }
    let reads = report["reader_roots"].as_array().unwrap();
    for (read_index, (read, source)) in report["reader_roots"]
        .as_array()
        .unwrap()
        .iter()
        .zip(sources)
        .enumerate()
    {
        let raw = &read["auxiliary_inputs"];
        if !super::semantic::domain_matches(raw, "reader.aux.raw") {
            return Err("auxiliary raw input schema mismatch".into());
        }
        if (source.site == "reader.call.inference.reload_revoke"
            && !raw["reload_revoke"]
                .as_str()
                .is_some_and(|s| ["absent", "pending", "finished"].contains(&s)))
            || (source.site != "reader.call.inference.reload_revoke"
                && !raw["reload_revoke"].is_null())
        {
            return Err("auxiliary source conditional input mismatch".into());
        }
        if source.site == "reader.call.inference.reload_revoke" {
            let cases: Vec<_> = report["cases"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|c| c["branches"].get("reload-revoke").is_some())
                .collect();
            if cases.len() != 1 || cases[0]["branches"]["reload-revoke"] != raw["reload_revoke"] {
                return Err(
                    "reload assertion branch differs from original raw input domain".into(),
                );
            }
        }
        let count = read["numeric_files"].as_u64().unwrap() as usize;
        if raw["records"].as_array().unwrap().len() != count
            || (source.site == "reader.call.main.leakage"
                && preview.as_ref() != Some(&raw["displayed"]))
            || (source.site != "reader.call.main.leakage"
                && (raw["displayed"] != json!([])
                    || raw["earlier_search"] != json!([])
                    || raw["earlier"] != "unknown"))
        {
            return Err("auxiliary original input domain mismatch".into());
        }
        let preparation = source
            .prepare
            .map(|ordinal| {
                requirements["helper_owner_sequences"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| owner(row) == source.owner)
                    .and_then(|row| {
                        super::semantic_domains::auxiliary::AuxiliaryPrepareSource::from_source_row(
                            row, ordinal,
                        )
                    })
                    .ok_or("missing auxiliary preparation source domain")
            })
            .transpose()?;
        let domain = super::semantic_domains::auxiliary::auxiliary_root(
            &source.site,
            &source.role,
            &source.owner.2,
            count,
            raw,
            preparation.as_ref(),
        );
        if !super::semantic::domain_matches(&domain, "reader.aux.root_domain") {
            return Err("invalid auxiliary source domain".into());
        }
        validate_guards(
            report,
            &read["auxiliary_guards"],
            "reader.aux.root",
            &domain,
            (
                read["end_ns"].as_u64().unwrap(),
                reads
                    .get(read_index + 1)
                    .map_or(duration, |r| r["start_ns"].as_u64().unwrap()),
                Some(&source.owner),
                source.prepare,
            ),
            &states,
        )?;
    }
    Ok(())
}

/// This computation runs in the supervisor, with its own clock and no child history.
pub fn validate_preflight(value: &Value, full: bool) -> Result<(), String> {
    let duration = value["duration_ns"]
        .as_u64()
        .ok_or("invalid preflight duration")?;
    let calls = value["auxiliary_calls"]
        .as_array()
        .ok_or("missing preflight auxiliary calls")?;
    if value.as_object().is_none_or(|o| o.len() != 4)
        || value["schema"] != 1
        || calls.len() != usize::from(full)
    {
        return Err("preflight auxiliary source/schema mismatch".into());
    }
    for call in calls {
        let start = call["start_ns"].as_u64().ok_or("invalid preflight start")?;
        let end = call["end_ns"].as_u64().ok_or("invalid preflight end")?;
        let domain = super::semantic_domains::auxiliary::auxiliary_absence();
        if call.as_object().is_none_or(|o| o.len() != 6)
            || call["site"] != "reader.aux.absence"
            || call["history_cursor"] != 0
            || call["domain"] != domain
            || start > end
            || end > duration
        {
            return Err("preflight auxiliary source/input mismatch".into());
        }
        let report = json!({"helper_history":[]});
        validate_guards(
            &report,
            &call["guards"],
            "reader.aux.absence",
            &domain,
            (start, end, None, None),
            &[reader_checks::CallerState::default()],
        )?;
    }
    Ok(())
}

fn validate_leakage_capture(report: &Value) -> Result<(), String> {
    let error = "original leakage history snapshot/source/capture census mismatch";
    let execution: Vec<_> = if report["mode"] == "full" {
        completion::inventory()["cases"]
            .as_array()
            .ok_or(error)?
            .iter()
            .map(|c| c["id"].clone())
            .collect()
    } else {
        report["plan"]["expected_execution"]
            .as_array()
            .ok_or(error)?
            .clone()
    };
    let index = execution.iter().position(|id| id == "main.c022.p001");
    let captures = report["leakage_input_captures"].as_array().ok_or(error)?;
    let uses = report["leakage_input_uses"].as_array().ok_or(error)?;
    if captures.len() != usize::from(index.is_some()) {
        return Err(error.into());
    }
    if uses.len() != captures.len() {
        return Err(error.into());
    }
    let Some(index) = index else {
        return Ok(());
    };
    let capture = &captures[0];
    let start = capture["start_ns"].as_u64().ok_or(error)?;
    let end = capture["end_ns"].as_u64().ok_or(error)?;
    let cursor = capture["history_cursor"].as_u64().ok_or(error)? as usize;
    let previous = index
        .checked_sub(1)
        .and_then(|i| execution[i].as_str())
        .ok_or(error)?;
    let states = reader_checks::caller_states(report);
    let events = report["helper_history"].as_array().ok_or(error)?;
    let owner = (
        "main.run".to_owned(),
        "after".to_owned(),
        previous.to_owned(),
    );
    let preview = report["auxiliary_calls"]
        .as_array()
        .ok_or(error)?
        .iter()
        .find(|c| c["site"] == "reader.aux.main_displayed")
        .ok_or(error)?;
    let use_ = &uses[0];
    if use_.as_object().is_none_or(|o| o.len() != 4)
        || use_["source"] != 1
        || use_["ok"] != true
        || use_["history_cursor"] != capture["history_cursor"]
        || use_["at_ns"].as_u64().is_none_or(|at| {
            at < end || preview["start_ns"].as_u64().is_none_or(|until| at > until)
        })
    {
        return Err(error.into());
    }
    if capture.as_object().is_none_or(|o| o.len() != 4)
        || capture["ok"] != true
        || start > end
        || states.get(cursor).and_then(|s| s.owner.as_ref()) != Some(&owner)
        || !super::observer::source_positions(report)
            .get(cursor)
            .is_some_and(|p| p.1)
        || events
            .get(cursor.wrapping_sub(1))
            .is_none_or(|e| e["at_ns"].as_u64().is_none_or(|at| at > start))
        || events
            .get(cursor)
            .is_none_or(|e| e["at_ns"].as_u64().is_none_or(|at| at < end))
        || preview["start_ns"].as_u64().is_none_or(|at| at < end)
    {
        return Err(error.into());
    }
    Ok(())
}

/// Validate the permitted declaration suffix using the authenticated original journal.
/// Ciphertexts and keys remain private, including when validation fails.
pub fn contracts_output_matches(
    origin: usize,
    before: &crate::Files,
    after: &crate::Files,
    pass: &str,
) -> bool {
    fn check(
        input: &RootInput,
        before: &crate::Files,
        after: &crate::Files,
        pass: &str,
    ) -> Option<()> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use std::collections::BTreeSet;
        if pass != input.passphrase
            || before.input()["ok"] != true
            || before.input()["site"] != "file.binding_cases.dump.001"
        {
            return None;
        }
        let mut access = BTreeMap::new();
        let mut classes = BTreeSet::new();
        let mut declared = BTreeSet::new();
        for event in &input.events {
            if let Some(entries) = event
                .pointer("/setup/approval/entries")
                .and_then(Value::as_array)
            {
                for entry in entries {
                    access.insert(
                        entry.pointer("/entry/machine")?.as_str()?.to_owned(),
                        entry.get("access")?.clone(),
                    );
                }
            }
            if let Some(machine) = event
                .pointer("/setup/class/machine")
                .and_then(Value::as_str)
            {
                classes.insert(machine.to_owned());
            }
            if let Some(proposal) = event.pointer("/setup/requirements/proposal")
                && proposal["kind"] == "declaration"
            {
                declared.insert(proposal["machine"].as_str()?.to_owned());
            }
        }
        let mut suffix = Vec::new();
        for machine in classes.difference(&declared) {
            if let Some(access) = access.get(machine).filter(|a| !a.is_null()) {
                suffix.push(json!({"setup":{"requirements":{"session":format!("fixture-contract-{machine}"),"candidate":0,"access":access,"proposal":{"kind":"declaration","machine":machine,"declaration":crate::file_recipes::minimum()}}}}));
            }
        }
        if after.len() != before.len() + suffix.len()
            || before
                .iter()
                .any(|(name, bytes)| after.get(name) != Some(bytes))
        {
            return None;
        }
        let envelope: Value = serde_json::from_slice(before.get("envelope.json")?).ok()?;
        let id = envelope["id"].as_str()?;
        let hash = |bytes: &[u8]| hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes));
        let number = input.events.len() as u64;
        let mut previous = hash(before.get(&number.checked_sub(1)?.to_string())?);
        for (number, expected) in (number..).zip(suffix) {
            let bytes = after.get(&number.to_string())?;
            let record: Value = serde_json::from_slice(bytes).ok()?;
            let mut nonce = [0x6d; 12];
            nonce[4..].copy_from_slice(&number.to_be_bytes());
            if record.as_object()?.len() != 6
                || record["id"] != id
                || record["type"] != "event"
                || record["number"] != number
                || record["previous"] != previous
                || URL_SAFE_NO_PAD.decode(record["nonce"].as_str()?).ok()? != nonce
                || crate::reader::record_bytes(&record) != *bytes
            {
                return None;
            }
            let mut ciphertext = URL_SAFE_NO_PAD
                .decode(record["ciphertext"].as_str()?)
                .ok()?;
            let key = ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &input.data_key).ok()?,
            );
            let aad = format!("tau-web/local/v1/{id}/event/{number}/{previous}");
            let plain = key
                .open_in_place(
                    ring::aead::Nonce::assume_unique_for_key(nonce),
                    ring::aead::Aad::from(aad.as_bytes()),
                    &mut ciphertext,
                )
                .ok()?;
            if plain
                != serde_json::to_vec(&crate::journal::wrap(&expected))
                    .ok()?
                    .as_slice()
            {
                return None;
            }
            previous = hash(bytes);
        }
        Some(())
    }
    if reader_checks::thread_latest_origin() != origin
        || reader_checks::origin_site(origin).as_deref()
            != Some("reader.call.binding.contracts_source")
        || reader_checks::origin_file_input(origin) != Some(before.input())
    {
        return false;
    }
    INPUTS
        .lock()
        .unwrap()
        .get(&origin)
        .is_some_and(|input| check(input, before, after, pass).is_some())
}

#[cfg(test)]
mod constructor_source_tests {
    #[test]
    fn supplied_passphrase_cannot_select_an_older_reader_invocation() {
        let events = vec![
            serde_json::json!({"seed":{"mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}}),
        ];
        for pass in [crate::PASSPHRASE, crate::SERVED_PASSPHRASE] {
            let files = crate::reader::build(pass, &events);
            crate::reader::read_at("reader.call.test.constructor_authority", &files, pass).unwrap();
        }
        assert!(
            super::original_events("reader.call.test.constructor_authority", crate::PASSPHRASE)
                .is_none()
        );
        assert_eq!(
            super::original_events(
                "reader.call.test.constructor_authority",
                crate::SERVED_PASSPHRASE
            ),
            Some(events)
        );
    }
}

#[cfg(test)]
mod leakage_tests {
    use super::*;
    fn python(report: &Value) -> (bool, String) {
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let mut child=Command::new("python3").args(["-B","-c","import json,sys;sys.path.insert(0,sys.argv[1]);import tracer_history;from pathlib import Path;tracer_history._validate_leakage_capture(json.load(sys.stdin),json.loads(Path(sys.argv[2]).read_text()))"])
            .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("scripts"))
            .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inventory.json"))
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(report.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        (
            output.status.success(),
            String::from_utf8(output.stderr).unwrap(),
        )
    }
    fn exercise(change: &str) {
        // This isolated component runs the original in-memory query producer and
        // both consumers. It supplies no full execution or conformance credit.
        super::super::history::start();
        for event in [
            json!({"event":"scenario_start","invocation":1,"id":"main.run"}),
            json!({"event":"scenario_start","invocation":1,"id":"goal_cases.run"}),
            json!({"event":"case_start","id":"goal_cases.c012.p001"}),
            json!({"event":"case_end","id":"goal_cases.c012.p001"}),
            json!({"event":"scenario_end","invocation":1,"id":"goal_cases.run"}),
        ] {
            super::super::history::event(event);
        }
        LEAKAGE_CAPTURES.lock().unwrap().clear();
        LEAKAGE_ORIGINALS.lock().unwrap().clear();
        LEAKAGE_USES.lock().unwrap().clear();
        DISPLAYED.lock().unwrap().clear();
        let source = RefCell::new(vec![
            json!({"from":{"seed_backup_display":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}}),
            json!({"to":{"unlock":"fixture input"}}),
            json!({"from":{"seed_backup_display":include_str!("../../tests/vectors/seed-backup-collisions.txt").lines().next().unwrap()}}),
        ]);
        let mut messages = capture_messages(&source, || true);
        if change == "value" {
            messages.raw.pop();
        }
        if change == "extra" {
            let _ = capture_messages(&source, || true);
        }
        let inputs =
            super::super::semantic_domains::auxiliary::AuxiliaryDisplayedInputs::from_messages(
                &messages,
            );
        let preview = standalone("reader.aux.main_displayed", inputs.preview_domain());
        let index = preview.index;
        drop(preview);
        let call = STANDALONE.lock().unwrap()[index].clone();
        super::super::history::event(json!({"event":"case_start","id":"main.c022.p001"}));
        let report = json!({"mode":"targeted","plan":{"expected_execution":["goal_cases.c012.p001","main.c022.p001"]},"helper_history":super::super::history::snapshot(),"auxiliary_calls":[call],"leakage_input_captures":leakage_input_captures(),"leakage_input_uses":leakage_input_uses()});
        let expected = change == "clean";
        let native = validate_leakage_capture(&report);
        let shell = python(&report);
        assert_eq!(native.is_ok(), expected, "native {change}");
        assert_eq!(shell.0, expected, "independent {change}: {}", shell.1);
        if !expected {
            assert!(
                native
                    .unwrap_err()
                    .contains("original leakage history snapshot")
            );
            assert!(shell.1.contains("original leakage history snapshot"));
        }
        if change == "value" {
            assert_eq!(
                report["leakage_input_captures"].as_array().unwrap().len(),
                1
            );
            assert_eq!(report["leakage_input_uses"][0]["ok"], false);
            assert_eq!(source.borrow().len(), 3);
        }
    }
    #[test]
    fn producer_and_capture_use_consumers_reject_changed_history() {
        if std::env::var_os("TAU_LEAKAGE_COMPONENT_CHILD").is_none() {
            let output=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","auxiliary::leakage_tests::producer_and_capture_use_consumers_reject_changed_history","--test-threads=1"]).env("TAU_LEAKAGE_COMPONENT_CHILD","1").output().unwrap();
            assert!(
                output.status.success(),
                "isolated component exited {:?}",
                output.status.code()
            );
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("1 passed; 0 failed")
            );
            return;
        }
        exercise("clean");
        exercise("value");
        exercise("clean");
        exercise("extra");
        exercise("clean");
    }
}
