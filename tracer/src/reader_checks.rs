//! Direct root-reader predicates, with an expectation expanded from the input file domain.
//! Event schemas and historical reader predicates have separate coverage obligations.
use super::{completion, json};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Mutex;

thread_local! {
    static LATEST: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static READS: RefCell<Vec<Reading>> = const { RefCell::new(Vec::new()) };
}
static COMPLETED: Mutex<Vec<Value>> = Mutex::new(Vec::new());

struct Reading {
    value: Value,
    counts: BTreeMap<&'static str, usize>,
    context: Vec<Value>,
}

pub struct Read {
    closed: bool,
}

impl Read {
    pub fn begin(site: &'static str, files: &super::reader::Files) -> Self {
        // This census precedes the actual parse and does not count successful guards.
        let numeric = files
            .keys()
            .filter(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()))
            .count();
        READS.with_borrow_mut(|reads| {
            reads.push(Reading {
                value: json!({"site":site,"history_cursor":super::history::cursor(),"file_input":files.input(),"numeric_files":numeric,"guards":[],"event_domains":[],"semantic_guards":[],"start_ns":completion::now()}),
                counts: BTreeMap::new(),
                context: Vec::new(),
            })
        });
        Self { closed: false }
    }

    pub fn finish(mut self) -> Result<usize, String> {
        READS.with_borrow(|reads| {
            let value = &reads.last().expect("active reader").value;
            validate_root(value)?;
            super::semantic::validate(value)
        })?;
        Ok(self.close())
    }

    fn close(&mut self) -> usize {
        self.closed = true;
        let mut read = READS
            .with_borrow_mut(|reads| reads.pop().expect("active reader"))
            .value;
        read["end_ns"] = json!(completion::now());
        read["auxiliary_inputs"] = Value::Null;
        read["auxiliary_guards"] = json!([]);
        let mut completed = COMPLETED.lock().unwrap();
        read["instance"] = json!(format!("reader.read.i{:03}", completed.len() + 1));
        completed.push(read);
        let origin = completed.len();
        LATEST.with(|latest| latest.set(origin));
        origin
    }
}

impl Drop for Read {
    fn drop(&mut self) {
        if !self.closed {
            self.close();
        }
    }
}

fn guard(id: &'static str, ok: bool) {
    READS.with_borrow_mut(|reads| {
        if let Some(read) = reads.last_mut() {
            let count = read.counts.entry(id).or_default();
            *count += 1;
            read.value["guards"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id":id,"instance":format!("{id}.i{count:03}"),"ok":ok}));
        }
    });
}

pub fn result<T, E>(id: &'static str, result: Result<T, E>) -> Result<T, E> {
    guard(id, result.is_ok());
    result
}

pub fn rejects(id: &'static str, fails: bool) -> bool {
    guard(id, !fails);
    fails
}

pub fn snapshot() -> Value {
    json!(*COMPLETED.lock().unwrap())
}

pub fn input_domain(domain: Value) {
    READS.with_borrow_mut(|reads| {
        if let Some(read) = reads.last_mut() {
            read.value["event_domains"]
                .as_array_mut()
                .unwrap()
                .push(domain);
        }
    });
}

pub fn push_slot(slot: &'static str, index: usize) -> bool {
    READS.with_borrow_mut(|reads| {
        if let Some(read) = reads.last_mut() {
            read.context.push(json!({"slot":slot,"index":index}));
            true
        } else {
            super::auxiliary::push_slot(slot, index);
            false
        }
    })
}

pub fn pop_slot() {
    READS.with_borrow_mut(|reads| {
        reads
            .last_mut()
            .expect("active reader")
            .context
            .pop()
            .expect("active input occurrence");
    });
}

pub fn semantic_guard(id: &'static str, ok: bool) {
    READS.with_borrow_mut(|reads| {
        if let Some(read) = reads.last_mut() {
            let count = read.counts.entry(id).or_default(); *count += 1;
            read.value["semantic_guards"].as_array_mut().unwrap().push(json!({"id":id,"instance":format!("{id}.i{count:03}"),"ok":ok,"context":read.context}));
        } else { super::auxiliary::record(id,ok); }
    });
}

pub fn append_auxiliary(origin: usize, guard: Value) {
    COMPLETED.lock().unwrap()[origin - 1]["auxiliary_guards"]
        .as_array_mut()
        .unwrap()
        .push(guard);
}

pub fn set_auxiliary_inputs(origin: usize, inputs: Value) {
    COMPLETED.lock().unwrap()[origin - 1]["auxiliary_inputs"] = inputs;
}

pub fn set_reload_revoke_input(origin: usize, state: &str) {
    COMPLETED.lock().unwrap()[origin - 1]["auxiliary_inputs"]["reload_revoke"] = json!(state);
}

pub fn thread_latest_origin() -> usize {
    LATEST.with(|latest| latest.get())
}
pub fn origin_file_input(origin: usize) -> Option<Value> {
    COMPLETED
        .lock()
        .unwrap()
        .get(origin.checked_sub(1)?)
        .map(|r| r["file_input"].clone())
}

pub fn last_origin() -> usize {
    COMPLETED.lock().unwrap().len()
}

pub fn origin_site(origin: usize) -> Option<String> {
    COMPLETED
        .lock()
        .unwrap()
        .get(origin.checked_sub(1)?)
        .and_then(|r| r["site"].as_str())
        .map(str::to_owned)
}

fn expected(numeric_files: usize) -> Vec<&'static str> {
    let mut expected = vec!["reader.envelope.lookup", "reader.envelope.json"];
    expected.extend([
        "reader.envelope.constant.iterations",
        "reader.envelope.constant.kdf",
        "reader.envelope.constant.purpose",
        "reader.envelope.constant.version",
        "reader.envelope.id",
        "reader.b64.text.salt",
        "reader.b64.decode.salt",
        "reader.b64.text.nonce",
        "reader.b64.decode.nonce",
        "reader.b64.text.wrapped_key",
        "reader.b64.decode.wrapped_key",
    ]);
    expected.extend([
        "reader.nonce.length",
        "reader.aead.open",
        "reader.data_key.length",
    ]);
    expected.extend(std::iter::repeat_n("reader.file.number", numeric_files));
    for _ in 0..numeric_files {
        expected.extend([
            "reader.record.contiguous",
            "reader.record.json",
            "reader.record.header",
            "reader.record.type",
            "reader.b64.text.nonce",
            "reader.b64.decode.nonce",
            "reader.b64.text.ciphertext",
            "reader.b64.decode.ciphertext",
            "reader.nonce.length",
            "reader.aead.open",
            "reader.record.plaintext_json",
        ]);
    }
    expected
}

fn validate_root(read: &Value) -> Result<(), String> {
    let numeric = read["numeric_files"]
        .as_u64()
        .ok_or("missing reader input domain")?;
    let count =
        usize::try_from(numeric).map_err(|_| "reader input domain exceeds address space")?;
    let guards = read["guards"]
        .as_array()
        .ok_or("missing reader root assertions")?;
    // Check size before expansion so corrupt evidence cannot allocate its claimed domain.
    if count.checked_mul(12).and_then(|n| n.checked_add(16)) != Some(guards.len()) {
        return Err("reader root assertion inventory mismatch: input-domain cardinality".into());
    }
    let want = expected(count);
    let mut counts = BTreeMap::new();
    for (guard, id) in guards.iter().zip(want) {
        let count = counts.entry(id).or_insert(0usize);
        *count += 1;
        if guard["id"] != id
            || guard["instance"] != format!("{id}.i{count:03}")
            || guard["ok"] != true
            || guard.as_object().is_none_or(|o| o.len() != 3)
        {
            return Err(
                "reader root assertion inventory mismatch: predicate identity/order".into(),
            );
        }
    }
    Ok(())
}

pub fn validate(report: &Value) -> Result<(), String> {
    let reads = report["reader_roots"]
        .as_array()
        .ok_or("missing reader root completions")?;
    let mut previous = 0;
    for (index, read) in reads.iter().enumerate() {
        let start = read["start_ns"].as_u64().ok_or("invalid reader start")?;
        let end = read["end_ns"].as_u64().ok_or("invalid reader end")?;
        if start < previous
            || end < start
            || end > report["duration_ns"].as_u64().ok_or("invalid duration")?
            || read.as_object().is_none_or(|o| o.len() != 12)
            || read["instance"] != format!("reader.read.i{:03}", index + 1)
        {
            return Err("reader root timing/schema mismatch".into());
        }
        previous = end;
        validate_root(read)?;
        super::semantic::validate(read)?;
    }
    validate_callers(report)
}

type Owner = (String, String, String);

fn key(scenario: &str, case: Option<&str>, previous: &str) -> Owner {
    (
        scenario.into(),
        if case.is_some() { "inside" } else { "after" }.into(),
        case.unwrap_or(previous).into(),
    )
}

#[derive(Clone)]
pub struct SourceRoot {
    pub invocation: u64,
    pub site: String,
    pub owner: (String, String, String),
    pub role: String,
    pub prepare: Option<usize>,
}

#[derive(Clone, Default)]
pub struct CallerState {
    pub invocation: u64,
    pub owner: Option<(String, String, String)>,
    pub prepare: Option<usize>,
    pub prepares_started: usize,
}

pub fn caller_states(report: &Value) -> Vec<CallerState> {
    let mut result = vec![CallerState::default()];
    let mut scenarios = Vec::new();
    let mut case = None;
    let mut previous = "";
    let mut calls = Vec::new();
    let mut starts: BTreeMap<Owner, usize> = BTreeMap::new();
    for event in report["helper_history"].as_array().unwrap() {
        match event["event"].as_str().unwrap() {
            "scenario_start" => scenarios.push((
                event["id"].as_str().unwrap(),
                event["invocation"].as_u64().unwrap(),
            )),
            "scenario_end" => {
                scenarios.pop();
            }
            "case_start" => case = event["id"].as_str(),
            "case_end" => {
                previous = event["id"].as_str().unwrap();
                case = None;
            }
            "call_start" => {
                let prepare = if event["kind"] == "binding.prepare" {
                    let owner = key(scenarios.last().unwrap().0, case, previous);
                    let n = starts.entry(owner).or_default();
                    *n += 1;
                    Some(*n)
                } else {
                    None
                };
                calls.push(prepare);
            }
            "call_end" => {
                calls.pop();
            }
            _ => {}
        }
        let owner = scenarios.last().map(|s| key(s.0, case, previous));
        result.push(CallerState {
            invocation: scenarios.last().map_or(0, |s| s.1),
            prepares_started: owner
                .as_ref()
                .and_then(|o| starts.get(o))
                .copied()
                .unwrap_or(0),
            owner,
            prepare: calls.iter().rev().find_map(|p| *p),
        });
    }
    result
}

fn validate_callers(report: &Value) -> Result<(), String> {
    resolve_callers(report).map(|_| ())
}

pub fn resolve_callers(report: &Value) -> Result<Vec<SourceRoot>, String> {
    let mut sources = Vec::new();
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
            .ok_or("missing reader selection domain")?
            .iter()
            .map(|c| c.as_str().ok_or("invalid reader selection domain"))
            .collect::<Result<_, _>>()?
    };
    let mut direct: BTreeMap<Owner, Vec<(&str, u64, &str, u64)>> = BTreeMap::new();
    let mut rules: Vec<_> = inventory["reader_caller_rules"]
        .as_array()
        .ok_or("missing independent reader caller rules")?
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
            let module = rule["scenario"]
                .as_str()
                .unwrap()
                .split('.')
                .next()
                .unwrap();
            anchor = execution
                .iter()
                .find(|c| c.starts_with(&format!("{module}.")))
                .ok_or("missing reader scenario projection")?;
        } else {
            return Err("invalid independent reader caller rule".into());
        }
        let invocation = inventory["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == anchor)
            .ok_or("missing reader source invocation")?["invocation"]
            .as_u64()
            .ok_or("invalid reader source invocation")?;
        let owner = match rule["position"].as_str() {
            Some("before") => {
                let index = execution
                    .iter()
                    .position(|c| *c == anchor)
                    .ok_or("reader anchor outside selection")?;
                (
                    rule["scenario"].as_str().unwrap().into(),
                    "after".into(),
                    index.checked_sub(1).map_or("", |i| execution[i]).into(),
                )
            }
            Some(position @ ("inside" | "after")) => (
                rule["scenario"].as_str().unwrap().into(),
                position.into(),
                anchor.into(),
            ),
            _ => return Err("invalid reader source position".into()),
        };
        direct.entry(owner).or_default().push((
            rule["site"].as_str().unwrap(),
            rule["after_prepare"]
                .as_u64()
                .ok_or("missing reader preparation history")?,
            rule["role"].as_str().unwrap(),
            invocation,
        ));
    }
    let mut expected_prepares: BTreeMap<(Owner, usize), Vec<&str>> = BTreeMap::new();
    for row in requirements["helper_owner_sequences"]
        .as_array()
        .ok_or("missing reader parent source domains")?
    {
        let owner = (
            row["scenario"].as_str().unwrap().into(),
            row["owner"].as_str().unwrap().into(),
            row["case"].as_str().unwrap_or("").into(),
        );
        for (i, domain) in row["prepare_domains"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let mut sites = Vec::new();
            if domain["active"] == true {
                sites.push("reader.call.binding.contracts_source");
                if domain["classes"].as_array().is_some_and(|a| !a.is_empty()) {
                    sites.push("reader.call.binding.opened_source");
                    if domain["pass"] == true {
                        sites.push("reader.call.binding.allocated_pass_source");
                    }
                }
            }
            if !sites.is_empty() {
                expected_prepares.insert((owner.clone(), i + 1), sites);
            }
        }
    }
    let mut prepare_invocations = BTreeMap::new();
    let mut ordinals = BTreeMap::new();
    for row in requirements["invocation_root_sequences"]
        .as_array()
        .ok_or("missing reader preparation invocations")?
    {
        let owner = (
            row["scenario"].as_str().unwrap().to_owned(),
            row["owner"].as_str().unwrap().to_owned(),
            row["case"].as_str().unwrap_or("").to_owned(),
        );
        for _ in row["prepare_domains"].as_array().unwrap() {
            let ordinal = ordinals.entry(owner.clone()).or_insert(0usize);
            *ordinal += 1;
            prepare_invocations.insert(
                (owner.clone(), *ordinal),
                row["invocation"]
                    .as_u64()
                    .ok_or("invalid preparation invocation")?,
            );
        }
    }
    let states = caller_states(report);
    let events = report["helper_history"]
        .as_array()
        .ok_or("missing reader caller history")?;
    let mut cursor = 0;
    let mut scenarios: Vec<&str> = Vec::new();
    let mut case = None;
    let mut previous = "";
    let mut calls: Vec<(&str, Owner, usize)> = Vec::new();
    let mut starts: BTreeMap<Owner, usize> = BTreeMap::new();
    let mut completed: BTreeMap<Owner, u64> = BTreeMap::new();
    let mut observed: BTreeMap<Owner, usize> = BTreeMap::new();
    let mut prepared: BTreeMap<(Owner, usize), usize> = BTreeMap::new();
    for read in report["reader_roots"].as_array().unwrap() {
        let start = read["start_ns"].as_u64().unwrap();
        while let Some(event) = events
            .get(cursor)
            .filter(|e| e["at_ns"].as_u64().is_some_and(|at| at <= start))
        {
            cursor += 1;
            match event["event"].as_str().unwrap() {
                "scenario_start" => scenarios.push(event["id"].as_str().unwrap()),
                "scenario_end" => {
                    scenarios.pop();
                }
                "case_start" => case = event["id"].as_str(),
                "case_end" => {
                    previous = event["id"].as_str().unwrap();
                    case = None;
                }
                "call_start" => {
                    let owner = key(
                        scenarios.last().ok_or("reader helper without scenario")?,
                        case,
                        previous,
                    );
                    let name = event["kind"].as_str().unwrap();
                    let ordinal = if name == "binding.prepare" {
                        let n = starts.entry(owner.clone()).or_default();
                        *n += 1;
                        *n
                    } else {
                        0
                    };
                    calls.push((name, owner, ordinal));
                }
                "call_end" => {
                    let (name, owner, _) = calls.pop().ok_or("reader caller history underflow")?;
                    if name == "binding.prepare" {
                        *completed.entry(owner).or_default() += 1;
                    }
                }
                _ => {}
            }
        }
        if events
            .get(cursor)
            .is_some_and(|e| e["at_ns"].as_u64() < read["end_ns"].as_u64())
        {
            return Err("reader crosses source caller/history boundary".into());
        }
        if read["history_cursor"].as_u64() != Some(cursor as u64) {
            return Err("reader source cursor mismatch".into());
        }
        let invocation = states
            .get(cursor)
            .ok_or("reader invocation outside history")?
            .invocation;
        let site = read["site"]
            .as_str()
            .ok_or("missing reader literal caller identity")?;
        if let Some((name, owner, ordinal)) = calls.last() {
            if *name != "binding.prepare" {
                return Err("reader outside required parent call".into());
            }
            let parent = (owner.clone(), *ordinal);
            let n = prepared.entry(parent.clone()).or_default();
            if expected_prepares.get(&parent).and_then(|v| v.get(*n)) != Some(&site)
                || prepare_invocations.get(&parent) != Some(&invocation)
            {
                return Err("missing/extra/duplicate reader parent-role completion".into());
            }
            sources.push(SourceRoot {
                invocation,
                site: site.into(),
                owner: owner.clone(),
                role: "only".into(),
                prepare: Some(*ordinal),
            });
            *n += 1;
        } else {
            let owner = key(
                scenarios.last().ok_or("reader without source scenario")?,
                case,
                previous,
            );
            let n = observed.entry(owner.clone()).or_default();
            let want = direct.get(&owner).and_then(|v| v.get(*n));
            if want.is_none_or(|(expected, after, _, expected_invocation)| {
                *expected != site
                    || *after != completed.get(&owner).copied().unwrap_or(0)
                    || *expected_invocation != invocation
            }) {
                return Err(format!(
                    "reader source caller/order/prepare history mismatch: {site}"
                ));
            }
            sources.push(SourceRoot {
                invocation,
                site: want.unwrap().0.into(),
                owner: owner.clone(),
                role: want.unwrap().2.into(),
                prepare: None,
            });
            *n += 1;
        }
    }
    if direct
        .iter()
        .any(|(k, v)| observed.get(k).copied().unwrap_or(0) != v.len())
        || expected_prepares
            .iter()
            .any(|(k, v)| prepared.get(k).copied().unwrap_or(0) != v.len())
    {
        return Err("missing/extra whole reader call: source caller obligations".into());
    }
    Ok(sources)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_input_domain_requires_each_root_guard() {
        let mut counts = BTreeMap::new();
        let base = json!({"numeric_files":2,"guards":expected(2).into_iter().map(|id|{let n=counts.entry(id).or_insert(0usize);*n+=1;json!({"id":id,"instance":format!("{id}.i{n:03}"),"ok":true})}).collect::<Vec<_>>()});
        validate_root(&base).unwrap();
        for site in [
            "reader.envelope.constant.purpose",
            "reader.record.header",
            "reader.aead.open",
        ] {
            let mut bad = base.clone();
            let guards = bad["guards"].as_array_mut().unwrap();
            let at = guards.iter().position(|g| g["id"] == site).unwrap();
            guards.remove(at);
            assert!(
                validate_root(&bad)
                    .unwrap_err()
                    .contains("inventory mismatch")
            );
        }
        let mut bad = base.clone();
        bad["numeric_files"] = json!(3);
        assert!(validate_root(&bad).is_err());
        let mut bad = base.clone();
        bad["guards"].as_array_mut().unwrap().swap(0, 1);
        assert!(validate_root(&bad).is_err());
        validate_root(&base).unwrap();
    }

    #[test]
    fn targeted_readers_cannot_all_disappear() {
        let plan = super::super::selection::plan(&BTreeMap::from([
            ("TAU_TRACER_DELIVERY".into(), "all".into()),
            ("TAU_TRACER_DELIVERY_CASE".into(), "reports".into()),
        ]))
        .unwrap();
        let report = json!({"mode":"targeted","duration_ns":1,"reader_roots":[],"helper_history":[],"plan":plan});
        assert!(
            validate(&report)
                .unwrap_err()
                .contains("missing/extra whole reader call")
        );
    }
}
