//! Private original fixture operands and their source lifetime. Raw jobs, keys and commands
//! stay here; completion contains only finite roles, counts and source-history coordinates.
use super::*;
use std::sync::{Arc, Mutex, OnceLock};

struct Original {
    seen: usize,
    gate: Arc<fixtures::SessionGate>,
    machine: Arc<machine::Machine>,
    relay: String,
    port: u16,
}
static ORIGINAL: OnceLock<Original> = OnceLock::new();
pub fn register(seen: &Observed, relay: &fixtures::Relay, sshd: &fixtures::Sshd) {
    let guard = seen.lock().unwrap();
    assert!(
        ORIGINAL
            .set(Original {
                seen: std::ptr::from_ref(&*guard) as usize,
                gate: relay.session_gate.clone(),
                machine: sshd.machine.clone(),
                relay: relay.url.clone(),
                port: sshd.port,
            })
            .is_ok(),
        "one original fixture input receiver"
    );
}
pub(super) fn seen_ok(seen: &Seen) -> bool {
    ORIGINAL
        .get()
        .is_some_and(|o| o.seen == std::ptr::from_ref(seen) as usize)
}
fn run_ok(run: &Run<'_>) -> bool {
    causal::source_seen(run.seen)
        && ORIGINAL.get().is_some_and(|o| {
            Arc::ptr_eq(&o.gate, &run.relay.session_gate)
                && Arc::ptr_eq(&o.machine, &run.sshd.machine)
                && o.relay == run.relay.url
                && o.port == run.sshd.port
        })
}

enum Raw {
    Static,
    Cursor(usize),
    Execs { baseline: usize, job: String },
    Command(String),
    Key(String),
    Probes(usize),
    Gate(Arc<fixtures::SessionGate>),
    End,
}
struct Source {
    raw: Raw,
    worker: Worker,
    value: Value,
}
struct Store {
    order: usize,
    sources: Vec<Source>,
}
static STORE: Mutex<Store> = Mutex::new(Store {
    order: 0,
    sources: Vec::new(),
});
fn stamp(store: &mut Store) -> Value {
    store.order += 1;
    json!({"order":store.order,"at_ns":completion::now(),"history_cursor":history::cursor()})
}
fn receiver(mut stamp: Value, worker: &Worker, ok: bool) -> Value {
    let (identity, page) = history::worker_identity(&worker.session);
    stamp["worker"] = json!(identity);
    stamp["page"] = json!(page);
    stamp["ok"] = json!(ok && observer::source_worker_matches(worker));
    stamp
}
pub struct Input(usize);
fn capture(
    name: &'static str,
    case: &str,
    worker: &Worker,
    raw: Raw,
    value: Value,
    ok: bool,
) -> Input {
    let mut store = STORE.lock().unwrap();
    let id = store.sources.len();
    let evidence = receiver(stamp(&mut store), worker, ok);
    store.sources.push(Source {
        raw,
        worker: worker.clone(),
        value: json!({
            "source":id+1,"name":name,"case":case,"capture":evidence,"value":value,
            "triggers":[],"uses":[],"retired":null
        }),
    });
    Input(id)
}
impl Input {
    fn trigger(
        &self,
        event: &'static str,
        run: &Run<'_>,
        worker: &Worker,
        payload_ok: bool,
        operation: &'static str,
    ) {
        let mut store = STORE.lock().unwrap();
        let ok = run_ok(run)
            && store.sources[self.0].worker == *worker
            && store.sources[self.0].value["retired"].is_null();
        let mut value = receiver(stamp(&mut store), worker, ok);
        value["event"] = json!(event);
        value["payload_ok"] = json!(payload_ok);
        value["operation"] = json!(operation);
        store.sources[self.0].value["triggers"]
            .as_array_mut()
            .unwrap()
            .push(value);
    }
}
impl Drop for Input {
    fn drop(&mut self) {
        let mut store = STORE.lock().unwrap();
        let value = stamp(&mut store);
        assert!(
            store.sources[self.0].value["retired"].is_null(),
            "one fixture input retirement"
        );
        store.sources[self.0].value["retired"] = value;
    }
}
fn used(store: &mut Store, input: &Input, call: &observer::Call, ok: bool) {
    let mut value = stamp(store);
    value["call"] = json!(call.id());
    value["attempt"] = json!(call.original_attempt());
    value["ok"] = json!(ok && store.sources[input.0].value["retired"].is_null());
    store.sources[input.0].value["uses"]
        .as_array_mut()
        .unwrap()
        .push(value);
}
pub fn snapshot() -> Value {
    json!(
        STORE
            .lock()
            .unwrap()
            .sources
            .iter()
            .map(|s| s.value.clone())
            .collect::<Vec<_>>()
    )
}

pub fn relay(run: &Run<'_>, worker: &Worker, case: &str, name: &'static str, seen: &Seen) -> Input {
    let value = seen.relay_log.len();
    capture(
        name,
        case,
        worker,
        Raw::Cursor(value),
        json!(value),
        run_ok(run) && seen_ok(seen),
    )
}
pub fn cursor(input: &Input, seen: &Seen, call: &observer::Call) -> usize {
    let mut store = STORE.lock().unwrap();
    let value = match store.sources[input.0].raw {
        Raw::Cursor(value) => value,
        _ => panic!("original relay cursor type"),
    };
    used(&mut store, input, call, seen_ok(seen));
    value
}
pub fn execs(run: &Run<'_>, worker: &Worker, case: &str, job: &str, occurrence: usize) -> Input {
    let baseline = run.seen.lock().unwrap().ssh_exec.len();
    capture(
        "execs",
        case,
        worker,
        Raw::Execs {
            baseline,
            job: job.into(),
        },
        json!(baseline),
        run_ok(run) && causal::produced_job_is("inference.sent_read", occurrence, job),
    )
}
pub fn sent_read(input: &Input, seen: &Seen, job: &str, call: &observer::Call) -> usize {
    let mut store = STORE.lock().unwrap();
    let (baseline, ok) = match &store.sources[input.0].raw {
        Raw::Execs {
            baseline,
            job: original,
        } => (*baseline, original == job),
        _ => panic!("original fixture exec baseline type"),
    };
    used(&mut store, input, call, ok && seen_ok(seen));
    baseline
}
pub fn command(run: &Run<'_>, worker: &Worker, case: &str, path: &Path) -> (Input, String) {
    let command = format!("sleep 2; cat '{}'", path.display());
    let input = capture(
        "command",
        case,
        worker,
        Raw::Command(command.clone()),
        Value::Null,
        run_ok(run),
    );
    (input, command)
}
pub fn command_use(input: &Input, run: &Run<'_>, command: &str, call: &observer::Call) {
    let mut store = STORE.lock().unwrap();
    let ok = matches!(&store.sources[input.0].raw,Raw::Command(original) if original==command);
    used(&mut store, input, call, ok && run_ok(run));
}
pub fn key(run: &Run<'_>, worker: &Worker, case: &str) -> Input {
    // These are precisely the two original queries, in the original order.
    let id = inference_cases::key_id(run, &inference_cases::last_key(run));
    capture("key", case, worker, Raw::Key(id), Value::Null, run_ok(run))
}
pub fn key_use(input: &Input, run: &Run<'_>, call: &observer::Call) -> String {
    let mut store = STORE.lock().unwrap();
    let id = match &store.sources[input.0].raw {
        Raw::Key(id) => id.clone(),
        _ => panic!("original fixture key type"),
    };
    used(&mut store, input, call, run_ok(run));
    id
}
pub fn probes(run: &Run<'_>, worker: &Worker, case: &str) -> Input {
    run.aggregator.observe_receiver();
    let count = fixture_predicates::probes(run, None, 0);
    capture(
        "probes",
        case,
        worker,
        Raw::Probes(count),
        json!(count),
        run_ok(run),
    )
}
pub fn probe_use(input: &Input, run: &Run<'_>, call: &observer::Call) -> usize {
    let mut store = STORE.lock().unwrap();
    let count = match store.sources[input.0].raw {
        Raw::Probes(count) => count,
        _ => panic!("original fixture probe count type"),
    };
    used(&mut store, input, call, run_ok(run));
    count
}
pub fn arm(run: &Run<'_>, worker: &Worker, case: &str, stage: &str) -> Input {
    let input = capture(
        "gate",
        case,
        worker,
        Raw::Gate(run.relay.session_gate.clone()),
        json!(stage),
        run_ok(run),
    );
    run.relay.session_gate.arm(stage);
    input
}
pub fn gate_use(input: &Input, run: &Run<'_>, call: &observer::Call) {
    let mut store = STORE.lock().unwrap();
    let ok = matches!(&store.sources[input.0].raw,Raw::Gate(gate) if Arc::ptr_eq(gate,&run.relay.session_gate));
    used(&mut store, input, call, ok && run_ok(run));
}
pub fn end_marker(run: &Run<'_>, worker: &Worker, case: &str) -> Input {
    capture("end", case, worker, Raw::End, Value::Null, run_ok(run))
}

fn source_case(input: &Input) -> Value {
    let store = STORE.lock().unwrap();
    let id = &store.sources[input.0].value["case"];
    completion::inventory()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == *id)
        .unwrap()
        .clone()
}
fn request(run: &Run<'_>, command: &str) -> Value {
    json!({"machine":"fixture","relay":run.relay.url,"host":"127.0.0.1","port":run.sshd.port,"user":SSH_USER,"command":command})
}
fn expected_run(input: &Input, run: &Run<'_>) -> String {
    let case = source_case(input);
    let site = case["site_id"].as_str().unwrap();
    let label = case["label"].as_str().unwrap();
    let command = match site {
        "session_end_cases.c001" => "printf should-not-launch",
        "session_end_cases.c004" => "printf evidence-race",
        "session_end_cases.c007" => "sleep 4; printf detached-end",
        "session_end_cases.c008" => "printf rekey-evidence",
        "inference_cases.c001" => "printf end-race-command; exit 7",
        "inference_cases.c003" => "printf must-stay-held",
        _ => panic!("original fixture dispatch source"),
    };
    let expression = run_expression(&request(run, command));
    if label.split_whitespace().any(|word| word == "collection") {
        expression.replace("module.run_command(", "module.collect_jobs(")
    } else {
        expression
    }
}

pub async fn session_start(
    input: &Input,
    gate: Option<&Input>,
    run: &Run<'_>,
    worker: &Worker,
    expression: &str,
) -> Result<(), String> {
    let payload_ok = expression == expected_run(input, run);
    if let Some(gate) = gate {
        gate.trigger("dispatch", run, worker, payload_ok, "page.evaluate");
    }
    input.trigger("start", run, worker, payload_ok, "page.evaluate");
    run.browser
        .evaluate(
            &worker.session,
            &format!("self.sessionResult={expression};void 0"),
        )
        .await?;
    Ok(())
}
pub async fn running_page(
    input: &Input,
    job_source: usize,
    run: &Run<'_>,
    worker: &Worker,
    expression: &str,
) -> Result<Value, String> {
    let expected = format!("self.sessionResult={};void 0", expected_run(input, run));
    input.trigger("start", run, worker, expression == expected, "job.page");
    causal::job_page(job_source, run, worker, expression).await
}
pub async fn rekey_module(
    packet: &Input,
    gate: &Input,
    run: &Run<'_>,
    worker: &Worker,
    expression: &str,
) -> Result<Value, String> {
    let case = source_case(packet);
    let expected = if case["site_id"] == "session_end_cases.c001" {
        let boundary = if case["label"].as_str().unwrap().ends_with("at auth-rekey") {
            "session_authentication"
        } else {
            "session_connected"
        };
        format!(
            "m.test_rekey_session({});self.releasePoint();return true;",
            json!(boundary)
        )
    } else {
        "m.test_rekey_session('session_evidence');self.moveReady=new Promise(ready=>m.test_hold_move(new Promise(release=>self.releaseMove=release),ready));self.releasePoint();await self.moveReady;return true;".into()
    };
    let ok = expression == expected && source_case(gate)["id"] == case["id"];
    packet.trigger("dispatch", run, worker, ok, "module");
    gate.trigger("dispatch", run, worker, ok, "module");
    inference_cases::module(run, worker, expression).await
}
pub async fn command_page(
    input: &Input,
    run: &Run<'_>,
    worker: &Worker,
    expression: &str,
) -> Result<Value, String> {
    let expected = format!("self.endRaceCommand={};void 0", expected_run(input, run));
    input.trigger(
        "start",
        run,
        worker,
        expression == expected,
        "page.evaluate",
    );
    run.browser.evaluate(&worker.session, expression).await
}
pub async fn sent_page(
    execs: &Input,
    relay: &Input,
    run: &Run<'_>,
    worker: &Worker,
    expression: &str,
) -> Result<Value, String> {
    let expected = format!("self.sentReadEnd={};void 0", expected_run(execs, run));
    let ok = expression == expected && source_case(execs)["id"] == source_case(relay)["id"];
    execs.trigger("dispatch", run, worker, ok, "page.evaluate");
    relay.trigger("start", run, worker, ok, "page.evaluate");
    run.browser.evaluate(&worker.session, expression).await
}
pub async fn command_module(
    input: &Input,
    run: &Run<'_>,
    worker: &Worker,
    expression: &str,
) -> Result<Value, String> {
    let command = {
        let store = STORE.lock().unwrap();
        match &store.sources[input.0].raw {
            Raw::Command(command) => command.clone(),
            _ => panic!("original lifecycle command"),
        }
    };
    let expected = format!(
        "self.interruptedJob=m.run_command({});return true;",
        json!(request(run, &command).to_string())
    );
    input.trigger("dispatch", run, worker, expression == expected, "module");
    inference_cases::module(run, worker, expression).await
}
pub async fn cold_start(
    input: &Input,
    run: &Run<'_>,
    worker: &Worker,
    expression: &str,
) -> Result<(), String> {
    let request = json!({"machine":"fixture","messages":[{"role":"user","content":"cold route"}]})
        .to_string();
    let expected = format!(
        "(async()=>{{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.inference_request({}));}})()",
        json!(request)
    );
    input.trigger(
        "dispatch",
        run,
        worker,
        expression == expected,
        "page.evaluate",
    );
    run.browser
        .evaluate(
            &worker.session,
            &format!("self.sessionResult={expression};void 0"),
        )
        .await?;
    Ok(())
}
pub async fn end_module(
    input: &Input,
    run: &Run<'_>,
    worker: &Worker,
    expression: &str,
) -> Result<Value, String> {
    let case = source_case(input);
    let expected = match case["site_id"].as_str().unwrap() {
        "inference_cases.c001" => {
            "await self.moveAcquired;self.heldEnd=m.end_sessions();await new Promise(r=>setTimeout(r,0));return true;"
        }
        "inference_cases.c003" => {
            "self.sentEndDone=false;self.heldEnd=m.end_sessions().then(()=>self.sentEndDone=true);return true;"
        }
        _ => {
            "self.endDone=false;self.endWork=m.end_sessions().then(()=>self.endDone=true);await new Promise(r=>setTimeout(r,0));return true;"
        }
    };
    input.trigger("end", run, worker, expression == expected, "module");
    inference_cases::module(run, worker, expression).await
}

pub fn probe_baseline(input: &Input) -> usize {
    match STORE.lock().unwrap().sources[input.0].raw {
        Raw::Probes(count) => count,
        _ => panic!("original fixture probe count type"),
    }
}

pub fn exec_baseline(input: &Input) -> usize {
    match STORE.lock().unwrap().sources[input.0].raw {
        Raw::Execs { baseline, .. } => baseline,
        _ => panic!("original fixture exec count type"),
    }
}

pub fn static_wait(run: &Run<'_>, worker: &Worker, case: &str, name: &'static str) -> Input {
    capture(name, case, worker, Raw::Static, Value::Null, run_ok(run))
}
pub fn static_use(input: &Input, seen: &Seen, call: &observer::Call) {
    let mut store = STORE.lock().unwrap();
    let ok = matches!(store.sources[input.0].raw, Raw::Static) && seen_ok(seen);
    used(&mut store, input, call, ok);
}
fn static_request(run: &Run<'_>) -> Value {
    json!({"machine":"fixture","relay":run.relay.url,"host":"127.0.0.1","port":run.sshd.port,"user":SSH_USER,"command":COMMAND,"fail_append":false,"tamper_auth":false})
}
pub fn setup_request_matches(run: &Run<'_>, value: &Value, tracer: bool, field: &str) -> bool {
    let Some(original) = ORIGINAL.get() else {
        return false;
    };
    let mut expected = json!({"machine":"fixture","relay":original.relay,"host":"127.0.0.1","port":original.port,"user":SSH_USER,"command":COMMAND});
    if tracer {
        expected["fail_append"] = json!(false);
        expected["tamper_auth"] = json!(false);
    }
    expected[field] = json!("sealed");
    run_ok(run) && *value == expected
}
pub async fn refusal_run(
    run: &Run<'_>,
    worker: &Worker,
    case: &str,
    args: Value,
) -> Result<(Input, Value), String> {
    let input = static_wait(run, worker, case, "refusal");
    let mut expected = static_request(run);
    if source_case(&input)["site_id"] == "main.c013" {
        expected["host"] = json!("127.0.0.2");
    }
    input.trigger("dispatch", run, worker, args == expected, "harness.run");
    let value = run.harness_run("fixture_inputs.rs#1", worker, args).await?;
    Ok((input, value))
}
pub async fn static_start(
    exec: &Input,
    socket: Option<&Input>,
    run: &Run<'_>,
    worker: &Worker,
    args: Value,
) -> Result<(), String> {
    let mut expected = static_request(run);
    expected["command"] = json!(LOCK_COMMAND);
    let ok = args == expected;
    exec.trigger("dispatch", run, worker, ok, "harness.start");
    if let Some(socket) = socket {
        socket.trigger(
            "start",
            run,
            worker,
            ok && source_case(exec)["id"] == source_case(socket)["id"],
            "harness.start",
        );
    }
    run.harness_start(worker, args).await
}
pub async fn hold_start(
    input: &Input,
    run: &Run<'_>,
    worker: &Worker,
    name: &str,
    expression: &str,
) -> Result<(), String> {
    let case = source_case(input);
    let source_name = {
        STORE.lock().unwrap().sources[input.0].value["name"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let expected_name = match source_name.as_str() {
        "read.stop" => "__stoppable",
        "read.actual" => "__evidence",
        "read.later" => "__laterEvidence",
        _ => panic!("original hold start site"),
    };
    let mut request = static_request(run);
    if source_name == "read.actual"
        && case["label"]
            .as_str()
            .unwrap()
            .starts_with("evidence append error")
    {
        request["fail_append"] = json!(true);
    }
    input.trigger(
        "dispatch",
        run,
        worker,
        name == expected_name && expression == run_expression(&request),
        "page.evaluate",
    );
    run.browser
        .evaluate(
            &worker.session,
            &format!("self.{name} = {expression}; void 0"),
        )
        .await?;
    Ok(())
}
pub async fn page_transition(
    input: &Input,
    run: &Run<'_>,
    tab: &Tab,
    worker: &Worker,
    expression: &str,
) -> Result<Value, String> {
    let case = source_case(input);
    let expected = match case["site_id"].as_str().unwrap() {
        "main.c017" => LOCK_TRANSITION,
        "main.c018" => "dispatchEvent(new PageTransitionEvent('pagehide', { persisted: false }))",
        "seed_cases.c007" => "document.getElementById(\"tau-redisplay\").click()",
        _ => panic!("original fixture close transition"),
    };
    let page_ok = {
        let store = STORE.lock().unwrap();
        store.sources[input.0].value["capture"]["page"] == history::page_id(&tab.session)
    };
    input.trigger(
        "end",
        run,
        worker,
        page_ok && expression == expected,
        "page.evaluate",
    );
    run.browser.evaluate(&tab.session, expression).await
}
pub async fn seed_click(
    input: &Input,
    run: &Run<'_>,
    tab: &Tab,
    worker: &Worker,
    id: &str,
) -> Result<(), String> {
    page_transition(
        input,
        run,
        tab,
        worker,
        &format!(
            "document.getElementById({}).click()",
            json!(format!("tau-{id}"))
        ),
    )
    .await?;
    Ok(())
}

type Owner = (String, String, String);
fn fields(value: &Value, keys: &[&str]) -> Result<(), String> {
    if value
        .as_object()
        .is_none_or(|o| o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)))
    {
        return Err("invalid original fixture input schema".into());
    }
    Ok(())
}
fn number(value: &Value) -> Result<u64, String> {
    value
        .as_u64()
        .ok_or("invalid original fixture input coordinate".into())
}
fn array(value: &Value) -> Result<&Vec<Value>, String> {
    value
        .as_array()
        .ok_or("invalid original fixture input sequence".into())
}
struct Coordinates<'a> {
    report: &'a Value,
    states: Vec<reader_checks::CallerState>,
    positions: Vec<(usize, bool)>,
    pages: Vec<std::collections::BTreeMap<String, u64>>,
    workers: Vec<std::collections::BTreeMap<u64, u64>>,
}
impl Coordinates<'_> {
    fn at(&self, value: &Value, owner: Option<&Owner>, root: Option<u64>) -> Result<usize, String> {
        let at = number(&value["at_ns"])?;
        let index =
            usize::try_from(number(&value["history_cursor"])?).map_err(|e| e.to_string())?;
        let state = self
            .states
            .get(index)
            .ok_or("fixture input outside source history")?;
        let events = self.report["helper_history"].as_array().unwrap();
        if at > number(&self.report["duration_ns"])?
            || index
                .checked_sub(1)
                .is_some_and(|i| events[i]["at_ns"].as_u64().unwrap() > at)
            || events
                .get(index)
                .is_some_and(|e| e["at_ns"].as_u64().unwrap() < at)
            || owner.is_some_and(|owner| state.owner.as_ref() != Some(owner))
            || root.is_some_and(|root| self.positions[index] != (root as usize, true))
        {
            return Err("original fixture input caller/cursor mismatch".into());
        }
        number(&value["order"])?;
        Ok(index)
    }
    fn receiver(&self, value: &Value, owner: &Owner, root: u64) -> Result<(), String> {
        let index = self.at(value, Some(owner), Some(root))?;
        let page = number(&value["page"])?;
        let worker = number(&value["worker"])?;
        if value["ok"] != true
            || self.pages[index].get("tracer") != Some(&page)
            || self.workers[index].get(&page) != Some(&worker)
        {
            return Err("original fixture input receiver/page/worker mismatch".into());
        }
        Ok(())
    }
}

pub fn validate(report: &Value) -> Result<(), String> {
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
    let program: Vec<_> = inventory["fixture_source_program"]
        .as_array()
        .ok_or("missing original fixture source program")?
        .iter()
        .filter(|p| execution.contains(&p["case"]))
        .collect();
    let expected: Vec<_> = program
        .iter()
        .flat_map(|p| p["sources"].as_array().unwrap().iter().map(|s| (*p, s)))
        .collect();
    let sources = array(&report["fixture_inputs"])?;
    if sources.len() != expected.len() {
        return Err("original fixture input capture multiplicity mismatch".into());
    }
    let ctx = Coordinates {
        report,
        states: reader_checks::caller_states(report),
        positions: observer::source_positions(report),
        pages: history::source_page_states(report)?,
        workers: history::worker_states(report),
    };
    let calls = report["observer_calls"].as_array().unwrap();
    let mut stamps = Vec::new();
    let mut events = Vec::new();
    let mut last_retired = std::collections::BTreeMap::<String, u64>::new();
    for (ordinal, (source, (group, want))) in sources.iter().zip(expected).enumerate() {
        fields(
            source,
            &[
                "source", "name", "case", "capture", "value", "triggers", "uses", "retired",
            ],
        )?;
        let name = want["name"].as_str().unwrap();
        let case = group["case"].as_str().unwrap();
        let scenario = group["scenario"].as_str().unwrap();
        if source["source"] != ordinal + 1
            || !source["source"].is_u64()
            || source["name"] != name
            || source["case"] != case
        {
            return Err("original fixture input source/order mismatch".into());
        }
        let case_index = execution.iter().position(|id| id == case).unwrap();
        let owner = |position: &str| -> Owner {
            if position == "before" {
                (
                    scenario.into(),
                    "after".into(),
                    case_index
                        .checked_sub(1)
                        .map(|i| execution[i].as_str().unwrap().into())
                        .unwrap_or_default(),
                )
            } else {
                (scenario.into(), position.into(), case.into())
            }
        };
        let capture = &source["capture"];
        fields(
            capture,
            &["order", "at_ns", "history_cursor", "worker", "page", "ok"],
        )?;
        ctx.receiver(
            capture,
            &owner(want["capture_owner"].as_str().unwrap()),
            want["capture_root"].as_u64().unwrap(),
        )?;
        let capture_order = number(&capture["order"])?;
        if last_retired
            .get(name)
            .is_some_and(|order| *order >= capture_order)
        {
            return Err("original fixture input source lifetime overlaps successor".into());
        }
        stamps.push(capture);
        events.push((capture_order, format!("{case}:{name}.capture")));
        let mut last_order = capture_order;
        let mut last_time = number(&capture["at_ns"])?;
        let triggers = array(&source["triggers"])?;
        let expected_triggers = want["triggers"].as_array().unwrap();
        if triggers.len() != expected_triggers.len() {
            return Err("original fixture input trigger multiplicity mismatch".into());
        }
        for (trigger, expected) in triggers.iter().zip(expected_triggers) {
            fields(
                trigger,
                &[
                    "order",
                    "at_ns",
                    "history_cursor",
                    "worker",
                    "page",
                    "ok",
                    "event",
                    "payload_ok",
                    "operation",
                ],
            )?;
            if trigger["payload_ok"] != true || trigger["operation"] != expected["operation"] {
                return Err("original fixture dispatch payload/operation mismatch".into());
            }
            ctx.receiver(
                trigger,
                &owner(expected["owner"].as_str().unwrap()),
                expected["root"].as_u64().unwrap(),
            )?;
            let order = number(&trigger["order"])?;
            let at = number(&trigger["at_ns"])?;
            if trigger["event"] != expected["event"]
                || trigger["worker"] != capture["worker"]
                || trigger["page"] != capture["page"]
                || order <= last_order
                || at < last_time
            {
                return Err("original fixture input capture/trigger lineage mismatch".into());
            }
            events.push((
                order,
                format!("{case}:{name}.{}", expected["event"].as_str().unwrap()),
            ));
            stamps.push(trigger);
            last_order = order;
            last_time = at;
        }
        let value = &source["value"];
        match name {
            "relay" | "packet" | "execs" | "probes" => {
                number(value)?;
            }
            "gate" => {
                if *value != want["value"] {
                    return Err("original fixture gate arm parameter mismatch".into());
                }
            }
            "command" | "key" | "end" | "refusal" | "exec" | "socket" | "read.stop"
            | "read.actual" | "read.later" => {
                if !value.is_null() {
                    return Err("unsafe original fixture private operand output".into());
                }
            }
            _ => return Err("unknown original fixture input name".into()),
        }
        let uses = array(&source["uses"])?;
        if want["active"] == true {
            let use_site = want["use_site"].as_str().unwrap();
            let inside = matches!(name, "relay" | "packet") || want["capture_owner"] == "inside";
            let use_owner = owner(if inside {
                "inside"
            } else {
                want["capture_owner"].as_str().unwrap()
            });
            let found: Vec<_> = calls
                .iter()
                .enumerate()
                .filter(|(_, c)| {
                    c["site"] == use_site
                        && ctx.states[c["start_cursor"].as_u64().unwrap() as usize]
                            .owner
                            .as_ref()
                            == Some(&use_owner)
                })
                .collect();
            if found.len() != 1 {
                return Err("original fixture input use caller multiplicity mismatch".into());
            }
            let (call_index, call) = found[0];
            let polls = call["polls"].as_array().unwrap();
            if uses.len() != polls.len() {
                return Err("original fixture input use multiplicity mismatch".into());
            }
            for (usage, poll) in uses.iter().zip(polls) {
                fields(
                    usage,
                    &["order", "at_ns", "history_cursor", "call", "attempt", "ok"],
                )?;
                let cursor = ctx.at(usage, Some(&use_owner), want["use_root"].as_u64())?;
                let at = number(&usage["at_ns"])?;
                let order = number(&usage["order"])?;
                let attempt = number(&usage["attempt"])?;
                if usage["ok"] != true
                    || usage["call"] != call_index + 1
                    || !usage["call"].is_u64()
                    || usage["attempt"] != poll["attempt"]
                    || order <= last_order
                    || at < last_time
                    || at < poll["start_ns"].as_u64().unwrap()
                    || at > poll["end_ns"].as_u64().unwrap()
                    || usage["history_cursor"] != poll["start_cursor"]
                    || ctx.pages[cursor].get("tracer").copied() != capture["page"].as_u64()
                    || !ctx.workers[cursor].contains_key(&capture["page"].as_u64().unwrap())
                    || (ctx.workers[cursor]
                        .get(&capture["page"].as_u64().unwrap())
                        .copied()
                        == capture["worker"].as_u64())
                        == (want["successor_worker"] == true)
                {
                    return Err("original fixture input use/operand/lifetime mismatch".into());
                }
                let predicate = &call["causal_matches"][attempt as usize - 1];
                if predicate["at_ns"].as_u64().is_none_or(|end| end < at) {
                    return Err("fixture input after original predicate".into());
                }
                let operand = &predicate["operands"];
                let bound = match name {
                    "relay" | "packet" => Some(&operand["from"]),
                    "execs" | "probes" => Some(&operand["baseline"]),
                    _ => None,
                };
                if bound.is_some_and(|bound| bound != value) {
                    return Err("original fixture captured operand substitution".into());
                }
                stamps.push(usage);
                last_order = order;
                last_time = at;
            }
            if name == "execs" {
                let occurrence = want["value"]["occurrence"].as_u64().unwrap();
                let producers: Vec<_> = calls
                    .iter()
                    .filter(|c| {
                        c["kind"] == "job.wait_launch"
                            && c["causal_input"][0]["source_job"] == "inference.sent_read"
                            && c["causal_input"][0]["occurrence"] == occurrence
                    })
                    .collect();
                if producers.len() != 1
                    || producers[0]["end_ns"].as_u64().unwrap() > number(&capture["at_ns"])?
                {
                    return Err("sent-read capture without original job producer".into());
                }
            }
        } else if !uses.is_empty() {
            return Err("inactive original fixture operand was used".into());
        }
        let retired = &source["retired"];
        fields(retired, &["order", "at_ns", "history_cursor"])?;
        let cursor = ctx.at(retired, None, None)?;
        let retired_owner = ctx.states[cursor].owner.as_ref();
        if number(&retired["order"])? <= last_order
            || number(&retired["at_ns"])? < last_time
            || retired_owner != Some(&owner("inside")) && retired_owner != Some(&owner("after"))
        {
            return Err("original fixture input retirement outside source lifetime".into());
        }
        stamps.push(retired);
        last_retired.insert(name.into(), number(&retired["order"])?);
    }
    events.sort_by_key(|e| e.0);
    let expected_events: Vec<_> = program
        .iter()
        .flat_map(|p| {
            p["events"].as_array().unwrap().iter().map(|event| {
                format!(
                    "{}:{}",
                    p["case"].as_str().unwrap(),
                    event.as_str().unwrap()
                )
            })
        })
        .collect();
    if events.iter().map(|e| &e.1).ne(expected_events.iter()) {
        return Err("original fixture source capture/trigger event order mismatch".into());
    }
    stamps.sort_by_key(|s| s["order"].as_u64().unwrap());
    let mut previous = 0;
    for (index, stamp) in stamps.iter().enumerate() {
        let at = number(&stamp["at_ns"])?;
        if number(&stamp["order"])? != index as u64 + 1 || at < previous {
            return Err("original fixture input event multiplicity/monotonicity mismatch".into());
        }
        previous = at;
    }
    Ok(())
}

const LOCK_TRANSITION: &str = "(() => {
                    const $ = (id) => document.getElementById('tau-'+id);
                    $('passphrase').value = 'typed, never submitted';
                    $('confirm').value = 'typed, never submitted';
                    $('lock').click();
                    return [$('passphrase').value, $('confirm').value];
                })()";
