//! Private source operands for the original causal job observations.
use super::*;
use std::sync::Mutex;

static UNMATCHED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
struct JobSource {
    source_job: &'static str,
    occurrence: usize,
    previous: u64,
    worker: Worker,
    request: Value,
    expression: Option<String>,
    capture: Value,
    trigger: Option<Value>,
    origin: &'static str,
    used: bool,
    produced: Option<(String, Value)>,
    productions: usize,
    raw_call: Option<u64>,
}
static USE_CALLS: Mutex<Vec<usize>> = Mutex::new(Vec::new());
pub fn original_call(site: &str, occurrence: usize) -> Option<u64> {
    JOBS.lock()
        .unwrap()
        .iter()
        .rev()
        .find(|j| j.source_job == site && j.occurrence == occurrence && j.productions == 1)
        .and_then(|j| j.raw_call)
}
pub fn use_calls() -> Value {
    json!(*USE_CALLS.lock().unwrap())
}
static JOBS: Mutex<Vec<JobSource>> = Mutex::new(Vec::new());

fn receiver(worker: &Worker) -> Value {
    let (identity, page) = history::worker_identity(&worker.session);
    json!({"worker":identity,"page":page,"worker_ok":observer::source_worker_matches(worker),"at_ns":completion::now(),"history_cursor":history::cursor()})
}

pub async fn job_baseline(
    source: (&'static str, usize, &'static str, &'static str),
    run: &Run<'_>,
    worker: &Worker,
    request: &Value,
) -> Result<(usize, Value), String> {
    let (source_job, occurrence, origin, dispatch) = source;
    let mut capture = receiver(worker);
    let state = run.inspect(worker).await?;
    capture["end_ns"] = json!(completion::now());
    capture["end_cursor"] = json!(history::cursor());
    let previous = if origin == "command" {
        state["commands"]
            .as_array()
            .and_then(|c| c.last())
            .and_then(|c| c["number"].as_u64())
            .unwrap_or(0)
    } else {
        state["calls"]
            .as_array()
            .and_then(|c| c.last())
            .and_then(|c| c["call"].as_u64())
            .unwrap_or(0)
    };
    let expression = match dispatch {
        "mismatch" => Some(format!(
            "self.__jobResult = {}; void 0",
            run_expression(request)
        )),
        "together" => Some(format!(
            "self.__together = Promise.all([{},{}]); void 0",
            run_expression(request),
            run_expression(request)
        )),
        "own" => Some(format!("self.__own = {}; void 0", run_expression(request))),
        _ => None,
    };
    let mut jobs = JOBS.lock().unwrap();
    let id = jobs.len();
    jobs.push(JobSource {
        source_job,
        occurrence,
        previous,
        worker: worker.clone(),
        request: request.clone(),
        expression,
        capture,
        trigger: None,
        origin,
        used: false,
        produced: None,
        productions: 0,
        raw_call: None,
    });
    Ok((id, state))
}

pub fn job_zero(source_job: &'static str, worker: &Worker, expression: &str) -> usize {
    let mut jobs = JOBS.lock().unwrap();
    let id = jobs.len();
    let mut capture = receiver(worker);
    capture["end_ns"] = capture["at_ns"].clone();
    capture["end_cursor"] = capture["history_cursor"].clone();
    jobs.push(JobSource {
        source_job,
        occurrence: 0,
        previous: 0,
        worker: worker.clone(),
        request: Value::Null,
        expression: Some(format!("self.sessionResult={expression};void 0")),
        capture,
        trigger: None,
        origin: "zero",
        used: false,
        produced: None,
        productions: 0,
        raw_call: None,
    });
    id
}

fn trigger(id: usize, worker: &Worker, request: Option<&Value>, expression: Option<&str>) {
    let mut jobs = JOBS.lock().unwrap();
    let source = &mut jobs[id];
    let mut evidence = receiver(worker);
    evidence["input_ok"] = json!(
        source.worker == *worker
            && match (request, expression) {
                (Some(request), None) => source.expression.is_none() && source.request == *request,
                (None, Some(expression)) => source.expression.as_deref() == Some(expression),
                _ => false,
            }
    );
    // Preserve duplicate dispatches as an invalid input rather than silently replacing one.
    if source.trigger.is_some() {
        evidence["input_ok"] = json!(false);
    }
    source.trigger = Some(evidence);
}

pub async fn job_start(
    id: usize,
    run: &Run<'_>,
    worker: &Worker,
    args: Value,
) -> Result<(), String> {
    trigger(id, worker, Some(&args), None);
    run.harness_start(worker, args).await
}
pub async fn job_page(
    id: usize,
    run: &Run<'_>,
    worker: &Worker,
    expression: &str,
) -> Result<Value, String> {
    trigger(id, worker, None, Some(expression));
    run.browser.evaluate(&worker.session, expression).await
}

pub fn launch_input(id: usize, worker: &Worker, previous: u64, call: usize) -> Value {
    USE_CALLS.lock().unwrap().push(call);
    let mut jobs = JOBS.lock().unwrap();
    let source = &mut jobs[id];
    let ok = !source.used && source.previous == previous && source.worker == *worker;
    source.used = true;
    json!({"source":id+1,"source_job":source.source_job,"occurrence":source.occurrence,"origin":source.origin,"capture":source.capture,"trigger":source.trigger,"input_ok":ok})
}
pub fn produced(
    id: usize,
    job: &str,
    call: usize,
    raw_call: u64,
    expected: (Option<u64>, Option<&str>),
) -> Value {
    let value = json!({"source":id+1,"call":call,"at_ns":completion::now(),"history_cursor":history::cursor(),"input_ok":expected.0==Some(raw_call)&&expected.1==Some(job)});
    let mut jobs = JOBS.lock().unwrap();
    jobs[id].productions += 1;
    if expected.0 == Some(raw_call) && expected.1 == Some(job) && jobs[id].productions == 1 {
        jobs[id].raw_call = Some(raw_call);
    }
    if jobs[id].produced.is_none() {
        jobs[id].produced = Some((job.into(), value.clone()));
    }
    value
}
pub fn end_input(source_job: &'static str, job: &str, call: usize) -> Value {
    USE_CALLS.lock().unwrap().push(call);
    let jobs = JOBS.lock().unwrap();
    let found = jobs
        .iter()
        .enumerate()
        .rev()
        .find(|(_, s)| s.source_job == source_job);
    match found {
        Some((id, source)) => {
            json!({"source":id+1,"source_job":source_job,"occurrence":source.occurrence,"origin":if source.origin=="holding" {"holding"} else {"launch"},"producer":source.produced.as_ref().map(|p|&p.1),"input_ok":source.produced.as_ref().is_some_and(|p|p.0==job),"capture":if source.origin=="holding" {source.capture.clone()} else {Value::Null},"trigger":if source.origin=="holding" {json!(source.trigger)} else {Value::Null}})
        }
        None => {
            json!({"source":0,"source_job":source_job,"occurrence":0,"origin":"missing","producer":null,"input_ok":false,"capture":null,"trigger":null})
        }
    }
}

pub async fn holding_run(run: &Run<'_>, worker: &Worker, args: Value) -> Result<Value, String> {
    let mut start = receiver(worker);
    start["input_ok"] = json!(
        args == json!({"machine":"fixture","relay":run.relay.url,"host":"127.0.0.1","port":run.sshd.port,"user":SSH_USER,"command":"printf origin-held-job"})
    );
    let result = run.harness_run("causal.rs#1", worker, args).await?;
    let mut jobs = JOBS.lock().unwrap();
    jobs.push(JobSource {
        source_job: "goal_admission.holding_job",
        occurrence: 0,
        previous: 0,
        worker: worker.clone(),
        request: Value::Null,
        expression: None,
        capture: Value::Null,
        trigger: Some(start),
        origin: "holding",
        used: false,
        produced: None,
        productions: 0,
        raw_call: None,
    });
    Ok(result)
}
pub async fn holding_inspect(run: &Run<'_>, worker: &Worker) -> Result<Value, String> {
    let mut capture = receiver(worker);
    let state = run.inspect(worker).await?;
    capture["end_ns"] = json!(completion::now());
    capture["end_cursor"] = json!(history::cursor());
    let job = state["calls"]
        .as_array()
        .and_then(|v| v.last())
        .and_then(|v| v["job"].as_str());
    let mut jobs = JOBS.lock().unwrap();
    let source_id = jobs.len();
    if let Some(source) = jobs.last_mut().filter(|s| s.origin == "holding" && !s.used) {
        source.capture = capture;
        source.used = true;
        if let Some(job) = job {
            source.productions += 1;
            source.produced = Some((
                job.into(),
                json!({"source":source_id,"call":null,"at_ns":completion::now(),"history_cursor":history::cursor(),"input_ok":true}),
            ));
        }
    } else {
        UNMATCHED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    Ok(state)
}
pub fn unbound_jobs() -> Value {
    json!(
        JOBS.lock()
            .unwrap()
            .iter()
            .filter(|s| !s.used
                || s.trigger.is_none()
                || s.produced.is_none()
                || s.productions != 1)
            .count()
            + UNMATCHED.load(std::sync::atomic::Ordering::Relaxed)
    )
}

struct Fixtures {
    seen: Observed,
    primary: (
        std::sync::Arc<std::sync::atomic::AtomicU32>,
        std::sync::Arc<std::sync::atomic::AtomicU32>,
    ),
    other: (
        std::sync::Arc<std::sync::atomic::AtomicU32>,
        std::sync::Arc<std::sync::atomic::AtomicU32>,
    ),
}
static FIXTURES: Mutex<Option<Fixtures>> = Mutex::new(None);
pub fn register(seen: &Observed, primary: &fixtures::Sshd, other: &fixtures::Sshd) {
    let mut original = FIXTURES.lock().unwrap();
    if original.is_some() {
        UNMATCHED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return;
    }
    *original = Some(Fixtures {
        seen: seen.clone(),
        primary: (primary.accepted.clone(), primary.ended.clone()),
        other: (other.accepted.clone(), other.ended.clone()),
    });
}
pub fn ssh_counter(
    sshd: &fixtures::Sshd,
    field: &str,
    counter: &std::sync::Arc<std::sync::atomic::AtomicU32>,
) -> (u32, Value) {
    let role = fixture_role(sshd);
    let receiver_ok = {
        let sources = FIXTURES.lock().unwrap();
        sources.as_ref().is_some_and(|s| {
            let pair = match role {
                "primary" => Some(&s.primary),
                "other" => Some(&s.other),
                _ => None,
            };
            pair.is_some_and(|p| {
                let expected = match field {
                    "accepted" => Some(&p.0),
                    "ended" => Some(&p.1),
                    _ => None,
                };
                expected.is_some_and(|expected| std::sync::Arc::ptr_eq(expected, counter))
            })
        })
    };
    let value = counter.load(std::sync::atomic::Ordering::SeqCst);
    let field_name = match field {
        "ended" => "ended",
        "accepted" => "accepted",
        _ => "unknown",
    };
    (
        value,
        json!({"field":field_name,"role":role,"receiver_ok":receiver_ok,"value":value,"at_ns":completion::now(),"history_cursor":history::cursor()}),
    )
}
pub fn fixture_role(sshd: &fixtures::Sshd) -> &'static str {
    let sources = FIXTURES.lock().unwrap();
    let Some(sources) = sources.as_ref() else {
        return "unknown";
    };
    let same = |source: &(
        std::sync::Arc<std::sync::atomic::AtomicU32>,
        std::sync::Arc<std::sync::atomic::AtomicU32>,
    )| {
        std::sync::Arc::ptr_eq(&source.0, &sshd.accepted)
            && std::sync::Arc::ptr_eq(&source.1, &sshd.ended)
    };
    if same(&sources.primary) {
        "primary"
    } else if same(&sources.other) {
        "other"
    } else {
        "unknown"
    }
}

pub fn previous_is(source: usize, previous: u64) -> bool {
    source
        .checked_sub(1)
        .and_then(|i| JOBS.lock().unwrap().get(i).map(|s| s.previous == previous))
        .unwrap_or(false)
}
pub fn job_is(source: usize, job: &str) -> bool {
    source
        .checked_sub(1)
        .and_then(|i| {
            JOBS.lock()
                .unwrap()
                .get(i)
                .map(|s| s.produced.as_ref().is_some_and(|p| p.0 == job))
        })
        .unwrap_or(false)
}

pub fn produced_job_is(source_job: &str, occurrence: usize, job: &str) -> bool {
    JOBS.lock().unwrap().iter().any(|source| {
        source.source_job == source_job
            && source.occurrence == occurrence
            && source.productions == 1
            && source
                .produced
                .as_ref()
                .is_some_and(|produced| produced.0 == job)
    })
}

pub fn source_seen(seen: &Observed) -> bool {
    FIXTURES
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|s| std::sync::Arc::ptr_eq(&s.seen, seen))
}
pub fn wait_domain(site: &str, seconds: u64, extra: Value) -> Value {
    let requires_ready = matches!(
        site,
        "session.network.stage_reached"
            | "session.rekey.stage_reached"
            | "inference.sent_read.exec"
            | "hold.evidence.actual_read"
    );
    let mut domain = json!({"seconds":seconds,"bound":seconds*20,"false_sleep_ms":50,"requires_ready":requires_ready});
    domain
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    domain
}
pub fn ended_domain(site: &str, sshd: &fixtures::Sshd, extra: Value) -> Value {
    let mut domain = json!({"fixture":fixture_role(sshd),"bound":600,"false_sleep_ms":50,"requires_ready":matches!(site,"session.reset.previous_ssh"|"job.drop.connection_end")});
    domain
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    domain
}
