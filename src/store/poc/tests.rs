use super::*;
use crate::poc::run::{self, Model, Observation, Runtime};
use crate::store::inference::tests::Fixed;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::task::{Context, Poll, Waker};

fn pass() -> LocalPassphrase {
    LocalPassphrase::new(b"inference fixture passphrase".to_vec())
}
fn ready() -> Store<MemoryStorage> {
    let mut s = ready_without_requirements();
    s.fixture_requirements("fixture");
    s
}
fn ready_without_requirements() -> Store<MemoryStorage> {
    let mut s = crate::store::inference::tests::ready();
    let session = s.sessions[0].identity.clone();
    block_on(s.enter_goal(&session, "install and run a small service".into(), None)).unwrap();
    block_on(s.accept_mode(&session, Mode::NoBrief)).unwrap();
    s
}
fn create_task(s: &mut Store<MemoryStorage>) -> Task {
    let session = s.sessions[0].identity.clone();
    block_on(s.poc_create(&session, vec!["systemctl is-active example.service".into()])).unwrap()
}
fn reopen(s: &Store<MemoryStorage>) -> Store<MemoryStorage> {
    block_on(unlock(
        MemoryStorage::with_files(s.storage.files()),
        &Fixed,
        pass(),
    ))
    .unwrap()
}
fn fresh(s: &mut Store<MemoryStorage>) -> String {
    block_on(s.bind("fixture")).unwrap();
    let session = s.sessions.last().unwrap().identity.clone();
    s.synthetic_confirm_limits(100).unwrap();
    block_on(s.accept_mode(&session, Mode::NoBrief)).unwrap();
    session
}
fn exec(command: &str) -> Tool {
    Tool::Exec {
        machine: "fixture".into(),
        command: command.into(),
    }
}
fn done() -> Tool {
    Tool::Done {
        machine: "fixture".into(),
    }
}
fn change(s: &mut Store<MemoryStorage>, task: &Task, c: Change) -> Task {
    block_on(s.poc_change(&task.id, task.revision, c)).unwrap()
}
fn proposal(s: &mut Store<MemoryStorage>, task: &Task) -> Task {
    let task = change(s, task, Change::Request);
    change(
        s,
        &task,
        Change::Propose {
            call_id: "install".into(),
            tool: exec("install-example-service"),
        },
    )
}
fn binding(task: &Task, session: &str) -> Binding {
    Binding {
        task: task.id.clone(),
        revision: task.revision,
        session: session.into(),
    }
}
fn entry(task: &Task, session: &str) -> Entry {
    let Tool::Exec { machine, command } = &task.proposal.as_ref().unwrap().tool else {
        panic!("command expected")
    };
    Entry {
        machine: machine.clone(),
        command: command.as_bytes().to_vec(),
        provenance: Some(crate::dispatch::CommandProvenance {
            target: crate::dispatch::Target::Entry(machine.clone()),
            session: Some(session.into()),
            requester: crate::dispatch::Requester::Session,
        }),
    }
}
fn approval() -> Approval {
    Approval::HarnessPin {
        machine: "fixture".into(),
        fingerprint: "SHA256:fixture".into(),
    }
}
fn append(s: &mut Store<MemoryStorage>, task: &Task, session: &str) -> u64 {
    block_on(s.poc_append(&binding(task, session), &entry(task, session), &approval())).unwrap()
}
fn record(task: &Task, exit: Option<u32>, output: &str) -> crate::jobs::Record {
    let Tool::Exec { command, .. } = &task.proposal.as_ref().unwrap().tool else {
        panic!("command expected")
    };
    crate::jobs::Record::Present {
        machine: hex::encode(&task.machine),
        command: hex::encode(command),
        boot: "boot-one".into(),
        current_boot: "boot-one".into(),
        pid: 123,
        alive: exit.is_none(),
        exit_status: exit,
        stdout: hex::encode(output),
        stderr: String::new(),
    }
}
fn evidence(s: &mut Store<MemoryStorage>, task: &Task, record: crate::jobs::Record) {
    let pending = task.pending.as_ref().unwrap();
    block_on(s.job_evidence(&crate::jobs::Evidence {
        call: pending.call,
        job: pending.job.clone(),
        record,
    }))
    .unwrap();
}

#[derive(Default)]
struct Script {
    calls: VecDeque<Result<(String, Tool), String>>,
    seen: Vec<Vec<Step>>,
    hold: bool,
    release: Option<Rc<Cell<bool>>>,
}
impl Script {
    fn one(id: &str, tool: Tool) -> Self {
        Self {
            calls: VecDeque::from([Ok((id.into(), tool))]),
            ..Default::default()
        }
    }
}
impl Model for Script {
    async fn next(
        &mut self,
        goal: &str,
        machine: &str,
        completed: &[Step],
    ) -> Result<(String, Tool), String> {
        assert_eq!(goal, "install and run a small service");
        assert_eq!(machine, "fixture");
        self.seen.push(completed.to_vec());
        if self.hold {
            if let Some(release) = &self.release {
                std::future::poll_fn(|_| {
                    if release.get() {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            } else {
                std::future::pending::<()>().await;
            }
        }
        self.calls
            .pop_front()
            .unwrap_or(Err("fixture has no further call".into()))
    }
}
#[derive(Default)]
struct Remote {
    sends: BTreeMap<String, u32>,
    records: BTreeMap<String, crate::jobs::Record>,
    reads: Vec<String>,
}
#[derive(Clone, Copy)]
enum Window {
    Normal,
    BeforeSend,
    AfterSend,
    AfterEvidence,
}
#[derive(Clone)]
struct Fixture {
    store: Rc<RefCell<Store<MemoryStorage>>>,
    remote: Rc<RefCell<Remote>>,
    window: Window,
    exit: u32,
    hold_observe: bool,
    observe_error: bool,
    collection_reports: Option<Vec<Value>>,
    observe_release: Option<Rc<Cell<bool>>>,
    live: Rc<Cell<bool>>,
    authority_error: Option<String>,
    continuation: Option<crate::lifecycle::Continuation>,
    reports: Rc<RefCell<Vec<Value>>>,
    publish_release: Option<Rc<Cell<bool>>>,
    execute_release: Option<Rc<Cell<bool>>>,
}
impl Fixture {
    fn new() -> (Self, Task, String) {
        let mut store = ready();
        let session = store.sessions[0].identity.clone();
        let task = create_task(&mut store);
        (
            Self {
                store: Rc::new(RefCell::new(store)),
                remote: Rc::new(RefCell::new(Remote::default())),
                window: Window::Normal,
                exit: 0,
                hold_observe: false,
                observe_error: false,
                collection_reports: None,
                observe_release: None,
                live: Rc::new(Cell::new(true)),
                authority_error: None,
                continuation: None,
                reports: Rc::default(),
                publish_release: None,
                execute_release: None,
            },
            task,
            session,
        )
    }
    fn reload(&mut self) -> String {
        let mut store = reopen(&self.store.borrow());
        let session = fresh(&mut store);
        *self.store.borrow_mut() = store;
        self.window = Window::Normal;
        session
    }
    fn task(&self, id: &str) -> Task {
        self.store.borrow().poc_task(id).unwrap()
    }
}
impl Runtime for Fixture {
    async fn progress(&mut self, task: &Task) {
        let pending = {
            // Publication must reacquire the writer, after the commit released it.
            let store = self
                .store
                .try_borrow_mut()
                .expect("publication writer released");
            let current = store.poc_task(&task.id).unwrap();
            let report = store.protect_output(&json!({"tasks":[current]})).unwrap();
            let pending = !report["tasks"][0]["pending"].is_null();
            self.reports.borrow_mut().push(report);
            pending
        };
        if pending && let Some(release) = &self.publish_release {
            wait_release(release).await;
        }
    }
    async fn load(&mut self, id: &str) -> Result<Task, String> {
        self.store.borrow().poc_task(id)
    }
    async fn authority(&mut self, id: &str, session: &str) -> Result<(), String> {
        if let Some(continuation) = &self.continuation {
            continuation.check()?;
        }
        if let Some(why) = &self.authority_error {
            return Err(why.clone());
        }
        if !self.live.get() {
            return Err("fixture authority lost".into());
        }
        self.store.borrow().poc_authority(id, session).map(|_| ())
    }
    async fn change(&mut self, task: &Task, c: Change) -> Result<Task, String> {
        // All memory-storage futures complete in one poll; no borrow survives suspension.
        block_on(
            self.store
                .borrow_mut()
                .poc_change(&task.id, task.revision, c),
        )
    }
    async fn propose(
        &mut self,
        task: &Task,
        session: &str,
        call_id: String,
        tool: Tool,
    ) -> Result<Task, String> {
        let mut store = self.store.borrow_mut();
        block_on(store.poc_propose(task, session, call_id, tool))
    }

    async fn execute(&mut self, binding: Binding, task: &Task) -> Result<(), String> {
        self.store
            .borrow_mut()
            .poc_prepare_execution(task, &binding.session)?;
        let store = self.store.clone();
        let call = run::commit_command(
            async {
                block_on(store.borrow_mut().poc_append(
                    &binding,
                    &entry(task, &binding.session),
                    &approval(),
                ))
            },
            self.progress(task),
        )
        .await
        .map_err(|e| e.to_string())?;
        if matches!(self.window, Window::BeforeSend) {
            std::future::pending::<()>().await;
        }
        self.authority(&task.id, &binding.session).await?;
        self.store.borrow().poc_binding_current(&binding)?;
        let pending = self.task(&task.id);
        assert_eq!(pending.pending.as_ref().unwrap().call, call);
        let job = pending.pending.as_ref().unwrap().job.clone();
        let record = record(&pending, Some(self.exit), "service active");
        {
            let mut remote = self.remote.borrow_mut();
            *remote.sends.entry(job.clone()).or_default() += 1;
            remote.records.insert(job, record.clone());
        }
        if matches!(self.window, Window::AfterSend) {
            std::future::pending::<()>().await;
        }
        if let Some(release) = &self.execute_release {
            wait_release(release).await;
        }
        evidence(&mut self.store.borrow_mut(), &pending, record);
        if matches!(self.window, Window::AfterEvidence) {
            std::future::pending::<()>().await;
        }
        Ok(())
    }
    async fn observe(&mut self, task: &Task, _: &str) -> Result<Observation, String> {
        if let Some(release) = &self.observe_release {
            std::future::poll_fn(|_| {
                if release.get() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
        if self.observe_error {
            return Err("record read failed; pending identity retained".into());
        }
        if self.hold_observe {
            std::future::pending::<()>().await;
        }
        let pending = task.pending.as_ref().unwrap();
        {
            let store = self.store.borrow();
            if let Some(r) = store.poc_committed(pending)
                && r.state == crate::jobs::State::Finished
                && matches!(r.comparison, crate::jobs::Comparison::AdvisoryMatch)
            {
                return Ok(Observation::Committed);
            }
        }
        if let Some(reports) = &self.collection_reports {
            return Ok(Observation::Unknown(
                self.store.borrow().poc_collection_reason(pending, reports),
            ));
        }
        let record = {
            let mut remote = self.remote.borrow_mut();
            remote.reads.push(pending.job.clone());
            remote
                .records
                .get(&pending.job)
                .cloned()
                .unwrap_or(crate::jobs::Record::Missing)
        };
        if record.classify(&task.machine) == crate::jobs::State::Running {
            return Ok(Observation::Running);
        }
        // A previous mismatched terminal cannot be silently replaced by another observation.
        if self
            .store
            .borrow()
            .poc_committed(pending)
            .is_some_and(|r| r.state == crate::jobs::State::Finished)
        {
            return Ok(Observation::Unknown(
                "record mismatch; inspect pending job".into(),
            ));
        }
        evidence(&mut self.store.borrow_mut(), task, record);
        let store = self.store.borrow();
        let r = store.poc_committed(pending).unwrap();
        Ok(
            if r.state == crate::jobs::State::Finished
                && matches!(r.comparison, crate::jobs::Comparison::AdvisoryMatch)
            {
                Observation::Committed
            } else {
                Observation::Unknown(
                    store.poc_collection_reason(pending, &[serde_json::to_value(r).unwrap()]),
                )
            },
        )
    }
}

#[test]
fn poc_task_replay_old_journal_and_atomic_failed_append() {
    let mut store = ready();
    let old = reopen(&store);
    assert!(old.poc.is_empty());
    let task = create_task(&mut store);
    assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), task);
    let session = store.sessions[0].identity.clone();
    assert_eq!(
        block_on(store.poc_create(&session, task.checks.clone())).unwrap(),
        task
    );
    let proposed = proposal(&mut store, &task);
    let files = store.storage.files();
    for fault in [
        Fault::Fail(1),
        Fault::Fail(2),
        Fault::Fail(3),
        Fault::LandThenFail(3),
    ] {
        let mut s = reopen(&store);
        let session = fresh(&mut s);
        s.storage.fault(fault);
        let published = Cell::new(false);
        assert!(
            block_on(run::commit_command(
                s.poc_append(
                    &binding(&proposed, &session),
                    &entry(&proposed, &session),
                    &approval(),
                ),
                async {
                    published.set(true);
                },
            ))
            .is_err()
        );
        assert!(
            !published.get(),
            "a failed commit never publishes pending progress"
        );
        assert_eq!(
            s.poc_task(&task.id).unwrap(),
            proposed,
            "failed append never applies"
        );
        assert!(s.dispatch.calls.is_empty());
        assert!(
            block_on(s.poc_append(
                &binding(&proposed, &session),
                &entry(&proposed, &session),
                &approval()
            ))
            .is_err(),
            "poisoned store cannot authorize a send"
        );
        let replay = reopen(&s);
        if matches!(fault, Fault::LandThenFail(_)) {
            assert!(replay.poc_task(&task.id).unwrap().pending.is_some());
        } else {
            assert_eq!(replay.poc_task(&task.id).unwrap(), proposed);
        }
    }
    assert_eq!(store.storage.files(), files);
}

#[test]
fn poc_three_crash_windows_collect_original_job_and_committed_evidence() {
    for window in [Window::BeforeSend, Window::AfterSend, Window::AfterEvidence] {
        let (mut f, task, session) = Fixture::new();
        f.window = window;
        let mut model = Script::one("install", exec("install-example-service"));
        {
            let mut run = std::pin::pin!(run::resume(&mut f, &mut model, &task.id, &session));
            assert!(matches!(
                run.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            ));
        }
        let pending = f.task(&task.id);
        let job = pending.pending.as_ref().unwrap().job.clone();
        assert_eq!(pending.proposal.as_ref().unwrap().call_id, "install");
        let session = f.reload();
        let observed = block_on(run::resume(
            &mut f,
            &mut Script::default(),
            &task.id,
            &session,
        ))
        .unwrap();
        if matches!(window, Window::BeforeSend) {
            assert_eq!(observed.status, Status::Paused);
            assert!(observed.pending.is_some());
            assert!(f.remote.borrow().sends.is_empty());
        } else {
            assert_eq!(observed.completed.len(), 1);
            assert!(observed.pending.is_none());
            assert_eq!(f.remote.borrow().sends[&job], 1);
        }
        for _ in 0..2 {
            block_on(run::resume(
                &mut f,
                &mut Script::default(),
                &task.id,
                &session,
            ))
            .unwrap();
        }
        assert_eq!(
            f.task(&task.id).completed.len(),
            usize::from(!matches!(window, Window::BeforeSend))
        );
        assert!(f.remote.borrow().sends.values().all(|n| *n == 1));
        if matches!(window, Window::AfterEvidence) {
            assert!(
                f.remote.borrow().reads.is_empty(),
                "settle terminal even when unresolved collector is empty"
            );
        }
    }
}

#[test]
fn poc_observes_running_missing_ended_mismatch_and_failed_reads_without_resend() {
    for case in 0..5 {
        let (mut f, task, session) = Fixture::new();
        let proposed = proposal(&mut f.store.borrow_mut(), &task);
        append(&mut f.store.borrow_mut(), &proposed, &session);
        let pending = f.task(&task.id);
        let job = pending.pending.as_ref().unwrap().job.clone();
        f.remote.borrow_mut().sends.insert(job.clone(), 1);
        let mut r = record(&pending, if case == 3 { Some(0) } else { None }, "active");
        if let crate::jobs::Record::Present { alive, command, .. } = &mut r {
            if case == 2 {
                *alive = false;
            }
            if case == 3 {
                *command = hex::encode("different-command");
            }
        }
        if case != 1 {
            f.remote.borrow_mut().records.insert(job.clone(), r);
        }
        if case == 5 {
            f.observe_error = true;
        }
        if case == 4 {
            // An incomplete read yields no trustworthy record at all.
            f.remote.borrow_mut().records.insert(
                job.clone(),
                crate::jobs::Record::Incomplete {
                    machine: None,
                    command: None,
                },
            );
        }
        let session = f.reload();
        for _ in 0..3 {
            let observed = block_on(run::resume(
                &mut f,
                &mut Script::default(),
                &task.id,
                &session,
            ))
            .unwrap();
            assert_eq!(
                observed.status,
                if case == 0 {
                    Status::Waiting
                } else {
                    Status::Paused
                }
            );
            assert_eq!(observed.pending, pending.pending);
            assert!(observed.completed.is_empty());
            assert!(observed.pause_reason.is_some());
            assert_eq!(f.remote.borrow().sends[&job], 1);
        }
    }
}

#[test]
fn poc_done_verifies_with_tracked_jobs_and_never_completes_on_failed_or_empty_checks() {
    for exit in [0, 7] {
        let (mut f, task, session) = Fixture::new();
        f.exit = exit;
        let done = block_on(run::resume(
            &mut f,
            &mut Script::one("done", done()),
            &task.id,
            &session,
        ))
        .unwrap();
        assert_eq!(done.status, Status::Verifying);
        assert!(done.verification.is_empty());
        assert!(f.remote.borrow().sends.is_empty());
        let verified = block_on(run::resume(
            &mut f,
            &mut Script::default(),
            &task.id,
            &session,
        ))
        .unwrap();
        assert_eq!(verified.verification.len(), 1);
        assert_eq!(verified.verification[0].exit_status, Some(exit));
        assert_eq!(
            verified.verification[0].command,
            "systemctl is-active example.service"
        );
        assert_ne!(verified.status, Status::Complete);
        let session = f.reload();
        for _ in 0..3 {
            let result = block_on(run::resume(
                &mut f,
                &mut Script::default(),
                &task.id,
                &session,
            ))
            .unwrap();
            assert_eq!(
                result.status,
                if exit == 0 {
                    Status::Complete
                } else {
                    Status::Paused
                }
            );
            assert_eq!(result.verification.len(), 1);
            assert_eq!(result.completed.len(), 2);
        }
        assert_eq!(f.remote.borrow().sends.len(), 1);
        assert!(f.remote.borrow().sends.values().all(|v| *v == 1));
    }
    let mut s = ready();
    let session = s.sessions[0].identity.clone();
    let task = block_on(s.poc_create(&session, vec![])).unwrap();
    let task = change(&mut s, &task, Change::Request);
    let task = change(
        &mut s,
        &task,
        Change::Propose {
            call_id: "done".into(),
            tool: done(),
        },
    );
    let task = change(&mut s, &task, Change::PrepareCheck);
    assert_eq!(task.status, Status::Paused);
    assert!(
        task.pause_reason
            .unwrap()
            .contains("no verification checks")
    );
}

#[test]
fn poc_verification_survives_all_crash_windows() {
    for window in [Window::BeforeSend, Window::AfterSend, Window::AfterEvidence] {
        let (mut f, task, session) = Fixture::new();
        block_on(run::resume(
            &mut f,
            &mut Script::one("done", done()),
            &task.id,
            &session,
        ))
        .unwrap();
        f.window = window;
        {
            let mut model = Script::default();
            let mut run = std::pin::pin!(run::resume(&mut f, &mut model, &task.id, &session));
            assert!(
                run.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        }
        let pending = f.task(&task.id);
        assert_eq!(pending.verification.len(), 1);
        assert_eq!(pending.verification[0].exit_status, None);
        let session = f.reload();
        for _ in 0..3 {
            block_on(run::resume(
                &mut f,
                &mut Script::default(),
                &task.id,
                &session,
            ))
            .unwrap();
        }
        let result = f.task(&task.id);
        assert_eq!(result.verification.len(), 1);
        if matches!(window, Window::BeforeSend) {
            assert_eq!(result.status, Status::Paused);
            assert!(result.pending.is_some());
            assert!(f.remote.borrow().sends.is_empty());
        } else {
            assert_eq!(result.status, Status::Complete);
        }
        assert!(f.remote.borrow().sends.values().all(|v| *v == 1));
    }
}

#[test]
fn poc_rebuilt_transcript_unique_calls_and_unavailable_tools_are_bounded() {
    let (mut f, task, session) = Fixture::new();
    let tools = [
        Tool::Job {
            machine: "fixture".into(),
            job: crate::goals::Job::FetchArtifact,
            arguments: json!({}),
        },
        Tool::Typed {
            machine: "fixture".into(),
            operation: crate::dispatch::Operation::Read,
            arguments: Default::default(),
        },
        Tool::Exec {
            machine: "outside".into(),
            command: "unreachable".into(),
        },
    ];
    for (index, tool) in tools.into_iter().enumerate() {
        block_on(run::resume(
            &mut f,
            &mut Script::one(&format!("step-{index}"), tool),
            &task.id,
            &session,
        ))
        .unwrap();
    }
    assert_eq!(f.task(&task.id).steps, 3);
    assert_eq!(f.task(&task.id).completed.len(), 3);
    assert!(f.remote.borrow().sends.is_empty());
    let session = f.reload();
    let before = f.task(&task.id);
    let mut duplicate = Script::one("step-0", exec("do-not-send"));
    let result = block_on(run::resume(&mut f, &mut duplicate, &task.id, &session)).unwrap();
    assert_eq!(result.status, Status::Paused);
    assert_eq!(
        duplicate.seen.as_slice(),
        std::slice::from_ref(&before.completed)
    );
    assert_eq!(result.completed, before.completed);
    assert!(
        result
            .completed
            .iter()
            .all(|(_, _, v)| v["type"] == "untrusted")
    );
    assert!(f.remote.borrow().sends.is_empty());
    let malformed = Tool::Job {
        machine: "fixture".into(),
        job: crate::goals::Job::FetchArtifact,
        arguments: json!({"extra":"field"}),
    };
    let result = block_on(run::resume(
        &mut f,
        &mut Script::one("bad", malformed),
        &task.id,
        &session,
    ))
    .unwrap();
    assert_eq!(result.status, Status::Paused);
    assert_eq!(result.steps, 3);
    assert!(f.remote.borrow().sends.is_empty());
}

#[test]
fn poc_request_budget_is_spent_before_request_and_raise_preserves_pending() {
    let (mut f, task, session) = Fixture::new();
    let mut model = Script {
        hold: true,
        ..Default::default()
    };
    {
        let mut run = std::pin::pin!(run::resume(&mut f, &mut model, &task.id, &session));
        assert!(
            run.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    assert_eq!(f.task(&task.id).requests, 1);
    let session = f.reload();
    for _ in 1..10 {
        block_on(run::resume(
            &mut f,
            &mut Script::default(),
            &task.id,
            &session,
        ))
        .unwrap();
    }
    let mut unused = Script::one("install", exec("install-example-service"));
    let exhausted = block_on(run::resume(&mut f, &mut unused, &task.id, &session)).unwrap();
    assert_eq!(exhausted.requests, 10);
    assert!(
        exhausted
            .pause_reason
            .as_ref()
            .unwrap()
            .contains("request limit")
    );
    assert!(unused.seen.is_empty());
    let raised = change(
        &mut f.store.borrow_mut(),
        &exhausted,
        Change::Raise(Limits {
            requests: 11,
            steps: 20,
        }),
    );
    assert_eq!(raised.requests, 10);
    f.window = Window::BeforeSend;
    {
        let mut run = std::pin::pin!(run::resume(&mut f, &mut unused, &task.id, &session));
        assert!(
            run.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    let pending = f.task(&task.id);
    assert_eq!(pending.requests, 11);
    change(
        &mut f.store.borrow_mut(),
        &pending,
        Change::Raise(Limits {
            requests: 12,
            steps: 21,
        }),
    );
    let session = f.reload();
    block_on(run::resume(&mut f, &mut unused, &task.id, &session)).unwrap();
    assert!(f.remote.borrow().sends.is_empty());
    assert_eq!(f.task(&task.id).pending, pending.pending);
}

#[test]
fn poc_step_limit_counts_refusals_and_verification_without_off_by_one() {
    let (mut f, task, session) = Fixture::new();
    let unavailable = Tool::Job {
        machine: "fixture".into(),
        job: crate::goals::Job::FetchArtifact,
        arguments: json!({}),
    };
    // Each rejected/unavailable proposal consumes one step and one request.
    let mut current = task;
    for index in 0..10 {
        current = block_on(run::resume(
            &mut f,
            &mut Script::one(&format!("u{index}"), unavailable.clone()),
            &current.id,
            &session,
        ))
        .unwrap();
    }
    current = change(
        &mut f.store.borrow_mut(),
        &current,
        Change::Raise(Limits {
            requests: 30,
            steps: 20,
        }),
    );
    for index in 10..19 {
        current = block_on(run::resume(
            &mut f,
            &mut Script::one(&format!("u{index}"), unavailable.clone()),
            &current.id,
            &session,
        ))
        .unwrap();
    }
    current = block_on(run::resume(
        &mut f,
        &mut Script::one("done", done()),
        &current.id,
        &session,
    ))
    .unwrap();
    assert_eq!(current.steps, 20);
    current = block_on(run::resume(
        &mut f,
        &mut Script::default(),
        &current.id,
        &session,
    ))
    .unwrap();
    assert_eq!(current.status, Status::Paused);
    assert!(current.verification.is_empty());
    assert!(f.remote.borrow().sends.is_empty());
    current = change(
        &mut f.store.borrow_mut(),
        &current,
        Change::Raise(Limits {
            requests: 30,
            steps: 21,
        }),
    );
    current = block_on(run::resume(
        &mut f,
        &mut Script::default(),
        &current.id,
        &session,
    ))
    .unwrap();
    assert_eq!(current.steps, 21);
    current = block_on(run::resume(
        &mut f,
        &mut Script::default(),
        &current.id,
        &session,
    ))
    .unwrap();
    assert_eq!(current.status, Status::Complete);
    assert_eq!(
        current.requests, 20,
        "verification consumes no model request"
    );
}

#[test]
fn poc_atomic_binding_refuses_stale_identity_machine_command_and_ended_authority() {
    for case in 0..6 {
        let mut store = ready();
        let session = store.sessions[0].identity.clone();
        let task = create_task(&mut store);
        let task = proposal(&mut store, &task);
        let mut b = binding(&task, &session);
        let mut e = entry(&task, &session);
        match case {
            0 => e.command = b"changed".to_vec(),
            1 => e.machine = "fixture-other".into(),
            2 => e.provenance.as_mut().unwrap().session = Some("wrong".into()),
            3 => b.revision += 1,
            4 => b.task = "unknown-task".into(),
            _ => store.sessions[0].ended.set(true),
        }
        let files = store.storage.files();
        assert!(block_on(store.poc_append(&b, &e, &approval())).is_err());
        assert_eq!(store.storage.files(), files);
        assert!(store.dispatch.calls.is_empty());
    }
}

#[test]
fn poc_stale_requests_duplicate_resume_and_abandon_cannot_launch_or_checkpoint_twice() {
    let (mut f, task, session) = Fixture::new();
    let shared = f.store.clone();
    let mut slow = Script {
        hold: true,
        ..Default::default()
    };
    {
        let mut run = std::pin::pin!(run::resume(&mut f, &mut slow, &task.id, &session));
        assert!(
            run.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let current = shared.borrow().poc_task(&task.id).unwrap();
        let abandoned = change(&mut shared.borrow_mut(), &current, Change::Abandon);
        assert_eq!(abandoned.status, Status::Abandoned);
    }
    let result = block_on(run::resume(
        &mut f,
        &mut Script::one("install", exec("never")),
        &task.id,
        &session,
    ))
    .unwrap();
    assert_eq!(result.status, Status::Abandoned);
    assert!(f.remote.borrow().sends.is_empty());
    // Two action futures sharing one task revision can append at most one intent.
    let (mut f, task, session) = Fixture::new();
    let task = proposal(&mut f.store.borrow_mut(), &task);
    let b = binding(&task, &session);
    append(&mut f.store.borrow_mut(), &task, &session);
    assert!(
        block_on(
            f.store
                .borrow_mut()
                .poc_append(&b, &entry(&task, &session), &approval())
        )
        .is_err()
    );
    let pending = f.task(&task.id);
    f.hold_observe = true;
    let shared = f.store.clone();
    {
        let mut model = Script::default();
        let mut run = std::pin::pin!(run::resume(&mut f, &mut model, &task.id, &session));
        assert!(
            run.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let current = shared.borrow().poc_task(&task.id).unwrap();
        change(&mut shared.borrow_mut(), &current, Change::Abandon);
    }
    let store = f.store.borrow();
    assert_eq!(store.poc_task(&task.id).unwrap().pending, pending.pending);
    assert!(matches!(
        block_on(store.check("fixture")),
        Err(AppendRefusal::Policy(
            crate::dispatch::DispatchRefusal::Held(_)
        ))
    ));
    assert_eq!(
        block_on(store.collectable("fixture")).unwrap().len(),
        1,
        "Abandon does not clear holds or prohibit safe collection"
    );
}

#[test]
fn poc_credential_boundaries_cover_creation_commands_results_pauses_transcripts_and_reports() {
    let secret = "fixture-account-private-value";
    let mut s = ready();
    let session = s.sessions[0].identity.clone();
    let files = s.storage.files();
    assert!(block_on(s.poc_create(&session, vec![format!("echo {secret}")])).is_err());
    assert_eq!(s.storage.files(), files);
    let (mut f, task, session) = Fixture::new();
    let refused = block_on(run::resume(
        &mut f,
        &mut Script::one("unsafe", exec(secret)),
        &task.id,
        &session,
    ))
    .unwrap();
    assert_eq!(refused.status, Status::Paused);
    assert!(refused.completed.is_empty());
    assert!(f.remote.borrow().sends.is_empty());
    let paused = change(
        &mut f.store.borrow_mut(),
        &refused,
        Change::Pause(format!("read failed: {secret}")),
    );
    assert!(!paused.pause_reason.as_ref().unwrap().contains(secret));
    let proposed = proposal(&mut f.store.borrow_mut(), &paused);
    append(&mut f.store.borrow_mut(), &proposed, &session);
    let pending = f.task(&task.id);
    evidence(
        &mut f.store.borrow_mut(),
        &pending,
        record(&pending, Some(0), &format!("active {secret}")),
    );
    let settled = block_on(run::resume(
        &mut f,
        &mut Script::default(),
        &task.id,
        &session,
    ))
    .unwrap();
    assert!(!serde_json::to_string(&settled).unwrap().contains(secret));
    let mut store = reopen(&f.store.borrow());
    let session = fresh(&mut store);
    assert!(
        store.goal(&session).is_none(),
        "continuation grants no legacy goal import"
    );
    assert_eq!(store.poc_task(&task.id).unwrap(), settled);
    let mut local = Local::new(store.storage.clone(), Fixed);
    local.state = super::super::State::Unlocked(Box::new(store));
    assert!(!local.report(None).to_string().contains(secret));
    assert_eq!(local.report(None)["tasks"][0]["id"], task.id);
}

#[test]
fn poc_no_fresh_acceptance_or_lost_authority_sends_nothing() {
    let (mut f, task, session) = Fixture::new();
    f.store.borrow().sessions[0].ended.set(true);
    let result = block_on(run::resume(
        &mut f,
        &mut Script::one("install", exec("never")),
        &task.id,
        &session,
    ))
    .unwrap();
    assert_eq!(result.requests, 0);
    assert_eq!(result.status, Status::Paused);
    let mut store = reopen(&f.store.borrow());
    block_on(store.bind("fixture")).unwrap();
    let session = store.sessions.last().unwrap().identity.clone();
    store.synthetic_confirm_limits(100).unwrap();
    assert!(
        store.poc_authority(&task.id, &session).is_err(),
        "recorded old acceptance is not current acceptance"
    );
    block_on(store.bind("fixture-other")).unwrap();
    let other = store.sessions.last().unwrap().identity.clone();
    block_on(store.accept_mode(&other, Mode::NoBrief)).unwrap();
    assert!(store.poc_authority(&task.id, &other).is_err());
    assert!(f.remote.borrow().sends.is_empty());
}

#[test]
fn poc_missing_job_can_later_be_observed_without_replacement_intent() {
    let (mut f, task, session) = Fixture::new();
    let proposed = proposal(&mut f.store.borrow_mut(), &task);
    append(&mut f.store.borrow_mut(), &proposed, &session);
    let pending = f.task(&task.id);
    let paused = block_on(run::resume(
        &mut f,
        &mut Script::default(),
        &task.id,
        &session,
    ))
    .unwrap();
    assert_eq!(paused.status, Status::Paused);
    let job = pending.pending.as_ref().unwrap().job.clone();
    f.remote
        .borrow_mut()
        .records
        .insert(job.clone(), record(&pending, Some(0), "active"));
    let session = f.reload();
    let settled = block_on(run::resume(
        &mut f,
        &mut Script::default(),
        &task.id,
        &session,
    ))
    .unwrap();
    assert_eq!(settled.completed.len(), 1);
    assert!(settled.pending.is_none());
    assert_eq!(f.store.borrow().dispatch.calls.len(), 1);
    assert!(f.remote.borrow().sends.is_empty());
}

#[test]
fn poc_outstanding_request_cannot_revive_abandoned_or_ended_authority() {
    for abandon in [true, false] {
        let (mut f, task, session) = Fixture::new();
        let release = Rc::new(Cell::new(false));
        let shared = f.store.clone();
        let mut model = Script {
            hold: true,
            release: Some(release.clone()),
            ..Script::one("stale", exec("must-not-send"))
        };
        {
            let mut run = std::pin::pin!(run::resume(&mut f, &mut model, &task.id, &session));
            assert!(
                run.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            if abandon {
                let current = shared.borrow().poc_task(&task.id).unwrap();
                change(&mut shared.borrow_mut(), &current, Change::Abandon);
            } else {
                shared.borrow().sessions[0].ended.set(true);
            }
            release.set(true);
            let result = run.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            if abandon {
                assert!(matches!(result, Poll::Ready(Err(_))));
            } else {
                let Poll::Ready(Ok(task)) = result else {
                    panic!("lost authority must pause")
                };
                assert_eq!(task.status, Status::Paused);
            }
        }
        assert!(shared.borrow().dispatch.calls.is_empty());
        assert!(f.remote.borrow().sends.is_empty());
        assert!(f.task(&task.id).completed.is_empty());
    }
}

#[test]
fn poc_transition_failures_and_invalid_replay_cannot_apply_progress() {
    let mut s = ready();
    let task = create_task(&mut s);
    for fault in [
        Fault::Fail(1),
        Fault::Fail(2),
        Fault::Fail(3),
        Fault::LandThenFail(3),
    ] {
        let mut copy = reopen(&s);
        copy.storage.fault(fault);
        assert!(block_on(copy.poc_change(&task.id, task.revision, Change::Request)).is_err());
        assert_eq!(copy.poc_task(&task.id).unwrap().requests, 0);
        let replay = reopen(&copy);
        assert_eq!(
            replay.poc_task(&task.id).unwrap().requests,
            u32::from(matches!(fault, Fault::LandThenFail(_)))
        );
    }
    let record = Record::Change {
        id: task.id.clone(),
        expected: task.revision,
        change: Change::Propose {
            call_id: "no-request".into(),
            tool: done(),
        },
    };
    block_on(s.commit(&Event::Poc(record))).unwrap();
    let error = block_on(unlock(
        MemoryStorage::with_files(s.storage.files()),
        &Fixed,
        pass(),
    ))
    .err()
    .unwrap();
    assert!(error.contains("no current task request"));
}

#[test]
fn poc_two_resume_futures_consume_one_job_response_once() {
    let (mut first, task, session) = Fixture::new();
    let proposed = proposal(&mut first.store.borrow_mut(), &task);
    append(&mut first.store.borrow_mut(), &proposed, &session);
    let pending = first.task(&task.id);
    let job = pending.pending.as_ref().unwrap().job.clone();
    first.remote.borrow_mut().sends.insert(job.clone(), 1);
    first
        .remote
        .borrow_mut()
        .records
        .insert(job.clone(), record(&pending, Some(0), "active"));
    let release = Rc::new(Cell::new(false));
    first.observe_release = Some(release.clone());
    let mut second = first.clone();
    {
        let mut model1 = Script::default();
        let mut model2 = Script::default();
        let mut a = std::pin::pin!(run::resume(&mut first, &mut model1, &task.id, &session));
        let mut b = std::pin::pin!(run::resume(&mut second, &mut model2, &task.id, &session));
        assert!(
            a.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert!(
            b.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        release.set(true);
        assert!(matches!(
            a.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            b.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(_))
        ));
    }
    assert_eq!(first.task(&task.id).completed.len(), 1);
    assert_eq!(first.remote.borrow().sends[&job], 1);
    assert_eq!(first.store.borrow().dispatch.jobs.len(), 1);
}

#[test]
fn poc_goal_admission_refuses_credentials_before_the_shared_goal_record() {
    let mut store = crate::store::inference::tests::ready();
    let session = store.sessions[0].identity.clone();
    let before = store.storage.files();
    assert_eq!(
        block_on(store.enter_goal(&session, "fixture-account-private-value".into(), None)),
        Err("goal credential boundary".into())
    );
    assert_eq!(store.storage.files(), before);
    assert!(store.goal(&session).is_none());
}

#[test]
fn poc_untagged_intents_replay_unchanged_and_unconfigured_model_pauses() {
    let mut store = ready();
    let entry = Entry {
        machine: "fixture".into(),
        command: b"printf legacy-command".to_vec(),
        provenance: None,
    };
    block_on(store.append(&entry, &approval())).unwrap();
    let replay = reopen(&store);
    assert!(replay.poc.is_empty());
    assert_eq!(replay.dispatch.calls, store.dispatch.calls);
    assert_eq!(replay.commands, store.commands);
    let mut local = Local::new(replay.storage.clone(), Fixed);
    local.state = super::super::State::Unlocked(Box::new(replay));
    assert!(
        local.report(None).get("tasks").is_none(),
        "untagged stores retain the existing report shape"
    );
    let (mut fixture, task, session) = Fixture::new();
    let task = block_on(run::resume(
        &mut fixture,
        &mut run::Unconfigured,
        &task.id,
        &session,
    ))
    .unwrap();
    assert_eq!(task.status, Status::Paused);
    assert_eq!(
        task.pause_reason.as_deref(),
        Some("no inference endpoint configured")
    );
    assert!(fixture.remote.borrow().sends.is_empty());
}

#[test]
fn poc_freeze_then_revalidation_does_not_revive_an_old_response() {
    let (mut f, task, session) = Fixture::new();
    let authority = Rc::new(crate::lifecycle::Authority::default());
    f.continuation = Some(authority.continuation().unwrap());
    let release = Rc::new(Cell::new(false));
    let mut model = Script {
        hold: true,
        release: Some(release.clone()),
        ..Script::one("stale", exec("never"))
    };
    {
        let mut run = std::pin::pin!(run::resume(&mut f, &mut model, &task.id, &session));
        assert!(
            run.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        authority.suspend();
        authority.revalidated().unwrap();
        release.set(true);
        let Poll::Ready(Ok(task)) = run.as_mut().poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("stale continuation must pause")
        };
        assert_eq!(task.status, Status::Paused);
    }
    assert!(f.remote.borrow().sends.is_empty());
    assert!(f.store.borrow().dispatch.calls.is_empty());
}

#[test]
fn poc_drive_continues_unavailable_tools_and_executes_verification_serially() {
    let (mut f, task, session) = Fixture::new();
    let mut model = Script {
        calls: VecDeque::from([
            Ok((
                "unavailable".into(),
                Tool::Job {
                    machine: "fixture".into(),
                    job: crate::goals::Job::FetchArtifact,
                    arguments: json!({}),
                },
            )),
            Ok(("install".into(), exec("install-example-service"))),
            Ok(("done".into(), done())),
        ]),
        ..Default::default()
    };
    let complete = block_on(run::drive(&mut f, &mut model, &task.id, &session)).unwrap();
    assert_eq!(complete.status, Status::Complete);
    assert_eq!(complete.requests, 3);
    assert_eq!(complete.steps, 4);
    assert_eq!(complete.completed.len(), 4);
    assert_eq!(
        model.seen.iter().map(Vec::len).collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(f.remote.borrow().sends.len(), 2);
    assert!(f.remote.borrow().sends.values().all(|n| *n == 1));
    assert_eq!(complete.verification[0].exit_status, Some(0));
}

#[test]
fn poc_checkpoint_does_not_depend_on_transient_output_redaction() {
    let (mut f, task, session) = Fixture::new();
    let proposed = proposal(&mut f.store.borrow_mut(), &task);
    append(&mut f.store.borrow_mut(), &proposed, &session);
    let pending = f.task(&task.id);
    let output = "later-sensitive-output-value";
    evidence(
        &mut f.store.borrow_mut(),
        &pending,
        record(&pending, Some(0), output),
    );
    block_on(f.store.borrow_mut().synthetic_scan_fixture(
        "later-value".into(),
        Zeroizing::new(output.as_bytes().to_vec()),
    ))
    .unwrap();
    let paused = block_on(run::resume(
        &mut f,
        &mut Script::default(),
        &task.id,
        &session,
    ))
    .unwrap();
    assert_eq!(paused.status, Status::Paused);
    assert!(
        paused
            .pause_reason
            .as_ref()
            .unwrap()
            .contains("requires protection")
    );
    assert!(paused.completed.is_empty());
    assert_eq!(paused.pending, pending.pending);
    assert!(!serde_json::to_string(&paused).unwrap().contains(output));
    assert_eq!(
        reopen(&f.store.borrow()).poc_task(&task.id).unwrap(),
        paused,
        "replay reconstructs identical task bytes without transient scan objects"
    );
    assert!(f.remote.borrow().sends.is_empty());
}

async fn wait_release(release: &Cell<bool>) {
    std::future::poll_fn(|_| {
        if release.get() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

#[test]
fn poc_protected_progress_precedes_command_and_check_results_and_allows_abandon() {
    for verifying in [false, true] {
        for before_send in [false, true] {
            let (mut f, task, session) = Fixture::new();
            let release = Rc::new(Cell::new(false));
            if before_send {
                f.publish_release = Some(release.clone());
            } else {
                f.execute_release = Some(release.clone());
            }
            let mut control = f.clone();
            let mut model = if verifying {
                Script::one("done", done())
            } else {
                Script::one("install", exec("install-example-service"))
            };
            let abandoned;
            {
                let mut future = Box::pin(run::drive(&mut f, &mut model, &task.id, &session));
                assert!(
                    future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                let pending = control.task(&task.id);
                let reports = control.reports.borrow();
                assert_eq!(reports[0]["tasks"][0]["id"], task.id);
                assert!(
                    reports[0]["tasks"][0]["proposal"].is_null(),
                    "creation precedes proposal"
                );
                let proposal_at = reports
                    .iter()
                    .position(|r| !r["tasks"][0]["proposal"].is_null())
                    .unwrap();
                let pending_at = reports
                    .iter()
                    .position(|r| !r["tasks"][0]["pending"].is_null())
                    .unwrap();
                assert!(
                    proposal_at < pending_at,
                    "proposal is published before intent commit"
                );
                let shown = &reports[pending_at]["tasks"][0];
                assert_eq!(
                    shown["pending"],
                    serde_json::to_value(&pending.pending).unwrap()
                );
                assert_eq!(
                    shown["proposal"],
                    serde_json::to_value(&pending.proposal).unwrap()
                );
                assert!(
                    shown["completed"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|step| step[0] != shown["proposal"]["call_id"]),
                    "pending step has no outcome checkpoint"
                );
                assert!(
                    !reports
                        .iter()
                        .any(|r| r.to_string().contains("fixture-account-private-value"))
                );
                assert_eq!(pending.verifying, verifying);
                if verifying {
                    assert_eq!(shown["verification"][0]["command"], task.checks[0]);
                    assert!(shown["verification"][0]["exit_status"].is_null());
                }
                drop(reports);
                assert_eq!(
                    control.remote.borrow().sends.len(),
                    usize::from(!before_send)
                );
                let mut duplicate = Script::default();
                assert_eq!(
                    block_on(run::drive(&mut control, &mut duplicate, &task.id, &session)),
                    Err("task action already active; collection may be waiting for the recorded job; let it finish or interrupt the session before Resume".into())
                );
                abandoned = change(&mut control.store.borrow_mut(), &pending, Change::Abandon);
                release.set(true);
                let Poll::Ready(Ok(result)) = future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                else {
                    panic!("released execution must settle locally");
                };
                assert_eq!(result, abandoned);
            }
            let result = block_on(run::drive(
                &mut control,
                &mut Script::default(),
                &task.id,
                &session,
            ))
            .unwrap();
            assert_eq!(result, abandoned);
            assert_eq!(result.pending, abandoned.pending);
            assert_eq!(result.completed.len(), usize::from(verifying));
            assert!(result.verification.iter().all(|v| v.exit_status.is_none()));
            assert_eq!(
                control.remote.borrow().sends.len(),
                usize::from(!before_send)
            );
            assert!(control.remote.borrow().sends.values().all(|n| *n == 1));
            assert_eq!(
                reopen(&control.store.borrow()).poc_task(&task.id).unwrap(),
                abandoned
            );
        }
    }
}

#[test]
fn poc_raise_request_cannot_invalidate_an_active_model_execute_or_collection() {
    for phase in ["model", "execute", "collection"] {
        let (mut f, task, session) = Fixture::new();
        let mut model = Script::one("install", exec("install-example-service"));
        match phase {
            "model" => model.hold = true,
            "execute" => f.publish_release = Some(Rc::new(Cell::new(false))),
            "collection" => {
                let proposed = proposal(&mut f.store.borrow_mut(), &task);
                append(&mut f.store.borrow_mut(), &proposed, &session);
                f.hold_observe = true;
            }
            _ => unreachable!(),
        }
        let control = f.clone();
        let limits = Limits {
            requests: 12,
            steps: 25,
        };
        let pending;
        {
            let mut future = Box::pin(run::drive(&mut f, &mut model, &task.id, &session));
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            let current = control.task(&task.id);
            let files = control.store.borrow().storage.files();
            assert_eq!(
                block_on(
                    control
                        .store
                        .borrow_mut()
                        .poc_raise(&task.id, limits.clone())
                ),
                Err("task action already active; raise limits after it pauses or waits".into())
            );
            assert_eq!(control.task(&task.id), current);
            assert_eq!(control.store.borrow().storage.files(), files);
            if phase == "execute" {
                assert!(
                    control
                        .store
                        .borrow()
                        .poc_binding_current(&Binding {
                            task: task.id.clone(),
                            revision: current.revision - 1,
                            session: session.clone(),
                        })
                        .is_ok(),
                    "Raise leaves final pre-send revision intact"
                );
            }
            pending = current.pending;
        }
        let raised = block_on(
            control
                .store
                .borrow_mut()
                .poc_raise(&task.id, limits.clone()),
        )
        .unwrap();
        assert_eq!(raised.pending, pending, "raising never clears uncertainty");
        assert_eq!(raised.limits, limits);
        assert_eq!(
            reopen(&control.store.borrow()).poc_task(&task.id).unwrap(),
            raised
        );
        assert!(control.remote.borrow().sends.is_empty());
    }
}

#[test]
fn poc_authorize_ended_tasks_writes_no_goal_or_acceptance() {
    for complete in [false, true] {
        let (mut f, task, session) = Fixture::new();
        let ended = if complete {
            block_on(run::drive(
                &mut f,
                &mut Script::one("done", done()),
                &task.id,
                &session,
            ))
            .unwrap()
        } else {
            change(&mut f.store.borrow_mut(), &task, Change::Abandon)
        };
        assert!(ended.ended());
        let mut store = reopen(&f.store.borrow());
        block_on(store.bind("fixture")).unwrap();
        let fresh = store.sessions.last().unwrap().identity.clone();
        store.synthetic_confirm_limits(100).unwrap();
        let files = store.storage.files();
        let acceptances = store.conduct_acceptances.len();
        assert!(store.goal(&fresh).is_none());
        assert_eq!(
            block_on(store.poc_authorize(&task.id, &fresh)),
            Err("task ended".into())
        );
        assert!(store.goal(&fresh).is_none());
        assert_eq!(store.conduct_acceptances.len(), acceptances);
        assert_eq!(store.storage.files(), files);
        assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), ended);
    }
    let (f, task, _) = Fixture::new();
    let mut store = reopen(&f.store.borrow());
    block_on(store.bind("fixture")).unwrap();
    let fresh = store.sessions.last().unwrap().identity.clone();
    store.synthetic_confirm_limits(100).unwrap();
    block_on(store.poc_authorize(&task.id, &fresh)).unwrap();
    assert_eq!(store.goal(&fresh).unwrap().text, task.goal);
    assert!(store.poc_authority(&task.id, &fresh).is_ok());
    assert!(reopen(&store).goal(&fresh).is_some());
}

#[test]
fn poc_initial_page_outcome_keeps_protected_concrete_error_and_task_identity() {
    let mut store = ready();
    let task = create_task(&mut store);
    let mut local = Local::new(store.storage.clone(), Fixed);
    local.state = super::super::State::Unlocked(Box::new(store));
    let report = local.report(Some(
        "trusted host pin missing; fixture-account-private-value",
    ));
    let outcome = run::page_outcome(&task.id, &report);
    assert_eq!(outcome["task"], task.id);
    assert!(
        outcome["refused"]
            .as_str()
            .unwrap()
            .contains("trusted host pin missing")
    );
    assert!(
        !outcome
            .to_string()
            .contains("fixture-account-private-value")
    );
    assert_eq!(report["tasks"][0]["id"], task.id);
    assert!(
        run::page_outcome(&task.id, &local.report(None))
            .get("refused")
            .is_none()
    );
}

#[test]
fn poc_unavailable_and_wrong_machine_steps_need_no_installation_declaration() {
    let (mut f, _, _) = Fixture::new();
    let mut store = ready_without_requirements();
    let session = store.sessions[0].identity.clone();
    let task = create_task(&mut store);
    *f.store.borrow_mut() = store;
    let tools = [
        Tool::Job {
            machine: "fixture".into(),
            job: crate::goals::Job::FetchArtifact,
            arguments: json!({}),
        },
        Tool::Typed {
            machine: "fixture".into(),
            operation: crate::dispatch::Operation::Read,
            arguments: Default::default(),
        },
        Tool::Exec {
            machine: "outside".into(),
            command: "never-send".into(),
        },
    ];
    for (i, tool) in tools.into_iter().enumerate() {
        let step = block_on(run::resume(
            &mut f,
            &mut Script::one(&format!("call-{i}"), tool),
            &task.id,
            &session,
        ))
        .unwrap();
        assert_eq!(step.steps, i as u32 + 1);
        assert_eq!(step.completed.len(), i + 1);
        assert_eq!(step.status, Status::Running);
    }
    let current = f.task(&task.id);
    assert_eq!(
        current.completed[0].2["content"]["unavailable"],
        "operation unavailable in this task runner"
    );
    assert_eq!(
        current.completed[1].2["content"]["unavailable"],
        "operation unavailable in this task runner"
    );
    assert_eq!(current.completed[2].2["content"]["refused"], "bound set");
    assert!(
        f.store
            .borrow()
            .pending_requirements_view(&session)
            .is_null()
    );
    assert!(f.store.borrow().dispatch.calls.is_empty());
    assert!(f.remote.borrow().sends.is_empty());
    assert_eq!(
        reopen(&f.store.borrow()).poc_task(&task.id).unwrap(),
        current
    );
}

#[test]
fn poc_exec_and_check_propose_requirements_and_require_explicit_approval() {
    for verification in [false, true] {
        let (mut f, _, _) = Fixture::new();
        let mut store = ready_without_requirements();
        let session = store.sessions[0].identity.clone();
        let task = create_task(&mut store);
        *f.store.borrow_mut() = store;
        let mut model = Script::one(
            "next",
            if verification {
                done()
            } else {
                exec("install-example-service")
            },
        );
        if verification {
            block_on(run::resume(&mut f, &mut model, &task.id, &session)).unwrap();
        }
        let paused = block_on(run::resume(&mut f, &mut model, &task.id, &session)).unwrap();
        assert_eq!(paused.status, Status::Paused);
        assert!(
            paused
                .pause_reason
                .as_ref()
                .unwrap()
                .contains("installation facts: approved declaration missing")
        );
        assert!(paused.proposal.is_some());
        assert!(f.remote.borrow().sends.is_empty());
        let pending = f.store.borrow().pending_requirements_view(&session);
        assert_eq!(pending["proposal"]["machine"], "fixture");
        assert_eq!(pending["proposal"]["kind"], "declaration");
        let candidate = pending["candidate"].as_u64().unwrap();
        let still_pending = block_on(run::resume(
            &mut f,
            &mut Script::default(),
            &task.id,
            &session,
        ))
        .unwrap();
        assert!(
            still_pending
                .pause_reason
                .as_ref()
                .unwrap()
                .contains("proposal approval pending; review the open requirements card")
        );
        assert!(
            !still_pending
                .pause_reason
                .as_ref()
                .unwrap()
                .contains("fresh accepted")
        );
        assert_eq!(still_pending.steps, paused.steps);
        assert_eq!(still_pending.requests, paused.requests);
        assert_eq!(still_pending.proposal, paused.proposal);
        assert!(f.remote.borrow().sends.is_empty());
        assert_eq!(
            reopen(&f.store.borrow()).poc_task(&task.id).unwrap(),
            still_pending
        );
        // Rejection consumes no authority to send. Resume offers the same visible flow again.
        f.store
            .borrow_mut()
            .reject_requirements(&session, "fixture", candidate)
            .unwrap();
        let rejected = block_on(run::resume(
            &mut f,
            &mut Script::default(),
            &task.id,
            &session,
        ))
        .unwrap();
        assert!(rejected.pending.is_none());
        assert!(
            rejected
                .pause_reason
                .as_ref()
                .unwrap()
                .contains("approved declaration missing")
        );
        assert_eq!(
            (rejected.requests, rejected.steps),
            (paused.requests, paused.steps)
        );
        assert!(f.remote.borrow().sends.is_empty());
        let pending = f.store.borrow().pending_requirements_view(&session);
        block_on(f.store.borrow_mut().approve_requirements(
            &session,
            "fixture",
            pending["candidate"].as_u64().unwrap(),
        ))
        .unwrap();
        let finished = block_on(run::resume(
            &mut f,
            &mut Script::default(),
            &task.id,
            &session,
        ))
        .unwrap();
        assert!(finished.pending.is_none());
        assert_eq!(f.remote.borrow().sends.values().sum::<u32>(), 1);
        assert_eq!(finished.steps, if verification { 2 } else { 1 });
        assert_eq!(
            reopen(&f.store.borrow()).poc_task(&task.id).unwrap(),
            finished
        );
    }
}

#[test]
fn poc_requirements_approval_after_session_loss_cannot_send() {
    let mut store = ready_without_requirements();
    let session = store.sessions[0].identity.clone();
    let task = create_task(&mut store);
    let task = proposal(&mut store, &task);
    assert!(store.poc_prepare_execution(&task, &session).is_err());
    let pending = store.pending_requirements_view(&session);
    store.sessions[0].ended.set(true);
    assert!(
        block_on(store.approve_requirements(
            &session,
            "fixture",
            pending["candidate"].as_u64().unwrap()
        ))
        .is_err()
    );
    assert!(
        block_on(store.poc_append(
            &binding(&task, &session),
            &entry(&task, &session),
            &approval()
        ))
        .is_err()
    );
    assert!(store.dispatch.calls.is_empty());
}

#[test]
fn poc_inspection_checkpoint_replaces_authority_pause_before_held_collection() {
    for abandon in [false, true] {
        let (mut f, task, session) = Fixture::new();
        let proposed = proposal(&mut f.store.borrow_mut(), &task);
        append(&mut f.store.borrow_mut(), &proposed, &session);
        let pending = f.task(&task.id).pending.unwrap();
        f.live.set(false);
        let paused = block_on(run::resume(
            &mut f,
            &mut Script::default(),
            &task.id,
            &session,
        ))
        .unwrap();
        assert_eq!(paused.status, Status::Paused);
        let session = f.reload();
        f.live.set(true);
        let release = Rc::new(Cell::new(false));
        f.observe_release = Some(release.clone());
        let control = f.clone();
        {
            let mut model = Script::default();
            let mut future = Box::pin(run::drive(&mut f, &mut model, &task.id, &session));
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            let waiting = control.task(&task.id);
            assert_eq!(waiting.status, Status::Waiting);
            assert!(
                waiting
                    .pause_reason
                    .as_ref()
                    .unwrap()
                    .contains("inspecting the recorded job")
            );
            assert!(
                !waiting
                    .pause_reason
                    .as_ref()
                    .unwrap()
                    .contains("is running")
            );
            assert_eq!(waiting.pending, Some(pending.clone()));
            assert_eq!(
                control.reports.borrow().last().unwrap()["tasks"][0]["status"],
                "waiting"
            );
            assert_eq!(
                reopen(&control.store.borrow()).poc_task(&task.id).unwrap(),
                waiting
            );
            if abandon {
                change(&mut control.store.borrow_mut(), &waiting, Change::Abandon);
            } else {
                control.live.set(false);
            }
            release.set(true);
            let result = future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()));
            if abandon {
                assert!(
                    matches!(result, Poll::Ready(Err(_))),
                    "stale collector cannot overwrite Abandon"
                );
            } else {
                assert!(
                    matches!(result, Poll::Ready(Ok(_))),
                    "lost authority becomes a concrete pause"
                );
            }
        }
        assert_eq!(control.task(&task.id).pending, Some(pending));
        assert_eq!(control.store.borrow().dispatch.calls.len(), 1);
        assert!(control.remote.borrow().sends.is_empty());
        if abandon {
            assert_eq!(control.task(&task.id).status, Status::Abandoned);
        } else {
            f.hold_observe = false;
            let paused = block_on(run::resume(
                &mut f,
                &mut Script::default(),
                &task.id,
                &session,
            ))
            .unwrap();
            assert_eq!(paused.status, Status::Paused);
        }
    }
}

#[test]
fn poc_structured_refusal_and_collection_causes_are_protected_before_progress() {
    let secret = "fixture-account-private-value";
    let (f, task, session) = Fixture::new();
    let cases = [
        (
            json!({"refused":"host-key", "pinned":"pin", "presented":"other"}),
            "host-key mismatch",
        ),
        (json!({"held":true,"calls":[]}), "machine held"),
        (
            json!({"unresolved":true,"call":1,"why":format!("read failed {secret}")}),
            "command outcome unresolved",
        ),
        (
            json!({"refused":"launch-too-long","bytes":99999}),
            "shorten the command",
        ),
        (
            json!({"refused":"signature-lowering"}),
            "signature-lowering",
        ),
        (json!({"refused":"disposition"}), "machine disposition"),
        (json!({"refused":"barrier"}), "machine barrier"),
        (
            json!({"refused":"journal","why":"installation facts: approved declaration missing"}),
            "approved declaration missing",
        ),
        (
            json!({"refused":"failed","why":format!("authentication failed {secret}")}),
            "transport or authentication failed",
        ),
    ];
    for (report, expected) in cases {
        let why = f.store.borrow().poc_refusal(&report);
        assert!(why.contains(expected), "{why}");
        assert!(!why.contains(secret));
        let current = f.task(&task.id);
        let paused = change(&mut f.store.borrow_mut(), &current, Change::Pause(why));
        assert!(!serde_json::to_string(&paused).unwrap().contains(secret));
        assert_eq!(
            reopen(&f.store.borrow()).poc_task(&task.id).unwrap(),
            paused
        );
    }
    let current = f.task(&task.id);
    let proposed = proposal(&mut f.store.borrow_mut(), &current);
    append(&mut f.store.borrow_mut(), &proposed, &session);
    let current = f.task(&task.id);
    let pending = current.pending.as_ref().unwrap();
    let reports = vec![
        json!({"call":pending.call + 1,"not_read":true,"why":"wrong call"}),
        json!({"call":pending.call,"not_read":true,"why":format!("own dispatch awaits its record {secret}")}),
    ];
    let why = f.store.borrow().poc_collection_reason(pending, &reports);
    assert!(why.contains("not read"));
    assert!(why.contains("own dispatch awaits its record"));
    assert!(!why.contains("wrong call"));
    assert!(!why.contains(secret));
    let paused = change(
        &mut f.store.borrow_mut(),
        &current,
        Change::Wait {
            why,
            running: false,
        },
    );
    assert_eq!(paused.pending, current.pending);
    assert_eq!(f.store.borrow().dispatch.calls.len(), 1);
    let replay = reopen(&f.store.borrow());
    assert_eq!(replay.poc_task(&task.id).unwrap(), paused);
    assert!(
        !replay
            .protect_output(&json!({"task":paused,"history":paused.completed}))
            .unwrap()
            .to_string()
            .contains(secret)
    );
    assert!(f.remote.borrow().sends.is_empty());
}

#[test]
fn poc_page_start_preflights_correctable_checks_and_continues_partial_acceptance() {
    for checks in [vec!["x".repeat(8193)], vec!["check".into(); 17]] {
        let mut store = crate::store::inference::tests::ready();
        let session = store.sessions[0].identity.clone();
        block_on(store.enter_goal(&session, "install and run a small service".into(), None))
            .unwrap();
        let files = store.storage.files();
        let error = block_on(store.poc_start(&session, checks)).unwrap_err();
        assert!(error.contains("verification"), "{error}");
        assert_eq!(
            store.storage.files(),
            files,
            "invalid checks never consume acceptance"
        );
        let checks = vec!["systemctl is-active example.service".into()];
        // This is the same preflight/acceptance boundary used by the page start helper.
        block_on(store.poc_accept_start(&session, &checks)).unwrap();
        assert_eq!(
            store.poc.len(),
            1,
            "acceptance atomically records the task inputs"
        );
        assert_eq!(
            store
                .conduct_acceptances
                .iter()
                .filter(|a| a.session == session)
                .count(),
            1
        );
        let task = block_on(store.poc_start(&session, checks.clone())).unwrap();
        assert_eq!(task.goal, "install and run a small service");
        assert_eq!(block_on(store.poc_start(&session, checks)).unwrap(), task);
        assert!(block_on(store.poc_start(&session, vec!["different-check".into()])).is_err());
        assert_eq!(store.poc.len(), 1);
        assert!(store.dispatch.calls.is_empty());
        assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), task);
        assert!(
            block_on(store.accept_mode(&session, Mode::NoBrief)).is_err(),
            "legacy acceptance stays one-shot"
        );
    }
}

#[test]
fn poc_empty_model_pause_is_concrete_durable_and_resumable() {
    for why in ["", " \t\n "] {
        let (mut f, task, session) = Fixture::new();
        let completed = block_on(run::resume(
            &mut f,
            &mut Script::one(
                "unavailable",
                Tool::Typed {
                    machine: "fixture".into(),
                    operation: crate::dispatch::Operation::Read,
                    arguments: Default::default(),
                },
            ),
            &task.id,
            &session,
        ))
        .unwrap()
        .completed;
        let mut model = Script {
            calls: VecDeque::from([Err(why.into())]),
            ..Default::default()
        };
        let paused = block_on(run::resume(&mut f, &mut model, &task.id, &session)).unwrap();
        assert_eq!(paused.status, Status::Paused);
        assert!(!paused.requesting);
        assert!(
            paused
                .pause_reason
                .as_ref()
                .unwrap()
                .contains("no usable pause reason")
        );
        assert_eq!(paused.requests, 2);
        assert_eq!(
            reopen(&f.store.borrow()).poc_task(&task.id).unwrap(),
            paused
        );
        let session = f.reload();
        let paused = block_on(run::resume(
            &mut f,
            &mut run::Unconfigured,
            &task.id,
            &session,
        ))
        .unwrap();
        assert_eq!(
            paused.pause_reason.as_deref(),
            Some("no inference endpoint configured")
        );
        assert_eq!(paused.requests, 3);
        assert_eq!(paused.completed, completed);
        assert!(f.remote.borrow().sends.is_empty());
    }
}

#[test]
fn poc_repeated_page_start_after_send_keeps_the_original_task_and_job() {
    let (mut f, task, session) = Fixture::new();
    f.window = Window::AfterSend;
    let control = f.clone();
    {
        let mut model = Script::one("install", exec("install-example-service"));
        let mut future = Box::pin(run::drive(&mut f, &mut model, &task.id, &session));
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let pending = control.task(&task.id);
        let again = block_on(
            control
                .store
                .borrow_mut()
                .poc_start(&session, task.checks.clone()),
        )
        .unwrap();
        assert_eq!(again, pending);
        assert_eq!(control.remote.borrow().sends.values().sum::<u32>(), 1);
    }
    let session = f.reload();
    let result = block_on(run::resume(
        &mut f,
        &mut Script::default(),
        &task.id,
        &session,
    ))
    .unwrap();
    assert!(result.pending.is_none());
    assert_eq!(result.completed.len(), 1);
    assert_eq!(f.remote.borrow().sends.values().sum::<u32>(), 1);
    assert_eq!(f.store.borrow().poc.len(), 1);
}

fn bind_fresh(s: &mut Store<MemoryStorage>) -> String {
    block_on(s.bind("fixture")).unwrap();
    let session = s.sessions.last().unwrap().identity.clone();
    s.synthetic_confirm_limits(100).unwrap();
    session
}

fn assert_continuation_page(s: &Store<MemoryStorage>, task: &Task) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut probe = Command::new("node")
        .args(["-e", include_str!("page-probe.cjs")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let payload = json!({"state":"unlocked", "seed_backup_stage":"inactive",
        "setup":s.dispatch.setup_view(), "sessions":s.sessions(), "tasks":[task]});
    probe
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let output = probe.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn poc_reload_continuation_approval_cannot_start_another_task_pending_or_settled() {
    for pending in [true, false] {
        let (mut f, task, session) = Fixture::new();
        block_on(run::resume(
            &mut f,
            &mut Script::one(
                "outside",
                Tool::Exec {
                    machine: "outside".into(),
                    command: "never".into(),
                },
            ),
            &task.id,
            &session,
        ))
        .unwrap();
        let mut model = Script::one("install", exec("install-example-service"));
        if pending {
            f.window = Window::AfterSend;
            let mut future = Box::pin(run::resume(&mut f, &mut model, &task.id, &session));
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            drop(future);
        } else {
            block_on(run::resume(&mut f, &mut model, &task.id, &session)).unwrap();
        }
        let before = f.task(&task.id);
        assert_eq!(before.pending.is_some(), pending);
        assert!(!before.completed.is_empty());
        let mut store = reopen(&f.store.borrow());
        assert!(
            store.sessions.is_empty(),
            "reopen never restores runtime authority"
        );
        let fresh = bind_fresh(&mut store);
        assert!(store.poc_authority(&task.id, &fresh).is_err());
        block_on(store.poc_authorize(&task.id, &fresh)).unwrap();
        let continued = store.poc_task(&task.id).unwrap();
        assert_eq!(continued.id, before.id);
        assert_eq!(continued.start_session, session);
        assert_eq!(
            continued.continuation_sessions,
            std::slice::from_ref(&fresh)
        );
        assert_eq!(continued.completed, before.completed);
        assert_eq!(
            (continued.requests, continued.steps),
            (before.requests, before.steps)
        );
        assert_eq!(continued.checks, before.checks);
        assert_eq!(continued.pending, before.pending);
        assert_continuation_page(&store, &continued);
        let files = store.storage.files();
        for checks in [continued.checks.clone(), vec!["different-check".into()]] {
            assert!(
                block_on(store.poc_start(&fresh, checks.clone()))
                    .unwrap_err()
                    .contains("use Resume")
            );
            assert!(block_on(store.poc_create(&fresh, checks.clone())).is_err());
            assert!(block_on(store.poc_accept_start(&fresh, &checks)).is_err());
        }
        assert_eq!(store.storage.files(), files);
        assert_eq!(store.poc.len(), 1);
        assert_eq!(store.dispatch.calls.len(), 1);
        assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), continued);
        *f.store.borrow_mut() = store;
        f.window = Window::Normal;
        let result = block_on(run::resume(
            &mut f,
            &mut run::Unconfigured,
            &task.id,
            &fresh,
        ))
        .unwrap();
        assert!(result.pending.is_none());
        assert_eq!(f.remote.borrow().sends.values().sum::<u32>(), 1);
        assert_eq!(f.store.borrow().poc.len(), 1);
        assert_eq!(result.steps, before.steps);
        // A different explicit start on a fresh session may intentionally use the same goal.
        let mut next = reopen(&f.store.borrow());
        let new_session = bind_fresh(&mut next);
        block_on(next.enter_goal(&new_session, before.goal, None)).unwrap();
        let new_task = block_on(next.poc_start(&new_session, before.checks)).unwrap();
        assert_ne!(new_task.id, task.id);
        assert_eq!(next.poc.len(), 2);
        assert!(
            next.poc_authority(&task.id, &new_session)
                .err()
                .unwrap()
                .contains("another task")
        );
    }
}

#[test]
fn poc_start_acceptance_and_inputs_replay_atomically_even_when_append_reply_is_lost() {
    for fault in [
        Some(Fault::Fail(1)),
        Some(Fault::Fail(2)),
        Some(Fault::Fail(3)),
        Some(Fault::LandThenFail(3)),
        None,
    ] {
        let mut store = crate::store::inference::tests::ready();
        store.fixture_requirements("fixture");
        let session = store.sessions[0].identity.clone();
        block_on(store.enter_goal(&session, "install and run a small service".into(), None))
            .unwrap();
        let checks = vec!["systemctl is-active example.service".into()];
        if let Some(fault) = fault {
            store.storage.fault(fault);
        }
        let result = block_on(store.poc_start(&session, checks.clone()));
        if fault.is_some() {
            assert!(result.is_err());
            assert!(store.poc.is_empty());
            assert!(
                !store
                    .conduct_acceptances
                    .iter()
                    .any(|a| a.session == session)
            );
            assert!(
                block_on(store.poc_start(&session, checks.clone())).is_err(),
                "append failure leaves the writer fail closed"
            );
        }
        let mut replay = reopen(&store);
        assert!(replay.sessions.is_empty());
        assert!(replay.dispatch.calls.is_empty());
        if matches!(fault, Some(Fault::Fail(_))) {
            assert!(replay.poc.is_empty());
            assert!(
                !replay
                    .conduct_acceptances
                    .iter()
                    .any(|a| a.session == session)
            );
            continue;
        }
        assert_eq!(replay.poc.len(), 1);
        let recovered = replay.poc.values().next().unwrap().clone();
        if let Ok(returned) = result {
            assert_eq!(returned, recovered);
        }
        assert_eq!(recovered.checks, checks);
        assert_eq!(recovered.goal, "install and run a small service");
        assert_eq!((recovered.requests, recovered.steps), (0, 0));
        assert!(replay.poc_authority(&recovered.id, &session).is_err());
        let fresh = bind_fresh(&mut replay);
        assert!(replay.poc_authority(&recovered.id, &fresh).is_err());
        block_on(replay.poc_authorize(&recovered.id, &fresh)).unwrap();
        let (mut f, _, _) = Fixture::new();
        *f.store.borrow_mut() = replay;
        let settled = block_on(run::resume(
            &mut f,
            &mut Script::one("install", exec("install-example-service")),
            &recovered.id,
            &fresh,
        ))
        .unwrap();
        assert_eq!(settled.id, recovered.id);
        assert_eq!(settled.checks, checks);
        assert_eq!(settled.completed.len(), 1);
        block_on(run::resume(
            &mut f,
            &mut run::Unconfigured,
            &recovered.id,
            &fresh,
        ))
        .unwrap();
        assert_eq!(f.remote.borrow().sends.values().sum::<u32>(), 1);
        assert_eq!(f.store.borrow().poc.len(), 1);
        assert_eq!(
            reopen(&f.store.borrow()).poc_task(&recovered.id).unwrap(),
            f.task(&recovered.id)
        );
    }
}

#[test]
fn poc_authority_pause_preserves_distinct_protected_error_and_pending_identity() {
    let (mut f, task, session) = Fixture::new();
    let proposed = proposal(&mut f.store.borrow_mut(), &task);
    append(&mut f.store.borrow_mut(), &proposed, &session);
    let before = f.task(&task.id);
    for why in [
        "session ended fixture-account-private-value",
        "fresh authority must bind only the task machine",
    ] {
        f.authority_error = Some(why.into());
        let paused = block_on(run::resume(
            &mut f,
            &mut Script::default(),
            &task.id,
            &session,
        ))
        .unwrap();
        let reason = paused.pause_reason.as_ref().unwrap();
        assert!(reason.contains(why.split(" fixture-account").next().unwrap()));
        assert!(!reason.contains("fixture-account-private-value"));
        assert_eq!(paused.pending, before.pending);
        assert_eq!(
            (paused.steps, paused.requests),
            (before.steps, before.requests)
        );
        assert_eq!(
            reopen(&f.store.borrow()).poc_task(&task.id).unwrap(),
            paused
        );
        assert!(f.remote.borrow().sends.is_empty());
    }
}

#[test]
fn poc_production_collector_reports_preserve_observed_causes_and_uncertainty() {
    for case in 0..6 {
        let (mut f, task, session) = Fixture::new();
        let proposed = proposal(&mut f.store.borrow_mut(), &task);
        append(&mut f.store.borrow_mut(), &proposed, &session);
        let pending_task = f.task(&task.id);
        let mut observed = record(&pending_task, None, "fixture-account-private-value");
        let expected = match case {
            0 => {
                observed = crate::jobs::Record::Missing;
                "no record found"
            }
            1 => {
                if let crate::jobs::Record::Present { alive, .. } = &mut observed {
                    *alive = false;
                }
                "process ended without a trustworthy exit"
            }
            2 => {
                observed = crate::jobs::Record::Incomplete {
                    machine: Some(hex::encode("fixture")),
                    command: None,
                };
                "incomplete job record"
            }
            3 => {
                if let crate::jobs::Record::Present { machine, .. } = &mut observed {
                    *machine = hex::encode("foreign");
                }
                "foreign machine record"
            }
            _ => {
                if let crate::jobs::Record::Present { command, alive, .. } = &mut observed {
                    *command = hex::encode("different");
                    *alive = false;
                }
                "command/record mismatch"
            }
        };
        let pending = pending_task.pending.as_ref().unwrap();
        evidence(&mut f.store.borrow_mut(), &pending_task, observed);
        let serialized =
            serde_json::to_value(f.store.borrow().poc_committed(pending).unwrap()).unwrap();
        assert!(serialized.get("why").is_none());
        let why = f
            .store
            .borrow()
            .poc_collection_reason(pending, std::slice::from_ref(&serialized));
        assert!(why.contains(expected), "{why}");
        assert!(why.contains(&pending.job));
        assert!(!why.contains("fixture-account-private-value"));
        let paused = change(
            &mut f.store.borrow_mut(),
            &pending_task,
            Change::Wait {
                why,
                running: false,
            },
        );
        assert_eq!(paused.pending, pending_task.pending);
        assert!(paused.completed.is_empty());
        assert!(matches!(
            f.store.borrow().dispatch.check_command("fixture"),
            Err(crate::dispatch::DispatchRefusal::Held(_))
        ));
        assert!(
            block_on(
                f.store
                    .borrow_mut()
                    .poc_change(&task.id, paused.revision, Change::Settle)
            )
            .is_err()
        );
        let mut replay = reopen(&f.store.borrow());
        assert_eq!(replay.poc_task(&task.id).unwrap(), paused);
        let fresh = bind_fresh(&mut replay);
        block_on(replay.poc_authorize(&task.id, &fresh)).unwrap();
        *f.store.borrow_mut() = replay;
        // Repeated Resume reads the same record and never authorizes another intent/send.
        f.observe_error = true;
        for _ in 0..2 {
            let paused = block_on(run::resume(
                &mut f,
                &mut Script::default(),
                &task.id,
                &fresh,
            ))
            .unwrap();
            assert_eq!(paused.pending, pending_task.pending);
            assert_ne!(paused.status, Status::Complete);
        }
        assert_eq!(f.store.borrow().dispatch.calls.len(), 1);
        assert!(f.remote.borrow().sends.is_empty());
        let mut malformed = serialized;
        malformed.as_object_mut().unwrap().remove("state");
        assert!(
            f.store
                .borrow()
                .poc_collection_reason(pending, &[malformed])
                .contains("malformed")
        );
        assert!(
            f.store
                .borrow()
                .poc_collection_reason(pending, &[json!({"call":pending.call,"job":"other"})])
                .contains("identity mismatch")
        );
    }
}

#[test]
fn poc_collector_checkpoint_failures_preserve_pending_jobs_and_verification() {
    let secret = "fixture-account-private-value";
    for verifying in [false, true] {
        for case in 0..6 {
            let (mut f, task, session) = Fixture::new();
            if verifying {
                block_on(run::resume(
                    &mut f,
                    &mut Script::one("done", done()),
                    &task.id,
                    &session,
                ))
                .unwrap();
            }
            // Launch once, then lose the response before any evidence checkpoint.
            f.window = Window::AfterSend;
            {
                let mut model = Script::one("install", exec("install-example-service"));
                let mut running =
                    std::pin::pin!(run::resume(&mut f, &mut model, &task.id, &session));
                assert!(
                    running
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
            }
            let before = f.task(&task.id);
            let pending = before.pending.as_ref().unwrap();
            let Tool::Exec { command, .. } = &before.proposal.as_ref().unwrap().tool else {
                panic!("pending command expected")
            };
            let uncommitted = block_on(crate::harness::BoundJournal::uncommitted(
                &*f.store.borrow(),
                &crate::jobs::Evidence {
                    call: pending.call,
                    job: pending.job.clone(),
                    record: record(&before, Some(0), secret),
                },
                &before.machine,
                &hex::encode(command),
            ))
            .unwrap();
            let uncommitted = serde_json::to_value(uncommitted).unwrap();
            assert!(!uncommitted.to_string().contains(secret));
            let (report, expected) = match case {
                0..=3 => (
                    // Exact collector failure shape, including unavailable diagnostics.
                    json!({"call":pending.call,"job":pending.job,"failed":true,
                        "why":if case < 2 {
                            format!("job evidence append: storage unavailable {secret}")
                        } else {
                            "wait stopped before journaling job evidence".into()
                        },
                        "job_record":if case % 2 == 0 { uncommitted } else { Value::Null }}),
                    "evidence checkpoint not confirmed",
                ),
                4 => (
                    json!({"call":pending.call,"job":pending.job,"failed":true,
                        "why":format!("session channel: record read failed {secret}")}),
                    "record read failed",
                ),
                _ => (
                    json!({"call":pending.call,"job":pending.job,"not_read":true,
                        "why":"sessions ended before record was read"}),
                    "not read",
                ),
            };
            f.collection_reports = Some(vec![report]);
            let mut session = session;
            let mut model = Script::default();
            for _ in 0..3 {
                let paused = block_on(run::resume(&mut f, &mut model, &task.id, &session)).unwrap();
                let why = paused.pause_reason.as_ref().unwrap();
                assert!(why.contains(expected), "{why}");
                if case < 4 {
                    assert!(why.contains("observation remains uncertain"), "{why}");
                    assert!(!why.contains("record read failed"), "{why}");
                    assert!(why.contains(if case < 2 {
                        "storage unavailable"
                    } else {
                        "wait stopped before journaling job evidence"
                    }));
                } else {
                    assert!(!why.contains("evidence checkpoint"), "{why}");
                }
                assert!(why.contains(&pending.job));
                assert!(!serde_json::to_string(&paused).unwrap().contains(secret));
                assert_eq!(paused.status, Status::Paused);
                assert_eq!(paused.pending, before.pending);
                assert_eq!(paused.proposal, before.proposal);
                assert_eq!(paused.completed, before.completed);
                assert_eq!(paused.verification, before.verification);
                assert_eq!(
                    (paused.requests, paused.steps),
                    (before.requests, before.steps)
                );
                assert!(f.store.borrow().poc_committed(pending).is_none());
                assert!(matches!(
                    f.store.borrow().dispatch.check_command("fixture"),
                    Err(crate::dispatch::DispatchRefusal::Held(_))
                ));
                assert_eq!(f.store.borrow().dispatch.calls.len(), 1);
                assert_eq!(f.remote.borrow().sends.len(), 1);
                assert_eq!(f.remote.borrow().sends[&pending.job], 1);
                assert!(model.seen.is_empty());
                let mut replay = reopen(&f.store.borrow());
                assert_eq!(replay.poc_task(&task.id).unwrap(), paused);
                session = bind_fresh(&mut replay);
                block_on(replay.poc_authorize(&task.id, &session)).unwrap();
                *f.store.borrow_mut() = replay;
            }
        }
    }
}

#[test]
fn poc_held_read_nested_host_key_and_read_append_failures_keep_safe_causes() {
    let (f, task, session) = Fixture::new();
    let task = proposal(&mut f.store.borrow_mut(), &task);
    append(&mut f.store.borrow_mut(), &task, &session);
    let task = f.task(&task.id);
    let pending = task.pending.as_ref().unwrap();
    let secret = "fixture-account-private-value";
    // Same held/calls/not_read/why/unreachable shape used by the command admission reader.
    let nested = json!({"held":true,"machine":"fixture","calls":[{
        "call":pending.call,"not_read":true,"why":{"unreachable":{
            "refused":"host-key","pinned":"pin","presented":"different", "why":format!("pin refused {secret}")
        }}}], "release":["finished_record","disposition"]});
    let why = f.store.borrow().poc_refusal(&nested);
    assert!(why.contains("host-key mismatch"), "{why}");
    assert!(why.contains(&format!("call {}", pending.call)));
    assert!(why.contains("not read"));
    assert!(!why.contains(secret));
    for (report, expected) in [
        (nested, "host-key mismatch"),
        (
            json!({"held":true,"calls":[{"call":pending.call,"failed":true,"why":format!("record channel failed {secret}")}]}),
            "record read failed",
        ),
        (
            json!({"held":true,"calls":[{"call":pending.call,"not_journaled":true,"why":format!("job evidence append: {secret}")}]}),
            "evidence checkpoint not confirmed",
        ),
        (json!({"refused":"unbound","machine":"fixture"}), "unbound"),
        (
            json!({"refused":"no-entry","machine":"fixture"}),
            "no approved entry",
        ),
        (json!({"refused":"provenance"}), "provenance"),
    ] {
        let why = f.store.borrow().poc_refusal(&report);
        assert!(why.contains(expected), "{why}");
        assert!(!why.contains(secret));
        let current = f.task(&task.id);
        let paused = change(
            &mut f.store.borrow_mut(),
            &current,
            Change::Wait {
                why,
                running: false,
            },
        );
        assert_eq!(paused.pending, task.pending);
        assert_eq!(
            reopen(&f.store.borrow()).poc_task(&task.id).unwrap(),
            paused
        );
        assert_ne!(paused.status, Status::Complete);
        assert!(f.remote.borrow().sends.is_empty());
    }
}
