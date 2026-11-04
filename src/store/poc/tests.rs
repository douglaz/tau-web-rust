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
    let mut s = crate::store::inference::tests::ready();
    s.fixture_requirements("fixture");
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
    observe_release: Option<Rc<Cell<bool>>>,
    live: Rc<Cell<bool>>,
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
                observe_release: None,
                live: Rc::new(Cell::new(true)),
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
        store.poc_authority(&task.id, session)?;
        if tool.machine() == task.machine {
            store.poc_tool(&task.id, session, &tool)?;
        }
        block_on(store.poc_change(&task.id, task.revision, Change::Propose { call_id, tool }))
    }
    async fn execute(&mut self, binding: Binding, task: &Task) -> Result<(), String> {
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
                Observation::Unknown("job missing or without trustworthy outcome".into())
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
    for case in 0..6 {
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
        change(&mut shared.borrow_mut(), &pending, Change::Abandon);
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
            Poll::Ready(Ok(_))
        ));
        assert!(matches!(
            b.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(_))
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
                    Err("task action already active".into())
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
