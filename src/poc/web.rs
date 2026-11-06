//! Durable browser execution through configured inference and stored connection authority.
use super::run::{self, Observation, Runtime};
use crate::binding::Session;
use crate::dispatch::{Approval, Intent, Terminal};
use crate::harness::{AppendRefusal, BoundJournal, Entry, Journal, PinSource, Target};
use crate::store::poc::{Binding, Change, Task};
use crate::worker::{StoreJournal, local};
use serde_json::Value;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::JsCast;
pub(crate) type Response = Rc<RefCell<Option<crate::poc::inference::CommandResponse>>>;

pub(crate) async fn publish_progress(session: &str) {
    let generation = crate::harness::inference::publication_generation();
    let report = local().lock().await.report(None).to_string();
    #[cfg(feature = "tracer")]
    crate::testonly::session_point("poc_progress_publication").await;
    crate::harness::inference::publish_report(generation, session.into(), report).await;
}

pub(crate) async fn resume_with(
    id: &str,
    session: &str,
    target: &Target,
    pins: &impl PinSource,
    model: &mut impl run::Model,
    response: Response,
) -> Result<Task, String> {
    let mut runtime = Web {
        target,
        pins,
        response,
        session,
        continuation: crate::lifecycle::owner().continuation()?,
    };
    run::drive(&mut runtime, model, id, session).await
}

struct Web<'a, P> {
    response: Response,
    target: &'a Target,
    pins: &'a P,
    session: &'a str,
    continuation: crate::lifecycle::Continuation,
}
impl<P: PinSource> Runtime for Web<'_, P> {
    async fn progress(&mut self, task: &Task) {
        if task.pending.is_some() {
            self.response
                .borrow_mut()
                .get_or_insert_with(crate::poc::inference::CommandResponse::reserve);
        }
        publish_progress(self.session).await;
    }
    async fn load(&mut self, id: &str) -> Result<Task, String> {
        local()
            .lock()
            .await
            .store()
            .ok_or(crate::poc::wait::LOCKED)?
            .poc_task(id)
    }
    async fn authority(&mut self, id: &str, session: &str) -> Result<(), String> {
        let local = local();
        let mut writer = local.lock().await;
        self.continuation.check()?;
        if let Some(why) = writer.dispatch_refusal() {
            return Err(why.into());
        }
        writer
            .store()
            .ok_or(crate::poc::wait::LOCKED)?
            .poc_authority(id, session)
            .map(|_| ())
    }
    async fn change(&mut self, task: &Task, change: Change) -> Result<Task, String> {
        local()
            .lock()
            .await
            .store()
            .ok_or(crate::poc::wait::LOCKED)?
            .poc_change(&task.id, task.revision, change)
            .await
    }
    async fn propose(
        &mut self,
        task: &Task,
        session: &str,
        call_id: String,
        tool: crate::goals::Tool,
    ) -> Result<Task, String> {
        let local = local();
        let mut writer = local.lock().await;
        self.continuation.check()?;
        let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
        store.poc_propose(task, session, call_id, tool).await
    }

    async fn execute(&mut self, binding: Binding, task: &Task) -> Result<(), String> {
        self.response
            .borrow_mut()
            .get_or_insert_with(crate::poc::inference::CommandResponse::reserve);
        {
            let local = local();
            let mut writer = local.lock().await;
            self.continuation.check()?;
            writer
                .store()
                .ok_or(crate::poc::wait::LOCKED)?
                .poc_prepare_execution(task, &binding.session)?;
        }
        if self.target.machine != task.machine {
            return Err(crate::poc::wait::TARGET_DIFFERS.into());
        }
        if self.target.relay.is_empty()
            || self.target.host.is_empty()
            || self.target.user.is_empty()
        {
            return Err(crate::poc::wait::TARGET_REQUIRED.into());
        }
        if self.pins.pin(&task.machine).is_none() {
            return Err(crate::poc::wait::PIN_REQUIRED.into());
        }
        let origin = local()
            .lock()
            .await
            .store()
            .ok_or(crate::poc::wait::LOCKED)?
            .poc_authority(&task.id, &binding.session)?;
        let proposal = task.proposal.as_ref().ok_or("missing command proposal")?;
        let crate::goals::Tool::Exec { command, .. } = &proposal.tool else {
            return Err("command required".into());
        };
        let mut journal = ScopedJournal {
            base: StoreJournal {
                local: local(),
                unavailable: false,
            },
            binding,
            origin: origin.clone(),
            collecting: false,
            continuation: self.continuation.clone(),
        };
        let result = crate::harness::run_command(
            self.pins,
            &mut journal,
            self.target,
            command.as_bytes(),
            Some(&origin),
            #[cfg(feature = "tracer")]
            false,
        )
        .await;
        #[cfg(feature = "tracer")]
        crate::testonly::session_point("poc_execution_return").await;
        match result {
            Ok(_) => Ok(()),
            Err(why) => Err(local()
                .lock()
                .await
                .store()
                .ok_or(crate::poc::wait::LOCKED)?
                .poc_refusal(&why.to_json())),
        }
    }
    async fn observe(&mut self, task: &Task, session: &str) -> Result<Observation, String> {
        self.response
            .borrow_mut()
            .get_or_insert_with(crate::poc::inference::CommandResponse::reserve);
        if let Some(observation) = committed(task, &self.continuation).await? {
            return Ok(observation);
        }
        if self.target.machine != task.machine {
            return Err(crate::poc::wait::TARGET_DIFFERS.into());
        }
        if self.target.relay.is_empty()
            || self.target.host.is_empty()
            || self.target.user.is_empty()
        {
            return Err(crate::poc::wait::TARGET_REQUIRED.into());
        }
        if self.pins.pin(&task.machine).is_none() {
            return Err(crate::poc::wait::PIN_REQUIRED.into());
        }
        let origin = local()
            .lock()
            .await
            .store()
            .ok_or(crate::poc::wait::LOCKED)?
            .poc_authority(&task.id, session)?;
        let mut journal = ScopedJournal {
            base: StoreJournal {
                local: local(),
                unavailable: false,
            },
            binding: Binding {
                task: task.id.clone(),
                revision: task.revision,
                session: session.into(),
            },
            origin,
            collecting: true,
            continuation: self.continuation.clone(),
        };
        publish_progress(session).await;
        let result = crate::harness::collect_jobs(
            self.pins,
            &mut journal,
            self.target,
            #[cfg(feature = "tracer")]
            false,
        )
        .await;
        if let Some(observation) = committed(task, &self.continuation).await? {
            return Ok(observation);
        }
        let local = local();
        let mut writer = local.lock().await;
        let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
        let pending = task
            .pending
            .as_ref()
            .ok_or(crate::poc::wait::MISSING_PENDING_JOB)?;
        let call = pending.call;
        match result {
            Ok(reports) => Ok(Observation::Unknown(
                store.poc_collection_reason(pending, &reports),
            )),
            Err(why) => Err(crate::poc::wait::COLLECTION_FAILED.render(
                call,
                "",
                &store.poc_refusal(&why.to_json()),
            )),
        }
    }
}
async fn committed(
    task: &Task,
    continuation: &crate::lifecycle::Continuation,
) -> Result<Option<Observation>, String> {
    let local = local();
    let mut writer = local.lock().await;
    let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
    let pending = task
        .pending
        .as_ref()
        .ok_or(crate::poc::wait::MISSING_PENDING_IDENTITY)?;
    let Some(report) = store.poc_committed(pending).cloned() else {
        return Ok(None);
    };
    let Some(observation) = run::committed_observation(&report) else {
        return Ok(None);
    };
    store.ensure_scan_references().await?;
    let value = serde_json::json!({"command_result":report});
    let mut safe = store.protect_output(&value)?;
    if store.current_command_results(&mut safe) {
        safe = store.protect_output(&safe)?;
    }
    let worker: web_sys::DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    loop {
        if continuation.check().is_err() && safe["historical"] != true {
            crate::jobs::historical(&mut safe, "stale result after suspension");
            safe = store.protect_output(&safe)?;
        }
        let encoded = safe.to_string();
        let message =
            js_sys::JSON::parse(&encoded).map_err(|_| crate::poc::wait::RESULT_ENCODING)?;
        if store.current_command_results(&mut safe) {
            safe = store.protect_output(&safe)?;
            continue;
        }
        // The same writer and response reservation cover scanning, encoding and post.
        worker
            .post_message(&message)
            .map_err(|_| crate::poc::wait::RESULT_PUBLICATION)?;
        break;
    }
    Ok(Some(observation))
}

/// This isolated adapter owns one task/step binding; no ambient tag can leak across awaits.
struct ScopedJournal {
    base: StoreJournal,
    binding: Binding,
    origin: Rc<Session>,
    collecting: bool,
    continuation: crate::lifecycle::Continuation,
}
impl Journal for ScopedJournal {
    async fn check_signature(
        &mut self,
        machine: &str,
        command: &[u8],
    ) -> Result<(), AppendRefusal> {
        self.base.check_signature(machine, command).await
    }
    async fn check(&self, machine: &str) -> Result<(), AppendRefusal> {
        self.base.check(machine).await
    }
    async fn append(&mut self, _: &Entry, _: &Approval) -> Result<u64, AppendRefusal> {
        Err(AppendRefusal::Storage(
            "task commands require bound append".into(),
        ))
    }
    async fn terminal(&mut self, terminal: &Terminal) -> Result<u64, String> {
        self.base.terminal(terminal).await
    }
    async fn read(&self, seq: u64) -> Option<Entry> {
        self.base.read(seq).await
    }
    async fn intent(&self, call: u64) -> Option<Intent> {
        self.base.intent(call).await
    }
    async fn collectable(&self, machine: &str) -> Result<Vec<Intent>, String> {
        let pending = local()
            .lock()
            .await
            .store()
            .ok_or(crate::poc::wait::LOCKED)?
            .poc_task(&self.binding.task)?
            .pending
            .ok_or("no pending task job")?;
        Ok(self
            .base
            .collectable(machine)
            .await?
            .into_iter()
            .filter(|i| i.call == pending.call && i.job.as_ref() == Some(&pending.job))
            .collect())
    }
    async fn job_evidence(
        &mut self,
        evidence: &crate::jobs::Evidence,
    ) -> Result<crate::jobs::Report, String> {
        self.base.job_evidence(evidence).await
    }
    async fn job_evidence_unless_stopped(
        &mut self,
        evidence: &crate::jobs::Evidence,
        stop: &crate::harness::Stop,
    ) -> Option<Result<crate::jobs::Report, String>> {
        self.base.job_evidence_unless_stopped(evidence, stop).await
    }
}
impl BoundJournal for ScopedJournal {
    async fn append_bound(
        &mut self,
        session: &Session,
        entry: &Entry,
        approval: &Approval,
    ) -> Result<u64, AppendRefusal> {
        run::commit_command(
            async {
                let local = local();
                let mut writer = local.lock().await;
                self.continuation.check().map_err(AppendRefusal::Storage)?;
                if let Some(why) = writer.dispatch_refusal() {
                    return Err(AppendRefusal::Storage(why.into()));
                }
                let store = writer
                    .store()
                    .ok_or_else(|| AppendRefusal::Storage(crate::poc::wait::LOCKED.into()))?;
                store
                    .check_current_session(session)
                    .map_err(AppendRefusal::Storage)?;
                if self.collecting
                    || !std::ptr::eq(session, self.origin.as_ref())
                    || session.identity != self.binding.session
                {
                    return Err(AppendRefusal::Storage("stale task session".into()));
                }
                store.poc_append(&self.binding, entry, approval).await
            },
            publish_progress(&self.binding.session),
        )
        .await
    }
    async fn current(&self, session: &Session) -> Result<(), String> {
        self.base.current(session).await?;
        if !std::ptr::eq(session, self.origin.as_ref()) {
            return Err("stale task session".into());
        }
        let local = local();
        let mut writer = local.lock().await;
        self.continuation.check()?;
        if let Some(why) = writer.dispatch_refusal() {
            return Err(why.into());
        }
        let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
        if self.collecting {
            store.poc_authority(&self.binding.task, &self.binding.session)?;
            if store.poc_task(&self.binding.task)?.revision != self.binding.revision {
                return Err("stale task collection".into());
            }
            Ok(())
        } else {
            store.poc_binding_current(&self.binding)
        }
    }
    async fn release(&self, value: Value) -> Result<Value, String> {
        self.base.release(value).await
    }
    async fn uncommitted(
        &self,
        evidence: &crate::jobs::Evidence,
        machine: &str,
        command: &str,
    ) -> Result<crate::jobs::Report, String> {
        self.base.uncommitted(evidence, machine, command).await
    }
    async fn connection_session(
        &mut self,
        machine: &str,
        _: Option<&Rc<Session>>,
    ) -> Result<Rc<Session>, crate::binding::AdmissionRefusal> {
        self.current(&self.origin)
            .await
            .map_err(crate::binding::AdmissionRefusal::Journal)?;
        self.base
            .connection_session(machine, Some(&self.origin))
            .await
    }
    async fn relay_key(&self) -> Option<crate::credential::RelayKey> {
        self.base.relay_key().await
    }
}

pub(crate) async fn request(request: String) -> String {
    request_with(request, Response::default()).await
}
pub(crate) async fn request_with(request: String, response: Response) -> String {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        action: String,
        id: Option<String>,
        session: Option<String>,
        checks: Option<Vec<String>>,
        limits: Option<crate::store::poc::Limits>,
    }
    let result = async {
        let value: Value = serde_json::from_str(&request).map_err(|_| "task request")?;
        if !value.is_object() {
            return Err("task request".into());
        }
        let request: Request = serde_json::from_value(value).map_err(|_| "task request")?;
        if request.action == "resume" {
            let id = request.id.as_deref().ok_or("task ID required")?;
            let session = request.session.as_deref().ok_or("fresh session required")?;
            let machine = local()
                .lock()
                .await
                .store()
                .ok_or(crate::poc::wait::LOCKED)?
                .poc_task(id)?
                .machine;
            let resolved = {
                let local = local();
                let mut writer = local.lock().await;
                let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
                match crate::poc::targets::resolve(store, &machine) {
                    Ok(resolved) => Ok(resolved),
                    Err(reason) => {
                        store.ensure_scan_references().await?;
                        let reason = if let Some(profile) =
                            reason.strip_prefix("unsupported relay profile: ")
                        {
                            let safe = store.protect_output(&serde_json::json!(profile))?;
                            format!(
                                "unsupported relay profile: {}",
                                safe.as_str().ok_or("profile protection")?
                            )
                        } else {
                            reason
                        };
                        let safe = store.protect_output(&serde_json::json!(reason))?;
                        Err(safe.as_str().ok_or("resolver protection")?.to_string())
                    }
                }
            };
            match resolved {
                Ok((target, pins)) => {
                    resume_with(
                        id,
                        session,
                        &target,
                        &pins,
                        &mut Configured {
                            response: response.clone(),
                        },
                        response.clone(),
                    )
                    .await?;
                }
                Err(reason) => {
                    let local = local();
                    let mut writer = local.lock().await;
                    let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
                    let task = store.poc_task(id)?;
                    store
                        .poc_change(id, task.revision, Change::Pause(reason))
                        .await?;
                }
            }
        } else {
            let local = local();
            let mut writer = local.lock().await;
            let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
            match request.action.as_str() {
                "start" => {
                    store
                        .poc_start(
                            request.session.as_deref().ok_or("session required")?,
                            request.checks.unwrap_or_default(),
                        )
                        .await?;
                }
                "authorize" => {
                    let id = request.id.as_deref().ok_or("task ID required")?;
                    let session = request.session.as_deref().ok_or("fresh session required")?;
                    store.poc_authorize(id, session).await?;
                }
                "retry-checks" => {
                    let id = request.id.as_deref().ok_or("task ID required")?;
                    crate::poc::run::check_raise(id)?;
                    store
                        .poc_authority(id, request.session.as_deref().ok_or("session required")?)?;
                    let task = store.poc_task(id)?;
                    store
                        .poc_change(id, task.revision, Change::RetryChecks)
                        .await?;
                }
                "abandon" => {
                    let id = request.id.as_deref().ok_or("task ID required")?;
                    let task = store.poc_task(id)?;
                    store.poc_change(id, task.revision, Change::Abandon).await?;
                }
                "raise" => {
                    let id = request.id.as_deref().ok_or("task ID required")?;
                    store
                        .poc_raise(id, request.limits.ok_or("limits required")?)
                        .await?;
                }
                _ => return Err("unknown task action".into()),
            }
        }
        Ok::<(), String>(())
    }
    .await;
    local()
        .lock()
        .await
        .report(result.as_ref().err().map(String::as_str))
        .to_string()
}

struct Configured {
    response: Response,
}
impl run::Model for Configured {
    async fn next(
        &mut self,
        goal: &str,
        machine: &str,
        completed: &[(String, crate::goals::Tool, Value)],
    ) -> Result<(String, crate::goals::Tool), String> {
        // Progress has released the preceding result. Configuration may change during
        // the next request, whose adapter detects changes and aborts honestly.
        self.response.borrow_mut().take();
        #[cfg(feature = "tracer")]
        if let Some(next) = crate::testonly::poc_model_next(machine) {
            *self.response.borrow_mut() = Some(crate::poc::inference::CommandResponse::reserve());
            return Ok(next);
        }
        let next = crate::poc::inference::next(goal, machine, completed).await;
        // A failed request has no new command result to release. In particular, let
        // the operator configure an endpoint/key while its pause is being recorded.
        if next.is_ok() {
            *self.response.borrow_mut() = Some(crate::poc::inference::CommandResponse::reserve());
        }
        #[cfg(feature = "tracer")]
        crate::testonly::session_point("poc_model_return").await;
        next
    }
}

/// Stored targets select the durable page route in fixture builds as well.
/// The legacy exercises have no enrolled target and keep their original route.
#[cfg(feature = "tracer")]
pub(crate) async fn page_uses_runner(session: &str) -> bool {
    #[cfg(not(feature = "tracer"))]
    {
        let _ = session;
        true
    }
    #[cfg(feature = "tracer")]
    {
        local()
            .lock()
            .await
            .store()
            .and_then(|store| {
                let live = store.live_goal_session(session).ok()?;
                live.bound_set
                    .first()
                    .and_then(|machine| store.poc_target(machine))
                    .map(|_| ())
            })
            .is_some()
    }
}

/// The page owns this scope through its actual final post. Each execution acquires a
/// reservation; requests release it while awaiting inference and reacquire on return.
#[wasm_bindgen::prelude::wasm_bindgen]
pub struct TaskPublication {
    response: Response,
}
#[wasm_bindgen::prelude::wasm_bindgen]
impl TaskPublication {
    #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            response: Response::default(),
        }
    }
    pub async fn request(&self, request: String) -> String {
        request_with(request, self.response.clone()).await
    }
    pub async fn run_goal(&self, session: String, checks: String) -> String {
        crate::worker::run_page_goal_with(session, checks, self.response.clone()).await
    }
    pub async fn publish(&self, generation: u64, session: String, report: String) {
        // Take ownership before awaiting the publisher: destruction covers every exit,
        // without a writer held during transport or an operator wait.
        let _response = self.response.borrow_mut().take();
        crate::harness::inference::publish_report(generation, session, report).await;
    }
}
impl Default for TaskPublication {
    fn default() -> Self {
        Self::new()
    }
}
