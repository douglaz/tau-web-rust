//! Browser adapter. Resolved targets and pins are supplied by the caller at integration.
use super::run::{self, Observation, Runtime};
use crate::binding::Session;
use crate::dispatch::{Approval, Intent, Terminal};
use crate::harness::{AppendRefusal, BoundJournal, Entry, Journal, PinSource, Target};
use crate::store::poc::{Binding, Change, Task};
use crate::worker::{StoreJournal, local};
use serde_json::Value;
use std::rc::Rc;

pub(crate) async fn publish_progress(session: &str) {
    let generation = crate::harness::inference::publication_generation();
    let report = local().lock().await.report(None).to_string();
    crate::harness::inference::publish_report(generation, session.into(), report).await;
}

pub(crate) async fn resume_with(
    id: &str,
    session: &str,
    target: &Target,
    pins: &impl PinSource,
    model: &mut impl run::Model,
) -> Result<Task, String> {
    let mut runtime = Web {
        target,
        pins,
        session,
        continuation: crate::lifecycle::owner().continuation()?,
    };
    run::drive(&mut runtime, model, id, session).await
}

struct Web<'a, P> {
    target: &'a Target,
    pins: &'a P,
    session: &'a str,
    continuation: crate::lifecycle::Continuation,
}
impl<P: PinSource> Runtime for Web<'_, P> {
    async fn progress(&mut self, _task: &Task) {
        publish_progress(self.session).await;
    }
    async fn load(&mut self, id: &str) -> Result<Task, String> {
        local().lock().await.store().ok_or("locked")?.poc_task(id)
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
            .ok_or("locked")?
            .poc_authority(id, session)
            .map(|_| ())
    }
    async fn change(&mut self, task: &Task, change: Change) -> Result<Task, String> {
        local()
            .lock()
            .await
            .store()
            .ok_or("locked")?
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
        let store = writer.store().ok_or("locked")?;
        store.poc_propose(task, session, call_id, tool).await
    }

    async fn execute(&mut self, binding: Binding, task: &Task) -> Result<(), String> {
        {
            let local = local();
            let mut writer = local.lock().await;
            self.continuation.check()?;
            writer
                .store()
                .ok_or("locked")?
                .poc_prepare_execution(task, &binding.session)?;
        }
        if self.target.machine != task.machine {
            return Err("resolved target differs from task machine".into());
        }
        if self.target.relay.is_empty()
            || self.target.host.is_empty()
            || self.target.user.is_empty()
        {
            return Err("resolved relay, host and user are required before Resume".into());
        }
        if self.pins.pin(&task.machine).is_none() {
            return Err("trusted host pin missing; configure it before Resume".into());
        }
        let origin = local()
            .lock()
            .await
            .store()
            .ok_or("locked")?
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
        match result {
            Ok(_) => Ok(()),
            Err(why) => Err(local()
                .lock()
                .await
                .store()
                .ok_or("locked")?
                .poc_refusal(&why.to_json())),
        }
    }
    async fn observe(&mut self, task: &Task, session: &str) -> Result<Observation, String> {
        if let Some(observation) = committed(task).await? {
            return Ok(observation);
        }
        if self.target.machine != task.machine {
            return Err("resolved target differs from task machine".into());
        }
        if self.target.relay.is_empty()
            || self.target.host.is_empty()
            || self.target.user.is_empty()
        {
            return Err("resolved relay, host and user are required before Resume".into());
        }
        if self.pins.pin(&task.machine).is_none() {
            return Err("trusted host pin missing; configure it before Resume".into());
        }
        let origin = local()
            .lock()
            .await
            .store()
            .ok_or("locked")?
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
        if let Some(observation) = committed(task).await? {
            return Ok(observation);
        }
        let local = local();
        let mut writer = local.lock().await;
        let store = writer.store().ok_or("locked")?;
        let pending = task.pending.as_ref().ok_or("missing pending job")?;
        let call = pending.call;
        match result {
            Ok(reports) => Ok(Observation::Unknown(
                store.poc_collection_reason(pending, &reports),
            )),
            Err(why) => Err(format!(
                "collection failed for pending call {call}: {}; pending identity retained",
                store.poc_refusal(&why.to_json())
            )),
        }
    }
}
async fn committed(task: &Task) -> Result<Option<Observation>, String> {
    let local = local();
    let mut writer = local.lock().await;
    let store = writer.store().ok_or("locked")?;
    let pending = task.pending.as_ref().ok_or("missing pending identity")?;
    Ok(store.poc_committed(pending).and_then(|report| {
        if report.state != crate::jobs::State::Finished { return None; }
        Some(if matches!(report.comparison, crate::jobs::Comparison::AdvisoryMatch) {
            Observation::Committed
        } else {
            Observation::Unknown("committed job record differs from its intent; pending identity retained for inspection".into())
        })
    }))
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
            .ok_or("locked")?
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
                    .ok_or_else(|| AppendRefusal::Storage("locked".into()))?;
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
        let store = writer.store().ok_or("locked")?;
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
                .ok_or("locked")?
                .poc_task(id)?
                .machine;
            // Resolution stays external; this served seam cannot contact an empty target.
            let target = Target {
                machine,
                relay: String::new(),
                host: String::new(),
                port: 22,
                user: String::new(),
            };
            struct MissingPins;
            impl PinSource for MissingPins {
                fn pin(&self, _: &str) -> Option<crate::credential::HostKeyPin> {
                    None
                }
            }
            resume_with(id, session, &target, &MissingPins, &mut run::Unconfigured).await?;
        } else {
            let local = local();
            let mut writer = local.lock().await;
            let store = writer.store().ok_or("locked")?;
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
