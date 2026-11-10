//! Durable local orchestration. A session supplies current authority, never continuation state.
use super::*;
use crate::goals::Tool;

pub type Step = (String, Tool, Value);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub requests: u32,
    pub steps: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            requests: 10,
            steps: 20,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Running,
    Waiting,
    Verifying,
    Paused,
    Complete,
    Abandoned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub call_id: String,
    pub tool: Tool,
    pub check: Option<usize>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub call: u64,
    pub job: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub command: String,
    pub job: String,
    pub exit_status: Option<u32>,
    pub excerpt: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub id: String,
    pub start_session: String,
    pub goal: String,
    pub machine: String,
    pub approved_plan: Option<String>,
    pub completed: Vec<Step>,
    pub proposal: Option<Proposal>,
    pub pending: Option<Pending>,
    pub status: Status,
    pub pause_reason: Option<String>,
    pub requests: u32,
    pub steps: u32,
    pub limits: Limits,
    pub checks: Vec<String>,
    pub verification: Vec<Verification>,
    pub verifying: bool,
    pub requesting: bool,
    /// Compare-and-append token: stale requests cannot publish or arm a command.
    pub revision: u64,
}
impl Task {
    /// The page card shows bounded excerpts; complete outcomes remain in the journal
    /// and the command evidence view. Repeating them here can exhaust a whole report.
    pub(super) fn view(&self) -> Value {
        let mut value = serde_json::to_value(self).expect("task serializes");
        for step in value["completed"].as_array_mut().expect("completed array") {
            let content = &mut step[2]["content"];
            for field in ["stdout", "stderr"] {
                if let Some(text) = content[field].as_str() {
                    let excerpt: String = text.chars().take(1024).collect();
                    if excerpt.len() < text.len() {
                        content[field] = excerpt.into();
                        content[format!("{field}_truncated")] = true.into();
                    }
                }
            }
        }
        value
    }
    pub fn ended(&self) -> bool {
        matches!(self.status, Status::Complete | Status::Abandoned)
    }
    fn pause(&mut self, why: impl Into<String>) {
        self.status = Status::Paused;
        self.pause_reason = Some(why.into());
        self.requesting = false;
    }
    fn active(&mut self) {
        self.pause_reason = None;
        self.status = if self.pending.is_some() {
            Status::Waiting
        } else if self.verifying {
            Status::Verifying
        } else {
            Status::Running
        };
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub task: String,
    pub revision: u64,
    pub session: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Change {
    Request,
    Propose { call_id: String, tool: Tool },
    PrepareCheck,
    RetryChecks,
    Settle,
    Inspect,
    Wait { why: String, running: bool },
    Pause(String),
    Raise(Limits),
    Abandon,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum Record {
    Create {
        id: String,
        session: String,
        checks: Vec<String>,
        limits: Limits,
    },
    Start {
        id: String,
        session: String,
        checks: Vec<String>,
        limits: Limits,
    },
    Change {
        id: String,
        expected: u64,
        change: Change,
    },
    Command {
        binding: Binding,
        intent: Intent,
    },
}

impl<S: Storage> Store<S> {
    pub(crate) fn poc_inference_facts(&self, machine: &str, goal: &str) -> Option<Value> {
        let task = self.poc.values().find(|t| {
            t.machine == machine
                && t.goal == goal
                && !self.ended_sessions.contains(&t.start_session)
        })?;
        let exposure = self
            .exposure_ledger
            .iter()
            .find(|e| e.session == task.start_session)?;
        let approved = self.dispatch.approved_entries.get(machine)?;
        Some(json!({
            "session":task.start_session,
            "task":task.id,
            "goal_source":self.goal(&task.start_session),
            "bound_set":exposure.bound_set.iter().map(|bound| &bound.machine).collect::<Vec<_>>(),
            "approved_entry":{"entry":approved.approved.entry,"access":approved.approved.access},
            "class":approved.class,
            "requirements":approved.requirements.iter().filter(|r| r.session == task.start_session).collect::<Vec<_>>(),
            "requests_consumed":task.requests,
            "steps_consumed":task.steps,
            "limits":task.limits,
            "uncertainty":"Earlier requests without a committed proposal may have lost their responses. Counts are not refunded and imply no machine outcome.",
            "unresolved_commands":self.dispatch.calls.values().filter(|c| c.intent.machine == machine && matches!(c.state, crate::dispatch::CallState::Unresolved)).map(|c| json!({"call":c.intent.call,"job":c.intent.job})).collect::<Vec<_>>()
        }))
    }
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn eligible_tasks(&self) -> Vec<Task> {
        self.poc
            .values()
            .filter(|t| {
                matches!(
                    t.status,
                    Status::Running | Status::Verifying | Status::Waiting
                ) && !self.ended_sessions.contains(&t.start_session)
                    && (t.status != Status::Waiting
                        || t.pending.is_some()
                            && (t.pause_reason.is_none()
                                || t.pause_reason.as_deref() == Some(crate::poc::wait::RUNNING)
                                || t.pause_reason.as_deref().is_some_and(|why| {
                                    why.starts_with("inspecting the recorded job")
                                })))
            })
            .cloned()
            .collect()
    }
    #[cfg(all(target_arch = "wasm32", feature = "tracer"))]
    pub(crate) async fn test_poc_inference_request(
        &mut self,
        machine: &str,
        goal: String,
        completed: Vec<Step>,
    ) -> Result<(Task, String), String> {
        let session = self
            .sessions
            .iter()
            .find(|s| !s.ended.get() && s.bound_set == [machine])
            .ok_or("no admitted fixture session")?
            .identity
            .clone();
        if self.goal(&session).is_none() {
            self.enter_goal(&session, goal.clone(), None).await?;
        }
        let task = match self.poc_session_task(&session) {
            Some(task) => task.clone(),
            None => self.poc_start(&session, vec![]).await?,
        };
        let task = self
            .poc_change(
                &task.id,
                task.revision,
                Change::Raise(Limits {
                    requests: 1000,
                    steps: 2000,
                }),
            )
            .await?;
        let mut task = self
            .poc_change(&task.id, task.revision, Change::Request)
            .await?;
        task.goal = goal;
        task.completed = completed;
        Ok((task, session))
    }

    fn poc_safe(&self, value: &impl Serialize) -> Result<(), String> {
        let value = serde_json::to_value(value).map_err(|_| crate::poc::wait::TASK_ENCODING)?;
        if !crate::redaction::Redacted::inference_value_is_safe(self, &value, &[]) {
            return Err(crate::poc::wait::TASK_BOUNDARY.into());
        }
        Ok(())
    }
    fn poc_record_safe(&self, record: &Record) -> Result<(), String> {
        let event = Event::Poc(record.clone());
        self.poc_safe(&event)?;
        let encoded = Zeroizing::new(
            serde_json::to_vec(&journal(&event)).map_err(|_| crate::poc::wait::TASK_ENCODING)?,
        );
        if crate::redaction::Redacted::for_store(self, &encoded, &[])
            .is_ok_and(|safe| safe.as_bytes() == encoded.as_slice())
        {
            Ok(())
        } else {
            Err(crate::poc::wait::TASK_BOUNDARY.into())
        }
    }
    pub(crate) fn poc_configuration_key(&self, key: &[u8]) -> Result<(), String> {
        let filter = crate::poc::inference::EchoFilter::new(&[key]);
        self.poc_admission(&filter, None, None)?;
        for exposure in self
            .exposure_ledger
            .iter()
            .filter(|e| !self.ended_sessions.contains(&e.session))
        {
            let task = self
                .poc
                .values()
                .find(|t| t.start_session == exposure.session && !t.ended());
            self.poc_admission(&filter, task, Some(exposure))?;
        }
        for task in self
            .poc
            .values()
            .filter(|task| !task.ended() && self.ended_sessions.contains(&task.start_session))
        {
            self.poc_admission(&filter, Some(task), None)?;
        }
        Ok(())
    }

    pub(super) fn poc_adoption_safe(
        &self,
        task: Option<&Task>,
        exposure: Option<&Exposure>,
    ) -> Result<(), String> {
        for filter in self.poc_credential_filters.borrow().iter() {
            self.poc_admission(filter, task, exposure)
                .map_err(|_| "task refused".to_string())?;
        }
        Ok(())
    }

    pub fn poc_task(&self, id: &str) -> Result<Task, String> {
        let task = self.poc.get(id).ok_or(crate::poc::wait::UNKNOWN_TASK)?;
        // Internal orchestration reads durable metadata without releasing the transcript.
        // Reports and inference independently scan their payloads against current custody.
        Ok(task.clone())
    }
    pub(crate) fn check_task_session(&self, task: &Task, session: &str) -> Result<(), String> {
        let current = self
            .poc
            .get(&task.id)
            .ok_or(crate::poc::wait::UNKNOWN_TASK)?;
        if current.revision != task.revision || current.start_session != session || current.ended()
        {
            return Err("stale task session or revision".into());
        }
        let live = self.live_goal_session(session)?;
        if live.bound_set != [task.machine.as_str()] {
            return Err("task binding differs".into());
        }
        Ok(())
    }

    pub fn check_inference_request(&self, task: &Task, session: &str) -> Result<(), String> {
        self.check_task_session(task, session)?;
        self.poc_authority(&task.id, session)?;
        if !task.requesting || task.pending.is_some() || task.proposal.is_some() {
            return Err("no current task request".into());
        }
        Ok(())
    }
    pub fn poc_authority(&self, id: &str, session: &str) -> Result<Rc<Session>, String> {
        let task = self.poc.get(id).ok_or(crate::poc::wait::UNKNOWN_TASK)?;
        if task.ended() {
            return Err(crate::poc::wait::TASK_ENDED.into());
        }
        if task.start_session != session {
            return Err("task requires its original session".into());
        }
        let live = self.live_goal_session(session)?;
        if self
            .poc_session_task(session)
            .is_some_and(|owner| owner.id != id)
        {
            return Err(crate::poc::wait::SESSION_OWNER.into());
        }
        if live.bound_set != [task.machine.as_str()] {
            return Err(crate::poc::wait::BOUND_MACHINE.into());
        }
        if self.pending_requirements.contains_key(session) {
            return Err(crate::poc::wait::APPROVAL_PENDING.into());
        }
        if !self
            .conduct_acceptances
            .iter()
            .any(|a| a.session == session && a.mode == Mode::NoBrief)
        {
            return Err(crate::poc::wait::ACCEPTANCE.into());
        }
        Ok(live)
    }
    fn poc_session_task(&self, session: &str) -> Option<&Task> {
        self.poc.values().find(|t| t.start_session == session)
    }
    fn poc_new_acceptance(&self, session: &str) -> Result<Option<Acceptance>, String> {
        if self
            .conduct_acceptances
            .iter()
            .any(|a| a.session == session && a.mode == Mode::NoBrief)
        {
            return Ok(None);
        }
        let acceptance = Acceptance {
            session: session.into(),
            mode: Mode::NoBrief,
        };
        self.check_acceptance(&acceptance)?;
        Ok(Some(acceptance))
    }
    pub async fn poc_raise(&mut self, id: &str, limits: Limits) -> Result<Task, String> {
        crate::poc::run::check_raise(id)?;
        let task = self.poc_task(id)?;
        self.poc_change(id, task.revision, Change::Raise(limits))
            .await
    }
    pub fn poc_tool(&self, id: &str, session: &str, tool: &Tool) -> Result<(), String> {
        let live = self.poc_authority(id, session)?;
        self.poc_safe(tool)?;
        if !live.bound_set.iter().any(|m| m == tool.machine()) {
            return Err("bound set".into());
        }
        // Reuse the legacy installation check without granting stored goals session authority.
        if matches!(tool, Tool::Exec { .. }) {
            self.dispatch.check_installation(tool.machine())?;
        }
        Ok(())
    }
    /// Record a safe proposal before testing prerequisites for its eventual effect.
    pub async fn poc_propose(
        &mut self,
        task: &Task,
        session: &str,
        call_id: String,
        tool: Tool,
    ) -> Result<Task, String> {
        self.poc_authority(&task.id, session)?;
        self.poc_safe(&tool)?;
        self.poc_change(&task.id, task.revision, Change::Propose { call_id, tool })
            .await
    }

    /// The pinned minimum is only a proposal. The existing approval card must authorize it.
    pub fn poc_prepare_execution(&mut self, task: &Task, session: &str) -> Result<(), String> {
        let tool = &task
            .proposal
            .as_ref()
            .ok_or("missing command proposal")?
            .tool;
        self.poc_authority(&task.id, session)?;
        if self.poc_task(&task.id)?.revision != task.revision || task.pending.is_some() {
            return Err("stale task execution".into());
        }
        if self
            .dispatch
            .approved_entries
            .get(&task.machine)
            .is_some_and(|m| m.declaration.is_none())
        {
            self.propose_requirements(
                session,
                self.next,
                crate::declaration::Proposal::Declaration {
                    machine: task.machine.clone(),
                    declaration: crate::declaration::ad_hoc_minimum(),
                },
                tool,
            )?;
            return Err("installation facts: approved declaration missing; review the proposed requirements, approve explicitly, then Resume".into());
        }
        self.poc_tool(&task.id, session, tool)
    }

    /// Map structured transport reports only after passing the existing protection boundary.
    pub fn poc_refusal(&self, report: &Value) -> String {
        match self.protect_output(report) {
            Ok(safe) => crate::poc::run::refusal_reason(&safe),
            Err(_) => "command refused; diagnostic protection failed; inspect connection and task configuration".into(),
        }
    }
    pub fn poc_collection_reason(&self, pending: &Pending, reports: &[Value]) -> String {
        match self.protect_output(&json!(reports)) {
            Ok(safe) => crate::poc::run::collection_reason(
                pending,
                safe.as_array().expect("protected reports"),
            ),
            Err(_) => {
                crate::poc::wait::COLLECTION_PROTECTION.render(pending.call, &pending.job, "")
            }
        }
    }

    fn poc_check_start(&self, session: &str, checks: &[String]) -> Result<(), String> {
        let live = self.live_goal_session(session)?;
        self.goal(session).ok_or("missing goal")?;
        if live.bound_set.len() != 1 {
            return Err("task start requires exactly one bound machine".into());
        }
        if checks.len() > 16 {
            return Err("too many verification commands; supply at most 16 and start again".into());
        }
        if checks.iter().any(|c| c.trim().is_empty() || c.len() > 8192) {
            return Err("verification commands must contain 1 to 8192 bytes; correct the commands and start again".into());
        }
        self.poc_safe(&checks)?;
        Ok(())
    }
    /// Acceptance and task inputs share one durable boundary, including a lost append reply.
    pub async fn poc_accept_start(
        &mut self,
        session: &str,
        checks: &[String],
    ) -> Result<(), String> {
        self.poc_start(session, checks.to_vec()).await.map(|_| ())
    }
    pub async fn poc_start(&mut self, session: &str, checks: Vec<String>) -> Result<Task, String> {
        self.poc_create_inner(session, checks, true).await
    }
    /// The page lets the operator edit and approve intended requirements before any
    /// request. Resume then chooses the first command against that declaration.
    pub async fn poc_page_start(
        &mut self,
        session: &str,
        checks: Vec<String>,
    ) -> Result<Task, String> {
        let task = self.poc_create(session, checks).await?;
        if self
            .dispatch
            .approved_entries
            .get(&task.machine)
            .is_some_and(|machine| machine.declaration.is_none())
        {
            self.poc_change(
                &task.id,
                task.revision,
                Change::Pause(
                    "propose and explicitly approve the installation declaration, then Resume"
                        .into(),
                ),
            )
            .await
        } else {
            Ok(task)
        }
    }
    pub async fn poc_create(&mut self, session: &str, checks: Vec<String>) -> Result<Task, String> {
        self.poc_create_inner(session, checks, false).await
    }
    async fn poc_create_inner(
        &mut self,
        session: &str,
        checks: Vec<String>,
        accept: bool,
    ) -> Result<Task, String> {
        self.poc_check_start(session, &checks)?;
        if self.pending_requirements.contains_key(session) {
            return Err("proposal approval pending".into());
        }
        if let Some(task) = self.poc_session_task(session) {
            if task.checks != checks {
                return Err("accepted start already has verification checks".into());
            }
            return self.poc_task(&task.id);
        }
        let id = hex::encode(random::<24>()?);
        let session = session.into();
        let limits = Limits::default();
        let record = if accept {
            Record::Start {
                id,
                session,
                checks,
                limits,
            }
        } else {
            self.check_goal_start(&session)?;
            Record::Create {
                id,
                session,
                checks,
                limits,
            }
        };
        let task = self.project_poc(self.next, &record)?;
        self.poc_safe(&task)?;
        self.poc_record_safe(&record)?;
        self.poc_adoption_safe(Some(&task), None)?;
        let number = self.commit(&Event::Poc(record.clone())).await?;
        self.apply_poc(number, &record)?;
        Ok(task)
    }
    pub async fn poc_change(
        &mut self,
        id: &str,
        expected: u64,
        mut change: Change,
    ) -> Result<Task, String> {
        match &mut change {
            Change::Pause(why) | Change::Wait { why, .. } => {
                *why = self
                    .protect_output(&json!(why))
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_else(|| crate::poc::wait::FALLBACK.into());
            }
            _ => {}
        }
        // Pauses and excerpts are data too. Refuse rather than persist a transformed command.
        let record = Record::Change {
            id: id.into(),
            expected,
            change,
        };
        self.poc_record_safe(&record)?;
        let task = self.project_poc(self.next, &record)?;
        self.commit(&Event::Poc(record)).await?;
        self.poc.insert(id.into(), task.clone());
        Ok(task)
    }
    /// A terminal awaiting its task checkpoint still needs a full current-inventory
    /// release. This durable barrier survives loss of the volatile response reservation.
    pub fn poc_configuration_ready(&self) -> Result<(), String> {
        for task in self.poc.values().filter(|task| !task.ended()) {
            let report = task
                .pending
                .as_ref()
                .and_then(|pending| self.poc_committed(pending));
            if let Some(report) =
                report.filter(|report| report.state == crate::jobs::State::Finished)
            {
                if !matches!(report.comparison, crate::jobs::Comparison::AdvisoryMatch) {
                    return Err("inference configuration refused: recorded task result differs from its intent and cannot checkpoint; inspect the finding, then Stop task before configuring; remote effects and command holds remain".into());
                }
                return Err("inference configuration refused: recorded task result awaits recovery; Resume collection in the original session before configuring; then retry configuration".into());
            }
        }
        Ok(())
    }
    pub fn poc_committed(&self, pending: &Pending) -> Option<&crate::jobs::Report> {
        self.dispatch
            .jobs
            .iter()
            .rev()
            .find(|r| r.evidence.call == pending.call && r.evidence.job == pending.job)
    }
    pub fn poc_binding_current(&self, binding: &Binding) -> Result<(), String> {
        self.poc_authority(&binding.task, &binding.session)?;
        let task = self
            .poc
            .get(&binding.task)
            .ok_or(crate::poc::wait::UNKNOWN_TASK)?;
        // After append, current authority also gates the final send and response boundary.
        let revision = if task.pending.is_some() {
            binding.revision.checked_add(1)
        } else {
            Some(binding.revision)
        };
        if revision != Some(task.revision) {
            return Err("stale task command".into());
        }
        Ok(())
    }
    pub async fn poc_append(
        &mut self,
        binding: &Binding,
        entry: &Entry,
        approval: &Approval,
    ) -> Result<u64, AppendRefusal> {
        self.poc_binding_current(binding)
            .map_err(AppendRefusal::Storage)?;
        let task = self
            .poc_task(&binding.task)
            .map_err(AppendRefusal::Storage)?;
        let proposal = task
            .proposal
            .as_ref()
            .ok_or_else(|| AppendRefusal::Storage("missing task proposal".into()))?;
        self.poc_tool(&binding.task, &binding.session, &proposal.tool)
            .map_err(AppendRefusal::Storage)?;
        if task.pending.is_some()
            || task.revision != binding.revision
            || entry.provenance.as_ref().and_then(|p| p.session.as_deref())
                != Some(&binding.session)
        {
            return Err(AppendRefusal::Storage("stale task command".into()));
        }
        self.check_signature(&entry.machine, &entry.command).await?;
        self.check(&entry.machine).await?;
        let intent = Intent {
            call: self.next,
            machine: entry.machine.clone(),
            command: hex::encode(&entry.command),
            approval: Some(approval.clone()),
            job: Some(hex::encode(random::<24>().map_err(AppendRefusal::Storage)?)),
            provenance: entry.provenance.clone(),
        };
        let record = Record::Command {
            binding: binding.clone(),
            intent,
        };
        self.project_poc(self.next, &record)
            .map_err(AppendRefusal::Storage)?;
        self.poc_record_safe(&record)
            .map_err(AppendRefusal::Storage)?;
        let number = self
            .commit(&Event::Poc(record.clone()))
            .await
            .map_err(AppendRefusal::Storage)?;
        self.apply_poc(number, &record)
            .expect("validated task intent applies after commit");
        Ok(number)
    }
    pub(super) fn apply_poc(&mut self, number: u64, record: &Record) -> Result<(), String> {
        // Validate the new record, not previously committed transcript bytes. Settle
        // protects its derived outcome separately before checkpointing it.
        self.poc_record_safe(record)?;
        let task = self.project_poc(number, record)?;
        if let Record::Command { intent, .. } = record {
            self.apply_intent(number, intent.clone())?;
        }
        if let Record::Start { session, .. } = record
            && let Some(acceptance) = self.poc_new_acceptance(session)?
        {
            self.conduct_acceptances.push(acceptance);
        }
        self.poc.insert(task.id.clone(), task);
        Ok(())
    }
    fn project_poc(&self, number: u64, record: &Record) -> Result<Task, String> {
        if let Record::Create {
            id,
            session,
            checks,
            limits,
        }
        | Record::Start {
            id,
            session,
            checks,
            limits,
        } = record
        {
            if matches!(record, Record::Start { .. }) {
                self.poc_new_acceptance(session)?;
            }
            let goal = self.goal(session).ok_or("task requires recorded goal")?;
            let exposure = self
                .exposure_ledger
                .iter()
                .find(|e| e.session == *session)
                .ok_or("task requires binding")?;
            if self.ended_sessions.contains(session)
                || id.len() != 48
                || hex::decode(id).is_err()
                || self.poc.contains_key(id)
                || self.poc_session_task(session).is_some()
                || exposure.bound_set.len() != 1
                || checks.len() > 16
                || checks.iter().any(|c| c.trim().is_empty() || c.len() > 8192)
                || limits.requests == 0
                || limits.steps == 0
                || (matches!(record, Record::Create { .. })
                    && !self
                        .conduct_acceptances
                        .iter()
                        .any(|a| a.session == *session && a.mode == Mode::NoBrief))
            {
                return Err("invalid task creation".into());
            }
            return Ok(Task {
                id: id.clone(),
                start_session: session.clone(),
                goal: goal.text.clone(),
                machine: exposure.bound_set[0].machine.clone(),
                approved_plan: None,
                completed: vec![],
                proposal: None,
                pending: None,
                status: Status::Running,
                pause_reason: None,
                requests: 0,
                steps: 0,
                limits: limits.clone(),
                checks: checks.clone(),
                verification: vec![],
                verifying: false,
                requesting: false,
                revision: 0,
            });
        }
        let (id, expected) = match record {
            Record::Change { id, expected, .. } => (id, *expected),
            Record::Command { binding, .. } => (&binding.task, binding.revision),
            _ => unreachable!(),
        };
        let mut task = self
            .poc
            .get(id)
            .ok_or(crate::poc::wait::UNKNOWN_TASK)?
            .clone();
        if task.revision != expected || task.ended() {
            return Err(crate::poc::wait::STALE_TASK.into());
        }
        if self.ended_sessions.contains(&task.start_session)
            && !matches!(
                record,
                Record::Change {
                    change: Change::Abandon,
                    ..
                }
            )
        {
            return Err("task session ended".into());
        }
        match record {
            Record::Command { binding, intent } => {
                let proposal = task.proposal.as_ref().ok_or("missing task proposal")?;
                let Tool::Exec { machine, command } = &proposal.tool else {
                    return Err("task command tool".into());
                };
                if binding.session != task.start_session
                    || self.ended_sessions.contains(&binding.session)
                    || task.pending.is_some()
                    || task.requesting
                    || intent.call != number
                    || intent.machine != task.machine
                    || machine != &task.machine
                    || intent.command != hex::encode(command)
                    || intent.provenance.as_ref().is_none_or(|p| {
                        p.session.as_ref() != Some(&binding.session)
                            || p.target != crate::dispatch::Target::Entry(task.machine.clone())
                            || p.requester != crate::dispatch::Requester::Session
                    })
                {
                    return Err("task command association differs".into());
                }
                let job = intent
                    .job
                    .as_ref()
                    .ok_or("task command requires job identity")?
                    .clone();
                let mut dispatch = self.dispatch.clone();
                dispatch.intent(number, intent.clone())?;
                task.pending = Some(Pending {
                    call: number,
                    job: job.clone(),
                });
                if let Some(index) = proposal.check {
                    if index != task.verification.len() {
                        return Err("verification order".into());
                    }
                    task.verification.push(Verification {
                        command: command.clone(),
                        job,
                        exit_status: None,
                        excerpt: String::new(),
                    });
                }
                task.active();
            }
            Record::Change { change, .. } => match change {
                Change::Abandon => {
                    task.status = Status::Abandoned;
                    task.pause_reason = Some(
                        "local orchestration abandoned; remote effects and command holds remain"
                            .into(),
                    );
                    task.requesting = false;
                }
                Change::Pause(why) => {
                    if why.trim().is_empty() {
                        return Err("empty pause".into());
                    }
                    task.pause(why);
                }
                Change::Raise(limits) => {
                    if limits.requests < task.limits.requests
                        || limits.steps < task.limits.steps
                        || limits.requests > 1000
                        || limits.steps > 2000
                    {
                        return Err(
                            "limits may only increase, up to 1000 requests and 2000 steps".into(),
                        );
                    }
                    task.limits = limits.clone();
                }
                Change::Request => {
                    if task.pending.is_some() || task.proposal.is_some() || task.verifying {
                        return Err("task has a next action already".into());
                    }
                    task.requesting = false;
                    if task.steps >= task.limits.steps {
                        task.pause("step limit reached; raise limits and Resume");
                    } else if task.requests >= task.limits.requests {
                        task.pause("request limit reached; raise limits and Resume");
                    } else {
                        task.requests += 1;
                        task.requesting = true;
                        task.active();
                    }
                }
                Change::Propose { call_id, tool } => {
                    if !task.requesting || task.pending.is_some() || task.proposal.is_some() {
                        return Err("no current task request".into());
                    }
                    task.requesting = false;
                    let wire = serde_json::to_value(tool).map_err(|_| "tool encoding")?;
                    Tool::parse(&wire)?;
                    if call_id.is_empty()
                        || call_id.len() > 256
                        || call_id.starts_with('$')
                        || task.completed.iter().any(|(id, _, _)| id == call_id)
                    {
                        return Err("invalid or duplicate task call ID".into());
                    }
                    if task.steps >= task.limits.steps {
                        task.pause("step limit reached; raise limits and Resume");
                    } else {
                        task.steps += 1;
                        task.active();
                        if tool.machine() != task.machine {
                            task.completed.push((
                                call_id.clone(),
                                tool.clone(),
                                crate::goals::untrusted(
                                    "tool_output",
                                    json!({"refused":"bound set"}),
                                ),
                            ));
                        } else {
                            match tool {
                                Tool::Exec { .. } => {
                                    task.proposal = Some(Proposal {
                                        call_id: call_id.clone(),
                                        tool: tool.clone(),
                                        check: None,
                                    });
                                }
                                Tool::Done { .. } => {
                                    task.verifying = true;
                                    task.status = Status::Verifying;
                                    task.completed.push((
                                        call_id.clone(),
                                        tool.clone(),
                                        crate::goals::untrusted(
                                            "tool_output",
                                            json!({"verification_required":true}),
                                        ),
                                    ));
                                }
                                Tool::Job { .. } | Tool::Typed { .. } => {
                                    task.completed.push((call_id.clone(), tool.clone(), crate::goals::untrusted("tool_output", json!({"unavailable":"operation unavailable in this task runner"}))));
                                }
                            }
                        }
                    }
                }
                Change::RetryChecks => {
                    if !task.verifying || task.pending.is_some() || task.proposal.is_some() {
                        return Err("verification retry requires a settled failed check".into());
                    }
                    let index = task
                        .verification
                        .iter()
                        .position(|v| v.exit_status.is_some_and(|exit| exit != 0))
                        .ok_or("no settled failed verification check")?;
                    // Completed attempts retain their original job and outcome. Only the
                    // latest verification sequence is restarted by this explicit action.
                    task.verification.truncate(index);
                    task.active();
                }
                Change::PrepareCheck => {
                    if !task.verifying || task.proposal.is_some() || task.pending.is_some() {
                        return Err("verification not ready".into());
                    }
                    if task.checks.is_empty() {
                        task.pause(
                            "no verification checks supplied; success cannot be established",
                        );
                    } else if task.verification.iter().any(|v| v.exit_status != Some(0)) {
                        task.pause("verification failed or has no trustworthy exit status");
                    } else if task.verification.len() == task.checks.len() {
                        task.status = Status::Complete;
                        task.pause_reason = None;
                    } else if task.steps >= task.limits.steps {
                        task.pause(
                            "step limit reached during verification; raise limits and Resume",
                        );
                    } else {
                        let index = task.verification.len();
                        task.steps += 1;
                        task.proposal = Some(Proposal {
                            call_id: if task
                                .completed
                                .iter()
                                .any(|(id, _, _)| id == &format!("$verify:{index}"))
                            {
                                format!("$verify:{index}:{}", task.steps)
                            } else {
                                format!("$verify:{index}")
                            },
                            tool: Tool::Exec {
                                machine: task.machine.clone(),
                                command: task.checks[index].clone(),
                            },
                            check: Some(index),
                        });
                        task.active();
                    }
                }
                Change::Inspect => {
                    if task.pending.is_none() {
                        return Err("inspection requires pending identity".into());
                    }
                    task.active();
                    task.pause_reason = Some("inspecting the recorded job; collection may wait for completion; an active collection must finish or be interrupted before Resume".into());
                }
                Change::Settle => {
                    let pending = task.pending.as_ref().ok_or(crate::poc::wait::NO_PENDING)?;
                    let report = self
                        .poc_committed(pending)
                        .ok_or(crate::poc::wait::NO_EVIDENCE)?;
                    if report.state != crate::jobs::State::Finished
                        || !matches!(report.comparison, crate::jobs::Comparison::AdvisoryMatch)
                    {
                        return Err(crate::poc::wait::UNTRUSTWORTHY.into());
                    }
                    let proposal = task.proposal.take().ok_or(crate::poc::wait::NO_PROPOSAL)?;
                    let exit = report.exit_status.ok_or(crate::poc::wait::NO_EXIT)?;
                    let outcome = json!({"call":pending.call,"job":pending.job,"exit_status":exit,"stdout":report.stdout,"stderr":report.stderr});
                    // The checkpoint derives from already committed, protected evidence. Do not
                    // make its bytes depend on credentials that disappear at worker restart.
                    if self.protect_output(&outcome)? != outcome {
                        return Err(crate::poc::wait::CHECKPOINT_PROTECTION.into());
                    }
                    if let Some(index) = proposal.check {
                        let check = task
                            .verification
                            .get_mut(index)
                            .ok_or(crate::poc::wait::NO_VERIFICATION)?;
                        if check.job != pending.job || check.exit_status.is_some() {
                            return Err(crate::poc::wait::VERIFICATION_MISMATCH.into());
                        }
                        check.exit_status = Some(exit);
                        // Protect complete output before taking the excerpt, then protect it again.
                        check.excerpt = outcome["stdout"]
                            .as_str()
                            .unwrap_or_default()
                            .chars()
                            .take(1024)
                            .collect();
                        if self.protect_output(&json!(check.excerpt))? != json!(check.excerpt) {
                            return Err(crate::poc::wait::EXCERPT_PROTECTION.into());
                        }
                    }
                    task.completed.push((
                        proposal.call_id,
                        proposal.tool,
                        crate::goals::untrusted("tool_output", outcome),
                    ));
                    task.pending = None;
                    task.active();
                    if task.verifying && exit != 0 {
                        task.pause("verification command failed; inspect the recorded result");
                    }
                }
                Change::Wait { why, running } => {
                    if task.pending.is_none() || why.trim().is_empty() {
                        return Err("waiting requires pending identity and reason".into());
                    }
                    task.pause(why);
                    if *running {
                        task.status = Status::Waiting;
                    }
                }
            },
            _ => unreachable!(),
        }
        task.revision = task
            .revision
            .checked_add(1)
            .ok_or(crate::poc::wait::REVISION_EXHAUSTED)?;
        Ok(task)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(super) mod tests;

mod admission;
