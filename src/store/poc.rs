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
    #[serde(default)]
    pub continuation_sessions: Vec<String>,
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
    Authorize {
        id: String,
        expected: u64,
        session: String,
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
    fn poc_safe(&self, value: &impl Serialize) -> Result<(), String> {
        let value = serde_json::to_value(value).map_err(|_| "task encoding")?;
        if !crate::redaction::Redacted::inference_value_is_safe(self, &value, &[]) {
            return Err("task credential boundary".into());
        }
        Ok(())
    }
    pub fn poc_task(&self, id: &str) -> Result<Task, String> {
        let task = self.poc.get(id).ok_or("unknown task")?;
        // Recheck on every rebuilt transcript, including newly held credentials.
        self.poc_safe(task)?;
        Ok(task.clone())
    }
    pub fn poc_authority(&self, id: &str, session: &str) -> Result<Rc<Session>, String> {
        let task = self.poc.get(id).ok_or("unknown task")?;
        if task.ended() {
            return Err("task ended".into());
        }
        let live = self.live_goal_session(session)?;
        if self
            .poc_session_task(session)
            .is_some_and(|owner| owner.id != id)
        {
            return Err("session authority belongs to another task; bind a fresh session".into());
        }
        if live.bound_set != [task.machine.as_str()] {
            return Err("fresh authority must bind only the task machine".into());
        }
        if self.pending_requirements.contains_key(session) {
            return Err("proposal approval pending; review the open requirements card and approve explicitly or reject before Resume".into());
        }
        if !self
            .conduct_acceptances
            .iter()
            .any(|a| a.session == session && a.mode == Mode::NoBrief)
        {
            return Err(
                "fresh session requires acceptance of Acting on a goal with no brief".into(),
            );
        }
        Ok(live)
    }
    pub async fn poc_authorize(&mut self, id: &str, session: &str) -> Result<(), String> {
        let task = self.poc_task(id)?;
        if task.ended() {
            return Err("task ended".into());
        }
        let live = self.live_goal_session(session)?;
        if live.bound_set != [task.machine.as_str()] {
            return Err("fresh authority must bind only the task machine".into());
        }
        if let Some(owner) = self.poc_session_task(session) {
            if owner.id != id {
                return Err("session already belongs to another task; bind a fresh session".into());
            }
            return self.poc_authority(id, session).map(|_| ());
        }
        if self.goal(session).is_none() {
            self.enter_goal(session, task.goal.clone(), None).await?;
        }
        let record = Record::Authorize {
            id: id.into(),
            expected: task.revision,
            session: session.into(),
        };
        self.project_poc(self.next, &record)?;
        let number = self.commit(&Event::Poc(record.clone())).await?;
        self.apply_poc(number, &record)
    }
    fn poc_session_task(&self, session: &str) -> Option<&Task> {
        self.poc.values().find(|t| {
            t.start_session == session || t.continuation_sessions.iter().any(|s| s == session)
        })
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
            Err(_) => format!(
                "collection failed for pending call {} job {}: diagnostic protection failed; pending identity retained",
                pending.call, pending.job
            ),
        }
    }

    fn poc_check_start(&self, session: &str, checks: &[String]) -> Result<(), String> {
        let live = self.live_goal_session(session)?;
        if let Some(task) = self.poc_session_task(session)
            && task.start_session != session
        {
            return Err(format!(
                "session is authorized to continue task {}; use Resume for that task or bind a fresh session to explicitly start new work",
                task.id
            ));
        }
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
                *why = self.protect_output(&json!(why)).ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_else(|| "task paused: diagnostic protection failed; inspect authority and configuration before Resume".into());
            }
            _ => {}
        }
        // Pauses and excerpts are data too. Refuse rather than persist a transformed command.
        self.poc_safe(&change)?;
        let record = Record::Change {
            id: id.into(),
            expected,
            change,
        };
        let task = self.project_poc(self.next, &record)?;
        self.poc_safe(&task)?;
        self.commit(&Event::Poc(record)).await?;
        self.poc.insert(id.into(), task.clone());
        Ok(task)
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
        let task = self.poc.get(&binding.task).ok_or("unknown task")?;
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
        let task = self
            .project_poc(self.next, &record)
            .map_err(AppendRefusal::Storage)?;
        self.poc_safe(&task).map_err(AppendRefusal::Storage)?;
        let number = self
            .commit(&Event::Poc(record.clone()))
            .await
            .map_err(AppendRefusal::Storage)?;
        self.apply_poc(number, &record)
            .expect("validated task intent applies after commit");
        Ok(number)
    }
    pub(super) fn apply_poc(&mut self, number: u64, record: &Record) -> Result<(), String> {
        let task = self.project_poc(number, record)?;
        self.poc_safe(&task)?;
        if let Record::Command { intent, .. } = record {
            self.apply_intent(number, intent.clone())?;
        }
        if let Record::Start { session, .. } | Record::Authorize { session, .. } = record
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
            if id.len() != 48
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
                continuation_sessions: vec![],
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
            Record::Change { id, expected, .. } | Record::Authorize { id, expected, .. } => {
                (id, *expected)
            }
            Record::Command { binding, .. } => (&binding.task, binding.revision),
            _ => unreachable!(),
        };
        let mut task = self.poc.get(id).ok_or("unknown task")?.clone();
        if task.revision != expected || task.ended() {
            return Err("stale or ended task".into());
        }
        match record {
            Record::Authorize { session, .. } => {
                let exposure = self
                    .exposure_ledger
                    .iter()
                    .find(|e| e.session == *session)
                    .ok_or("task continuation requires binding")?;
                if self.poc_session_task(session).is_some()
                    || exposure.bound_set.len() != 1
                    || exposure.bound_set[0].machine != task.machine
                    || self.goal(session).is_none_or(|g| g.text != task.goal)
                {
                    return Err(
                        "task continuation session differs or already belongs to a task".into(),
                    );
                }
                self.poc_new_acceptance(session)?;
                task.continuation_sessions.push(session.clone());
            }
            Record::Command { binding, intent } => {
                let proposal = task.proposal.as_ref().ok_or("missing task proposal")?;
                let Tool::Exec { machine, command } = &proposal.tool else {
                    return Err("task command tool".into());
                };
                if task.pending.is_some()
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
                            call_id: format!("$verify:{index}"),
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
                    let pending = task.pending.as_ref().ok_or("task has no pending job")?;
                    let report = self
                        .poc_committed(pending)
                        .ok_or("no committed job evidence")?;
                    if report.state != crate::jobs::State::Finished
                        || !matches!(report.comparison, crate::jobs::Comparison::AdvisoryMatch)
                    {
                        return Err("job outcome is not trustworthy".into());
                    }
                    let proposal = task.proposal.take().ok_or("pending task has no proposal")?;
                    let exit = report.exit_status.ok_or("missing job exit")?;
                    let outcome = json!({"call":pending.call,"job":pending.job,"exit_status":exit,"stdout":report.stdout,"stderr":report.stderr});
                    // The checkpoint derives from already committed, protected evidence. Do not
                    // make its bytes depend on credentials that disappear at worker restart.
                    if self.protect_output(&outcome)? != outcome {
                        return Err(
                            "recorded job output requires protection before checkpoint".into()
                        );
                    }
                    if let Some(index) = proposal.check {
                        let check = task
                            .verification
                            .get_mut(index)
                            .ok_or("missing verification record")?;
                        if check.job != pending.job || check.exit_status.is_some() {
                            return Err("verification job mismatch".into());
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
                            return Err(
                                "verification excerpt requires protection before checkpoint".into(),
                            );
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
            .ok_or("task revision exhausted")?;
        Ok(task)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
