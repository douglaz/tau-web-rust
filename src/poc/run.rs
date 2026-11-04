//! Durable actions run serially. Every turn rebuilds its input from the journal.
use crate::goals::Tool;
use crate::store::poc::{Binding, Change, Status, Task};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::future::Future;

thread_local! {
    static ACTIVE: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
}
struct Active(String);
impl Drop for Active {
    fn drop(&mut self) {
        ACTIVE.with_borrow_mut(|set| set.remove(&self.0));
    }
}
pub(crate) fn check_raise(id: &str) -> Result<(), String> {
    if ACTIVE.with_borrow(|set| set.contains(id)) {
        return Err("task action already active; raise limits after it pauses or waits".into());
    }
    Ok(())
}

/// The commit future must release its writer before returning. Publishing may acquire that
/// writer again; the existing command path rechecks authority and revision before sending.
pub async fn commit_command(
    commit: impl Future<Output = Result<u64, crate::harness::AppendRefusal>>,
    progress: impl Future<Output = ()>,
) -> Result<u64, crate::harness::AppendRefusal> {
    let call = commit.await?;
    progress.await;
    Ok(call)
}

/// Retain an early refusal from the protected store report alongside the durable identity.
pub fn page_outcome(id: &str, report: &Value) -> Value {
    let mut outcome = serde_json::json!({"task":id});
    if let Some(error) = report.get("error") {
        outcome["refused"] = error.clone();
    }
    outcome
}

#[allow(async_fn_in_trait, reason = "single worker or host fixture")]
pub trait Model {
    async fn next(
        &mut self,
        goal: &str,
        machine: &str,
        completed: &[(String, Tool, Value)],
    ) -> Result<(String, Tool), String>;
}

pub struct Unconfigured;
impl Model for Unconfigured {
    async fn next(
        &mut self,
        _: &str,
        _: &str,
        _: &[(String, Tool, Value)],
    ) -> Result<(String, Tool), String> {
        Err("no inference endpoint configured".into())
    }
}

pub enum Observation {
    Committed,
    Running,
    Unknown(String),
}

/// Implementations take the store writer only for an individual transaction. Execution uses
/// the existing command journal; inspection collects the pending identity and never launches.
#[allow(async_fn_in_trait, reason = "single worker or host fixture")]
pub trait Runtime {
    async fn progress(&mut self, _task: &Task) {}
    async fn load(&mut self, id: &str) -> Result<Task, String>;
    async fn authority(&mut self, id: &str, session: &str) -> Result<(), String>;
    async fn change(&mut self, task: &Task, change: Change) -> Result<Task, String>;
    async fn propose(
        &mut self,
        task: &Task,
        session: &str,
        call_id: String,
        tool: Tool,
    ) -> Result<Task, String>;
    async fn execute(&mut self, binding: Binding, task: &Task) -> Result<(), String>;
    async fn observe(&mut self, task: &Task, session: &str) -> Result<Observation, String>;
}

/// Continue only after the previous action has checkpointed. Budgets bound unavailable and
/// refused proposals too; waiting or uncertain jobs always return to the operator.
pub async fn drive(
    runtime: &mut impl Runtime,
    model: &mut impl Model,
    id: &str,
    session: &str,
) -> Result<Task, String> {
    if !ACTIVE.with_borrow_mut(|set| set.insert(id.into())) {
        return Err("task action already active".into());
    }
    let _active = Active(id.into());
    loop {
        let task = resume(runtime, model, id, session).await?;
        runtime.progress(&task).await;
        if task.pending.is_some() || !matches!(task.status, Status::Running | Status::Verifying) {
            return Ok(task);
        }
    }
}

/// Advance one action, also usable independently by fixtures and incremental callers.
pub async fn resume(
    runtime: &mut impl Runtime,
    model: &mut impl Model,
    id: &str,
    session: &str,
) -> Result<Task, String> {
    let mut task = runtime.load(id).await?;
    if task.ended() {
        return Ok(task);
    }
    runtime.progress(&task).await;
    if runtime.authority(id, session).await.is_err() {
        return runtime
            .change(
                &task,
                Change::Pause(
                    "fresh accepted session authority for the task machine is required".into(),
                ),
            )
            .await;
    }
    if task.pending.is_some() {
        return inspect(runtime, &task, session).await;
    }
    if task.proposal.is_none() {
        if task.verifying {
            task = runtime.change(&task, Change::PrepareCheck).await?;
        } else {
            task = runtime.change(&task, Change::Request).await?;
            if !task.requesting {
                return Ok(task);
            }
            // The durable request count is consumed even if this future is lost.
            let next = model.next(&task.goal, &task.machine, &task.completed).await;
            if runtime.authority(id, session).await.is_err() {
                return pause_authority(runtime, &task).await;
            }
            task = match next {
                Ok((call_id, tool)) => match runtime.propose(&task, session, call_id, tool).await {
                    Ok(task) => task,
                    Err(_) => {
                        return runtime
                            .change(
                                &task,
                                Change::Pause(
                                    "invalid, duplicate or unsafe tool proposal refused".into(),
                                ),
                            )
                            .await;
                    }
                },
                Err(why) => return runtime.change(&task, Change::Pause(why)).await,
            };
        }
    }
    if task.proposal.is_some() {
        runtime.progress(&task).await;
        if runtime.authority(id, session).await.is_err() {
            return pause_authority(runtime, &task).await;
        }
        let binding = Binding {
            task: id.into(),
            revision: task.revision,
            session: session.into(),
        };
        let result = runtime.execute(binding, &task).await;
        // A command may have committed its intent or terminal before losing its response.
        // Neither the return value nor an absent unresolved-collector entry settles it.
        let current = runtime.load(id).await?;
        if current.ended() {
            return Ok(current);
        }
        if current.pending.is_some() {
            return inspect(runtime, &current, session).await;
        }
        if current.revision != task.revision {
            return Err("stale task execution".into());
        }
        return runtime
            .change(
                &current,
                Change::Pause(match result {
                    Err(why) => why,
                    Ok(()) => "command returned without a durable task intent".into(),
                }),
            )
            .await;
    }
    Ok(task)
}

async fn inspect(runtime: &mut impl Runtime, task: &Task, session: &str) -> Result<Task, String> {
    if runtime.authority(&task.id, session).await.is_err() {
        return pause_authority(runtime, task).await;
    }
    let observation = runtime.observe(task, session).await;
    // Rechecking the original revision also rejects Abandon or another Resume's outcome.
    if runtime.authority(&task.id, session).await.is_err() {
        return pause_authority(runtime, task).await;
    }
    match observation {
        Ok(Observation::Committed) => match runtime.change(task, Change::Settle).await {
            Ok(task) => Ok(task),
            Err(why) => {
                runtime
                    .change(
                        task,
                        Change::Wait {
                            why: format!("recorded result could not be checkpointed: {why}"),
                            running: false,
                        },
                    )
                    .await
            }
        },
        Ok(Observation::Running) => {
            runtime
                .change(
                    task,
                    Change::Wait {
                        why: "recorded job is running; Resume inspects it again".into(),
                        running: true,
                    },
                )
                .await
        }
        Ok(Observation::Unknown(why)) | Err(why) => {
            runtime
                .change(
                    task,
                    Change::Wait {
                        why,
                        running: false,
                    },
                )
                .await
        }
    }
}

async fn pause_authority(runtime: &mut impl Runtime, task: &Task) -> Result<Task, String> {
    runtime
        .change(
            task,
            Change::Pause(
                "fresh accepted session authority for the task machine is required".into(),
            ),
        )
        .await
}
