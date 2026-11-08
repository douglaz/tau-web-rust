//! Durable actions run serially. Every turn rebuilds its input from the journal.
use crate::goals::Tool;
use crate::store::poc::{Binding, Change, Status, Task};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::future::Future;

thread_local! {
    static ACTIVE: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
    static WAKE_PENDING: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
}
struct Active(String);
impl Drop for Active {
    fn drop(&mut self) {
        ACTIVE.with_borrow_mut(|set| set.remove(&self.0));
        if WAKE_PENDING.with_borrow_mut(|set| set.remove(&self.0)) {
            #[cfg(target_arch = "wasm32")]
            crate::poc::web::wake();
        }
    }
}
#[cfg(target_arch = "wasm32")]
pub(crate) fn defer_if_active(id: &str) -> bool {
    let active = ACTIVE.with_borrow(|set| set.contains(id));
    if active {
        WAKE_PENDING.with_borrow_mut(|set| set.insert(id.into()));
    }
    active
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
    async fn ready(&mut self, _task: &Task, _session: &str) -> Result<(), String> {
        Ok(())
    }
    async fn next(&mut self, task: &Task, session: &str) -> Result<(String, Tool), String>;
}

pub struct Unconfigured;
impl Model for Unconfigured {
    async fn next(&mut self, _: &Task, _: &str) -> Result<(String, Tool), String> {
        Err("no inference endpoint configured".into())
    }
}

pub enum Observation {
    Committed,
    Running,
    Unknown(String),
}

/// Classify durable terminal evidence before the worker publishes its protected result.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn committed_observation(report: &crate::jobs::Report) -> Option<Observation> {
    if report.state != crate::jobs::State::Finished {
        return None;
    }
    Some(
        if matches!(report.comparison, crate::jobs::Comparison::AdvisoryMatch) {
            Observation::Committed
        } else {
            Observation::Unknown(crate::poc::wait::COMMITTED_MISMATCH.into())
        },
    )
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
        return Err("task action already active; collection may be waiting for the recorded job; let it finish or interrupt the session before Resume".into());
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
    if let Err(why) = runtime.authority(id, session).await {
        return pause_authority(runtime, &task, why).await;
    }
    if task.pending.is_some() {
        return inspect(runtime, &task, session).await;
    }
    if task.proposal.is_none() {
        if task.verifying {
            task = runtime.change(&task, Change::PrepareCheck).await?;
        } else {
            model.ready(&task, session).await?;
            task = runtime.change(&task, Change::Request).await?;
            if !task.requesting {
                return Ok(task);
            }
            // The durable request count is consumed even if this future is lost.
            let next = model.next(&task, session).await;
            if let Err(why) = runtime.authority(id, session).await {
                return pause_authority(runtime, &task, why).await;
            }
            task = match next {
                Ok((call_id, tool)) => match runtime.propose(&task, session, call_id, tool).await {
                    Ok(task) => task,
                    Err(why) => {
                        return runtime
                            .change(&task, Change::Pause(concrete_pause(why)))
                            .await;
                    }
                },
                Err(why) => {
                    return runtime
                        .change(&task, Change::Pause(concrete_pause(why)))
                        .await;
                }
            };
        }
    }
    if task.proposal.is_some() {
        runtime.progress(&task).await;
        if let Err(why) = runtime.authority(id, session).await {
            return pause_authority(runtime, &task, why).await;
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
    if let Err(why) = runtime.authority(&task.id, session).await {
        return pause_authority(runtime, task, why).await;
    }
    let inspecting = runtime.change(task, Change::Inspect).await?;
    runtime.progress(&inspecting).await;
    let task = &inspecting;
    let observation = runtime.observe(task, session).await;
    // Rechecking the inspection revision also rejects Abandon or another Resume's outcome.
    if let Err(why) = runtime.authority(&task.id, session).await {
        return pause_authority(runtime, task, why).await;
    }
    match observation {
        Ok(Observation::Committed) => match runtime.change(task, Change::Settle).await {
            Ok(task) => Ok(task),
            Err(why) => {
                runtime
                    .change(
                        task,
                        Change::Wait {
                            why: crate::poc::wait::checkpoint(&why),
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
                        why: crate::poc::wait::RUNNING.into(),
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

async fn pause_authority(
    runtime: &mut impl Runtime,
    task: &Task,
    why: String,
) -> Result<Task, String> {
    runtime
        .change(
            task,
            Change::Pause(if why.starts_with("proposal approval pending") {
                why
            } else {
                format!(
                    "original accepted session authority for the task machine is required: {}",
                    concrete_pause(why)
                )
            }),
        )
        .await
}

fn concrete_pause(why: String) -> String {
    if why.trim().is_empty() {
        "inference returned no usable pause reason; configure inference and Resume".into()
    } else {
        why
    }
}

/// Render selected structured causes; callers protect the report before rendering diagnostics.
pub fn refusal_reason(report: &Value) -> String {
    let category = report["refused"].as_str().unwrap_or_else(|| {
        if report["held"] == true {
            "held"
        } else if report["unresolved"] == true {
            "unresolved"
        } else if report["historical"] == true {
            "historical"
        } else {
            "command"
        }
    });
    if matches!(category, "held" | "command-held")
        && let Some(failed) = report["calls"].as_array().and_then(|calls| {
            calls.iter().find(|r| {
                r["not_read"] == true || r["failed"] == true || r["not_journaled"] == true
            })
        })
    {
        let identity = format!(
            "call {}{}",
            failed["call"],
            failed["job"]
                .as_str()
                .map(|j| format!(" job {j}"))
                .unwrap_or_default()
        );
        return format!(
            "machine held by an unresolved command; {identity}: {}",
            collection_cause(failed)
        );
    }
    let action = match category {
        "host-key" => "host-key mismatch; verify the trusted host pin before Resume",
        "held" | "command-held" => {
            "machine held by an unresolved command; inspect its recorded job"
        }
        "unresolved" => "command outcome unresolved; inspect the original pending job",
        "barrier" => "machine barrier; inspect unresolved operations",
        "disposition" => "machine disposition prevents this command",
        "launch-too-long" => "command is too long to launch; shorten the command",
        "signature-lowering" => "signature-lowering refused",
        "journal" => "command journal or storage refused",
        "failed" => "transport or authentication failed; check connection configuration",
        "relay" => "relay refused the connection",
        "no-pin" => crate::poc::wait::PIN_REQUIRED,
        "no-credentials" => "connection credentials missing; restore session authority",
        "unbound" => "machine is unbound; bind the task machine before Resume",
        "no-entry" => "machine has no approved entry; review setup before Resume",
        "provenance" => "command provenance refused; restore the task session binding",
        _ => "tracked command refused; inspect task and connection configuration",
    };
    let detail = report.get("why").or_else(|| report.get("reason"));
    match detail {
        Some(Value::String(why)) if !why.trim().is_empty() => format!("{action}: {why}"),
        Some(why) if !why.is_null() => format!("{action}: {why}"),
        _ => action.into(),
    }
}

pub fn collection_reason(pending: &crate::store::poc::Pending, reports: &[Value]) -> String {
    let Some(report) = reports.iter().find(|r| r["call"] == pending.call) else {
        return crate::poc::wait::NO_OUTCOME.render(pending.call, &pending.job, "");
    };
    if report.get("job").is_some_and(|job| job != &pending.job) {
        return crate::poc::wait::IDENTITY_MISMATCH.render(pending.call, &pending.job, "");
    }
    let cause = collection_cause(report);
    crate::poc::wait::COLLECTION.render(pending.call, &pending.job, &cause)
}

fn collection_cause(report: &Value) -> String {
    let category = if report["not_journaled"] == true
        || (report["failed"] == true && report.get("job_record").is_some())
    {
        // The collector includes job_record (possibly null) only after a successful read.
        // An append error or stopped wait does not prove whether its commit landed.
        crate::poc::wait::CHECKPOINT_UNCERTAIN
    } else if report["not_read"] == true {
        crate::poc::wait::NOT_READ
    } else if report["failed"] == true {
        crate::poc::wait::READ_FAILED
    } else {
        // These are the production collector's flattened Report fields, not synthetic reasons.
        let Ok(observed) = serde_json::from_value::<crate::jobs::Report>(report.clone()) else {
            return crate::poc::wait::MALFORMED.into();
        };
        if observed.number.is_none() || observed.evidence.record.validate().is_err() {
            return crate::poc::wait::NO_METADATA.into();
        }
        if observed.state == crate::jobs::State::OtherMachine {
            return crate::poc::wait::FOREIGN.into();
        }
        if matches!(observed.comparison, crate::jobs::Comparison::Finding { .. }) {
            return crate::poc::wait::COMMAND_MISMATCH.into();
        }
        return match observed.state {
            crate::jobs::State::Missing => crate::poc::wait::MISSING,
            crate::jobs::State::Ended => crate::poc::wait::ENDED,
            crate::jobs::State::Incomplete => crate::poc::wait::INCOMPLETE,
            crate::jobs::State::Running => crate::poc::wait::STILL_RUNNING,
            crate::jobs::State::Finished => crate::poc::wait::FINISHED,
            crate::jobs::State::OtherMachine => unreachable!(),
        }
        .into();
    };
    match report.get("why") {
        Some(why) => crate::poc::wait::with_detail(category, &read_detail(why)),
        None => category.into(),
    }
}

fn read_detail(why: &Value) -> String {
    if let Some(unreachable) = why.get("unreachable") {
        return format!("unreachable: {}", refusal_reason(unreachable));
    }
    why.as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| why.to_string())
}
