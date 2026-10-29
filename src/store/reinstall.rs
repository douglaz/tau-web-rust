//! Dedicated-path standing approval consumption. No vendor adapter or stage admission.
use super::*;
use crate::dispatch::{
    Facts, Operation, OperationApproval, OperationIntent, Request, Requester, Resource, Target,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub reset: String,
    pub entry: String,
    pub session: String,
    pub facts: Facts,
    pub modes: Vec<Mode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Record {
    Approve(Approval),
    Activation {
        entry: String,
    },
    Read {
        entry: String,
        activation: u64,
        confirmed: bool,
    },
    Withdraw {
        approval: u64,
        reset: String,
        entry: String,
    },
    Dispatch {
        approval: u64,
        reset: String,
        read: u64,
        intent: Box<OperationIntent>,
    },
}

#[derive(Clone, Default)]
pub(super) struct State {
    approvals: BTreeMap<u64, Approval>,
    withdrawn: BTreeMap<u64, u64>,
    dispatched: BTreeMap<u64, u64>,
    activations: BTreeMap<String, u64>,
    reads: BTreeMap<u64, (String, u64, bool)>,
    // An adapter's admitted dedicated path, never inferred from a disposition or machine class.
    paths: BTreeSet<String>,
}
impl State {
    fn matching(&self, id: u64, reset: &str, entry: &str) -> Result<&Approval, String> {
        let a = self
            .approvals
            .get(&id)
            .ok_or("unknown reinstall approval")?;
        if a.reset != reset || a.entry != entry {
            return Err("reinstall approval identity differs".into());
        }
        if self.dispatched.contains_key(&id) {
            return Err("reinstall reset already dispatched".into());
        }
        if self.withdrawn.contains_key(&id) {
            return Err("reinstall approval withdrawn".into());
        }
        Ok(a)
    }
    fn apply(&mut self, n: u64, record: &Record) -> Result<(), String> {
        match record {
            Record::Approve(a) => {
                if a.reset.is_empty()
                    || a.entry.is_empty()
                    || a.session.is_empty()
                    || self.approvals.values().any(|old| old.reset == a.reset)
                {
                    return Err("invalid or reused reinstall reset identity".into());
                }
                self.approvals.insert(n, a.clone());
            }
            Record::Activation { entry } => {
                if entry.is_empty() {
                    return Err("activation entry".into());
                }
                self.activations.insert(entry.clone(), n);
            }
            Record::Read {
                entry,
                activation,
                confirmed,
            } => {
                if self.activations.get(entry) != Some(activation) {
                    return Err("read does not name newest dispatched activation".into());
                }
                self.reads
                    .insert(n, (entry.clone(), *activation, *confirmed));
            }
            Record::Withdraw {
                approval,
                reset,
                entry,
            } => {
                self.matching(*approval, reset, entry)?;
                self.withdrawn.insert(*approval, n);
            }
            Record::Dispatch {
                approval,
                reset,
                read,
                intent,
            } => {
                let a = self.matching(
                    *approval,
                    reset,
                    match &intent.resource {
                        Resource::Entry(entry) => entry,
                        _ => return Err("dedicated reset resource".into()),
                    },
                )?;
                let (entry, activation, confirmed) =
                    self.reads.get(read).ok_or("missing activation read")?;
                if read.checked_add(1) != Some(n)
                    || !confirmed
                    || entry != &a.entry
                    || self.activations.get(entry) != Some(activation)
                    || activation <= approval
                    || intent.call != n
                    || intent.operation != Operation::Reinstall
                    || intent.target != Target::Entry(a.entry.clone())
                    || intent.requester != Requester::Operator
                    || intent.receipt_binding.is_some()
                    || intent.session != a.session
                    || intent.facts != a.facts
                    || intent.restated_modes != a.modes
                {
                    return Err("reinstall original facts or immediate activation read".into());
                }
                self.dispatched.insert(*approval, n);
            }
        }
        Ok(())
    }
}

pub struct PendingReset {
    pub intent: OperationIntent,
    approval: u64,
    live: Rc<Session>,
    ticket: crate::lifecycle::Continuation,
    sent: std::cell::Cell<bool>,
    scan_revision: u64,
    standing: Option<u64>,
}

impl<S: Storage> Store<S> {
    /// Fixture-only adapter admission. It supplies no stage-1 or vendor authority.
    #[cfg(any(test, feature = "tracer"))]
    pub fn synthetic_dedicated_path(&mut self, entry: &str) -> Result<(), String> {
        if !self.dispatch.approved_entries.contains_key(entry) {
            return Err("missing fixture entry".into());
        }
        self.reinstall.paths.insert(entry.into());
        Ok(())
    }
    fn dedicated_session(&self, session: &str, entry: &str) -> Result<Rc<Session>, String> {
        if !self.reinstall.paths.contains(entry) {
            return Err("no admitted dedicated path".into());
        }
        let live = self
            .sessions
            .iter()
            .find(|s| s.identity == session)
            .ok_or("rendering session ended")?;
        self.check_current_session(live)?;
        if live.bound_set != [entry] {
            return Err("dedicated reset binding".into());
        }
        Ok(live.clone())
    }
    pub async fn approve_reinstall(&mut self, approval: Approval) -> Result<u64, String> {
        self.dedicated_session(&approval.session, &approval.entry)?;
        if approval.modes != self.standing_modes(&approval.entry) {
            return Err("reinstall modes changed".into());
        }
        let n = self.next;
        self.reinstall_record(Record::Approve(approval)).await?;
        Ok(n)
    }
    /// Adapter entry: call only after the original rescue activation was dispatched.
    pub async fn dedicated_activation(
        &mut self,
        session: &str,
        entry: &str,
    ) -> Result<u64, String> {
        self.dedicated_session(session, entry)?;
        let n = self.next;
        self.reinstall_record(Record::Activation {
            entry: entry.into(),
        })
        .await?;
        Ok(n)
    }
    /// Adapter entry: journal the actual newest activation read, even when it does not confirm.
    pub async fn dedicated_activation_read(
        &mut self,
        session: &str,
        entry: &str,
        activation: u64,
        confirmed: bool,
    ) -> Result<u64, String> {
        self.dedicated_session(session, entry)?;
        let n = self.next;
        self.reinstall_record(Record::Read {
            entry: entry.into(),
            activation,
            confirmed,
        })
        .await?;
        Ok(n)
    }
    pub async fn withdraw_reinstall(
        &mut self,
        approval: u64,
        reset: &str,
        entry: &str,
    ) -> Result<(), String> {
        let a = self.reinstall.matching(approval, reset, entry)?;
        self.dedicated_session(&a.session, entry)?;
        self.reinstall_record(Record::Withdraw {
            approval,
            reset: reset.into(),
            entry: entry.into(),
        })
        .await
    }
    /// Durable reset boundary, under the same Store owner and normal typed barrier. An adapter
    /// must recheck `dedicated_reset_current` immediately before its actual transport send.
    pub async fn dispatch_reinstall(
        &mut self,
        approval: u64,
        reset: &str,
        entry: &str,
        read: u64,
    ) -> Result<PendingReset, String> {
        let a = self.reinstall.matching(approval, reset, entry)?.clone();
        let live = self.dedicated_session(&a.session, entry)?;
        let ticket = self.authority.continuation()?;
        let request = reinstall_request(&a);
        self.check_operation(&request)
            .map_err(|e| format!("{e:?}"))?;
        let intent = self
            .dispatch
            .prepare(self.next, &request)
            .map_err(|e| format!("{e:?}"))?;
        self.reinstall_record(Record::Dispatch {
            approval,
            reset: reset.into(),
            read,
            intent: Box::new(intent.clone()),
        })
        .await?;
        ticket.check()?;
        self.check_current_session(&live)?;
        Ok(PendingReset {
            intent: intent.clone(),
            approval,
            live,
            ticket,
            sent: std::cell::Cell::new(false),
            scan_revision: self.scans.revision(),
            standing: self
                .dispatch
                .standing_for(&intent.resource)
                .map(|d| d.number),
        })
    }
    pub fn dedicated_reset_current(&self, pending: &PendingReset) -> Result<(), String> {
        pending.ticket.check()?;
        self.check_current_session(&pending.live)?;
        if self.failed.is_some() || pending.sent.get() {
            return Err("failed writer or possibly transmitted reset".into());
        }
        if pending.scan_revision != self.scans.revision()
            || pending.standing
                != self
                    .dispatch
                    .standing_for(&pending.intent.resource)
                    .map(|d| d.number)
            || self
                .dispatch
                .unresolved(&pending.intent.resource)
                .iter()
                .any(|id| *id != pending.intent.call)
        {
            return Err("reset holdings or references changed".into());
        }
        let approval = pending.approval;
        let intent = &pending.intent;
        let a = self
            .reinstall
            .approvals
            .get(&approval)
            .ok_or("unknown approval")?;
        self.dedicated_session(&a.session, &a.entry)?;
        if self.reinstall.dispatched.get(&approval) != Some(&intent.call)
            || self
                .dispatch
                .typed_calls
                .get(&intent.call)
                .is_none_or(|c| c.intent != *intent)
            || self.reinstall.withdrawn.contains_key(&approval)
        {
            return Err("not the original dispatched reset".into());
        }
        pending.sent.set(true);
        Ok(())
    }
    async fn reinstall_record(&mut self, record: Record) -> Result<(), String> {
        let mut next = self.reinstall.clone();
        next.apply(self.next, &record)?;
        let mut dispatch = self.dispatch.clone();
        if let Record::Dispatch { intent, .. } = &record {
            dispatch.operation_intent(self.next, intent.as_ref().clone())?;
        }
        self.commit(&Event::DedicatedReinstall(record)).await?;
        self.reinstall = next;
        self.dispatch = dispatch;
        Ok(())
    }
    pub(super) fn replay_reinstall(&mut self, n: u64, record: &Record) -> Result<(), String> {
        if let Record::Approve(a) = record
            && (!self.dispatch.approved_entries.contains_key(&a.entry)
                || !self.exposure_ledger.iter().any(|e| {
                    e.session == a.session
                        && e.bound_set.len() == 1
                        && e.bound_set[0].machine == a.entry
                }))
        {
            return Err("reinstall approval has no original bound entry/session".into());
        }
        self.reinstall.apply(n, record)?;
        if let Record::Dispatch { intent, .. } = record {
            self.dispatch.operation_intent(n, intent.as_ref().clone())?;
        }
        Ok(())
    }
    pub fn reinstall_approvals(&self) -> Value {
        self.reinstall.approvals.iter().map(|(id,a)| {
            let live = self.sessions.iter().any(|s| s.identity == a.session && !s.ended.get()) && self.authority.verification();
            let state = if self.reinstall.dispatched.contains_key(id) { "dispatched" }
                else if self.reinstall.withdrawn.contains_key(id) { "withdrawn" }
                else if live { "standing" } else { "no longer usable" };
            json!({"approval":id,"reset":a.reset,"entry":a.entry,"session":a.session,"facts":a.facts,"state":state,"withdrawal_offer":state=="standing"})
        }).collect::<Vec<_>>().into()
    }
}
fn reinstall_request(a: &Approval) -> Request {
    let approved = OperationApproval {
        receipt_binding: None,
        restated_modes: a.modes.clone(),
        resource: Resource::Entry(a.entry.clone()),
        target: Target::Entry(a.entry.clone()),
        operation: Operation::Reinstall,
        session: a.session.clone(),
        requester: Requester::Operator,
        facts: a.facts.clone(),
    };
    Request {
        receipt_binding: None,
        target: approved.target.clone(),
        operation: approved.operation,
        session: a.session.clone(),
        requester: approved.requester,
        facts: a.facts.clone(),
        approved: Some(approved),
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
