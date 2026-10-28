//! Journal-derived calls across both planes and operator dispositions (`STA-4`, `STA-8`, `STA-24`).
//! No clock, transport or storage enters this core. `STA-20`'s unresolved-command hold
//! and destructive dispositions are both derived from committed records.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod setup;
mod typed;
pub use setup::*;
pub use typed::*;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod comparison;
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod fixture;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod receipt_tests;
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod typed_tests;

/// The identity of what admitted a command, not approval of its contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Approval {
    HarnessPin {
        machine: String,
        fingerprint: String,
    },
    /// Projection marker only: old command records preceded transmission.
    #[serde(skip_deserializing)]
    LegacyCommand,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub call: u64,
    pub machine: String,
    /// Exact command bytes in lowercase hex.
    pub command: String,
    pub approval: Option<Approval>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<String>,
    /// Request provenance, separate from the scope admission above (`ARC-4`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<CommandProvenance>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terminal {
    pub call: u64,
    pub exit_status: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Continuation {
    DestructiveReinstall,
    Abandonment,
    AsIfDone,
    AsIfNotDone,
}

impl Continuation {
    pub fn destructive(self) -> bool {
        matches!(self, Self::DestructiveReinstall | Self::Abandonment)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Disposition {
    pub machine: String,
    pub calls: Vec<u64>,
    pub continuation: Continuation,
    pub uncertainty: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CallState {
    Unresolved,
    Finished {
        terminal: u64,
        exit_status: u32,
    },
    Disposed {
        disposition: u64,
        outcome: Unknown,
    },
    Cancelled,
    NoEffect,
    Confirmed {
        observation: u64,
    },
    ReceiptConfirmed {
        receipt: u64,
        association: Option<u64>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unknown {
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Call {
    #[serde(flatten)]
    pub intent: Intent,
    #[serde(flatten)]
    pub state: CallState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TerminalRecord {
    pub number: u64,
    #[serde(flatten)]
    pub terminal: Terminal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DispositionIssue {
    pub call: Option<u64>,
    pub why: String,
    pub settled_by: Option<u64>,
    pub settling_record: Option<SettlingRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "record", rename_all = "snake_case")]
pub enum SettlingRecord {
    Terminal(TerminalRecord),
    Observation(ObservationRecord),
    Receipt {
        receipt: ReceiptRecord,
        association: Option<AssociationRecord>,
    },
    Disposition {
        number: u64,
        disposition: Disposition,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum DispositionReport {
    Accepted {
        number: u64,
        replaces: Option<u64>,
        dropped: Vec<u64>,
        assumption: Option<Assumption>,
    },
    Refused {
        issues: Vec<DispositionIssue>,
        unresolved: Vec<u64>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DispositionRecord {
    pub number: u64,
    #[serde(flatten)]
    pub disposition: Disposition,
    pub report: DispositionReport,
    pub resource: Resource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DestructiveDisposition {
    pub disposition: u64,
    pub continuation: Continuation,
}

/// The calls that hold this machine, including unreadable legacy calls.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CommandHold {
    pub calls: Vec<Intent>,
    pub disposition: Option<DestructiveDisposition>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispatchRefusal {
    NoEntry { machine: String },
    Provenance,
    Held(CommandHold),
    Disposition(DestructiveDisposition),
    TypedBarrier { calls: Vec<OperationIntent> },
}

/// All projections come from committed records applied in journal order.
#[derive(Clone, Debug, Default)]
pub struct Dispatch {
    pub approved_entries: BTreeMap<String, ApprovedMachine>,
    pub intent_order: Vec<u64>,
    pub calls: BTreeMap<u64, Call>,
    pub terminals: Vec<TerminalRecord>,
    pub dispositions: Vec<DispositionRecord>,
    pub standing: BTreeMap<String, DispositionRecord>,
    pub jobs: Vec<crate::jobs::Report>,
    pub typed_calls: BTreeMap<u64, OperationCall>,
    pub observations: Vec<ObservationRecord>,
    pub associations: Vec<Association>,
    pub association_records: Vec<AssociationRecord>,
    pub receipts: Vec<ReceiptRecord>,
    pub current_installations: BTreeMap<String, u64>,
    pub inference_standing: Option<DispositionRecord>,
}

impl Dispatch {
    pub fn check_command(&self, machine: &str) -> Result<(), DispatchRefusal> {
        if !self.approved_entries.contains_key(machine) {
            return Err(DispatchRefusal::NoEntry {
                machine: machine.into(),
            });
        }
        let resource = Resource::Entry(machine.into());
        match self.check_operation(&resource, Operation::Exec, Requester::Session) {
            Ok(()) => Ok(()),
            Err(RequestRefusal::Barrier { calls }) => {
                let running: Vec<_> = calls
                    .iter()
                    .filter_map(|id| self.typed_calls.get(id).map(|c| c.intent.clone()))
                    .collect();
                if !running.is_empty() {
                    return Err(DispatchRefusal::TypedBarrier { calls: running });
                }
                let calls = calls
                    .iter()
                    .map(|id| self.calls[id].intent.clone())
                    .collect();
                let disposition = self.standing.get(machine).and_then(|record| {
                    record.disposition.continuation.destructive().then_some(
                        DestructiveDisposition {
                            disposition: record.number,
                            continuation: record.disposition.continuation,
                        },
                    )
                });
                Err(DispatchRefusal::Held(CommandHold { calls, disposition }))
            }
            Err(RequestRefusal::Continuation { in_force }) => {
                Err(DispatchRefusal::Disposition(in_force))
            }
            Err(_) => unreachable!("operation admission checks only barriers and continuations"),
        }
    }

    pub fn intent(&mut self, number: u64, intent: Intent) -> Result<(), String> {
        if intent.call != number || self.call_state(number).is_some() {
            return Err("intent identity is not its unique record number".into());
        }
        let bytes = hex::decode(&intent.command).map_err(|_| "intent command is not hex")?;
        if hex::encode(bytes) != intent.command {
            return Err("intent command is not lowercase hex".into());
        }
        if let Some(job) = &intent.job
            && (!crate::jobs::valid_id(job)
                || self
                    .calls
                    .values()
                    .any(|c| c.intent.job.as_ref() == Some(job)))
        {
            return Err("intent job identity is invalid or reused".into());
        }
        let state = if intent.approval.is_some() {
            CallState::Unresolved
        } else {
            CallState::Cancelled
        };
        self.calls.insert(number, Call { intent, state });
        self.intent_order.push(number);
        self.current_installations
            .entry(self.calls[&number].intent.machine.clone())
            .or_default();
        Ok(())
    }

    pub fn terminal(&mut self, number: u64, terminal: Terminal) -> Result<(), String> {
        match self.call_operation(terminal.call) {
            None => return Err("terminal names no call".into()),
            Some(Operation::Exec) => {}
            Some(_) => return Err("terminal names no box-plane call".into()),
        }
        let state = self
            .call_state_mut(terminal.call)
            .expect("recorded command");
        if matches!(state, CallState::Cancelled | CallState::Finished { .. }) {
            return Err("terminal names a cancelled or already finished call".into());
        }
        if matches!(state, CallState::Unresolved) {
            *state = CallState::Finished {
                terminal: number,
                exit_status: terminal.exit_status,
            };
        }
        // Later evidence is shown but cannot reopen a disposed call or remove its disposition.
        self.terminals.push(TerminalRecord { number, terminal });
        Ok(())
    }

    /// Unresolved calls and disposed calls without job evidence are eligible for collection.
    pub fn collectable(&self, machine: &str) -> Vec<Intent> {
        self.calls
            .values()
            .filter(|call| {
                call.intent.machine == machine
                    && call.intent.job.is_some()
                    && (matches!(call.state, CallState::Unresolved)
                        || (matches!(call.state, CallState::Disposed { .. })
                            && !self
                                .jobs
                                .iter()
                                .any(|r| r.evidence.call == call.intent.call)))
            })
            .map(|call| call.intent.clone())
            .collect()
    }

    pub fn job_evidence(
        &mut self,
        number: u64,
        evidence: crate::jobs::Evidence,
        terminal: bool,
    ) -> Result<crate::jobs::Report, String> {
        use crate::jobs::State;
        evidence.record.validate()?;
        let call = self
            .calls
            .get(&evidence.call)
            .ok_or("job evidence names no call")?;
        if matches!(
            call.state,
            CallState::Cancelled | CallState::Finished { .. }
        ) || self
            .terminals
            .iter()
            .any(|t| t.terminal.call == evidence.call)
        {
            return Err("job evidence names a cancelled or already finished call".into());
        }
        if call.intent.job.as_ref() != Some(&evidence.job) {
            return Err("job evidence identity differs from the intent".into());
        }
        let report = evidence.report(number, &call.intent.machine, &call.intent.command);
        if terminal != (report.state == State::Finished) || report.state == State::Running {
            return Err("job evidence kind differs from what the record establishes".into());
        }
        if terminal {
            self.terminal(
                number,
                Terminal {
                    call: evidence.call,
                    exit_status: report.exit_status.expect("finished record"),
                },
            )?;
        }
        self.jobs.push(report.clone());
        Ok(report)
    }

    /// The same test is used before recording and during replay (`STA-24`).
    pub fn check_disposition(&self, number: u64, disposition: &Disposition) -> DispositionReport {
        self.check_resource_disposition(
            number,
            &Resource::Entry(disposition.machine.clone()),
            disposition,
        )
    }

    pub fn check_resource_disposition(
        &self,
        number: u64,
        resource: &Resource,
        disposition: &Disposition,
    ) -> DispositionReport {
        let standing = self.standing_for(resource);
        let mut issues = Vec::new();
        if disposition.calls.is_empty() {
            issues.push(DispositionIssue {
                call: None,
                why: "names no call".into(),
                settled_by: None,
                settling_record: None,
            });
        }
        for id in &disposition.calls {
            let call = self.call_state(*id);
            let eligible = call.is_some_and(|state| {
                self.call_resource(*id).as_ref() == Some(resource)
                    && (matches!(state, CallState::Unresolved)
                        || matches!(state, CallState::Disposed { disposition: old, .. }
                            if standing.is_some_and(|record| record.number == *old)))
            });
            if !eligible {
                let settled_by = call.and_then(|state| match state {
                    CallState::Finished { terminal, .. } => Some(*terminal),
                    CallState::Confirmed { observation } => Some(*observation),
                    CallState::ReceiptConfirmed {
                        receipt,
                        association,
                    } => Some(association.map_or(*receipt, |a| a.max(*receipt))),
                    CallState::Disposed { disposition, .. } => Some(*disposition),
                    _ => None,
                });
                let settling_record = settled_by.and_then(|number| {
                    if let Some(CallState::ReceiptConfirmed {
                        receipt,
                        association,
                    }) = call
                    {
                        return self
                            .receipts
                            .iter()
                            .find(|r| r.number == *receipt)
                            .map(|r| SettlingRecord::Receipt {
                                receipt: r.clone(),
                                association: association.and_then(|n| {
                                    self.association_records
                                        .iter()
                                        .find(|a| a.number == n)
                                        .cloned()
                                }),
                            });
                    }
                    self.terminals
                        .iter()
                        .find(|record| record.number == number)
                        .cloned()
                        .map(SettlingRecord::Terminal)
                        .or_else(|| {
                            self.observations
                                .iter()
                                .find(|r| r.number == number)
                                .cloned()
                                .map(SettlingRecord::Observation)
                        })
                        .or_else(|| {
                            self.dispositions
                                .iter()
                                .find(|record| record.number == number)
                                .map(|record| SettlingRecord::Disposition {
                                    number,
                                    disposition: record.disposition.clone(),
                                })
                        })
                });
                let why = match call {
                    None => "call does not exist",
                    Some(_) if self.call_resource(*id).as_ref() != Some(resource) => {
                        "call names another machine"
                    }
                    Some(_) => {
                        "call is neither unresolved nor disposed by the standing disposition"
                    }
                };
                issues.push(DispositionIssue {
                    call: Some(*id),
                    why: why.into(),
                    settled_by,
                    settling_record,
                });
            }
        }
        if issues.is_empty() {
            DispositionReport::Accepted {
                number,
                replaces: standing.map(|record| record.number),
                dropped: standing
                    .map(|record| {
                        record
                            .disposition
                            .calls
                            .iter()
                            .filter(|id| !disposition.calls.contains(id))
                            .copied()
                            .collect()
                    })
                    .unwrap_or_default(),
                assumption: (!disposition.continuation.destructive()).then_some(Assumption {
                    continuation: disposition.continuation,
                    outcome: Unknown::Unknown,
                }),
            }
        } else {
            DispositionReport::Refused {
                issues,
                unresolved: self.unresolved(resource),
            }
        }
    }

    pub fn disposition(&mut self, number: u64, disposition: Disposition) -> DispositionReport {
        self.resource_disposition(
            number,
            Resource::Entry(disposition.machine.clone()),
            disposition,
        )
    }

    pub fn resource_disposition(
        &mut self,
        number: u64,
        resource: Resource,
        disposition: Disposition,
    ) -> DispositionReport {
        let report = self.check_resource_disposition(number, &resource, &disposition);
        let record = DispositionRecord {
            number,
            disposition,
            report: report.clone(),
            resource: resource.clone(),
        };
        if matches!(report, DispositionReport::Accepted { .. }) {
            for id in &record.disposition.calls {
                *self.call_state_mut(*id).expect("checked call") = CallState::Disposed {
                    disposition: number,
                    outcome: Unknown::Unknown,
                };
            }
            match resource {
                Resource::Entry(entry) => {
                    self.standing.insert(entry, record.clone());
                }
                Resource::Inference => self.inference_standing = Some(record.clone()),
            }
        }
        self.dispositions.push(record);
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(call: u64, approval: Option<Approval>) -> Intent {
        Intent {
            call,
            machine: "fixture".into(),
            command: hex::encode("true"),
            approval,
            job: None,
            provenance: None,
        }
    }

    #[test]
    fn unresolved_command_hold_includes_every_legacy_and_unreadable_call_only_on_its_machine() {
        let mut dispatch = Dispatch::default();
        let mut allocation = crate::allocation::Metadata::new("fixture-seed".into());
        allocation
            .apply(&crate::allocation::Event::SeedBackup {
                seed: "fixture-seed".into(),
                completion: crate::allocation::Completion::Skipped,
            })
            .unwrap();
        let entries = ["fixture", "other"]
            .into_iter()
            .map(|name| {
                let mut entry = fixture_setup().remove(0);
                entry.machine = name.into();
                let identity = allocation
                    .issue(crate::allocation::Family::Machines)
                    .unwrap();
                allocation
                    .apply(&crate::allocation::Event::Reserve(identity.clone()))
                    .unwrap();
                ApprovedEntry {
                    entry,
                    identity,
                    access: Some(Access::ad_hoc()),
                }
            })
            .collect();
        let mut original = crate::allocation::Metadata::new("fixture-seed".into());
        original
            .apply(&crate::allocation::Event::SeedBackup {
                seed: "fixture-seed".into(),
                completion: crate::allocation::Completion::Skipped,
            })
            .unwrap();
        dispatch
            .apply_setup(
                &mut original,
                &SetupRecord::Approval(SetupApproval {
                    entries,
                    monthly_sat: 2000,
                    annual_sat: 24000,
                }),
            )
            .unwrap();
        dispatch
            .intent(1, intent(1, Some(Approval::LegacyCommand)))
            .unwrap();
        dispatch
            .intent(
                2,
                intent(
                    2,
                    Some(Approval::HarnessPin {
                        machine: "fixture".into(),
                        fingerprint: "SHA256:fixture".into(),
                    }),
                ),
            )
            .unwrap();
        dispatch.intent(3, intent(3, None)).unwrap();
        let Err(DispatchRefusal::Held(hold)) = dispatch.check_command("fixture") else {
            panic!("criteria 1, 3: legacy and unreadable unresolved commands hold their machine")
        };
        assert_eq!(
            hold.calls.iter().map(|c| c.call).collect::<Vec<_>>(),
            [1, 2],
            "criterion 7: names every holding call, excludes cancelled calls"
        );
        assert!(
            dispatch.check_command("other").is_ok(),
            "criterion 4: other machine unaffected while this machine is held"
        );
        dispatch
            .terminal(
                4,
                Terminal {
                    call: 1,
                    exit_status: 0,
                },
            )
            .unwrap();
        assert!(
            matches!(
                dispatch.check_command("fixture"),
                Err(DispatchRefusal::Held(_))
            ),
            "criterion 3: a finished call releases only its own hold"
        );
        dispatch
            .terminal(
                5,
                Terminal {
                    call: 2,
                    exit_status: 7,
                },
            )
            .unwrap();
        assert!(
            dispatch.check_command("fixture").is_ok(),
            "criterion 3: finished and cancelled calls hold nothing"
        );
    }
}
