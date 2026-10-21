//! Journal-derived box-plane calls and operator dispositions (`STA-4`, `STA-8`, `STA-24`).
//! No clock, transport or storage enters this core. `STA-20`'s unresolved-command hold
//! and destructive dispositions are both derived from committed records.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    Finished { terminal: u64, exit_status: u32 },
    Disposed { disposition: u64, outcome: Unknown },
    Cancelled,
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
    Held(CommandHold),
    Disposition(DestructiveDisposition),
}

/// All projections come from committed records applied in journal order.
#[derive(Clone, Debug, Default)]
pub struct Dispatch {
    pub calls: BTreeMap<u64, Call>,
    pub terminals: Vec<TerminalRecord>,
    pub dispositions: Vec<DispositionRecord>,
    pub standing: BTreeMap<String, DispositionRecord>,
    pub jobs: Vec<crate::jobs::Report>,
}

impl Dispatch {
    pub fn check_command(&self, machine: &str) -> Result<(), DispatchRefusal> {
        let disposition = self.standing.get(machine).and_then(|record| {
            record
                .disposition
                .continuation
                .destructive()
                .then_some(DestructiveDisposition {
                    disposition: record.number,
                    continuation: record.disposition.continuation,
                })
        });
        let calls: Vec<_> = self
            .calls
            .values()
            .filter(|call| call.intent.machine == machine && call.state == CallState::Unresolved)
            .map(|call| call.intent.clone())
            .collect();
        if !calls.is_empty() {
            return Err(DispatchRefusal::Held(CommandHold { calls, disposition }));
        }
        if let Some(disposition) = disposition {
            return Err(DispatchRefusal::Disposition(disposition));
        }
        Ok(())
    }

    pub fn intent(&mut self, number: u64, intent: Intent) -> Result<(), String> {
        if intent.call != number || self.calls.contains_key(&number) {
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
        Ok(())
    }

    pub fn terminal(&mut self, number: u64, terminal: Terminal) -> Result<(), String> {
        let call = self
            .calls
            .get_mut(&terminal.call)
            .ok_or("terminal names no call")?;
        if matches!(
            call.state,
            CallState::Cancelled | CallState::Finished { .. }
        ) {
            return Err("terminal names a cancelled or already finished call".into());
        }
        if matches!(call.state, CallState::Unresolved) {
            call.state = CallState::Finished {
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
        let standing = self.standing.get(&disposition.machine);
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
            let call = self.calls.get(id);
            let eligible = call.is_some_and(|call| {
                call.intent.machine == disposition.machine
                    && (matches!(call.state, CallState::Unresolved)
                        || matches!(call.state, CallState::Disposed { disposition: old, .. }
                            if standing.is_some_and(|record| record.number == old)))
            });
            if !eligible {
                let settled_by = call.and_then(|call| match call.state {
                    CallState::Finished { terminal, .. } => Some(terminal),
                    CallState::Disposed { disposition, .. } => Some(disposition),
                    _ => None,
                });
                let settling_record = settled_by.and_then(|number| {
                    self.terminals
                        .iter()
                        .find(|record| record.number == number)
                        .cloned()
                        .map(SettlingRecord::Terminal)
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
                    Some(call) if call.intent.machine != disposition.machine => {
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
            }
        } else {
            DispositionReport::Refused {
                issues,
                unresolved: self
                    .calls
                    .iter()
                    .filter_map(|(id, call)| {
                        (call.intent.machine == disposition.machine
                            && matches!(call.state, CallState::Unresolved))
                        .then_some(*id)
                    })
                    .collect(),
            }
        }
    }

    pub fn disposition(&mut self, number: u64, disposition: Disposition) -> DispositionReport {
        let report = self.check_disposition(number, &disposition);
        let record = DispositionRecord {
            number,
            disposition,
            report: report.clone(),
        };
        if matches!(report, DispositionReport::Accepted { .. }) {
            for id in &record.disposition.calls {
                self.calls.get_mut(id).expect("checked call").state = CallState::Disposed {
                    disposition: number,
                    outcome: Unknown::Unknown,
                };
            }
            self.standing
                .insert(record.disposition.machine.clone(), record.clone());
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
        }
    }

    #[test]
    fn unresolved_command_hold_includes_every_legacy_and_unreadable_call_only_on_its_machine() {
        let mut dispatch = Dispatch::default();
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
            dispatch.check_command("fixture").is_err(),
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
