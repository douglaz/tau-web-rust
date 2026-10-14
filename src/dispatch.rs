//! Journal-derived box-plane calls and operator dispositions (`STA-4`, `STA-8`, `STA-24`).
//! No clock, transport or storage enters this core. Box-plane calls can be unresolved together.

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
pub struct DispatchRefusal {
    pub disposition: u64,
    pub continuation: Continuation,
}

/// All projections come from committed records applied in journal order.
#[derive(Clone, Debug, Default)]
pub struct Dispatch {
    pub calls: BTreeMap<u64, Call>,
    pub terminals: Vec<TerminalRecord>,
    pub dispositions: Vec<DispositionRecord>,
    pub standing: BTreeMap<String, DispositionRecord>,
}

impl Dispatch {
    pub fn check_command(&self, machine: &str) -> Result<(), DispatchRefusal> {
        if let Some(record) = self.standing.get(machine)
            && record.disposition.continuation.destructive()
        {
            return Err(DispatchRefusal {
                disposition: record.number,
                continuation: record.disposition.continuation,
            });
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

/// Relevant channel deliveries, in transport order. Output does not affect the decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelEvent {
    ExitStatus(u32),
    ExitSignal,
    Close,
    StreamEnd,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelDecision {
    Finished { exit_status: u32, terminal: u64 },
    Unresolved(String),
}

/// Requests the first exit status's terminal immediately, then folds its append result and
/// channel endings. Neither a later status nor a failed append may request another terminal.
pub struct ChannelFold {
    call: u64,
    exit_status: Option<u32>,
    appended: Option<Result<u64, String>>,
    exit_signal: bool,
    closed: bool,
}

impl ChannelFold {
    pub fn new(call: u64) -> Self {
        Self {
            call,
            exit_status: None,
            appended: None,
            exit_signal: false,
            closed: false,
        }
    }

    pub fn receive(&mut self, event: ChannelEvent) -> Option<Terminal> {
        match event {
            ChannelEvent::ExitStatus(exit_status) if self.exit_status.is_none() => {
                self.exit_status = Some(exit_status);
                Some(Terminal {
                    call: self.call,
                    exit_status,
                })
            }
            ChannelEvent::ExitSignal => {
                self.exit_signal = true;
                None
            }
            ChannelEvent::Close => {
                self.closed = true;
                None
            }
            ChannelEvent::ExitStatus(_) | ChannelEvent::StreamEnd => None,
        }
    }

    /// The caller performs each requested append before delivering another channel event.
    pub fn appended(&mut self, result: Result<u64, String>) {
        self.appended = Some(result);
    }

    pub fn conclude(self) -> ChannelDecision {
        match (self.exit_status, self.appended) {
            (Some(exit_status), Some(Ok(terminal))) => ChannelDecision::Finished {
                exit_status,
                terminal,
            },
            (_, Some(Err(why))) => ChannelDecision::Unresolved(format!("terminal append: {why}")),
            (Some(_), None) => {
                ChannelDecision::Unresolved("terminal append did not complete".into())
            }
            _ => ChannelDecision::Unresolved(
                if self.exit_signal {
                    "exit signal without an exit status"
                } else if self.closed {
                    "channel closed without an exit status"
                } else {
                    "connection lost without an exit status"
                }
                .into(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fold(
        events: &[ChannelEvent],
        append: Result<u64, String>,
    ) -> (Vec<Terminal>, ChannelDecision) {
        let mut fold = ChannelFold::new(1);
        let mut requests = Vec::new();
        for event in events {
            if let Some(record) = fold.receive(*event) {
                requests.push(record);
                fold.appended(append.clone());
            }
        }
        (requests, fold.conclude())
    }

    fn finished(events: &[ChannelEvent], exit_status: u32) {
        assert_eq!(
            fold(events, Ok(2)),
            (
                vec![Terminal {
                    call: 1,
                    exit_status
                }],
                ChannelDecision::Finished {
                    exit_status,
                    terminal: 2
                },
            )
        );
    }

    fn unresolved(events: &[ChannelEvent], why: &str) {
        assert_eq!(
            fold(events, Ok(2)),
            (vec![], ChannelDecision::Unresolved(why.into()))
        );
    }

    #[test]
    fn exit_status_then_close_finishes_with_that_status() {
        finished(&[ChannelEvent::ExitStatus(7), ChannelEvent::Close], 7);
    }

    #[test]
    fn exit_status_then_stream_end_finishes_with_that_status() {
        finished(&[ChannelEvent::ExitStatus(0), ChannelEvent::StreamEnd], 0);
    }

    #[test]
    fn close_without_exit_status_stays_unresolved() {
        unresolved(
            &[ChannelEvent::Close],
            "channel closed without an exit status",
        );
    }

    #[test]
    fn exit_signal_then_close_stays_unresolved() {
        unresolved(
            &[ChannelEvent::ExitSignal, ChannelEvent::Close],
            "exit signal without an exit status",
        );
    }

    #[test]
    fn exit_signal_then_stream_end_stays_unresolved() {
        unresolved(
            &[ChannelEvent::ExitSignal, ChannelEvent::StreamEnd],
            "exit signal without an exit status",
        );
    }

    #[test]
    fn empty_stream_end_stays_unresolved() {
        unresolved(
            &[ChannelEvent::StreamEnd],
            "connection lost without an exit status",
        );
    }

    #[test]
    fn second_exit_status_requests_no_second_terminal() {
        finished(
            &[ChannelEvent::ExitStatus(3), ChannelEvent::ExitStatus(5)],
            3,
        );
    }

    #[test]
    fn failed_terminal_append_stays_unresolved() {
        assert_eq!(
            fold(
                &[ChannelEvent::ExitStatus(7), ChannelEvent::Close],
                Err("move refused".into()),
            ),
            (
                vec![Terminal {
                    call: 1,
                    exit_status: 7
                }],
                ChannelDecision::Unresolved("terminal append: move refused".into()),
            )
        );
    }
}
