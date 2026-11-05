//! Command response composition shared by release and its capacity checks.
use super::Entry;
use crate::jobs;
use serde_json::{Value, json};

/// What a completed command returns, including the journal read-back it was reconciled with.
pub struct Done {
    pub seq: u64,
    pub sent: Vec<u8>,
    pub recorded: Entry,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: u32,
    pub terminal: u64,
    pub host_key: String,
    pub evidence: jobs::Report,
}

impl Done {
    pub fn report(&self) -> Value {
        json!({
            "done": true,
            "seq": self.seq,
            "call": self.seq,
            "terminal": self.terminal,
            "sent": hex::encode(&self.sent),
            "recorded": hex::encode(&self.recorded.command),
            "recorded_machine": self.recorded.machine,
            "stdout": String::from_utf8_lossy(&self.stdout),
            "stderr": String::from_utf8_lossy(&self.stderr),
            "exit_status": self.exit_status,
            "host_key": self.host_key,
            "job_record": self.evidence,
        })
    }
}

/// The page's command response envelope.
pub(crate) fn response(outcome: Value) -> Value {
    json!({"outcome":outcome})
}

pub(crate) fn collected(records: Vec<Value>) -> Value {
    json!({"collected":records})
}

pub(crate) fn dispatch_result(call: u64, result: Value) -> Value {
    json!({"call":call,"dispatch_result":result})
}

pub(crate) fn held_report(
    machine: &str,
    calls: Vec<Value>,
    disposition: Option<&crate::dispatch::DestructiveDisposition>,
) -> Value {
    let mut answer = json!({"held":true,"machine":machine,"calls":calls,
        "release":["finished_record","disposition"]});
    if let Some(disposition) = disposition {
        answer["disposition"] = json!(disposition.disposition);
        answer["continuation"] = json!(disposition.continuation);
        answer["dispatch_still_restricted"] = json!(true);
    }
    answer
}

/// Supported single-call releases, including a held request waiting for its own dispatch.
/// Several reports after dispositions require a separate aggregate capacity check.
pub(crate) fn release_forms(done: &Done) -> Vec<Value> {
    let command = done.report();
    let record = serde_json::to_value(&done.evidence).expect("report serialization");
    let mut historical_record = record.clone();
    historical_record["historical"] = true.into();
    historical_record["actionable"] = false.into();
    historical_record["why"] = "stale result after suspension".into();
    vec![
        command.clone(),
        response(command.clone()),
        response(collected(vec![record.clone()])),
        response(collected(vec![historical_record])),
        response(held_report(&done.recorded.machine, vec![record], None)),
        response(held_report(
            &done.recorded.machine,
            vec![dispatch_result(done.seq, command)],
            None,
        )),
    ]
}
