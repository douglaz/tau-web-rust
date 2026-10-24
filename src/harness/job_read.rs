//! Reporting a job read uses its send history, even when session end races its result.

use serde_json::{Value, json};
use std::cell::Cell;

#[derive(Default)]
pub(super) struct Read {
    sent: Cell<bool>,
}

impl Read {
    /// Called in the same poll that successfully queues the channel's exec.
    pub fn mark_sent(&self) {
        self.sent.set(true);
    }

    pub fn failure(&self, call: u64, job: Option<&str>, ending: bool, why: &str) -> Value {
        let mut report = json!({"call":call});
        if let Some(job) = job {
            report["job"] = json!(job);
        }
        if !self.sent.get() && ending {
            report["not_read"] = json!(true);
            report["why"] = json!("sessions ended before record was read");
        } else {
            report[if job.is_some() { "failed" } else { "not_read" }] = json!(true);
            report["why"] = json!(why);
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sent_read_error_survives_session_end_in_collection_report() {
        sent_read_error_survives_session_end(Some("fixture-job"));
    }

    #[test]
    fn sent_read_error_survives_session_end_in_held_report() {
        sent_read_error_survives_session_end(None);
    }

    fn sent_read_error_survives_session_end(job: Option<&str>) {
        let read = Read::default();
        let ending = Cell::new(false);
        read.mark_sent();
        // The exec has gone out before session end and the read's own error.
        ending.set(true);
        let report = read.failure(9, job, ending.get(), "job record read: missing exit status");
        assert_eq!(report["call"], 9);
        if job.is_some() {
            assert_eq!(report["failed"], true, "{report}");
            assert!(report.get("not_read").is_none(), "{report}");
        } else {
            assert_eq!(report["not_read"], true, "{report}");
            assert!(report.get("failed").is_none(), "{report}");
        }
        assert_eq!(report["why"], "job record read: missing exit status");
        assert_eq!(report.get("job").cloned(), job.map(|j| json!(j)));
    }

    #[test]
    fn unsent_read_names_session_end_in_collection_and_held_reports() {
        for job in [Some("fixture-job"), None] {
            let report = Read::default().failure(9, job, true, "stopped while reading record");
            assert_eq!(report["not_read"], true);
            assert!(report.get("failed").is_none());
            assert_eq!(report["why"], "sessions ended before record was read");
        }
    }
}
