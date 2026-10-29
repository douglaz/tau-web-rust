//! Installed-system job records and their advisory evidence (`STA-20`, `STA-20a`, `STA-21`).

use serde::{Deserialize, Serialize};

pub const DIRECTORY: &str = "/var/lib/tau-web/jobs";
pub const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

// sshd runs the launch as one $SHELL -c argument. Linux MAX_ARG_STRLEN is
// 32 × PAGE_SIZE: 131072 bytes at 4 KiB pages, including the terminating NUL.
// The composed text may therefore be at most 131071 bytes.
pub const MAX_LAUNCH_BYTES: usize = 131071;

pub fn launch_fits(bytes: usize) -> bool {
    bytes <= MAX_LAUNCH_BYTES
}

/// Job identities always have 48 ASCII bytes, so this is exact before an intent exists.
pub fn launch_size(machine: &str, command: &[u8]) -> usize {
    launch(
        "000000000000000000000000000000000000000000000000",
        machine,
        command,
    )
    .len()
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 48
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn octal(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\0{b:03o}")).collect()
}

/// All inserted command and machine bytes are octal printf operands, never shell syntax.
/// The same text is sent by both browser builds. Existing job records are never changed;
/// the parent jobs directory is restricted to mode 0700.
pub fn launch(id: &str, machine: &str, command: &[u8]) -> String {
    assert!(valid_id(id));
    let runner = quote(include_str!("jobs/runner.sh"));
    format!(
        "# tau-web job launch {id}\numask 077\nmkdir -p {DIRECTORY} || exit 1\nchmod 700 {DIRECTORY} || exit 1\nd={DIRECTORY}/{id}\nmkdir \"$d\" || {{ printf '%s\\n' \"refusing existing or unavailable job directory: $d\" >&2; exit 1; }}\nprintf '%b' '{}' > \"$d/command\" || exit 1\nprintf '%b' '{}' > \"$d/machine\" || exit 1\ncat {BOOT_ID} > \"$d/boot\" || exit 1\n: > \"$d/stdout\"\n: > \"$d/stderr\"\nsetsid sh -c {runner} sh \"$d\" </dev/null >/dev/null 2> \"$d/runner-stderr\" &\nlauncher=$!\nwhile [ ! -f \"$d/ready\" ]; do\n    kill -0 \"$launcher\" 2>/dev/null || {{ [ -f \"$d/ready\" ] && break; cat \"$d/runner-stderr\" >&2; exit 1; }}\n    # GNU coreutils (Arch) and busybox (Alpine) accept fractional sleep.\n    sleep 0.05\ndone\nwait_job=true\n{}",
        octal(command),
        octal(machine.as_bytes()),
        include_str!("jobs/read.sh")
    )
}

/// A read only: neither launch text nor the command bytes are in a collection exec.
pub fn collect(id: &str) -> String {
    assert!(valid_id(id));
    format!(
        "# tau-web job read {id}\nd={DIRECTORY}/{id}\nwait_job=true\n{}",
        include_str!("jobs/read.sh")
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Record {
    Missing,
    Incomplete {
        machine: Option<String>,
        command: Option<String>,
    },
    Present {
        /// Machine and command are exact bytes, encoded as lowercase hex.
        machine: String,
        command: String,
        boot: String,
        current_boot: String,
        pid: u32,
        alive: bool,
        exit_status: Option<u32>,
        stdout: String,
        stderr: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Finished,
    Running,
    Ended,
    Missing,
    OtherMachine,
    Incomplete,
}

impl Record {
    pub fn validate(&self) -> Result<(), String> {
        if let Self::Incomplete { machine, command } = self {
            for value in machine.iter().chain(command.iter()) {
                if hex::decode(value).is_err() || value.to_ascii_lowercase() != *value {
                    return Err("incomplete record bytes are not lowercase hex".into());
                }
            }
        }
        if let Self::Present {
            machine,
            command,
            stdout,
            stderr,
            boot,
            current_boot,
            exit_status,
            ..
        } = self
        {
            for value in [machine, command, stdout, stderr] {
                if hex::decode(value).is_err() || value.to_ascii_lowercase() != *value {
                    return Err("job record bytes are not lowercase hex".into());
                }
            }
            if boot.is_empty() || current_boot.is_empty() || exit_status.is_some_and(|s| s > 128) {
                return Err("job record has invalid boot identity or exit code".into());
            }
        }
        Ok(())
    }

    pub fn classify(&self, expected_machine: &str) -> State {
        match self {
            Self::Missing => State::Missing,
            Self::Incomplete { .. } => State::Incomplete,
            Self::Present { machine, .. } if *machine != hex::encode(expected_machine) => {
                State::OtherMachine
            }
            Self::Present {
                exit_status: Some(_),
                ..
            } => State::Finished,
            Self::Present { pid: 0, .. } => State::Incomplete,
            Self::Present {
                boot,
                current_boot,
                alive: true,
                pid,
                ..
            } if boot == current_boot && *pid != 0 => State::Running,
            Self::Present { .. } => State::Ended,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub call: u64,
    pub job: String,
    pub record: Record,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "agreement", rename_all = "snake_case")]
pub enum Comparison {
    AdvisoryMatch,
    Finding { journal: String, received: String },
    NoRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub number: Option<u64>,
    #[serde(flatten)]
    pub evidence: Evidence,
    pub state: State,
    #[serde(flatten)]
    pub comparison: Comparison,
    pub stdout: String,
    pub stderr: String,
    pub exit_status: Option<u32>,
}

/// Channel deliveries accumulated by the transport; the decision is shared on every target.
#[derive(Default)]
pub struct ReadDelivery {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: Option<u32>,
    pub closed: bool,
}

pub const WRAPPER_STDERR_LIMIT: usize = 2048;

impl ReadDelivery {
    pub fn extended_data(&mut self, bytes: &[u8]) {
        let remaining = WRAPPER_STDERR_LIMIT.saturating_sub(self.stderr.len());
        self.stderr
            .extend_from_slice(&bytes[..bytes.len().min(remaining)]);
    }

    pub fn record(self) -> Result<Record, String> {
        if self.status != Some(0) {
            return Err(format!(
                "job read ended without a complete record (wrapper status {:?} is not a command status): {}",
                self.status,
                String::from_utf8_lossy(&self.stderr)
            ));
        }
        if !self.closed {
            return Err("job read stream ended before channel close".into());
        }
        let record: Record = serde_json::from_slice(&self.stdout)
            .map_err(|_| "job read returned a malformed record")?;
        record.validate()?;
        Ok(record)
    }
}

/// A read can be reported even when its evidence append fails; it has no journal number.
pub fn uncommitted(evidence: &Evidence, machine: &str, command: &str) -> Report {
    let mut report = evidence.report(0, machine, command);
    report.number = None;
    report
}

/// A stale continuation can still carry truthful outcome/accounting information.
pub(crate) fn historical(value: &mut serde_json::Value, why: &str) {
    match value {
        serde_json::Value::Object(fields) => {
            if fields.contains_key("call") || fields.contains_key("done") {
                fields.remove("done");
                fields.insert("historical".into(), true.into());
                fields.insert("actionable".into(), false.into());
                fields.insert("refused".into(), why.into());
            }
            for nested in fields.values_mut() {
                historical(nested, why);
            }
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(|v| historical(v, why)),
        _ => {}
    }
}

pub fn unresolved(call: u64, why: &str, evidence: Option<&Report>) -> serde_json::Value {
    let mut response = serde_json::json!({"unresolved":true,"call":call,"why":why});
    if let Some(evidence) = evidence {
        response["job_record"] = serde_json::to_value(evidence).expect("report serialization");
    }
    response
}

impl Evidence {
    pub fn report(&self, number: u64, machine: &str, command: &str) -> Report {
        let (comparison, stdout, stderr, exit_status) = match &self.record {
            Record::Missing => (Comparison::NoRecord, String::new(), String::new(), None),
            Record::Incomplete {
                command: received, ..
            } => (
                match received {
                    None => Comparison::NoRecord,
                    Some(received) if received == command => Comparison::AdvisoryMatch,
                    Some(received) => Comparison::Finding {
                        journal: command.into(),
                        received: received.clone(),
                    },
                },
                String::new(),
                String::new(),
                None,
            ),
            Record::Present {
                command: received,
                stdout,
                stderr,
                exit_status,
                ..
            } => (
                if command == received {
                    Comparison::AdvisoryMatch
                } else {
                    Comparison::Finding {
                        journal: command.into(),
                        received: received.clone(),
                    }
                },
                String::from_utf8_lossy(&hex::decode(stdout).expect("validated output"))
                    .into_owned(),
                String::from_utf8_lossy(&hex::decode(stderr).expect("validated output"))
                    .into_owned(),
                *exit_status,
            ),
        };
        Report {
            number: Some(number),
            evidence: self.clone(),
            state: self.record.classify(machine),
            comparison,
            stdout,
            stderr,
            exit_status,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_size_boundary_and_exact_composition() {
        assert!(launch_fits(131071));
        assert!(!launch_fits(131072));
        for machine in ["fixture", "machine with 'quotes' and 日本語"] {
            let base = launch_size(machine, b"");
            let longest = vec![b'x'; (MAX_LAUNCH_BYTES - base) / 5];
            let size = launch_size(machine, &longest);
            assert_eq!(size, launch(&"a".repeat(48), machine, &longest).len());
            assert!(launch_fits(size));
            let mut larger = longest;
            larger.push(b'x');
            assert_eq!(launch_size(machine, &larger), size + 5);
            assert!(!launch_fits(launch_size(machine, &larger)));
            let bytes = b"'\n\xff";
            assert_eq!(launch_size(machine, bytes), base + 5 * bytes.len());
            assert_eq!(
                launch_size(machine, bytes),
                launch(&"b".repeat(48), machine, bytes).len()
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launch_argument_limit_matches_kernel() {
        use std::process::Command;

        assert!(
            Command::new("sh")
                .args(["-c", "exit 0", "sh", &"x".repeat(MAX_LAUNCH_BYTES)])
                .status()
                .unwrap()
                .success()
        );
        let error = Command::new("sh")
            .args(["-c", "exit 0", "sh", &"x".repeat(MAX_LAUNCH_BYTES + 1)])
            .status()
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(7));
    }

    pub fn record() -> Record {
        Record::Present {
            machine: hex::encode("fixture"),
            command: hex::encode("exit 7"),
            boot: "boot-a".into(),
            current_boot: "boot-a".into(),
            pid: 12,
            alive: true,
            exit_status: None,
            stdout: hex::encode("out\n"),
            stderr: hex::encode("err\n"),
        }
    }

    #[test]
    fn read_delivery_requires_zero_status_close_and_valid_record() {
        let valid = serde_json::to_vec(&Record::Missing).unwrap();
        let delivered = |stdout, status, closed| ReadDelivery {
            stdout,
            status,
            closed,
            ..Default::default()
        };
        assert_eq!(
            delivered(valid.clone(), Some(0), true).record().unwrap(),
            Record::Missing
        );
        assert!(
            delivered(valid.clone(), Some(0), false)
                .record()
                .unwrap_err()
                .contains("before channel close")
        );
        assert!(delivered(valid.clone(), None, true).record().is_err());
        assert!(
            delivered(b"broken".to_vec(), Some(0), true)
                .record()
                .unwrap_err()
                .contains("malformed")
        );
        let mut invalid = record();
        if let Record::Present { boot, .. } = &mut invalid {
            boot.clear();
        }
        assert!(
            delivered(serde_json::to_vec(&invalid).unwrap(), Some(0), true)
                .record()
                .unwrap_err()
                .contains("invalid boot")
        );
        let mut failed = delivered(valid, Some(7), true);
        failed.extended_data(b"mkdir refused: \xff");
        let why = failed.record().unwrap_err();
        assert!(why.contains("mkdir refused: \u{fffd}"), "{why}");
        let mut bounded = ReadDelivery::default();
        bounded.extended_data(&vec![b'x'; WRAPPER_STDERR_LIMIT + 20]);
        bounded.extended_data(b"overflow");
        assert_eq!(bounded.stderr.len(), WRAPPER_STDERR_LIMIT);
    }

    #[test]
    fn exit_status_ceiling_is_128_in_records_and_deliveries() {
        for status in [128, 129, 137, 255] {
            let mut record = record();
            if let Record::Present { exit_status, .. } = &mut record {
                *exit_status = Some(status);
            }
            assert_eq!(record.validate().is_ok(), status == 128, "status {status}");
            let delivered = ReadDelivery {
                stdout: serde_json::to_vec(&record).unwrap(),
                status: Some(0),
                closed: true,
                ..Default::default()
            };
            assert_eq!(delivered.record().is_ok(), status == 128, "status {status}");
        }
    }

    #[test]
    fn unresolved_live_report_retains_evidence_output_and_finding() {
        let mut record = record();
        if let Record::Present { alive, .. } = &mut record {
            *alive = false;
        }
        let evidence = Evidence {
            call: 1,
            job: "a".repeat(48),
            record,
        };
        let report = evidence.report(2, "fixture", &hex::encode("different"));
        let response = unresolved(1, "job record: Ended", Some(&report));
        assert_eq!(response["unresolved"], true);
        assert_eq!(response["job_record"]["state"], "ended");
        assert_eq!(response["job_record"]["agreement"], "finding");
        assert_eq!(response["job_record"]["stdout"], "out\n");
        assert_eq!(response["job_record"]["stderr"], "err\n");
        assert!(response["job_record"]["exit_status"].is_null());
        assert_eq!(uncommitted(&evidence, "fixture", "").number, None);
    }

    #[test]
    fn every_record_shape_has_a_distinct_decision() {
        assert_eq!(Record::Missing.classify("fixture"), State::Missing);
        assert_eq!(
            Record::Incomplete {
                machine: None,
                command: Some(hex::encode("part"))
            }
            .classify("fixture"),
            State::Incomplete
        );
        let mut r = record();
        assert_eq!(r.classify("fixture"), State::Running);
        assert_eq!(r.classify("other"), State::OtherMachine);
        if let Record::Present { current_boot, .. } = &mut r {
            *current_boot = "boot-b".into();
        }
        assert_eq!(r.classify("fixture"), State::Ended);
        if let Record::Present { exit_status, .. } = &mut r {
            *exit_status = Some(7);
        }
        assert_eq!(r.classify("fixture"), State::Finished);
        assert_eq!(r.classify("other"), State::OtherMachine);
        let mut r = record();
        if let Record::Present { alive, .. } = &mut r {
            *alive = false;
        }
        assert_eq!(r.classify("fixture"), State::Ended);
        if let Record::Present { pid, .. } = &mut r {
            *pid = 0;
        }
        assert_eq!(r.classify("fixture"), State::Incomplete);
    }

    #[test]
    fn comparison_reports_advisory_agreement_or_exact_finding() {
        let e = Evidence {
            call: 1,
            job: "a".repeat(48),
            record: record(),
        };
        let matched = e.report(2, "fixture", &hex::encode("exit 7"));
        assert_eq!(matched.comparison, Comparison::AdvisoryMatch);
        let mismatched = e.report(2, "fixture", &hex::encode("exit 0"));
        assert_eq!(
            mismatched.comparison,
            Comparison::Finding {
                journal: hex::encode("exit 0"),
                received: hex::encode("exit 7")
            }
        );
        for report in [matched, mismatched] {
            let text = serde_json::to_string(&report).unwrap().to_lowercase();
            assert!(
                !text.contains("verif") && !text.contains("passed"),
                "{text}"
            );
        }
    }
}
