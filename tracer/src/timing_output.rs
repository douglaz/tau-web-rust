//! Validate the timing bytes actually emitted by the execution child.
use serde::Deserialize;
use serde_json::{Value, json};

const MAX_NS: u64 = 9_007_199_254_740_991;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Phase {
    phase: String,
    start_ns: u64,
    end_ns: u64,
    #[serde(default)]
    status: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identified {
    id: String,
    #[serde(default)]
    invocation: Option<u64>,
    start_ns: u64,
    end_ns: u64,
    #[serde(default)]
    status: Option<String>,
}
#[derive(Default)]
pub struct Output {
    records: Vec<(&'static str, Value)>,
    evidence: Option<usize>,
    last_end: u64,
}
impl Output {
    pub fn observe(&mut self, line: &str) -> Result<(), String> {
        if line.starts_with("TRACER_EVIDENCE ")
            && self.evidence.replace(self.records.len()).is_some()
        {
            return Err("duplicate timing evidence boundary".into());
        }
        for (prefix, kind) in [
            ("TRACER_TIMING", "phase"),
            ("TRACER_CASE_TIMING", "case"),
            ("TRACER_GROUP_TIMING", "group"),
        ] {
            if !line.starts_with(prefix) {
                continue;
            }
            let raw = line
                .strip_prefix(prefix)
                .and_then(|v| v.strip_prefix(' '))
                .ok_or("invalid printed timing schema")?;
            let original: Value =
                serde_json::from_str(raw).map_err(|_| "invalid printed timing schema")?;
            // Struct decoding also rejects duplicate keys, including a hidden bad first value.
            let (mut value, start, end, status) = if kind == "phase" {
                let parsed: Phase =
                    serde_json::from_str(raw).map_err(|_| "invalid printed timing schema")?;
                if !["fixtures", "browser", "groups", "cleanup", "execution"]
                    .contains(&parsed.phase.as_str())
                {
                    return Err("invalid printed timing phase".into());
                }
                (
                    json!({"phase":parsed.phase,"start_ns":parsed.start_ns,"end_ns":parsed.end_ns}),
                    parsed.start_ns,
                    parsed.end_ns,
                    parsed.status,
                )
            } else {
                let parsed: Identified =
                    serde_json::from_str(raw).map_err(|_| "invalid printed timing schema")?;
                let mut value =
                    json!({"id":parsed.id,"start_ns":parsed.start_ns,"end_ns":parsed.end_ns});
                if kind == "group" {
                    value["invocation"] = json!(
                        parsed
                            .invocation
                            .filter(|i| *i > 0)
                            .ok_or("missing printed scenario invocation")?
                    );
                } else if parsed.invocation.is_some() {
                    return Err("unexpected case invocation field".into());
                }
                (value, parsed.start_ns, parsed.end_ns, parsed.status)
            };
            if let Some(status) = status {
                if !["failed", "incomplete"].contains(&status.as_str()) {
                    return Err("invalid printed timing status".into());
                }
                value["status"] = json!(status);
            }
            if original != value || start > end || end > MAX_NS || end < self.last_end {
                return Err("invalid printed timing schema/bounds/order".into());
            }
            self.last_end = end;
            self.records.push((kind, value));
        }
        Ok(())
    }
    pub fn validate(&self, report: &Value) -> Result<(), String> {
        let phases: Vec<_> = self
            .records
            .iter()
            .filter(|(kind, _)| *kind == "phase")
            .map(|(_, v)| v)
            .collect();
        let cases: Vec<_> = self
            .records
            .iter()
            .filter(|(kind, _)| *kind == "case")
            .map(|(_, v)| v.clone())
            .collect();
        let groups: Vec<_> = self
            .records
            .iter()
            .filter(|(kind, _)| *kind == "group")
            .map(|(_, v)| v.clone())
            .collect();
        let want_cases: Vec<_> = report["cases"]
            .as_array()
            .ok_or("missing timing case domain")?
            .iter()
            .map(|c| json!({"id":c["id"],"start_ns":c["start_ns"],"end_ns":c["end_ns"]}))
            .collect();
        if phases.len() != 5
            || cases != want_cases
            || json!(groups) != report["scenario_spans"]
            || self.evidence != self.records.len().checked_sub(1)
        {
            return Err("printed timing coverage/placement mismatch".into());
        }
        if phases[..4].iter().copied().ne(report["timings"]
            .as_array()
            .ok_or("missing timing phase domain")?
            .iter())
        {
            return Err("printed phase timing differs from execution report".into());
        }
        let execution = phases[4];
        if self.records.first().map(|(_, v)| v) != Some(phases[0])
            || self.records.get(1).map(|(_, v)| v) != Some(phases[1])
            || self.records.last().map(|(k, v)| (*k, v)) != Some(("phase", execution))
            || execution["phase"] != "execution"
            || execution.as_object().is_none_or(|v| v.len() != 3)
            || execution["start_ns"].as_u64() > phases[0]["start_ns"].as_u64()
            || execution["end_ns"].as_u64() < report["duration_ns"].as_u64()
        {
            return Err("printed execution timing envelope mismatch".into());
        }
        let groups_start = phases[2]["start_ns"].as_u64().unwrap();
        let groups_end = phases[2]["end_ns"].as_u64().unwrap();
        for (kind, value) in &self.records {
            if *kind != "phase"
                && (value["start_ns"].as_u64().is_none_or(|n| n < groups_start)
                    || value["end_ns"].as_u64().is_none_or(|n| n > groups_end))
            {
                return Err("printed case/group outside original groups phase".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Value, Vec<String>) {
        let report = json!({"cases":[{"id":"case","start_ns":3,"end_ns":4}],
            "scenario_spans":[{"id":"group","invocation":1,"start_ns":2,"end_ns":5}],
            "timings":[{"phase":"fixtures","start_ns":0,"end_ns":1},
                {"phase":"browser","start_ns":1,"end_ns":2},
                {"phase":"groups","start_ns":2,"end_ns":5},
                {"phase":"cleanup","start_ns":5,"end_ns":6}],"duration_ns":7});
        let lines = vec![
            format!("TRACER_TIMING {}", report["timings"][0]),
            format!("TRACER_TIMING {}", report["timings"][1]),
            format!("TRACER_CASE_TIMING {}", report["cases"][0]),
            format!("TRACER_GROUP_TIMING {}", report["scenario_spans"][0]),
            format!("TRACER_TIMING {}", report["timings"][2]),
            format!("TRACER_TIMING {}", report["timings"][3]),
            format!("TRACER_EVIDENCE {report}"),
            "TRACER_TIMING {\"phase\":\"execution\",\"start_ns\":0,\"end_ns\":8}".into(),
        ];
        (report, lines)
    }
    fn check(report: &Value, lines: &[String]) -> Result<(), String> {
        let mut output = Output::default();
        for line in lines {
            output.observe(line)?;
        }
        output.validate(report)
    }
    #[test]
    fn printed_timing_controls_require_the_actual_complete_stream() {
        let (report, lines) = fixture();
        assert!(check(&report, &lines).is_ok());
        let mut mutants = Vec::new();
        let mut bad = lines.clone();
        bad.remove(2);
        mutants.push(bad);
        let mut bad = lines.clone();
        bad.insert(2, lines[2].clone());
        mutants.push(bad);
        let mut bad = lines.clone();
        bad.swap(0, 1);
        mutants.push(bad);
        let mut bad = lines.clone();
        bad.swap(6, 7);
        mutants.push(bad);
        let mut bad = lines.clone();
        bad[2] = "TRACER_CASE_TIMING {}".into();
        mutants.push(bad);
        let mut bad = lines.clone();
        bad[7] =
            "TRACER_TIMING {\"phase\":\"execution\",\"start_ns\":0,\"end_ns\":9007199254740992}"
                .into();
        mutants.push(bad);
        let mut bad = lines.clone();
        bad[0] = "TRACER_TIMING {\"phase\":\"fixtures\",\"start_ns\":0,\"end_ns\":99,\"end_ns\":1}"
            .into();
        mutants.push(bad);
        for (index, bad) in mutants.iter().enumerate() {
            assert!(check(&report, bad).is_err(), "timing mutant {index}");
            assert!(
                check(&report, &lines).is_ok(),
                "restored timing stream {index}"
            );
        }
    }
}
