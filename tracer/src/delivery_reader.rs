//! Independent delivery-record inspection; does not calculate a delivery verdict.
use crate::semantic;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
fn exact(v: &Value, keys: &[&str]) -> Result<(), String> {
    if semantic::holds(
        semantic::catalogue("delivery.g001", keys),
        v.as_object()
            .is_some_and(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k))),
    ) {
        Ok(())
    } else {
        Err("delivery members".into())
    }
}
pub(super) fn shape(v: &Value) -> Result<(), String> {
    match v["kind"].as_str() {
        Some("check") => {
            exact(v, &["kind", "check"])?;
            let c = &v["check"];
            exact(c, &["session", "authority", "measurements", "result"])?;
            if semantic::rejects(
                "delivery.g002",
                c["session"].as_str().is_none_or(str::is_empty),
            ) {
                return Err("delivery session".into());
            }
            let a = &c["authority"];
            exact(a, &["machine", "requirements", "class", "declaration"])?;
            if semantic::rejects(
                "delivery.g003",
                a["machine"].as_str().is_none_or(str::is_empty)
                    || a["requirements"].as_u64().is_none(),
            ) {
                return Err("delivery authority".into());
            }
            if semantic::rejects(
                "delivery.g004",
                !["single_purpose", "multi_tenant"]
                    .iter()
                    .any(|s| a["class"] == *s),
            ) {
                return Err("delivery class".into());
            }
            crate::declaration_reader::declaration(
                &a["declaration"],
                a["class"] == "multi_tenant",
            )?;
            let m = &c["measurements"];
            exact(
                m,
                &[
                    "inbound",
                    "outbound",
                    "services",
                    "spendable",
                    "permitted",
                    "required",
                    "credentials",
                    "fixed_default_credentials",
                    "sshd_posture",
                    "placing_session",
                ],
            )?;
            if semantic::rejects("delivery.g005", !m["placing_session"].is_boolean()) {
                return Err("placing-session evidence".into());
            }
            for (source_index, f) in [
                "inbound",
                "outbound",
                "services",
                "spendable",
                "permitted",
                "required",
                "credentials",
                "fixed_default_credentials",
                "sshd_posture",
            ]
            .into_iter()
            .enumerate()
            {
                let _source_slot = semantic::Slot::new("delivery.measurement", source_index);
                let measurement = &m[f];
                match measurement["read"].as_str() {
                    Some("missing" | "failed") => exact(measurement, &["read"])?,
                    Some("value") => {
                        exact(measurement, &["read", "value"])?;
                        if ["spendable", "fixed_default_credentials", "sshd_posture"].contains(&f) {
                            if semantic::rejects(
                                semantic::field_site("delivery.g006", f),
                                !measurement["value"].is_boolean(),
                            ) {
                                return Err("boolean measurement".into());
                            }
                        } else if semantic::rejects(
                            semantic::field_site("delivery.g007", f),
                            !measurement["value"].is_array(),
                        ) {
                            return Err("set measurement".into());
                        }
                    }
                    _ => return Err("measurement read state".into()),
                }
                semantic::entered("delivery.g008");
            }
            let r = &c["result"];
            exact(
                r,
                &[
                    "fields",
                    "findings",
                    "notes",
                    "complete",
                    "delivered",
                    "placement_eligible",
                    "findings_unknown",
                ],
            )?;
            for f in [
                "complete",
                "delivered",
                "placement_eligible",
                "findings_unknown",
            ] {
                if semantic::rejects(semantic::field_site("delivery.g009", f), !r[f].is_boolean()) {
                    return Err("delivery result flag".into());
                }
            }
            for (source_index, row) in semantic::result(
                "delivery.g010",
                r["fields"].as_array().ok_or("delivery field results"),
            )?
            .iter()
            .enumerate()
            {
                let _source_slot = semantic::Slot::new("delivery.result_field", source_index);
                exact(row, &["field", "status", "findings", "notes"])?;
                if semantic::rejects(
                    "delivery.g011",
                    ![
                        "checked",
                        "finding",
                        "blocked",
                        "schema_error",
                        "unavailable",
                    ]
                    .iter()
                    .any(|s| row["status"] == *s),
                ) {
                    return Err("delivery field status".into());
                }
                field(&row["field"])?;
            }
            for (source_index, finding) in semantic::result(
                "delivery.g012",
                r["findings"].as_array().ok_or("delivery findings"),
            )?
            .iter()
            .enumerate()
            {
                let _source_slot = semantic::Slot::new("delivery.finding", source_index);
                exact(finding, &["field", "detail", "service"])?;
                field(&finding["field"])?;
                if semantic::rejects("delivery.g013", !finding["detail"].is_string()) {
                    return Err("finding text".into());
                }
            }
            for (source_index, note) in semantic::result(
                "delivery.g014",
                r["notes"].as_array().ok_or("delivery notes"),
            )?
            .iter()
            .enumerate()
            {
                let _source_slot = semantic::Slot::new("delivery.note", source_index);
                exact(note, &["service", "text"])?;
                if semantic::rejects(
                    "delivery.g015",
                    ![
                        "enabled, restart not demonstrated",
                        "stopped since a restart, as approved",
                    ]
                    .iter()
                    .any(|s| note["text"] == *s),
                ) {
                    return Err("unknown delivery evidence note".into());
                }
            }
        }
        Some("application") => {
            exact(v, &["kind", "machine", "name"])?;
            if semantic::rejects(
                "delivery.g016",
                v["name"].as_str().is_none_or(str::is_empty),
            ) {
                return Err("application name".into());
            }
        }
        Some("findings_unknown") => exact(v, &["kind", "machine"])?,
        Some("subsequent_placement") => exact(v, &["kind", "machine", "session"])?,
        _ => return Err("delivery record kind".into()),
    }
    semantic::entered("delivery.g017");
    Ok(())
}
fn field(v: &Value) -> Result<(), String> {
    if semantic::holds(
        semantic::field_site("delivery.g018", v.as_str().unwrap_or("unknown")),
        [
            "version",
            "inbound",
            "outbound",
            "services",
            "spendable",
            "permitted",
            "drift_checks",
            "required",
            "default_credentials",
            "fixed_default_credentials",
            "sshd_posture",
        ]
        .iter()
        .any(|s| v == *s),
    ) {
        Ok(())
    } else {
        Err("delivery result field".into())
    }
}
#[derive(Default)]
pub(super) struct History {
    declarations: BTreeMap<String, Value>,
    classes: BTreeMap<String, Value>,
    counts: BTreeMap<String, u64>,
    applications: BTreeSet<(String, String)>,
}
impl History {
    pub fn apply(&mut self, event: &Value) -> Result<(), String> {
        semantic::entered("delivery.history");

        if let Some(c) = event.pointer("/setup/class") {
            self.classes.insert(
                semantic::result(
                    "delivery.history.class_machine",
                    c["machine"].as_str().ok_or("class machine"),
                )?
                .into(),
                c["class"].clone(),
            );
        }
        if let Some(p) = event.pointer("/setup/requirements/proposal") {
            let machine = semantic::result(
                "delivery.history.requirements_machine",
                p["machine"].as_str().ok_or("requirements machine"),
            )?
            .to_owned();
            *self.counts.entry(machine.clone()).or_default() += 1;
            if p["kind"] == "declaration" {
                self.declarations.insert(machine, p["declaration"].clone());
            } else {
                self.classes.insert(machine, p["class"].clone());
            }
        }
        if let Some(v) = event.get("delivery") {
            shape(v)?;
            if v["kind"] == "check" {
                let a = &v["check"]["authority"];
                let machine = semantic::result(
                    "delivery.history.authority_machine",
                    a["machine"].as_str().ok_or("delivery machine"),
                )?;
                if semantic::rejects(
                    "delivery.g019",
                    self.declarations.get(machine) != Some(&a["declaration"])
                        || self.classes.get(machine) != Some(&a["class"])
                        || self.counts.get(machine).copied() != a["requirements"].as_u64(),
                ) {
                    return Err("delivery authority differs from journaled requirements".into());
                }
            }
            if semantic::rejects(
                "delivery.g021",
                v["kind"] == "application"
                    && !self.applications.insert((
                        semantic::result(
                            "delivery.g020",
                            v["machine"].as_str().ok_or("application machine"),
                        )?
                        .into(),
                        semantic::result(
                            "delivery.history.application_name",
                            v["name"].as_str().ok_or("application name"),
                        )?
                        .into(),
                    )),
            ) {
                return Err("duplicate application on machine".into());
            }
        }
        Ok(())
    }
}
