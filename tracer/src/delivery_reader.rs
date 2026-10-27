//! Independent delivery-record inspection; does not calculate a delivery verdict.
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
fn exact(v: &Value, keys: &[&str]) -> Result<(), String> {
    if v.as_object()
        .is_some_and(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)))
    {
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
            if c["session"].as_str().is_none_or(str::is_empty) {
                return Err("delivery session".into());
            }
            let a = &c["authority"];
            exact(a, &["machine", "requirements", "class", "declaration"])?;
            if a["machine"].as_str().is_none_or(str::is_empty)
                || a["requirements"].as_u64().is_none()
            {
                return Err("delivery authority".into());
            }
            if !["single_purpose", "multi_tenant"]
                .iter()
                .any(|s| a["class"] == *s)
            {
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
            if !m["placing_session"].is_boolean() {
                return Err("placing-session evidence".into());
            }
            for f in [
                "inbound",
                "outbound",
                "services",
                "spendable",
                "permitted",
                "required",
                "credentials",
                "fixed_default_credentials",
                "sshd_posture",
            ] {
                let measurement = &m[f];
                match measurement["read"].as_str() {
                    Some("missing" | "failed") => exact(measurement, &["read"])?,
                    Some("value") => {
                        exact(measurement, &["read", "value"])?;
                        if ["spendable", "fixed_default_credentials", "sshd_posture"].contains(&f) {
                            if !measurement["value"].is_boolean() {
                                return Err("boolean measurement".into());
                            }
                        } else if !measurement["value"].is_array() {
                            return Err("set measurement".into());
                        }
                    }
                    _ => return Err("measurement read state".into()),
                }
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
                if !r[f].is_boolean() {
                    return Err("delivery result flag".into());
                }
            }
            for row in r["fields"].as_array().ok_or("delivery field results")? {
                exact(row, &["field", "status", "findings", "notes"])?;
                if ![
                    "checked",
                    "finding",
                    "blocked",
                    "schema_error",
                    "unavailable",
                ]
                .iter()
                .any(|s| row["status"] == *s)
                {
                    return Err("delivery field status".into());
                }
                field(&row["field"])?;
            }
            for finding in r["findings"].as_array().ok_or("delivery findings")? {
                exact(finding, &["field", "detail", "service"])?;
                field(&finding["field"])?;
                if !finding["detail"].is_string() {
                    return Err("finding text".into());
                }
            }
            for note in r["notes"].as_array().ok_or("delivery notes")? {
                exact(note, &["service", "text"])?;
                if ![
                    "enabled, restart not demonstrated",
                    "stopped since a restart, as approved",
                ]
                .iter()
                .any(|s| note["text"] == *s)
                {
                    return Err("unknown delivery evidence note".into());
                }
            }
        }
        Some("application") => {
            exact(v, &["kind", "machine", "name"])?;
            if v["name"].as_str().is_none_or(str::is_empty) {
                return Err("application name".into());
            }
        }
        Some("findings_unknown") => exact(v, &["kind", "machine"])?,
        Some("subsequent_placement") => exact(v, &["kind", "machine", "session"])?,
        _ => return Err("delivery record kind".into()),
    }
    Ok(())
}
fn field(v: &Value) -> Result<(), String> {
    if [
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
    .any(|s| v == *s)
    {
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
        if let Some(c) = event.pointer("/setup/class") {
            self.classes.insert(
                c["machine"].as_str().ok_or("class machine")?.into(),
                c["class"].clone(),
            );
        }
        if let Some(p) = event.pointer("/setup/requirements/proposal") {
            let machine = p["machine"]
                .as_str()
                .ok_or("requirements machine")?
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
                let machine = a["machine"].as_str().ok_or("delivery machine")?;
                if self.declarations.get(machine) != Some(&a["declaration"])
                    || self.classes.get(machine) != Some(&a["class"])
                    || self.counts.get(machine).copied() != a["requirements"].as_u64()
                {
                    return Err("delivery authority differs from journaled requirements".into());
                }
            }
            if v["kind"] == "application"
                && !self.applications.insert((
                    v["machine"].as_str().ok_or("application machine")?.into(),
                    v["name"].as_str().ok_or("application name")?.into(),
                ))
            {
                return Err("duplicate application on machine".into());
            }
        }
        Ok(())
    }
}
