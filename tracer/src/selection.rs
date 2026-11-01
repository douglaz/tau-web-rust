//! Admission happens before artifact reads, fixture creation or browser launch.
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

static SELECTION: OnceLock<BTreeMap<String, String>> = OnceLock::new();

pub fn current() -> BTreeMap<String, String> {
    SELECTION.get().cloned().unwrap_or_default()
}

pub fn normalized(selection: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut result = selection.clone();
    for name in ["MODE_CASE", "GOALS", "DELIVERY", "INFERENCE"] {
        if let Some(value) = result.get_mut(&format!("TAU_TRACER_{name}")) {
            *value = "all".into();
        }
    }
    result
}

/// Dispatch and naming are code-owned; required coverage is computed separately.
pub fn plan(selection: &BTreeMap<String, String>) -> Result<Value, String> {
    let selection = normalized(selection);
    let source = super::catalogue::plan(&selection)?;
    let expected = super::requirements::plan(&selection)?;
    for (field, value) in source.as_object().unwrap() {
        if expected[field] != *value {
            return Err(format!(
                "executable catalogue/projection differs from independent key: {field}"
            ));
        }
    }
    Ok(expected)
}

pub fn value(name: &str) -> Result<String, std::env::VarError> {
    SELECTION
        .get()
        .and_then(|s| s.get(name))
        .cloned()
        .ok_or(std::env::VarError::NotPresent)
}

pub fn present(name: &str) -> Option<std::ffi::OsString> {
    value(name).ok().map(Into::into)
}

pub fn admit(mode: &str, explicit: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut entries = Vec::new();
    for (name, val) in std::env::vars_os() {
        if name.as_encoded_bytes().starts_with(b"TAU_TRACER_") {
            let name = name.to_string_lossy().into_owned();
            if mode != "targeted" {
                return Err(format!("full admission refuses inherited {name}"));
            }
            let val = val
                .into_string()
                .map_err(|_| format!("invalid selection: {name}"))?;
            entries.push((name, val));
        }
    }
    if mode != "targeted" && !explicit.is_empty() {
        return Err("full admission refuses explicit filtering".into());
    }
    for arg in explicit {
        let (name, val) = arg.split_once('=').ok_or("selection must be NAME=VALUE")?;
        entries.push((name.into(), val.into()));
    }
    validate(mode, &entries)
}

pub fn validate(
    mode: &str,
    entries: &[(String, String)],
) -> Result<BTreeMap<String, String>, String> {
    let schema: Value =
        serde_json::from_str(include_str!("../selectors.json")).map_err(|e| e.to_string())?;
    let mut result = BTreeMap::new();
    for (name, val) in entries {
        let allowed = schema
            .get(name)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("unknown selection: {name}"))?;
        if val.is_empty() || result.insert(name.clone(), val.clone()).is_some() {
            return Err(format!("empty or conflicting selection: {name}"));
        }
        if name == "TAU_TRACER_SESSION_END" {
            let inventory = super::catalogue::cases();
            let parts = val.split(',').collect::<Vec<_>>();
            if parts
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != parts.len()
            {
                return Err(format!("duplicate selection: {name}"));
            }
            for part in val.split(',') {
                if part.is_empty()
                    || !inventory.as_array().unwrap().iter().any(|c| {
                        c["site_id"]
                            .as_str()
                            .unwrap()
                            .starts_with("session_end_cases.")
                            && part.strip_prefix('=').map_or_else(
                                || c["label"].as_str().unwrap().contains(part),
                                |exact| c["label"] == exact,
                            )
                    })
                {
                    return Err(format!("unknown or empty selection: {name}"));
                }
            }
        } else {
            let parts: Vec<_> = if name == "TAU_TRACER_HOLD_CASE" {
                val.split(',').collect()
            } else {
                vec![val.as_str()]
            };
            if parts
                .iter()
                .any(|p| !allowed.iter().any(|a| a == p || a == "*"))
                || (parts.len() > 1 && parts.contains(&"all"))
                || parts
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != parts.len()
            {
                return Err(format!("unknown or conflicting selection: {name}"));
            }
        }
    }
    let has = |name: &str| result.contains_key(name);
    let roots = [
        "HOLD_CASE",
        "SEED_CASE",
        "SETUP_CASE",
        "MODE_CASE",
        "GOALS",
        "DELIVERY",
        "INFERENCE",
    ];
    if roots
        .iter()
        .filter(|r| has(&format!("TAU_TRACER_{r}")))
        .count()
        > 1
    {
        return Err("conflicting selection groups".into());
    }
    for (child, parent) in [
        ("GOAL_CASE", "GOALS"),
        ("DELIVERY_CASE", "DELIVERY"),
        ("INFERENCE_PHASE", "INFERENCE"),
        ("INFERENCE_END", "INFERENCE"),
        ("SESSION_END", "INFERENCE"),
    ] {
        if has(&format!("TAU_TRACER_{child}")) && !has(&format!("TAU_TRACER_{parent}")) {
            return Err(format!(
                "selection TAU_TRACER_{child} requires TAU_TRACER_{parent}"
            ));
        }
    }
    if has("TAU_TRACER_INFERENCE_END") && has("TAU_TRACER_INFERENCE_PHASE") {
        return Err("conflicting inference selections".into());
    }
    if has("TAU_TRACER_SESSION_END")
        && result.get("TAU_TRACER_INFERENCE_PHASE").map(String::as_str) != Some("session-end")
    {
        return Err("TAU_TRACER_SESSION_END requires the session-end phase".into());
    }
    if mode == "targeted" && result.is_empty() {
        return Err("targeted mode requires a selection".into());
    }
    Ok(result)
}

pub fn install(selection: BTreeMap<String, String>) -> Result<(), String> {
    SELECTION
        .set(selection)
        .map_err(|_| "selection already installed".into())
}

#[cfg(test)]
pub fn test_selections() -> Vec<BTreeMap<String, String>> {
    let schema: Value = serde_json::from_str(include_str!("../selectors.json")).unwrap();
    let mut selections = Vec::new();
    for root in [
        "HOLD_CASE",
        "SEED_CASE",
        "SETUP_CASE",
        "MODE_CASE",
        "GOALS",
        "DELIVERY",
        "INFERENCE",
    ] {
        let name = format!("TAU_TRACER_{root}");
        for value in schema[&name].as_array().unwrap() {
            selections.push(BTreeMap::from([(
                name.clone(),
                if value == "*" {
                    "all".into()
                } else {
                    value.as_str().unwrap().into()
                },
            )]));
        }
    }
    for (child, parent) in [
        ("GOAL_CASE", "GOALS"),
        ("DELIVERY_CASE", "DELIVERY"),
        ("INFERENCE_PHASE", "INFERENCE"),
        ("INFERENCE_END", "INFERENCE"),
    ] {
        for value in schema[format!("TAU_TRACER_{child}")].as_array().unwrap() {
            selections.push(BTreeMap::from([
                (format!("TAU_TRACER_{parent}"), "all".into()),
                (
                    format!("TAU_TRACER_{child}"),
                    value.as_str().unwrap().into(),
                ),
            ]));
        }
    }
    selections
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_owner_registry_references_declared_cases_and_scenarios() {
        let inventory = super::super::completion::inventory();
        let full = serde_json::json!({"helper_owner_sequences":inventory["helper_owner_sequences"],"expected_execution":inventory["cases"].as_array().unwrap().iter().map(|c|c["id"].clone()).collect::<Vec<_>>(),"scenario_scopes":inventory["scenario_scopes"]});
        let plans = test_selections()
            .iter()
            .map(|selection| plan(selection).unwrap())
            .collect::<Vec<_>>();
        for plan in std::iter::once(&full).chain(&plans) {
            let mut owners = std::collections::BTreeSet::new();
            for row in plan["helper_owner_sequences"].as_array().unwrap() {
                let scenario = row["scenario"].as_str().unwrap();
                let case = row["case"].as_str().unwrap_or("");
                let owner = row["owner"].as_str().unwrap();
                assert!(
                    plan["scenario_scopes"].get(scenario).is_some(),
                    "{scenario}"
                );
                assert!(
                    case.is_empty()
                        || plan["expected_execution"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|id| id == case),
                    "{case}"
                );
                assert!(["inside", "after"].contains(&owner));
                assert!(
                    owners.insert((scenario, owner, case)),
                    "duplicate caller owner"
                );
            }
        }
    }
    #[test]
    fn admission_child() {
        if std::env::var_os("TRACER_ADMISSION_CONTROL").is_none() {
            return;
        }
        if std::env::var("TRACER_ADMISSION_CONTROL").as_deref() == Ok("eligible") {
            assert!(admit("full", &[]).is_ok());
            let entries = vec![
                ("TAU_TRACER_GOALS".into(), "1".into()),
                ("TAU_TRACER_GOAL_CASE".into(), "admission".into()),
            ];
            assert!(plan(&validate("targeted", &entries).unwrap()).is_ok());
            return;
        }
        let result = admit("full", &[]).unwrap_err();
        assert!(
            result.starts_with("full admission refuses inherited TAU_TRACER_"),
            "{result}"
        );
        assert!(!result.contains("never-print-this-value"));
    }

    #[test]
    fn full_admission_is_early_and_names_only() {
        let mut eligible = std::process::Command::new(std::env::current_exe().unwrap());
        for (name, _) in std::env::vars_os() {
            if name.as_encoded_bytes().starts_with(b"TAU_TRACER_") {
                eligible.env_remove(name);
            }
        }
        assert!(
            eligible
                .args(["--exact", "selection::tests::admission_child"])
                .env("TRACER_ADMISSION_CONTROL", "eligible")
                .status()
                .unwrap()
                .success()
        );
        for (name, value) in [
            ("TAU_TRACER_GOALS", "never-print-this-value"),
            ("TAU_TRACER_UNKNOWN", ""),
            ("TAU_TRACER_UNKNOWN", "never-print-this-value"),
        ] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            for (key, _) in std::env::vars_os() {
                if key.as_encoded_bytes().starts_with(b"TAU_TRACER_") {
                    command.env_remove(key);
                }
            }
            let output = command
                .args([
                    "--exact",
                    "selection::tests::admission_child",
                    "--nocapture",
                ])
                .env("TRACER_ADMISSION_CONTROL", "1")
                .env(name, value)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
        assert!(
            admit("full", &["filter".into()])
                .unwrap_err()
                .contains("explicit filtering")
        );
    }
    #[test]
    fn hierarchy_and_refusals() {
        let pairs = |s: &[(&str, &str)]| {
            s.iter()
                .map(|(k, v)| (format!("TAU_TRACER_{k}"), v.to_string()))
                .collect::<Vec<_>>()
        };
        for entry in [
            pairs(&[("GOALS", "1"), ("GOAL_CASE", "admission")]),
            pairs(&[
                ("INFERENCE", "1"),
                ("INFERENCE_PHASE", "session-end"),
                ("SESSION_END", "at kex"),
            ]),
            pairs(&[("HOLD_CASE", "drop,stop")]),
        ] {
            assert!(validate("targeted", &entry).is_ok(), "{entry:?}");
        }
        for entry in [
            pairs(&[("UNKNOWN", "")]),
            pairs(&[("GOALS", "")]),
            pairs(&[("GOAL_CASE", "admission")]),
            pairs(&[("GOALS", "1"), ("INFERENCE", "1")]),
            pairs(&[("HOLD_CASE", "drop,drop")]),
            pairs(&[("HOLD_CASE", "all,drop")]),
            pairs(&[("INFERENCE", "1"), ("SESSION_END", "kex")]),
        ] {
            assert!(validate("targeted", &entry).is_err());
        }
    }
}
