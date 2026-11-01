//! Source-owned scalar and correlated-object predicates outside serial helper frames.
use super::{completion, history, json, reader_checks};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Mutex};
static COUNTS: Mutex<BTreeMap<&'static str, usize>> = Mutex::new(BTreeMap::new());
pub trait Observe: Sized {
    fn checked(self, id: &'static str) -> Self;
}
impl<T, E> Observe for Result<T, E> {
    fn checked(self, id: &'static str) -> Self {
        let mut counts = COUNTS.lock().unwrap();
        let count = counts.entry(id).or_default();
        *count += 1;
        history::event(
            json!({"event":"logical_check","id":id,"instance":format!("{id}.i{count:03}"),"ok":self.is_ok()}),
        );
        self
    }
}
type Owner = (String, String, String);
pub fn validate(report: &Value) -> Result<(), String> {
    let error = "original logical predicate/source/instance/order mismatch";
    let requirements = if report["mode"] == "full" {
        completion::inventory()
    } else {
        &report["plan"]
    };
    let execution: Vec<_> = if report["mode"] == "full" {
        completion::inventory()["cases"]
            .as_array()
            .ok_or(error)?
            .iter()
            .map(|c| c["id"].clone())
            .collect()
    } else {
        requirements["expected_execution"]
            .as_array()
            .ok_or(error)?
            .clone()
    };
    let mut rows = Vec::new();
    for (order, row) in completion::inventory()["logical_predicate_sources"]
        .as_array()
        .ok_or(error)?
        .iter()
        .enumerate()
    {
        let Some(index) = execution.iter().position(|id| *id == row["case"]) else {
            continue;
        };
        let source = row["scenario"].as_str().ok_or(error)?;
        let selected = source
            .strip_suffix(".run")
            .map(|prefix| format!("{prefix}.selected"));
        let scenario = selected
            .as_ref()
            .filter(|name| requirements["scenario_scopes"].get(*name).is_some())
            .map_or(source, |name| name.as_str());
        let before = row["position"] == "before";
        let case = if before {
            index
                .checked_sub(1)
                .map(|i| execution[i].as_str().unwrap())
                .unwrap_or("")
        } else {
            execution[index].as_str().ok_or(error)?
        };
        rows.push((
            index,
            usize::from(!before),
            order,
            (
                scenario.to_owned(),
                if before { "after" } else { "inside" }.to_owned(),
                case.to_owned(),
            ),
            row,
        ));
    }
    rows.sort_by_key(|(index, position, order, _, _)| (*index, *position, *order));
    let mut expected: BTreeMap<Owner, Vec<&str>> = BTreeMap::new();
    for (_, _, _, owner, row) in rows {
        expected.entry(owner).or_default().extend(
            row["predicates"]
                .as_array()
                .ok_or(error)?
                .iter()
                .map(|id| id.as_str().unwrap()),
        );
    }
    let states = reader_checks::caller_states(report);
    let events = report["helper_history"].as_array().ok_or(error)?;
    let mut positions = BTreeMap::new();
    let mut instances = BTreeMap::new();
    let mut total = 0;
    for (index, event) in events
        .iter()
        .enumerate()
        .filter(|(_, e)| e["event"] == "logical_check")
    {
        let owner = states[index].owner.as_ref().ok_or(error)?;
        let position = positions.entry(owner.clone()).or_insert(0usize);
        let id = *expected
            .get(owner)
            .and_then(|ids| ids.get(*position))
            .ok_or(error)?;
        *position += 1;
        total += 1;
        let instance = instances.entry(id).or_insert(0usize);
        *instance += 1;
        if event["id"] != id
            || event["instance"] != format!("{id}.i{instance:03}")
            || event["ok"] != true
        {
            return Err(error.into());
        }
    }
    if total != expected.values().map(Vec::len).sum::<usize>() {
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn report() -> Value {
        json!({"mode":"targeted","plan":{"expected_execution":["lifecycle_repairs.c002.p002"],"scenario_scopes":{"lifecycle_repairs.run":1}},"helper_history":[
            {"event":"scenario_start","invocation":1,"id":"lifecycle_repairs.run","at_ns":0},
            {"event":"logical_check","id":"repairs.transition.mint","instance":"repairs.transition.mint.i001","ok":true,"at_ns":1},
            {"event":"logical_check","id":"repairs.transition.expiry","instance":"repairs.transition.expiry.i001","ok":true,"at_ns":2},
            {"event":"logical_check","id":"repairs.transition.anchor","instance":"repairs.transition.anchor.i001","ok":true,"at_ns":3},
            {"event":"case_start","id":"lifecycle_repairs.c002.p002","at_ns":4},
            {"event":"case_end","id":"lifecycle_repairs.c002.p002","at_ns":5},
            {"event":"scenario_end","invocation":1,"id":"lifecycle_repairs.run","at_ns":6}]})
    }
    #[test]
    fn original_source_predicates_cannot_be_omitted_moved_or_reordered() {
        let report = report();
        assert!(validate(&report).is_ok());
        let mut bad = report.clone();
        bad["helper_history"].as_array_mut().unwrap().remove(2);
        assert!(validate(&bad).is_err());
        let mut bad = report.clone();
        bad["helper_history"].as_array_mut().unwrap().swap(1, 2);
        assert!(validate(&bad).is_err());
        let mut bad = report.clone();
        bad["helper_history"][2]["instance"] = json!("repairs.transition.expiry.i002");
        assert!(validate(&bad).is_err());
        let mut bad = report.clone();
        bad["helper_history"][2]["ok"] = json!(false);
        assert!(validate(&bad).is_err());
        let mut bad = report.clone();
        bad["helper_history"].as_array_mut().unwrap().swap(3, 4);
        assert!(validate(&bad).is_err());
        assert!(validate(&report).is_ok());
    }
}
