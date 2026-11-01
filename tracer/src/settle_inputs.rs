//! Conditional fixture disposition reads its original worker projection exactly once.
use super::{completion, history};
use serde_json::{Value, json};
use std::sync::Mutex;

static SLOTS: Mutex<std::collections::BTreeMap<String, usize>> =
    Mutex::new(std::collections::BTreeMap::new());
static INPUTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static DISPOSITIONS: Mutex<std::collections::BTreeMap<usize, Value>> =
    Mutex::new(std::collections::BTreeMap::new());

pub struct Calls {
    source: usize,
    selected: Vec<Value>,
}

pub async fn inspect(
    site: &'static str,
    run: &super::Run<'_>,
    tab: &super::Tab,
    worker: &super::Worker,
) -> Result<Calls, String> {
    let start = completion::now();
    let cursor = history::cursor();
    let (identity, page) = history::worker_identity(&worker.session);
    let state = run.inspect(worker).await?;
    let calls = state["calls"]
        .as_array()
        .ok_or("no fixture call projection")?;
    let domain: Vec<_> = calls
        .iter()
        .map(|call| [call["machine"] == "fixture", call["state"] == "unresolved"])
        .collect();
    let selected = calls
        .iter()
        .filter(|call| call["machine"] == "fixture" && call["state"] == "unresolved")
        .map(|call| call["call"].clone())
        .collect();
    let mut inputs = INPUTS.lock().unwrap();
    let source = inputs.len() + 1;
    inputs.push(json!({"source":source,"site":site,"page":page,"worker":identity,"input":domain,"empty_tests":0,"empty":null,"dispositions":0,"constructor_uses":0,"reader_origin":null,"puts":[],"start_ns":start,"start_cursor":cursor,"end_ns":null,"end_cursor":null,"ok":page==history::page_id(&tab.session)&&history::selected_worker_matches(page,worker)}));
    Ok(Calls { source, selected })
}

impl Calls {
    pub fn is_empty(&self) -> bool {
        let empty = self.selected.is_empty();
        let mut inputs = INPUTS.lock().unwrap();
        let row = &mut inputs[self.source - 1];
        row["empty_tests"] = json!(row["empty_tests"].as_u64().unwrap() + 1);
        row["empty"] = json!(empty);
        empty
    }

    pub fn disposition(&self) -> Value {
        let mut inputs = INPUTS.lock().unwrap();
        let row = &mut inputs[self.source - 1];
        row["dispositions"] = json!(row["dispositions"].as_u64().unwrap() + 1);
        let event = json!({"disposition":{"machine":"fixture","calls":self.selected,"continuation":"as_if_not_done","uncertainty":"the command outcome is unknown"}});
        DISPOSITIONS
            .lock()
            .unwrap()
            .insert(self.source, event.clone());
        event
    }
}

impl Drop for Calls {
    fn drop(&mut self) {
        let mut inputs = INPUTS.lock().unwrap();
        let row = &mut inputs[self.source - 1];
        row["end_ns"] = json!(completion::now());
        row["end_cursor"] = json!(history::cursor());
    }
}

pub fn original_slot(site: &str) -> Option<usize> {
    SLOTS.lock().unwrap().get(site).copied()
}
pub fn construction_valid() -> bool {
    INPUTS
        .lock()
        .unwrap()
        .last()
        .is_some_and(|r| r["end_ns"].is_null() && r["ok"] == true && r["constructor_uses"] == 1)
}

pub fn snapshot() -> Value {
    json!(*INPUTS.lock().unwrap())
}

pub fn put(tab: &super::Tab, files: &super::Files) {
    let mut inputs = INPUTS.lock().unwrap();
    if let Some(row) = inputs.last_mut()
        && row["end_ns"].is_null()
        && row["start_cursor"] == history::cursor()
    {
        row["puts"].as_array_mut().unwrap().push(json!({
            "input":files.input(), "page":history::page_id(&tab.session),
            "at_ns":completion::now(), "history_cursor":history::cursor()
        }));
    }
}

pub fn construction(site: &str, events: &[Value]) {
    if site != "file.main.build.008" {
        return;
    }
    let mut inputs = INPUTS.lock().unwrap();
    if let Some(row) = inputs.last_mut() {
        let source = row["source"].as_u64().unwrap() as usize;
        let expected = DISPOSITIONS.lock().unwrap().remove(&source);
        let origin = crate::reader_checks::last_origin();
        let original = crate::reader_checks::origin_site(origin).as_deref()
            == Some("reader.call.settle_unresolved.disposition_source")
            && events
                .split_last()
                .is_some_and(|(_, prefix)| crate::auxiliary::original_events_match(origin, prefix));
        row["reader_origin"] = json!(origin);
        row["ok"] = json!(
            row["ok"] == true
                && expected.is_some()
                && events.last() == expected.as_ref()
                && original
        );
        row["constructor_uses"] = json!(row["constructor_uses"].as_u64().unwrap() + 1);
        if row["ok"] == true
            && let Some(slot) = events.len().checked_sub(1)
        {
            SLOTS
                .lock()
                .unwrap()
                .insert(row["site"].as_str().unwrap().to_owned(), slot);
        }
    }
}

pub fn validate(report: &Value) -> Result<(), String> {
    validate_with(report, completion::inventory())
}

fn validate_with(report: &Value, key: &Value) -> Result<(), String> {
    let error = "original conditional disposition input/domain mismatch";
    let execution: Vec<_> = if report["mode"] == "full" {
        key["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].clone())
            .collect()
    } else {
        report["plan"]["expected_execution"]
            .as_array()
            .ok_or(error)?
            .clone()
    };
    let mut required = std::collections::BTreeMap::new();
    for rule in key["settle_call_rules"].as_array().ok_or(error)? {
        for case in key["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["site_id"] == rule[1] && execution.contains(&c["id"]))
        {
            let anchor = case["id"].as_str().ok_or(error)?;
            let scenario = format!(
                "{}.run",
                case["site_id"]
                    .as_str()
                    .ok_or(error)?
                    .split('.')
                    .next()
                    .unwrap()
            );
            let (position, anchor) = if rule[2] == "before" {
                let index = execution.iter().position(|c| c == anchor).ok_or(error)?;
                (
                    "after",
                    index
                        .checked_sub(1)
                        .map_or("", |i| execution[i].as_str().unwrap()),
                )
            } else {
                (rule[2].as_str().ok_or(error)?, anchor)
            };
            let owner = (
                scenario,
                position.to_owned(),
                anchor.to_owned(),
                case["invocation"].as_u64().ok_or(error)?,
            );
            required
                .entry(owner)
                .or_insert_with(Vec::new)
                .push(rule[0].as_str().ok_or(error)?.to_owned());
        }
    }
    let states = super::reader_checks::caller_states(report);
    let pages = history::source_page_states(report)?;
    let workers = history::worker_states(report);
    let history = report["helper_history"].as_array().ok_or(error)?;
    let captures = report["file_captures"].as_array().ok_or(error)?;
    let reads = report["reader_roots"].as_array().ok_or(error)?;
    let mut previous = 0;
    for (index, input) in report["settle_inputs"]
        .as_array()
        .ok_or(error)?
        .iter()
        .enumerate()
    {
        let start = input["start_ns"].as_u64().ok_or(error)?;
        let end = input["end_ns"].as_u64().ok_or(error)?;
        let cursor = input["start_cursor"].as_u64().ok_or(error)? as usize;
        let until = input["end_cursor"].as_u64().ok_or(error)? as usize;
        let state = states.get(cursor).ok_or(error)?;
        let owner = state.owner.as_ref().ok_or(error)?;
        let expected = required
            .get_mut(&(
                owner.0.clone(),
                owner.1.clone(),
                owner.2.clone(),
                state.invocation,
            ))
            .filter(|v| !v.is_empty())
            .ok_or(error)?
            .remove(0);
        let page = pages
            .get(cursor)
            .and_then(|p| p.get("tracer"))
            .ok_or(error)?;
        let domain = input["input"].as_array().ok_or(error)?;
        if domain.iter().any(|row| {
            row.as_array()
                .is_none_or(|a| a.len() != 2 || a.iter().any(|v| !v.is_boolean()))
        }) {
            return Err(error.into());
        }
        let empty = !domain.iter().any(|row| row[0] == true && row[1] == true);
        if input.as_object().is_none_or(|o| o.len() != 16)
            || input["source"] != index + 1
            || input["site"] != expected
            || input["ok"] != true
            || input["page"] != *page
            || workers[cursor]
                .get(page)
                .is_none_or(|w| input["worker"] != *w)
            || input["empty_tests"] != 1
            || input["empty"] != empty
            || input["dispositions"] != u64::from(!empty)
            || input["constructor_uses"] != u64::from(!empty)
            || start < previous
            || end < start
            || end > report["duration_ns"].as_u64().ok_or(error)?
            || until < cursor
            || until >= states.len()
            || states[until].owner.as_ref() != Some(owner)
            || states[until].invocation != state.invocation
            || cursor > 0 && history[cursor - 1]["at_ns"].as_u64().ok_or(error)? > start
            || cursor < history.len() && history[cursor]["at_ns"].as_u64().ok_or(error)? < start
            || until > 0 && history[until - 1]["at_ns"].as_u64().ok_or(error)? > end
            || until < history.len() && history[until]["at_ns"].as_u64().ok_or(error)? < end
        {
            return Err(error.into());
        }
        let within = |v: &&Value| v["at_ns"].as_u64().is_some_and(|t| start <= t && t <= end);
        let observed: Vec<_> = captures
            .iter()
            .filter(within)
            .filter(|c| c["site"] == "file.main.dump.017" || c["site"] == "file.main.build.008")
            .collect();
        let observed_reads: Vec<_> = reads
            .iter()
            .filter(|r| {
                r["site"] == "reader.call.settle_unresolved.disposition_source"
                    && r["start_ns"]
                        .as_u64()
                        .is_some_and(|t| start <= t && t <= end)
            })
            .collect();
        let puts = input["puts"].as_array().ok_or(error)?;
        if empty {
            if cursor != until
                || !observed.is_empty()
                || !observed_reads.is_empty()
                || !input["reader_origin"].is_null()
                || !puts.is_empty()
            {
                return Err(error.into());
            }
        } else {
            if observed.len() != 3
                || observed[0]["kind"] != "browser.dump"
                || observed[1]["kind"] != "browser.store"
                || observed[2]["kind"] != "constructor"
                || observed_reads.len() != 1
                || input["reader_origin"].as_u64().is_none_or(|origin| {
                    observed_reads[0]["instance"] != format!("reader.read.i{origin:03}")
                })
                || observed_reads[0]["file_input"]["source"] != observed[1]["source"]
                || observed_reads[0]["end_ns"].as_u64() > observed[2]["at_ns"].as_u64()
            {
                return Err(error.into());
            }
            let put = puts.first().ok_or(error)?;
            let operand = &put["input"];
            if puts.len() != 1
                || put.as_object().is_none_or(|o| o.len() != 4)
                || operand.as_object().is_none_or(|o| o.len() != 5)
                || operand["source"] != observed[2]["source"]
                || operand["kind"] != "constructor"
                || operand["site"] != "file.main.build.008"
                || operand["page"] != 0
                || operand["ok"] != true
                || put["page"] != *page
                || put["history_cursor"] != cursor
                || put["at_ns"].as_u64().is_none_or(|t| {
                    t < observed[2]["at_ns"].as_u64().unwrap()
                        || t > end
                        || history
                            .get(cursor)
                            .and_then(|e| e["at_ns"].as_u64())
                            .is_none_or(|next| t > next)
                })
            {
                return Err(error.into());
            }
            let mut depth = 0;
            let mut roots = Vec::new();
            for event in &history[cursor..until] {
                match event["event"].as_str() {
                    Some("call_start") => {
                        if depth == 0 {
                            roots.push(event["kind"].as_str().ok_or(error)?);
                        }
                        depth += 1;
                    }
                    Some("call_end") if depth > 0 => depth -= 1,
                    _ => {}
                }
            }
            if depth != 0 || roots != ["runtime.worker", "runtime.submit", "binding.prepare"] {
                return Err(error.into());
            }
        }
        previous = end;
    }
    if required.values().any(|v| !v.is_empty()) {
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disposition_prefix_is_the_original_authenticated_reader_input() {
        let events = [
            json!({"seed":{"mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}}),
        ];
        let pass = "original disposition input passphrase";
        let files = crate::reader::build(pass, &events);
        let opened = crate::reader::read_at(
            "reader.call.settle_unresolved.disposition_source",
            &files,
            pass,
        )
        .unwrap();
        assert!(crate::auxiliary::original_events_match(
            opened.origin(),
            &events
        ));
        let mut changed = events.clone();
        changed[0]["seed"]["mnemonic"] = json!("replaced");
        assert!(!crate::auxiliary::original_events_match(
            opened.origin(),
            &changed
        ));
        assert!(!crate::auxiliary::original_events_match(
            opened.origin(),
            &[]
        ));
        assert!(crate::auxiliary::original_events_match(
            opened.origin(),
            &events
        ));
    }
    #[test]
    fn original_predicate_requires_both_empty_and_nonempty_paths() {
        let fixture: Value =
            serde_json::from_str(include_str!("../testdata/settle-inputs.json")).unwrap();
        for branch in ["empty", "nonempty"] {
            let base = &fixture[branch];
            let check = |report: &Value| validate_with(report, &fixture["key"]);
            check(base).unwrap();
            if branch == "nonempty" {
                for (pointer, value) in [
                    ("/settle_inputs/0/puts", json!([])),
                    ("/settle_inputs/0/puts/0/input/source", json!(2)),
                    ("/settle_inputs/0/puts/0/input/ok", json!(false)),
                    ("/settle_inputs/0/puts/0/page", json!(999)),
                    ("/settle_inputs/0/puts/0/history_cursor", json!(0)),
                ] {
                    let mut bad = base.clone();
                    *bad.pointer_mut(pointer).unwrap() = value;
                    assert!(check(&bad).is_err(), "{pointer}");
                }
            }
            let mut missing = base.clone();
            missing["settle_inputs"] = json!([]);
            assert!(check(&missing).is_err());
            for (field, value) in [
                ("empty", json!(branch != "empty")),
                ("empty_tests", json!(0)),
                ("constructor_uses", json!(2)),
                ("page", json!(999)),
            ] {
                let mut bad = base.clone();
                bad["settle_inputs"][0][field] = value;
                assert!(check(&bad).is_err(), "{branch}: {field}");
            }
            check(base).unwrap();
        }
    }
}
