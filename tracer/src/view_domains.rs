//! Independent requirements for original view queries and their typed consumers.
use crate::{completion, history, reader_checks};
use serde_json::{Value, json};
use std::collections::BTreeMap;
const ERROR: &str = "original page view query/input/predicate correspondence mismatch";
struct Expected {
    fields: Value,
    start: u64,
    end: u64,
    cursor: usize,
    checkpoint: Option<(String, String)>,
}
type Program = BTreeMap<String, Expected>;
fn capture_key(v: &Value) -> String {
    json!([
        v["kind"],
        v["site"],
        v["call"],
        v["attempt"],
        v["slot"],
        v["case"]
    ])
    .to_string()
}
fn use_key(v: &Value) -> String {
    json!([v["kind"], v["call"], v["attempt"]]).to_string()
}
fn origin(
    kind: &str,
    site: Option<&str>,
    call: Option<u64>,
    attempt: Option<usize>,
    slot: Option<&str>,
    in_use: Option<bool>,
    location: (u64, Option<&str>),
) -> Value {
    let (page, case) = location;
    json!({"kind":kind,"site":site,"call":call,"attempt":attempt,"slot":slot,"in_use":in_use,"page":page,"case":case})
}
fn add(
    program: &mut Program,
    fields: Value,
    start: u64,
    end: u64,
    cursor: usize,
    checkpoint: Option<(String, String)>,
) -> Result<(), String> {
    if program
        .insert(
            capture_key(&fields),
            Expected {
                fields,
                start,
                end,
                cursor,
                checkpoint,
            },
        )
        .is_some()
    {
        return Err(ERROR.into());
    }
    Ok(())
}
fn add_use(
    program: &mut Program,
    kind: &str,
    call: Option<u64>,
    attempt: Option<usize>,
    sources: Vec<usize>,
    result: bool,
    window: (u64, u64, usize),
) -> Result<(), String> {
    let bound = matches!(
        kind,
        "main.a004" | "main.a014" | "main.a093" | "main.a097" | "main.a100" | "seed_cases.a022"
    );
    let fields = json!({"kind":kind,"call":call,"attempt":attempt,"sources":sources,"result":result,"ok":true,"check_ns":if bound {json!(window.1)} else {Value::Null},"check_cursor":if bound {json!(window.2)} else {Value::Null},"check_instance":if bound {json!(attempt.filter(|_| kind == "main.a100").unwrap_or(1))} else {Value::Null}});
    if program
        .insert(
            use_key(&fields),
            Expected {
                fields,
                start: window.0,
                end: window.1,
                cursor: window.2,
                checkpoint: None,
            },
        )
        .is_some()
    {
        return Err(ERROR.into());
    }
    Ok(())
}
#[derive(Default)]
struct Attempt {
    number: usize,
    start: u64,
    cursor: usize,
    check: u64,
    poll: u64,
    poll_cursor: usize,
    ready: bool,
}
struct Runtime {
    id: u64,
    page: u64,
    in_use: bool,
    attempts: Vec<Attempt>,
    ready_check: u64,
    end: u64,
    cursor: usize,
}

pub fn validate(report: &Value) -> Result<(), String> {
    validate_with(report, completion::inventory())
}
fn validate_with(report: &Value, key: &Value) -> Result<(), String> {
    let states = reader_checks::caller_states(report);
    let pages = history::source_page_states(report)?;
    let events = report["helper_history"].as_array().ok_or(ERROR)?;
    let mut stack: Vec<(u64, String, u64)> = Vec::new();
    let mut runtime: BTreeMap<u64, Runtime> = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        match event["event"].as_str() {
            Some("call_start") => {
                let id = event["call"].as_u64().ok_or(ERROR)?;
                let kind = event["kind"].as_str().ok_or(ERROR)?.to_owned();
                let page = event["page"].as_u64().ok_or(ERROR)?;
                if kind == "runtime.settled" {
                    let in_use = report["runtime_inputs"]
                        .as_array()
                        .ok_or(ERROR)?
                        .iter()
                        .find(|r| r["call"] == id)
                        .ok_or(ERROR)?["parameters"]["in_use"]
                        .as_bool()
                        .ok_or(ERROR)?;
                    runtime.insert(
                        id,
                        Runtime {
                            id,
                            page,
                            in_use,
                            attempts: Vec::new(),
                            ready_check: 0,
                            end: 0,
                            cursor: 0,
                        },
                    );
                }
                stack.push((id, kind, page));
            }
            Some("call_end") => {
                let (id, _, _) = stack.pop().ok_or(ERROR)?;
                if let Some(frame) = runtime.get_mut(&id) {
                    frame.end = event["at_ns"].as_u64().ok_or(ERROR)?;
                    frame.cursor = index;
                }
            }
            Some("attempt" | "check" | "poll") => {
                let Some((id, kind, _)) = stack.last() else {
                    continue;
                };
                if kind != "runtime.settled" {
                    continue;
                }
                let frame = runtime.get_mut(id).ok_or(ERROR)?;
                let at = event["at_ns"].as_u64().ok_or(ERROR)?;
                if event["event"] == "attempt" {
                    frame.attempts.push(Attempt {
                        number: event["ordinal"].as_u64().ok_or(ERROR)? as usize,
                        start: at,
                        cursor: index + 1,
                        ..Attempt::default()
                    });
                } else if event["event"] == "poll" {
                    let attempt = frame.attempts.last_mut().ok_or(ERROR)?;
                    attempt.poll = at;
                    attempt.poll_cursor = index;
                    attempt.ready = event["ready"].as_bool().ok_or(ERROR)?;
                } else if event["id"] == "runtime.store.not_failed" {
                    frame.attempts.last_mut().ok_or(ERROR)?.check = at;
                } else if event["id"] == "runtime.store.ready_nontransient" {
                    frame.ready_check = at;
                }
            }
            _ => {}
        }
    }
    let mut expected = Program::new();
    for frame in runtime.values() {
        for attempt in &frame.attempts {
            let state = states.get(attempt.cursor).ok_or(ERROR)?;
            let case = state
                .owner
                .as_ref()
                .filter(|o| o.1 == "inside")
                .map(|o| o.2.as_str());
            add(
                &mut expected,
                origin(
                    "runtime",
                    None,
                    Some(frame.id),
                    Some(attempt.number),
                    None,
                    Some(frame.in_use),
                    (frame.page, case),
                ),
                attempt.start,
                attempt.check,
                attempt.cursor,
                None,
            )?;
        }
    }
    let calls = report["observer_calls"].as_array().ok_or(ERROR)?;
    let observer_rules = key["view_observer_sources"].as_object().ok_or(ERROR)?;
    for (index, call) in calls.iter().enumerate() {
        let Some(rule) = observer_rules.get(call["site"].as_str().ok_or(ERROR)?) else {
            continue;
        };
        let mut inputs = call["page_inputs"].as_array().ok_or(ERROR)?.iter();
        let polls = call["polls"].as_array().ok_or(ERROR)?;
        for (n, poll) in polls.iter().enumerate() {
            let before = rule[0] == "before";
            if !before && poll["ready"] == true {
                continue;
            }
            let upper = if before {
                poll["end_ns"].as_u64().ok_or(ERROR)?
            } else {
                polls.get(n + 1).unwrap_or(call)["start_ns"]
                    .as_u64()
                    .ok_or(ERROR)?
            };
            let upper = if !before && n + 1 == polls.len() {
                call["end_ns"].as_u64().ok_or(ERROR)?
            } else {
                upper
            };
            for slot in rule[1].as_array().ok_or(ERROR)? {
                let input = inputs.next().ok_or(ERROR)?;
                if input["slot"] != *slot {
                    return Err(ERROR.into());
                }
                let cursor = input["history_cursor"].as_u64().ok_or(ERROR)? as usize;
                let case = states
                    .get(cursor)
                    .ok_or(ERROR)?
                    .owner
                    .as_ref()
                    .filter(|o| o.1 == "inside")
                    .map(|o| o.2.as_str());
                let lower = if before {
                    poll["start_ns"].as_u64().ok_or(ERROR)?
                } else {
                    poll["end_ns"].as_u64().ok_or(ERROR)?
                };
                add(
                    &mut expected,
                    origin(
                        "observer",
                        None,
                        Some(index as u64 + 1),
                        Some(poll["attempt"].as_u64().ok_or(ERROR)? as usize),
                        slot.as_str(),
                        None,
                        (input["page"].as_u64().ok_or(ERROR)?, case),
                    ),
                    lower.max(input["at_ns"].as_u64().ok_or(ERROR)?),
                    upper,
                    cursor,
                    None,
                )?;
            }
        }
        if inputs.next().is_some() {
            return Err(ERROR.into());
        }
    }
    for (index, row) in report["observer_prior_inputs"]
        .as_array()
        .ok_or(ERROR)?
        .iter()
        .enumerate()
    {
        let cursor = row["start_cursor"].as_u64().ok_or(ERROR)? as usize;
        let case = states
            .get(cursor)
            .ok_or(ERROR)?
            .owner
            .as_ref()
            .filter(|o| o.1 == "inside")
            .map(|o| o.2.as_str());
        add(
            &mut expected,
            origin(
                "prior",
                row["site"].as_str(),
                Some(index as u64 + 1),
                None,
                None,
                None,
                (row["page"].as_u64().ok_or(ERROR)?, case),
            ),
            row["start_ns"].as_u64().ok_or(ERROR)?,
            row["end_ns"].as_u64().ok_or(ERROR)?,
            cursor,
            None,
        )?;
    }
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
            .ok_or(ERROR)?
            .clone()
    };
    for (site, rule) in key["view_direct_sources"].as_object().ok_or(ERROR)? {
        for case in key["cases"]
            .as_array()
            .ok_or(ERROR)?
            .iter()
            .filter(|c| c["site_id"] == rule[0] && execution.contains(&c["id"]))
        {
            let role = if rule[1] == "invocation" {
                if case["invocation"] == 2 {
                    "served"
                } else {
                    "tracer"
                }
            } else {
                rule[1].as_str().ok_or(ERROR)?
            };
            let actual = report["cases"]
                .as_array()
                .ok_or(ERROR)?
                .iter()
                .find(|c| c["id"] == case["id"])
                .ok_or(ERROR)?;
            let primary = primary(
                report,
                case["id"].as_str().ok_or(ERROR)?,
                rule[2].as_str().ok_or(ERROR)?,
                1,
            )?;
            let cursor = primary["history_cursor"].as_u64().ok_or(ERROR)? as usize;
            let page = *pages.get(cursor).and_then(|p| p.get(role)).ok_or(ERROR)?;
            add(
                &mut expected,
                origin(
                    "direct",
                    Some(site),
                    None,
                    None,
                    None,
                    None,
                    (page, case["id"].as_str()),
                ),
                actual["start_ns"].as_u64().ok_or(ERROR)?,
                primary["at_ns"].as_u64().ok_or(ERROR)?,
                cursor,
                Some((
                    case["id"].as_str().unwrap().into(),
                    rule[2].as_str().unwrap().into(),
                )),
            )?;
        }
    }
    let value = &report["view_inputs"];
    if value.as_object().is_none_or(|o| o.len() != 2) {
        return Err(ERROR.into());
    }
    let captures = value["captures"].as_array().ok_or(ERROR)?;
    let mut matched = BTreeMap::new();
    let mut previous = 0;
    for (index, row) in captures.iter().enumerate() {
        let descriptor = capture_key(row);
        let want = expected
            .remove(&descriptor)
            .ok_or_else(|| format!("{ERROR}: extra source {descriptor}"))?;
        let start = row["start_ns"].as_u64().ok_or(ERROR)?;
        let end = row["end_ns"].as_u64().ok_or(ERROR)?;
        let cursor = row["start_cursor"].as_u64().ok_or(ERROR)? as usize;
        if row.as_object().is_none_or(|o| o.len() != 14)
            || row["source"] != index + 1
            || row["query_ok"] != true
            || start < previous
            || start < want.start
            || end < start
            || end > want.end
            || cursor != want.cursor
            || row["end_cursor"] != cursor
            || want
                .fields
                .as_object()
                .unwrap()
                .iter()
                .any(|(k, v)| row[k] != *v)
        {
            return Err(format!("{ERROR}: source {descriptor}"));
        }
        if let Some((case, predicate)) = &want.checkpoint {
            crate::file_domains::checkpoint(
                report,
                &json!({"at_ns":start,"history_cursor":cursor}),
                case,
                predicate,
                1,
            )?;
        }
        matched.insert(descriptor, row);
        previous = end;
    }
    if !expected.is_empty() {
        return Err(format!(
            "{ERROR}: missing source {}",
            expected.keys().next().unwrap()
        ));
    }
    let find = |kind: &str,
                site: Option<&str>,
                call: Option<u64>,
                attempt: Option<usize>,
                slot: Option<&str>|
     -> Result<&Value, String> {
        let rows: Vec<_> = matched
            .values()
            .copied()
            .filter(|r| {
                r["kind"] == kind
                    && r["site"] == json!(site)
                    && r["call"] == json!(call)
                    && r["attempt"] == json!(attempt)
                    && r["slot"] == json!(slot)
            })
            .collect();
        if rows.len() != 1 {
            return Err(ERROR.into());
        }
        Ok(rows[0])
    };
    let mut uses = Program::new();
    for frame in runtime.values() {
        for attempt in &frame.attempts {
            let row = find("runtime", None, Some(frame.id), Some(attempt.number), None)?;
            let source = row["source"].as_u64().ok_or(ERROR)? as usize;
            add_use(
                &mut uses,
                "failed",
                Some(frame.id),
                Some(attempt.number),
                vec![source],
                false,
                (
                    row["end_ns"].as_u64().ok_or(ERROR)?,
                    attempt.check,
                    attempt.cursor,
                ),
            )?;
            add_use(
                &mut uses,
                "ready",
                Some(frame.id),
                Some(attempt.number),
                vec![source],
                attempt.ready,
                (attempt.check, attempt.poll, attempt.poll_cursor),
            )?;
        }
        let last = frame.attempts.last().ok_or(ERROR)?;
        let row = find("runtime", None, Some(frame.id), Some(last.number), None)?;
        add_use(
            &mut uses,
            "returned",
            Some(frame.id),
            None,
            vec![row["source"].as_u64().ok_or(ERROR)? as usize],
            true,
            (frame.ready_check, frame.end, frame.cursor),
        )?;
    }
    let mut final_views: BTreeMap<&str, Vec<(&Value, usize)>> = BTreeMap::new();
    for (index, call) in calls.iter().enumerate() {
        let site = call["site"].as_str().ok_or(ERROR)?;
        let Some(rule) = observer_rules.get(site) else {
            continue;
        };
        let polls = call["polls"].as_array().ok_or(ERROR)?;
        let mut last_sources = Vec::new();
        for (n, poll) in polls.iter().enumerate() {
            let mut sources = Vec::new();
            for slot in rule[1].as_array().ok_or(ERROR)? {
                let row = if rule[0] == "before" {
                    find(
                        "observer",
                        None,
                        Some(index as u64 + 1),
                        Some(poll["attempt"].as_u64().ok_or(ERROR)? as usize),
                        slot.as_str(),
                    )?
                } else if n == 0 {
                    let prior = report["observer_prior_inputs"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .enumerate()
                        .find(|(_, p)| p["site"] == site && p["end_cursor"] == call["start_cursor"])
                        .ok_or(ERROR)?;
                    let row = find("prior", Some(site), Some(prior.0 as u64 + 1), None, None)?;
                    if prior.1["view_source"] != row["source"] {
                        return Err(ERROR.into());
                    }
                    row
                } else {
                    find(
                        "observer",
                        None,
                        Some(index as u64 + 1),
                        Some(polls[n - 1]["attempt"].as_u64().ok_or(ERROR)? as usize),
                        slot.as_str(),
                    )?
                };
                sources.push(row["source"].as_u64().ok_or(ERROR)? as usize);
            }
            add_use(
                &mut uses,
                "observer",
                Some(index as u64 + 1),
                Some(poll["attempt"].as_u64().ok_or(ERROR)? as usize),
                sources.clone(),
                poll["ready"].as_bool().ok_or(ERROR)?,
                (
                    poll["start_ns"].as_u64().ok_or(ERROR)?,
                    poll["end_ns"].as_u64().ok_or(ERROR)?,
                    poll["end_cursor"].as_u64().ok_or(ERROR)? as usize,
                ),
            )?;
            last_sources = sources;
        }
        if rule[0] == "after" && polls.last().is_some_and(|p| p["ready"] == false) {
            last_sources = vec![
                find(
                    "observer",
                    None,
                    Some(index as u64 + 1),
                    Some(polls.last().unwrap()["attempt"].as_u64().ok_or(ERROR)? as usize),
                    Some("source"),
                )?["source"]
                    .as_u64()
                    .ok_or(ERROR)? as usize,
            ];
        }
        for source in last_sources {
            final_views.entry(site).or_default().push((call, source));
        }
    }
    for (site, predicate) in [
        ("main.writer.waiter_unlocked", "main.a097"),
        ("main.persistence.shown", "main.a100"),
    ] {
        for (n, (call, source)) in final_views.get(site).into_iter().flatten().enumerate() {
            let cursor = call["end_cursor"].as_u64().ok_or(ERROR)? as usize;
            let case = &states
                .get(cursor)
                .ok_or(ERROR)?
                .owner
                .as_ref()
                .ok_or(ERROR)?
                .2;
            let check = primary(report, case, predicate, n + 1)?;
            add_use(
                &mut uses,
                predicate,
                None,
                Some(n + 1),
                vec![*source],
                true,
                (
                    call["end_ns"].as_u64().ok_or(ERROR)?,
                    check["at_ns"].as_u64().ok_or(ERROR)?,
                    check["history_cursor"].as_u64().ok_or(ERROR)? as usize,
                ),
            )?;
        }
    }
    if let Some(pair) = final_views.get("main.writer.holder_and_waiter") {
        if pair.len() != 2 {
            return Err(ERROR.into());
        }
        let row = find("direct", Some("view.main.waiter_current"), None, None, None)?;
        let check = primary(report, "main.c020.p001", "main.a094", 1)?;
        add_use(
            &mut uses,
            "equal",
            None,
            None,
            vec![row["source"].as_u64().ok_or(ERROR)? as usize, pair[1].1],
            true,
            (
                row["end_ns"].as_u64().ok_or(ERROR)?,
                check["at_ns"].as_u64().ok_or(ERROR)?,
                check["history_cursor"].as_u64().ok_or(ERROR)? as usize,
            ),
        )?;
    }
    let mut direct_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for row in captures.iter().filter(|r| r["kind"] == "direct") {
        let site = row["site"].as_str().ok_or(ERROR)?;
        let rule = &key["view_direct_sources"][site];
        let predicate = rule[2].as_str().ok_or(ERROR)?;
        if predicate == "main.a094" {
            continue;
        }
        let n = direct_counts.entry(predicate).or_default();
        *n += 1;
        let check = primary(report, row["case"].as_str().ok_or(ERROR)?, predicate, 1)?;
        add_use(
            &mut uses,
            predicate,
            None,
            Some(*n),
            vec![row["source"].as_u64().ok_or(ERROR)? as usize],
            true,
            (
                row["end_ns"].as_u64().ok_or(ERROR)?,
                check["at_ns"].as_u64().ok_or(ERROR)?,
                check["history_cursor"].as_u64().ok_or(ERROR)? as usize,
            ),
        )?;
    }
    previous = 0;
    for row in value["uses"].as_array().ok_or(ERROR)? {
        let descriptor = use_key(row);
        let want = uses
            .remove(&descriptor)
            .ok_or_else(|| format!("{ERROR}: extra use {descriptor}"))?;
        let at = row["at_ns"].as_u64().ok_or(ERROR)?;
        if row.as_object().is_none_or(|o| o.len() != 11)
            || at < previous
            || at < want.start
            || at > want.end
            || row["history_cursor"] != want.cursor
            || want
                .fields
                .as_object()
                .unwrap()
                .iter()
                .any(|(k, v)| row[k] != *v)
        {
            return Err(format!("{ERROR}: use {descriptor}"));
        }
        previous = at;
    }
    if !uses.is_empty() {
        return Err(format!(
            "{ERROR}: missing use {}",
            uses.keys().next().unwrap()
        ));
    }
    Ok(())
}
fn primary<'a>(
    report: &'a Value,
    case: &str,
    predicate: &str,
    n: usize,
) -> Result<&'a Value, String> {
    report["primary_history"]
        .as_array()
        .ok_or(ERROR)?
        .iter()
        .find(|r| r["case"] == case && r["id"] == format!("{predicate}.i{n:03}"))
        .ok_or_else(|| ERROR.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_view_attempt_and_use_correspondence() {
        let fixture: Value =
            serde_json::from_str(include_str!("../testdata/view-inputs.json")).unwrap();
        let report = &fixture["report"];
        let key = &fixture["inventory"];
        validate_with(report, key).unwrap();
        for (pointer, value) in [
            ("/view_inputs/captures/0/query_ok", json!(false)),
            ("/view_inputs/captures/0/page", json!(8)),
            ("/view_inputs/captures/0/in_use", json!(true)),
            ("/view_inputs/captures/0/attempt", json!(2)),
            ("/view_inputs/uses/1/sources/0", json!(2)),
            ("/view_inputs/uses/1/result", json!(false)),
            ("/view_inputs/uses/2/at_ns", json!(9)),
            ("/view_inputs/uses/0/history_cursor", json!(5)),
        ] {
            let mut changed = report.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(validate_with(&changed, key).is_err(), "{pointer}");
        }
        for field in ["captures", "uses"] {
            let mut missing = report.clone();
            missing["view_inputs"][field].as_array_mut().unwrap().pop();
            assert!(validate_with(&missing, key).is_err());
            let mut extra = report.clone();
            let row = extra["view_inputs"][field][0].clone();
            extra["view_inputs"][field]
                .as_array_mut()
                .unwrap()
                .push(row);
            assert!(validate_with(&extra, key).is_err());
        }
    }
}
