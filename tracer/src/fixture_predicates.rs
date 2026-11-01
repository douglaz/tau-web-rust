//! Finite operands from the original fixture predicates. No fixture query is repeated.
use super::*;
use std::collections::BTreeMap;
use tau_web::jobs;

pub fn socket(
    seen: &Seen,
    ended: bool,
    input: &fixture_inputs::Input,
    call: &observer::Call,
) -> bool {
    fixture_inputs::static_use(input, seen, call);
    let mut visits = Vec::new();
    let ready = seen.relay_log.iter().any(|(_, event)| {
        let event = match event {
            Event::Frame("close") => "close",
            Event::Ended => "ended",
            _ => "other",
        };
        visits.push(event);
        event == "close" || ended && event == "ended"
    });
    call.fixture_predicate(
        json!({"receiver_ok":fixture_inputs::seen_ok(seen),"ended":ended,"length":seen.relay_log.len(),"visits":visits}),
        ready,
    )
}

pub fn exec(
    seen: &Seen,
    command: &str,
    input: &fixture_inputs::Input,
    call: &observer::Call,
) -> bool {
    fixture_inputs::static_use(input, seen, call);
    let mut steps = vec![Value::Null; 5];
    let ready = matches!(seen.ssh_exec.as_slice(), [bytes] if {
        let id = std::str::from_utf8(bytes).ok().and_then(|s| {
            steps[0] = json!(true);
            let line = s.lines().next();
            steps[1] = json!(line.is_some());
            line
        }).and_then(|line| {
            let id = line.strip_prefix("# tau-web job launch ");
            steps[2] = json!(id.is_some());
            id
        });
        if steps[0].is_null() { steps[0] = json!(false); }
        id.is_some_and(|id| {
            let valid = tau_web::jobs::valid_id(id);
            steps[3] = json!(valid);
            valid && {
                let equal = bytes == tau_web::jobs::launch(id, "fixture", command.as_bytes()).as_bytes();
                steps[4] = json!(equal);
                equal
            }
        })
    });
    call.fixture_predicate(
        json!({"receiver_ok":fixture_inputs::seen_ok(seen),"length":seen.ssh_exec.len(),"steps":steps,"command_ok":command==LOCK_COMMAND}),
        ready,
    )
}

pub fn reads(
    seen: &Seen,
    required: usize,
    input: &fixture_inputs::Input,
    call: &observer::Call,
) -> bool {
    fixture_inputs::static_use(input, seen, call);
    let mut prefixes = Vec::new();
    let mut length = None;
    let ready = !seen.ssh_exec.is_empty()
        && seen.ssh_exec.iter().all(|bytes| {
            let matches = bytes.starts_with(b"# tau-web job read ");
            prefixes.push(matches);
            matches
        })
        && {
            length = Some(seen.ssh_exec.len());
            length == Some(required)
        };
    call.fixture_predicate(
        json!({"receiver_ok":fixture_inputs::seen_ok(seen),"required":required,"total":seen.ssh_exec.len(),"prefixes":prefixes,"length":length}),
        ready,
    )
}

pub fn packet(seen: &Seen, input: &fixture_inputs::Input, call: &observer::Call) -> bool {
    let from = fixture_inputs::cursor(input, seen, call);
    let mut visits = Vec::new();
    let slice = &seen.relay_log[from..];
    let ready = slice.iter().any(|(_, event)| {
        let event = match event {
            Event::Forwarded(fixtures::Toward::Destination, _) => "destination",
            Event::Frame("binary") => "binary",
            _ => "other",
        };
        visits.push(event);
        event == "destination" || event == "binary"
    });
    call.fixture_predicate(
        json!({"total":seen.relay_log.len(),"from":from,"length":slice.len(),"visits":visits}),
        ready,
    )
}

pub fn relay_closed(seen: &Seen, input: &fixture_inputs::Input, call: &observer::Call) -> bool {
    let from = fixture_inputs::cursor(input, seen, call);
    let slice = &seen.relay_log[from..];
    // Ordinals preserve equality only within this original slice. Raw connection identities
    // and Held payloads never enter completion output.
    let mut identities = BTreeMap::new();
    let mut events = Vec::new();
    let connections: std::collections::BTreeSet<_> = slice
        .iter()
        .filter_map(|(id, event)| {
            let next = identities.len();
            let ordinal = *identities.entry(*id).or_insert(next);
            let event = match event {
                Event::ChallengeSent => "challenge",
                Event::Held(_) => "held",
                Event::Ended => "ended",
                Event::Frame("close") => "close",
                _ => "other",
            };
            events.push(json!([ordinal, event]));
            matches!(event, "challenge" | "held").then_some(*id)
        })
        .collect();
    let mut visits = Vec::new();
    let ready = slice.iter().any(|(id, event)| {
        let member = connections.contains(id);
        let terminal = if member {
            Some(matches!(event, Event::Ended | Event::Frame("close")))
        } else {
            None
        };
        visits.push(json!([member, terminal]));
        member && terminal == Some(true)
    });
    call.fixture_predicate(
        json!({"total":seen.relay_log.len(),"from":from,"length":slice.len(),"events":events,"visits":visits}),
        ready,
    )
}

pub fn sent_read(
    seen: &Seen,
    input: &fixture_inputs::Input,
    job: &str,
    call: &observer::Call,
) -> bool {
    let execs = fixture_inputs::sent_read(input, seen, job, call);
    let mut last = None;
    let ready = seen.ssh_exec.len() == execs + 1 && {
        let equal = seen.ssh_exec.last().unwrap() == jobs::collect(job).as_bytes();
        last = Some(equal);
        equal
    };
    call.fixture_predicate(
        json!({"length":seen.ssh_exec.len(),"baseline":execs,"last":last}),
        ready,
    )
}

pub fn launched(
    run: &Run<'_>,
    input: &fixture_inputs::Input,
    command: &str,
    call: &observer::Call,
) -> bool {
    fixture_inputs::command_use(input, run, command, call);
    let launches = run.sshd.machine.launches();
    let mut visits = Vec::new();
    let ready = launches.iter().any(|(_, job)| {
        let equal = job.command == command.as_bytes();
        visits.push(equal);
        equal
    });
    call.fixture_predicate(
        json!({"length":launches.len(),"visits":visits,"fixture":causal::fixture_role(run.sshd)}),
        ready,
    )
}

pub fn stage(run: &Run<'_>, input: &fixture_inputs::Input, call: &observer::Call) -> bool {
    fixture_inputs::gate_use(input, run, call);
    let value = run.relay.session_gate.reached.load(Ordering::SeqCst);
    call.fixture_predicate(json!({"value":value}), value)
}

pub fn probes(run: &Run<'_>, call: Option<&observer::Call>, baseline: usize) -> usize {
    run.aggregator.observe_receiver();
    let requests = run.aggregator.requests.lock().unwrap();
    let mut visits = Vec::new();
    let count = requests
        .iter()
        .filter(|raw| {
            let options = raw.starts_with(b"OPTIONS / ");
            let account = options.then(|| {
                String::from_utf8_lossy(raw)
                    .to_ascii_lowercase()
                    .contains("x-inference-account: probe-placeholder")
            });
            visits.push(json!([options, account]));
            options && account == Some(true)
        })
        .count();
    if let Some(call) = call {
        call.fixture_predicate(
            json!({"length":requests.len(),"visits":visits,"baseline":baseline}),
            count > baseline,
        );
    }
    count
}

pub fn revoke(run: &Run<'_>, input: &fixture_inputs::Input, call: &observer::Call) -> bool {
    let id = fixture_inputs::key_use(input, run, call);
    run.aggregator.observe_receiver();
    let requests = run.aggregator.requests.lock().unwrap();
    let mut visits = Vec::new();
    let ready = requests.iter().any(|raw| {
        let post = raw.starts_with(b"POST /revoke ");
        let mut body_present = None;
        let mut key_equal = None;
        let matches = post && {
            let body = inference_cases::request_body(raw);
            body_present = Some(body.is_some());
            body.is_some_and(|body| {
                let equal = body["key_id"] == id;
                key_equal = Some(equal);
                equal
            })
        };
        visits.push(json!([post, body_present, key_equal]));
        matches
    });
    call.fixture_predicate(json!({"length":requests.len(),"visits":visits}), ready)
}

fn fields(value: &Value, names: &[&str]) -> Result<(), String> {
    if value
        .as_object()
        .is_none_or(|o| o.len() != names.len() || names.iter().any(|name| !o.contains_key(*name)))
    {
        return Err("invalid original fixture predicate operand schema".into());
    }
    Ok(())
}
fn number(value: &Value) -> Result<u64, String> {
    value
        .as_u64()
        .ok_or("invalid original fixture predicate count".into())
}
fn boolean(value: &Value) -> Result<bool, String> {
    value
        .as_bool()
        .ok_or("invalid original fixture predicate Boolean".into())
}
fn array(value: &Value) -> Result<&Vec<Value>, String> {
    value
        .as_array()
        .ok_or("invalid original fixture predicate sequence".into())
}
fn any(values: &[bool], length: u64) -> Result<bool, String> {
    if values.len() as u64 > length
        || values
            .iter()
            .position(|v| *v)
            .is_some_and(|i| i + 1 != values.len())
        || !values.contains(&true) && values.len() as u64 != length
    {
        return Err("original fixture predicate iterator/short-circuit mismatch".into());
    }
    Ok(values.last() == Some(&true))
}

/// This replay chooses the recipe from the source site, never from producer ready bits.
pub fn replay(site: &str, input: &Value) -> Result<bool, String> {
    match site {
        "fixture.settle.wait"
        | "main.lock_command.socket_closed"
        | "seed.redisplay.socket_closed"
        | "session.network.client_packet"
        | "session.rekey.client_packet" => {
            if site.contains("client_packet") {
                slice(input, &["total", "from", "length", "visits"])?;
            } else {
                fields(input, &["receiver_ok", "ended", "length", "visits"])?;
                original_receiver(input)?;
                if input["ended"] != (site != "fixture.settle.wait") {
                    return Err("original fixture socket predicate parameter mismatch".into());
                }
            }
            let values = array(&input["visits"])?
                .iter()
                .map(|v| {
                    let value = v.as_str().ok_or("invalid fixture event alias")?;
                    let allowed: &[&str] = if site.contains("client_packet") {
                        &["destination", "binary", "other"]
                    } else {
                        &["close", "ended", "other"]
                    };
                    if !allowed.contains(&value) {
                        return Err("invalid fixture event alias".to_owned());
                    }
                    Ok(if site.contains("client_packet") {
                        value != "other"
                    } else {
                        value == "close" || site != "fixture.settle.wait" && value == "ended"
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            any(&values, number(&input["length"])?)
        }
        "main.crash.running_exec" | "main.lock_command.exec" | "seed.redisplay.running_exec" => {
            fields(input, &["receiver_ok", "length", "steps", "command_ok"])?;
            original_receiver(input)?;
            if input["command_ok"] != true {
                return Err("original lock command operand mismatch".into());
            }
            let steps = array(&input["steps"])?;
            if steps.len() != 5 {
                return Err("invalid fixture exec parse stages".into());
            }
            let mut reached = number(&input["length"])? == 1;
            for step in steps {
                if reached {
                    reached = boolean(step)?;
                } else if !step.is_null() {
                    return Err("original fixture exec short-circuit mismatch".into());
                }
            }
            Ok(reached)
        }
        "hold.stop.reading" | "hold.evidence.actual_read" | "hold.evidence.later_read" => {
            fields(
                input,
                &["receiver_ok", "required", "total", "prefixes", "length"],
            )?;
            original_receiver(input)?;
            if number(&input["required"])? != if site == "hold.stop.reading" { 2 } else { 1 } {
                return Err("original fixture read predicate parameter mismatch".into());
            }
            let total = number(&input["total"])?;
            let prefixes = array(&input["prefixes"])?
                .iter()
                .map(boolean)
                .collect::<Result<Vec<_>, _>>()?;
            let mut ready = total > 0;
            if total == 0 {
                if !prefixes.is_empty() {
                    return Err("empty fixture read iterated".into());
                }
            } else {
                let failures: Vec<_> = prefixes.iter().map(|v| !v).collect();
                ready = !any(&failures, total)?;
            }
            if ready {
                let length = number(&input["length"])?;
                if input["length"] != input["total"] {
                    return Err("original fixture read count changed".into());
                }
                Ok(length == if site == "hold.stop.reading" { 2 } else { 1 })
            } else if input["length"].is_null() {
                Ok(false)
            } else {
                Err("original fixture read count evaluated after failure".into())
            }
        }
        "session.closed.relay" => {
            slice(input, &["total", "from", "length", "events", "visits"])?;
            let events = array(&input["events"])?;
            if events.len() as u64 != number(&input["length"])? {
                return Err("original relay first-pass multiplicity mismatch".into());
            }
            let mut ordinals = BTreeMap::new();
            let mut connections = std::collections::BTreeSet::new();
            for row in events {
                let row = array(row)?;
                if row.len() != 2 {
                    return Err("invalid original relay connection operand".into());
                }
                let id = number(&row[0])?;
                let next = ordinals.len() as u64;
                let assigned = *ordinals.entry(id).or_insert(next);
                if assigned != id {
                    return Err("noncanonical relay identity equivalence class".into());
                }
                let event = row[1].as_str().ok_or("invalid original relay event")?;
                if !["challenge", "held", "ended", "close", "other"].contains(&event) {
                    return Err("invalid original relay event".into());
                }
                if matches!(event, "challenge" | "held") {
                    connections.insert(id);
                }
            }
            let visits = array(&input["visits"])?;
            if visits.len() > events.len() {
                return Err("extra original relay visits".into());
            }
            let mut values = Vec::new();
            for (visit, event) in visits.iter().zip(events) {
                let visit = array(visit)?;
                let member = connections.contains(&number(&event[0])?);
                let terminal = member.then(|| matches!(event[1].as_str(), Some("ended" | "close")));
                if visit.len() != 2 || visit[0] != member || visit[1] != json!(terminal) {
                    return Err("original relay membership/termination mismatch".into());
                }
                values.push(member && terminal == Some(true));
            }
            any(&values, events.len() as u64)
        }
        "inference.sent_read.exec" => {
            fields(input, &["length", "baseline", "last"])?;
            let ready =
                number(&input["baseline"])?.checked_add(1) == Some(number(&input["length"])?);
            if ready {
                boolean(&input["last"])
            } else if input["last"].is_null() {
                Ok(false)
            } else {
                Err("original sent-read short-circuit mismatch".into())
            }
        }
        "lifecycle.hidden.job_launched" => {
            fields(input, &["length", "visits", "fixture"])?;
            if input["fixture"] != "primary" {
                return Err("original lifecycle job fixture mismatch".into());
            }
            let values = array(&input["visits"])?
                .iter()
                .map(boolean)
                .collect::<Result<Vec<_>, _>>()?;
            any(&values, number(&input["length"])?)
        }
        "session.network.stage_reached" | "session.rekey.stage_reached" => {
            fields(input, &["value"])?;
            boolean(&input["value"])
        }
        "session.cold_probe.sent" => {
            fields(input, &["length", "visits", "baseline"])?;
            if array(&input["visits"])?.len() as u64 != number(&input["length"])? {
                return Err("original probe iterator multiplicity mismatch".into());
            }
            let mut count = 0;
            for row in array(&input["visits"])? {
                let row = array(row)?;
                if row.len() != 2 {
                    return Err("invalid original probe operands".into());
                }
                if boolean(&row[0])? {
                    count += u64::from(boolean(&row[1])?);
                } else if !row[1].is_null() {
                    return Err("original probe short-circuit mismatch".into());
                }
            }
            Ok(count > number(&input["baseline"])?)
        }
        "session.cold_probe.revoke" | "session.revoke_control.sent" => {
            fields(input, &["length", "visits"])?;
            let mut values = Vec::new();
            for row in array(&input["visits"])? {
                let row = array(row)?;
                if row.len() != 3 {
                    return Err("invalid original revoke operands".into());
                }
                let post = boolean(&row[0])?;
                let ready = if post {
                    if boolean(&row[1])? {
                        boolean(&row[2])?
                    } else {
                        if !row[2].is_null() {
                            return Err("original revoke body short-circuit mismatch".into());
                        }
                        false
                    }
                } else {
                    if !row[1].is_null() || !row[2].is_null() {
                        return Err("original revoke method short-circuit mismatch".into());
                    }
                    false
                };
                values.push(ready);
            }
            any(&values, number(&input["length"])?)
        }
        _ => Err("unknown original fixture predicate site".into()),
    }
}

/// The original count query and comparison, using its own pre-dispatch baseline.
pub fn probe_ready(run: &Run<'_>, input: &fixture_inputs::Input, call: &observer::Call) -> bool {
    let baseline = fixture_inputs::probe_use(input, run, call);
    probes(run, Some(call), baseline) > baseline
}

fn slice(input: &Value, names: &[&str]) -> Result<(), String> {
    fields(input, names)?;
    if number(&input["total"])?.checked_sub(number(&input["from"])?)
        != Some(number(&input["length"])?)
    {
        return Err("original fixture slice cursor/domain mismatch".into());
    }
    Ok(())
}

fn original_receiver(input: &Value) -> Result<(), String> {
    if input["receiver_ok"] != true {
        return Err("original fixture predicate receiver mismatch".into());
    }
    Ok(())
}

#[test]
fn original_predicate_examples_and_impossible_operands() {
    let rows: Value =
        serde_json::from_str(include_str!("../testdata/fixture-predicates.json")).unwrap();
    for row in rows.as_array().unwrap() {
        let result = replay(row["site"].as_str().unwrap(), &row["operands"]);
        if let Some(expected) = row["result"].as_bool() {
            assert_eq!(result, Ok(expected), "{}", row["name"]);
        } else {
            assert!(result.is_err(), "{}: {result:?}", row["name"]);
        }
    }
}
