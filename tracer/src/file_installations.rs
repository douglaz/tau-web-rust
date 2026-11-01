//! Every actual installation belongs to an independently required source window and operand.
use crate::{history, reader_checks};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
const ERROR: &str = "original installation source/operand/placement mismatch";
type Context = (String, String, String, u64);
fn context(state: &reader_checks::CallerState) -> Result<Context, String> {
    let o = state.owner.as_ref().ok_or(ERROR)?;
    Ok((o.0.clone(), o.1.clone(), o.2.clone(), state.invocation))
}
fn row_context(row: &Value) -> Result<Context, String> {
    Ok((
        row["scenario"].as_str().ok_or(ERROR)?.into(),
        row["owner"].as_str().ok_or(ERROR)?.into(),
        row["case"].as_str().unwrap_or("").into(),
        row["invocation"].as_u64().ok_or(ERROR)?,
    ))
}
struct Check<'a, 'b> {
    key: &'a Value,
    report: &'a Value,
    requirements: &'a Value,
    execution: Vec<Value>,
    events: &'a [Value],
    captures: &'a [Value],
    puts: &'a [Value],
    states: Vec<reader_checks::CallerState>,
    pages: Vec<BTreeMap<String, u64>>,
    roots: BTreeMap<Context, Vec<usize>>,
    children: BTreeMap<u64, Vec<usize>>,
    ends: BTreeMap<u64, usize>,
    consumed: &'b mut BTreeSet<usize>,
}
impl<'a> Check<'a, '_> {
    fn original(
        &self,
        site: &str,
        kind: &str,
        scope: &str,
        invocation: u64,
        instance: usize,
    ) -> Result<&'a Value, String> {
        let candidates: Vec<_> = self
            .captures
            .iter()
            .filter(|c| c["site"] == site && c["kind"] == kind)
            .filter(|c| {
                c["history_cursor"]
                    .as_u64()
                    .and_then(|n| self.states.get(n as usize))
                    .is_some_and(|s| {
                        s.owner.as_ref().is_some_and(|o| {
                            scope == "@unique" || o.0 == scope && s.invocation == invocation
                        })
                    })
            })
            .collect();
        if scope == "@unique" && candidates.len() != 1 {
            return Err(ERROR.into());
        }
        candidates
            .get(instance.checked_sub(1).ok_or(ERROR)?)
            .copied()
            .ok_or_else(|| ERROR.into())
    }
    fn operand(capture: &Value, ok: bool) -> Value {
        json!({"site":capture["site"],"source":capture["source"],"kind":capture["kind"],"page":capture["page"],"ok":ok})
    }
    fn consume(
        &mut self,
        cursor: usize,
        page: u64,
        operand: Value,
        provenance: Value,
        earliest: u64,
    ) -> Result<(), String> {
        let matching: Vec<_> = self
            .puts
            .iter()
            .enumerate()
            .filter(|(_, p)| p["history_cursor"] == cursor)
            .collect();
        if matching.len() != 1 {
            return Err(ERROR.into());
        }
        let (index, row) = matching[0];
        if !self.consumed.insert(index)
            || row["page"] != page
            || row["input"] != operand
            || row["provenance"] != provenance
            || row["at_ns"].as_u64().is_none_or(|t| {
                t < earliest
                    || self
                        .events
                        .get(cursor)
                        .and_then(|e| e["at_ns"].as_u64())
                        .is_none_or(|end| t > end)
            })
        {
            return Err(ERROR.into());
        }
        Ok(())
    }
    fn capture_put(&mut self, cursor: usize, page: u64, capture: &Value) -> Result<(), String> {
        let next = self.events.get(cursor).ok_or(ERROR)?;
        if next["event"] != "call_start"
            || next["kind"] != "runtime.worker"
            || next["page"] != page
            || capture["ok"] != true
        {
            return Err(ERROR.into());
        }
        let matching: Vec<_> = self
            .puts
            .iter()
            .filter(|p| p["history_cursor"] == cursor)
            .collect();
        if matching.len() != 1 {
            return Err(ERROR.into());
        }
        let provenance =
            json!({"empty":matching[0]["provenance"]["empty"],"control":null,"contracts":null});
        self.consume(
            cursor,
            page,
            Self::operand(capture, true),
            provenance,
            capture["at_ns"].as_u64().ok_or(ERROR)?,
        )
    }
    fn anchor(
        &self,
        scope: &str,
        invocation: u64,
        pattern: &str,
    ) -> Result<Option<String>, String> {
        if !matches!(pattern, "@last" | "@entry" | "@last_descendant") {
            return Ok(Some(pattern.into()));
        }
        let family = format!("{}.", scope.split('.').next().ok_or(ERROR)?);
        let cases: Vec<_> = self.key["cases"]
            .as_array()
            .ok_or(ERROR)?
            .iter()
            .filter(|c| {
                self.execution.contains(&c["id"])
                    && c["invocation"] == invocation
                    && c["site_id"].as_str().is_some_and(|s| {
                        s.starts_with(&family)
                            || pattern == "@last_descendant"
                                && [
                                    "goal_admission_cases.",
                                    "declaration_cases.",
                                    "delivery_cases.",
                                ]
                                .iter()
                                .any(|p| s.starts_with(p))
                    })
            })
            .collect();
        if cases.is_empty() {
            return Ok(None);
        }
        if pattern != "@entry" {
            return Ok(Some(
                cases.last().unwrap()["id"].as_str().ok_or(ERROR)?.into(),
            ));
        }
        let index = self
            .execution
            .iter()
            .position(|id| *id == cases[0]["id"])
            .ok_or(ERROR)?;
        Ok(Some(
            index
                .checked_sub(1)
                .map_or("", |i| self.execution[i].as_str().unwrap_or(""))
                .into(),
        ))
    }
    fn sparse(&mut self, rows: &[Value]) -> Result<(), String> {
        for rule in self.key["file_installation_rules"]
            .as_array()
            .ok_or(ERROR)?
        {
            if rule.as_array().is_none_or(|r| r.len() != 6) {
                return Err(ERROR.into());
            }
            let scope = rule[0].as_str().ok_or(ERROR)?;
            let invocation = rule[1].as_u64().ok_or(ERROR)?;
            let phase = rule[2].as_str().ok_or(ERROR)?;
            let pattern = rule[3].as_str().ok_or(ERROR)?;
            let positions = rule[4].as_array().ok_or(ERROR)?;
            let descriptor = &rule[5];
            let kind = descriptor[0].as_str().ok_or(ERROR)?;
            if !matches!(kind, "capture" | "empty" | "control") {
                return Err(ERROR.into());
            }
            let wanted = self.anchor(scope, invocation, pattern)?;
            for row in rows {
                let ctx = row_context(row)?;
                if ctx.0 != scope
                    || ctx.1 != phase
                    || ctx.3 != invocation
                    || wanted.as_ref().is_none_or(|s| {
                        ctx.2 != *s && !(s.ends_with(".*") && ctx.2.starts_with(&s[..s.len() - 1]))
                    })
                {
                    continue;
                }
                let actual = self.roots.get(&ctx).cloned().unwrap_or_default();
                for (ordinal, position) in positions.iter().enumerate() {
                    let position = position.as_u64().ok_or(ERROR)? as usize;
                    if row["tokens"].get(position) != Some(&json!("call:runtime.worker")) {
                        return Err(ERROR.into());
                    }
                    let cursor = *actual.get(position).ok_or(ERROR)?;
                    let page = self.events[cursor]["page"].as_u64().ok_or(ERROR)?;
                    match kind{
                        "capture"=>{let capture=self.original(descriptor[1].as_str().ok_or(ERROR)?,descriptor[2].as_str().ok_or(ERROR)?,scope,invocation,descriptor[3].get(ordinal).and_then(Value::as_u64).ok_or(ERROR)? as usize)?;self.capture_put(cursor,page,capture)?;},
                        "empty"=>self.consume(cursor,page,json!({"site":"","source":null,"kind":"unbound","page":null,"ok":false}),json!({"empty":true,"control":null,"contracts":null}),0)?,
                        "control"=>{let number=descriptor[1].as_u64().ok_or(ERROR)?;let capture=self.original("file.main.dump.013","browser.store",scope,invocation,1)?;self.consume(cursor,page,Self::operand(capture,number==1),json!({"empty":false,"control":{"source":number,"ok":true},"contracts":null}),capture["at_ns"].as_u64().ok_or(ERROR)?)?;},
                        _=>unreachable!(),
                    }
                }
            }
        }
        Ok(())
    }
    fn resets_and_contracts(&mut self, rows: &[Value]) -> Result<(), String> {
        for row in rows {
            let ctx = row_context(row)?;
            let scope = ctx.0.as_str();
            let tokens = row["tokens"].as_array().ok_or(ERROR)?;
            let actual = self.roots.get(&ctx).cloned().unwrap_or_default();
            if ctx.1 == "after"
                && matches!(
                    scope,
                    "lifecycle_cases.run" | "lifecycle_cases.selected" | "lifecycle_repairs.run"
                )
            {
                let (site, kind) = if scope == "lifecycle_cases.selected" {
                    ("file.lifecycle_cases.dump.007", "browser.store")
                } else if scope == "lifecycle_repairs.run"
                    && self.requirements["scenario_scopes"]["lifecycle_cases.repair_cases"]
                        .as_u64()
                        .is_some()
                {
                    ("file.lifecycle_cases.dump.009", "browser.store")
                } else {
                    ("file.lifecycle_cases.build.001", "constructor")
                };
                for n in 1..tokens.len() {
                    if tokens[n - 1] == "call:runtime.worker" && tokens[n] == "call:runtime.worker"
                    {
                        let cursor = *actual.get(n).ok_or(ERROR)?;
                        let capture = self.original(site, kind, "@unique", 1, 1)?;
                        self.capture_put(
                            cursor,
                            self.events[cursor]["page"].as_u64().ok_or(ERROR)?,
                            capture,
                        )?;
                    }
                }
            }
            if ctx.1 == "after" && scope == "session_end_cases.run" {
                for n in 2..tokens.len() {
                    if tokens[n - 2] == "call:runtime.worker"
                        && tokens[n - 1] == "check:session-end.previous_ssh.closed"
                        && tokens[n] == "call:runtime.worker"
                    {
                        let at = self
                            .execution
                            .iter()
                            .position(|id| *id == ctx.2)
                            .map_or(0, |n| n + 1);
                        let unpinned =
                            self.execution
                                .get(at)
                                .and_then(Value::as_str)
                                .is_some_and(|s| {
                                    matches!(
                                        s,
                                        "session_end_cases.c002.p004"
                                            | "session_end_cases.c002.p005"
                                    )
                                });
                        let site = if unpinned {
                            "file.session_end_cases.build.002"
                        } else {
                            "file.session_end_cases.build.001"
                        };
                        let cursor = *actual.get(n).ok_or(ERROR)?;
                        let capture = self.original(site, "constructor", "@unique", 1, 1)?;
                        self.capture_put(
                            cursor,
                            self.events[cursor]["page"].as_u64().ok_or(ERROR)?,
                            capture,
                        )?;
                    }
                }
                if self.anchor(scope, ctx.3, "@last")?.as_deref() == Some(ctx.2.as_str()) {
                    let cursor = *actual.get(1).ok_or(ERROR)?;
                    let capture = self.original(
                        "file.session_end_cases.dump.002",
                        "browser.store",
                        scope,
                        ctx.3,
                        1,
                    )?;
                    self.capture_put(
                        cursor,
                        self.events[cursor]["page"].as_u64().ok_or(ERROR)?,
                        capture,
                    )?;
                }
            }
            let mut preparation = 0;
            for (position, token) in tokens.iter().enumerate() {
                if token != "call:binding.prepare" {
                    continue;
                }
                let domain = row["prepare_domains"].get(preparation).ok_or(ERROR)?;
                preparation += 1;
                if domain["active"] != true || domain["contracts"] != true {
                    continue;
                }
                let cursor = *actual.get(position).ok_or(ERROR)?;
                let parent = &self.events[cursor];
                let call = parent["call"].as_u64().ok_or(ERROR)?;
                let end = *self.ends.get(&call).ok_or(ERROR)?;
                let workers: Vec<_> = self
                    .children
                    .get(&call)
                    .into_iter()
                    .flatten()
                    .copied()
                    .filter(|n| self.events[*n]["kind"] == "runtime.worker")
                    .collect();
                let files: Vec<_> = self
                    .captures
                    .iter()
                    .filter(|c| {
                        c["site"] == "file.binding_cases.dump.001"
                            && c["kind"] == "browser.store"
                            && c["history_cursor"]
                                .as_u64()
                                .is_some_and(|n| n as usize > cursor && (n as usize) < end)
                    })
                    .collect();
                if workers.len() != 1 || files.len() != 1 {
                    return Err(ERROR.into());
                }
                let at = workers[0];
                let capture = files[0];
                let page = parent["page"].as_u64().ok_or(ERROR)?;
                if self.events[at]["page"] != page || capture["page"] != page {
                    return Err(ERROR.into());
                }
                let readers: Vec<_> = self.report["reader_roots"]
                    .as_array()
                    .ok_or(ERROR)?
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| {
                        r["site"] == "reader.call.binding.contracts_source"
                            && r["history_cursor"]
                                .as_u64()
                                .is_some_and(|n| n as usize > cursor && (n as usize) < end)
                            && r["file_input"] == Self::operand(capture, true)
                    })
                    .collect();
                if readers.len() != 1 {
                    return Err(ERROR.into());
                }
                let (reader_id, reader) = readers[0];
                let matching: Vec<_> = self
                    .puts
                    .iter()
                    .filter(|p| p["history_cursor"] == at)
                    .collect();
                if matching.len() != 1
                    || reader["end_ns"].as_u64().ok_or(ERROR)?
                        > matching[0]["at_ns"].as_u64().ok_or(ERROR)?
                {
                    return Err(ERROR.into());
                }
                self.consume(at,page,Self::operand(capture,false),json!({"empty":false,"control":null,"contracts":{"source":capture["source"],"reader":reader_id+1,"ok":true}}),capture["at_ns"].as_u64().ok_or(ERROR)?)?;
            }
        }
        Ok(())
    }
    fn settlements_and_entry(&mut self) -> Result<(), String> {
        for source in self.report["settle_inputs"].as_array().ok_or(ERROR)? {
            let needed = source["input"]
                .as_array()
                .ok_or(ERROR)?
                .iter()
                .any(|b| b[0] == true && b[1] == true);
            if !needed {
                continue;
            }
            let start = source["start_ns"].as_u64().ok_or(ERROR)?;
            let end = source["end_ns"].as_u64().ok_or(ERROR)?;
            let captures: Vec<_> = self
                .captures
                .iter()
                .filter(|c| {
                    c["site"] == "file.main.build.008"
                        && c["kind"] == "constructor"
                        && c["at_ns"].as_u64().is_some_and(|t| start <= t && t <= end)
                })
                .collect();
            if captures.len() != 1 {
                return Err(ERROR.into());
            }
            let capture = captures[0];
            self.capture_put(
                capture["history_cursor"].as_u64().ok_or(ERROR)? as usize,
                source["page"].as_u64().ok_or(ERROR)?,
                capture,
            )?;
        }
        if self.report["mode"] == "targeted"
            && self.requirements["name"]
                .as_str()
                .is_some_and(|s| s.starts_with("inference."))
        {
            let capture = self.original("file.main.build.001", "constructor", "main.run", 1, 1)?;
            let cursors: Vec<_> = self
                .events
                .iter()
                .enumerate()
                .filter(|(_, e)| e["event"] == "scenario_start" && e["id"] == "inference_cases.run")
                .map(|(n, _)| n)
                .collect();
            if cursors.len() != 1 {
                return Err(ERROR.into());
            }
            let cursor = cursors[0];
            let page = *self
                .pages
                .get(cursor)
                .and_then(|p| p.get("tracer"))
                .ok_or(ERROR)?;
            self.consume(
                cursor,
                page,
                Self::operand(capture, true),
                json!({"empty":false,"control":null,"contracts":null}),
                capture["at_ns"].as_u64().ok_or(ERROR)?,
            )?;
        }
        Ok(())
    }
}
pub fn validate(report: &Value, key: &Value, consumed: &mut BTreeSet<usize>) -> Result<(), String> {
    let requirements = if report["mode"] == "full" {
        key
    } else {
        &report["plan"]
    };
    let events = report["helper_history"].as_array().ok_or(ERROR)?;
    let execution = if report["mode"] == "full" {
        key["cases"]
            .as_array()
            .ok_or(ERROR)?
            .iter()
            .map(|c| c["id"].clone())
            .collect()
    } else {
        requirements["expected_execution"]
            .as_array()
            .ok_or(ERROR)?
            .clone()
    };
    let states = reader_checks::caller_states(report);
    let mut roots: BTreeMap<Context, Vec<usize>> = BTreeMap::new();
    let mut children: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    let mut ends = BTreeMap::new();
    let mut stack = Vec::new();
    for (n, event) in events.iter().enumerate() {
        match event["event"].as_str() {
            Some("call_start") => {
                if let Some(parent) = stack.last() {
                    children.entry(*parent).or_default().push(n);
                } else {
                    roots
                        .entry(context(states.get(n + 1).ok_or(ERROR)?)?)
                        .or_default()
                        .push(n);
                }
                stack.push(event["call"].as_u64().ok_or(ERROR)?);
            }
            Some("call_end") => {
                let call = event["call"].as_u64().ok_or(ERROR)?;
                if stack.pop() != Some(call) {
                    return Err(ERROR.into());
                }
                ends.insert(call, n);
            }
            Some("check") if stack.is_empty() => roots
                .entry(context(states.get(n + 1).ok_or(ERROR)?)?)
                .or_default()
                .push(n),
            _ => {}
        }
    }
    let puts = report["file_uses"]["puts"].as_array().ok_or(ERROR)?;
    for row in puts {
        let p = &row["provenance"];
        if p.as_object().is_none_or(|p| p.len() != 3) || !p["empty"].is_boolean() {
            return Err(ERROR.into());
        }
        for k in ["control", "contracts"] {
            if !p[k].is_null()
                && (p[k]
                    .as_object()
                    .is_none_or(|o| o.len() != if k == "contracts" { 3 } else { 2 })
                    || k == "contracts" && p[k]["reader"].as_u64().is_none_or(|n| n == 0)
                    || p[k]["source"].as_u64().is_none_or(|n| n == 0)
                    || !p[k]["ok"].is_boolean())
            {
                return Err(ERROR.into());
            }
        }
    }
    let rows = requirements["invocation_root_sequences"]
        .as_array()
        .ok_or(ERROR)?;
    let mut check = Check {
        key,
        report,
        requirements,
        execution,
        events,
        captures: report["file_captures"].as_array().ok_or(ERROR)?,
        puts,
        states,
        pages: history::source_page_states(report)?,
        roots,
        children,
        ends,
        consumed,
    };
    check.sparse(rows)?;
    check.resets_and_contracts(rows)?;
    check.settlements_and_entry()?;
    if check.consumed.len() != puts.len() {
        return Err(format!("{ERROR}: unmatched installation"));
    }
    for row in puts {
        let cursor = row["history_cursor"].as_u64().ok_or(ERROR)? as usize;
        let event = events.get(cursor).ok_or(ERROR)?;
        if event["event"] == "scenario_start" && event["id"] == "inference_cases.run" {
            if row["input"]["site"] != "file.main.build.001"
                || row["end_ns"].as_u64().ok_or(ERROR)? > event["at_ns"].as_u64().ok_or(ERROR)?
            {
                return Err(ERROR.into());
            }
            continue;
        }
        if event["event"] != "call_start" || event["kind"] != "runtime.worker" {
            return Err(ERROR.into());
        }
        let end = *check
            .ends
            .get(&event["call"].as_u64().ok_or(ERROR)?)
            .ok_or(ERROR)?
            + 1;
        let matching: Vec<_> = report["state_inputs"]["operations"]
            .as_array()
            .ok_or(ERROR)?
            .iter()
            .filter(|o| {
                o["kind"] == "reload"
                    && o["page"] == row["page"]
                    && o["start_cursor"] == cursor
                    && o["end_cursor"] == end
            })
            .collect();
        if matching.len() != 1
            || row["end_ns"].as_u64().ok_or(ERROR)?
                > matching[0]["start_ns"].as_u64().ok_or(ERROR)?
        {
            return Err(format!(
                "{ERROR}: installation did not finish before reload"
            ));
        }
    }
    Ok(())
}
