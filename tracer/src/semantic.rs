//! Predicate completion against an input grammar independent of the checked reader.
use super::{completion, reader_checks};
use serde_json::Value;
use std::collections::BTreeMap;

pub fn entered(id: &'static str) {
    reader_checks::semantic_guard(id, true);
}

pub fn holds(id: &'static str, value: bool) -> bool {
    reader_checks::semantic_guard(id, value);
    value
}

pub fn rejects(id: &'static str, value: bool) -> bool {
    holds(id, !value);
    value
}

pub fn result<T, E>(id: &'static str, value: Result<T, E>) -> Result<T, E> {
    holds(id, value.is_ok());
    value
}

pub fn option<T>(id: &'static str, value: Option<T>) -> Option<T> {
    holds(id, value.is_some());
    value
}

pub fn catalogue(family: &str, arguments: &[&str]) -> &'static str {
    completion::inventory()["semantic_catalogues"][family]
        .as_array()
        .and_then(|entries| {
            entries.iter().find(|entry| {
                entry["arguments"].as_array().is_some_and(|args| {
                    args.len() == arguments.len()
                        && args.iter().zip(arguments).all(|(a, b)| a == *b)
                })
            })
        })
        .and_then(|entry| entry["id"].as_str())
        .unwrap_or("semantic.unknown_argument")
}

pub fn member_site(family: &str, field: &str, choices: &[&str]) -> &'static str {
    let mut arguments = vec![field];
    arguments.extend_from_slice(choices);
    catalogue(family, &arguments)
}

pub fn object_site(family: &str, required: &[&str], optional: &[&str]) -> &'static str {
    let mut arguments = required.to_vec();
    arguments.push("|");
    arguments.extend_from_slice(optional);
    catalogue(family, &arguments)
}

pub fn field_site(family: &str, field: &str) -> &'static str {
    catalogue(family, &[field])
}

fn schema_matches(value: &Value, schema: &Value, definitions: &Value, depth: usize) -> bool {
    if depth > 100 {
        return false;
    }
    if let Some(accept) = schema.as_bool() {
        return accept;
    }
    if let Some(reference) = schema["$ref"].as_str() {
        return reference
            .strip_prefix("#/$defs/")
            .and_then(|name| definitions.get(name))
            .is_some_and(|s| schema_matches(value, s, definitions, depth + 1));
    }
    if let Some(choices) = schema["anyOf"].as_array() {
        return choices
            .iter()
            .any(|s| schema_matches(value, s, definitions, depth + 1));
    }
    if schema
        .get("const")
        .is_some_and(|expected| value != expected)
    {
        return false;
    }
    if schema["enum"]
        .as_array()
        .is_some_and(|choices| !choices.contains(value))
    {
        return false;
    }
    match schema["type"].as_str() {
        Some("null") => value.is_null(),
        Some("boolean") => value.is_boolean(),
        Some("string") => value.is_string(),
        Some("integer") => value.as_u64().is_some(),
        Some("object") => {
            let Some(object) = value.as_object() else {
                return false;
            };
            let Some(properties) = schema["properties"].as_object() else {
                return false;
            };
            if schema["required"].as_array().is_some_and(|keys| {
                keys.iter()
                    .any(|k| k.as_str().is_none_or(|k| !object.contains_key(k)))
            }) {
                return false;
            }
            object.iter().all(|(k, v)| {
                properties
                    .get(k)
                    .is_some_and(|s| schema_matches(v, s, definitions, depth + 1))
            })
        }
        Some("array") => {
            let Some(items) = value.as_array() else {
                return false;
            };
            if schema["minItems"]
                .as_u64()
                .is_some_and(|n| items.len() < n as usize)
                || schema["maxItems"]
                    .as_u64()
                    .is_some_and(|n| items.len() > n as usize)
            {
                return false;
            }
            let prefix = schema["prefixItems"].as_array();
            items.iter().enumerate().all(|(i, v)| {
                let child = prefix
                    .and_then(|p| p.get(i))
                    .or_else(|| schema.get("items"));
                child.is_some_and(|s| schema_matches(v, s, definitions, depth + 1))
            })
        }
        None => schema.get("const").is_some() || schema.get("enum").is_some(),
        _ => false,
    }
}

pub fn domain_matches(value: &Value, name: &str) -> bool {
    let definitions = &completion::inventory()["semantic_domain_schemas"];
    definitions
        .get(name)
        .is_some_and(|schema| schema_matches(value, schema, definitions, 0))
}

pub fn program(
    rule: &str,
    domain: &Value,
    limit: usize,
) -> Result<Vec<(&'static str, Vec<Value>)>, String> {
    let rules = &completion::inventory()["semantic_rules"];
    let mut out = Vec::new();
    expand(
        rules.get(rule).ok_or("missing helper grammar")?,
        domain,
        rules,
        &mut out,
        &mut Vec::new(),
        limit,
        0,
    )?;
    Ok(out)
}

fn expand<'a>(
    node: &'a Value,
    domain: &Value,
    rules: &'a Value,
    out: &mut Vec<(&'a str, Vec<Value>)>,
    context: &mut Vec<Value>,
    limit: usize,
    depth: usize,
) -> Result<(), String> {
    if depth > 100 {
        return Err("semantic grammar nesting exceeds bound".into());
    }
    if let Some(id) = node["guard"].as_str() {
        if out.len() >= limit {
            return Err("semantic assertion inventory mismatch: cardinality".into());
        }
        out.push((id, context.clone()));
    } else if let Some(sequence) = node["seq"].as_array() {
        for child in sequence {
            expand(child, domain, rules, out, context, limit, depth + 1)?;
        }
    } else if let Some(rule) = node["call"].as_str() {
        let target = match node["at"]
            .as_str()
            .ok_or("missing semantic domain selector")?
        {
            "" => domain,
            field => domain
                .get(field)
                .ok_or("missing semantic child input domain")?,
        };
        expand(
            rules.get(rule).ok_or("unknown semantic rule")?,
            target,
            rules,
            out,
            context,
            limit,
            depth + 1,
        )?;
    } else if let Some(field) = node["each"].as_str() {
        let items = domain[field]
            .as_array()
            .ok_or("invalid semantic input array")?;
        if items.len() > limit {
            return Err("semantic input domain exceeds completion bound".into());
        }
        let slot = node["slot"]
            .as_str()
            .ok_or("missing source input occurrence slot")?;
        for (index, item) in items.iter().enumerate() {
            context.push(serde_json::json!({"slot":slot,"index":index}));
            expand(&node["do"], item, rules, out, context, limit, depth + 1)?;
            context.pop();
        }
    } else if let Some(slot) = node["scope"].as_str() {
        let index = node["index"]
            .as_u64()
            .ok_or("invalid fixed source input occurrence")?;
        context.push(serde_json::json!({"slot":slot,"index":index}));
        expand(&node["do"], domain, rules, out, context, limit, depth + 1)?;
        context.pop();
    } else if let Some(field) = node["if"].as_str() {
        let branch = if domain[field]
            .as_bool()
            .ok_or("invalid semantic input boolean")?
        {
            "then"
        } else {
            "else"
        };
        expand(&node[branch], domain, rules, out, context, limit, depth + 1)?;
    } else if let Some(field) = node["switch"].as_str() {
        let alias = domain[field]
            .as_str()
            .ok_or("invalid semantic input alias")?;
        let branch = node["cases"]
            .get(alias)
            .ok_or("unknown semantic input alternative")?;
        expand(branch, domain, rules, out, context, limit, depth + 1)?;
    } else {
        return Err("invalid semantic grammar operator".into());
    }
    Ok(())
}

pub fn validate(read: &Value) -> Result<(), String> {
    let domains = read["event_domains"]
        .as_array()
        .ok_or("missing semantic input domains")?;
    if read["numeric_files"].as_u64() != Some(domains.len() as u64) {
        return Err("semantic event/history invocation domain mismatch".into());
    }
    let guards = read["semantic_guards"]
        .as_array()
        .ok_or("missing semantic predicate completions")?;
    let rules = &completion::inventory()["semantic_rules"];
    let mut expected = Vec::new();
    for (index, domain) in domains.iter().enumerate() {
        let definitions = &completion::inventory()["semantic_domain_schemas"];
        if !schema_matches(domain, &definitions["semantic.record"], definitions, 0) {
            return Err("semantic input domain schema mismatch".into());
        }
        for (rule, field) in [
            ("reader.event", "event"),
            ("inference.history", "inference"),
            ("reader.mode_history", "modes"),
            ("declaration.history", "declaration"),
            ("delivery.history", "delivery"),
        ] {
            let mut context = vec![
                serde_json::json!({"slot":"reader.record","index":index}),
                serde_json::json!({"slot":rule,"index":0}),
            ];
            expand(
                rules.get(rule).ok_or("missing semantic rule")?,
                &domain[field],
                rules,
                &mut expected,
                &mut context,
                guards.len(),
                0,
            )?;
        }
    }
    if expected.len() != guards.len() {
        return Err("semantic assertion inventory mismatch: cardinality".into());
    }
    let mut counts = BTreeMap::new();
    for (guard, (id, context)) in guards.iter().zip(expected) {
        let n = counts.entry(id).or_insert(0usize);
        *n += 1;
        if guard["id"] != id
            || guard["instance"] != format!("{id}.i{n:03}")
            || guard["ok"] != true
            || guard["context"] != serde_json::json!(context)
            || guard.as_object().is_none_or(|o| o.len() != 4)
        {
            return Err(format!("semantic assertion inventory mismatch: {id}"));
        }
    }
    Ok(())
}

/// An original input occurrence, independent of the number of guards that finish.
pub struct Slot {
    active: bool,
}
impl Slot {
    pub fn new(slot: &'static str, index: usize) -> Self {
        Self {
            active: reader_checks::push_slot(slot, index),
        }
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        if self.active {
            reader_checks::pop_slot();
        } else {
            super::auxiliary::pop_slot();
        }
    }
}
