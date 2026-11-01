//! Decode the compact independent key. No executable catalogue or dispatch lives here.
use serde_json::{Value, json};

fn matches(modes: &Value, mode: &str) -> bool {
    modes
        .as_array()
        .expect("placement mode predicates")
        .iter()
        .any(|v| {
            let pattern = v.as_str().expect("placement mode name");
            pattern == mode
                || pattern
                    .strip_suffix('*')
                    .is_some_and(|prefix| mode.starts_with(prefix))
        })
}

fn call(key: &Value, id: &Value, depth: usize) -> Value {
    assert!(depth < 32, "cyclic source-call rule");
    let index = id.as_u64().expect("source-call rule index") as usize;
    let rule = &key["call_rules"].as_array().expect("source-call rules")[index];
    let fields = key["call_shapes"][rule[0].as_u64().expect("source-call shape") as usize]
        .as_array()
        .expect("source-call fields");
    assert_eq!(
        rule.as_array().unwrap().len(),
        fields.len() + 1,
        "source-call shape arity"
    );
    let mut node = json!(
        fields
            .iter()
            .zip(rule.as_array().unwrap().iter().skip(1))
            .map(|(field, value)| (field.as_str().unwrap().to_owned(), value.clone()))
            .collect::<serde_json::Map<_, _>>()
    );
    if let Some(children) = node.get_mut("children") {
        *children = json!(
            children
                .as_array()
                .unwrap()
                .iter()
                .map(|id| call(key, id, depth + 1))
                .collect::<Vec<_>>()
        );
    }
    if let Some(child) = node.get_mut("then") {
        *child = call(key, child, depth + 1);
    }
    node
}

pub fn read() -> Value {
    let mut key: Value =
        serde_json::from_str(include_str!("../inventory.json")).expect("independent key JSON");
    assert_eq!(key["schema"], 2, "unknown key schema");
    key["semantic_rules"] = json!(
        key["predicate_rules"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, node)| (name.clone(), predicate(node)))
            .collect::<serde_json::Map<_, _>>()
    );
    key["semantic_domain_schemas"] = json!(
        key["domain_types"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, node)| (name.clone(), domain_type(node)))
            .collect::<serde_json::Map<_, _>>()
    );
    key["session_owner_templates"] = json!(
        key["session_roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                let roots = roots(&key, &row[3]);
                let mut source = helper(&json!({}), &roots);
                source["scenario"] = row[0].clone();
                source["position"] = row[1].clone();
                source["case"] = row[2].clone();
                source
            })
            .collect::<Vec<_>>()
    );
    key["fixture_source_program"]=json!(key["fixture_rules"].as_array().unwrap().iter().map(|row|{
        let sources=row[2].as_array().unwrap().iter().map(|s|{
            let flags=s[5].as_u64().expect("fixture source flags");assert!(flags<4);
            json!({"name":s[0],"capture_owner":s[1],"capture_root":s[2],"use_site":s[3],"use_root":s[4],"active":flags&1!=0,"successor_worker":flags&2!=0,"value":s[6],"triggers":s[7].as_array().unwrap().iter().map(|t|json!({"event":t[0],"owner":t[1],"root":t[2],"operation":t[3]})).collect::<Vec<_>>()})
        }).collect::<Vec<_>>();
        let events=row[3].as_array().unwrap().iter().map(|event|format!("{}.{}",sources[event[0].as_u64().unwrap() as usize]["name"].as_str().unwrap(),["capture","dispatch","start","end"][event[1].as_u64().unwrap() as usize])).collect::<Vec<_>>();
        json!({"case":row[0],"scenario":row[1],"sources":sources,"events":events})
    }).collect::<Vec<_>>());
    for case in key["cases"].as_array_mut().expect("case key") {
        let mut sites = Vec::new();
        for run in case["predicates"].as_array().expect("predicate runs") {
            let count = run[1]
                .as_u64()
                .filter(|n| *n > 0 && *n < 100_000)
                .expect("predicate run count");
            sites.extend(std::iter::repeat_n(run[0].clone(), count as usize));
        }
        case["assertions"] = json!(sites);
        if case.get("variants").is_some() {
            case["variants"]["sequences"] = json!(
                case["variants"]["runs"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(name, runs)| {
                        (
                            name.clone(),
                            json!(
                                runs.as_array()
                                    .unwrap()
                                    .iter()
                                    .flat_map(|run| std::iter::repeat_n(
                                        run[0].clone(),
                                        run[1].as_u64().expect("branch run") as usize
                                    ))
                                    .collect::<Vec<_>>()
                            ),
                        )
                    })
                    .collect::<serde_json::Map<_, _>>()
            );
        }
    }
    for field in ["direct_observer_source_rows", "causal_observer_sources"] {
        let mut rows = key[field].as_array().unwrap().clone();
        for row in &mut rows {
            row["calls"] = json!(
                row["calls"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| call(&key, id, 0))
                    .collect::<Vec<_>>()
            );
        }
        key[field] = json!(rows);
    }
    let mut compositions = key["observer_compositions"].clone();
    for rows in compositions.as_object_mut().unwrap().values_mut() {
        for row in rows.as_array_mut().unwrap() {
            row["calls"] = json!(
                row["calls"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| call(&key, id, 0))
                    .collect::<Vec<_>>()
            );
        }
    }
    key["observer_compositions"] = compositions;
    let full = requirements(&key, "full");
    for (field, value) in full.as_object().unwrap() {
        key[field] = value.clone();
    }
    key
}

fn helper(owner: &Value, roots: &[Value]) -> Value {
    let mut row = owner.clone();
    row["tokens"] = json!(roots.iter().map(|r| r[0].clone()).collect::<Vec<_>>());
    row["page_operations"] = json!(roots.iter().map(|r| r[1].clone()).collect::<Vec<_>>());
    row["reload_sources"] = json!(
        roots
            .iter()
            .map(|r| {
                if r[0] == "call:runtime.worker" {
                    assert_eq!(
                        r.as_array().unwrap().len(),
                        6,
                        "missing original worker source"
                    );
                }
                r[5].clone()
            })
            .collect::<Vec<_>>()
    );
    row["prepare_domains"] =
        json!(roots.iter().filter(|r|r[0]=="call:binding.prepare").map(|r|{
        let p=&r[2];assert_eq!(p.as_array().expect("preparation source domain").len(),5);
        json!({"active":p[0],"classes":p[1],"contracts":p[2],"pass":p[3],"bindings":p[4]})
    }).collect::<Vec<_>>());
    row
}

pub fn requirements(key: &Value, mode: &str) -> Value {
    let mut programs: Vec<Value> = Vec::new();
    let mut invocation_roots = Vec::new();
    let mut invocation_observers = Vec::new();
    for row in key["placements"].as_array().expect("source placements") {
        if !matches(&row[0], mode) {
            continue;
        }
        let owner = json!({"scenario":row[1],"owner":row[3],"case":row[4]});
        let roots = roots(key, &row[5]);
        if !roots.is_empty() {
            let mut invocation = helper(&owner, &roots);
            invocation["invocation"] = row[2].clone();
            invocation_roots.push(invocation);
        }
        if !row[6].as_array().unwrap().is_empty() {
            let mut invocation = owner.clone();
            invocation["invocation"] = row[2].clone();
            invocation["calls"] = json!(
                row[6]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| call(key, id, 0))
                    .collect::<Vec<_>>()
            );
            invocation_observers.push(invocation);
        }
        let index = programs
            .iter()
            .position(|r| r["owner"] == owner)
            .unwrap_or_else(|| {
                programs.push(json!({"owner":owner,"roots":[],"observers":[]}));
                programs.len() - 1
            });
        programs[index]["roots"]
            .as_array_mut()
            .unwrap()
            .extend(roots.iter().cloned());
        programs[index]["observers"].as_array_mut().unwrap().extend(
            row[6]
                .as_array()
                .expect("source observer roots")
                .iter()
                .cloned(),
        );
    }
    let mut helpers = Vec::new();
    let mut observers = Vec::new();
    let mut submissions = Vec::new();
    let mut runtime = Vec::new();
    for program in programs {
        let owner = &program["owner"];
        let roots = program["roots"].as_array().unwrap();
        if !roots.is_empty() {
            helpers.push(helper(owner, roots));
        }
        let calls = program["observers"].as_array().unwrap();
        if !calls.is_empty() {
            let mut row = owner.clone();
            row["calls"] = json!(calls.iter().map(|id| call(key, id, 0)).collect::<Vec<_>>());
            observers.push(row);
        }
        let mut kinds = serde_json::Map::new();
        let mut roles = serde_json::Map::new();
        let mut arguments = serde_json::Map::new();
        for (index, root) in roots.iter().enumerate() {
            if root[0] != "call:binding.prepare" {
                assert!(root[2].is_null(), "preparation domain on another root");
            }
            if !root[3].is_null() {
                arguments.insert(index.to_string(), root[3].clone());
            }
            if !root[4].is_null() {
                kinds.insert(index.to_string(), root[4][0].clone());
                roles.insert(index.to_string(), root[4][1].clone());
            }
        }
        if !kinds.is_empty() {
            let mut row = owner.clone();
            row["kinds"] = json!(kinds);
            row["roles"] = json!(roles);
            submissions.push(row);
        }
        if !arguments.is_empty() {
            let mut row = owner.clone();
            row["arguments"] = json!(arguments);
            runtime.push(row);
        }
    }
    let mut scopes = serde_json::Map::new();
    for row in key["scopes"]
        .as_array()
        .expect("source scenario invocations")
    {
        if matches(&row[0], mode) {
            assert!(
                scopes
                    .insert(row[1].as_str().unwrap().into(), row[2].clone())
                    .is_none(),
                "conflicting scenario count rule"
            );
        }
    }
    json!({"helper_owner_sequences":helpers,"invocation_root_sequences":invocation_roots,"invocation_observer_sequences":invocation_observers,"observer_owner_sequences":observers,"submission_sources":submissions,"runtime_source_domains":runtime,"scenario_scopes":scopes,"assertion_overrides":{}})
}

fn roots(key: &Value, ids: &Value) -> Vec<Value> {
    ids.as_array()
        .expect("source root references")
        .iter()
        .map(|id| {
            key["root_rules"].as_array().expect("closed root rules")
                [id.as_u64().expect("source root index") as usize]
                .clone()
        })
        .collect()
}

fn predicate(node: &Value) -> Value {
    if node.is_string() {
        return json!({"guard":node});
    }
    let parts = node.as_array().expect("closed predicate rule");
    match parts.first().and_then(Value::as_str) {
        Some("s") => json!({"seq":parts[1..].iter().map(predicate).collect::<Vec<_>>()}),
        Some("c") if parts.len() == 3 => json!({"call":parts[1],"at":parts[2]}),
        Some("x") if parts.len() == 4 => {
            json!({"scope":parts[1],"index":parts[2],"do":predicate(&parts[3])})
        }
        Some("?") if parts.len() == 4 => {
            json!({"if":parts[1],"then":predicate(&parts[2]),"else":predicate(&parts[3])})
        }
        Some("|") if parts.len() == 4 => {
            json!({"switch":parts[1],"cases":parts[2].as_object().unwrap().iter().map(|(n,v)|(n.clone(),predicate(v))).collect::<serde_json::Map<_,_>>(),"unknown":parts[3]})
        }
        Some("*") if parts.len() == 4 => {
            json!({"each":parts[1],"slot":parts[2],"do":predicate(&parts[3])})
        }
        _ => panic!("unknown closed predicate rule"),
    }
}
fn domain_type(node: &Value) -> Value {
    if let Some(kind) = node.as_str() {
        assert!(["boolean", "integer", "number", "string", "null"].contains(&kind));
        return json!({"type":kind});
    }
    let parts = node.as_array().expect("closed domain type");
    match parts.first().and_then(Value::as_str) {
        Some("r") if parts.len() == 2 => json!({"$ref":parts[1]}),
        Some("=") if parts.len() == 2 => json!({"const":parts[1]}),
        Some("e") => json!({"enum":parts[1..]}),
        Some("|") => json!({"anyOf":parts[1..].iter().map(domain_type).collect::<Vec<_>>()}),
        Some("o") if parts.len() == 4 => {
            let mut schema = json!({"type":"object","properties":parts[1].as_object().unwrap().iter().map(|(n,v)|(n.clone(),domain_type(v))).collect::<serde_json::Map<_,_>>(),"required":parts[2]});
            if !parts[3].is_null() {
                schema["additionalProperties"] = parts[3].clone();
            }
            schema
        }
        Some("a") if parts.len() == 5 => {
            let mut schema = json!({"type":"array","items":if parts[1].is_boolean(){parts[1].clone()}else{domain_type(&parts[1])}});
            if !parts[2].is_null() {
                schema["minItems"] = parts[2].clone();
            }
            if !parts[3].is_null() {
                schema["maxItems"] = parts[3].clone();
            }
            if !parts[4].as_array().unwrap().is_empty() {
                schema["prefixItems"] = json!(
                    parts[4]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(domain_type)
                        .collect::<Vec<_>>()
                );
            }
            schema
        }
        _ => panic!("unknown closed domain type"),
    }
}
