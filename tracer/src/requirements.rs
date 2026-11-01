//! Independent native projection of the source requirements.
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub fn plan(selection: &BTreeMap<String, String>) -> Result<Value, String> {
    let mut inputs = selection.clone();
    for (name, value) in &mut inputs {
        if matches!(
            name.as_str(),
            "TAU_TRACER_MODE_CASE"
                | "TAU_TRACER_GOALS"
                | "TAU_TRACER_DELIVERY"
                | "TAU_TRACER_INFERENCE"
        ) {
            *value = "all".into();
        }
    }
    let mut plan = shape(&inputs)?;
    let name = plan["name"].as_str().unwrap().to_owned();
    let mut requirements = super::inventory::requirements(super::completion::inventory(), &name);
    if name == "hold.union" {
        requirements = super::inventory::requirements(super::completion::inventory(), "hold.all");
        let execution = plan["expected_execution"].as_array().unwrap();
        let last = execution
            .iter()
            .rev()
            .find(|id| id.as_str().unwrap().starts_with("hold_cases."))
            .unwrap();
        for field in [
            "helper_owner_sequences",
            "invocation_root_sequences",
            "submission_sources",
            "runtime_source_domains",
        ] {
            let rows = requirements[field].as_array_mut().unwrap();
            rows.retain(|r| r["owner"] != "inside" || execution.contains(&r["case"]));
            for row in rows {
                if row["scenario"] == "hold_cases.run"
                    && row["owner"] == "after"
                    && row["case"]
                        .as_str()
                        .is_some_and(|s| s.starts_with("hold_cases."))
                {
                    row["case"] = last.clone();
                }
            }
        }
        requirements["observer_owner_sequences"] =
            super::completion::inventory()["observer_compositions"]["hold"].clone();
    } else if name == "inference.session-end.selection" {
        requirements =
            super::inventory::requirements(super::completion::inventory(), "inference.session-end");
        requirements["submission_sources"] = json!([]);
        requirements["runtime_source_domains"] = json!([]);
        let execution = plan["expected_execution"].as_array().unwrap();
        let last = execution
            .iter()
            .rev()
            .find(|id| id.as_str().unwrap().starts_with("session_end_cases."))
            .unwrap();
        let mut owners: BTreeMap<(String, String, String), Value> = BTreeMap::new();
        owners.insert(("main.run".into(),"after".into(),String::new()),json!({"tokens":["call:runtime.worker"],"page_operations":["new:tracer"],"reload_sources":[null],"prepare_domains":[]}));
        for row in super::completion::inventory()["session_owner_templates"]
            .as_array()
            .unwrap()
        {
            let position = row["position"].as_str().unwrap();
            let case = &row["case"];
            let (owner, anchor) = if position == "after_last_selected" {
                ("after", last.clone())
            } else {
                let Some(index) = execution.iter().position(|id| id == case) else {
                    continue;
                };
                match position {
                    "before" => (
                        "after",
                        index
                            .checked_sub(1)
                            .map_or(json!(""), |i| execution[i].clone()),
                    ),
                    "within" => ("inside", case.clone()),
                    "after" => ("after", case.clone()),
                    _ => return Err("unknown source placement rule".into()),
                }
            };
            let key = (
                row["scenario"].as_str().unwrap().into(),
                owner.into(),
                anchor.as_str().unwrap().into(),
            );
            let entry = owners
                .entry(key)
                .or_insert_with(|| json!({"tokens":[],"page_operations":[],"reload_sources":[],"prepare_domains":[]}));
            for field in [
                "tokens",
                "page_operations",
                "reload_sources",
                "prepare_domains",
            ] {
                entry[field]
                    .as_array_mut()
                    .unwrap()
                    .extend(row[field].as_array().unwrap().iter().cloned());
            }
        }
        requirements["helper_owner_sequences"] = json!(
            owners
                .into_iter()
                .map(|((scenario, owner, case), mut row)| {
                    row["scenario"] = json!(scenario);
                    row["owner"] = json!(owner);
                    row["case"] = json!(case);
                    row
                })
                .collect::<Vec<_>>()
        );
        requirements["invocation_root_sequences"] = json!(
            requirements["helper_owner_sequences"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    let mut row = row.clone();
                    row["invocation"] = json!(1);
                    row
                })
                .collect::<Vec<_>>()
        );
        requirements["observer_owner_sequences"] =
            super::completion::inventory()["observer_compositions"]["session"].clone();
    }
    if matches!(
        name.as_str(),
        "hold.union" | "inference.session-end.selection"
    ) {
        requirements["invocation_observer_sequences"] = json!(
            requirements["observer_owner_sequences"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    let mut row = row.clone();
                    row["invocation"] = json!(1);
                    row
                })
                .collect::<Vec<_>>()
        );
    }
    // Scenario invocations are checked independently of the executable case catalogue.
    if requirements["scenario_scopes"] != plan["scenario_scopes"] {
        return Err(format!(
            "scenario catalogue differs from independent scope key: {name}"
        ));
    }
    for (field, value) in requirements.as_object().unwrap() {
        plan[field] = value.clone();
    }
    Ok(plan)
}

// Derive required selected/support domains from the source branches, over immutable key
// cases. This interpreter does not call the execution scheduler or its catalogue.
fn shape(selection: &BTreeMap<String, String>) -> Result<Value, String> {
    let key = super::completion::inventory();
    let value = |n: &str| {
        selection
            .get(&format!("TAU_TRACER_{n}"))
            .map(String::as_str)
    };
    let root = [
        "HOLD_CASE",
        "SEED_CASE",
        "SETUP_CASE",
        "MODE_CASE",
        "GOALS",
        "DELIVERY",
        "INFERENCE",
    ]
    .into_iter()
    .find(|n| value(n).is_some())
    .ok_or("missing selection root")?;
    let (name, focus) = match root {
        "HOLD_CASE" => {
            let v = value(root).unwrap();
            (
                if v.contains(',') {
                    "hold.union".into()
                } else {
                    format!("hold.{v}")
                },
                v,
            )
        }
        "SEED_CASE" => (
            format!("seed.{}", value(root).unwrap()),
            value(root).unwrap(),
        ),
        "SETUP_CASE" => (
            format!("setup.{}", value(root).unwrap()),
            value(root).unwrap(),
        ),
        "MODE_CASE" => ("mode.all".into(), "all"),
        "GOALS" => {
            let v = value("GOAL_CASE").unwrap_or("all");
            (format!("goals.{v}"), v)
        }
        "DELIVERY" => {
            let v = value("DELIVERY_CASE").unwrap_or("all");
            (format!("delivery.{v}"), v)
        }
        "INFERENCE" => {
            let phase = value("INFERENCE_PHASE").unwrap_or("all");
            (
                if value("SESSION_END").is_some() {
                    "inference.session-end.selection".into()
                } else if let Some(end) = value("INFERENCE_END") {
                    format!("inference.end.{end}")
                } else {
                    format!("inference.{phase}")
                },
                phase,
            )
        }
        _ => return Err("unknown required selection branch".into()),
    };
    let mut primary = Vec::new();
    let mut support = Vec::new();
    let mut execution = Vec::new();
    for case in key["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let site = case["site_id"].as_str().unwrap();
        let module = site.split('.').next().unwrap();
        let number = site
            .rsplit_once('c')
            .and_then(|(_, s)| s.parse::<u32>().ok())
            .ok_or("invalid required case site")?;
        let slot = id
            .rsplit_once('p')
            .and_then(|(_, s)| s.parse::<usize>().ok())
            .ok_or("invalid required parameter slot")?;
        let main_setup = matches!(site, "main.c001" | "main.c002");
        let (chosen, needed) = match root {
            "HOLD_CASE" => {
                let parameter = match id {
                    "hold_cases.c001.p001" => "drop",
                    "hold_cases.c002.p001" => "simultaneous",
                    "hold_cases.c003.p001" => "stop",
                    "hold_cases.c004.p001" => "writer-stop",
                    "hold_cases.c004.p002" => "append-error",
                    "hold_cases.c005.p001" => "shared-stop",
                    "hold_cases.c006.p001" => "legacy",
                    "hold_cases.c007.p001" => "unreachable",
                    "hold_cases.c008.p001" => "destructive",
                    _ => "",
                };
                (
                    module == "hold_cases"
                        && (focus == "all" || focus.split(',').any(|part| part == parameter)),
                    main_setup,
                )
            }
            "SEED_CASE" => (
                module == "seed_cases"
                    && (focus == "all" || number == if focus == "failed-append" { 4 } else { 2 }),
                main_setup || site == "seed_cases.c001" && focus != "all",
            ),
            "SETUP_CASE" => (
                if focus == "all" {
                    module == "setup_cases"
                } else {
                    matches!(
                        module,
                        "main" | "typed_cases" | "job_cases" | "hold_cases" | "binding_cases"
                    ) && !main_setup
                        && site != "main.c022"
                },
                main_setup,
            ),
            "MODE_CASE" => (module == "mode_cases", main_setup),
            "DELIVERY" => (
                module == "delivery_cases"
                    && match focus {
                        "all" => true,
                        "reports" => [9, 10].contains(&number),
                        "incomplete" => number == 7,
                        _ => false,
                    },
                false,
            ),
            "GOALS" => {
                let limit = match focus {
                    "card" => 1,
                    "context" => 2,
                    "outcome" => 3,
                    "hold" => 5,
                    "barrier" => 7,
                    "credential" => 8,
                    "document_pending" => 9,
                    "document_end" => 10,
                    _ => 0,
                };
                let chosen = match focus {
                    "all" => matches!(
                        module,
                        "goal_admission_cases"
                            | "goal_cases"
                            | "declaration_cases"
                            | "delivery_cases"
                    ),
                    "declaration" => module == "declaration_cases",
                    "admission" => module == "goal_admission_cases",
                    "barrier" => module == "goal_cases" && [6, 7].contains(&number),
                    _ => module == "goal_cases" && number == limit,
                };
                (
                    chosen,
                    limit > 0
                        && (module == "goal_admission_cases"
                            || module == "goal_cases" && number < limit),
                )
            }
            "INFERENCE" => {
                let core = module == "inference_cases" && [4, 5, 6].contains(&number);
                let chosen = if let Some(end) = value("INFERENCE_END") {
                    module == "inference_cases"
                        && number == 7
                        && [
                            "lock",
                            "hidden",
                            "pagehide",
                            "reload",
                            "bfcache",
                            "redisplay",
                        ]
                        .get(slot - 1)
                            == Some(&end)
                } else {
                    match focus {
                        "all" => matches!(
                            module,
                            "inference_cases"
                                | "session_end_cases"
                                | "lifecycle_cases"
                                | "lifecycle_repairs"
                        ),
                        "core" => core,
                        "dispatch" => {
                            matches!(
                                module,
                                "session_end_cases" | "lifecycle_cases" | "lifecycle_repairs"
                            ) || module == "inference_cases" && [1, 2, 3].contains(&number)
                        }
                        "cutoff" => module == "inference_cases" && [12, 13].contains(&number),
                        "command-intent" => site == "inference_cases.c001",
                        "sent-reads" => site == "inference_cases.c003",
                        "session-end" => {
                            module == "session_end_cases"
                                && value("SESSION_END").is_none_or(|parts| {
                                    parts.split(',').any(|part| {
                                        part.strip_prefix('=').map_or_else(
                                            || case["label"].as_str().unwrap().contains(part),
                                            |exact| case["label"] == exact,
                                        )
                                    })
                                })
                        }
                        "lifecycle" => matches!(module, "lifecycle_cases" | "lifecycle_repairs"),
                        "lifecycle-core" => module == "lifecycle_cases",
                        "lifecycle-boundaries" => {
                            module == "lifecycle_cases" && [4, 5, 6, 11].contains(&number)
                        }
                        "lifecycle-expiry" => site == "lifecycle_cases.c010",
                        "lifecycle-locked" => site == "lifecycle_cases.c013",
                        "lifecycle-repairs" => module == "lifecycle_repairs",
                        _ => return Err("unknown source phase rule".into()),
                    }
                };
                (chosen, !chosen && (core || site == "inference_cases.c014"))
            }
            _ => return Err("unknown source selection rule".into()),
        };
        if chosen {
            primary.push(json!(id));
        } else if needed {
            support.push(json!(id));
        }
        if chosen || needed {
            execution.push(json!(id));
        }
    }
    if primary.is_empty() {
        return Err("selection has no required cases".into());
    }
    let scope_mode = match name.as_str() {
        "hold.union" => "hold.all",
        "inference.session-end.selection" => "inference.session-end",
        _ => &name,
    };
    let scopes = super::inventory::requirements(key, scope_mode)["scenario_scopes"].clone();
    Ok(
        json!({"name":name,"selection":selection,"selected":primary,"support":support,"expected_execution":execution,"scenario_scopes":scopes}),
    )
}
