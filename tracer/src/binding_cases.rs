//! Operator binding through the page and fixture enrolment from independently read identities.
use super::*;

pub(super) async fn prepare(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    pass: &str,
) -> Result<(), String> {
    prepare_with_enrolment(run, tab, worker, pass, true).await
}

pub(super) async fn prepare_without_enrolment(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    pass: &str,
) -> Result<(), String> {
    prepare_with_enrolment(run, tab, worker, pass, false).await
}

async fn prepare_with_enrolment(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    pass: &str,
    enrol: bool,
) -> Result<(), String> {
    let call = history::Call::worker("binding.prepare", &worker.session);
    observer::prepare_input(call.id(), pass);
    let state = run.inspect(worker).await?;
    call.observe("prepare_input", json!({"active":state["state"] == "unlocked" && state["seed_backup_stage"] == "inactive", "classes":state["setup"].as_array().map(|machines| machines.iter().map(|m| m["class"].is_null()).collect::<Vec<_>>())}));
    if state["state"] != "unlocked" || state["seed_backup_stage"] != "inactive" {
        return Ok(());
    }
    let machines = call.predicate(
        "binding.prepare.setup_array",
        state["setup"].as_array().ok_or("no setup projection"),
    )?;
    for machine in machines {
        if machine["class"].is_null() {
            let name = call.predicate(
                "binding.prepare.machine_name",
                machine["entry"]["machine"].as_str().ok_or("no machine"),
            )?;
            setup_cases::click(
                run,
                tab,
                &format!("[data-machine={name:?}] [data-answer=no]"),
            )
            .await?;
            wait(run, worker, "binding.fixture_class.ready", |s| {
                s["setup"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|m| m["entry"]["machine"] == name)
                    .is_some_and(|m| !m["class"].is_null())
            })
            .await?;
        }
    }
    let files = store_files(&run.dump_at("file.binding_cases.dump.001", tab).await?);
    let approved = reader::with_contracts(files.clone(), pass)?;
    call.observe("contracts", json!({"changed":!file_inputs::equal_at("binding.contracts.observe", "", &approved, &files)}));
    if !file_inputs::equal_at("binding.contracts.branch", "", &(approved), &(files)) {
        run.put(tab, &approved).await?;
        *worker = run
            .reload("binding_cases.rs::reload#1", tab, worker)
            .await?;
        run.browser.evaluate(&worker.session, &format!("(async()=>{{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);if(m.test_inference_origin)await m.test_inference_origin({});return true;}})()", json!(run.aggregator.origin))).await?;
        run.submit(tab, "unlock", pass).await?;
    }
    if machines.is_empty() {
        return Ok(());
    }
    let tracer = run.browser.evaluate(&worker.session, "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return typeof m.test_allocate === 'function';})()").await? == true;
    let mut opened = reader::read_at(
        "reader.call.binding.opened_source",
        &store_files(&run.dump_at("file.binding_cases.dump.002", tab).await?),
        pass,
    )?;
    let mut passes = passes_at("reader.aux.call.binding.prepare.passes_first", &opened)?;
    call.observe(
        "pass",
        json!({"needed":tracer && enrol && passes.is_empty()}),
    );
    if tracer && enrol && passes.is_empty() {
        let result = run.browser.evaluate(&worker.session, "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.test_allocate('passes'));})()").await?;
        if completion::rejects(
            "binding.pass.allocation_identity",
            result.get("identity").is_none(),
        ) {
            return Err(format!("fixture enrolment: {result}"));
        }
        opened = reader::read_at(
            "reader.call.binding.allocated_pass_source",
            &store_files(&run.dump_at("file.binding_cases.dump.003", tab).await?),
            pass,
        )?;
        passes = self::passes_at("reader.aux.call.binding.prepare.passes_allocated", &opened)?;
    }
    let mnemonic = opened.mnemonic_at("reader.aux.call.binding.prepare.mnemonic")?;
    {
        let _enrolment = auxiliary::Call::begin(
            "reader.aux.call.binding.prepare.enrolment",
            "reader.aux.prepare_enrolment",
            opened.origin(),
        );
        auxiliary::opened_input(opened.origin(), &opened.records);
        for (record, (_, bytes)) in opened.records.iter().enumerate() {
            let _source_record = semantic::Slot::new("reader.aux.prepare_record", record);
            let event: Value = semantic::result(
                "binding.prepare.record_json",
                serde_json::from_slice(bytes).map_err(|e| e.to_string()),
            )?;
            if let Some(entries) = event
                .pointer("/setup/approval/entries")
                .and_then(Value::as_array)
            {
                for (source_index, entry) in entries.iter().enumerate() {
                    let _source_slot =
                        semantic::Slot::new("reader.aux.prepare_machine_key", source_index);
                    let fixture = match entry["entry"]["machine"].as_str() {
                        Some("fixture") => run.sshd,
                        Some("fixture-other") => run.sshd_other,
                        _ => continue,
                    };
                    let index = semantic::result(
                        "binding.prepare.machine_index",
                        entry["identity"]["index"]
                            .as_u64()
                            .ok_or("no machine index"),
                    )? as u32;
                    let key = keys::ed25519(&reader::role_key_at(
                        "reader.aux.call.binding.prepare.authorized_key",
                        opened.origin(),
                        &mnemonic,
                        0,
                        index,
                    )?);
                    std::fs::write(
                        fixture.machine.root.join("authorized_keys"),
                        key.public_key().to_openssh().map_err(|e| e.to_string())? + "\n",
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
        }
    }
    if tracer
        && enrol
        && let Some(index) = passes.first()
    {
        let key = keys::relay_public(&reader::role_key_at(
            "reader.aux.call.binding.prepare.relay_key",
            opened.origin(),
            &mnemonic,
            3,
            *index,
        )?);
        *run.relay.passes.lock().expect("passes lock") = vec![fixtures::Pass {
            key,
            hosts: vec!["127.0.0.1".into()],
            expires: SystemTime::now() + Duration::from_secs(3600),
        }];
    }
    for (slot, machine) in machines.iter().enumerate() {
        let name = machine["entry"]["machine"].as_str().unwrap();
        observer::binding_input(call.id(), slot + 1, name);
        let state = run.inspect(worker).await?;
        let bound = state["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["bound_set"].as_array().unwrap().iter().any(|m| m == name));
        call.observe("binding_input", json!({"slot":slot+1,"bound":bound}));
        if bound {
            continue;
        }
        setup_cases::click(run, tab, &format!("[data-bind={name:?}]")).await?;
        wait(run, worker, "binding.page.bound", |s| {
            s["sessions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["bound_set"] == json!([name]))
        })
        .await?;
    }
    Ok(())
}

fn passes_at(caller: &'static str, opened: &reader::Opened) -> Result<Vec<u32>, String> {
    let _helper_call = auxiliary::Call::begin(caller, "reader.aux.passes", opened.origin());
    auxiliary::opened_input(opened.origin(), &opened.records);
    let mut passes = Vec::new();
    for (source_index, (_, bytes)) in opened.records.iter().enumerate() {
        let _source_slot = semantic::Slot::new("reader.aux.pass_record", source_index);
        let event: Value = semantic::result(
            "binding.passes.record_json",
            serde_json::from_slice(bytes).map_err(|e| e.to_string()),
        )?;
        if let Some(id) = event.pointer("/allocation/reserve")
            && id["family"] == "passes"
        {
            passes.push(semantic::result(
                "binding.passes.index_u64",
                id["index"].as_u64().ok_or("no pass index"),
            )? as u32);
        }
    }
    Ok(passes)
}

async fn wait(
    run: &Run<'_>,
    worker: &Worker,
    identity: &'static str,
    check: impl Fn(&Value) -> bool,
) -> Result<(), String> {
    let call = history::Call::worker(identity, &worker.session);
    completion::prerequisite_request(identity);
    for poll in 0..300 {
        call.attempt(poll + 1);
        if call.poll(check(&run.inspect(worker).await?)) {
            completion::prerequisite(identity, true);
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err("binding page act did not finish".into())
}

pub(super) async fn run(
    run: &Run<'_>,
    tab: &Tab,
    pass: &str,
    tracer: bool,
    args: &dyn Fn(&str) -> Value,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let _scenario_span = completion::scenario("binding_cases.run");
    run.browser
        .call(
            None,
            "Target.activateTarget",
            json!({"targetId":tab.target}),
        )
        .await?;
    let mut worker = run.worker(tab, None, false).await?;
    let saved = store_files(&run.dump_at("file.binding_cases.dump.004", tab).await?);
    let mnemonic = reader::read_at("reader.call.binding.saved", &saved, pass)?
        .mnemonic_at("reader.aux.call.binding.saved.mnemonic")?;
    let events = vec![
        json!({"seed":{"mnemonic":mnemonic}}),
        json!({"allocation":{"seed_backup":{"seed":reader::seed_id_from_latest_at("reader.aux.call.binding.saved.seed_id", &mnemonic)?,"completion":"skipped"}}}),
    ];
    run.put(
        tab,
        &reader::build_at("file.binding_cases.build.001", pass, &events),
    )
    .await?;
    worker = run
        .reload("binding_cases.rs::reload#2", tab, &worker)
        .await?;
    run.submit(tab, "unlock", pass).await?;
    setup_cases::approve("binding.setup_approve", run, tab, &worker).await?;
    let build = if tracer { "tracer" } else { "served" };
    let mut case = Case::new(
        "binding_cases.c001",
        &format!("binding is an operator act before contact: {build}"),
    );
    take(run.seen);
    let result = run
        .harness_run("binding_cases.rs#1", &worker, args("fixture"))
        .await?;
    let collected = run
        .harness_collect("binding_cases.rs#2", &worker, args("fixture"))
        .await?;
    let observed = take(run.seen);
    let state = run.inspect(&worker).await?;
    let opened = reader::read_at(
        "reader.call.binding.unbound_refusal",
        &store_files(&run.dump_at("file.binding_cases.dump.005", tab).await?),
        pass,
    )?;
    // Served requests resolve stored targets before connection admission.
    let refusal_outcome = if tracer {
        json!({"refused":"unbound","machine":"fixture"})
    } else {
        json!({"refused":"machine has no stored target or pin"})
    };
    let expected_records = if tracer {
        json!([0, 1, 2, 3, 4])
    } else {
        json!([0, 1, 2])
    };
    case.check(
        "binding_cases.a001",
        "unbound command and collection refuse without binding, intent or contact",
        result["outcome"] == refusal_outcome
            && collected["outcome"] == result["outcome"]
            && state["sessions"] == json!([])
            && state["calls"] == json!([])
            && state["records"] == expected_records
            && observed.relay_accepted == 0
            && observed.ssh_connections == 0,
    );
    case.check(
        "binding_cases.a002",
        "independent reader verifies the refusal append boundary",
        if tracer {
            let refusal: Value =
                serde_json::from_slice(&opened.records[3].1).map_err(|e| e.to_string())?;
            refusal == json!({"connection_refusal":{"machine":"fixture","reason":"unbound"}})
        } else {
            opened.records.len() == 3
        },
    );
    prepare(run, tab, &mut worker, pass).await?;
    let state = run.inspect(&worker).await?;
    case.check(
        "binding_cases.a003",
        "page binding gives each session only its machine client credential",
        state["sessions"].as_array().is_some_and(|sessions| {
            sessions.len() == 2
                && sessions.iter().all(|s| {
                    s["bound_set"].as_array().is_some_and(|set| {
                        set.len() == 1 && s["given"] == json!([{"row":3,"machine":set[0]}])
                    })
                })
        }),
    );
    let before = store_files(&run.dump_at("file.binding_cases.dump.006", tab).await?);
    let second = file_windows::binding_refusal(run, &worker, None).await?;
    case.check(
        "binding_cases.a004",
        "second live binding refuses without a record",
        crate::state_inputs::all!(
            second["error"] == "already bound",
            file_inputs::equal_primary(
                "binding_cases.a004.1",
                "binding_cases.a004",
                &(store_files(&run.dump_at("file.binding_cases.dump.007", tab).await?)),
                &(before),
            )
        ),
    );
    for bad in [
        json!({"machine":"fixture","extra":true}),
        json!(["fixture"]),
        json!({"machine":0}),
    ] {
        let result = file_windows::binding_refusal(run, &worker, Some(bad.clone())).await?;
        case.check(
            "binding_cases.a005",
            "malformed bind input creates no record",
            crate::state_inputs::all!(
                result["error"] == "invalid binding",
                file_inputs::equal_primary(
                    "binding_cases.a005.1",
                    "binding_cases.a005",
                    &(store_files(&run.dump_at("file.binding_cases.dump.008", tab).await?)),
                    &(before),
                )
            ),
        );
    }
    case.finish(cases);

    let mut case = Case::new(
        "binding_cases.c002",
        &format!("bound credentials and machine authorized keys: {build}"),
    );
    for (machine, fixture) in [("fixture", run.sshd), ("fixture-other", run.sshd_other)] {
        let index = machine_index(
            &reader::read_at(
                "reader.call.binding.authorized_key_source",
                &store_files(&run.dump_at("file.binding_cases.dump.009", tab).await?),
                pass,
            )?,
            machine,
        )?;
        let expected = keys::ed25519(&reader::role_key_from_latest_at(
            "reader.aux.call.binding.authorized_key.role_key",
            &mnemonic,
            0,
            index,
        )?)
        .public_key()
        .to_openssh()
        .map_err(|e| e.to_string())?
            + "\n";
        case.check(
            "binding_cases.a006",
            &format!("{machine}'s own authorized_keys holds exactly its derived public key"),
            std::fs::read_to_string(fixture.machine.root.join("authorized_keys"))
                .map_err(|e| e.to_string())?
                == expected,
        );
    }
    let machines: &[&str] = if tracer {
        &["fixture", "fixture-other"]
    } else {
        &["fixture"]
    };
    for &machine in machines {
        fresh_pace(run.relay);
        take(run.seen);
        let mut command = args(machine);
        command["command"] = "true # bound credential witness".into();
        let result = file_uses::binding_authentication(run, &worker, command).await?;
        let observed = take(run.seen);
        if tracer {
            let fingerprint = keys::fingerprint(&reader::role_key_from_latest_at(
                "reader.aux.call.binding.authentication.role_key",
                &mnemonic,
                0,
                machine_index(
                    &reader::read_at(
                        "reader.call.binding.authentication_index",
                        &store_files(&run.dump_at("file.binding_cases.dump.010", tab).await?),
                        pass,
                    )?,
                    machine,
                )?,
            )?);
            let opened = reader::read_at(
                "reader.call.binding.authentication_journal",
                &store_files(&run.dump_at("file.binding_cases.dump.011", tab).await?),
                pass,
            )?;
            let _intent = auxiliary::Call::begin(
                "reader.aux.call.binding.authentication.intent",
                "reader.aux.binding_intent",
                opened.origin(),
            );
            auxiliary::opened_input(opened.origin(), &opened.records);
            let call = semantic::result(
                "binding.authentication.result_call",
                result["outcome"]["call"]
                    .as_u64()
                    .ok_or("bound command did not run"),
            )?;
            let intent: Value = semantic::result(
                "binding.authentication.intent_json",
                serde_json::from_slice(&opened.records[call as usize].1).map_err(|e| e.to_string()),
            )?;
            let session = state["sessions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["bound_set"] == json!([machine]))
                .unwrap();
            case.check("binding_cases.a007",
                &format!("{machine}: derived fingerprint authenticates and intent names the bound session"),
                result["outcome"]["done"] == true
                    && observed
                        .ssh_auth
                        .iter()
                        .any(|(_, actual, admitted)| *admitted && actual == &fingerprint)
                    && intent["intent"]["provenance"]["session"] == session["identity"],
            );
        } else {
            case.check(
                "binding_cases.a008",
                "bound served command requires a stored target and pin before contact",
                result["outcome"] == refusal_outcome
                    && observed.relay_accepted == 0
                    && observed.ssh_connections == 0
                    && run.inspect(&worker).await?["calls"] == json!([]),
            );
        }
    }
    case.finish(cases);

    let mut case = Case::new(
        "binding_cases.c003",
        &format!("exposure ledger survives restart without live bindings: {build}"),
    );
    let opened = reader::read_at(
        "reader.call.binding.exposure_ledger",
        &store_files(&run.dump_at("file.binding_cases.dump.012", tab).await?),
        pass,
    )?;
    let ledger = opened
        .records
        .iter()
        .filter_map(|(_, bytes)| {
            serde_json::from_slice::<Value>(bytes)
                .ok()?
                .get("exposure")
                .cloned()
        })
        .collect::<Vec<_>>();
    case.check(
        "binding_cases.a009",
        "independent reader reads each bound set at binding",
        ledger.len() == 2
            && ledger.iter().all(|e| {
                e["bound_set"]
                    .as_array()
                    .is_some_and(|s| s.len() == 1 && s[0]["identity"]["family"] == "machines")
            }),
    );
    let before = run
        .inspect_state_at("state.binding.replay.before", &worker)
        .await?;
    worker = run
        .reload("binding_cases.rs::reload#3", tab, &worker)
        .await?;
    run.submit(tab, "unlock", pass).await?;
    let after = run
        .inspect_state_at("state.binding.replay.after", &worker)
        .await?;
    case.check(
        "binding_cases.a010",
        "replay preserves the ledger and never revives sessions",
        crate::state_inputs::all!(
            after.same_at("binding_cases.a010", &before, &["/exposure_ledger"]),
            after["sessions"] == json!([])
        ),
    );
    take(run.seen);
    let report = run
        .harness_run("binding_cases.rs#3", &worker, args("fixture"))
        .await?;
    let seen = take(run.seen);
    case.check(
        "binding_cases.a011",
        "an attempt after restart is unbound until another operator binding",
        report["outcome"] == refusal_outcome
            && seen.relay_accepted == 0
            && seen.ssh_connections == 0,
    );
    prepare(run, tab, &mut worker, pass).await?;
    case.check(
        "binding_cases.a012",
        "re-entry creates new session identities and ledger entries",
        crate::state_inputs::all!(
            run.inspect(&worker).await?["exposure_ledger"]
                .as_array()
                .unwrap()
                .len()
                == 4,
            !run.inspect_state_at("state.binding.rebind.after", &worker)
                .await?
                .same_at("binding_cases.a012", &before, &["/sessions"])
        ),
    );
    case.finish(cases);

    let mut case = Case::new(
        "binding_cases.c004",
        &format!("seed-backup re-display ends bindings: {build}"),
    );
    setup_cases::click(run, tab, "#tau-redisplay").await?;
    worker = run.worker(tab, Some(&worker), false).await?;
    run.submit(tab, "unlock", pass).await?;
    seed_cases::skip("binding.redisplay.skip", run, tab).await?;
    take(run.seen);
    let report = run
        .harness_run("binding_cases.rs#4", &worker, args("fixture"))
        .await?;
    let seen = take(run.seen);
    case.check(
        "binding_cases.a013",
        "after re-display completes the session remains ended until rebinding",
        report["outcome"] == refusal_outcome
            && run.inspect(&worker).await?["sessions"] == json!([])
            && seen.relay_accepted == 0
            && seen.ssh_connections == 0,
    );
    prepare(run, tab, &mut worker, pass).await?;
    case.check(
        "binding_cases.a014",
        "the page can bind again",
        run.inspect(&worker).await?["sessions"]
            .as_array()
            .unwrap()
            .len()
            == 2,
    );
    case.finish(cases);
    run.put(tab, &saved).await?;
    run.reload("binding_cases.rs::reload#4", tab, &worker)
        .await?;
    run.submit(tab, "unlock", pass).await?;
    Ok(())
}

pub(super) fn replayed(before: &Value) -> Value {
    let mut expected = before.clone();
    expected["sessions"] = json!([]);
    expected
}

fn machine_index(opened: &reader::Opened, machine: &str) -> Result<u32, String> {
    let _query = auxiliary::Call::begin(
        "reader.aux.call.binding.machine_index",
        "reader.aux.machine_index",
        opened.origin(),
    );
    auxiliary::opened_input(opened.origin(), &opened.records);
    semantic::entered(match machine {
        "fixture" => "binding.machine_index.machine.first",
        "fixture-other" => "binding.machine_index.machine.second",
        _ => "binding.machine_index.machine.unknown",
    });
    for (record, (_, bytes)) in opened.records.iter().enumerate() {
        let _source_record = semantic::Slot::new("reader.aux.machine_index_record", record);
        let event: Value = semantic::result(
            "binding.machine_index.record_json",
            serde_json::from_slice(bytes).map_err(|e| e.to_string()),
        )?;
        if let Some(entries) = event
            .pointer("/setup/approval/entries")
            .and_then(Value::as_array)
            && let Some(entry) = entries.iter().find(|e| e["entry"]["machine"] == machine)
        {
            completion::prerequisite(
                "binding.machine_identity.schema",
                entry["identity"]["index"].as_u64().is_some(),
            );
            return semantic::result(
                "binding.machine_index.value",
                entry["identity"]["index"]
                    .as_u64()
                    .and_then(|i| u32::try_from(i).ok())
                    .ok_or("invalid machine index".into()),
            );
        }
    }
    Err("no approved machine identity".into())
}
