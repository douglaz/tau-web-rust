//! Operator binding through the page and fixture enrolment from independently read identities.
use super::*;

pub(super) async fn prepare(
    run: &Run<'_>,
    tab: &Tab,
    worker: &Worker,
    pass: &str,
) -> Result<(), String> {
    prepare_with_enrolment(run, tab, worker, pass, true).await
}

pub(super) async fn prepare_without_enrolment(
    run: &Run<'_>,
    tab: &Tab,
    worker: &Worker,
    pass: &str,
) -> Result<(), String> {
    prepare_with_enrolment(run, tab, worker, pass, false).await
}

async fn prepare_with_enrolment(
    run: &Run<'_>,
    tab: &Tab,
    worker: &Worker,
    pass: &str,
    enrol: bool,
) -> Result<(), String> {
    let state = run.inspect(worker).await?;
    if state["state"] != "unlocked" || state["seed_backup_stage"] != "inactive" {
        return Ok(());
    }
    let machines = state["setup"].as_array().ok_or("no setup projection")?;
    for machine in machines {
        if machine["class"].is_null() {
            let name = machine["entry"]["machine"].as_str().ok_or("no machine")?;
            setup_cases::click(
                run,
                tab,
                &format!("[data-machine={name:?}] [data-answer=no]"),
            )
            .await?;
            wait(run, worker, |s| {
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
    if machines.is_empty() {
        return Ok(());
    }
    let tracer = run.browser.evaluate(&worker.session, "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return typeof m.test_allocate === 'function';})()").await? == true;
    let mut opened = reader::read(&store_files(&run.dump(tab).await?), pass)?;
    let mut passes = passes(&opened)?;
    if tracer && enrol && passes.is_empty() {
        let result = run.browser.evaluate(&worker.session, "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.test_allocate('passes'));})()").await?;
        if result.get("identity").is_none() {
            return Err(format!("fixture enrolment: {result}"));
        }
        opened = reader::read(&store_files(&run.dump(tab).await?), pass)?;
        passes = self::passes(&opened)?;
    }
    let mnemonic = opened.mnemonic()?;
    for (_, bytes) in &opened.records {
        let event: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if let Some(entries) = event
            .pointer("/setup/approval/entries")
            .and_then(Value::as_array)
        {
            for entry in entries {
                let fixture = match entry["entry"]["machine"].as_str() {
                    Some("fixture") => run.sshd,
                    Some("fixture-other") => run.sshd_other,
                    _ => continue,
                };
                let index = entry["identity"]["index"]
                    .as_u64()
                    .ok_or("no machine index")? as u32;
                let key = keys::ed25519(&reader::role_key(&mnemonic, 0, index)?);
                std::fs::write(
                    fixture.machine.root.join("authorized_keys"),
                    key.public_key().to_openssh().map_err(|e| e.to_string())? + "\n",
                )
                .map_err(|e| e.to_string())?;
            }
        }
    }
    if tracer
        && enrol
        && let Some(index) = passes.first()
    {
        let key = keys::relay_public(&reader::role_key(&mnemonic, 3, *index)?);
        *run.relay.passes.lock().expect("passes lock") = vec![fixtures::Pass {
            key,
            hosts: vec!["127.0.0.1".into()],
            expires: SystemTime::now() + Duration::from_secs(3600),
        }];
    }
    for machine in machines {
        let name = machine["entry"]["machine"].as_str().unwrap();
        let state = run.inspect(worker).await?;
        if state["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["bound_set"].as_array().unwrap().iter().any(|m| m == name))
        {
            continue;
        }
        setup_cases::click(run, tab, &format!("[data-bind={name:?}]")).await?;
        wait(run, worker, |s| {
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

fn passes(opened: &reader::Opened) -> Result<Vec<u32>, String> {
    let mut passes = Vec::new();
    for (_, bytes) in &opened.records {
        let event: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if let Some(id) = event.pointer("/allocation/reserve")
            && id["family"] == "passes"
        {
            passes.push(id["index"].as_u64().ok_or("no pass index")? as u32);
        }
    }
    Ok(passes)
}

async fn wait(
    run: &Run<'_>,
    worker: &Worker,
    check: impl Fn(&Value) -> bool,
) -> Result<(), String> {
    for _ in 0..300 {
        if check(&run.inspect(worker).await?) {
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
    run.browser
        .call(
            None,
            "Target.activateTarget",
            json!({"targetId":tab.target}),
        )
        .await?;
    let mut worker = run.worker(tab, None, false).await?;
    let saved = store_files(&run.dump(tab).await?);
    let mnemonic = reader::read(&saved, pass)?.mnemonic()?;
    let events = vec![
        json!({"seed":{"mnemonic":mnemonic}}),
        json!({"allocation":{"seed_backup":{"seed":reader::seed_id(&mnemonic)?,"completion":"skipped"}}}),
    ];
    run.put(tab, &reader::build(pass, &events)).await?;
    worker = run.reload(tab, &worker).await?;
    run.submit(tab, "unlock", pass).await?;
    setup_cases::approve(run, tab, &worker).await?;
    let build = if tracer { "tracer" } else { "served" };
    let mut case = Case::new(&format!(
        "binding is an operator act before contact: {build}"
    ));
    take(run.seen);
    let result = run.harness_run(&worker, args("fixture")).await?;
    let collected = run.harness_collect(&worker, args("fixture")).await?;
    let observed = take(run.seen);
    let state = run.inspect(&worker).await?;
    let opened = reader::read(&store_files(&run.dump(tab).await?), pass)?;
    let refusal: Value = serde_json::from_slice(&opened.records[3].1).map_err(|e| e.to_string())?;
    case.check(
        "unbound command and collection refuse without binding, intent or contact",
        result["outcome"] == json!({"refused":"unbound","machine":"fixture"})
            && collected["outcome"] == result["outcome"]
            && state["sessions"] == json!([])
            && state["calls"] == json!([])
            && state["records"] == json!([0, 1, 2, 3, 4])
            && observed.relay_accepted == 0
            && observed.ssh_connections == 0,
    );
    case.check(
        "independent reader reads the journaled unbound refusal",
        refusal == json!({"connection_refusal":{"machine":"fixture","reason":"unbound"}}),
    );
    prepare(run, tab, &worker, pass).await?;
    let state = run.inspect(&worker).await?;
    case.check(
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
    let before = store_files(&run.dump(tab).await?);
    let second = run.browser.evaluate(&worker.session, "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.bind(JSON.stringify({machine:'fixture'})));})()").await?;
    case.check(
        "second live binding refuses without a record",
        second["error"] == "already bound" && store_files(&run.dump(tab).await?) == before,
    );
    for bad in [
        json!({"machine":"fixture","extra":true}),
        json!(["fixture"]),
        json!({"machine":0}),
    ] {
        let result = run.browser.evaluate(&worker.session, &format!("(async()=>{{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.bind({}));}})()", json!(bad.to_string()))).await?;
        case.check(
            "malformed bind input creates no record",
            result["error"] == "invalid binding" && store_files(&run.dump(tab).await?) == before,
        );
    }
    cases.push(case);

    let mut case = Case::new(&format!(
        "bound credentials and machine authorized keys: {build}"
    ));
    for (machine, fixture) in [("fixture", run.sshd), ("fixture-other", run.sshd_other)] {
        let index = machine_index(
            &reader::read(&store_files(&run.dump(tab).await?), pass)?,
            machine,
        )?;
        let expected = keys::ed25519(&reader::role_key(&mnemonic, 0, index)?)
            .public_key()
            .to_openssh()
            .map_err(|e| e.to_string())?
            + "\n";
        case.check(
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
        let result = run.harness_run(&worker, command).await?;
        let observed = take(run.seen);
        if tracer {
            let fingerprint = keys::fingerprint(&reader::role_key(
                &mnemonic,
                0,
                machine_index(
                    &reader::read(&store_files(&run.dump(tab).await?), pass)?,
                    machine,
                )?,
            )?);
            let opened = reader::read(&store_files(&run.dump(tab).await?), pass)?;
            let call = result["outcome"]["call"]
                .as_u64()
                .ok_or("bound command did not run")?;
            let intent: Value = serde_json::from_slice(&opened.records[call as usize].1)
                .map_err(|e| e.to_string())?;
            let session = state["sessions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["bound_set"] == json!([machine]))
                .unwrap();
            case.check(
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
                "bound served command reaches the missing-pin gate without contact",
                result["outcome"] == json!({"refused":"no-pin"}) && observed.relay_accepted == 0,
            );
        }
    }
    cases.push(case);

    let mut case = Case::new(&format!(
        "exposure ledger survives restart without live bindings: {build}"
    ));
    let opened = reader::read(&store_files(&run.dump(tab).await?), pass)?;
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
        "independent reader reads each bound set at binding",
        ledger.len() == 2
            && ledger.iter().all(|e| {
                e["bound_set"]
                    .as_array()
                    .is_some_and(|s| s.len() == 1 && s[0]["identity"]["family"] == "machines")
            }),
    );
    let before = run.inspect(&worker).await?;
    worker = run.reload(tab, &worker).await?;
    run.submit(tab, "unlock", pass).await?;
    let after = run.inspect(&worker).await?;
    case.check(
        "replay preserves the ledger and never revives sessions",
        after["exposure_ledger"] == before["exposure_ledger"] && after["sessions"] == json!([]),
    );
    take(run.seen);
    let report = run.harness_run(&worker, args("fixture")).await?;
    let seen = take(run.seen);
    case.check(
        "an attempt after restart is unbound until another operator binding",
        report["outcome"]["refused"] == "unbound"
            && seen.relay_accepted == 0
            && seen.ssh_connections == 0,
    );
    prepare(run, tab, &worker, pass).await?;
    case.check(
        "re-entry creates new session identities and ledger entries",
        run.inspect(&worker).await?["exposure_ledger"]
            .as_array()
            .unwrap()
            .len()
            == 4
            && run.inspect(&worker).await?["sessions"] != before["sessions"],
    );
    cases.push(case);

    let mut case = Case::new(&format!("seed-backup re-display ends bindings: {build}"));
    setup_cases::click(run, tab, "#tau-redisplay").await?;
    worker = run.worker(tab, Some(&worker), false).await?;
    run.submit(tab, "unlock", pass).await?;
    seed_cases::skip(run, tab).await?;
    take(run.seen);
    let report = run.harness_run(&worker, args("fixture")).await?;
    let seen = take(run.seen);
    case.check(
        "after re-display completes the session remains ended until rebinding",
        report["outcome"]["refused"] == "unbound"
            && run.inspect(&worker).await?["sessions"] == json!([])
            && seen.relay_accepted == 0
            && seen.ssh_connections == 0,
    );
    prepare(run, tab, &worker, pass).await?;
    case.check(
        "the page can bind again",
        run.inspect(&worker).await?["sessions"]
            .as_array()
            .unwrap()
            .len()
            == 2,
    );
    cases.push(case);
    run.put(tab, &saved).await?;
    run.reload(tab, &worker).await?;
    run.submit(tab, "unlock", pass).await?;
    Ok(())
}

pub(super) fn replayed(before: &Value) -> Value {
    let mut expected = before.clone();
    expected["sessions"] = json!([]);
    expected
}

fn machine_index(opened: &reader::Opened, machine: &str) -> Result<u32, String> {
    for (_, bytes) in &opened.records {
        let event: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if let Some(entries) = event
            .pointer("/setup/approval/entries")
            .and_then(Value::as_array)
            && let Some(entry) = entries.iter().find(|e| e["entry"]["machine"] == machine)
        {
            return entry["identity"]["index"]
                .as_u64()
                .and_then(|i| u32::try_from(i).ok())
                .ok_or("invalid machine index".into());
        }
    }
    Err("no approved machine identity".into())
}
