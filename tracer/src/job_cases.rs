//! Job-record cases against the browser build and the fixture's own observations.

use super::*;
use std::time::Instant;

async fn collect(run: &Run<'_>, worker: &Worker, args: Value) -> Result<Value, String> {
    fresh_pace(run.relay);
    let report = run.harness_collect(worker, args).await?;
    println!("   collection reported: {report}");
    Ok(report)
}

fn evidence(report: &Value, call: u64) -> Value {
    report["outcome"]
        .get("collected")
        .unwrap_or(&report["outcome"]["calls"])
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["call"] == call)
        .cloned()
        .unwrap_or(Value::Null)
}

pub(super) async fn wait_launch(
    run: &Run<'_>,
    worker: &Worker,
    previous: u64,
) -> Result<(u64, String), String> {
    for _ in 0..300 {
        let state = run.inspect(worker).await?;
        if let Some(call) = state["calls"].as_array().and_then(|c| c.last())
            && let (Some(call), Some(id)) = (call["call"].as_u64(), call["job"].as_str())
            && call > previous
            && run.sshd.machine.observe().contains_key(id)
        {
            return Ok((call, id.into()));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("fixture saw no job launch".into())
}

pub(super) async fn wait_end(run: &Run<'_>, id: &str) -> Result<(), String> {
    for _ in 0..1000 {
        if run
            .sshd
            .machine
            .observe()
            .get(id)
            .is_some_and(|j| j.ended.is_some())
            && run.sshd.machine.path(id, "exit").is_file()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("fixture saw no job end: {id}"))
}

pub(super) async fn drop_command(
    run: &Run<'_>,
    tab: &Tab,
    worker: Worker,
    mut args: Value,
    command: &str,
) -> Result<(Worker, u64, String), String> {
    fresh_pace(run.relay);
    args["command"] = command.into();
    let previous = run.inspect(&worker).await?["calls"]
        .as_array()
        .and_then(|c| c.last())
        .and_then(|c| c["call"].as_u64())
        .unwrap_or(0);
    run.harness_start(&worker, args).await?;
    let (call, id) = wait_launch(run, &worker, previous).await?;
    if !machine::alive(run.sshd.machine.observe()[&id].pid) {
        return Err("command ended before the drop".into());
    }
    run.browser
        .evaluate(&tab.session, "document.getElementById('tau-lock').click()")
        .await?;
    let mut new = run.worker(tab, Some(&worker), false).await?;
    if !run.sshd.all_ended().await {
        return Err("dropped SSH connection remained".into());
    }
    run.submit(tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare(run, tab, &mut new, PASSPHRASE).await?;
    Ok((new, call, id))
}

pub(super) fn only_reads(seen: &Seen) -> bool {
    !seen.ssh_exec.is_empty()
        && seen
            .ssh_exec
            .iter()
            .all(|e| e.starts_with(b"# tau-web job read "))
}

pub(super) async fn run(
    run: &Run<'_>,
    tab: &Tab,
    mut worker: Worker,
    args: &dyn Fn(&str) -> Value,
    cases: &mut Vec<Case>,
) -> Result<Worker, String> {
    run.submit(tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare(run, tab, &mut worker, PASSPHRASE).await?;
    // Explicit-lock, visibility/pagehide and renderer-crash jobs from earlier cases cannot
    // hold a later collection open. Reboot keeps their records and proves their old boot ended.
    run.sshd.machine.reboot();
    collect(run, &worker, args("fixture")).await?;
    worker = settle_unresolved(run, tab, worker).await?;
    take(run.seen);

    let mut case = Case::new("job drop waits without a second launch (CNF-40)");
    let command = "sleep 6; echo waited; exit 0";
    let (new, call, id) = drop_command(run, tab, worker, args("fixture"), command).await?;
    worker = new;
    let jobs_before = run.sshd.machine.observe();
    case.check(
        "after lock the detached command is still alive",
        machine::alive(jobs_before[&id].pid) && jobs_before[&id].ended.is_none(),
    );
    take(run.seen);
    let commands_before = run.inspect(&worker).await?["commands"].clone();
    let start = Instant::now();
    let report = collect(run, &worker, args("fixture")).await?;
    let observed = take(run.seen);
    let jobs_after = run.sshd.machine.observe();
    let e = evidence(&report, call);
    case.check(
        "collect_jobs appends no intent and reports the holding call",
        run.inspect(&worker).await?["commands"] == commands_before
            && report["journal_entries"] == json!([])
            && report["outcome"]["collected"].is_array()
            && e["call"] == call,
    );
    case.check(
        "collection waited until the fixture saw the command end",
        jobs_after[&id].ended.is_some_and(|t| t >= start)
            && e["state"] == "finished"
            && e["stdout"] == "waited\n",
    );
    case.check(
        "one launch, original command never re-executed, collection only read",
        jobs_before.len() == jobs_after.len()
            && run
                .sshd
                .machine
                .launches()
                .iter()
                .filter(|(job, _)| job == &id)
                .count()
                == 1
            && jobs_after
                .values()
                .filter(|j| j.command == command.as_bytes())
                .count()
                == 1
            && only_reads(&observed)
            && observed.relay_dials.len() == 1,
    );
    case.check(
        "matching record is labelled advisory",
        e["agreement"] == "advisory_match"
            && !e.to_string().to_lowercase().contains("verif")
            && !e.to_string().to_lowercase().contains("passed"),
    );
    cases.push(case);

    let mut case = Case::new(
        "held request on a dropped running command waits without a second launch (CNF-40)",
    );
    let command = "sleep 6; echo held-waited; exit 0";
    let (new, call, id) = drop_command(run, tab, worker, args("fixture"), command).await?;
    worker = new;
    let jobs_before = run.sshd.machine.observe();
    case.check(
        "after lock the detached command is still alive",
        machine::alive(jobs_before[&id].pid) && jobs_before[&id].ended.is_none(),
    );
    take(run.seen);
    let commands_before = run.inspect(&worker).await?["commands"].clone();
    let start = Instant::now();
    fresh_pace(run.relay);
    let report = run.harness_run(&worker, args("fixture")).await?;
    let observed = take(run.seen);
    let jobs_after = run.sshd.machine.observe();
    let e = evidence(&report, call);
    case.check(
        "criteria 1, 5, 7, 9: held request names the call and release, never runs or appends intent",
        run.inspect(&worker).await?["commands"] == commands_before
            && report["outcome"]["held"] == true
            && report["outcome"]["release"] == json!(["finished_record","disposition"])
            && e["call"] == call,
    );
    case.check(
        "criteria 5, 10: held collection waited until the fixture saw the command end",
        jobs_after[&id].ended.is_some_and(|t| t >= start)
            && e["state"] == "finished"
            && e["stdout"] == "held-waited\n",
    );
    case.check(
        "one launch, original command never re-executed, collection only read",
        jobs_before.len() == jobs_after.len()
            && run
                .sshd
                .machine
                .launches()
                .iter()
                .filter(|(job, _)| job == &id)
                .count()
                == 1
            && jobs_after
                .values()
                .filter(|j| j.command == command.as_bytes())
                .count()
                == 1
            && only_reads(&observed)
            && observed.relay_dials.len() == 1,
    );
    case.check(
        "matching record is labelled advisory",
        e["agreement"] == "advisory_match"
            && !e.to_string().to_lowercase().contains("verif")
            && !e.to_string().to_lowercase().contains("passed"),
    );
    cases.push(case);

    let mut case = Case::new("completed dropped job returns its recorded output and exit (CNF-54)");
    let (new, call, id) = drop_command(
        run,
        tab,
        worker,
        args("fixture"),
        "sleep 3; printf 'from disk\\n'; printf 'disk error\\n' >&2; exit 19",
    )
    .await?;
    worker = new;
    wait_end(run, &id).await?;
    let jobs_before = run.sshd.machine.observe();
    let ended = jobs_before[&id].ended.unwrap();
    take(run.seen);
    let start = Instant::now();
    let report = collect(run, &worker, args("fixture")).await?;
    let observed = take(run.seen);
    let e = evidence(&report, call);
    case.check(
        "finished while disconnected and collection did not wait",
        ended < start && start.elapsed() < Duration::from_secs(2),
    );
    case.check(
        "both streams and nonzero command exit came from persistent files",
        e["exit_status"] == 19
            && e["stdout"] == "from disk\n"
            && e["stderr"] == "disk error\n"
            && std::fs::read_to_string(run.sshd.machine.path(&id, "exit"))
                .is_ok_and(|s| s.trim() == "19"),
    );
    case.check(
        "the fixture saw read execs and no launch",
        only_reads(&observed) && run.sshd.machine.observe().len() == jobs_before.len(),
    );
    cases.push(case);

    let mut case =
        Case::new("reboot keeps records; ended and missing calls stay unresolved (CNF-55)");
    let (new, finished, finished_id) = drop_command(
        run,
        tab,
        worker,
        args("fixture"),
        "sleep 2; echo before-reboot; exit 4",
    )
    .await?;
    worker = new;
    wait_end(run, &finished_id).await?;
    let mut legacy_slots = Vec::new();
    legacy_slots.push(
        run.inspect(&worker).await?["records"]
            .as_array()
            .unwrap()
            .len(),
    );
    worker = settle_unresolved(run, tab, worker).await?;
    let (new, running, running_id) =
        drop_command(run, tab, worker, args("fixture"), "sleep 30; echo too-late").await?;
    worker = new;
    legacy_slots.push(
        run.inspect(&worker).await?["records"]
            .as_array()
            .unwrap()
            .len(),
    );
    worker = settle_unresolved(run, tab, worker).await?;
    let (new, missing, missing_id) = drop_command(
        run,
        tab,
        worker,
        args("fixture"),
        "sleep 2; echo missing-record",
    )
    .await?;
    worker = new;
    worker = restore_older_journal(run, tab, worker, &legacy_slots).await?;
    wait_end(run, &missing_id).await?;
    std::fs::remove_dir_all(run.sshd.machine.path(&missing_id, "")).map_err(|e| e.to_string())?;
    let old_boot =
        std::fs::read(run.sshd.machine.path(&running_id, "boot")).map_err(|e| e.to_string())?;
    let count = run.sshd.machine.observe().len();
    run.sshd.machine.reboot();
    take(run.seen);
    let start = Instant::now();
    let report = collect(run, &worker, args("fixture")).await?;
    let observed = take(run.seen);
    let state = run.inspect(&worker).await?;
    case.check(
        "persistent finished record survives reboot",
        evidence(&report, finished)["state"] == "finished"
            && evidence(&report, finished)["exit_status"] == 4
            && evidence(&report, finished)["stdout"] == "before-reboot\n",
    );
    case.check(
        "boot identity proves ended without a terminal, missing stays distinct",
        old_boot != std::fs::read(run.sshd.machine.root.join("boot")).map_err(|e| e.to_string())?
            && evidence(&report, running)["state"] == "ended"
            && evidence(&report, missing)["state"] == "missing"
            && [running, missing].iter().all(|id| {
                state["calls"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|c| c["call"] == *id && c["state"] == "unresolved")
                    && state["terminals"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|t| t["call"] != *id)
            }),
    );
    case.check(
        "neither is waited on or launched again",
        start.elapsed() < Duration::from_secs(2)
            && only_reads(&observed)
            && run.sshd.machine.observe().len() == count,
    );
    cases.push(case);
    worker = settle_unresolved(run, tab, worker).await?;

    let mut case = Case::new("background stdout holder does not hold the command open (STA-20a)");
    fresh_pace(run.relay);
    take(run.seen);
    let mut request = args("fixture");
    request["command"] = "sleep 30 & echo hi".into();
    let start = Instant::now();
    let report = run.harness_run(&worker, request).await?;
    let observed = take(run.seen);
    let outcome = &report["outcome"];
    let id = replay_job(outcome);
    let job = run.sshd.machine.observe().get(id).cloned();
    case.check(
        "command returns within the background process lifetime",
        start.elapsed() < Duration::from_secs(3)
            && outcome["done"] == true
            && outcome["stdout"] == "hi\n"
            && outcome["exit_status"] == 0,
    );
    case.check(
        "fixture saw the real command launch and end",
        exec_command_is(&observed, "sleep 30 & echo hi")
            && job.is_some_and(|j| j.command == b"sleep 30 & echo hi" && j.ended.is_some()),
    );
    cases.push(case);

    let mut case =
        Case::new("every live command is compared and mismatch survives reload (CNF-56)");
    fresh_pace(run.relay);
    take(run.seen);
    let mut request = args("fixture");
    let command = "printf 'started\\n'; sleep 3; echo mismatch; exit 9";
    request["command"] = command.into();
    let previous = run.inspect(&worker).await?["calls"]
        .as_array()
        .and_then(|c| c.last())
        .and_then(|c| c["call"].as_u64())
        .unwrap_or(0);
    run.browser
        .evaluate(
            &worker.session,
            &format!("self.__jobResult = {}; void 0", run_expression(&request)),
        )
        .await?;
    let (call, id) = wait_launch(run, &worker, previous).await?;
    let mut started = false;
    for _ in 0..300 {
        if std::fs::read(run.sshd.machine.path(&id, "stdout"))
            .is_ok_and(|b| b.starts_with(b"started\n"))
        {
            started = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    if !started {
        return Err("mismatch command did not emit its start marker".into());
    }
    std::fs::write(run.sshd.machine.path(&id, "command"), b"truncated record")
        .map_err(|e| e.to_string())?;
    let report = run
        .browser
        .evaluate(&worker.session, "self.__jobResult")
        .await?;
    let observed = take(run.seen);
    let outcome = &report["outcome"];
    let e = &outcome["job_record"];
    case.check(
        "live mismatch settles with finding and command output",
        outcome["done"] == true
            && outcome["exit_status"] == 9
            && outcome["stdout"] == "started\nmismatch\n"
            && e["agreement"] == "finding"
            && e["journal"] == hex::encode(command)
            && e["received"] == hex::encode("truncated record")
            && !e.to_string().to_lowercase().contains("verif")
            && !e.to_string().to_lowercase().contains("passed"),
    );
    case.check(
        "fixture observed the original launch, and its altered command record",
        exec_command_is(&observed, command)
            && run.sshd.machine.observe()[&id].command == command.as_bytes()
            && std::fs::read(run.sshd.machine.path(&id, "command"))
                .is_ok_and(|b| b == b"truncated record"),
    );
    let before = run.inspect(&worker).await?;
    worker = run.reload(tab, &worker).await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    let after = run.inspect(&worker).await?;
    case.check(
        "finding and terminal survive reload and unlock",
        after == binding_cases::replayed(&before)
            && after["jobs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["call"] == call && r["agreement"] == "finding"),
    );
    case.check(
        "independent reader reads all new record shapes",
        reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE).is_ok(),
    );
    cases.push(case);

    binding_cases::prepare(run, tab, &mut worker, PASSPHRASE).await?;
    let mut case = Case::new("collection under each standing disposition preserves it (CNF-110)");
    for continuation in [
        "destructive_reinstall",
        "abandonment",
        "as_if_done",
        "as_if_not_done",
    ] {
        let original = store_files(&run.dump(tab).await?);
        let (new, call, id) = drop_command(
            run,
            tab,
            worker,
            args("fixture"),
            "sleep 3; echo disposed; exit 6",
        )
        .await?;
        worker = new;
        let opened = reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
        let mut events = opened
            .records
            .iter()
            .map(|(_, p)| serde_json::from_slice::<Value>(p).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        events.push(json!({"disposition":{"machine":"fixture","calls":[call],"continuation":continuation,"uncertainty":"the command outcome is unknown"}}));
        run.put(tab, &reader::build(PASSPHRASE, &events)).await?;
        worker = run.reload(tab, &worker).await?;
        run.submit(tab, "unlock", PASSPHRASE).await?;
        binding_cases::prepare(run, tab, &mut worker, PASSPHRASE).await?;
        let before = run.inspect(&worker).await?;
        let destructive = matches!(continuation, "destructive_reinstall" | "abandonment");
        for phase in 0..2 {
            take(run.seen);
            fresh_pace(run.relay);
            let report = run.harness_run(&worker, args("fixture")).await?;
            let observed = take(run.seen);
            case.check(
                &format!("{continuation}, phase {phase}: command verdict and contact"),
                if destructive {
                    report["outcome"]["refused"] == "disposition"
                        && observed.relay_accepted == 0
                        && observed.ssh_connections == 0
                } else {
                    report["outcome"]["done"] == true && exec_command_is(&observed, COMMAND)
                },
            );
            if phase == 0 {
                let jobs_before = run.sshd.machine.observe().len();
                let commands_before = run.inspect(&worker).await?["commands"].clone();
                let report = collect(run, &worker, args("fixture")).await?;
                let observed = take(run.seen);
                case.check(&format!("{continuation}: collection contacted the fixtures, read a real job, appended evidence only"), evidence(&report, call)["exit_status"] == 6 && evidence(&report, call)["stdout"] == "disposed\n" && only_reads(&observed) && observed.relay_dials.len() == 1 && run.sshd.machine.observe().len() == jobs_before && run.sshd.machine.path(&id, "exit").exists() && run.inspect(&worker).await?["commands"] == commands_before);
            }
        }
        let after = run.inspect(&worker).await?;
        case.check(
            &format!("{continuation}: disposition still stands and call stays disposed"),
            after["standing"] == before["standing"]
                && after["calls"].as_array().unwrap().iter().any(|c| {
                    c["call"] == call && c["state"] == "disposed" && c["outcome"] == "unknown"
                }),
        );
        // Restore this case's input journal, so the next continuation starts unrestricted.
        run.put(tab, &original).await?;
        worker = run.reload(tab, &worker).await?;
        run.submit(tab, "unlock", PASSPHRASE).await?;
        binding_cases::prepare(run, tab, &mut worker, PASSPHRASE).await?;
    }
    cases.push(case);
    let mut case = Case::new("live signal reports ended evidence without a terminal");
    fresh_pace(run.relay);
    let mut request = args("fixture");
    request["command"] = "echo before; kill -KILL $$; echo after".into();
    let report = run.harness_run(&worker, request).await?;
    let outcome = &report["outcome"];
    let call = outcome["call"]
        .as_u64()
        .ok_or("signal result has no call")?;
    let state = run.inspect(&worker).await?;
    case.check(
        "live signal is unresolved with its evidence and partial output",
        outcome["unresolved"] == true
            && outcome["job_record"]["state"] == "ended"
            && outcome["job_record"]["agreement"] == "advisory_match"
            && outcome["job_record"]["stdout"] == "before\n"
            && outcome["job_record"]["exit_status"].is_null(),
    );
    case.check(
        "no terminal is journaled for a signalled command",
        state["calls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["call"] == call && c["state"] == "unresolved")
            && state["terminals"]
                .as_array()
                .unwrap()
                .iter()
                .all(|t| t["call"] != call),
    );
    cases.push(case);

    worker = settle_unresolved(run, tab, worker).await?;
    let mut case = Case::new("collection continues past an invalid job record file");
    let (new, bad, bad_id) =
        drop_command(run, tab, worker, args("fixture"), "sleep 2; echo damaged").await?;
    worker = new;
    wait_end(run, &bad_id).await?;
    let slot = run.inspect(&worker).await?["records"]
        .as_array()
        .unwrap()
        .len();
    worker = settle_unresolved(run, tab, worker).await?;
    let (new, good, good_id) = drop_command(
        run,
        tab,
        worker,
        args("fixture"),
        "sleep 2; echo later; exit 23",
    )
    .await?;
    worker = new;
    worker = restore_older_journal(run, tab, worker, &[slot]).await?;
    wait_end(run, &good_id).await?;
    let boot_path = run.sshd.machine.path(&bad_id, "boot");
    let boot = std::fs::read(&boot_path).map_err(|e| e.to_string())?;
    std::fs::write(&boot_path, "damaged\"boot\n").map_err(|e| e.to_string())?;
    let report = collect(run, &worker, args("fixture")).await?;
    let state = run.inspect(&worker).await?;
    case.check(
        "first read reports its own failure and later read reports finished",
        evidence(&report, bad)["failed"] == true
            && evidence(&report, bad)["why"].as_str().is_some_and(|why| {
                why.contains("cannot read complete job record file")
                    && why.contains(boot_path.to_str().unwrap())
            })
            && evidence(&report, good)["state"] == "finished"
            && evidence(&report, good)["exit_status"] == 23
            && evidence(&report, good)["stdout"] == "later\n",
    );
    case.check(
        "later terminal is journaled while the damaged call stays unresolved",
        state["calls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["call"] == bad && c["state"] == "unresolved")
            && state["terminals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["call"] == good && t["exit_status"] == 23),
    );
    std::fs::write(&boot_path, boot).map_err(|e| e.to_string())?;
    cases.push(case);

    worker = settle_unresolved(run, tab, worker).await?;
    super::hold_cases::run(run, tab, worker, args, cases).await
}

/// Replay fixture for an older journal with several unresolved commands on one machine.
/// Replace temporary fixture dispositions by cancelled intents, preserving every call number.
pub(super) async fn restore_older_journal(
    run: &Run<'_>,
    tab: &Tab,
    worker: Worker,
    slots: &[usize],
) -> Result<Worker, String> {
    let files = store_files(&run.dump(tab).await?);
    let opened = reader::read(&files, PASSPHRASE)?;
    let mut events: Vec<Value> = opened
        .records
        .iter()
        .map(|(_, p)| serde_json::from_slice(p).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    for &slot in slots {
        assert!(events[slot].get("disposition").is_some());
        events[slot] = json!({"intent":{"call":slot,"machine":"fixture","command":hex::encode("true"),"approval":null}});
    }
    run.put(tab, &reader::build(PASSPHRASE, &events)).await?;
    let mut worker = run.reload(tab, &worker).await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare(run, tab, &mut worker, PASSPHRASE).await?;
    Ok(worker)
}
