//! Job-record cases against the browser build and the fixture's own observations.

use super::logical_checks::Observe as _;
use super::*;
use std::time::Instant;

async fn collect(run: &Run<'_>, worker: &Worker, args: Value) -> Result<Value, String> {
    fresh_pace(run.relay);
    let report = run.harness_collect("job_cases.rs#1", worker, args).await?;
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
    site: &'static str,
    source: usize,
    run: &Run<'_>,
    worker: &Worker,
    previous: u64,
) -> Result<(u64, String), String> {
    let observation = observer::Call::begin_worker(site, "job.wait_launch", worker, json!({}));
    observation.causal_input(causal::launch_input(
        source,
        worker,
        previous,
        observation.id(),
    ));
    for poll in 0..300 {
        observation.attempt(poll + 1);
        let state = observation.inspect(run, worker).await?;
        let launched = if let Some(call) = state["calls"].as_array().and_then(|c| c.last())
            && let (Some(call), Some(id)) = (call["call"].as_u64(), call["job"].as_str())
            && observation.job_newer(call, previous)
            && observation.job_contains(run.sshd, id)
        {
            Some((call, id.to_string()))
        } else {
            None
        };
        if observation.poll(poll + 1, launched.is_some()) {
            let (call, id) = launched.unwrap();
            return Ok(observation.job_result(source, call, id));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("fixture saw no job launch".into())
}

pub(super) async fn wait_end(
    site: &'static str,
    source_job: &'static str,
    run: &Run<'_>,
    id: &str,
) -> Result<(), String> {
    let observation = observer::Call::begin(site, "job.wait_end", None, json!({}));
    observation.causal_input(causal::end_input(source_job, id, observation.id()));
    observation.fact("fixture_input", causal::fixture_role(run.sshd) == "primary");
    for poll in 0..1000 {
        observation.attempt(poll + 1);
        if observation.poll(
            poll + 1,
            observation.job_ended(run.sshd, id) && observation.job_exit(run.sshd, id),
        ) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("fixture saw no job end: {id}"))
}

pub(super) async fn drop_command(
    source: (&'static str, &'static str, usize),
    run: &Run<'_>,
    tab: &Tab,
    worker: Worker,
    mut args: Value,
    command: &str,
) -> Result<(Worker, u64, String), String> {
    let (site, source_job, occurrence) = source;
    let _observation = observer::Call::begin(
        site,
        "job.drop_command",
        Some(&tab.session),
        json!({"source_job":source_job,"occurrence":occurrence}),
    );
    fresh_pace(run.relay);
    args["command"] = command.into();
    let (source, before) = causal::job_baseline(
        (source_job, occurrence, "call", "drop"),
        run,
        &worker,
        &args,
    )
    .await?;
    let previous = before["calls"]
        .as_array()
        .and_then(|c| c.last())
        .and_then(|c| c["call"].as_u64())
        .unwrap_or(0);
    causal::job_start(source, run, &worker, args).await?;
    let (call, id) = wait_launch("job.drop.wait_launch", source, run, &worker, previous).await?;
    completion::prerequisite(
        "job.drop.original_launch",
        run.sshd.machine.observe().contains_key(&id),
    );
    if completion::rejects(
        "job.drop.alive_before_lock",
        !machine::alive(run.sshd.machine.observe()[&id].pid),
    ) {
        return Err("command ended before the drop".into());
    }
    run.browser
        .evaluate(&tab.session, "document.getElementById('tau-lock').click()")
        .await?;
    let mut new = run.worker(tab, Some(&worker), false).await?;
    if completion::rejects(
        "job.drop.ssh_closed",
        !run.sshd
            .all_ended_at(Some("job.drop.connection_end"), json!({}))
            .await,
    ) {
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
    let _scenario_span = completion::scenario("job_cases.run");
    run.submit(tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare(run, tab, &mut worker, PASSPHRASE).await?;
    // Explicit-lock, visibility/pagehide and renderer-crash jobs from earlier cases cannot
    // hold a later collection open. Reboot keeps their records and proves their old boot ended.
    run.sshd.machine.reboot();
    collect(run, &worker, args("fixture")).await?;
    worker = settle_unresolved("settle.job_cases.001", run, tab, worker).await?;
    take(run.seen);

    let mut case = Case::new(
        "job_cases.c001",
        "job drop waits without a second launch (CNF-40)",
    );
    let command = "sleep 6; echo waited; exit 0";
    let (new, call, id) = drop_command(
        ("job.dropped_wait", "job.dropped_wait", 0),
        run,
        tab,
        worker,
        args("fixture"),
        command,
    )
    .await?;
    worker = new;
    let jobs_before = run.sshd.machine.observe();
    case.check(
        "job_cases.a001",
        "after lock the detached command is still alive",
        machine::alive(jobs_before[&id].pid) && jobs_before[&id].ended.is_none(),
    );
    take(run.seen);
    let commands_before = run
        .inspect_state_at("state.job.collect.before", &worker)
        .await?;
    let start = Instant::now();
    let report = collect(run, &worker, args("fixture")).await?;
    let observed = take(run.seen);
    let jobs_after = run.sshd.machine.observe();
    let e = evidence(&report, call);
    case.check(
        "job_cases.a002",
        "collect_jobs appends no intent and reports the holding call",
        crate::state_inputs::all!(
            run.inspect_state_at("state.job.collect.after", &worker)
                .await?
                .same_at("job_cases.a002", &commands_before, &["/commands"]),
            report["journal_entries"] == json!([]),
            report["outcome"]["collected"].is_array(),
            e["call"] == call
        ),
    );
    case.check(
        "job_cases.a003",
        "collection waited until the fixture saw the command end",
        jobs_after[&id].ended.is_some_and(|t| t >= start)
            && e["state"] == "finished"
            && e["stdout"] == "waited\n",
    );
    case.check(
        "job_cases.a004",
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
        "job_cases.a005",
        "matching record is labelled advisory",
        e["agreement"] == "advisory_match"
            && !e.to_string().to_lowercase().contains("verif")
            && !e.to_string().to_lowercase().contains("passed"),
    );
    case.finish(cases);

    let mut case = Case::new(
        "job_cases.c002",
        "held request on a dropped running command waits without a second launch (CNF-40)",
    );
    let command = "sleep 6; echo held-waited; exit 0";
    let (new, call, id) = drop_command(
        ("job.held_wait", "job.held_wait", 0),
        run,
        tab,
        worker,
        args("fixture"),
        command,
    )
    .await?;
    worker = new;
    let jobs_before = run.sshd.machine.observe();
    case.check(
        "job_cases.a006",
        "after lock the detached command is still alive",
        machine::alive(jobs_before[&id].pid) && jobs_before[&id].ended.is_none(),
    );
    take(run.seen);
    let commands_before = run
        .inspect_state_at("state.job.held.before", &worker)
        .await?;
    let start = Instant::now();
    fresh_pace(run.relay);
    let report = run
        .harness_run("job_cases.rs#2", &worker, args("fixture"))
        .await?;
    let observed = take(run.seen);
    let jobs_after = run.sshd.machine.observe();
    let e = evidence(&report, call);
    case.check("job_cases.a007",
"criteria 1, 5, 7, 9: held request names the call and release, never runs or appends intent",
crate::state_inputs::all!(
run.inspect_state_at("state.job.held.after", &worker).await?.same_at("job_cases.a007", &commands_before, &["/commands"]),
report["outcome"]["held"] == true,
report["outcome"]["release"] == json!(["finished_record","disposition"]),
e["call"] == call
));
    case.check(
        "job_cases.a008",
        "criteria 5, 10: held collection waited until the fixture saw the command end",
        jobs_after[&id].ended.is_some_and(|t| t >= start)
            && e["state"] == "finished"
            && e["stdout"] == "held-waited\n",
    );
    case.check(
        "job_cases.a009",
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
        "job_cases.a010",
        "matching record is labelled advisory",
        e["agreement"] == "advisory_match"
            && !e.to_string().to_lowercase().contains("verif")
            && !e.to_string().to_lowercase().contains("passed"),
    );
    case.finish(cases);

    let mut case = Case::new(
        "job_cases.c003",
        "completed dropped job returns its recorded output and exit (CNF-54)",
    );
    let (new, call, id) = drop_command(
        ("job.completed", "job.completed", 0),
        run,
        tab,
        worker,
        args("fixture"),
        "sleep 3; printf 'from disk\\n'; printf 'disk error\\n' >&2; exit 19",
    )
    .await?;
    worker = new;
    wait_end("job.completed.wait_end", "job.completed", run, &id).await?;
    let jobs_before = run.sshd.machine.observe();
    let ended = jobs_before[&id].ended.unwrap();
    take(run.seen);
    let start = Instant::now();
    let report = collect(run, &worker, args("fixture")).await?;
    let observed = take(run.seen);
    let e = evidence(&report, call);
    case.check(
        "job_cases.a011",
        "finished while disconnected and collection did not wait",
        ended < start && start.elapsed() < Duration::from_secs(2),
    );
    case.check(
        "job_cases.a012",
        "both streams and nonzero command exit came from persistent files",
        e["exit_status"] == 19
            && e["stdout"] == "from disk\n"
            && e["stderr"] == "disk error\n"
            && std::fs::read_to_string(run.sshd.machine.path(&id, "exit"))
                .is_ok_and(|s| s.trim() == "19"),
    );
    case.check(
        "job_cases.a013",
        "the fixture saw read execs and no launch",
        only_reads(&observed) && run.sshd.machine.observe().len() == jobs_before.len(),
    );
    case.finish(cases);

    let mut case = Case::new(
        "job_cases.c004",
        "reboot keeps records; ended and missing calls stay unresolved (CNF-55)",
    );
    let (new, finished, finished_id) = drop_command(
        ("job.reboot.finished", "job.reboot.finished", 0),
        run,
        tab,
        worker,
        args("fixture"),
        "sleep 2; echo before-reboot; exit 4",
    )
    .await?;
    worker = new;
    wait_end(
        "job.reboot.finished.wait_end",
        "job.reboot.finished",
        run,
        &finished_id,
    )
    .await?;
    let mut legacy_slots = Vec::new();
    legacy_slots.push(
        run.inspect(&worker).await?["records"]
            .as_array()
            .unwrap()
            .len(),
    );
    worker = settle_unresolved("settle.job_cases.002", run, tab, worker).await?;
    let (new, running, running_id) = drop_command(
        ("job.reboot.running", "job.reboot.running", 0),
        run,
        tab,
        worker,
        args("fixture"),
        "sleep 30; echo too-late",
    )
    .await?;
    worker = new;
    legacy_slots.push(
        run.inspect(&worker).await?["records"]
            .as_array()
            .unwrap()
            .len(),
    );
    worker = settle_unresolved("settle.job_cases.003", run, tab, worker).await?;
    let (new, missing, missing_id) = drop_command(
        ("job.reboot.missing", "job.reboot.missing", 0),
        run,
        tab,
        worker,
        args("fixture"),
        "sleep 2; echo missing-record",
    )
    .await?;
    worker = new;
    worker = restore_older_journal(run, tab, worker, &legacy_slots).await?;
    wait_end(
        "job.reboot.missing.wait_end",
        "job.reboot.missing",
        run,
        &missing_id,
    )
    .await?;
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
        "job_cases.a014",
        "persistent finished record survives reboot",
        evidence(&report, finished)["state"] == "finished"
            && evidence(&report, finished)["exit_status"] == 4
            && evidence(&report, finished)["stdout"] == "before-reboot\n",
    );
    case.check(
        "job_cases.a015",
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
        "job_cases.a016",
        "neither is waited on or launched again",
        start.elapsed() < Duration::from_secs(2)
            && only_reads(&observed)
            && run.sshd.machine.observe().len() == count,
    );
    case.finish(cases);
    worker = settle_unresolved("settle.job_cases.004", run, tab, worker).await?;

    let mut case = Case::new(
        "job_cases.c005",
        "background stdout holder does not hold the command open (STA-20a)",
    );
    fresh_pace(run.relay);
    take(run.seen);
    let mut request = args("fixture");
    request["command"] = "sleep 30 & echo hi".into();
    let start = Instant::now();
    let report = run.harness_run("job_cases.rs#3", &worker, request).await?;
    let observed = take(run.seen);
    let outcome = &report["outcome"];
    let id = replay_job(outcome);
    let job = run.sshd.machine.observe().get(id).cloned();
    case.check(
        "job_cases.a017",
        "command returns within the background process lifetime",
        start.elapsed() < Duration::from_secs(3)
            && outcome["done"] == true
            && outcome["stdout"] == "hi\n"
            && outcome["exit_status"] == 0,
    );
    case.check(
        "job_cases.a018",
        "fixture saw the real command launch and end",
        exec_command_is(&observed, "sleep 30 & echo hi")
            && job.is_some_and(|j| j.command == b"sleep 30 & echo hi" && j.ended.is_some()),
    );
    case.finish(cases);

    let mut case = Case::new(
        "job_cases.c006",
        "every live command is compared and mismatch survives reload (CNF-56)",
    );
    fresh_pace(run.relay);
    take(run.seen);
    let mut request = args("fixture");
    let command = "printf 'started\\n'; sleep 3; echo mismatch; exit 9";
    request["command"] = command.into();
    let (source, before) = causal::job_baseline(
        ("job.mismatch", 0, "call", "mismatch"),
        run,
        &worker,
        &request,
    )
    .await?;
    let previous = before["calls"]
        .as_array()
        .and_then(|c| c.last())
        .and_then(|c| c["call"].as_u64())
        .unwrap_or(0);
    causal::job_page(
        source,
        run,
        &worker,
        &format!("self.__jobResult = {}; void 0", run_expression(&request)),
    )
    .await?;
    let (call, id) =
        wait_launch("job.mismatch.wait_launch", source, run, &worker, previous).await?;
    let mut started = false;
    {
        let observation = observer::Call::begin(
            "job.mismatch.start_observed",
            "serial.observation",
            Some(&tab.session),
            json!({"bound":300,"false_sleep_ms":10,"requires_ready":true,"job":"original_mismatch_dispatch"}),
        );
        observation.causal_input(causal::end_input("job.mismatch", &id, observation.id()));
        for poll in 0..300 {
            observation.attempt(poll + 1);
            if observation.poll(
                poll + 1,
                observation.job_marker(run.sshd, source, &id, "stdout", b"started\n"),
            ) {
                started = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    if completion::rejects("job.mismatch.start_marker", !started) {
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
        "job_cases.a019",
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
        "job_cases.a020",
        "fixture observed the original launch, and its altered command record",
        exec_command_is(&observed, command)
            && run.sshd.machine.observe()[&id].command == command.as_bytes()
            && std::fs::read(run.sshd.machine.path(&id, "command"))
                .is_ok_and(|b| b == b"truncated record"),
    );
    let before = run
        .inspect_state_at("state.job.replay.before", &worker)
        .await?;
    worker = run.reload("job_cases.rs::reload#1", tab, &worker).await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    let after = run
        .inspect_state_at("state.job.replay.after", &worker)
        .await?;
    case.check(
        "job_cases.a021",
        "finding and terminal survive reload and unlock",
        crate::state_inputs::all!(
            after.replayed_at("job_cases.a021", &before),
            after["jobs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["call"] == call && r["agreement"] == "finding")
        ),
    );
    case.check(
        "job_cases.a022",
        "independent reader reads all new record shapes",
        reader::read_at(
            "reader.call.job.new_shapes",
            &store_files(&run.dump_at("file.job_cases.dump.001", tab).await?),
            PASSPHRASE,
        )
        .is_ok(),
    );
    case.finish(cases);

    binding_cases::prepare(run, tab, &mut worker, PASSPHRASE).await?;
    let mut case = Case::new(
        "job_cases.c007",
        "collection under each standing disposition preserves it (CNF-110)",
    );
    for continuation in [
        "destructive_reinstall",
        "abandonment",
        "as_if_done",
        "as_if_not_done",
    ] {
        let original = store_files(&run.dump_at("file.job_cases.dump.002", tab).await?);
        let (new, call, id) = drop_command(
            (
                "job.disposition",
                "job.disposition",
                match continuation {
                    "destructive_reinstall" => 0,
                    "abandonment" => 1,
                    "as_if_done" => 2,
                    "as_if_not_done" => 3,
                    _ => usize::MAX,
                },
            ),
            run,
            tab,
            worker,
            args("fixture"),
            "sleep 3; echo disposed; exit 6",
        )
        .await?;
        worker = new;
        let opened = reader::read_at(
            "reader.call.job.disposition_source",
            &store_files(&run.dump_at("file.job_cases.dump.003", tab).await?),
            PASSPHRASE,
        )?;
        let mut events = opened
            .records
            .iter()
            .map(|(_, p)| serde_json::from_slice::<Value>(p).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        events.push(json!({"disposition":{"machine":"fixture","calls":[call],"continuation":continuation,"uncertainty":"the command outcome is unknown"}}));
        run.put(
            tab,
            &reader::build_at("file.job_cases.build.001", PASSPHRASE, &events),
        )
        .await?;
        worker = run.reload("job_cases.rs::reload#2", tab, &worker).await?;
        run.submit(tab, "unlock", PASSPHRASE).await?;
        binding_cases::prepare(run, tab, &mut worker, PASSPHRASE).await?;
        let before = run
            .inspect_state_at("state.job.disposition.before", &worker)
            .await?;
        let destructive = matches!(continuation, "destructive_reinstall" | "abandonment");
        for phase in 0..2 {
            take(run.seen);
            fresh_pace(run.relay);
            let report = run
                .harness_run("job_cases.rs#4", &worker, args("fixture"))
                .await?;
            let observed = take(run.seen);
            case.check(
                "job_cases.a023",
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
                let commands_before = run
                    .inspect_state_at("state.job.disposition_collect.before", &worker)
                    .await?;
                let report = collect(run, &worker, args("fixture")).await?;
                let observed = take(run.seen);
                case.check("job_cases.a024",
&format!("{continuation}: collection contacted the fixtures, read a real job, appended evidence only"),
crate::state_inputs::all!(
evidence(&report, call)["exit_status"] == 6,
evidence(&report, call)["stdout"] == "disposed\n",
only_reads(&observed),
observed.relay_dials.len() == 1,
run.sshd.machine.observe().len() == jobs_before,
run.sshd.machine.path(&id, "exit").exists(),
run.inspect_state_at("state.job.disposition_collect.after", &worker).await?.same_at("job_cases.a024", &commands_before, &["/commands"])
));
            }
        }
        let after = run
            .inspect_state_at("state.job.disposition.after", &worker)
            .await?;
        case.check(
            "job_cases.a025",
            &format!("{continuation}: disposition still stands and call stays disposed"),
            crate::state_inputs::all!(
                after.same_at("job_cases.a025", &before, &["/standing"]),
                after["calls"].as_array().unwrap().iter().any(|c| {
                    c["call"] == call && c["state"] == "disposed" && c["outcome"] == "unknown"
                })
            ),
        );
        // Restore this case's input journal, so the next continuation starts unrestricted.
        run.put(tab, &original).await?;
        worker = run.reload("job_cases.rs::reload#3", tab, &worker).await?;
        run.submit(tab, "unlock", PASSPHRASE).await?;
        binding_cases::prepare(run, tab, &mut worker, PASSPHRASE).await?;
    }
    case.finish(cases);
    let mut case = Case::new(
        "job_cases.c008",
        "live signal reports ended evidence without a terminal",
    );
    fresh_pace(run.relay);
    let mut request = args("fixture");
    request["command"] = "echo before; kill -KILL $$; echo after".into();
    let report = run.harness_run("job_cases.rs#5", &worker, request).await?;
    let outcome = &report["outcome"];
    let call = outcome["call"]
        .as_u64()
        .ok_or("signal result has no call")
        .checked("job.signal.call")?;
    let state = run.inspect(&worker).await?;
    case.check(
        "job_cases.a026",
        "live signal is unresolved with its evidence and partial output",
        outcome["unresolved"] == true
            && outcome["job_record"]["state"] == "ended"
            && outcome["job_record"]["agreement"] == "advisory_match"
            && outcome["job_record"]["stdout"] == "before\n"
            && outcome["job_record"]["exit_status"].is_null(),
    );
    case.check(
        "job_cases.a027",
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
    case.finish(cases);

    worker = settle_unresolved("settle.job_cases.005", run, tab, worker).await?;
    let mut case = Case::new(
        "job_cases.c009",
        "collection continues past an invalid job record file",
    );
    let (new, bad, bad_id) = drop_command(
        ("job.damaged.first", "job.damaged.first", 0),
        run,
        tab,
        worker,
        args("fixture"),
        "sleep 2; echo damaged",
    )
    .await?;
    worker = new;
    wait_end(
        "job.damaged.first.wait_end",
        "job.damaged.first",
        run,
        &bad_id,
    )
    .await?;
    let slot = run.inspect(&worker).await?["records"]
        .as_array()
        .unwrap()
        .len();
    worker = settle_unresolved("settle.job_cases.006", run, tab, worker).await?;
    let (new, good, good_id) = drop_command(
        ("job.damaged.later", "job.damaged.later", 0),
        run,
        tab,
        worker,
        args("fixture"),
        "sleep 2; echo later; exit 23",
    )
    .await?;
    worker = new;
    worker = restore_older_journal(run, tab, worker, &[slot]).await?;
    wait_end(
        "job.damaged.later.wait_end",
        "job.damaged.later",
        run,
        &good_id,
    )
    .await?;
    let boot_path = run.sshd.machine.path(&bad_id, "boot");
    let boot = std::fs::read(&boot_path).map_err(|e| e.to_string())?;
    std::fs::write(&boot_path, "damaged\"boot\n").map_err(|e| e.to_string())?;
    let report = collect(run, &worker, args("fixture")).await?;
    let state = run.inspect(&worker).await?;
    case.check(
        "job_cases.a028",
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
        "job_cases.a029",
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
    case.finish(cases);

    worker = settle_unresolved("settle.job_cases.007", run, tab, worker).await?;
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
    let files = store_files(&run.dump_at("file.job_cases.dump.004", tab).await?);
    let opened = reader::read_at("reader.call.job.older_source", &files, PASSPHRASE)?;
    let mut events: Vec<Value> = opened
        .records
        .iter()
        .map(|(_, p)| serde_json::from_slice(p).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    for &slot in slots {
        assert!(completion::prerequisite(
            "job.legacy_slot.was_disposition",
            events[slot].get("disposition").is_some()
        ));
        events[slot] = json!({"intent":{"call":slot,"machine":"fixture","command":hex::encode("true"),"approval":null}});
    }
    run.put(
        tab,
        &reader::build_at("file.job_cases.build.002", PASSPHRASE, &events),
    )
    .await?;
    let mut worker = run.reload("job_cases.rs::reload#4", tab, &worker).await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare(run, tab, &mut worker, PASSPHRASE).await?;
    Ok(worker)
}
