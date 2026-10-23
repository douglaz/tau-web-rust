//! Unresolved-command hold witnesses against the worker and the relay/SSH fixtures.

use super::*;
use std::time::Instant;

async fn start(run: &Run<'_>, worker: &Worker, name: &str, expression: &str) -> Result<(), String> {
    run.browser
        .evaluate(
            &worker.session,
            &format!("self.{name} = {expression}; void 0"),
        )
        .await?;
    Ok(())
}

async fn restore(
    run: &Run<'_>,
    tab: &Tab,
    worker: Worker,
    files: &Files,
) -> Result<Worker, String> {
    run.put(tab, files).await?;
    let worker = run.reload(tab, &worker).await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare(run, tab, &worker, PASSPHRASE).await?;
    Ok(worker)
}

fn events(files: &Files) -> Result<Vec<Value>, String> {
    reader::read(files, PASSPHRASE)?
        .records
        .iter()
        .map(|(_, p)| serde_json::from_slice(p).map_err(|e| e.to_string()))
        .collect()
}

fn held_call(outcome: &Value, call: u64) -> Value {
    outcome["calls"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["call"] == call)
        .cloned()
        .unwrap_or(Value::Null)
}

async fn stop(run: &Run<'_>, worker: &Worker) -> Result<Value, String> {
    run.browser.evaluate(&worker.session,
        "(async()=>{ const m=await import(new URL('./pkg/tau_web.js',self.location.href).href); return m.stop_waits('fixture'); })()"
    ).await
}

pub(super) async fn run(
    run: &Run<'_>,
    tab: &Tab,
    mut worker: Worker,
    args: &dyn Fn(&str) -> Value,
    cases: &mut Vec<Case>,
) -> Result<Worker, String> {
    let saved = store_files(&run.dump(tab).await?);
    // Independent fixtures start from the same seed, without older collectable disposed calls.
    let prior = events(&saved)?;
    let mnemonic = prior[0]["seed"]["mnemonic"]
        .as_str()
        .ok_or("fixture seed")?;
    let mut initial = vec![prior[0].clone()];
    initial.extend(reader::setup_events(
        mnemonic,
        &["fixture", "fixture-other", "unpinned"],
    ));
    let original = reader::build(PASSPHRASE, &initial);
    worker = restore(run, tab, worker, &original).await?;
    let selected = |name: &str| {
        std::env::var("TAU_TRACER_HOLD_CASE").map_or(true, |s| {
            s == "all" || s.split(',').any(|part| part == name)
        })
    };
    if selected("drop") {
        let mut case = Case::new(
            "held request after replay collects to finished and caller must ask again (CNF-40)",
        );
        let (new, call, _) = job_cases::drop_command(
            run,
            tab,
            worker,
            args("fixture"),
            "sleep 4; echo held-record",
        )
        .await?;
        worker = new;
        let before = run.inspect(&worker).await?;
        take(run.seen);
        fresh_pace(run.relay);
        let report = run.harness_run(&worker, args("fixture")).await?;
        let seen = take(run.seen);
        case.check("criteria 1, 5, 7, 9, 10: after replay a second command stays held, reads only, names its finished holding call and release, records no intent",
            report["outcome"]["held"] == true && held_call(&report["outcome"],call)["state"] == "finished"
            && held_call(&report["outcome"],call)["stdout"] == "held-record\n"
            && report["outcome"]["release"] == json!(["finished_record","disposition"])
            && seen.relay_dials.len() == 1 && job_cases::only_reads(&seen)
            && run.inspect(&worker).await?["commands"] == before["commands"]);
        fresh_pace(run.relay);
        case.check(
            "criterion 5: only a new request runs after the finished record releases hold",
            run.harness_run(&worker, args("fixture")).await?["outcome"]["done"] == true,
        );
        worker = restore(run, tab, worker, &original).await?;
        cases.push(case);
    }
    if selected("simultaneous") {
        let spacing = run
            .relay
            .pace
            .lock()
            .expect("pace")
            .set_spacing(Duration::ZERO);
        let mut case =
            Case::new("simultaneous requests share exactly one dispatch result (CNF-40)");
        for command in [
            "sleep 2; echo shared",
            "sleep 2; kill -KILL $$",
            "close-without-status",
        ] {
            fresh_pace(run.relay);
            take(run.seen);
            let before = run.inspect(&worker).await?;
            let mut request = args("fixture");
            request["command"] = command.into();
            let expression = format!(
                "Promise.all([{},{}])",
                run_expression(&request),
                run_expression(&request)
            );
            start(run, &worker, "__together", &expression).await?;
            if command != "close-without-status" {
                let previous = before["calls"]
                    .as_array()
                    .unwrap()
                    .last()
                    .map(|c| c["call"].as_u64().unwrap())
                    .unwrap_or(0);
                job_cases::wait_launch(run, &worker, previous).await?;
                let collected = run.harness_collect(&worker, args("fixture")).await?;
                case.check(
                "criterion 6: collection during own dispatch does not read or append its result",
                collected["outcome"]["collected"]
                    .as_array()
                    .is_some_and(|r| r.len() == 1 && r[0]["not_read"] == true)
                    && run.inspect(&worker).await?["jobs"] == before["jobs"],
            );
            }
            let reports = run
                .browser
                .evaluate(&worker.session, "self.__together")
                .await?;
            let observed = take(run.seen);
            let after = run.inspect(&worker).await?;
            let results: Vec<_> = reports
                .as_array()
                .ok_or("no simultaneous reports")?
                .iter()
                .map(|r| &r["outcome"])
                .collect();
            let own = results
                .iter()
                .find(|r| r["held"] != true)
                .copied()
                .unwrap_or(&Value::Null);
            let held = results
                .iter()
                .find(|r| r["held"] == true)
                .copied()
                .unwrap_or(&Value::Null);
            let call = own["call"].as_u64().unwrap_or(0);
            case.check("criterion 2: two requests together record one intent and launch exactly one command; later request stays held",
            after["commands"].as_array().unwrap().len() == before["commands"].as_array().unwrap().len()+1
            && observed.ssh_exec.len() == 1 && exec_command_is(&observed,command)
            && held["held"] == true);
            case.check(
                "criterion 2: both overlapping request reports show the single concurrent intent",
                reports
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|r| r["journal_entries"] == json!([hex::encode(command)])),
            );
            case.check("criteria 6, 7: held request carries the own dispatch's exact finished or unresolved result, once",
            held_call(held,call)["dispatch_result"] == *own
            && after["jobs"].as_array().unwrap().len()-before["jobs"].as_array().unwrap().len() == usize::from(command != "close-without-status")
            && held["release"] == json!(["finished_record","disposition"]));
            worker = restore(run, tab, worker, &original).await?;
        }
        run.relay.pace.lock().expect("pace").set_spacing(spacing);
        cases.push(case);
    }
    if selected("stop") {
        let mut case =
            Case::new("stopped held collection leaves writer free and settles nothing (STA-20)");
        let (new, first, first_job) = job_cases::drop_command(
            run,
            tab,
            worker,
            args("fixture"),
            "sleep 2; echo before-stop",
        )
        .await?;
        worker = new;
        job_cases::wait_end(run, &first_job).await?;
        let slot = run.inspect(&worker).await?["records"]
            .as_array()
            .unwrap()
            .len();
        worker = settle_unresolved(run, tab, worker).await?;
        let (new, call, id) = job_cases::drop_command(
            run,
            tab,
            worker,
            args("fixture"),
            "sleep 20; echo stopped-job",
        )
        .await?;
        worker = new;
        worker = job_cases::restore_older_journal(run, tab, worker, &[slot]).await?;
        let mut records = events(&store_files(&run.dump(tab).await?))?;
        let unreadable = records.len() as u64;
        records.push(json!({"command":{"machine":"fixture","command":hex::encode("unreadable legacy command")}}));
        worker = restore(run, tab, worker, &reader::build(PASSPHRASE, &records)).await?;

        take(run.seen);
        fresh_pace(run.relay);
        let before = run.inspect(&worker).await?;
        start(
            run,
            &worker,
            "__stoppable",
            &run_expression(&args("fixture")),
        )
        .await?;
        let reading = settle_for(run.seen, 3, |seen| {
            job_cases::only_reads(seen) && seen.ssh_exec.len() == 2
        })
        .await;
        case.check(
            "criteria 1, 8: held wait reads only the holding job before contact for any command",
            reading && run.seen.lock().expect("seen").relay_dials.len() == 1,
        );
        let operations = async {
            let state = run.inspect(&worker).await?;
            fresh_pace(run.relay);
            let other = run.harness_run(&worker, args("fixture-other")).await?;
            fresh_pace(run.relay);
            let collection = run.harness_collect(&worker, args("fixture-other")).await?;
            Ok::<_, String>((state, other, collection))
        };
        let progress = tokio::time::timeout(Duration::from_secs(4), operations).await;
        case.check("criteria 4, 8: while this request is held, store_state, another machine's command and collection complete",
        progress.as_ref().is_ok_and(|r|r.as_ref().is_ok_and(|(state,other,collected)|
            state["commands"] == before["commands"] && other["outcome"]["done"] == true
            && collected["outcome"]["collected"].is_array())));
        if progress.is_err() {
            return Err("criterion 8: held wait retained the writer".into());
        }
        let before_stop = store_files(&run.dump(tab).await?);
        case.check(
            "criterion 8: stop names the held wait",
            stop(run, &worker).await? == 1,
        );
        let report = run
            .browser
            .evaluate(&worker.session, "self.__stoppable")
            .await?;
        tokio::time::sleep(Duration::from_millis(250)).await;
        case.check("criterion 8: stop and abandoned read append nothing, settle nothing, and leave the detached command alive",
        report["outcome"]["held"] == true && held_call(&report["outcome"],first)["state"] == "finished" && held_call(&report["outcome"],call)["not_read"] == true
        && held_call(&report["outcome"],unreadable)["why"].as_str().is_some_and(|why|why.contains("no job identity; only a disposition"))
        && store_files(&run.dump(tab).await?) == before_stop && machine::alive(run.sshd.machine.observe()[&id].pid)
        && run.inspect(&worker).await?["calls"].as_array().unwrap().iter().any(|c|c["call"] == call && c["state"] == "unresolved"));
        run.sshd.machine.reboot();
        worker = restore(run, tab, worker, &original).await?;
        cases.push(case);
    }
    for mode in ["writer-stop", "append-error"] {
        if !selected(mode) {
            continue;
        }
        let mut case = Case::new(if mode == "writer-stop" {
            "stopped evidence append retains the completed read through the worker (STA-20)"
        } else {
            "evidence append error retains the completed read and unresolved-command hold (STA-20)"
        });
        let command = "sleep 60; echo detached-evidence";
        let (new, call, id) =
            job_cases::drop_command(run, tab, worker, args("fixture"), command).await?;
        worker = new;
        let before = run.inspect(&worker).await?;
        let files_before = store_files(&run.dump(tab).await?);
        take(run.seen);
        fresh_pace(run.relay);
        let mut request = args("fixture");
        if mode == "append-error" {
            request["fail_append"] = true.into();
        }
        start(run, &worker, "__evidence", &run_expression(&request)).await?;
        if !settle_for(run.seen, 3, |seen| {
            job_cases::only_reads(seen) && seen.ssh_exec.len() == 1
        })
        .await
        {
            return Err(format!("{mode}: no holding-call record read"));
        }
        let count_expression = "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return m.test_completed_reads();})()";
        let reads_before = run
            .browser
            .evaluate(&worker.session, count_expression)
            .await?;
        if mode == "writer-stop" {
            run.browser.evaluate(&worker.session,
                "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);let ready;const acquired=new Promise(r=>ready=r);self.__writer=m.test_writer(new Promise(r=>self.__releaseWriter=r),ready);await acquired;})()"
            ).await?;
        }
        // Supply a finished advisory record while the detached command remains alive.
        // The real read can now finish, but the worker's evidence append needs the writer.
        let exit = run.sshd.machine.path(&id, "exit");
        std::fs::write(&exit, "0\n").map_err(|e| e.to_string())?;
        if mode == "writer-stop" {
            let mut completed = false;
            for _ in 0..500 {
                if run
                    .browser
                    .evaluate(&worker.session, count_expression)
                    .await?
                    != reads_before
                {
                    completed = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            // Always release the writer, including when the observation check fails.
            let stopped = stop(run, &worker).await?;
            run.browser
                .evaluate(&worker.session, "self.__releaseWriter(); self.__writer")
                .await?;
            case.check(
                "criterion 8: read completed while the real writer was occupied before stop",
                completed && stopped == 1,
            );
        }
        let report = run
            .browser
            .evaluate(&worker.session, "self.__evidence")
            .await?;
        let entry = held_call(&report["outcome"], call);
        let expected_record = json!({
            "kind":"present", "machine":hex::encode("fixture"),
            "command":hex::encode(command),
            "boot":std::fs::read_to_string(run.sshd.machine.path(&id, "boot"))
                .map_err(|e|e.to_string())?.trim(),
            "current_boot":std::fs::read_to_string(run.sshd.machine.root.join("boot"))
                .map_err(|e|e.to_string())?.trim(),
            "pid":run.sshd.machine.observe()[&id].pid,
            "alive":false, "exit_status":0, "stdout":"", "stderr":""
        });
        case.check(&format!("criterion 8: {mode} reports not_journaled with the completed job_record and why, without not_read"),
            report["outcome"]["held"] == true && entry["not_journaled"] == true
            && entry.get("not_read").is_none()
            && entry["job_record"] == json!({"number":null,"call":call,"job":id,
                "record":expected_record,"state":"finished","agreement":"advisory_match",
                "stdout":"","stderr":"","exit_status":0})
            && if mode == "writer-stop" {
                entry["why"] == "wait stopped before journaling job evidence"
            } else {
                entry["why"].as_str().is_some_and(|why|why.starts_with("job evidence append: "))
            });
        let after = run.inspect(&worker).await?;
        let mut files_after = store_files(&run.dump(tab).await?);
        if mode == "append-error" {
            // A rejected move leaves its staging file, which is never a journal record.
            files_after.remove(tau_web::store::STAGING);
        }
        case.check(&format!("criterion 8: {mode} appends no evidence or terminal and leaves the call unresolved and detached command alive"),
            ["records","commands","jobs","terminals","calls"].iter().all(|key|after[key] == before[key])
            && after["calls"].as_array().is_some_and(|calls|calls.iter().any(|c|c["call"] == call && c["state"] == "unresolved"))
            && files_after == files_before
            && machine::alive(run.sshd.machine.observe()[&id].pid)
            && job_cases::only_reads(&take(run.seen)));
        // Remove only the record file supplied above; the original runner still owns the job.
        std::fs::remove_file(&exit).map_err(|e| e.to_string())?;
        if mode == "append-error" {
            // A storage error latches dispatch off until the worker reopens the journal.
            worker = run.reload(tab, &worker).await?;
            run.submit(tab, "unlock", PASSPHRASE).await?;
            binding_cases::prepare(run, tab, &worker, PASSPHRASE).await?;
        }
        take(run.seen);
        fresh_pace(run.relay);
        start(
            run,
            &worker,
            "__laterEvidence",
            &run_expression(&args("fixture")),
        )
        .await?;
        let reading = settle_for(run.seen, 3, |seen| {
            job_cases::only_reads(seen) && seen.ssh_exec.len() == 1
        })
        .await;
        let stopped = stop(run, &worker).await?;
        let later = run
            .browser
            .evaluate(&worker.session, "self.__laterEvidence")
            .await?;
        case.check(&format!("criterion 8: {mode} leaves a later request held without killing or relaunching the detached command"),
            reading && stopped == 1 && later["outcome"]["held"] == true
            && held_call(&later["outcome"],call)["not_read"] == true
            && machine::alive(run.sshd.machine.observe()[&id].pid)
            && run.sshd.machine.launches().iter().filter(|(job,_)|job == &id).count() == 1
            && run.inspect(&worker).await?["calls"] == before["calls"]);
        run.sshd.machine.reboot();
        worker = restore(run, tab, worker, &original).await?;
        cases.push(case);
    }
    if selected("shared-stop") {
        let mut case =
            Case::new("stopping a shared-result wait does not stop its own dispatch (STA-20)");
        fresh_pace(run.relay);
        let mut request = args("fixture");
        request["command"] = "sleep 2; echo still-running".into();
        let previous = run.inspect(&worker).await?["commands"]
            .as_array()
            .unwrap()
            .last()
            .map(|c| c["number"].as_u64().unwrap_or(0))
            .unwrap_or(0);
        start(run, &worker, "__own", &run_expression(&request)).await?;
        job_cases::wait_launch(run, &worker, previous).await?;
        start(run, &worker, "__shared", &run_expression(&args("fixture"))).await?;
        let stopped = stop(run, &worker).await?;
        let shared = run
            .browser
            .evaluate(&worker.session, "self.__shared")
            .await?;
        let own = run.browser.evaluate(&worker.session, "self.__own").await?;
        case.check("criterion 8: stopped shared-result wait stays held and its independent dispatch still finishes",
        stopped == 1 && shared["outcome"]["held"] == true
        && shared["outcome"]["calls"][0]["not_read"] == true
        && own["outcome"]["done"] == true && own["outcome"]["stdout"] == "still-running\n");
        worker = restore(run, tab, worker, &original).await?;
        cases.push(case);
    }
    if selected("legacy") {
        let mut case = Case::new(
            "legacy and unreadable commands all hold without inventing a record (STA-20)",
        );
        let mut records = events(&original)?;
        let a = records.len();
        records.push(json!({"command":{"machine":"fixture","command":hex::encode("true")}}));
        let b = records.len();
        records.push(
            json!({"intent":{"call":b,"machine":"fixture","command":hex::encode("true"),
            "approval":{"harness_pin":{"machine":"fixture","fingerprint":"SHA256:fixture"}}}}),
        );
        worker = restore(run, tab, worker, &reader::build(PASSPHRASE, &records)).await?;
        let before = store_files(&run.dump(tab).await?);
        for command in ["true", "cat /etc/os-release"] {
            let mut request = args("fixture");
            request["command"] = command.into();
            take(run.seen);
            fresh_pace(run.relay);
            let report = run.harness_run(&worker, request).await?;
            let seen = take(run.seen);
            case.check("criteria 1, 3, 7, 9: same bytes and reads name every unreadable holding call after replay, with no contact or writes",
                report["outcome"]["held"] == true
                && report["outcome"]["calls"].as_array().is_some_and(|r|r.len()==2)
                && [a,b].iter().all(|&call| held_call(&report["outcome"],call as u64)["not_read"] == true
                    && held_call(&report["outcome"],call as u64)["why"].as_str().is_some_and(|s|s.contains("no job identity; only a disposition")))
                && seen.relay_accepted == 0 && store_files(&run.dump(tab).await?) == before);
        }
        worker = restore(run, tab, worker, &original).await?;
        cases.push(case);
    }
    if selected("unreachable") {
        let mut case =
            Case::new("held unreachable machines answer once with why nothing was read (STA-20)");
        for reason in [
            "no-pin",
            "no-credentials",
            "relay",
            "host-key",
            "authentication",
            "connection",
            "lost-during-read",
        ] {
            let mut records = events(&original)?;
            let call = records.len();
            let name = if reason == "no-pin" {
                "unpinned"
            } else {
                "fixture"
            };
            records.push(json!({"intent":{"call":call,"machine":name,"command":hex::encode("true"),
            "approval":{"harness_pin":{"machine":name,"fingerprint":"SHA256:fixture"}},"job":"ab".repeat(24)}}));
            worker = restore(run, tab, worker, &reader::build(PASSPHRASE, &records)).await?;
            let mut request = args(name);
            match reason {
                "no-credentials" => request["test_no_credentials"] = true.into(),
                "relay" => request["tamper_auth"] = true.into(),
                "host-key" => run.sshd.present_other.store(true, Ordering::SeqCst),
                "authentication" => request["user"] = "unauthorized".into(),
                "connection" => request["port"] = 1.into(),
                "lost-during-read" => run.sshd.disconnect_read.store(true, Ordering::SeqCst),
                _ => {}
            }
            take(run.seen);
            fresh_pace(run.relay);
            let before = store_files(&run.dump(tab).await?);
            let start = Instant::now();
            let report =
                tokio::time::timeout(Duration::from_secs(3), run.harness_run(&worker, request))
                    .await;
            run.sshd.present_other.store(false, Ordering::SeqCst);
            let seen = take(run.seen);
            case.check(
            &format!(
                "criterion 5: held {reason} answers at once with no retry, wait, intent or launch"
            ),
            report.as_ref().is_ok_and(|r| {
                r.as_ref().is_ok_and(|r| {
                    r["outcome"]["held"] == true
                        && r["outcome"]["calls"][0]["not_read"] == true
                        && (r["outcome"]["calls"][0]["why"]["unreachable"].is_object() || (reason == "lost-during-read" && r["outcome"]["calls"][0]["why"].is_string()))
                })
            }) && start.elapsed() < Duration::from_secs(3)
                && (seen.ssh_exec.is_empty() || (reason == "lost-during-read" && seen.ssh_exec.len() == 1 && job_cases::only_reads(&seen)))
                && seen.relay_accepted <= 1
                && store_files(&run.dump(tab).await?) == before,
        );
        }
        worker = restore(run, tab, worker, &original).await?;
        cases.push(case);
    }
    if selected("destructive") {
        let mut case = Case::new(
            "destructive replacement and an unnamed unresolved command both restrict dispatch (STA-24)",
        );
        let (new, a, _) = job_cases::drop_command(
            run,
            tab,
            worker,
            args("fixture"),
            "sleep 2; echo disposed-only",
        )
        .await?;
        worker = new;
        worker = settle_unresolved(run, tab, worker).await?;
        let (new, b, _) = job_cases::drop_command(
            run,
            tab,
            worker,
            args("fixture"),
            "sleep 2; echo holding-only",
        )
        .await?;
        worker = new;
        let files = store_files(&run.dump(tab).await?);
        let mut records = events(&files)?;
        let disposition = records.len();
        records.push(json!({"disposition":{"machine":"fixture","calls":[a],"continuation":"abandonment","uncertainty":"the command outcome is unknown"}}));
        worker = restore(run, tab, worker, &reader::build(PASSPHRASE, &records)).await?;
        take(run.seen);
        fresh_pace(run.relay);
        let before = run.inspect(&worker).await?;
        let report = run.harness_run(&worker, args("fixture")).await?;
        let seen = take(run.seen);
        case.check("criteria 1, 3, 5, 7: held answer reads only holding calls, carries finished evidence and standing destructive disposition, never dispatches afterwards",
        report["outcome"]["held"] == true && report["outcome"]["calls"].as_array().is_some_and(|r| r.len()==1 && r[0]["call"] == b && r[0]["state"] == "finished")
        && report["outcome"]["disposition"] == disposition && report["outcome"]["dispatch_still_restricted"] == true
        && seen.ssh_exec.len()==1 && job_cases::only_reads(&seen) && seen.relay_dials.len()==1
        && run.inspect(&worker).await?["commands"] == before["commands"]);
        fresh_pace(run.relay);
        let report = run.harness_collect(&worker, args("fixture")).await?;
        case.check("criteria 3, 4: collection is unheld under a destructive disposition and releasing hold leaves that restriction standing",
        report["outcome"]["collected"].as_array().is_some_and(|r|r.iter().any(|e|e["call"]==a))
        && run.harness_run(&worker,args("fixture")).await?["outcome"]["refused"] == "disposition");
        worker = restore(run, tab, worker, &original).await?;
        cases.push(case);
    }
    restore(run, tab, worker, &saved).await
}
