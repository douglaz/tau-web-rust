//! Deterministic lifecycle consumers through the production page and worker.
use super::*;
#[path = "lifecycle_repairs.rs"]
mod repairs;

async fn event(run: &Run<'_>, tab: &Tab, name: &str) -> Result<(), String> {
    run.browser
        .evaluate(
            &tab.session,
            &format!("document.dispatchEvent(new Event({}));true", json!(name)),
        )
        .await?;
    // A worker round trip orders the processed transition before the next operation.
    module(
        run,
        &run.live_workers(tab)[0],
        "await new Promise(r=>setTimeout(r,20));return true;",
    )
    .await?;
    Ok(())
}

async fn reset(run: &Run<'_>, tab: &Tab, worker: &mut Worker, saved: &Files) -> Result<(), String> {
    run.aggregator.state.lock().unwrap().hold_completion = false;
    run.aggregator.state.lock().unwrap().hold_revoke = false;
    *worker = run.reload(tab, worker).await?;
    run.put(tab, saved).await?;
    *worker = run.reload(tab, worker).await?;
    resume(run, tab, worker).await?;
    module(run, worker, "return await m.test_confirm_inference();").await?;
    Ok(())
}

pub(super) async fn run(
    run: &Run<'_>,
    tab: &mut Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    // Each phase owns an isolated truthful fixture journal. Predecessor phases deliberately
    // leave possibly-sent calls unresolved; those holds must not bar this phase's positives.
    let previous = store_files(&run.dump(tab).await?);
    let mnemonic = reader::read(&previous, PASSPHRASE)?.mnemonic()?;
    let mut events = vec![json!({"seed":{"mnemonic":mnemonic}})];
    events.extend(reader::setup_events(
        &mnemonic,
        &["fixture", "fixture-other", "unpinned"],
    ));
    for machine in ["fixture", "fixture-other", "unpinned"] {
        events.push(
            json!({"setup":{"class":{"machine":machine,"answer":"no","class":"single_purpose"}}}),
        );
    }
    events.push(json!({"inference_account":{"credential":run.aggregator.state.lock().unwrap().account.clone()}}));
    let saved = reader::build(PASSPHRASE, &events);
    locked_freeze(run, tab, worker, cases).await?;
    dedicated_approvals(run, tab, worker, &saved, cases).await?;
    aggregate_cap(run, tab, worker, &saved, cases).await?;
    unsent_mint(run, tab, worker, &saved, cases).await?;
    reset(run, tab, worker, &saved).await?;
    let mut case = Case::new(
        "hidden scheduled work retains original session limits and scan reference (CNF-7/69/82/95/102)",
    );
    let secret = "original-lifecycle-reference-123456";
    // The isolated machine owns these fixture bytes; the ordinary exec only reads them.
    let secret_path = run.sshd.machine.root.join("lifecycle-value");
    std::fs::write(&secret_path, secret).map_err(|e| e.to_string())?;
    let scan_id = module(
        run,
        worker,
        &format!(
            "return await m.test_scan_fixture('service access',new TextEncoder().encode({}));",
            json!(secret)
        ),
    )
    .await?;
    let session = run.inspect(worker).await?["sessions"][0]["identity"]
        .as_str()
        .ok_or("missing session")?
        .to_string();
    module(run,worker,&format!("return m.test_model_target({});",json!(json!({"machine":"fixture","relay":run.relay.url,"host":"127.0.0.1","port":run.sshd.port,"user":SSH_USER}).to_string()))).await?;
    module(
        run,
        worker,
        &format!(
            "await m.goal_request({});await m.goal_accept({});return true;",
            json!(
                json!({"session":session,"text":"Read the fixture output","document_source":null})
                    .to_string()
            ),
            json!(json!({"session":session}).to_string())
        ),
    )
    .await?;
    let initial = infer(run, worker).await?;
    case.check(
        "eligible initial inference establishes one original key",
        initial["finished"] == true,
    );
    let before = run.inspect(worker).await?;
    let blob_name = format!("scan-{}", scan_id.as_str().ok_or("scan identity")?);
    let blob = store_files(&run.dump(tab).await?)[&blob_name].clone();
    let mints = run.aggregator.count("/keys");
    let revokes = run.aggregator.count("/revoke");
    for iteration in 0..2 {
        let other = run
            .browser
            .call(None, "Target.createTarget", json!({"url":"about:blank"}))
            .await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        case.check(
            "actual page is hidden",
            run.browser
                .evaluate(&tab.session, "document.visibilityState")
                .await?
                == "hidden",
        );
        let reply = module(run,worker,&format!("return await new Promise(resolve=>setTimeout(async()=>resolve(JSON.parse(await m.inference_request({}))),30));", json!(json!({"machine":"fixture","messages":[{"role":"user","content":"scheduled fixture turn"}]}).to_string()))).await?;
        case.check(
            "scheduled model work completes hidden",
            reply["finished"] == true && reply.get("body").is_some(),
        );
        fresh_pace(run.relay);
        let output = module(run,worker,&format!("return JSON.parse(await m.test_model_tool({},{}));",json!(session),json!(json!({"name":"exec","arguments":{"machine":"fixture","command":format!("head -c 7 '{}'; tail -c +8 '{}'; cat '{}' >&2",secret_path.display(),secret_path.display(),secret_path.display())}}).to_string()))).await?;
        println!(
            "   actual tool stdout contains raw fixture secret: {}",
            output["stdout"]
                .as_str()
                .is_some_and(|s| s.contains(secret))
        );
        case.check(
            "real tool scan protects both stdout and stderr",
            output["stdout"] == "<redacted secret: service access>"
                && output["stderr"] == "<redacted secret: service access>"
                && !output.to_string().contains(secret),
        );
        let after = run.inspect(worker).await?;
        case.check(
            "same session, binding, context and original expiry",
            after["sessions"][0]["identity"] == before["sessions"][0]["identity"]
                && after["sessions"][0]["bound_set"] == before["sessions"][0]["bound_set"]
                && after["sessions"][0]["goal"] == before["sessions"][0]["goal"]
                && after["sessions"][0]["inference_limits"]["original_expiry"]
                    == before["sessions"][0]["inference_limits"]["original_expiry"],
        );
        case.check(
            "no replacement mint, revoke or encrypted scan write on hide",
            run.aggregator.count("/keys") == mints
                && run.aggregator.count("/revoke") == revokes
                && store_files(&run.dump(tab).await?)[&blob_name] == blob,
        );
        let original_limits = after["sessions"][0]["inference_limits"].clone();
        run.aggregator.state.lock().unwrap().credit_hundredths += 100;
        case.check("synthetic account credit neither changes the original tuple nor replenishes observed consumption",run.inspect(worker).await?["sessions"][0]["inference_limits"]==original_limits);
        if iteration == 0 {
            event(run, tab, "freeze").await?;
            case.check("actual page shows processed reconciliation while retaining Lock",run.browser.evaluate(&tab.session,"document.getElementById('tau-store-state').textContent.includes('reconciling') && !document.getElementById('tau-lock').hidden").await?==true);
            let withheld = infer(run, worker).await?;
            case.check(
                "processed freeze withholds ordinary work while retaining writer",
                withheld.get("refused").is_some() && run.live_workers(tab) == vec![worker.clone()],
            );
            let verified = module(
                run,
                worker,
                &format!(
                    "return JSON.parse(await m.verify_inference_clock({}));",
                    json!(session)
                ),
            )
            .await?;
            case.check("narrow authenticated time read succeeds hidden while ordinary authority is withheld",verified["finished"]==true && run.aggregator.count_method("GET","/time")>0);
            event(run, tab, "resume").await?;
            case.check(
                "hidden freeze return retains eligible key",
                infer(run, worker).await?["finished"] == true,
            );
            fresh_pace(run.relay);
            let output=run.harness_run(worker,json!({"machine":"fixture","relay":run.relay.url,"host":"127.0.0.1","port":run.sshd.port,"user":SSH_USER,"command":format!("cat '{}'",secret_path.display())})).await?;
            case.check(
                "same material scans actual normal dispatch after authenticated reload",
                output["outcome"]["stdout"] == "<redacted secret: service access>"
                    && output["outcome"]["job_record"]["record"]["stdout"]
                        == hex::encode("<redacted secret: service access>"),
            );
        }
        run.browser
            .call(
                None,
                "Target.activateTarget",
                json!({"targetId":tab.target}),
            )
            .await?;
        run.browser
            .call(
                None,
                "Target.closeTarget",
                json!({"targetId":other["targetId"]}),
            )
            .await?;
    }
    let (second_tab, second_worker) = run.open(&tab.origin, true).await?;
    case.check(
        "second page waits in-use without taking over hidden writer",
        run.inspect(&second_worker).await?["state"] == "unopened"
            && run.live_workers(tab) == vec![worker.clone()],
    );
    if run.inspect(&second_worker).await?["state"] == "locked" {
        let result = module(
            run,
            &second_worker,
            &format!(
                "return JSON.parse(await m.unlock(new TextEncoder().encode({})));",
                json!(PASSPHRASE)
            ),
        )
        .await?;
        case.check(
            "a second instance cannot unwrap the store while the original writer can act",
            result["state"] != "unlocked",
        );
    }
    run.browser
        .call(
            None,
            "Target.closeTarget",
            json!({"targetId":second_tab.target}),
        )
        .await?;
    run.browser
        .call(
            None,
            "Target.activateTarget",
            json!({"targetId":tab.target}),
        )
        .await?;
    let completions_before_missing = run.aggregator.count("/completion");
    let missing = module(run,worker,"await m.test_scan_reload(true);return JSON.parse(await m.inference_request(JSON.stringify({machine:'fixture',messages:[{role:'user',content:'safe'}]})));").await?;
    println!(
        "   actual missing-reference completion counts: {completions_before_missing} -> {}",
        run.aggregator.count("/completion")
    );
    case.check(
        "working copy loss withholds output rather than arming empty set",
        missing.get("refused").is_some()
            && run.aggregator.count("/completion") == completions_before_missing,
    );
    case.check(
        "read-only reload restores the original reference",
        module(run, worker, "return await m.test_scan_reload(false);").await? == true
            && store_files(&run.dump(tab).await?)[&blob_name] == blob,
    );
    let other = run
        .browser
        .call(None, "Target.createTarget", json!({"url":"about:blank"}))
        .await?;
    let command = format!("sleep 2; cat '{}'", secret_path.display());
    fresh_pace(run.relay);
    let request = json!({"machine":"fixture","relay":run.relay.url,"host":"127.0.0.1","port":run.sshd.port,"user":SSH_USER,"command":command});
    module(
        run,
        worker,
        &format!(
            "self.interruptedJob=m.run_command({});return true;",
            json!(request.to_string())
        ),
    )
    .await?;
    case.check(
        "independent machine observes the original detached job before processed freeze",
        settle_for(run.seen, 5, |_| {
            run.sshd
                .machine
                .launches()
                .iter()
                .any(|(_, job)| job.command == command.as_bytes())
        })
        .await,
    );
    event(run, tab, "freeze").await?;
    let interrupted = module(run, worker, "return JSON.parse(await self.interruptedJob);").await?;
    case.check(
        "possibly sent job remains unresolved without a replacement launch",
        interrupted["outcome"]["unresolved"] == true,
    );
    let original_call = interrupted["outcome"]["call"].clone();
    module(
        run,
        worker,
        &format!(
            "return JSON.parse(await m.verify_inference_clock({}));",
            json!(session)
        ),
    )
    .await?;
    run.browser
        .call(
            None,
            "Target.activateTarget",
            json!({"targetId":tab.target}),
        )
        .await?;
    run.browser
        .call(
            None,
            "Target.closeTarget",
            json!({"targetId":other["targetId"]}),
        )
        .await?;
    event(run, tab, "resume").await?;
    fresh_pace(run.relay);
    let collected = module(
        run,
        worker,
        &format!(
            "return JSON.parse(await m.collect_jobs({}));",
            json!(request.to_string())
        ),
    )
    .await?;
    let records = collected["outcome"]["collected"]
        .as_array()
        .ok_or("missing collection")?;
    let record = records
        .iter()
        .find(|r| r["call"] == original_call)
        .ok_or_else(|| format!("original lifecycle job {original_call} not collected: interrupted={interrupted}; collection={collected}"))?;
    println!("   collected original lifecycle job: {record}");
    case.check(
        "hidden freeze to visible return collects original job and scans both nested copies",
        record["stdout"] == "<redacted secret: service access>"
            && record["record"]["stdout"] == hex::encode("<redacted secret: service access>")
            && record["state"] == "finished",
    );
    case.check(
        "collection does not replay the mutation",
        run.sshd
            .machine
            .launches()
            .iter()
            .filter(|(_, j)| j.command == command.as_bytes())
            .count()
            == 1,
    );
    let original_job = record["job"].as_str().ok_or("job identity")?;
    case.check(
        "machine output artifact retains original bytes outside browser scanning",
        std::fs::read(run.sshd.machine.path(original_job, "stdout")).map_err(|e| e.to_string())?
            == secret.as_bytes(),
    );
    cases.push(case);

    expiry_case(run, tab, worker, &saved, cases).await?;

    reset(run, tab, worker, &saved).await?;
    let mut case = Case::new(
        "page-started goal keeps scheduled hidden context and scans actual model input (CNF-82/95/102)",
    );
    let session = run.inspect(worker).await?["sessions"][0]["identity"]
        .as_str()
        .ok_or("session")?
        .to_string();
    module(run,worker,&format!("await m.test_scan_fixture('service access',new TextEncoder().encode({}));return m.test_model_target({});",json!(secret),json!(json!({"machine":"fixture","relay":run.relay.url,"host":"127.0.0.1","port":run.sshd.port,"user":SSH_USER}).to_string()))).await?;
    run.browser.evaluate(&tab.session,&format!("(()=>{{const card=document.querySelector('[data-goal-card=\"{}\"]');card.querySelector('[data-goal-text]').value='Read the fixture service output';card.querySelector('[data-goal-enter]').click();return true;}})()",session)).await?;
    for _ in 0..100 {
        if run.inspect(worker).await?["goals"]
            .as_array()
            .is_some_and(|g| !g.is_empty())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let command = format!("cat '{}'", secret_path.display());
    run.aggregator.state.lock().unwrap().script = vec![
        json!({"name":"exec","arguments":{"machine":"fixture","command":command}}),
        json!({"name":"done","arguments":{"machine":"fixture"}}),
    ]
    .into();
    module(run,worker,"self.hiddenGoalReady=new Promise(ready=>m.test_hold_session_point('goal_turn',new Promise(release=>self.releaseHiddenGoal=release),ready));return true;").await?;
    setup_cases::click(run, tab, &format!("[data-goal-accept='{session}']")).await?;
    module(run, worker, "await self.hiddenGoalReady;return true;").await?;
    let from = run.aggregator.requests.lock().unwrap().len();
    let other = run
        .browser
        .call(None, "Target.createTarget", json!({"url":"about:blank"}))
        .await?;
    event(run, tab, "freeze").await?;
    event(run, tab, "resume").await?;
    module(
        run,
        worker,
        &format!(
            "return JSON.parse(await m.verify_inference_clock({}));",
            json!(session)
        ),
    )
    .await?;
    fresh_pace(run.relay);
    module(run, worker, "self.releaseHiddenGoal();return true;").await?;
    let mut done = false;
    for _ in 0..300 {
        done=run.browser.evaluate(&tab.session,&format!("document.querySelector('[data-goal-outcome=\"{}\"]')?.textContent.includes('done')??false",session)).await?==true;
        if done {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    case.check(
        "real page-to-worker goal loop reaches done while hidden without new consent",
        done && run
            .browser
            .evaluate(&tab.session, "document.visibilityState")
            .await?
            == "hidden",
    );
    let bodies: Vec<Value> = run
        .aggregator
        .requests
        .lock()
        .unwrap()
        .iter()
        .skip(from)
        .filter(|r| r.starts_with(b"POST /completion "))
        .filter_map(|r| request_body(r))
        .collect();
    println!(
        "   actual next request contains raw fixture secret: {}",
        bodies
            .get(1)
            .is_some_and(|b| b.to_string().contains(secret))
    );
    case.check(
        "actual next model input contains the named marker and no exact value",
        bodies.len() == 2
            && bodies[1]
                .to_string()
                .contains("<redacted secret: service access>")
            && !bodies[1].to_string().contains(secret),
    );
    let posted = run
        .browser
        .evaluate(
            &tab.session,
            "document.getElementById('tau-setup').textContent",
        )
        .await?;
    case.check(
        "page publication retains the safe final outcome",
        posted
            .as_str()
            .is_some_and(|s| s.contains("Goal loop ended: done.") && !s.contains(secret)),
    );
    run.browser
        .call(
            None,
            "Target.activateTarget",
            json!({"targetId":tab.target}),
        )
        .await?;
    run.browser
        .call(
            None,
            "Target.closeTarget",
            json!({"targetId":other["targetId"]}),
        )
        .await?;
    cases.push(case);

    for begun in [false, true] {
        reset(run, tab, worker, &saved).await?;
        infer(run, worker).await?;
        let mut case = Case::new(if begun {
            "freeze finishes a begun command append whole and fences its send (CNF-29/40/82)"
        } else {
            "freeze refuses a queued command append before it begins (CNF-29/40/82)"
        });
        let before = run.inspect(worker).await?;
        let request = json!({"machine":"fixture","relay":run.relay.url,"host":"127.0.0.1","port":run.sshd.port,"user":SSH_USER,"command":"printf lifecycle-append"});
        if begun {
            module(run,worker,"self.appendReady=new Promise(ready=>m.test_hold_move(new Promise(release=>self.releaseAppend=release),ready));return true;").await?;
        } else {
            module(run,worker,"self.appendReady=new Promise(ready=>m.test_hold_session_point('command_writer',new Promise(release=>self.releaseAppend=release),ready));return true;").await?;
        }
        fresh_pace(run.relay);
        let execs = run.seen.lock().unwrap().ssh_exec.len();
        module(
            run,
            worker,
            &format!(
                "self.appendOperation=m.run_command({});return true;",
                json!(request.to_string())
            ),
        )
        .await?;
        module(run, worker, "await self.appendReady;return true;").await?;
        if !begun {
            module(run,worker,"self.writerReady=new Promise(ready=>self.queuedWriter=m.test_writer(new Promise(release=>self.releaseQueuedWriter=release),ready));await self.writerReady;self.releaseAppend();await new Promise(r=>setTimeout(r,0));return true;").await?;
        }
        event(run, tab, "freeze").await?;
        if begun {
            module(run, worker, "self.releaseAppend();return true;").await?;
        } else {
            module(
                run,
                worker,
                "self.releaseQueuedWriter();await self.queuedWriter;return true;",
            )
            .await?;
        }
        let result = module(
            run,
            worker,
            "return JSON.parse(await self.appendOperation);",
        )
        .await?;
        case.check(
            "no command exec crosses the processed freeze",
            run.seen.lock().unwrap().ssh_exec.len() == execs
                && result["outcome"].get("done").is_none(),
        );
        event(run, tab, "resume").await?;
        let after = run.inspect(worker).await?;
        case.check(
            "only an already begun durable append can add its original intent",
            after["commands"].as_array().unwrap().len()
                == before["commands"].as_array().unwrap().len() + usize::from(begun),
        );
        if begun {
            case.check(
                "committed original command remains unresolved",
                after["calls"].as_array().unwrap().last().is_some_and(|c| {
                    c["state"] == "unresolved" && c["call"] == result["outcome"]["call"]
                }),
            );
        }
        cases.push(case);
    }

    boundaries(run, tab, worker, &saved, cases).await?;
    if std::env::var("TAU_TRACER_INFERENCE_PHASE").as_deref() != Ok("lifecycle-core") {
        repairs::run(run, tab, worker, &saved, cases).await?;
    }
    Ok(())
}

async fn boundaries(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    reset(run, tab, worker, saved).await?;
    let mut case = Case::new(
        "freeze fences stale model and publication results without replacing their intent (CNF-29/69/82/102)",
    );
    infer(run, worker).await?;
    run.aggregator.state.lock().unwrap().hold_completion = true;
    let completions = run.aggregator.count("/completion");
    module(run,worker,"self.pendingLifecycle=m.inference_request(JSON.stringify({machine:'fixture',messages:[{role:'user',content:'late fixture turn'}]}));self.oldGeneration=m.publication_generation();return true;").await?;
    wait_count(run, "/completion", completions + 1).await?;
    event(run, tab, "freeze").await?;
    let result = module(
        run,
        worker,
        "return JSON.parse(await self.pendingLifecycle);",
    )
    .await?;
    case.check(
        "possibly sent completion remains unresolved and supplies no actionable body",
        result["unresolved"] == true && result.get("body").is_none(),
    );
    run.aggregator.state.lock().unwrap().hold_completion = false;
    event(run, tab, "resume").await?;
    let session = run.inspect(worker).await?["sessions"][0]["identity"]
        .as_str()
        .ok_or("session")?
        .to_string();
    println!(
        "   actual completion count before clock repair: {} (expected {})",
        run.aggregator.count("/completion"),
        completions + 1
    );
    let uncertain = infer(run, worker).await?;
    println!(
        "   actual uncertain-clock completion count after attempted ordinary send: {} (expected {})",
        run.aggregator.count("/completion"),
        completions + 1
    );
    case.check(
        "clock remains withheld until justified observation",
        uncertain.get("refused").is_some()
            && run.aggregator.count("/completion") == completions + 1,
    );
    module(
        run,
        worker,
        &format!(
            "return JSON.parse(await m.verify_inference_clock({}));",
            json!(session)
        ),
    )
    .await?;
    let stale=module(run,worker,&format!("return JSON.parse(await m.protect_publication(self.oldGeneration,{},JSON.stringify({{state:'unlocked',goal_outcome:{{done:true}}}})));",json!(session))).await?;
    case.check(
        "an old scanned publication cannot become actionable after repair",
        stale["state"] == "unlocked"
            && stale.get("goal_outcome").is_none()
            && stale.get("error").is_some(),
    );
    module(run,worker,&format!("const current=JSON.parse(await m.open());current.goal_outcome={{session:{},outcome:{{done:true}}}};await m.publish_report(self.oldGeneration,{},JSON.stringify(current));return true;",json!(session),json!(session))).await?;
    case.check("actual posted store message cannot render a stale done result",!run.browser.evaluate(&tab.session,"document.getElementById('tau-setup').textContent.includes('Goal loop ended: done.')").await?.as_bool().unwrap_or(true));
    case.check(
        "next eligible inference uses the original key without retrying lost request",
        infer(run, worker).await?["finished"] == true
            && run.aggregator.count("/completion") == completions + 2,
    );
    cases.push(case);
    for frozen in [false, true] {
        reset(run, tab, worker, saved).await?;
        infer(run, worker).await?;
        let mut case = Case::new(if frozen {
            "actual transport rechecks authority after a queued send boundary (CNF-69/82)"
        } else {
            "actual transport allows the nearest eligible queued send (CNF-69/82)"
        });
        module(run,worker,"self.sendReady=new Promise(ready=>m.test_hold_session_point('transport_send',new Promise(release=>self.releaseSend=release),ready));self.sendResult=m.inference_request(JSON.stringify({machine:'fixture',messages:[{role:'user',content:'original queued operation'}]}));await self.sendReady;return true;").await?;
        let before = run.aggregator.count("/completion");
        if frozen {
            event(run, tab, "freeze").await?;
        }
        module(run, worker, "self.releaseSend();return true;").await?;
        let result = module(run, worker, "return JSON.parse(await self.sendResult);").await?;
        if frozen {
            println!(
                "   actual processed-freeze completion counts: {before} -> {}",
                run.aggregator.count("/completion")
            );
            case.check(
                "processed suspension sends no completion at the actual fetch boundary",
                run.aggregator.count("/completion") == before
                    && result["unresolved"] == true
                    && result.get("body").is_none(),
            );
        } else {
            case.check(
                "eligible original request actually reaches the fixture and returns its body",
                run.aggregator.count("/completion") == before + 1
                    && result["finished"] == true
                    && result.get("body").is_some(),
            );
        }
        cases.push(case);
    }
    reset(run, tab, worker, saved).await?;
    infer(run, worker).await?;
    let mut case = Case::new(
        "actual transport refuses carried bytes introduced after request protection (CNF-69/95)",
    );
    let before = run.aggregator.count("/completion");
    module(
        run,
        worker,
        "m.test_transport_append('post-scan-carried-fixture-bytes');return true;",
    )
    .await?;
    let result = infer(run, worker).await?;
    println!(
        "   actual changed-body completion counts: {before} -> {}; carried marker at endpoint: {}",
        run.aggregator.count("/completion"),
        run.aggregator.requests.lock().unwrap().iter().any(|r| r
            .windows(b"post-scan-carried-fixture-bytes".len())
            .any(|w| w == b"post-scan-carried-fixture-bytes"))
    );
    case.check(
        "changed actual request bytes reach no completion endpoint",
        result["unresolved"] == true
            && run.aggregator.count("/completion") == before
            && !run.aggregator.requests.lock().unwrap().iter().any(|r| {
                r.windows(b"post-scan-carried-fixture-bytes".len())
                    .any(|w| w == b"post-scan-carried-fixture-bytes")
            }),
    );
    cases.push(case);
    reset(run, tab, worker, saved).await?;
    reference_revision(run, tab, worker, saved, cases).await?;
    Ok(())
}

async fn dedicated(
    run: &Run<'_>,
    worker: &Worker,
    action: &str,
    value: Value,
) -> Result<Value, String> {
    module(
        run,
        worker,
        &format!(
            "return JSON.parse(await m.test_reinstall({},{}));",
            json!(action),
            json!(value.to_string())
        ),
    )
    .await
}
async fn dedicated_approvals(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    reset(run, tab, worker, saved).await?;
    let mut case = Case::new(
        "dedicated standing approvals survive hide with original prerequisites and independent withdrawal (CNF-86)",
    );
    let a = dedicated(run, worker, "approve", json!({"reset":"synthetic-reset-a"})).await?;
    let b = dedicated(run, worker, "approve", json!({"reset":"synthetic-reset-b"})).await?;
    let mut aa = json!({"approval":a["approval"],"reset":"synthetic-reset-a","read":0});
    case.check(
        "no activation/read is supplied by hide",
        dedicated(run, worker, "dispatch", aa.clone())
            .await?
            .get("refused")
            .is_some(),
    );
    visibility(run, tab, "hidden").await?;
    let before = run.inspect(worker).await?["reinstall_approvals"].clone();
    case.check(
        "independent original approvals remain standing hidden",
        before
            .as_array()
            .is_some_and(|a| a.len() == 2 && a.iter().all(|a| a["state"] == "standing")),
    );
    let activation = dedicated(run, worker, "activate", json!({})).await?;
    let no = dedicated(
        run,
        worker,
        "read",
        json!({"activation":activation["activation"],"confirmed":false}),
    )
    .await?;
    aa["read"] = no["read"].clone();
    case.check(
        "non-confirming durable read refuses unseen reset",
        dedicated(run, worker, "dispatch", aa.clone())
            .await?
            .get("refused")
            .is_some(),
    );
    module(run,worker,"const v=await m.open();await m.publish_report(m.publication_generation(),'',v);return true;").await?;
    visibility(run, tab, "visible").await?;
    let selector = format!("[data-withdraw-reinstall='{}']", b["approval"]);
    setup_cases::click(run, tab, &selector).await?;
    module(
        run,
        worker,
        "await new Promise(r=>setTimeout(r,50));return true;",
    )
    .await?;
    let view = run.inspect(worker).await?["reinstall_approvals"].clone();
    case.check(
        "actual page withdrawal names only its approval",
        view[0]["state"] == "standing" && view[1]["state"] == "withdrawn",
    );
    visibility(run, tab, "hidden").await?;
    let yes = dedicated(
        run,
        worker,
        "read",
        json!({"activation":activation["activation"],"confirmed":true}),
    )
    .await?;
    aa["read"] = yes["read"].clone();
    let dispatched = dedicated(run, worker, "dispatch", aa).await?;
    case.check(
        "eligible original separately approved reset dispatches hidden",
        dispatched["dispatched"] == true
            && run.inspect(worker).await?["reinstall_approvals"][0]["state"] == "dispatched",
    );
    let history = reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
    case.check(
        "independent journal reader sees original approval and actual reset boundary",
        history.records.iter().any(|(_, bytes)| {
            serde_json::from_slice::<Value>(bytes)
                .ok()
                .is_some_and(|e| {
                    e.pointer("/dedicated_reinstall/dispatch/reset")
                        == Some(&json!("synthetic-reset-a"))
                })
        }),
    );
    cases.push(case);

    for how in ["Lock", "worker restart"] {
        reset(run, tab, worker, saved).await?;
        let mut case = Case::new(&format!(
            "dedicated {how} ends old approval; a separately admitted successor alone can reset (CNF-86)"
        ));
        let a = dedicated(run, worker, "approve", json!({"reset":"ended-reset"})).await?;
        if how == "Lock" {
            setup_cases::click(run, tab, "#tau-lock").await?;
            *worker = run.worker(tab, Some(worker), false).await?;
        } else {
            *worker = run.reload(tab, worker).await?;
        }
        resume(run, tab, worker).await?;
        let view = run.inspect(worker).await?["reinstall_approvals"].clone();
        case.check(
            "actual successor shows no longer usable with no withdrawal offer",
            view[0]["state"] == "no longer usable"
                && view[0]["withdrawal_offer"] == false
                && run
                    .browser
                    .evaluate(
                        &tab.session,
                        &format!(
                            "document.querySelector('[data-withdraw-reinstall=\"{}\"]')===null",
                            a["approval"]
                        ),
                    )
                    .await?
                    == true,
        );
        // Explicitly admit a different approval. This prevents absent adapter admission or a
        // missing activation/read from masking failure of the original rendering-session fence.
        let new_reset = format!("successor-reset-{how}");
        let new = dedicated(run, worker, "approve", json!({"reset":new_reset})).await?;
        let activation = dedicated(run, worker, "activate", json!({})).await?;
        let read = dedicated(
            run,
            worker,
            "read",
            json!({"activation":activation["activation"],"confirmed":true}),
        )
        .await?;
        let old = dedicated(
            run,
            worker,
            "dispatch",
            json!({"approval":a["approval"],"reset":"ended-reset","read":read["read"]}),
        )
        .await?;
        case.check("old rendering-session approval cannot dispatch despite otherwise valid current prerequisites",old.get("refused").is_some());
        let new = dedicated(
            run,
            worker,
            "dispatch",
            json!({"approval":new["approval"],"reset":new_reset,"read":read["read"]}),
        )
        .await?;
        case.check(
            "only new separately admitted approval dispatches under its newer confirmed activation",
            new["dispatched"] == true
                && run.inspect(worker).await?["reinstall_approvals"][0]["state"]
                    == "no longer usable",
        );
        reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
        cases.push(case);
    }
    Ok(())
}

async fn visibility(run: &Run<'_>, tab: &Tab, state: &str) -> Result<(), String> {
    if state == "hidden" {
        run.browser
            .call(None, "Target.createTarget", json!({"url":"about:blank"}))
            .await?;
    } else {
        run.browser
            .call(
                None,
                "Target.activateTarget",
                json!({"targetId":tab.target}),
            )
            .await?;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    if run
        .browser
        .evaluate(&tab.session, "document.visibilityState")
        .await?
        != state
    {
        return Err("fixture page visibility did not change".into());
    }
    Ok(())
}

async fn aggregate_cap(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    reset(run, tab, worker, saved).await?;
    let mut case = Case::new(
        "original fixture aggregate cap includes an in-flight lost reply and never renews (CNF-69/82)",
    );
    infer(run, worker).await?;
    let mints = run.aggregator.count("/keys");
    let before = run.aggregator.count("/completion");
    // The first settled charge was 0.01; admit a second charge and hold its reply in flight.
    run.aggregator.state.lock().unwrap().hold_completion = true;
    module(run,worker,"self.capInFlight=m.inference_request(JSON.stringify({machine:'fixture',messages:[{role:'user',content:'in flight charge'}]}));return true;").await?;
    wait_count(run, "/completion", before + 1).await?;
    for _ in 0..8 {
        case.check(
            "remaining eligible charge uses the same original key",
            infer(run, worker).await?["finished"] == true,
        );
    }
    let before_refusal = run.aggregator.count("/completion");
    let refusal = infer(run, worker).await?;
    let view = run.inspect(worker).await?;
    let session = view["sessions"][0]["identity"]
        .as_str()
        .ok_or("session")?
        .to_owned();
    let (key_id, cap, spent) = {
        let state = run.aggregator.state.lock().unwrap();
        let key = state.keys.last().unwrap();
        (key.id.clone(), key.cap, key.spent)
    };
    case.check(
        "issuer total includes the in-flight charge at the hard original aggregate cap",
        cap == Some(10)
            && spent == 10
            && before_refusal == before + 9
            && run.aggregator.count("/completion") == before_refusal + 1
            && refusal.get("body").is_none(),
    );
    case.check(
        "lost reply remains unaccounted and evidenced key exhaustion ends only its session",
        view["sessions"][0]["unaccounted_spend"]["count"]
            .as_u64()
            .is_some_and(|n| n >= 1)
            && view["sessions"][0]["session_state"] == "ended"
            && view["sessions"][1]["session_state"] == "running",
    );
    run.aggregator.state.lock().unwrap().credit_hundredths += 100;
    let _ = module(
        run,
        worker,
        &format!(
            "return JSON.parse(await m.verify_inference_clock({}));",
            json!(session)
        ),
    )
    .await?;
    let _ = infer(run, worker).await?;
    case.check(
        "credit or clock repair supplies no replacement attempt or refunded cap",
        run.aggregator.count("/keys") == mints
            && run.aggregator.count("/completion") == before_refusal + 1
            && run
                .aggregator
                .state
                .lock()
                .unwrap()
                .keys
                .iter()
                .find(|k| k.id == key_id)
                .is_some_and(|k| k.spent == 10),
    );
    cases.push(case);
    Ok(())
}

async fn expiry_case(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    reset(run, tab, worker, saved).await?;
    let mut case = Case::new(
        "original expiry equality fences actual hidden sends and cannot be renewed by credit (CNF-69/82)",
    );
    infer(run, worker).await?;
    let state = run.inspect(worker).await?;
    let mint = state["inference_calls"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|c| c["kind"] == "mint")
        .ok_or("mint")?;
    let bounds = &mint["intent"]["mint"];
    let clock = &bounds["evidence"]["clock"];
    let expires = bounds["expires"].as_u64().ok_or("expiry")?;
    let delta = expires
        .checked_sub(clock["latest"].as_u64().ok_or("issuer anchor")?)
        .ok_or("expiry before anchor")?;
    let base_m = clock["sent"]["monotonic"]
        .as_u64()
        .ok_or("monotonic anchor")?;
    let base_w = clock["sent"]["wall"].as_u64().ok_or("wall anchor")?;
    let other = run
        .browser
        .call(None, "Target.createTarget", json!({"url":"about:blank"}))
        .await?;
    module(
        run,
        worker,
        &format!(
            "return m.test_clock_sample({},{});",
            json!((base_m + (delta - 1) * 1_000_000).to_string()),
            json!((base_w + (delta - 1) * 1_000_000).to_string())
        ),
    )
    .await?;
    case.check(
        "nearest current upper bound below expiry still sends hidden",
        infer(run, worker).await?["finished"] == true,
    );
    let completions = run.aggregator.count("/completion");
    let mints = run.aggregator.count("/keys");
    module(
        run,
        worker,
        &format!(
            "return m.test_clock_sample({},{});",
            json!((base_m + delta * 1_000_000).to_string()),
            json!((base_w + delta * 1_000_000).to_string())
        ),
    )
    .await?;
    let expired = infer(run, worker).await?;
    println!(
        "   actual expiry-equality completion counts: {completions} -> {}",
        run.aggregator.count("/completion")
    );
    case.check(
        "expiry equality refuses before actual next completion or replacement mint",
        expired.get("refused").is_some()
            && run.aggregator.count("/completion") == completions
            && run.aggregator.count("/keys") == mints,
    );
    run.aggregator.state.lock().unwrap().credit_hundredths += 100;
    module(run, worker, "m.test_clock_sample('','');return true;").await?;
    case.check(
        "clock refresh and synthetic credit cannot revive the ended session",
        infer(run, worker).await?.get("refused").is_some()
            && run.aggregator.count("/keys") == mints,
    );
    run.browser
        .call(
            None,
            "Target.activateTarget",
            json!({"targetId":tab.target}),
        )
        .await?;
    run.browser
        .call(
            None,
            "Target.closeTarget",
            json!({"targetId":other["targetId"]}),
        )
        .await?;
    cases.push(case);

    Ok(())
}

pub(super) async fn selected(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
    expiry: bool,
) -> Result<(), String> {
    let saved = store_files(&run.dump(tab).await?);
    if expiry {
        expiry_case(run, tab, worker, &saved, cases).await
    } else {
        boundaries(run, tab, worker, &saved, cases).await
    }
}

async fn reference_revision(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    reset(run, tab, worker, saved).await?;
    infer(run, worker).await?;
    let mut case = Case::new(
        "actual send rejects a reference revision changed after earlier request protection (CNF-95)",
    );
    let secret = "later-armed-fixture-value-123456";
    module(run,worker,&format!("self.referenceReady=new Promise(ready=>m.test_hold_session_point('transport_send',new Promise(release=>self.releaseReferenceSend=release),ready));self.referenceSend=m.inference_request(JSON.stringify({{machine:'fixture',messages:[{{role:'user',content:{}}}]}}));await self.referenceReady;return true;",json!(secret))).await?;
    module(
        run,
        worker,
        &format!(
            "return await m.test_scan_fixture('later service',new TextEncoder().encode({}));",
            json!(secret)
        ),
    )
    .await?;
    let before = run.aggregator.count("/completion");
    module(run, worker, "self.releaseReferenceSend();return true;").await?;
    let result = module(run, worker, "return JSON.parse(await self.referenceSend);").await?;
    let leaked = run
        .aggregator
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r.windows(secret.len()).any(|w| w == secret.as_bytes()));
    println!(
        "   actual changed-reference completion counts: {before} -> {}; raw fixture value at endpoint: {leaked}",
        run.aggregator.count("/completion")
    );
    case.check(
        "changed reference revision sends no old scanned bytes",
        run.aggregator.count("/completion") == before && !leaked && result["unresolved"] == true,
    );
    let eligible=module(run,worker,&format!("return JSON.parse(await m.inference_request(JSON.stringify({{machine:'fixture',messages:[{{role:'user',content:{}}}]}})));",json!(secret))).await?;
    let bodies = run
        .aggregator
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter_map(|r| request_body(r))
        .collect::<Vec<_>>();
    case.check(
        "nearest fresh operation scans the same actual value with the now-armed reference",
        eligible["finished"] == true
            && run.aggregator.count("/completion") == before + 1
            && bodies
                .iter()
                .any(|b| b.to_string().contains("<redacted secret: later service>")),
    );
    cases.push(case);
    reset(run, tab, worker, saved).await?;
    Ok(())
}

async fn unsent_mint(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    reset(run, tab, worker, saved).await?;
    let mut case = Case::new(
        "never-transmitted original mint continues unchanged once after real clock repair (CNF-69/82)",
    );
    let mints = run.aggregator.count("/keys");
    module(run,worker,"self.mintReady=new Promise(ready=>m.test_hold_session_point('mint_intent',new Promise(release=>self.releaseMintIntent=release),ready));self.unsentMint=m.inference_request(JSON.stringify({machine:'fixture',messages:[{role:'user',content:'original mint attempt'}]}));return true;").await?;
    module(run, worker, "await self.mintReady;return true;").await?;
    event(run, tab, "freeze").await?;
    module(
        run,
        worker,
        "self.releaseMintIntent();await self.unsentMint;return true;",
    )
    .await?;
    event(run, tab, "resume").await?;
    let state = run.inspect(worker).await?;
    let original = state["inference_calls"]
        .as_array()
        .ok_or("calls")?
        .iter()
        .rev()
        .find(|c| c["kind"] == "mint")
        .ok_or("original mint")?
        .clone();
    let call = original["call"].as_u64().ok_or("call")?;
    let session = original["intent"]["mint"]["session"]
        .as_str()
        .ok_or("session")?
        .to_owned();
    let refused = module(
        run,
        worker,
        &format!("return JSON.parse(await m.continue_inference(BigInt({call})));"),
    )
    .await?;
    case.check("processed freeze retained one durable never-sent mint and uncertain clock refuses its send",original["state"]=="unresolved"&&run.aggregator.count("/keys")==mints&&refused.get("refused").is_some());
    let verified = module(
        run,
        worker,
        &format!(
            "return JSON.parse(await m.verify_inference_clock({}));",
            json!(session)
        ),
    )
    .await?;
    case.check(
        "actual narrow time exchange repairs the same non-ended session",
        verified["finished"] == true,
    );
    let continued = module(
        run,
        worker,
        &format!("return JSON.parse(await m.continue_inference(BigInt({call})));"),
    )
    .await?;
    let state = run.inspect(worker).await?;
    let calls = state["inference_calls"].as_array().ok_or("calls")?;
    case.check(
        "actual original mint is sent once without another intent or changed origin/expiry/cap",
        continued["finished"] == true
            && continued.get("refused").is_none()
            && run.aggregator.count("/keys") == mints + 1
            && calls
                .iter()
                .filter(|c| c["kind"] == "mint" && c["intent"]["mint"]["session"] == session)
                .count()
                == 1
            && calls
                .iter()
                .find(|c| c["call"] == call)
                .is_some_and(|c| c["intent"] == original["intent"]),
    );
    let again = module(
        run,
        worker,
        &format!("return JSON.parse(await m.continue_inference(BigInt({call})));"),
    )
    .await?;
    case.check(
        "transmitted original cannot be retried and next ordinary completion keeps its key",
        again.get("refused").is_some()
            && infer(run, worker).await?["finished"] == true
            && run.aggregator.count("/keys") == mints + 1,
    );
    reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
    cases.push(case);
    Ok(())
}

pub(super) async fn locked_freeze(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    *worker = run.reload(tab, worker).await?;
    let mut case = Case::new(
        "processed freeze and return preserve a locked store and allow later explicit unlock (CNF-7/82)",
    );
    event(run, tab, "freeze").await?;
    case.check("actual frozen page still says locked and offers only explicit unlock",run.inspect(worker).await?["state"]=="locked"&&run.browser.evaluate(&tab.session,"document.getElementById('tau-store').dataset.state==='locked' && !document.getElementById('tau-unlock').hidden && document.getElementById('tau-lock').hidden").await?==true);
    event(run, tab, "resume").await?;
    case.check(
        "actual return does not unwrap or invent unlocked authority",
        run.inspect(worker).await?["state"] == "locked",
    );
    resume(run, tab, worker).await?;
    let view = run.inspect(worker).await?;
    case.check(
        "subsequent explicit unlock and admission use the retained worker normally",
        view["state"] == "unlocked"
            && view["lifecycle_state"] != "reconciling"
            && view["sessions"].as_array().is_some_and(|s| !s.is_empty()),
    );
    cases.push(case);
    Ok(())
}

pub(super) async fn repair_cases(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let saved = store_files(&run.dump(tab).await?);
    repairs::run(run, tab, worker, &saved, cases).await
}
