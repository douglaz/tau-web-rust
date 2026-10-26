#[path = "session_end_cases.rs"]
mod session_end_cases;
// Browser evidence uses real fetch against the loopback fixture, then searches its key needles.
use super::*;
use std::sync::Arc;
use tau_web::jobs;

pub(super) async fn module(
    run: &Run<'_>,
    worker: &Worker,
    expression: &str,
) -> Result<Value, String> {
    run.browser.evaluate(&worker.session,&format!("(async()=>{{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);{expression}}})()")).await
}
async fn origin(run: &Run<'_>, worker: &Worker) -> Result<(), String> {
    if module(
        run,
        worker,
        &format!(
            "return await m.test_inference_origin({});",
            json!(run.aggregator.origin)
        ),
    )
    .await?
        != true
    {
        return Err("fixture origin was not set before unlock".into());
    }
    Ok(())
}
async fn infer(run: &Run<'_>, worker: &Worker) -> Result<Value, String> {
    module(run,worker,&format!("return JSON.parse(await m.inference_request({}));",json!(json!({"machine":"fixture","messages":[{"role":"user","content":"browser prompt never journaled"}]}).to_string()))).await
}
async fn resume(run: &Run<'_>, tab: &Tab, worker: &mut Worker) -> Result<(), String> {
    origin(run, worker).await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    let state = run.inspect(worker).await?;
    if state["seed_backup_stage"] != "inactive" {
        setup_cases::click(run, tab, "#tau-seed-backup-skip").await?;
    }
    binding_cases::prepare(run, tab, worker, PASSPHRASE).await
}
fn last_key(run: &Run<'_>) -> String {
    run.aggregator
        .state
        .lock()
        .unwrap()
        .keys
        .last()
        .unwrap()
        .value
        .clone()
}
async fn restart(run: &Run<'_>, tab: &Tab, worker: &mut Worker) -> Result<(), String> {
    setup_cases::click(run, tab, "#tau-lock").await?;
    *worker = run.worker(tab, Some(worker), false).await?;
    resume(run, tab, worker).await
}

fn request_body(raw: &[u8]) -> Option<Value> {
    let start = raw.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    serde_json::from_slice(&raw[start..]).ok()
}
fn key_id(run: &Run<'_>, key: &str) -> String {
    run.aggregator
        .state
        .lock()
        .unwrap()
        .keys
        .iter()
        .find(|k| k.value == key)
        .unwrap()
        .id
        .clone()
}
fn revoke_sent(run: &Run<'_>, id: &str) -> bool {
    run.aggregator.requests.lock().unwrap().iter().any(|raw| {
        raw.starts_with(b"POST /revoke ")
            && request_body(raw).is_some_and(|body| body["key_id"] == id)
    })
}
fn reload_status(finished: bool, sent: bool, status: u16) -> bool {
    status == if finished { 402 } else { 200 } || (!finished && sent && status == 402)
}
// Judge the pre-unlock observation against the durable record, including a revoke that
// completed before teardown. A refusal without an intent is never evidence of revocation.
fn check_reload_record<'a>(
    case: &mut Case,
    records: &'a [Value],
    id: &str,
    status: u16,
    sent: bool,
) -> (Option<&'a Value>, bool) {
    let revoke = records.iter().find_map(|v| {
        v.get("inference_intent")?
            .get("revoke")
            .filter(|r| r["key_id"] == id)
    });
    let finished = revoke.is_some_and(|r| {
        records.iter().any(|v| {
            v.get("inference_terminal")
                .is_some_and(|t| t["call"] == r["call"])
        })
    });
    case.check(
        "reload key status before unlock matches its recorded revoke",
        reload_status(finished, revoke.is_some() && sent, status),
    );
    (revoke, finished)
}

async fn wait_count(run: &Run<'_>, path: &str, count: usize) -> Result<(), String> {
    for _ in 0..100 {
        if run.aggregator.count(path) >= count {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("fixture did not receive {count} {path} requests"))
}
async fn wait_refused(run: &Run<'_>, key: &str) -> Result<(), String> {
    // Inspect fixture state without sending paid completion probes while the sweep progresses.
    for _ in 0..100 {
        if !run.aggregator.state.lock().unwrap().accepts(key) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err("sweep did not revoke the ended session inference key".into())
}
async fn check_expiry(run: &Run<'_>, key: &str, case: &mut Case) -> Result<(), String> {
    let (now, expires) = {
        let s = run.aggregator.state.lock().unwrap();
        (
            s.now,
            s.keys
                .iter()
                .find(|k| k.value == key)
                .unwrap()
                .expires
                .unwrap_or(s.now + tau_web::inference::SESSION_LIFETIME_SECONDS),
        )
    };
    run.aggregator.state.lock().unwrap().now = expires + 1;
    case.check(
        "fixture refuses the session inference key past expiry",
        run.aggregator.key_status(key).await? == 402,
    );
    run.aggregator.state.lock().unwrap().now = now;
    Ok(())
}
async fn crash(run: &Run<'_>, tab: &Tab) -> Result<(), String> {
    run.collect(tab).await?;
    let _ = tokio::time::timeout(
        Duration::from_secs(3),
        run.browser
            .call(Some(&tab.session), "Page.crash", json!({})),
    )
    .await;
    run.browser
        .call(None, "Target.closeTarget", json!({"targetId":tab.target}))
        .await?;
    Ok(())
}
fn check_request_tiers(run: &Run<'_>, case: &mut Case) {
    let requests = run.aggregator.requests.lock().unwrap().clone();
    let state = run.aggregator.state.lock().unwrap();
    case.check("every browser completion names fixture-model; credentials occur only in their tier's header, never any URL or body", requests.iter().all(|raw| {
        let text = String::from_utf8_lossy(raw);
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        let line = head.lines().next().unwrap();
        let completion = line.starts_with("POST /completion ");
        let management = line.starts_with("GET /account ") || line.starts_with("POST /keys ") || line.starts_with("POST /revoke ");
        let account_header = format!("x-inference-account: {}", state.account);
        let account_ok = if management { head.lines().filter(|l| l.contains(&state.account)).all(|l| l.to_ascii_lowercase() == account_header)
            && head.lines().filter(|l| l.to_ascii_lowercase() == account_header).count() == 1 }
            else { !text.contains(&state.account) };
        account_ok && !line.contains(&state.account) && !body.contains(&state.account)
            && state.keys.iter().all(|k| {
                if !text.contains(&k.value) { return true; }
                completion && !line.contains(&k.value) && !body.contains(&k.value)
                    && head.lines().filter(|l| l.contains(&k.value)).all(|l| l.to_ascii_lowercase() == format!("authorization: bearer {}", k.value))
            })
            && (!completion || head.to_ascii_lowercase().contains("x-tracer-check: true") || request_body(raw).is_some_and(|b| b["model"] == "fixture-model"))
    }));
}

async fn command_during_end(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    restart(run, tab, worker).await?;
    infer(run, worker).await?;
    let mut case = Case::new("session end during box-plane intent commit prevents exec");
    let before = run.seen.lock().unwrap().ssh_exec.len();
    let log_before = run.seen.lock().unwrap().relay_log.len();
    run.aggregator.state.lock().unwrap().hold_revoke = true;
    module(run, worker, "self.moveAcquired=new Promise(ready=>m.test_hold_move(new Promise(release=>self.releaseMove=release),ready));return true;").await?;
    let request = json!({"machine":"fixture", "relay":run.relay.url, "host":"127.0.0.1",
        "port":run.sshd.port, "user":SSH_USER, "command":"printf end-race-command; exit 7"});
    run.browser
        .evaluate(
            &worker.session,
            &format!("self.endRaceCommand={};void 0", run_expression(&request)),
        )
        .await?;
    module(run, worker, "await self.moveAcquired;self.heldEnd=m.end_sessions();await new Promise(r=>setTimeout(r,0));return true;").await?;
    session_end_cases::closed(run, log_before, &mut case).await;
    let report = module(
        run,
        worker,
        "self.releaseMove();return await self.endRaceCommand;",
    )
    .await?;
    let outcome = &report["outcome"];
    case.check(
        "committed command reports unresolved after end begins",
        outcome["unresolved"] == true,
    );
    case.check(
        "sshd receives no exec after the held intent commits",
        run.seen.lock().unwrap().ssh_exec.len() == before,
    );
    run.aggregator.state.lock().unwrap().hold_revoke = false;
    restart(run, tab, worker).await?;
    let state = run.inspect(worker).await?;
    case.check(
        "unlock recovers the committed command as unresolved",
        state["calls"].as_array().unwrap().iter().any(|c| {
            c["command"] == hex::encode("printf end-race-command; exit 7")
                && c["state"] == "unresolved"
        }),
    );
    cases.push(case);
    Ok(())
}

async fn job_read_during_end(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    // The preceding command case left a durable, unsent command to collect after restart.
    for collect in [true, false] {
        restart(run, tab, worker).await?;
        let state = run.inspect(worker).await?;
        let call = state["calls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| {
                c["command"] == hex::encode("printf end-race-command; exit 7")
                    && c["state"] == "unresolved"
            })
            .ok_or("missing unresolved command for session-end read case")?["call"]
            .clone();
        let mut case = Case::new(if collect {
            "session end before collection read prevents exec"
        } else {
            "session end stops held read before acquiring writer"
        });
        let before = run.seen.lock().unwrap().ssh_exec.len();
        module(run, worker, "self.readAcquired=new Promise(ready=>m.test_hold_job_read(new Promise(release=>self.releaseRead=release),ready));return true;").await?;
        let mut request = json!({"machine":"fixture", "relay":run.relay.url,
            "host":"127.0.0.1", "port":run.sshd.port, "user":SSH_USER});
        if !collect {
            request["command"] = json!("printf must-stay-held");
        }
        let expression = run_expression(&request);
        let expression = if collect {
            expression.replace("module.run_command(", "module.collect_jobs(")
        } else {
            expression
        };
        run.browser
            .evaluate(
                &worker.session,
                &format!("self.endRaceRead={expression};void 0"),
            )
            .await?;
        module(run, worker, "await self.readAcquired;self.writerAcquired=new Promise(ready=>self.heldWriter=m.test_writer(new Promise(release=>self.releaseWriter=release),ready));await self.writerAcquired;self.heldEnd=m.end_sessions();await new Promise(r=>setTimeout(r,0));return true;").await?;
        if !collect {
            case.check(
                "held wait is stopped while end-sessions still awaits the writer",
                module(run, worker, "return m.stop_waits('fixture');").await? == 0,
            );
        }
        let report = module(run, worker, "self.releaseRead();self.releaseWriter();await self.heldWriter;await self.heldEnd;return await self.endRaceRead;").await?;
        let reports = if collect {
            report["outcome"]["collected"].as_array()
        } else {
            report["outcome"]["calls"].as_array()
        };
        case.check(
            "unread calls report not_read with session end as the reason",
            reports.is_some_and(|rs| {
                rs.iter().any(|r| r["call"] == call)
                    && rs.iter().all(|r| {
                        r["not_read"] == true
                            && r["why"]
                                .as_str()
                                .is_some_and(|why| why.contains("sessions ended"))
                    })
            }),
        );
        case.check(
            "sshd receives no read exec after session end begins",
            run.seen.lock().unwrap().ssh_exec.len() == before,
        );
        let after = run.inspect(worker).await?;
        case.check(
            "session end appends no job evidence and settles no command",
            after["jobs"] == state["jobs"] && after["calls"] == state["calls"],
        );
        cases.push(case);
    }
    Ok(())
}

async fn sent_job_read_during_end(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let saved = store_files(&run.dump(tab).await?);
    let opened = reader::read(&saved, PASSPHRASE)?;
    let seed: Value = serde_json::from_slice(&opened.records[0].1).map_err(|e| e.to_string())?;
    let mnemonic = seed["seed"]["mnemonic"].as_str().ok_or("fixture seed")?;
    let mut initial = vec![seed.clone()];
    initial.extend(reader::setup_events(
        mnemonic,
        &["fixture", "fixture-other", "unpinned"],
    ));
    let initial = reader::build(PASSPHRASE, &initial);
    for collect in [false, true] {
        run.put(tab, &initial).await?;
        *worker = run.reload(tab, worker).await?;
        resume(run, tab, worker).await?;
        let request = json!({"machine":"fixture", "relay":run.relay.url,
            "host":"127.0.0.1", "port":run.sshd.port, "user":SSH_USER,
            "command":"printf must-stay-held"});
        let (new, call, job) = job_cases::drop_command(
            run,
            tab,
            worker.clone(),
            request.clone(),
            "sleep 20; echo sent-read-end",
        )
        .await?;
        *worker = new;
        restart(run, tab, worker).await?;
        module(
            run,
            worker,
            &format!(
                "return await m.test_inference_account(new TextEncoder().encode({}));",
                json!(run.aggregator.state.lock().unwrap().account)
            ),
        )
        .await?;
        infer(run, worker).await?;
        run.aggregator.state.lock().unwrap().hold_revoke = true;
        let before = run.inspect(worker).await?;
        let execs = run.seen.lock().unwrap().ssh_exec.len();
        fresh_pace(run.relay);
        let log_before = run.seen.lock().unwrap().relay_log.len();
        let expression = run_expression(&request);
        let expression = if collect {
            expression.replace("module.run_command(", "module.collect_jobs(")
        } else {
            expression
        };
        run.browser
            .evaluate(
                &worker.session,
                &format!("self.sentReadEnd={expression};void 0"),
            )
            .await?;
        let sent = settle_for(run.seen, 5, |seen| {
            seen.ssh_exec.len() == execs + 1
                && seen.ssh_exec.last().unwrap() == jobs::collect(&job).as_bytes()
        })
        .await;
        if !sent {
            return Err("sshd did not receive the job-read exec before session end".into());
        }
        let mut case = Case::new(if collect {
            "session end cancels a sent collection read"
        } else {
            "session end cancels a sent held read"
        });
        case.check(
            "sshd received the read exec while the detached command is still alive",
            machine::alive(run.sshd.machine.observe()[&job].pid),
        );
        module(run, worker, "self.sentEndDone=false;self.heldEnd=m.end_sessions().then(()=>self.sentEndDone=true);return true;").await?;
        session_end_cases::closed(run, log_before, &mut case).await;
        case.check(
            "end step remains open",
            module(run, worker, "return self.sentEndDone;").await? == false,
        );
        let report = module(run, worker, "return await Promise.race([self.sentReadEnd,new Promise(r=>setTimeout(()=>r({read_wait_expired:true}),3000))]);").await?;
        println!("   sent read reported: {report}");
        let reports = report["outcome"][if collect { "collected" } else { "calls" }]
            .as_array()
            .ok_or("sent read report has no calls")?;
        let read = reports
            .iter()
            .find(|r| r["call"] == call)
            .ok_or("sent read report lost its call")?;
        case.check(
            "sent read names session end and preserves its send history",
            read["why"] == "sessions ended while reading record"
                && if collect {
                    read["failed"] == true && read.get("not_read").is_none() && read["job"] == job
                } else {
                    report["outcome"]["held"] == true
                        && read["not_read"] == true
                        && read.get("failed").is_none()
                },
        );
        let after = run.inspect(worker).await?;
        case.check(
            "session end sends no further exec and appends no job evidence or terminal",
            run.seen.lock().unwrap().ssh_exec.len() == execs + 1
                && after["jobs"] == before["jobs"]
                && after["calls"] == before["calls"],
        );
        run.sshd.machine.reboot();
        run.aggregator.state.lock().unwrap().hold_revoke = false;
        *worker = run.reload(tab, worker).await?;
        cases.push(case);
    }
    run.put(tab, &saved).await?;
    *worker = run.reload(tab, worker).await?;
    resume(run, tab, worker).await
}

pub(super) async fn run(
    run: &Run<'_>,
    tab: &mut Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    *worker = run.reload(tab, worker).await?;
    resume(run, tab, worker).await?;
    let account = run.aggregator.state.lock().unwrap().account.clone();
    if module(run,worker,&format!("const b=new TextEncoder().encode({}); const ok=await m.test_inference_account(b);return ok&&b.every(v=>v===0);",json!(account))).await? != true {return Err("account credential entry or buffer clearing failed".into())}
    let mut case =
        Case::new("procured inference: tiers, metadata, routing, unresolved spend and redirects");
    // Concurrent first calls exercise one mint attempt and one shared memory-only holding.
    let replies = module(run,worker,&format!("const r={};return await Promise.all([m.inference_request(r),m.inference_request(r)]).then(a=>a.map(JSON.parse));",json!(json!({"machine":"fixture","messages":[{"role":"user","content":"browser prompt never journaled"}]}).to_string()))).await?;
    case.check(
        "both concurrent first requests finish under exactly one mint",
        replies
            .as_array()
            .is_some_and(|a| a.len() == 2 && a.iter().all(|r| r["finished"] == true))
            && run.aggregator.count("/keys") == 1,
    );
    let state = run.inspect(worker).await?;
    let session = state["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["bound_set"] == json!(["fixture"]))
        .unwrap();
    case.check(
        "the live session is given row 2 beside row 3, never row 14",
        session["given"] == json!([{"row":3,"machine":"fixture"},{"row":2,"machine":null}]),
    );
    let opened = reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
    let terms: Vec<Value> = opened
        .records
        .iter()
        .filter_map(|(_, b)| {
            serde_json::from_slice::<Value>(b)
                .ok()?
                .get("inference_terminal")
                .cloned()
        })
        .filter(|t| t.get("model").is_some())
        .collect();
    case.check("independent reader sees the requested and reported providers, tokens, spend and request id",terms.len()==2 && terms.iter().all(|t| t["model"]=="fixture-model" && t["requested_provider"]=="fixture-provider"&&t["reported_provider"]=="Fixture Provider"&&t["prompt_tokens"]==3&&t["completion_tokens"]==5&&t["total_tokens"]==8&&t["spend"]=="0.01"&&t["request_id"]=="gen-fixture"));
    case.check(
        "no prompt appears in any decrypted record",
        opened
            .records
            .iter()
            .all(|(_, b)| !String::from_utf8_lossy(b).contains("browser prompt never journaled")),
    );
    let requests = run.aggregator.requests.lock().unwrap().clone();
    let actual: Vec<_> = requests
        .iter()
        .filter(|r| String::from_utf8_lossy(r).starts_with("POST /completion "))
        .collect();
    case.check(
        "every call carries the provider field and retention request",
        actual.len() == 2
            && actual.iter().all(|r| {
                String::from_utf8_lossy(r)
                    .contains("\"provider\":{\"only\":[\"fixture-provider\"],\"zdr\":true}")
            }),
    );
    let credentialed: Vec<_> = requests
        .iter()
        .filter(|r| !r.starts_with(b"OPTIONS "))
        .collect();
    let mint_body = credentialed.get(1).and_then(|r| request_body(r));
    let minted_at = run.aggregator.state.lock().unwrap().now();
    case.check("fixture order is dedicated probe, account read with top-up off, capped expiring mint, then completions",
        requests[0].starts_with(b"OPTIONS / ")
        && credentialed.len() == 4
        && credentialed[0].starts_with(b"GET /account ")
        && !run.aggregator.state.lock().unwrap().top_up
        && credentialed[1].starts_with(b"POST /keys ")
        && mint_body.as_ref().is_some_and(|b| b["cap"] == tau_web::inference::SESSION_CAP
            && b["expires"].as_u64().is_some_and(|expires| expires >= minted_at.saturating_sub(60) + tau_web::inference::SESSION_LIFETIME_SECONDS && expires <= minted_at + tau_web::inference::SESSION_LIFETIME_SECONDS + 60))
        && credentialed[2..].iter().all(|r| r.starts_with(b"POST /completion ")));
    check_request_tiers(run, &mut case);
    run.aggregator.state.lock().unwrap().no_report = true;
    case.check(
        "case-H response remains readable",
        infer(run, worker).await?["finished"] == true,
    );
    let state = run.inspect(worker).await?;
    let t = &state["inference_calls"].as_array().unwrap().last().unwrap()["terminal"];
    case.check(
        "absent provider and cost stay absent",
        t.get("reported_provider").is_none() && t.get("spend").is_none(),
    );
    run.aggregator.state.lock().unwrap().no_report = false;
    run.aggregator.state.lock().unwrap().routing_refusal = true;
    case.check(
        "readable routing refusal gets a 404 terminal",
        infer(run, worker).await?["status"] == 404,
    );
    run.aggregator.state.lock().unwrap().routing_refusal = false;
    run.aggregator.state.lock().unwrap().lose = Some("/completion".into());
    let lost = module(run,worker,&format!("return JSON.parse(await m.inference_request({}));", json!(json!({"machine":"fixture","messages":[{"role":"user","content":"browser lost completion"}]}).to_string()))).await?;
    let lost_id = lost["call"].clone();
    case.check(
        "lost completion reports unresolved, never failed",
        lost["unresolved"] == true && lost.get("failed").is_none(),
    );
    case.check(
        "next inference request dispatches",
        infer(run, worker).await?["finished"] == true,
    );
    let state = run.inspect(worker).await?;
    case.check(
        "unaccounted spend is shown against the key cap",
        state["inference_calls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| {
                c["call"] == lost_id
                    && c["state"] == "unresolved"
                    && c["unaccounted_spend"]["cap"] == tau_web::inference::SESSION_CAP
            }),
    );
    run.aggregator.state.lock().unwrap().fail = true;
    case.check(
        "readable 5xx gets a terminal",
        infer(run, worker).await?["status"] == 503,
    );
    let probes_before = run
        .aggregator
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| String::from_utf8_lossy(r).starts_with("OPTIONS / "))
        .count();
    case.check(
        "failed real call leaves route chosen",
        infer(run, worker).await?["finished"] == true,
    );
    let probes_after = run
        .aggregator
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| String::from_utf8_lossy(r).starts_with("OPTIONS / "))
        .count();
    case.check(
        "no real-call failure caused a second probe",
        probes_before == probes_after && probes_after > 0,
    );
    run.aggregator.state.lock().unwrap().redirect = true;
    let redirected = infer(run, worker).await?;
    case.check(
        "manual redirect ends unresolved",
        redirected["unresolved"] == true && redirected.get("failed").is_none(),
    );
    case.check(
        "redirect target received nothing",
        !run.aggregator
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| String::from_utf8_lossy(r).starts_with("POST /redirect-target ")),
    );
    run.aggregator.state.lock().unwrap().redirect = false;
    check_request_tiers(run, &mut case);
    cases.push(case);

    // Hold a response open: the second call must record and reach the fixture before it ends.
    let mut case = Case::new("held completion does not bar the next inference request");
    run.aggregator.state.lock().unwrap().hold_completion = true;
    let before = run.aggregator.count("/completion");
    module(run, worker, &format!("self.heldCompletion=m.inference_request({});return true;", json!(json!({"machine":"fixture","messages":[{"role":"user","content":"held completion"}]}).to_string()))).await?;
    wait_count(run, "/completion", before + 1).await?;
    let held_id = run.inspect(worker).await?["inference_calls"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["call"]
        .clone();
    let second = tokio::time::timeout(Duration::from_secs(5), module(run, worker,
        &format!("return JSON.parse(await m.inference_request({}));",
            json!(json!({"machine":"fixture","messages":[{"role":"user","content":"second beside held completion"}]}).to_string())))).await;
    let second = second.ok().and_then(Result::ok);
    case.check(
        "second completion finishes while the first response is withheld",
        second.as_ref().is_some_and(|v| v["finished"] == true),
    );
    case.check(
        "both intents committed and both completions reached the fixture",
        run.aggregator.count("/completion") == before + 2
            && ["held completion", "second beside held completion"]
                .iter()
                .all(|message| {
                    run.aggregator
                        .requests
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|r| {
                            request_body(r)
                                .is_some_and(|body| body["messages"][0]["content"] == *message)
                        })
                        .count()
                        == 1
                })
            && run.inspect(worker).await?["inference_calls"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| {
                    c["call"] == held_id && c["kind"] == "completion" && c["state"] == "unresolved"
                })
            && second.as_ref().is_some_and(|v| {
                v["call"] != held_id && v["call"] != lost_id && v["finished"] == true
            })
            && run.inspect(worker).await?["inference_calls"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| {
                    second.as_ref().is_some_and(|v| c["call"] == v["call"])
                        && c["kind"] == "completion"
                        && c["state"] == "finished"
                }),
    );
    cases.push(case);

    // Kill the worker with the lost and held intents, then verify replay never resends them.
    let mut case = Case::new("lost completion survives crash and unlock without replay send");
    let key = last_key(run);
    let before = run.aggregator.count("/completion");
    crash(run, tab).await?;
    let crash_accepts = run.aggregator.key_status(&key).await? == 200;
    (*tab, *worker) = run.open(&tab.origin, false).await?;
    resume(run, tab, worker).await?;
    let state = run.inspect(worker).await?;
    case.check(
        "lost local call remains unresolved after crash and unlock",
        state["inference_calls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["call"] == lost_id && c["state"] == "unresolved"),
    );
    case.check(
        "fixture saw the lost completion once and replay sent no completion",
        run.aggregator.count("/completion") == before + 1
            && run
                .aggregator
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| {
                    request_body(r)
                        .is_some_and(|b| b["messages"][0]["content"] == "browser lost completion")
                })
                .count()
                == 1,
    );
    // key_status above is an explicit tracer request, distinct from a replay send.
    case.check(
        "new request dispatches after crash",
        infer(run, worker).await?["finished"] == true,
    );
    wait_refused(run, &key).await?;
    let id = key_id(run, &key);
    let mut recorded = false;
    for _ in 0..100 {
        recorded = run.inspect(worker).await?["inference_calls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| {
                c["kind"] == "revoke"
                    && c["intent"]["revoke"]["key_id"] == id
                    && c["state"] == "finished"
            });
        if recorded {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    case.check(
        "readable crash-sweep response commits its terminal",
        recorded,
    );
    case.check(
        "crash accepts before unlock and sweep revokes afterwards",
        crash_accepts && run.aggregator.key_status(&key).await? == 402,
    );
    cases.push(case);

    let phase = std::env::var("TAU_TRACER_INFERENCE_PHASE").unwrap_or_default();
    if phase == "sent-reads" {
        return sent_job_read_during_end(run, tab, worker, cases).await;
    }
    if phase == "command-intent" {
        return command_during_end(run, tab, worker, cases).await;
    }
    if phase == "session-end" {
        return session_end_cases::run(run, tab, worker, cases).await;
    }
    let selected_end = std::env::var("TAU_TRACER_INFERENCE_END").ok();
    if phase == "core" {
        return Ok(());
    }
    if phase != "cutoff" && selected_end.is_none() {
        command_during_end(run, tab, worker, cases).await?;
        job_read_during_end(run, tab, worker, cases).await?;
        sent_job_read_during_end(run, tab, worker, cases).await?;
        session_end_cases::run(run, tab, worker, cases).await?;
    }
    if phase == "dispatch" {
        return Ok(());
    }
    for end in [
        "lock",
        "hidden",
        "pagehide",
        "reload",
        "bfcache",
        "redisplay",
    ] {
        if phase == "cutoff" || selected_end.as_ref().is_some_and(|s| s != end) {
            continue;
        }
        restart(run, tab, worker).await?;
        let reply = infer(run, worker).await?;
        if reply["finished"] != true {
            return Err(format!("inference before {end}: {reply}"));
        }
        let key = last_key(run);
        let mut case = Case::new(&format!("session inference key end at {end}"));
        let old = worker.clone();
        match end {
            "reload" => *worker = run.reload(tab, worker).await?,
            "hidden" => {
                let other = run
                    .browser
                    .call(None, "Target.createTarget", json!({"url":"about:blank"}))
                    .await?;
                *worker = run.worker(tab, Some(&old), false).await?;
                run.browser
                    .call(
                        None,
                        "Target.closeTarget",
                        json!({"targetId":other["targetId"]}),
                    )
                    .await?;
                run.browser
                    .call(
                        None,
                        "Target.activateTarget",
                        json!({"targetId":tab.target}),
                    )
                    .await?;
            }
            "pagehide" | "bfcache" => {
                let expression = if end == "pagehide" {
                    "dispatchEvent(new PageTransitionEvent('pagehide'))"
                } else {
                    "dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}))"
                };
                run.browser.evaluate(&tab.session, expression).await?;
                *worker = run.worker(tab, Some(&old), false).await?;
            }
            _ => {
                setup_cases::click(
                    run,
                    tab,
                    if end == "redisplay" {
                        "#tau-redisplay"
                    } else {
                        "#tau-lock"
                    },
                )
                .await?;
                *worker = run.worker(tab, Some(&old), false).await?;
            }
        }
        if end == "reload" {
            let id = key_id(run, &key);
            let opened = reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
            let intents: Vec<Value> = opened
                .records
                .iter()
                .filter_map(|(_, b)| serde_json::from_slice::<Value>(b).ok())
                .collect();
            let (revoke, finished) = check_reload_record(
                &mut case,
                &intents,
                &id,
                run.aggregator.key_status(&key).await?,
                revoke_sent(run, &id),
            );
            let before = run.aggregator.count("/revoke");
            resume(run, tab, worker).await?;
            if let Some(revoke) = revoke {
                let state = run.inspect(worker).await?;
                case.check(
                    "recorded unload revoke is never sent a second time",
                    state["inference_calls"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|c| {
                            c["call"] == revoke["call"]
                                && c["state"] == if finished { "finished" } else { "unresolved" }
                        })
                        && run.aggregator.count("/revoke") == before,
                );
                if !finished {
                    case.check(
                        "cut-off unload key is accepted or its recorded revoke reached the fixture",
                        reload_status(
                            false,
                            revoke_sent(run, &id),
                            run.aggregator.key_status(&key).await?,
                        ),
                    );
                } else {
                    case.check(
                        "completed unload revoke remains refused",
                        run.aggregator.key_status(&key).await? == 402,
                    );
                }
            } else {
                wait_refused(run, &key).await?;
                case.check(
                    "next-unlock sweep revokes the reload key",
                    run.aggregator.key_status(&key).await? == 402,
                );
            }
        } else {
            case.check(
                "the tracer uses the ended session's key and the fixture refuses it",
                run.aggregator.key_status(&key).await? == 402,
            );
            resume(run, tab, worker).await?;
        }
        check_expiry(run, &key, &mut case).await?;
        cases.push(case);
    }
    if selected_end.is_some() {
        return Ok(());
    }
    // The page cannot run a revoke after a crash. Prove the window before unlock, then the sweep.
    for unlock in [true, false] {
        if phase == "cutoff" {
            continue;
        }
        restart(run, tab, worker).await?;
        infer(run, worker).await?;
        let key = last_key(run);
        let mut case = Case::new(if unlock {
            "crash leaves key usable until next-unlock sweep"
        } else {
            "crash without unlock leaves key usable until expiry"
        });
        run.collect(tab).await?;
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            run.browser
                .call(Some(&tab.session), "Page.crash", json!({})),
        )
        .await;
        case.check(
            "fixture still accepts key immediately after crash",
            run.aggregator.key_status(&key).await? == 200,
        );
        run.browser
            .call(None, "Target.closeTarget", json!({"targetId":tab.target}))
            .await?;
        (*tab, *worker) = run.open(&tab.origin, false).await?;
        if unlock {
            resume(run, tab, worker).await?;
        } else {
            let now = run.aggregator.state.lock().unwrap().now;
            let expires = run
                .aggregator
                .state
                .lock()
                .unwrap()
                .keys
                .last()
                .unwrap()
                .expires
                .unwrap_or(now + tau_web::inference::SESSION_LIFETIME_SECONDS);
            run.aggregator.state.lock().unwrap().now = expires + 1;
            case.check(
                "fixture refuses past the requested expiry without an unlock",
                run.aggregator.key_status(&key).await? == 402,
            );
            run.aggregator.state.lock().unwrap().now = now;
            resume(run, tab, worker).await?;
        }
        wait_refused(run, &key).await?;
        check_expiry(run, &key, &mut case).await?;
        case.check(
            "fixture refuses key after sweep",
            run.aggregator.key_status(&key).await? == 402,
        );
        cases.push(case);
    }
    if phase != "cutoff" {
        restart(run, tab, worker).await?;
        let mut case =
            Case::new("mint finishing during session end is revoked before the end answers");
        let release = Arc::new(tokio::sync::Notify::new());
        run.aggregator.state.lock().unwrap().hold_mint = Some(release.clone());
        let before = run.aggregator.count("/keys");
        module(
            run,
            worker,
            &format!(
                "self.lateMint=m.inference_request({});return true;",
                json!(
                    json!({"machine":"fixture","messages":[{"role":"user","content":"late mint"}]})
                        .to_string()
                )
            ),
        )
        .await?;
        wait_count(run, "/keys", before + 1).await?;
        module(run, worker, "self.endAnswered=false;self.lateEnd=m.end_sessions().then(()=>{self.endAnswered=true;});return true;").await?;
        let mut cleared = false;
        for _ in 0..100 {
            cleared = run.inspect(worker).await?["sessions"]
                .as_array()
                .unwrap()
                .is_empty();
            if cleared {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        case.check(
            "end drops holdings and waits for the held mint",
            cleared && module(run, worker, "return self.endAnswered;").await? == false,
        );
        release.notify_one();
        module(
            run,
            worker,
            "await self.lateEnd;await self.lateMint;return true;",
        )
        .await?;
        let key = last_key(run);
        let id = key_id(run, &key);
        case.check(
            "late identifier has a committed revoke terminal before end answers",
            run.inspect(worker).await?["inference_calls"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| {
                    c["kind"] == "revoke"
                        && c["intent"]["revoke"]["key_id"] == id
                        && c["state"] == "finished"
                })
                && run.aggregator.key_status(&key).await? == 402,
        );
        cases.push(case);
        restart(run, tab, worker).await?;
        let mut case = Case::new("identifier-only mint is revoked at session end");
        run.aggregator.state.lock().unwrap().identifier_only = true;
        let result = infer(run, worker).await?;
        run.aggregator.state.lock().unwrap().identifier_only = false;
        let key = last_key(run);
        case.check(
            "identifier-only response installs no row-2 holding",
            result.get("refused").is_some()
                && run.inspect(worker).await?["sessions"][0]["given"]
                    == json!([{"row":3,"machine":"fixture"}]),
        );
        setup_cases::click(run, tab, "#tau-lock").await?;
        *worker = run.worker(tab, Some(worker), false).await?;
        case.check(
            "identifier-only key is refused immediately after end, before unlock",
            run.aggregator.key_status(&key).await? == 402,
        );
        resume(run, tab, worker).await?;
        cases.push(case);

        let mut case = Case::new("unlock answers while sweep revoke is withheld");
        infer(run, worker).await?;
        let key = last_key(run);
        crash(run, tab).await?;
        (*tab, *worker) = run.open(&tab.origin, false).await?;
        origin(run, worker).await?;
        run.aggregator.state.lock().unwrap().hold_revoke = true;
        let before = run.aggregator.count("/revoke");
        let unlocked = tokio::time::timeout(
            Duration::from_secs(8),
            run.submit(tab, "unlock", PASSPHRASE),
        )
        .await;
        case.check(
            "unlock report arrives while aggregator withholds the revoke response",
            unlocked.is_ok_and(|v| v.is_ok_and(|v| v["store"] == "unlocked")),
        );
        wait_count(run, "/revoke", before + 1).await?;
        case.check(
            "withheld sweep revoke has an unresolved intent",
            run.inspect(worker).await?["inference_calls"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["kind"] == "revoke" && c["state"] == "unresolved"),
        );
        case.check(
            "withheld revoke did not act",
            run.aggregator.key_status(&key).await? == 200,
        );
        run.aggregator.state.lock().unwrap().hold_revoke = false;
        binding_cases::prepare(run, tab, worker, PASSPHRASE).await?;
        case.check(
            "new session mints while the recovered revoke is withheld",
            infer(run, worker).await?["finished"] == true,
        );
        let live_key = last_key(run);
        let before = run.aggregator.count("/revoke");
        module(run, worker, "await m.sweep_inference();return true;").await?;
        case.check(
            "delayed sweep leaves this worker's minted key usable",
            run.aggregator.count("/revoke") == before
                && run.aggregator.key_status(&live_key).await? == 200,
        );
        cases.push(case);
    }
    restart(run, tab, worker).await?;
    infer(run, worker).await?;
    let key = last_key(run);
    let mut case = Case::new("bounded revoke stays unresolved and is never swept twice");
    run.aggregator.state.lock().unwrap().hold_revoke = true;
    let before = run.aggregator.count("/revoke");
    setup_cases::click(run, tab, "#tau-lock").await?;
    *worker = run.worker(tab, Some(worker), false).await?;
    run.aggregator.state.lock().unwrap().hold_revoke = false;
    origin(run, worker).await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    // A second invocation is a barrier for this check: with a revoke intent it does nothing.
    // If sweeping retries an unresolved revoke, await that transmission before counting it.
    module(run, worker, "await m.sweep_inference();return true;").await?;
    case.check(
        "exactly one revoke was sent, with no sweep retry",
        run.aggregator.count("/revoke") == before + 1,
    );
    let state = run.inspect(worker).await?;
    case.check(
        "cut-off revoke remains unresolved",
        state["inference_calls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["kind"] == "revoke" && c["state"] == "unresolved"),
    );
    case.check(
        "cut-off key is still accepted before expiry",
        run.aggregator.key_status(&key).await? == 200,
    );
    let now = run.aggregator.state.lock().unwrap().now;
    let expires = run
        .aggregator
        .state
        .lock()
        .unwrap()
        .keys
        .last()
        .unwrap()
        .expires
        .unwrap_or(now + tau_web::inference::SESSION_LIFETIME_SECONDS);
    run.aggregator.state.lock().unwrap().now = expires + 1;
    case.check(
        "cut-off key is refused past expiry",
        run.aggregator.key_status(&key).await? == 402,
    );
    run.aggregator.state.lock().unwrap().now = now;
    cases.push(case);

    restart(run, tab, worker).await?;
    let mut case = Case::new("top-up and route refusals send no mint or credentialed request");
    run.aggregator.state.lock().unwrap().top_up = true;
    let before = run.aggregator.count("/keys");
    case.check(
        "top-up on refuses before mint",
        infer(run, worker).await?.get("refused").is_some()
            && run.aggregator.count("/keys") == before,
    );
    run.aggregator.state.lock().unwrap().top_up = false;
    // A new worker has no route table; a refused dedicated probe sends no credential.
    *worker = run.reload(tab, worker).await?;
    resume(run, tab, worker).await?;
    run.aggregator.state.lock().unwrap().refuse_probe = true;
    let before = run.aggregator.requests.lock().unwrap().len();
    case.check(
        "refused probe refuses inference",
        infer(run, worker).await?["refused"] == "no route to that origin in this build",
    );
    case.check(
        "only OPTIONS requests reached fixture",
        run.aggregator.requests.lock().unwrap()[before..]
            .iter()
            .all(|r| r.starts_with(b"OPTIONS ")),
    );
    run.aggregator.state.lock().unwrap().refuse_probe = false;
    cases.push(case);
    // Leave a real key minted for the tracer build's following no-plaintext search.
    infer(run, worker).await?;
    Ok(())
}

pub(super) async fn no_plaintext(
    run: &Run<'_>,
    tab: &Tab,
    worker: &Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let mut case = Case::new("inference no-plaintext needles and loopback-only requests");
    let collector = DUMP.replace("navigator.storage.getDirectory()", "fixture");
    let moved = run.browser.evaluate(&tab.session, &format!(r#"(async()=>{{
        let attempts=0;
        const file=(text)=>({{kind:'file',getFile:async()=>new Blob([text])}});
        const fixture={{async *entries(){{
            if (attempts++===0) {{
                yield ['abandoned',file('old')];
                yield ['staging',{{kind:'file',getFile:async()=>{{throw new DOMException('moved','NotFoundError');}}}}];
            }} else {{yield ['committed',file('new')];}}
        }}}};
        try {{return {{files:await {collector},attempts}};}}
        catch(error) {{return {{error:error.name,attempts}};}}
    }})()"#)).await?;
    case.check(
        "OPFS dump retries a move and discards the partial snapshot",
        moved == json!({"files":{"committed":"bmV3"},"attempts":2}),
    );
    for (error, expected_attempts) in [("NotFoundError", 10), ("SecurityError", 1)] {
        let refused = run.browser.evaluate(&tab.session, &format!(r#"(async()=>{{
            let attempts=0;
            const fixture={{async *entries(){{
                attempts++;
                yield ['unreadable',{{kind:'file',getFile:async()=>{{throw new DOMException('unreadable',{error});}}}}];
            }}}};
            try {{await {collector};return null;}}
            catch(error) {{return {{error:error.name,attempts}};}}
        }})()"#,error=json!(error))).await?;
        case.check(
            "OPFS dump bounds move retries and preserves unrelated errors",
            refused == json!({"error":error,"attempts":expected_attempts}),
        );
    }
    check_request_tiers(run, &mut case);
    let mut needles = Vec::new();
    add_inference_needles(run, &mut needles);
    case.check(
        "account and every minted session inference key contribute needles",
        needles.len() > 10,
    );
    // Each actual value must be independently findable; deleting its needle makes this red.
    let values: Vec<String> = {
        let s = run.aggregator.state.lock().unwrap();
        std::iter::once(s.account.clone())
            .chain(s.keys.iter().map(|k| k.value.clone()))
            .collect()
    };
    for value in &values {
        case.check(
            "planted credential is detected",
            !reader::found(&needles, value.as_bytes()).is_empty(),
        );
    }
    let files = run.dump(tab).await?;
    let opened = reader::read(&store_files(&files), PASSPHRASE)?;
    case.check(
        "OPFS holds no credential plaintext",
        files
            .values()
            .all(|b| reader::found(&needles, b).is_empty()),
    );
    case.check(
        "decrypted records exempt only the account credential field",
        opened.records.iter().all(|(_, b)| {
            reader::record_findings(&needles, b, &opened.seed_id().unwrap()).is_empty()
        }),
    );
    let storage = run.browser.evaluate(&tab.session, OTHER_STORAGE).await?;
    case.check(
        "browser storage empty and no service worker",
        storage == json!({"local":[],"session":[],"databases":[],"caches":[],"service_workers":0}),
    );
    run.collect(tab).await?;
    case.check(
        "page-worker messages hold no credential",
        run.messages
            .borrow()
            .iter()
            .all(|m| reader::found(&needles, m.to_string().as_bytes()).is_empty()),
    );
    case.check(
        "store_state holds no credential",
        reader::found(&needles, run.inspect(worker).await?.to_string().as_bytes()).is_empty(),
    );
    let console = run
        .browser
        .events
        .lock()
        .unwrap()
        .iter()
        .filter_map(console_params)
        .map(Value::to_string)
        .collect::<Vec<_>>();
    case.check(
        "console and logs hold no credential",
        console
            .iter()
            .all(|s| reader::found(&needles, s.as_bytes()).is_empty()),
    );
    let requests = run.aggregator.requests.lock().unwrap().clone();
    case.check(
        "completion bodies hold no credential",
        requests
            .iter()
            .filter(|r| r.starts_with(b"POST /completion "))
            .all(|r| {
                let start = r
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map_or(r.len(), |i| i + 4);
                reader::found(&needles, &r[start..]).is_empty()
            }),
    );
    let negative = "https://loopback-fence-negative.invalid/";
    let worker_from = run.browser.event_count();
    let blocked = module(
        run,
        worker,
        &format!(
            "return await fetch({}).then(()=>true,()=>false);",
            json!(negative)
        ),
    )
    .await?;
    let worker_blocked = run.browser.events.lock().unwrap()[worker_from..]
        .iter()
        .any(|e| {
            e["sessionId"] == worker.session
                && e["method"] == "Network.loadingFailed"
                && e["params"]["blockedReason"] == "inspector"
        });
    case.check(
        "worker negative control was blocked before transmission",
        blocked == false && worker_blocked,
    );
    run.browser
        .evaluate(
            &tab.session,
            &format!("fetch({}).catch(()=>false)", json!(negative)),
        )
        .await?;
    let events = run.browser.events.lock().unwrap();
    let paused: Vec<_> = events
        .iter()
        .filter(|e| e["method"] == "Fetch.requestPaused")
        .filter_map(|e| e["params"]["request"]["url"].as_str())
        .collect();
    case.check(
        "negative control was stopped before transmission",
        paused.contains(&negative),
    );
    case.check(
        "all page and worker requests were loopback except the blocked negative control",
        paused
            .iter()
            .all(|u| cdp::loopback_url(u) || *u == negative),
    );
    let urls: Vec<_> = events
        .iter()
        .filter(|e| e["method"] == "Network.requestWillBeSent")
        .filter_map(|e| e["params"]["request"]["url"].as_str())
        .collect();
    case.check(
        "no request URL carries an inference account credential or session inference key",
        urls.iter()
            .all(|url| reader::found(&needles, url.as_bytes()).is_empty()),
    );
    case.check(
        "network events cover page and worker requests, all loopback except blocked control",
        !urls.is_empty() && urls.iter().all(|u| cdp::loopback_url(u) || *u == negative),
    );
    cases.push(case);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_checks_all_three_recorded_outcomes_and_rejects_unrecorded_refusal() {
        let intent = json!({"inference_intent":{"revoke":{"call":10,"key_id":"ended-key"}}});
        let terminal = json!({"inference_terminal":{"call":10,"status":200}});
        for (records, sent, status, accepted, has_intent, finished) in [
            (vec![], false, 200, true, false, false),
            (vec![], true, 402, false, false, false),
            (vec![intent.clone()], false, 200, true, true, false),
            (vec![intent.clone()], false, 402, false, true, false),
            (vec![intent.clone()], true, 200, true, true, false),
            (vec![intent.clone()], true, 402, true, true, false),
            (
                vec![intent.clone(), terminal.clone()],
                true,
                402,
                true,
                true,
                true,
            ),
            (vec![intent, terminal], true, 200, false, true, true),
        ] {
            let mut case = Case::new("reload observation");
            let (revoke, observed_finished) =
                check_reload_record(&mut case, &records, "ended-key", status, sent);
            assert_eq!(
                case.failures.is_empty(),
                accepted,
                "{records:?}, sent={sent}, status={status}"
            );
            assert_eq!(revoke.is_some(), has_intent);
            assert_eq!(observed_finished, finished);
        }
    }
}
