//! Session-end races observed while revocation keeps the worker alive.
use super::*;
use std::sync::atomic::Ordering;

fn selected(name: &str) -> bool {
    std::env::var("TAU_TRACER_SESSION_END").map_or(true, |s| {
        s.split(',').any(|part| {
            part.strip_prefix('=')
                .map_or_else(|| name.contains(part), |exact| name == exact)
        })
    })
}
async fn point(run: &Run<'_>, worker: &Worker, name: &str) -> Result<(), String> {
    module(run, worker, &format!("self.pointReady=new Promise(ready=>m.test_hold_session_point({},new Promise(release=>self.releasePoint=release),ready));return true;",json!(name))).await?;
    Ok(())
}
async fn wait_point(run: &Run<'_>, worker: &Worker) -> Result<(), String> {
    module(run, worker, "await self.pointReady;return true;").await?;
    Ok(())
}
async fn writer(run: &Run<'_>, worker: &Worker) -> Result<(), String> {
    module(run,worker,"self.writerReady=new Promise(ready=>self.writerWork=m.test_writer(new Promise(release=>self.releaseWriter=release),ready));await self.writerReady;return true;").await?;
    Ok(())
}
async fn begin_end(run: &Run<'_>, worker: &Worker) -> Result<(), String> {
    run.aggregator.state.lock().unwrap().hold_revoke = true;
    module(run,worker,"self.endDone=false;self.endWork=m.end_sessions().then(()=>self.endDone=true);await new Promise(r=>setTimeout(r,0));return true;").await?;
    Ok(())
}
async fn end_open(run: &Run<'_>, worker: &Worker, case: &mut Case) -> Result<(), String> {
    case.check(
        "checked before end step completes and before worker termination",
        module(run, worker, "return self.endDone;").await? == false,
    );
    Ok(())
}
async fn start(run: &Run<'_>, worker: &Worker, expression: &str) -> Result<(), String> {
    run.browser
        .evaluate(
            &worker.session,
            &format!("self.sessionResult={expression};void 0"),
        )
        .await?;
    Ok(())
}
async fn answer(run: &Run<'_>, worker: &Worker) -> Result<Value, String> {
    let result = module(run,worker,"return await Promise.race([self.sessionResult,new Promise(r=>setTimeout(()=>r({wait_expired:true}),3000))]);").await?;
    println!("   session-end report: {result}");
    Ok(result)
}
fn request(run: &Run<'_>, command: &str) -> Value {
    json!({"machine":"fixture","relay":run.relay.url,"host":"127.0.0.1","port":run.sshd.port,"user":SSH_USER,"command":command})
}
fn expression(run: &Run<'_>, site: &str, command: &str) -> String {
    let s = run_expression(&request(run, command));
    if site == "collection" {
        s.replace("module.run_command(", "module.collect_jobs(")
    } else {
        s
    }
}
async fn reset(run: &Run<'_>, tab: &Tab, worker: &mut Worker, files: &Files) -> Result<(), String> {
    reset_with_bindings(run, tab, worker, files, true).await
}
async fn reset_with_bindings(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    files: &Files,
    bind_all: bool,
) -> Result<(), String> {
    run.relay.session_gate.clear();
    run.aggregator.state.lock().unwrap().hold_revoke = false;
    *worker = run.reload(tab, worker).await?;
    if !run.sshd.all_ended().await {
        return Err("previous fixture SSH connection did not end".into());
    }
    run.put(tab, files).await?;
    *worker = run.reload(tab, worker).await?;
    if bind_all {
        resume(run, tab, worker).await?;
    } else {
        origin(run, worker).await?;
        run.submit(tab, "unlock", PASSPHRASE).await?;
        setup_cases::click(run, tab, "[data-bind=fixture]").await?;
        let mut bound = false;
        for _ in 0..300 {
            bound = run.inspect(worker).await?["sessions"]
                .as_array()
                .is_some_and(|sessions| {
                    sessions
                        .iter()
                        .any(|s| s["bound_set"] == json!(["fixture"]))
                });
            if bound {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if !bound {
            return Err("fixture session did not bind".into());
        }
    }
    let account = run.aggregator.state.lock().unwrap().account.clone();
    module(
        run,
        worker,
        &format!(
            "return await m.test_inference_account(new TextEncoder().encode({}));",
            json!(account)
        ),
    )
    .await?;
    let result = infer(run, worker).await?;
    if result["finished"] != true {
        return Err(format!("session-end fixture inference: {result}"));
    }
    fresh_pace(run.relay);
    Ok(())
}
async fn unresolved(run: &Run<'_>, worker: &Worker) -> Result<(), String> {
    let result = run
        .harness_run(worker, request(run, "close-without-status"))
        .await?;
    if result["outcome"]["unresolved"] != true {
        return Err(format!("session-end fixture unresolved call: {result}"));
    }
    fresh_pace(run.relay);
    Ok(())
}
pub(super) async fn closed(run: &Run<'_>, from: usize, case: &mut Case) {
    let relay_closed = settle_for(run.seen, 5, |seen| {
        let connections: std::collections::BTreeSet<_> = seen.relay_log[from..]
            .iter()
            .filter_map(|(id, event)| {
                matches!(
                    event,
                    fixtures::Event::ChallengeSent | fixtures::Event::Held(_)
                )
                .then_some(*id)
            })
            .collect();
        seen.relay_log[from..].iter().any(|(id, event)| {
            connections.contains(id)
                && matches!(
                    event,
                    fixtures::Event::Ended | fixtures::Event::Frame("close")
                )
        })
    })
    .await;
    case.check(
        "relay observes browser socket close during end step",
        relay_closed,
    );
    let ssh_closed = settle_for(run.seen, 5, |_| {
        run.sshd.accepted.load(Ordering::SeqCst) == run.sshd.ended.load(Ordering::SeqCst)
    })
    .await;
    case.check("every dialed sshd observes connection end", ssh_closed);
}
async fn network(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    files: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    for site in ["command", "held", "collection"] {
        for stage in [
            "challenge",
            "verdict",
            "identification",
            "kex",
            "auth",
            "auth-rekey",
            "connected-rekey",
        ] {
            let name = format!("session end closes {site} at {stage}");
            if !selected(&name) {
                continue;
            }
            reset(run, tab, worker, files).await?;
            if site != "command" {
                unresolved(run, worker).await?;
            }
            let (log_before, exec_before, auth_before, channel_before) = {
                let s = run.seen.lock().unwrap();
                (
                    s.relay_log.len(),
                    s.ssh_exec.len(),
                    s.ssh_auth.len(),
                    s.ssh_channels,
                )
            };
            let accepted_before = run.sshd.accepted.load(Ordering::SeqCst);
            let rekey = stage.ends_with("-rekey");
            let rekey_log = run.seen.lock().unwrap().relay_log.len();
            let boundary = if stage == "auth-rekey" {
                "session_authentication"
            } else {
                "session_connected"
            };
            let banners = run.seen.lock().unwrap().ssh_authentication_banners;
            if stage == "auth-rekey" {
                run.sshd.auth_banner.store(true, Ordering::SeqCst);
            }
            if rekey {
                point(run, worker, boundary).await?;
            } else {
                run.relay.session_gate.arm(stage);
            }
            start(
                run,
                worker,
                &expression(run, site, "printf should-not-launch"),
            )
            .await?;
            if rekey {
                wait_point(run, worker).await?;
                run.relay.session_gate.arm("rekey");
                module(
                    run,
                    worker,
                    &format!(
                        "m.test_rekey_session({});self.releasePoint();return true;",
                        json!(boundary)
                    ),
                )
                .await?;
            }
            let reached = settle_for(run.seen, 5, |_| {
                run.relay.session_gate.reached.load(Ordering::SeqCst)
            })
            .await;
            if !reached {
                return Err(format!(
                    "could not arrange {name}: fixture never reached held stage"
                ));
            }
            let mut case = Case::new(&name);
            if stage == "auth-rekey" {
                case.check(
                    "authentication service reached before rekey starts",
                    run.seen.lock().unwrap().ssh_authentication_banners == banners + 1,
                );
            }
            if rekey {
                case.check(
                    "requested rekey emits a client SSH packet before session end",
                    settle_for(run.seen, 5, |seen| {
                        seen.relay_log[rekey_log..].iter().any(|(_, event)| {
                            matches!(
                                event,
                                fixtures::Event::Forwarded(fixtures::Toward::Destination, _)
                                    | fixtures::Event::Frame("binary")
                            )
                        })
                    })
                    .await,
                );
            }
            begin_end(run, worker).await?;
            closed(run, log_before, &mut case).await;
            let report = answer(run, worker).await?;
            case.check(
                "stopped request answers before termination",
                report.get("wait_expired").is_none(),
            );
            if site == "command" {
                case.check(
                    "command stopped before intent reports session-end journal refusal",
                    report["outcome"]["refused"] == "journal"
                        && report["outcome"]["why"] == "sessions ended",
                );
            }
            case.check(
                "no command or job-read exec reaches sshd",
                run.seen.lock().unwrap().ssh_exec.len() == exec_before,
            );
            if stage == "challenge" {
                case.check(
                    "before relay dial sshd sees no contact",
                    run.sshd.accepted.load(Ordering::SeqCst) == accepted_before,
                );
            }
            case.check(
                "no later SSH channel is opened",
                run.seen.lock().unwrap().ssh_channels == channel_before,
            );
            if ["identification", "kex"].contains(&stage) {
                case.check(
                    "no later authentication stage is sent",
                    run.seen.lock().unwrap().ssh_auth.len() == auth_before,
                );
            }
            end_open(run, worker, &mut case).await?;
            cases.push(case);
        }
    }
    Ok(())
}

async fn admission(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    files: &Files,
    unpinned: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    for (site, behind) in [
        ("unbound", false),
        ("unbound", true),
        ("bound", false),
        ("signature", false),
        ("signature", true),
        ("collection", false),
    ] {
        let name = format!(
            "session end fences {site} writer {} end snapshot",
            if behind { "behind" } else { "ahead of" }
        );
        if !selected(&name) {
            continue;
        }
        reset_with_bindings(
            run,
            tab,
            worker,
            if site == "signature" { unpinned } else { files },
            site != "unbound",
        )
        .await?;
        if site == "collection" {
            unresolved(run, worker).await?;
        }
        let before = run.inspect(worker).await?;
        if site == "unbound" {
            let approved = before["setup"].as_array().is_some_and(|machines| {
                machines.iter().any(|m| m["entry"]["machine"] == "unpinned")
            });
            let bound = before["sessions"].as_array().is_some_and(|sessions| {
                sessions.iter().any(|s| {
                    s["bound_set"]
                        .as_array()
                        .is_some_and(|machines| machines.contains(&json!("unpinned")))
                })
            });
            if !approved || bound {
                return Err("admission fixture must be approved and unbound before ending".into());
            }
        }
        let boundary = if site == "signature" {
            "signature_writer"
        } else {
            "connection_writer"
        };
        point(run, worker, boundary).await?;
        let mut args = request(
            run,
            if site == "signature" {
                "echo SigLevel = Never >> /etc/pacman.conf"
            } else {
                "true"
            },
        );
        if site == "unbound" {
            args["machine"] = json!("unpinned");
        }
        let mut expr = run_expression(&args);
        if site == "collection" {
            expr = expr.replace("module.run_command(", "module.collect_jobs(");
        }
        start(run, worker, &expr).await?;
        wait_point(run, worker).await?;
        writer(run, worker).await?;
        if !behind {
            module(
                run,
                worker,
                "self.releasePoint();await new Promise(r=>setTimeout(r,0));return true;",
            )
            .await?;
        }
        begin_end(run, worker).await?;
        if behind {
            module(
                run,
                worker,
                "self.releasePoint();await new Promise(r=>setTimeout(r,0));return true;",
            )
            .await?;
        }
        module(
            run,
            worker,
            "self.releaseWriter();await self.writerWork;return true;",
        )
        .await?;
        let report = answer(run, worker).await?;
        let after = run.inspect(worker).await?;
        let mut case = Case::new(&name);
        case.check(
            "session-end refusal replaces admission or collected answer",
            report["outcome"]["refused"] == "journal"
                && report["outcome"]["why"] == "sessions ended",
        );
        case.check(
            "no connection or signature refusal is committed",
            before["connection_refusals"] == after["connection_refusals"]
                && before["signature_refusals"] == after["signature_refusals"],
        );
        end_open(run, worker, &mut case).await?;
        cases.push(case);
    }
    Ok(())
}

async fn bodies(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    files: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    for boundary in ["finish_writer", "response_writer"] {
        let name = format!("session end withholds completion body at {boundary}");
        if !selected(&name) {
            continue;
        }
        reset(run, tab, worker, files).await?;
        point(run, worker, boundary).await?;
        let req=json!({"machine":"fixture","messages":[{"role":"user","content":"session end body race"}]}).to_string();
        start(run,worker,&format!("(async()=>{{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.inference_request({}));}})()",json!(req))).await?;
        wait_point(run, worker).await?;
        if boundary == "finish_writer" {
            writer(run, worker).await?;
            module(
                run,
                worker,
                "self.releasePoint();await new Promise(r=>setTimeout(r,0));return true;",
            )
            .await?;
            begin_end(run, worker).await?;
            module(
                run,
                worker,
                "self.releaseWriter();await self.writerWork;return true;",
            )
            .await?;
        } else {
            begin_end(run, worker).await?;
            module(run, worker, "self.releasePoint();return true;").await?;
        }
        let report = answer(run, worker).await?;
        let state = run.inspect(worker).await?;
        let mut case = Case::new(&name);
        case.check(
            "body absent with session-end refusal and finished call metadata",
            report.get("body").is_none()
                && report["refused"] == "sessions ended"
                && report["finished"] == true
                && report["status"] == 200
                && report["call"].is_u64(),
        );
        case.check(
            "completion terminal remains committed",
            state["inference_calls"]
                .as_array()
                .is_some_and(|cs| cs.iter().any(|c| c["terminal"]["call"] == report["call"])),
        );
        end_open(run, worker, &mut case).await?;
        cases.push(case);
    }
    Ok(())
}

async fn appends(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    files: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    for site in ["command", "held", "collection"] {
        for begun in [false, true] {
            let name = format!(
                "session end {} {site} evidence append",
                if begun {
                    "completes begun"
                } else {
                    "fences queued"
                }
            );
            if !selected(&name) {
                continue;
            }
            reset(run, tab, worker, files).await?;
            if site != "command" {
                unresolved(run, worker).await?;
            }
            point(run, worker, "evidence_writer").await?;
            let log_before = run.seen.lock().unwrap().relay_log.len();
            start(run, worker, &expression(run, site, "printf evidence-race")).await?;
            wait_point(run, worker).await?;
            let before = run.inspect(worker).await?;
            if begun {
                module(run,worker,"self.moveReady=new Promise(ready=>m.test_hold_move(new Promise(release=>self.releaseMove=release),ready));self.releasePoint();await self.moveReady;return true;").await?;
            } else {
                writer(run, worker).await?;
            }
            begin_end(run, worker).await?;
            if !begun {
                module(
                    run,
                    worker,
                    "self.releasePoint();await new Promise(r=>setTimeout(r,0));return true;",
                )
                .await?;
            }
            let mut case = Case::new(&name);
            // A command normally queued its disconnect before evidence; read sites still own a channel.
            closed(run, log_before, &mut case).await;
            if begun {
                module(run, worker, "self.releaseMove();return true;").await?;
            } else {
                module(
                    run,
                    worker,
                    "self.releaseWriter();await self.writerWork;return true;",
                )
                .await?;
            }
            let report = answer(run, worker).await?;
            let after = run.inspect(worker).await?;
            case.check(
                "begun append completes whole; queued append commits nothing",
                if begun {
                    after["jobs"] != before["jobs"]
                } else {
                    after["jobs"] == before["jobs"] && after["calls"] == before["calls"]
                },
            );
            if !begun && site == "command" {
                case.check(
                    "uncommitted job record is reported as unresolved evidence",
                    report["outcome"]["unresolved"] == true
                        && report["outcome"].get("job_record").is_some(),
                );
            }
            end_open(run, worker, &mut case).await?;
            if site == "command" && !begun {
                run.aggregator.state.lock().unwrap().hold_revoke = false;
                restart(run, tab, worker).await?;
                let replay = run.inspect(worker).await?;
                case.check(
                    "uncommitted evidence leaves command unresolved after unlock",
                    replay["calls"].as_array().is_some_and(|cs| {
                        cs.iter().any(|c| {
                            c["call"] == report["outcome"]["call"] && c["state"] == "unresolved"
                        })
                    }),
                );
            }
            cases.push(case);
        }
    }
    Ok(())
}

async fn cold_probe(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    files: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let name = "session end fences a cold probe queued ahead of the end writer";
    if !selected(name) {
        return Ok(());
    }
    reset(run, tab, worker, files).await?;
    module(
        run,
        worker,
        "await m.test_cold_inference_route();return true;",
    )
    .await?;
    let count = || {
        run.aggregator
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| {
                r.starts_with(b"OPTIONS / ")
                    && String::from_utf8_lossy(r)
                        .to_ascii_lowercase()
                        .contains("x-inference-account: probe-placeholder")
            })
            .count()
    };
    let probes = count();
    point(run, worker, "route_writer").await?;
    let req = json!({"machine":"fixture","messages":[{"role":"user","content":"cold route"}]})
        .to_string();
    start(run,worker,&format!("(async()=>{{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.inference_request({}));}})()",json!(req))).await?;
    wait_point(run, worker).await?;
    writer(run, worker).await?;
    module(
        run,
        worker,
        "self.releasePoint();await new Promise(r=>setTimeout(r,0));return true;",
    )
    .await?;
    begin_end(run, worker).await?;
    module(
        run,
        worker,
        "self.releaseWriter();await self.writerWork;return true;",
    )
    .await?;
    let report = answer(run, worker).await?;
    let sent = settle_for(run.seen, 5, |_| count() > probes).await;
    let mut case = Case::new(name);
    case.check(
        "stopped inference refuses its cold probe",
        report["refused"] == "sessions ended" && report.get("call").is_none(),
    );
    case.check(
        "only the revoke probe is sent after ending",
        sent && count() == probes + 1,
    );
    let original_key_id = key_id(run, &last_key(run));
    let revoke = settle_for(run.seen, 5, |_| revoke_sent(run, &original_key_id)).await;
    case.check(
        "revoke itself is sent for the original known identity",
        revoke,
    );
    end_open(run, worker, &mut case).await?;
    cases.push(case);
    Ok(())
}

async fn revoke_probe_control(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    files: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let name = "revoke cold probe control during session end";
    if !selected(name) {
        return Ok(());
    }
    reset(run, tab, worker, files).await?;
    module(
        run,
        worker,
        "await m.test_cold_inference_route();return true;",
    )
    .await?;
    let before = run.aggregator.requests.lock().unwrap().len();
    begin_end(run, worker).await?;
    let id = key_id(run, &last_key(run));
    let sent = settle_for(run.seen, 5, |_| revoke_sent(run, &id)).await;
    let mut case = Case::new(name);
    case.check(
        "revoke and its dedicated probe still go out",
        sent && run.aggregator.requests.lock().unwrap()[before..]
            .iter()
            .any(|r| {
                r.starts_with(b"OPTIONS / ")
                    && String::from_utf8_lossy(r).contains("probe-placeholder")
            }),
    );
    end_open(run, worker, &mut case).await?;
    cases.push(case);
    Ok(())
}

async fn running_command(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    files: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let name =
        "session end closes a running command without DISCONNECT and preserves unresolved replay";
    if !selected(name) {
        return Ok(());
    }
    reset(run, tab, worker, files).await?;
    let log_before = run.seen.lock().unwrap().relay_log.len();
    let ends = run.seen.lock().unwrap().ssh_ends.len();
    start(
        run,
        worker,
        &expression(run, "command", "sleep 4; printf detached-end"),
    )
    .await?;
    let (call, job) = job_cases::wait_launch(run, worker, 0).await?;
    let before = run.inspect(worker).await?;
    begin_end(run, worker).await?;
    let mut case = Case::new(name);
    closed(run, log_before, &mut case).await;
    let report = answer(run, worker).await?;
    case.check(
        "sent command reports unresolved with session end and its send history",
        report["outcome"]["call"] == call
            && report["outcome"]["unresolved"] == true
            && report["outcome"]["why"] == "sessions ended while awaiting job record"
            && report["outcome"].get("not_sent").is_none(),
    );
    let ssh_ends = run.seen.lock().unwrap().ssh_ends[ends..].to_vec();
    case.check(
        "sshd received transport EOF, not SSH DISCONNECT",
        ssh_ends.iter().any(|s| s.starts_with("Err(")) && ssh_ends.iter().all(|s| s != "Ok(())"),
    );

    let after = run.inspect(worker).await?;
    case.check(
        "no command evidence or terminal is appended",
        after["jobs"] == before["jobs"] && after["calls"] == before["calls"],
    );
    end_open(run, worker, &mut case).await?;
    run.aggregator.state.lock().unwrap().hold_revoke = false;
    restart(run, tab, worker).await?;
    let replay = run.inspect(worker).await?;
    case.check(
        "call reads unresolved after unlock",
        replay["calls"].as_array().is_some_and(|cs| {
            cs.iter()
                .any(|c| c["call"] == call && c["state"] == "unresolved")
        }),
    );
    job_cases::wait_end(run, &job).await?;
    fresh_pace(run.relay);
    let collected = run.harness_collect(worker, request(run, "")).await?;
    case.check(
        "command is collectable after unlock",
        collected["outcome"]["collected"]
            .as_array()
            .is_some_and(|rs| {
                rs.iter()
                    .any(|r| r["call"] == call && r["state"] == "finished")
            }),
    );
    cases.push(case);
    Ok(())
}

async fn rekey_append(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    files: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    for site in ["command", "held", "collection"] {
        let name =
            format!("session end closes {site} during begun evidence append with rekey stalled");
        if !selected(&name) {
            continue;
        }
        reset(run, tab, worker, files).await?;
        if site != "command" {
            unresolved(run, worker).await?;
        }
        let log_before = run.seen.lock().unwrap().relay_log.len();
        point(run, worker, "session_evidence").await?;
        start(run, worker, &expression(run, site, "printf rekey-evidence")).await?;
        wait_point(run, worker).await?;
        let rekey_log = run.seen.lock().unwrap().relay_log.len();
        run.relay.session_gate.arm("rekey");
        module(run,worker,"m.test_rekey_session('session_evidence');self.moveReady=new Promise(ready=>m.test_hold_move(new Promise(release=>self.releaseMove=release),ready));self.releasePoint();await self.moveReady;return true;").await?;
        let reached = settle_for(run.seen, 5, |_| {
            run.relay.session_gate.reached.load(Ordering::SeqCst)
        })
        .await;
        if !reached {
            return Err(format!(
                "could not arrange {name}: rekey did not reach relay"
            ));
        }
        let mut case = Case::new(&name);
        case.check(
            "rekey request emits a client SSH packet",
            settle_for(run.seen, 5, |seen| {
                seen.relay_log[rekey_log..].iter().any(|(_, event)| {
                    matches!(
                        event,
                        fixtures::Event::Frame("binary")
                            | fixtures::Event::Forwarded(fixtures::Toward::Destination, _)
                    )
                })
            })
            .await,
        );
        begin_end(run, worker).await?;
        closed(run, log_before, &mut case).await;
        case.check("append still suspended after socket closes",module(run,worker,"let done=false;self.sessionResult.then(()=>done=true);await new Promise(r=>setTimeout(r,0));return done;").await?==false);
        module(run, worker, "self.releaseMove();return true;").await?;
        let report = answer(run, worker).await?;
        let evidence = if site == "command" {
            report["outcome"]["job_record"].clone()
        } else {
            report["outcome"][if site == "held" { "calls" } else { "collected" }]
                .as_array()
                .and_then(|rs| rs.iter().find(|r| r["number"].is_u64()))
                .cloned()
                .unwrap_or(Value::Null)
        };
        case.check(
            "begun evidence append still completes",
            evidence["number"].is_u64() && evidence["state"] == "finished",
        );
        case.check(
            "late committed outcome is historical and never actionable",
            if site == "command" {
                report["outcome"]["historical"] == true
                    && report["outcome"]["actionable"] == false
                    && report["outcome"].get("done").is_none()
                    && report["outcome"]["call"] == evidence["call"]
                    && report["outcome"]["terminal"] == evidence["number"]
            } else {
                evidence["historical"] == true && evidence["actionable"] == false
            },
        );
        let files = store_files(&run.dump(tab).await?);
        let opened = reader::read(&files, PASSPHRASE)?;
        let committed = opened
            .records
            .iter()
            .find(|(number, _)| Some(*number) == evidence["number"].as_u64())
            .and_then(|(_, bytes)| serde_json::from_slice::<Value>(bytes).ok());
        case.check(
            "independent reader proves exact original call job boot record and terminal",
            committed.as_ref().is_some_and(|v| {
                v["job_terminal"]["call"] == evidence["call"]
                    && v["job_terminal"]["job"] == evidence["job"]
                    && v["job_terminal"]["record"] == evidence["record"]
            }),
        );
        if site == "command" {
            case.check(
                "late terminal retains exact output and exit outcome",
                evidence["stdout"] == "rekey-evidence" && evidence["exit_status"] == 0,
            );
        }
        let sends = run.seen.lock().unwrap().ssh_exec.len();
        tokio::time::sleep(Duration::from_millis(50)).await;
        case.check(
            "late evidence causes no next SSH effect",
            run.seen.lock().unwrap().ssh_exec.len() == sends,
        );
        end_open(run, worker, &mut case).await?;
        cases.push(case);
    }
    Ok(())
}

pub(super) async fn run(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let saved = store_files(&run.dump(tab).await?);
    let mnemonic = reader::read(&saved, PASSPHRASE)?.mnemonic()?;
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
    let files = reader::build(PASSPHRASE, &events);
    let identity = events[2]["setup"]["approval"]["entries"][0]["identity"].clone();
    let session = format!("session-{}", events.len());
    events.push(json!({"exposure":{"session":session,"bound_set":[{"machine":"fixture","identity":identity}],"accepted_modes":["no_artifact_pin"]}}));
    let unpinned = reader::build(PASSPHRASE, &events);
    cold_probe(run, tab, worker, &files, cases).await?;
    revoke_probe_control(run, tab, worker, &files, cases).await?;
    network(run, tab, worker, &files, cases).await?;
    running_command(run, tab, worker, &files, cases).await?;
    rekey_append(run, tab, worker, &files, cases).await?;
    admission(run, tab, worker, &files, &unpinned, cases).await?;
    bodies(run, tab, worker, &files, cases).await?;
    appends(run, tab, worker, &files, cases).await?;
    run.aggregator.state.lock().unwrap().hold_revoke = false;
    run.relay.session_gate.clear();
    *worker = run.reload(tab, worker).await?;
    run.put(tab, &saved).await?;
    *worker = run.reload(tab, worker).await?;
    resume(run, tab, worker).await
}
