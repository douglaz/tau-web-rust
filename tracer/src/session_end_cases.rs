//! Session-end races observed while revocation keeps the worker alive.
use super::*;
use std::sync::atomic::Ordering;

fn selected(name: &str) -> bool {
    selection::value("TAU_TRACER_SESSION_END").map_or(true, |s| {
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
async fn begin_end(
    run: &Run<'_>,
    worker: &Worker,
    input: Option<&fixture_inputs::Input>,
) -> Result<(), String> {
    run.aggregator.state.lock().unwrap().hold_revoke = true;
    let expression = "self.endDone=false;self.endWork=m.end_sessions().then(()=>self.endDone=true);await new Promise(r=>setTimeout(r,0));return true;";
    if let Some(input) = input {
        fixture_inputs::end_module(input, run, worker, expression).await?;
    } else {
        module(run, worker, expression).await?;
    }
    Ok(())
}
async fn end_open(run: &Run<'_>, worker: &Worker, case: &mut Case) -> Result<(), String> {
    case.check(
        "session_end_cases.a001",
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
    *worker = run
        .reload("session_end_cases.rs::reload#1", tab, worker)
        .await?;
    if completion::rejects(
        "session-end.previous_ssh.closed",
        !run.sshd
            .all_ended_at(Some("session.reset.previous_ssh"), json!({}))
            .await,
    ) {
        return Err("previous fixture SSH connection did not end".into());
    }
    run.put(tab, files).await?;
    *worker = run
        .reload("session_end_cases.rs::reload#2", tab, worker)
        .await?;
    if bind_all {
        resume(run, tab, worker).await?;
    } else {
        origin(run, worker).await?;
        run.submit(tab, "unlock", PASSPHRASE).await?;
        setup_cases::click(run, tab, "[data-bind=fixture]").await?;
        let mut bound = false;
        {
            let observation = observer::Call::begin(
                "session_end.unbound.fixture_bound",
                "serial.observation",
                Some(&tab.session),
                json!({"bound":300,"false_sleep_ms":10,"requires_ready":true,"machine":"first","bind_all":bind_all}),
            );
            for poll in 0..300 {
                observation.attempt(poll + 1);
                bound = observation.inspect(run, worker).await?["sessions"]
                    .as_array()
                    .is_some_and(|sessions| {
                        sessions
                            .iter()
                            .any(|s| s["bound_set"] == json!(["fixture"]))
                    });
                if observation.poll(poll + 1, bound) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        if completion::rejects("session-end.fixture.direct_binding", !bound) {
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
    if completion::rejects(
        "session-end.fixture.inference_finished",
        result["finished"] != true,
    ) {
        return Err(format!("session-end fixture inference: {result}"));
    }
    fresh_pace(run.relay);
    Ok(())
}
async fn unresolved(run: &Run<'_>, worker: &Worker) -> Result<(), String> {
    let result = run
        .harness_run(
            "session_end_cases.rs#1",
            worker,
            request(run, "close-without-status"),
        )
        .await?;
    if completion::rejects(
        "session-end.fixture.unresolved",
        result["outcome"]["unresolved"] != true,
    ) {
        return Err(format!("session-end fixture unresolved call: {result}"));
    }
    fresh_pace(run.relay);
    Ok(())
}
pub(super) async fn closed(
    site: &'static str,
    run: &Run<'_>,
    from: &fixture_inputs::Input,
    case: &mut Case,
) {
    let observation = observer::Call::begin(
        site,
        "session.closed",
        None,
        json!({"from":"independent original pre-send relay log cursor"}),
    );
    observation.fact("fixture_input", causal::source_seen(run.seen));
    let relay_closed = settle_for(
        "session.closed.relay",
        run.seen,
        5,
        json!({"from":"original source caller relay snapshot"}),
        |seen, observation| fixture_predicates::relay_closed(seen, from, observation),
    )
    .await;
    case.check(
        "session_end_cases.a002",
        "relay observes browser socket close during end step",
        relay_closed,
    );
    let ssh_closed = settle_for(
        "session.closed.ssh",
        run.seen,
        5,
        json!({}),
        |_, observation| {
            observation.ssh_counter(run.sshd, "accepted", &run.sshd.accepted)
                == observation.ssh_counter(run.sshd, "ended", &run.sshd.ended)
        },
    )
    .await;
    case.check(
        "session_end_cases.a003",
        "every dialed sshd observes connection end",
        ssh_closed,
    );
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
            let target_case = catalogue::case_id("session_end_cases.c001", &name);
            if site != "command" {
                unresolved(run, worker).await?;
            }
            let (log_before, exec_before, auth_before, channel_before) = {
                let s = run.seen.lock().unwrap();
                (
                    fixture_inputs::relay(run, worker, &target_case, "relay", &s),
                    s.ssh_exec.len(),
                    s.ssh_auth.len(),
                    s.ssh_channels,
                )
            };
            let accepted_before = run.sshd.accepted.load(Ordering::SeqCst);
            let rekey = stage.ends_with("-rekey");
            let rekey_log = fixture_inputs::relay(
                run,
                worker,
                &target_case,
                "packet",
                &run.seen.lock().unwrap(),
            );
            let boundary = if stage == "auth-rekey" {
                "session_authentication"
            } else {
                "session_connected"
            };
            let banners = run.seen.lock().unwrap().ssh_authentication_banners;
            if stage == "auth-rekey" {
                run.sshd.auth_banner.store(true, Ordering::SeqCst);
            }
            let mut gate = None;
            if rekey {
                point(run, worker, boundary).await?;
            } else {
                gate = Some(fixture_inputs::arm(run, worker, &target_case, stage));
            }
            fixture_inputs::session_start(
                &log_before,
                gate.as_ref(),
                run,
                worker,
                &expression(run, site, "printf should-not-launch"),
            )
            .await?;
            if rekey {
                wait_point(run, worker).await?;
                gate = Some(fixture_inputs::arm(run, worker, &target_case, "rekey"));
                fixture_inputs::rekey_module(
                    &rekey_log,
                    gate.as_ref().unwrap(),
                    run,
                    worker,
                    &format!(
                        "m.test_rekey_session({});self.releasePoint();return true;",
                        json!(boundary)
                    ),
                )
                .await?;
            }
            let reached = settle_for(
                "session.network.stage_reached",
                run.seen,
                5,
                json!({"site":site,"stage":stage}),
                |_, observation| {
                    fixture_predicates::stage(run, gate.as_ref().unwrap(), observation)
                },
            )
            .await;
            if completion::rejects("session-end.network.stage_reached", !reached) {
                return Err(format!(
                    "could not arrange {name}: fixture never reached held stage"
                ));
            }
            let mut case = Case::new("session_end_cases.c001", &name);
            if stage == "auth-rekey" {
                case.check(
                    "session_end_cases.a004",
                    "authentication service reached before rekey starts",
                    run.seen.lock().unwrap().ssh_authentication_banners == banners + 1,
                );
            }
            if rekey {
                case.check(
                    "session_end_cases.a005",
                    "requested rekey emits a client SSH packet before session end",
                    settle_for(
                        "session.network.client_packet",
                        run.seen,
                        5,
                        json!({"site":site,"stage":stage,"cursor":"pre-rekey_log"}),
                        |seen, observation| {
                            fixture_predicates::packet(seen, &rekey_log, observation)
                        },
                    )
                    .await,
                );
            }
            begin_end(run, worker, Some(&log_before)).await?;
            closed("session.network.closed", run, &log_before, &mut case).await;
            let report = answer(run, worker).await?;
            case.check(
                "session_end_cases.a006",
                "stopped request answers before termination",
                report.get("wait_expired").is_none(),
            );
            if site == "command" {
                case.check(
                    "session_end_cases.a007",
                    "command stopped before intent reports session-end journal refusal",
                    report["outcome"]["refused"] == "journal"
                        && report["outcome"]["why"] == "sessions ended",
                );
            }
            case.check(
                "session_end_cases.a008",
                "no command or job-read exec reaches sshd",
                run.seen.lock().unwrap().ssh_exec.len() == exec_before,
            );
            if stage == "challenge" {
                case.check(
                    "session_end_cases.a009",
                    "before relay dial sshd sees no contact",
                    run.sshd.accepted.load(Ordering::SeqCst) == accepted_before,
                );
            }
            case.check(
                "session_end_cases.a010",
                "no later SSH channel is opened",
                run.seen.lock().unwrap().ssh_channels == channel_before,
            );
            if ["identification", "kex"].contains(&stage) {
                case.check(
                    "session_end_cases.a011",
                    "no later authentication stage is sent",
                    run.seen.lock().unwrap().ssh_auth.len() == auth_before,
                );
            }
            end_open(run, worker, &mut case).await?;
            case.finish(cases);
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
            if completion::rejects("session-end.admission.approved_unbound", !approved || bound) {
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
        begin_end(run, worker, None).await?;
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
        let mut case = Case::new("session_end_cases.c002", &name);
        case.check(
            "session_end_cases.a012",
            "session-end refusal replaces admission or collected answer",
            report["outcome"]["refused"] == "journal"
                && report["outcome"]["why"] == "sessions ended",
        );
        case.check(
            "session_end_cases.a013",
            "no connection or signature refusal is committed",
            before["connection_refusals"] == after["connection_refusals"]
                && before["signature_refusals"] == after["signature_refusals"],
        );
        end_open(run, worker, &mut case).await?;
        case.finish(cases);
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
            begin_end(run, worker, None).await?;
            module(
                run,
                worker,
                "self.releaseWriter();await self.writerWork;return true;",
            )
            .await?;
        } else {
            begin_end(run, worker, None).await?;
            module(run, worker, "self.releasePoint();return true;").await?;
        }
        let report = answer(run, worker).await?;
        let state = run.inspect(worker).await?;
        let mut case = Case::new("session_end_cases.c003", &name);
        case.check(
            "session_end_cases.a014",
            "body absent with session-end refusal and finished call metadata",
            report.get("body").is_none()
                && report["refused"] == "sessions ended"
                && report["finished"] == true
                && report["status"] == 200
                && report["call"].is_u64(),
        );
        case.check(
            "session_end_cases.a015",
            "completion terminal remains committed",
            state["inference_calls"]
                .as_array()
                .is_some_and(|cs| cs.iter().any(|c| c["terminal"]["call"] == report["call"])),
        );
        end_open(run, worker, &mut case).await?;
        case.finish(cases);
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
            let target_case = catalogue::case_id("session_end_cases.c004", &name);
            if site != "command" {
                unresolved(run, worker).await?;
            }
            point(run, worker, "evidence_writer").await?;
            let log_before = fixture_inputs::relay(
                run,
                worker,
                &target_case,
                "relay",
                &run.seen.lock().unwrap(),
            );
            fixture_inputs::session_start(
                &log_before,
                None,
                run,
                worker,
                &expression(run, site, "printf evidence-race"),
            )
            .await?;
            wait_point(run, worker).await?;
            let before = run.inspect(worker).await?;
            if begun {
                module(run,worker,"self.moveReady=new Promise(ready=>m.test_hold_move(new Promise(release=>self.releaseMove=release),ready));self.releasePoint();await self.moveReady;return true;").await?;
            } else {
                writer(run, worker).await?;
            }
            begin_end(run, worker, Some(&log_before)).await?;
            if !begun {
                module(
                    run,
                    worker,
                    "self.releasePoint();await new Promise(r=>setTimeout(r,0));return true;",
                )
                .await?;
            }
            let mut case = Case::new("session_end_cases.c004", &name);
            // A command normally queued its disconnect before evidence; read sites still own a channel.
            closed("session.append.closed", run, &log_before, &mut case).await;
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
                "session_end_cases.a016",
                "begun append completes whole; queued append commits nothing",
                if begun {
                    after["jobs"] != before["jobs"]
                } else {
                    after["jobs"] == before["jobs"] && after["calls"] == before["calls"]
                },
            );
            if !begun && site == "command" {
                case.check(
                    "session_end_cases.a017",
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
                    "session_end_cases.a018",
                    "uncommitted evidence leaves command unresolved after unlock",
                    replay["calls"].as_array().is_some_and(|cs| {
                        cs.iter().any(|c| {
                            c["call"] == report["outcome"]["call"] && c["state"] == "unresolved"
                        })
                    }),
                );
            }
            case.finish(cases);
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
    let target_case = catalogue::case_id("session_end_cases.c005", name);
    let probes_input = fixture_inputs::probes(run, worker, &target_case);
    let probes = fixture_inputs::probe_baseline(&probes_input);
    point(run, worker, "route_writer").await?;
    let req = json!({"machine":"fixture","messages":[{"role":"user","content":"cold route"}]})
        .to_string();
    fixture_inputs::cold_start(&probes_input,run,worker,&format!("(async()=>{{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.inference_request({}));}})()",json!(req))).await?;
    wait_point(run, worker).await?;
    writer(run, worker).await?;
    module(
        run,
        worker,
        "self.releasePoint();await new Promise(r=>setTimeout(r,0));return true;",
    )
    .await?;
    begin_end(run, worker, Some(&probes_input)).await?;
    module(
        run,
        worker,
        "self.releaseWriter();await self.writerWork;return true;",
    )
    .await?;
    let report = answer(run, worker).await?;
    let sent = settle_for(
        "session.cold_probe.sent",
        run.seen,
        5,
        json!({"count_origin":"pre-probe count"}),
        |_, observation| fixture_predicates::probe_ready(run, &probes_input, observation),
    )
    .await;
    let mut case = Case::new("session_end_cases.c005", name);
    case.check(
        "session_end_cases.a019",
        "stopped inference refuses its cold probe",
        report["refused"] == "sessions ended" && report.get("call").is_none(),
    );
    case.check(
        "session_end_cases.a020",
        "only the revoke probe is sent after ending",
        sent && count() == probes + 1,
    );
    let original_key_id = fixture_inputs::key(run, worker, &target_case);
    let revoke = settle_for(
        "session.cold_probe.revoke",
        run.seen,
        5,
        json!({"key":"source original session key"}),
        |_, observation| fixture_predicates::revoke(run, &original_key_id, observation),
    )
    .await;
    case.check(
        "session_end_cases.a021",
        "revoke itself is sent for the original known identity",
        revoke,
    );
    end_open(run, worker, &mut case).await?;
    case.finish(cases);
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
    let target_case = catalogue::case_id("session_end_cases.c006", name);
    let end_input = fixture_inputs::end_marker(run, worker, &target_case);
    begin_end(run, worker, Some(&end_input)).await?;
    let id = fixture_inputs::key(run, worker, &target_case);
    let sent = settle_for(
        "session.revoke_control.sent",
        run.seen,
        5,
        json!({"key":"source original session key"}),
        |_, observation| fixture_predicates::revoke(run, &id, observation),
    )
    .await;
    let mut case = Case::new("session_end_cases.c006", name);
    case.check(
        "session_end_cases.a022",
        "revoke and its dedicated probe still go out",
        sent && run.aggregator.requests.lock().unwrap()[before..]
            .iter()
            .any(|r| {
                r.starts_with(b"OPTIONS / ")
                    && String::from_utf8_lossy(r).contains("probe-placeholder")
            }),
    );
    end_open(run, worker, &mut case).await?;
    case.finish(cases);
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
    let target_case = catalogue::case_id("session_end_cases.c007", name);
    let log_before = fixture_inputs::relay(
        run,
        worker,
        &target_case,
        "relay",
        &run.seen.lock().unwrap(),
    );
    let ends = run.seen.lock().unwrap().ssh_ends.len();
    let expression = expression(run, "command", "sleep 4; printf detached-end");
    let source = causal::job_zero("session_end.running", worker, &expression);
    fixture_inputs::running_page(
        &log_before,
        source,
        run,
        worker,
        &format!("self.sessionResult={expression};void 0"),
    )
    .await?;
    let (call, job) =
        job_cases::wait_launch("session_end.running.wait_launch", source, run, worker, 0).await?;
    let before = run.inspect(worker).await?;
    begin_end(run, worker, Some(&log_before)).await?;
    let mut case = Case::new("session_end_cases.c007", name);
    closed("session.running.closed", run, &log_before, &mut case).await;
    let report = answer(run, worker).await?;
    case.check(
        "session_end_cases.a023",
        "sent command reports unresolved with session end and its send history",
        report["outcome"]["call"] == call
            && report["outcome"]["unresolved"] == true
            && report["outcome"]["why"] == "sessions ended while awaiting job record"
            && report["outcome"].get("not_sent").is_none(),
    );
    let ssh_ends = run.seen.lock().unwrap().ssh_ends[ends..].to_vec();
    case.check(
        "session_end_cases.a024",
        "sshd received transport EOF, not SSH DISCONNECT",
        ssh_ends.iter().any(|s| s.starts_with("Err(")) && ssh_ends.iter().all(|s| s != "Ok(())"),
    );

    let after = run.inspect(worker).await?;
    case.check(
        "session_end_cases.a025",
        "no command evidence or terminal is appended",
        after["jobs"] == before["jobs"] && after["calls"] == before["calls"],
    );
    end_open(run, worker, &mut case).await?;
    run.aggregator.state.lock().unwrap().hold_revoke = false;
    restart(run, tab, worker).await?;
    let replay = run.inspect(worker).await?;
    case.check(
        "session_end_cases.a026",
        "call reads unresolved after unlock",
        replay["calls"].as_array().is_some_and(|cs| {
            cs.iter()
                .any(|c| c["call"] == call && c["state"] == "unresolved")
        }),
    );
    job_cases::wait_end(
        "session_end.running.wait_end",
        "session_end.running",
        run,
        &job,
    )
    .await?;
    fresh_pace(run.relay);
    let collected = run
        .harness_collect("session_end_cases.rs#2", worker, request(run, ""))
        .await?;
    case.check(
        "session_end_cases.a027",
        "command is collectable after unlock",
        collected["outcome"]["collected"]
            .as_array()
            .is_some_and(|rs| {
                rs.iter()
                    .any(|r| r["call"] == call && r["state"] == "finished")
            }),
    );
    case.finish(cases);
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
        let target_case = catalogue::case_id("session_end_cases.c008", &name);
        if site != "command" {
            unresolved(run, worker).await?;
        }
        let log_before = fixture_inputs::relay(
            run,
            worker,
            &target_case,
            "relay",
            &run.seen.lock().unwrap(),
        );
        point(run, worker, "session_evidence").await?;
        fixture_inputs::session_start(
            &log_before,
            None,
            run,
            worker,
            &expression(run, site, "printf rekey-evidence"),
        )
        .await?;
        wait_point(run, worker).await?;
        let rekey_log = fixture_inputs::relay(
            run,
            worker,
            &target_case,
            "packet",
            &run.seen.lock().unwrap(),
        );
        let gate = fixture_inputs::arm(run, worker, &target_case, "rekey");
        fixture_inputs::rekey_module(&rekey_log,&gate,run,worker,"m.test_rekey_session('session_evidence');self.moveReady=new Promise(ready=>m.test_hold_move(new Promise(release=>self.releaseMove=release),ready));self.releasePoint();await self.moveReady;return true;").await?;
        let reached = settle_for(
            "session.rekey.stage_reached",
            run.seen,
            5,
            json!({"site":site,"stage":"rekey"}),
            |_, observation| fixture_predicates::stage(run, &gate, observation),
        )
        .await;
        if completion::rejects("session-end.rekey.actual_stage", !reached) {
            return Err(format!(
                "could not arrange {name}: rekey did not reach relay"
            ));
        }
        let mut case = Case::new("session_end_cases.c008", &name);
        case.check(
            "session_end_cases.a028",
            "rekey request emits a client SSH packet",
            settle_for(
                "session.rekey.client_packet",
                run.seen,
                5,
                json!({"site":site,"cursor":"pre-rekey_log"}),
                |seen, observation| fixture_predicates::packet(seen, &rekey_log, observation),
            )
            .await,
        );
        begin_end(run, worker, Some(&log_before)).await?;
        closed("session.rekey.closed", run, &log_before, &mut case).await;
        case.check("session_end_cases.a029", "append still suspended after socket closes",module(run,worker,"let done=false;self.sessionResult.then(()=>done=true);await new Promise(r=>setTimeout(r,0));return done;").await?==false);
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
            "session_end_cases.a030",
            "begun evidence append still completes",
            evidence["number"].is_u64() && evidence["state"] == "finished",
        );
        case.check(
            "session_end_cases.a031",
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
        let files = store_files(&run.dump_at("file.session_end_cases.dump.001", tab).await?);
        let opened = reader::read_at("reader.call.session_end.rekey_evidence", &files, PASSPHRASE)?;
        let committed = opened
            .records
            .iter()
            .find(|(number, _)| Some(*number) == evidence["number"].as_u64())
            .and_then(|(_, bytes)| crate::journal::event(bytes).ok());
        case.check(
            "session_end_cases.a032",
            "independent reader proves exact original call job boot record and terminal",
            committed.as_ref().is_some_and(|v| {
                v["job_terminal"]["call"] == evidence["call"]
                    && v["job_terminal"]["job"] == evidence["job"]
                    && v["job_terminal"]["record"] == evidence["record"]
            }),
        );
        if site == "command" {
            case.check(
                "session_end_cases.a033",
                "late terminal retains exact output and exit outcome",
                evidence["stdout"] == "rekey-evidence" && evidence["exit_status"] == 0,
            );
        }
        let sends = run.seen.lock().unwrap().ssh_exec.len();
        tokio::time::sleep(Duration::from_millis(50)).await;
        case.check(
            "session_end_cases.a034",
            "late evidence causes no next SSH effect",
            run.seen.lock().unwrap().ssh_exec.len() == sends,
        );
        end_open(run, worker, &mut case).await?;
        case.finish(cases);
    }
    Ok(())
}

pub(super) async fn run(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let _scenario_span = completion::scenario("session_end_cases.run");
    let saved = store_files(&run.dump_at("file.session_end_cases.dump.002", tab).await?);
    let mnemonic = reader::read_at("reader.call.session_end.original", &saved, PASSPHRASE)?
        .mnemonic_at("reader.aux.call.session_end.original.mnemonic")?;
    let mut events = vec![json!({"seed":{"mnemonic":mnemonic}})];
    events.extend(reader::setup_events_at(
        "reader.aux.call.session_end.setup",
        &mnemonic,
        &["fixture", "fixture-other", "unpinned"],
    ));
    for machine in ["fixture", "fixture-other", "unpinned"] {
        events.push(
            json!({"setup":{"class":{"machine":machine,"answer":"no","class":"single_purpose"}}}),
        );
    }
    let files = reader::build_at("file.session_end_cases.build.001", PASSPHRASE, &events);
    let identity = events[2]["setup"]["approval"]["entries"][0]["identity"].clone();
    let session = format!("session-{}", events.len());
    events.push(json!({"exposure":{"inference_approval":crate::file_recipes::synthetic_approval(),"session":session,"bound_set":[{"machine":"fixture","identity":identity}],"accepted_modes":["no_artifact_pin"]}}));
    let unpinned = reader::build_at("file.session_end_cases.build.002", PASSPHRASE, &events);
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
    *worker = run
        .reload("session_end_cases.rs::reload#3", tab, worker)
        .await?;
    run.put(tab, &saved).await?;
    *worker = run
        .reload("session_end_cases.rs::reload#4", tab, worker)
        .await?;
    resume(run, tab, worker).await
}
