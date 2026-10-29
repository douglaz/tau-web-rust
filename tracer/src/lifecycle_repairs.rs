//! Deterministic races at the actual worker consumers and release boundaries.
use super::*;

async fn fresh(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
) -> Result<String, String> {
    reset(run, tab, worker, saved).await?;
    let result = infer(run, worker).await?;
    if result["finished"] != true || result.get("body").is_none() {
        return Err(format!(
            "lifecycle race prerequisite did not reach completion: {result}"
        ));
    }
    run.inspect(worker).await?["sessions"]
        .as_array()
        .and_then(|ss| ss.iter().find(|s| s["bound_set"] == json!(["fixture"])))
        .and_then(|s| s["identity"].as_str())
        .map(str::to_owned)
        .ok_or("fixture session".into())
}
async fn hold(run: &Run<'_>, worker: &Worker, point: &str) -> Result<(), String> {
    module(run,worker,&format!("self.raceReady=new Promise(ready=>m.test_hold_session_point({},new Promise(release=>self.raceRelease=release),ready));return true;",json!(point))).await?;
    Ok(())
}
async fn transition(
    run: &Run<'_>,
    worker: &Worker,
    session: &str,
    kind: &str,
) -> Result<(), String> {
    if kind == "expired" {
        let state = run.inspect(worker).await?;
        let mint = state["inference_calls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["kind"] == "mint" && c["intent"]["mint"]["session"] == session)
            .ok_or("mint")?;
        let intent = &mint["intent"]["mint"];
        let clock = &intent["evidence"]["clock"];
        let delta = intent["expires"].as_u64().ok_or("expiry")?
            - clock["latest"].as_u64().ok_or("anchor")?;
        module(
            run,
            worker,
            &format!(
                "return m.test_clock_sample({},{});",
                json!(
                    (clock["sent"]["monotonic"].as_u64().unwrap() + delta * 1_000_000).to_string()
                ),
                json!((clock["sent"]["wall"].as_u64().unwrap() + delta * 1_000_000).to_string())
            ),
        )
        .await?;
    } else if kind != "eligible" {
        module(
            run,
            worker,
            &format!(
                "await m.test_session_transition({},{});return true;",
                json!(session),
                json!(kind)
            ),
        )
        .await?;
    }
    Ok(())
}
async fn status(run: &Run<'_>, worker: &Worker) -> Result<(), String> {
    module(
        run,
        worker,
        "await m.publish_report(m.publication_generation(),'',await m.open());return true;",
    )
    .await?;
    Ok(())
}

pub(super) async fn run(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    mint_custody(run, tab, worker, saved, cases).await?;
    clock_terminal(run, tab, worker, saved, cases).await?;
    command_writer(run, tab, worker, saved, cases).await?;
    command_release(run, tab, worker, saved, cases).await?;
    source_append(run, tab, worker, saved, cases).await?;
    documents(run, tab, worker, saved, cases).await?;
    publications(run, tab, worker, saved, cases).await?;
    prepared_publication(run, tab, worker, saved, cases).await?;
    status_carriers(run, tab, worker, saved, cases).await?;
    reset(run, tab, worker, saved).await
}

async fn clock_terminal(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    for begun in [false, true] {
        let session = fresh(run, tab, worker, saved).await?;
        let before = run.inspect(worker).await?;
        let original = before["sessions"][0]["inference_limits"].clone();
        hold(run, worker, "finish_writer").await?;
        module(
            run,
            worker,
            &format!(
                "self.raceWork=m.verify_inference_clock({});await self.raceReady;return true;",
                json!(session)
            ),
        )
        .await?;
        if begun {
            module(run,worker,"self.raceMoveReady=new Promise(ready=>m.test_hold_move(new Promise(release=>self.raceMoveRelease=release),ready));self.raceRelease();await self.raceMoveReady;return true;").await?;
        }
        event(run, tab, "freeze").await?;
        module(
            run,
            worker,
            if begun {
                "self.raceMoveRelease();return true;"
            } else {
                "self.raceRelease();return true;"
            },
        )
        .await?;
        let result = module(run, worker, "return JSON.parse(await self.raceWork);").await?;
        event(run, tab, "resume").await?;
        let mut case = Case::new(&format!(
            "clock response {} terminal append cannot repair after processed freeze",
            if begun { "during begun" } else { "queued for" }
        ));
        case.check(
            "late authenticated clock terminal retains original call and refusal",
            result["finished"] == true
                && result["call"].is_u64()
                && result.get("refused").is_some(),
        );
        let state = run.inspect(worker).await?;
        case.check(
            "old observation does not establish ordinary clock validity",
            state["sessions"][0]["inference_limits"]["state"] == "clock-withheld",
        );
        let sends = run.aggregator.count("/completion");
        case.check(
            "no completion can use the invalidated observation",
            infer(run, worker).await?.get("refused").is_some()
                && run.aggregator.count("/completion") == sends,
        );
        let opened = reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
        case.check(
            "independent reader retains late measured time terminal",
            opened.records.iter().any(|(_, b)| {
                serde_json::from_slice::<Value>(b).is_ok_and(|v| {
                    v["inference_terminal"]["call"] == result["call"]
                        && v["inference_terminal"]["issuer_time"].is_u64()
                        && v["inference_terminal"]["clock_received"].is_object()
                })
            }),
        );
        let repaired = module(
            run,
            worker,
            &format!(
                "return JSON.parse(await m.verify_inference_clock({}));",
                json!(session)
            ),
        )
        .await?;
        case.check(
            "fresh current verification repairs same session",
            repaired["finished"] == true && repaired.get("refused").is_none(),
        );
        let current = run.inspect(worker).await?["sessions"][0]["inference_limits"].clone();
        for field in [
            "confirmed",
            "original_origin",
            "original_expiry",
            "observed_spend",
        ] {
            case.check(
                &format!("repair preserves original {field}"),
                current[field] == original[field],
            );
        }
        case.check(
            "same-generation eligible completion still sends",
            infer(run, worker).await?["finished"] == true
                && run.aggregator.count("/completion") == sends + 1,
        );
        cases.push(case);
    }
    Ok(())
}

async fn command_writer(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    for kind in ["eligible", "expired", "exhausted", "uncertain", "ended"] {
        let session = fresh(run, tab, worker, saved).await?;
        hold(run, worker, "command_writer").await?;
        let request = json!({"machine":"fixture","relay":run.relay.url,"host":"127.0.0.1","port":run.sshd.port,"user":SSH_USER,"command":"printf current-writer"});
        fresh_pace(run.relay);
        module(
            run,
            worker,
            &format!(
                "self.raceWork=m.run_command({});await self.raceReady;return true;",
                json!(request.to_string())
            ),
        )
        .await?;
        let before = run.inspect(worker).await?;
        let execs = run.seen.lock().unwrap().ssh_exec.len();
        let generation = module(run, worker, "return String(m.publication_generation());").await?;
        if kind == "expired" {
            transition(run, worker, &session, kind).await?;
        }
        module(run,worker,&format!("self.queueReady=new Promise(ready=>self.queueWork=m.test_writer_transition({},{},new Promise(release=>self.queueRelease=release),ready));await self.queueReady;self.raceRelease();await new Promise(r=>setTimeout(r,20));self.queueRelease();await self.queueWork;return true;",json!(session),json!(kind))).await?;
        module(run, worker, "self.raceRelease();return true;").await?;
        let result = module(run, worker, "return JSON.parse(await self.raceWork);").await?;
        let after = run.inspect(worker).await?;
        let admitted = kind == "eligible";
        if kind == "expired"
            && after["sessions"][0]["inference_limits"]["state"] != "session expired"
        {
            return Err(format!(
                "writer expiry prerequisite did not establish expiry: {}",
                after["sessions"]
            ));
        }
        let mut case = Case::new(&format!(
            "command acquired writer validates affected session {kind} before intent"
        ));
        case.check(
            "transition does not rely on global end or generation",
            module(run, worker, "return String(m.publication_generation());").await? == generation,
        );
        case.check(
            "only eligible original caller records intent and job",
            after["commands"].as_array().unwrap().len()
                == before["commands"].as_array().unwrap().len() + usize::from(admitted),
        );
        case.check(
            "refused writer creates no barrier",
            admitted || after["calls"] == before["calls"],
        );
        case.check(
            "actual SSH send follows current eligibility",
            if admitted {
                result["outcome"]["done"] == true && run.seen.lock().unwrap().ssh_exec.len() > execs
            } else {
                result["outcome"].get("done").is_none()
                    && run.seen.lock().unwrap().ssh_exec.len() == execs
            },
        );
        cases.push(case);
    }
    Ok(())
}

async fn documents(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    for point in ["document_send", "document_release"] {
        for kind in ["eligible", "expired", "uncertain", "ended"] {
            let session = fresh(run, tab, worker, saved).await?;
            hold(run, worker, point).await?;
            status(run, worker).await?;
            run.aggregator.state.lock().unwrap().document = "scheduled hidden document".into();
            let count = run.aggregator.count_method("GET", "/document");
            let source = format!("{}/document", run.aggregator.origin);
            run.browser.evaluate(&tab.session,&format!("(()=>{{const card=document.querySelector('[data-machine=fixture]');card.querySelector('[data-goal-text]').value='Read the scheduled document';card.querySelector('[data-document-source]').value={};card.querySelector('[data-goal-enter]').click();return true;}})()",json!(source))).await?;
            module(run, worker, "await self.raceReady;return true;").await?;
            let generation =
                module(run, worker, "return String(m.publication_generation());").await?;
            transition(run, worker, &session, kind).await?;
            visibility(run, tab, "hidden").await?;
            module(run, worker, "self.raceRelease();return true;").await?;
            let mut state = Value::Null;
            for _ in 0..200 {
                state = module(
                    run,
                    worker,
                    &format!(
                        "return JSON.parse(m.test_document_state({}));",
                        json!(session)
                    ),
                )
                .await?;
                if state["pending"] == false {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let mut case = Case::new(&format!(
                "page goal document {point} checks affected session {kind}"
            ));
            case.check(
                "no global generation change masks individual transition",
                module(run, worker, "return String(m.publication_generation());").await?
                    == generation,
            );
            case.check(
                "document GET reaches only eligible send boundary",
                run.aggregator.count_method("GET", "/document")
                    == count + usize::from(point == "document_release" || kind == "eligible"),
            );
            case.check(
                "only current eligible document is retained",
                state["pending"] == false && state["retained"] == (kind == "eligible"),
            );
            case.check(
                "safe source history remains durable",
                run.inspect(worker).await?["goals"]
                    .as_array()
                    .is_some_and(|gs| {
                        gs.iter()
                            .any(|g| g["session"] == session && g["document_source"] == source)
                    }),
            );
            visibility(run, tab, "visible").await?;
            cases.push(case);
        }
    }
    Ok(())
}

async fn publications(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    for kind in ["eligible", "expired", "uncertain", "ended"] {
        let session = fresh(run, tab, worker, saved).await?;
        hold(run, worker, "publication_writer").await?;
        module(run,worker,"self.racePosted=[];const post=self.postMessage.bind(self);self.postMessage=value=>{self.racePosted.push(value);post(value);};return true;").await?;
        module(run,worker,&format!("const v=JSON.parse(await m.open());v.goal_outcome={{session:{},outcome:{{done:true}}}};self.raceWork=m.publish_report(m.publication_generation(),{},JSON.stringify(v));await self.raceReady;return true;",json!(session),json!(session))).await?;
        transition(run, worker, &session, kind).await?;
        module(
            run,
            worker,
            "self.raceRelease();await self.raceWork;return true;",
        )
        .await?;
        let dom=run.browser.evaluate(&tab.session,"({state:document.getElementById('tau-store').dataset.state,lock:!document.getElementById('tau-lock').hidden,text:document.getElementById('tau-setup').textContent,verify:!!document.querySelector('[data-verify-clock]'),other:!!document.querySelector('[data-machine=fixture-other] [data-goal-card]')})").await?;
        let mut case = Case::new(&format!(
            "actual final postMessage and DOM keep current state after session {kind}"
        ));
        case.check(
            "unlocked app always retains explicit Lock",
            dom["state"] == "unlocked" && dom["lock"] == true,
        );
        case.check(
            "only eligible final result is actionable",
            dom["text"]
                .as_str()
                .is_some_and(|t| t.contains("Goal loop ended: done."))
                == (kind == "eligible"),
        );
        if kind == "uncertain" {
            case.check(
                "clock-withheld state retains verification control",
                dom["verify"] == true,
            );
        }
        if kind == "ended" {
            case.check(
                "other eligible session keeps its controls",
                dom["other"] == true,
            );
        }
        let posted = module(run, worker, "return self.racePosted;").await?;
        case.check(
            "actual posted payload contains no stale actionable outcome",
            posted.as_array().is_some_and(|messages| {
                messages
                    .iter()
                    .any(|m| m["store"]["store_state"] == "unlocked")
                    && messages
                        .iter()
                        .all(|m| m["store"].get("goal_outcome").is_some() == (kind == "eligible"))
            }),
        );
        cases.push(case);
    }
    Ok(())
}

async fn source_append(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    for kind in ["eligible", "expired", "uncertain"] {
        let session = fresh(run, tab, worker, saved).await?;
        let state = run.inspect(worker).await?;
        let mint = state["inference_calls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["kind"] == "mint" && c["intent"]["mint"]["session"] == session)
            .ok_or("mint prerequisite")?;
        let intent = &mint["intent"]["mint"];
        let clock = &intent["evidence"]["clock"];
        let delta = intent["expires"].as_u64().ok_or("expiry")?
            - clock["latest"].as_u64().ok_or("anchor")?;
        let sample = match kind {
            "expired" => Some((
                clock["sent"]["monotonic"].as_u64().unwrap() + delta * 1_000_000,
                clock["sent"]["wall"].as_u64().unwrap() + delta * 1_000_000,
            )),
            "uncertain" => Some((
                clock["sent"]["monotonic"].as_u64().unwrap() + 1_000_000,
                clock["sent"]["wall"].as_u64().unwrap() + 7_000_001,
            )),
            _ => None,
        };
        status(run, worker).await?;
        module(run,worker,"self.sourceReady=new Promise(ready=>m.test_hold_move(new Promise(release=>self.sourceRelease=release),ready));return true;").await?;
        let before = run.aggregator.count_method("GET", "/document");
        let source = format!("{}/document", run.aggregator.origin);
        run.browser.evaluate(&tab.session,&format!("(()=>{{const card=document.querySelector('[data-machine=fixture]');card.querySelector('[data-goal-text]').value='Read after source append';card.querySelector('[data-document-source]').value={};card.querySelector('[data-goal-enter]').click();return true;}})()",json!(source))).await?;
        module(run, worker, "await self.sourceReady;return true;").await?;
        if let Some((monotonic, wall)) = sample {
            module(
                run,
                worker,
                &format!(
                    "return m.test_clock_sample({},{});",
                    json!(monotonic.to_string()),
                    json!(wall.to_string())
                ),
            )
            .await?;
        }
        module(run, worker, "self.sourceRelease();return true;").await?;
        let mut complete = false;
        for _ in 0..200 {
            let state = run.inspect(worker).await?;
            let document = module(
                run,
                worker,
                &format!(
                    "return JSON.parse(m.test_document_state({}));",
                    json!(session)
                ),
            )
            .await?;
            complete = state["goals"]
                .as_array()
                .is_some_and(|gs| gs.iter().any(|g| g["session"] == session))
                && document["pending"] == false;
            if complete {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut case = Case::new(&format!(
            "individual session {kind} during begun goal source append fences document GET"
        ));
        case.check("source append completes whole as durable history", complete);
        case.check(
            "current original limits govern actual GET after append",
            run.aggregator.count_method("GET", "/document")
                == before + usize::from(kind == "eligible"),
        );
        cases.push(case);
    }
    Ok(())
}

async fn command_release(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    for kind in ["eligible", "expired", "ended", "uncertain"] {
        let session = fresh(run, tab, worker, saved).await?;
        hold(run, worker, "command_release_writer").await?;
        let request = json!({"machine":"fixture","relay":run.relay.url,"host":"127.0.0.1","port":run.sshd.port,"user":SSH_USER,"command":"printf final-release-evidence"});
        fresh_pace(run.relay);
        module(
            run,
            worker,
            &format!(
                "self.raceWork=m.run_command({});await self.raceReady;return true;",
                json!(request.to_string())
            ),
        )
        .await?;
        transition(run, worker, &session, kind).await?;
        module(run, worker, "self.raceRelease();return true;").await?;
        let report = module(run, worker, "return JSON.parse(await self.raceWork);").await?;
        let outcome = &report["outcome"];
        let mut case = Case::new(&format!(
            "final command release retains committed evidence after session {kind}"
        ));
        case.check(
            "only eligible final release carries done",
            (outcome["done"] == true) == (kind == "eligible"),
        );
        case.check(
            "committed call job terminal and exact output survive release",
            outcome["call"].is_u64()
                && outcome["terminal"].is_u64()
                && outcome["job_record"]["state"] == "finished"
                && outcome["job_record"]["stdout"] == "final-release-evidence",
        );
        if kind != "eligible" {
            case.check(
                "stale release is explicitly non-actionable history",
                outcome["historical"] == true && outcome["actionable"] == false,
            );
        }
        let opened = reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
        case.check(
            "independent reader retains original final job evidence",
            opened.records.iter().any(|(n, b)| {
                Some(*n) == outcome["terminal"].as_u64()
                    && serde_json::from_slice::<Value>(b).is_ok_and(|v| {
                        v["job_terminal"]["call"] == outcome["call"]
                            && v["job_terminal"]["record"] == outcome["job_record"]["record"]
                    })
            }),
        );
        cases.push(case);
    }
    Ok(())
}

async fn prepared_publication(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    for kind in ["eligible", "expired", "freeze"] {
        let session = fresh(run, tab, worker, saved).await?;
        let state = run.inspect(worker).await?;
        let mint = state["inference_calls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["kind"] == "mint" && c["intent"]["mint"]["session"] == session)
            .ok_or("affected mint")?;
        let intent = &mint["intent"]["mint"];
        let clock = &intent["evidence"]["clock"];
        let delta = intent["expires"].as_u64().unwrap() - clock["latest"].as_u64().unwrap();
        let monotonic = clock["sent"]["monotonic"].as_u64().unwrap() + delta * 1_000_000;
        let wall = clock["sent"]["wall"].as_u64().unwrap() + delta * 1_000_000;
        hold(run, worker, "publication_prepared").await?;
        module(run,worker,&format!("self.finalPosts=[];const post=self.postMessage.bind(self);self.postMessage=v=>{{self.finalPosts.push(v);post(v);}};const value=JSON.parse(await m.open());value.goal_outcome={{session:{},outcome:{{done:true}}}};self.finalPublication=m.publish_report(m.publication_generation(),{},JSON.stringify(value));await self.raceReady;return true;",json!(session),json!(session))).await?;
        if kind == "expired" {
            module(
                run,
                worker,
                &format!(
                    "return m.test_clock_sample({},{});",
                    json!(monotonic.to_string()),
                    json!(wall.to_string())
                ),
            )
            .await?;
        } else if kind == "freeze" {
            event(run, tab, "freeze").await?;
        }
        module(
            run,
            worker,
            "self.raceRelease();await self.finalPublication;return true;",
        )
        .await?;
        let posts = module(run, worker, "return self.finalPosts;").await?;
        let mut case = Case::new(&format!(
            "prepared scanned publication validates final authority after {kind}"
        ));
        case.check(
            "only eligible prepared result reaches actual postMessage",
            posts.as_array().is_some_and(|ps| {
                !ps.is_empty()
                    && ps
                        .iter()
                        .all(|p| p["store"].get("goal_outcome").is_some() == (kind == "eligible"))
            }),
        );
        case.check("withheld prepared result keeps truthful unlocked state and Lock",run.browser.evaluate(&tab.session,"document.getElementById('tau-store').dataset.state==='unlocked'&&!document.getElementById('tau-lock').hidden").await?==true);
        if kind == "expired" {
            case.check(
                "expiry after protection is actually established",
                run.inspect(worker).await?["sessions"][0]["inference_limits"]["state"]
                    == "session expired",
            );
        }
        cases.push(case);
    }
    Ok(())
}

async fn mint_custody(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    for begun in [false, true] {
        reset(run, tab, worker, saved).await?;
        let initial = run.inspect(worker).await?;
        let session = initial["sessions"][0]["identity"]
            .as_str()
            .ok_or("mint session")?
            .to_owned();
        let confirmed = initial["sessions"][0]["inference_limits"]["confirmed"].clone();
        let mints = run.aggregator.count("/keys");
        let completions = run.aggregator.count("/completion");
        hold(run, worker, "mint_finish_writer").await?;
        module(run,worker,"self.mintWork=m.inference_request(JSON.stringify({machine:'fixture',messages:[{role:'user',content:'one original key'}]}));await self.raceReady;return true;").await?;
        if begun {
            module(run,worker,"self.mintMoveReady=new Promise(ready=>m.test_hold_move(new Promise(release=>self.mintMoveRelease=release),ready));self.raceRelease();await self.mintMoveReady;return true;").await?;
        }
        event(run, tab, "freeze").await?;
        module(
            run,
            worker,
            if begun {
                "self.mintMoveRelease();return true;"
            } else {
                "self.raceRelease();return true;"
            },
        )
        .await?;
        let result = module(run, worker, "return JSON.parse(await self.mintWork);").await?;
        let mut case = Case::new(&format!(
            "original mint key custody survives freeze {} terminal append with use withheld",
            if begun { "during begun" } else { "queued for" }
        ));
        case.check(
            "old mint workflow publishes no ordinary body or completion",
            result.get("refused").is_some()
                && result.get("body").is_none()
                && run.aggregator.count("/completion") == completions,
        );
        let repaired = module(
            run,
            worker,
            &format!(
                "return JSON.parse(await m.verify_inference_clock({}));",
                json!(session)
            ),
        )
        .await?;
        case.check(
            "narrow fresh verification repairs same original key before ordinary resume",
            repaired["finished"] == true && repaired.get("refused").is_none(),
        );
        let withheld = infer(run, worker).await?;
        case.check(
            "clock repair alone grants no ordinary authority during suspension",
            withheld.get("refused").is_some() && run.aggregator.count("/completion") == completions,
        );
        event(run, tab, "resume").await?;
        let state = run.inspect(worker).await?;
        let mint = state["inference_calls"]
            .as_array()
            .ok_or_else(|| format!("missing mint history after resume: {state}"))?
            .iter()
            .find(|c| c["kind"] == "mint" && c["intent"]["mint"]["session"] == session)
            .ok_or("original mint terminal")?;
        case.check(
            "exact original lower-tier key remains held by the same non-ended session",
            mint["state"] == "finished"
                && mint["terminal"]["key_id"].is_string()
                && state["sessions"][0]["given"]
                    .as_array()
                    .is_some_and(|given| given.iter().any(|h| h["row"] == 2))
                && state["sessions"][0]["session_state"] == "running",
        );
        let limits = &state["sessions"][0]["inference_limits"];
        case.check(
            "custody and repair preserve original confirmed tuple origin expiry and consumption",
            limits["confirmed"] == confirmed
                && limits["original_origin"] == mint["intent"]["mint"]["evidence"]["origin"]
                && limits["original_expiry"] == mint["intent"]["mint"]["expires"]
                && limits["observed_spend"] == "0",
        );
        let next = infer(run, worker).await?;
        case.check(
            "fresh eligible request uses original key without replacement mint",
            next["finished"] == true
                && next.get("body").is_some()
                && run.aggregator.count("/completion") == completions + 1
                && run.aggregator.count("/keys") == mints + 1,
        );
        cases.push(case);
    }
    Ok(())
}

async fn status_carriers(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    saved: &Files,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    for carrier in ["ordinary", "delivery"] {
        for kind in ["eligible", "ended", "uncertain"] {
            let session = fresh(run, tab, worker, saved).await?;
            status(run, worker).await?;
            if carrier == "delivery" {
                module(
                    run,
                    worker,
                    &format!(
                        "await m.test_delivery_fixture({},'fixture',{});return true;",
                        json!(session),
                        json!(crate::delivery_cases::clean().to_string())
                    ),
                )
                .await?;
            }
            hold(run, worker, "publication_writer").await?;
            module(run,worker,"self.carrierPosts=[];const post=self.postMessage.bind(self);self.postMessage=v=>{self.carrierPosts.push(v);post(v);};return true;").await?;
            if carrier == "delivery" {
                setup_cases::click(run, tab, "[data-delivery-check=fixture]").await?;
                module(run, worker, "await self.raceReady;return true;").await?;
                let state = run.inspect(worker).await?;
                if state["delivery"][0]["verdict"] != "Delivered" {
                    return Err(format!(
                        "delivery publication prerequisite never reached committed Delivered: {}",
                        state["delivery"]
                    ));
                }
            } else {
                module(run,worker,"self.carrierWork=m.publish_report(m.publication_generation(),'',await m.open());await self.raceReady;return true;").await?;
            }
            let generation =
                module(run, worker, "return String(m.publication_generation());").await?;
            transition(run, worker, &session, kind).await?;
            module(run, worker, "self.raceRelease();return true;").await?;
            let mut posted = Value::Null;
            for _ in 0..200 {
                posted = module(
                    run,
                    worker,
                    "return self.carrierPosts.find(p=>p.store)?.store??null;",
                )
                .await?;
                if posted.is_object() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let mut case = Case::new(&format!(
                "queued actual {carrier} publication refreshes current controls after individual session {kind}"
            ));
            case.check(
                "final status uses current affected session without a global generation change",
                module(run, worker, "return String(m.publication_generation());").await?
                    == generation
                    && posted["store_state"] == "unlocked"
                    && posted["sessions"].as_array().is_some_and(|ss| {
                        ss.iter().any(|s| {
                            s["identity"] == session
                                && s["session_state"]
                                    == if kind == "ended" { "ended" } else { "running" }
                        })
                    }),
            );
            let dom=run.browser.evaluate(&tab.session,"({lock:!document.getElementById('tau-lock').hidden,target:!!document.querySelector('[data-machine=fixture] [data-goal-card]'),other:!!document.querySelector('[data-machine=fixture-other] [data-goal-card]'),verify:!!document.querySelector('[data-machine=fixture] [data-verify-clock]'),delivery:!!document.querySelector('[data-delivery-check=fixture]')})").await?;
            case.check(
                "Lock and another eligible session remain operable",
                dom["lock"] == true && dom["other"] == true,
            );
            case.check(
                "only eligible current target retains ordinary controls",
                dom["target"] == (kind == "eligible") && dom["delivery"] == (kind == "eligible"),
            );
            if kind == "uncertain" {
                case.check(
                    "clock-withheld target retains narrow verification control",
                    dom["verify"] == true,
                );
            }
            if carrier == "delivery" && kind == "ended" {
                case.check(
                    "completed delivery remains safe history with placement disabled",
                    posted["delivery"][0]["verdict"] == "Delivered"
                        && posted["delivery"][0]["verdict_is_historical"] == true
                        && posted["delivery"][0]["placement_eligible"] == false,
                );
            }
            cases.push(case);
        }
    }
    Ok(())
}
