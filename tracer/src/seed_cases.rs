//! Integrated seed-backup ceremony checks against the document, encrypted bytes and fixtures.
use super::*;

const FAMILIES: [&str; 3] = ["machines", "passes", "handoffs"];

async fn wait_stage(run: &Run<'_>, tab: &Tab, stage: &str) -> Result<(), String> {
    for _ in 0..300 {
        let ready = run.browser.evaluate(&tab.session, &format!(
            "(() => {{ const s=document.getElementById('tau-seed-backup'); return {} === 'inactive' ? s.hidden : !s.hidden && ({} === 'display' ? !!document.getElementById('tau-seed-backup-words') : !document.getElementById('tau-seed-backup-entry').hidden); }})()",
            json!(stage), json!(stage))).await?;
        if ready == true {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("seed-backup stage did not become {stage}"))
}

async fn click(run: &Run<'_>, tab: &Tab, id: &str) -> Result<(), String> {
    run.browser
        .evaluate(
            &tab.session,
            &format!(
                "document.getElementById({}).click()",
                json!(format!("tau-{id}"))
            ),
        )
        .await?;
    Ok(())
}

pub(super) async fn skip(run: &Run<'_>, tab: &Tab) -> Result<(), String> {
    wait_stage(run, tab, "display").await?;
    click(run, tab, "seed-backup-answer").await?;
    wait_stage(run, tab, "answering").await?;
    click(run, tab, "seed-backup-skip").await?;
    wait_stage(run, tab, "inactive").await
}

async fn phrase(run: &Run<'_>, tab: &Tab) -> Result<String, String> {
    wait_stage(run, tab, "display").await?;
    let words = run.browser.evaluate(&tab.session,
        "Array.from(document.querySelectorAll('#tau-seed-backup-words li'), n=>n.textContent).join(' ')").await?;
    words
        .as_str()
        .map(str::to_string)
        .ok_or("no displayed words".into())
}

async fn document(run: &Run<'_>, tab: &Tab) -> Result<Value, String> {
    run.browser.evaluate(&tab.session, r#"(() => {
        const root=document.documentElement.cloneNode(true);
        for(const node of [root,...root.querySelectorAll('*')]) {
            const attributes=Array.from(node.attributes,a=>[a.name,a.value]).sort(([a],[b])=>a.localeCompare(b));
            for(const a of Array.from(node.attributes)) node.removeAttribute(a.name);
            for(const [name,value] of attributes) node.setAttribute(name,value);
        }
        return {html:root.outerHTML, fields:Array.from(document.querySelectorAll('input,textarea,select'), n=>n.value)};
    })()"#).await
}

// Each baseline is the same stage under an independent seed. Compare the entire document
// and every field value: a leftover word changes the document, even in a hidden element.
// Attribute order is canonicalized because removing/re-adding `hidden` changes that order.
struct Documents {
    answering: Value,
    locked: Value,
    redisplay: Value,
    wrong_pass: Value,
}

async fn absent(run: &Run<'_>, tab: &Tab, expected: &Value) -> Result<bool, String> {
    Ok(document(run, tab).await? == *expected)
}

async fn collision_controls(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    pass: &str,
    tracer: bool,
    check_mismatch: bool,
    cases: &mut Vec<Case>,
) -> Result<Documents, String> {
    let controls: Vec<_> = include_str!("../../tests/vectors/seed-backup-collisions.txt")
        .lines()
        .collect();
    let mut baseline: Option<Documents> = None;
    for (index, words) in controls.iter().enumerate() {
        let mut case = Case::new(&format!(
            "seed-backup collision control {}: {}",
            index + 1,
            if tracer { "tracer" } else { "served" }
        ));
        run.put(
            tab,
            &reader::build(pass, &[json!({"seed":{"mnemonic":words}})]),
        )
        .await?;
        *worker = run.reload(tab, worker).await?;
        run.submit(tab, "unlock", pass).await?;
        case.check(
            "control owing the seed-backup ceremony displays exactly its twelve words",
            phrase(run, tab).await? == *words,
        );
        language(run, tab, &mut case).await?;
        run.browser.evaluate(&tab.session,
            "window.__seedLanguageLeak=document.createElement('span'); window.__seedLanguageLeak.hidden=true; window.__seedLanguageLeak.textContent='proven'; document.body.append(window.__seedLanguageLeak)").await?;
        case.check(
            "language check reports a planted hidden reserved claim with words displayed",
            !language_clear(run, tab).await?,
        );
        run.browser
            .evaluate(
                &tab.session,
                "window.__seedLanguageLeak.remove(); delete window.__seedLanguageLeak",
            )
            .await?;
        language(run, tab, &mut case).await?;
        click(run, tab, "seed-backup-answer").await?;
        wait_stage(run, tab, "answering").await?;
        language(run, tab, &mut case).await?;
        let answering = document(run, tab).await?;
        run.browser.evaluate(&tab.session,&format!(r#"(() => {{
            window.__seedLeak={}.split(' ').map(word=>{{const n=document.createElement('span'); n.hidden=true;n.textContent=word;document.body.append(n);return n;}});
        }})()"#,json!(words))).await?;
        case.check(
            "hidden check reports twelve planted hidden word elements",
            !absent(run, tab, &answering).await?,
        );
        run.browser
            .evaluate(
                &tab.session,
                "window.__seedLeak.forEach(n=>n.remove());delete window.__seedLeak",
            )
            .await?;
        case.check(
            "removing the planted elements restores the entire answering document",
            absent(run, tab, &answering).await?,
        );
        if check_mismatch {
            reenter(run, tab, controls[(index + 1) % controls.len()]).await?;
            let returned = wait_stage(run, tab, "display").await.is_ok();
            case.check(
                "control mismatch returns to its original display",
                returned && phrase(run, tab).await? == *words,
            );
            if !returned {
                return Err("control mismatch completed instead of returning to display".into());
            }
        }
        let old = worker.clone();
        click(run, tab, "lock").await?;
        *worker = run.worker(tab, Some(&old), false).await?;
        run.settled(tab, false).await?;
        let locked = document(run, tab).await?;
        language(run, tab, &mut case).await?;
        run.submit(tab, "unlock", pass).await?;
        phrase(run, tab).await?;
        click(run, tab, "seed-backup-answer").await?;
        wait_stage(run, tab, "answering").await?;
        reenter(run, tab, words).await?;
        wait_stage(run, tab, "inactive").await?;
        language(run, tab, &mut case).await?;
        case.check(
            "control full re-entry is durably recorded",
            read(&run.dump(tab).await?, pass)?.seed_backups()? == ["full_reentry"],
        );
        let old = worker.clone();
        click(run, tab, "redisplay").await?;
        *worker = run.worker(tab, Some(&old), false).await?;
        run.submit(tab, "unlock", pass).await?;
        skip(run, tab).await?;
        let old = worker.clone();
        click(run, tab, "redisplay").await?;
        *worker = run.worker(tab, Some(&old), false).await?;
        run.submit(tab, "unlock", pass).await?;
        phrase(run, tab).await?;
        click(run, tab, "seed-backup-answer").await?;
        wait_stage(run, tab, "answering").await?;
        let redisplay = document(run, tab).await?;
        language(run, tab, &mut case).await?;
        click(run, tab, "seed-backup-skip").await?;
        wait_stage(run, tab, "inactive").await?;
        let old = worker.clone();
        click(run, tab, "redisplay").await?;
        *worker = run.worker(tab, Some(&old), false).await?;
        run.submit(tab, "unlock", WRONG_PASSPHRASE).await?;
        let wrong_pass = document(run, tab).await?;
        let documents = Documents {
            answering,
            locked,
            redisplay,
            wrong_pass,
        };
        if let Some(baseline) = &baseline {
            case.check(
                "answering document and fields are identical under different seeds",
                documents.answering == baseline.answering,
            );
            case.check(
                "locked document and fields are identical under different seeds",
                documents.locked == baseline.locked,
            );
            case.check(
                "re-display answering document and fields are identical under different seeds",
                documents.redisplay == baseline.redisplay,
            );
            case.check(
                "wrong-passphrase document and fields are identical under different seeds",
                documents.wrong_pass == baseline.wrong_pass,
            );
        } else {
            baseline = Some(documents);
        }
        language(run, tab, &mut case).await?;
        cases.push(case);
    }
    Ok(baseline.expect("four controls"))
}

// Remove only the mnemonic list. Hidden interface text elsewhere must still be checked.
async fn language_clear(run: &Run<'_>, tab: &Tab) -> Result<bool, String> {
    Ok(run.browser.evaluate(&tab.session, r#"(() => {
        const body=document.body.cloneNode(true);
        body.querySelector('#tau-seed-backup-words')?.remove();
        return !(/verified|no anomalies found|proven|formally verified|machine-checked/i).test(body.textContent);
    })()"#).await? == true)
}

async fn language(run: &Run<'_>, tab: &Tab, case: &mut Case) -> Result<(), String> {
    case.check(
        "CNF-44: page text makes none of the reserved claims",
        language_clear(run, tab).await?,
    );
    Ok(())
}

async fn reenter(run: &Run<'_>, tab: &Tab, words: &str) -> Result<(), String> {
    let cleared = run.browser.evaluate(&tab.session, &format!(
        "(() => {{ const f=document.getElementById('tau-seed-backup-input'); f.value={}; document.getElementById('tau-seed-backup-check').click(); return f.value === ''; }})()", json!(words))).await?;
    if cleared != true {
        return Err("re-entry field not cleared immediately".into());
    }
    Ok(())
}

async fn allocate(run: &Run<'_>, worker: &Worker, family: &str) -> Result<Value, String> {
    run.browser.evaluate(&worker.session, &format!(
        "(async()=>{{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href); return JSON.parse(await m.test_allocate({}));}})()",json!(family))).await
}

async fn gated(run: &Run<'_>, worker: &Worker, case: &mut Case) -> Result<(), String> {
    for family in FAMILIES {
        case.check(
            &format!("{family}: allocation refuses with the seed-backup gate's reason"),
            allocate(run, worker, family).await?["refused"]
                == tau_web::allocation::Refusal::BackupMissing.to_string(),
        );
    }
    Ok(())
}

async fn refused_dispatch(
    run: &Run<'_>,
    worker: &Worker,
    args: &Value,
    case: &mut Case,
) -> Result<(), String> {
    let before = run.inspect(worker).await?;
    take(run.seen);
    let command = run.harness_run(worker, args.clone()).await?;
    let collect = run.harness_collect(worker, args.clone()).await?;
    let observed = take(run.seen);
    case.check(
        "command and collection refuse before relay/SSH contact and append",
        command == json!({"outcome":{"refused":"seed_backup"}})
            && collect == command
            && observed.relay_accepted == 0
            && observed.ssh_connections == 0
            && run.inspect(worker).await? == before,
    );
    Ok(())
}

fn read(files: &Files, pass: &str) -> Result<reader::Opened, String> {
    reader::read(&store_files(files), pass)
}

pub(super) async fn run(
    run: &Run<'_>,
    tab: &mut Tab,
    worker: &mut Worker,
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
    *worker = run.worker(tab, None, false).await?;
    let saved = store_files(&run.dump(tab).await?);
    let selected = std::env::var("TAU_TRACER_SEED_CASE").unwrap_or_else(|_| "all".into());
    let full_run = selected == "all";
    let documents = collision_controls(run, tab, worker, pass, tracer, full_run, cases).await?;
    if full_run || selected == "create" || selected == "mismatch" {
        let mut case = Case::new(if tracer {
            "seed-backup create, hidden answer and mismatch: tracer"
        } else {
            "seed-backup create, hidden answer and mismatch: served"
        });
        run.put(tab, &Files::new()).await?;
        *worker = run.reload(tab, worker).await?;
        run.submit(tab, "create", pass).await?;
        let words = phrase(run, tab).await?;
        let before = run.dump(tab).await?;
        let opened = read(&before, pass)?;
        case.check(
            "all twelve numbered words are the reader's record-0 mnemonic",
            words == opened.mnemonic()? && words.split(' ').count() == 12,
        );
        let text = run
            .browser
            .evaluate(
                &tab.session,
                "document.getElementById('tau-seed-backup-state').textContent",
            )
            .await?;
        case.check(
            "page explains all three allocation families are refused until recorded",
            text.as_str()
                .is_some_and(|t| t.contains("machines, relay passes and handoffs are refused")),
        );
        refused_dispatch(run, worker, &args("fixture"), &mut case).await?;
        if tracer {
            gated(run, worker, &mut case).await?;
        }
        case.check(
            "nothing appended at display",
            run.dump(tab).await? == before,
        );
        language(run, tab, &mut case).await?;
        click(run, tab, "seed-backup-answer").await?;
        wait_stage(run, tab, "answering").await?;
        case.check(
            "answering document and fields equal an independent seed's document",
            absent(run, tab, &documents.answering).await?,
        );
        language(run, tab, &mut case).await?;
        let different = bip39::Mnemonic::from_entropy(&[17; 16])
            .map_err(|e| e.to_string())?
            .to_string();
        reenter(run, tab, &different).await?;
        let returned = wait_stage(run, tab, "display").await.is_ok();
        case.check(
            "different valid mnemonic returns to the original display",
            returned && phrase(run, tab).await? == words,
        );
        case.check(
            "reader finds no completion after mismatch",
            run.dump(tab).await? == before
                && read(&run.dump(tab).await?, pass)?
                    .seed_backups()?
                    .is_empty(),
        );
        if tracer {
            gated(run, worker, &mut case).await?;
        }
        language(run, tab, &mut case).await?;
        cases.push(case);
    }
    if full_run {
        for full in [true, false] {
            let mut case = Case::new(match (tracer, full) {
                (true, true) => "seed-backup full re-entry and restart: tracer",
                (false, true) => "seed-backup full re-entry and restart: served",
                (true, false) => "seed-backup explicit skip and restart: tracer",
                (false, false) => "seed-backup explicit skip and restart: served",
            });
            run.put(tab, &Files::new()).await?;
            *worker = run.reload(tab, worker).await?;
            run.submit(tab, "create", pass).await?;
            let words = phrase(run, tab).await?;
            click(run, tab, "seed-backup-answer").await?;
            wait_stage(run, tab, "answering").await?;
            case.check(
                "completion's answering document equals an independent seed's document",
                absent(run, tab, &documents.answering).await?,
            );
            if full {
                reenter(run, tab, &format!("  {}\n", words.replace(' ', "\t"))).await?;
            } else {
                click(run, tab, "seed-backup-skip").await?;
            }
            wait_stage(run, tab, "inactive").await?;
            let completion = if full { "full_reentry" } else { "skipped" };
            let opened = read(&run.dump(tab).await?, pass)?;
            case.check(
                "independent reader decrypts this seed's distinct completion with no words",
                opened.seed_backups()? == [completion] && opened.records.len() == 2,
            );
            let text = run.view(tab).await?;
            case.check(
                "page states which completion was recorded",
                text["text"].as_str().is_some_and(|t| {
                    t.contains(if full {
                        "all twelve words re-entered"
                    } else {
                        "re-entry check skipped"
                    })
                }),
            );
            language(run, tab, &mut case).await?;
            if tracer {
                for family in FAMILIES {
                    case.check(
                        &format!("{family}: first index admitted"),
                        allocate(run, worker, family).await?["identity"]["index"] == 0,
                    );
                }
                let opened = read(&run.dump(tab).await?, pass)?;
                let reservations: Vec<Value> = opened
                    .records
                    .iter()
                    .filter_map(|(_, p)| {
                        serde_json::from_slice::<Value>(p)
                            .ok()?
                            .pointer("/allocation/reserve")
                            .cloned()
                    })
                    .collect();
                case.check(
                    "reader sees all three reservations after completion",
                    reservations.len() == 3
                        && reservations
                            .iter()
                            .all(|r| r["seed"] == opened.seed_id().unwrap() && r["index"] == 0),
                );
            }
            *worker = run.reload(tab, worker).await?;
            run.submit(tab, "unlock", pass).await?;
            case.check(
                "restart shows no seed-backup ceremony and retains the same record",
                run.inspect(worker).await?["seed_backup_stage"] == "inactive"
                    && read(&run.dump(tab).await?, pass)?.seed_backups()? == [completion],
            );
            if tracer {
                for family in FAMILIES {
                    case.check(
                        &format!("{family}: next index after reopen"),
                        allocate(run, worker, family).await?["identity"]["index"] == 1,
                    );
                }
            }
            cases.push(case);
        }
    }
    if tracer && (full_run || selected == "failed-append") {
        for full in [false, true] {
            let mut case = Case::new(if full {
                "seed-backup full re-entry failed OPFS move"
            } else {
                "seed-backup skip failed OPFS move"
            });
            run.put(tab, &Files::new()).await?;
            *worker = run.reload(tab, worker).await?;
            run.submit(tab, "create", pass).await?;
            let words = phrase(run, tab).await?;
            let before = store_files(&run.dump(tab).await?);
            click(run, tab, "seed-backup-answer").await?;
            wait_stage(run, tab, "answering").await?;
            run.browser.evaluate(&worker.session,"(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href); await m.test_seed_backup_fail_append();})()").await?;
            if full {
                reenter(run, tab, &words).await?;
            } else {
                click(run, tab, "seed-backup-skip").await?;
            }
            for _ in 0..300 {
                if run.inspect(worker).await?["seed_backup_stage"] == "append_failed" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let state = run.inspect(worker).await?;
            case.check(
                "failed completion is not applied and still owed",
                state["seed_backup_owed"] == true && state["seed_backup_completion"].is_null(),
            );
            let page = run
                .browser
                .evaluate(&tab.session, "document.body.textContent")
                .await?;
            case.check(
                "page says not recorded, still owed, reload and unlock",
                page.as_str().is_some_and(|t| {
                    t.contains("not recorded")
                        && t.contains("Reload and unlock")
                        && t.contains("seed-backup ceremony is still owed")
                }),
            );
            gated(run, worker, &mut case).await?;
            language(run, tab, &mut case).await?;
            *worker = run.reload(tab, worker).await?;
            run.submit(tab, "unlock", pass).await?;
            case.check(
                "next unlock owes the same words and reader finds no completion",
                phrase(run, tab).await? == words
                    && read(&run.dump(tab).await?, pass)?
                        .seed_backups()?
                        .is_empty()
                    && read(&run.dump(tab).await?, pass)?.records
                        == reader::read(&before, pass)?.records,
            );
            cases.push(case);
        }
    }
    if full_run {
        let mut case = Case::new(if tracer {
            "seed-backup creation-finishing unlock: tracer"
        } else {
            "seed-backup creation-finishing unlock: served"
        });
        run.put(tab, &reader::build(pass, &[])).await?;
        *worker = run.reload(tab, worker).await?;
        run.submit(tab, "unlock", pass).await?;
        case.check(
            "envelope-only unlock displays the mnemonic the reader finds in new record 0",
            phrase(run, tab).await? == read(&run.dump(tab).await?, pass)?.mnemonic()?,
        );
        cases.push(case);
        for answering in [false, true] {
            for trigger in ["lock", "hidden", "pagehide", "pageshow", "close", "crash"] {
                let mut case = Case::new(&format!(
                    "seed-backup interrupted {} by {trigger}: {}",
                    if answering { "answering" } else { "display" },
                    if tracer { "tracer" } else { "served" }
                ));
                run.put(tab, &Files::new()).await?;
                *worker = run.reload(tab, worker).await?;
                run.submit(tab, "create", pass).await?;
                let words = phrase(run, tab).await?;
                let before = store_files(&run.dump(tab).await?);
                if answering {
                    click(run, tab, "seed-backup-answer").await?;
                    wait_stage(run, tab, "answering").await?;
                }
                run.browser
                    .evaluate(
                        &tab.session,
                        "document.getElementById('tau-seed-backup-input').value='discard this entry'",
                    )
                    .await?;
                let old = worker.clone();
                match trigger {
                    "close" | "crash" => {
                        run.collect(tab).await?;
                        if trigger == "crash" {
                            let _ = tokio::time::timeout(
                                Duration::from_secs(3),
                                run.browser
                                    .call(Some(&tab.session), "Page.crash", json!({})),
                            )
                            .await;
                        }
                        run.browser
                            .call(None, "Target.closeTarget", json!({"targetId":tab.target}))
                            .await?;
                        (*tab, *worker) = run.open(&tab.origin, false).await?;
                    }
                    "hidden" => {
                        let cover = run
                            .browser
                            .call(None, "Target.createTarget", json!({"url":"about:blank"}))
                            .await?;
                        let id = cover["targetId"].as_str().ok_or("no cover target")?;
                        run.browser
                            .call(None, "Target.activateTarget", json!({"targetId":id}))
                            .await?;
                        *worker = run.worker(tab, Some(&old), false).await?;
                        run.browser
                            .call(None, "Target.closeTarget", json!({"targetId":id}))
                            .await?;
                        run.browser
                            .call(
                                None,
                                "Target.activateTarget",
                                json!({"targetId":tab.target}),
                            )
                            .await?;
                    }
                    _ => {
                        if trigger == "lock" {
                            click(run, tab, "lock").await?;
                        } else {
                            run.browser.evaluate(&tab.session,&format!("dispatchEvent(new PageTransitionEvent({},{{persisted:{}}}))",json!(trigger),trigger=="pageshow")).await?;
                        }
                        *worker = run.worker(tab, Some(&old), false).await?;
                    }
                }
                case.check(
                    &format!(
                        "{trigger}, answering={answering}: lock removes mnemonic and typed input"
                    ),
                    absent(run, tab, &documents.locked).await?
                        && run
                            .browser
                            .evaluate(
                                &tab.session,
                                "document.getElementById('tau-seed-backup-input').value === ''",
                            )
                            .await?
                            == true,
                );
                run.submit(tab, "unlock", pass).await?;
                case.check(&format!("{trigger}: next unlock still owes same seed-backup ceremony with nothing appended"),phrase(run,tab).await?==words && store_files(&run.dump(tab).await?)==before);
                language(run, tab, &mut case).await?;
                cases.push(case);
            }
        }
        // No session input exists yet: session workers arrive with twr-ggw.11 and twr-ggw.14.
        let mut case = Case::new(if tracer {
            "seed-backup re-display ends dispatch connections and waits"
        } else {
            "seed-backup re-display requires passphrase: served"
        });
        skip(run, tab).await?;
        let mut before = run.inspect(worker).await?;
        if tracer {
            setup_cases::approve(run, tab, worker).await?;
            take(run.seen);
            fresh_pace(run.relay);
            let mut request = args("fixture");
            request["command"] = LOCK_COMMAND.into();
            run.harness_start(worker, request).await?;
            case.check(
                "running command reached fixture exec",
                settle_for(run.seen, 20, |s| exec_command_is(s, LOCK_COMMAND)).await,
            );
            before = run.inspect(worker).await?;
            run.browser.evaluate(&worker.session,&format!("self.__seedHeld = {}.then(r=>{{self.__seedHeldDone=true;return r;}}); self.__seedHeldDone=false; true",run_expression(&args("fixture")))).await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
            case.check(
                "held request is waiting without a second intent",
                run.browser
                    .evaluate(&worker.session, "self.__seedHeldDone")
                    .await?
                    == false
                    && run.inspect(worker).await? == before,
            );
        }
        let old = worker.clone();
        click(run, tab, "redisplay").await?;
        *worker = run.worker(tab, Some(&old), false).await?;
        case.check(
            "before passphrase no mnemonic is displayed",
            run.browser
                .evaluate(
                    &tab.session,
                    "document.getElementById('tau-seed-backup-words') === null",
                )
                .await?
                == true,
        );
        if tracer {
            let gone = settle_for(run.seen, 20, |s| {
                s.relay_log
                    .iter()
                    .any(|(_, e)| matches!(e, Event::Frame("close") | Event::Ended))
            })
            .await;
            case.check(
                "before words, relay and SSH connections ended and held worker is gone",
                gone && run.sshd.all_ended().await && !run.live_workers(tab).contains(&old),
            );
        }
        run.submit(tab, "unlock", pass).await?;
        let words = phrase(run, tab).await?;
        language(run, tab, &mut case).await?;
        refused_dispatch(run, worker, &args("fixture"), &mut case).await?;
        click(run, tab, "seed-backup-answer").await?;
        wait_stage(run, tab, "answering").await?;
        case.check(
            "re-display removes words while answering",
            absent(run, tab, &documents.redisplay).await?,
        );
        refused_dispatch(run, worker, &args("fixture"), &mut case).await?;
        reenter(run, tab, &words).await?;
        wait_stage(run, tab, "inactive").await?;
        case.check(
            "re-display journals another completion",
            read(&run.dump(tab).await?, pass)?.seed_backups()? == ["skipped", "full_reentry"],
        );
        if tracer {
            let after = run.inspect(worker).await?;
            case.check(
                "cut-off call unresolved; held request records no intent and never resumes",
                after["calls"] == before["calls"]
                    && after["commands"] == before["commands"]
                    && after["calls"].as_array().is_some_and(|calls| {
                        !calls.is_empty() && calls.iter().all(|call| call["state"] == "unresolved")
                    }),
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
            let observed = take(run.seen);
            case.check(
                "no second exec after completion",
                observed.ssh_exec.is_empty(),
            );
        }
        let old = worker.clone();
        click(run, tab, "redisplay").await?;
        *worker = run.worker(tab, Some(&old), false).await?;
        let persisted = store_files(&run.dump(tab).await?);
        run.submit(tab, "unlock", WRONG_PASSPHRASE).await?;
        case.check(
            "wrong passphrase shows no word and journals nothing",
            absent(run, tab, &documents.wrong_pass).await?
                && store_files(&run.dump(tab).await?) == persisted,
        );
        cases.push(case);
    }
    run.put(tab, &saved).await?;
    *worker = run.reload(tab, worker).await?;
    run.submit(tab, "unlock", pass).await?;
    Ok(())
}
