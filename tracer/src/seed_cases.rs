//! Integrated seed-backup ceremony checks against the document, encrypted bytes and fixtures.
use super::*;

const FAMILIES: [&str; 3] = ["machines", "passes", "handoffs"];

async fn wait_stage(
    site: &'static str,
    run: &Run<'_>,
    tab: &Tab,
    stage: &str,
) -> Result<(), String> {
    let observer = observer::Call::begin(
        site,
        "seed.wait_stage",
        Some(&tab.session),
        json!({"stage":match stage {"display"=>"display","answering"=>"answering","inactive"=>"inactive",_=>"unknown"}}),
    );

    for poll in 0..300 {
        observer.attempt(poll + 1);
        let ready = run.browser.evaluate(&tab.session, &format!(
            "(() => {{ const s=document.getElementById('tau-seed-backup'); return {} === 'inactive' ? s.hidden : !s.hidden && ({} === 'display' ? !!document.getElementById('tau-seed-backup-words') : !document.getElementById('tau-seed-backup-entry').hidden); }})()",
            json!(stage), json!(stage))).await?;
        if observer.poll(poll + 1, ready == true) {
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

pub(super) async fn skip(site: &'static str, run: &Run<'_>, tab: &Tab) -> Result<(), String> {
    let _observer = observer::Call::begin(site, "seed.skip", Some(&tab.session), json!({}));

    wait_stage("seed.skip.display", run, tab, "display").await?;
    click(run, tab, "seed-backup-answer").await?;
    wait_stage("seed.skip.answering", run, tab, "answering").await?;
    click(run, tab, "seed-backup-skip").await?;
    wait_stage("seed.skip.inactive", run, tab, "inactive").await
}

async fn phrase(
    site: &'static str,
    run: &Run<'_>,
    tab: &Tab,
) -> Result<observer::DisplayedPhrase, String> {
    let _observer = observer::Call::begin(site, "seed.phrase", Some(&tab.session), json!({}));

    wait_stage("seed.phrase.display", run, tab, "display").await?;
    observer::displayed_words(run, tab,
        "Array.from(document.querySelectorAll('#tau-seed-backup-words li'), n=>n.textContent).join(' ')").await
}

async fn document(run: &Run<'_>, tab: &Tab) -> Result<Value, String> {
    run.browser.evaluate(&tab.session, r#"(() => {
        const root=document.documentElement.cloneNode(true);
        for(const node of [root,...root.querySelectorAll('*')]) {
            const attributes=Array.from(node.attributes,a=>[a.name,a.value]).sort(([a],[b])=>a.localeCompare(b));
            for(const a of Array.from(node.attributes)) node.removeAttribute(a.name);
            for(const [name,value] of attributes) node.setAttribute(name,value);
        }
        return {html:root.outerHTML, fields:Array.from(document.querySelectorAll('input,textarea,select'), n=>[n.id,n.value])};
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

fn retained_public_configuration(baseline: &Value, tracer: bool) -> Value {
    let mut expected = baseline.clone();
    if tracer {
        for (id, value) in [
            ("tau-poc-endpoint", "https://fixture.invalid/completions"),
            ("tau-poc-model", "fixture"),
        ] {
            let field = expected["fields"]
                .as_array_mut()
                .expect("field snapshot")
                .iter_mut()
                .find(|field| field[0] == id)
                .expect("public inference field");
            field[1] = json!(value);
        }
    }
    expected
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
        let mut case = Case::new(
            "seed_cases.c001",
            &format!(
                "seed-backup collision control {}: {}",
                index + 1,
                if tracer { "tracer" } else { "served" }
            ),
        );
        run.put(
            tab,
            &reader::build_at(
                "file.seed_cases.build.001",
                pass,
                &[json!({"seed":{"mnemonic":words}})],
            ),
        )
        .await?;
        *worker = run.reload("seed_cases.rs::reload#1", tab, worker).await?;
        run.submit(tab, "unlock", pass).await?;
        case.check(
            "seed_cases.a001",
            "control owing the seed-backup ceremony displays exactly its twelve words",
            phrase("seed.collision.initial_phrase", run, tab)
                .await?
                .collision(&observer::collision_phrase(index + 1, words)),
        );
        language(run, tab, &mut case).await?;
        run.browser.evaluate(&tab.session,
            "window.__seedLanguageLeak=document.createElement('span'); window.__seedLanguageLeak.hidden=true; window.__seedLanguageLeak.textContent='proven'; document.body.append(window.__seedLanguageLeak)").await?;
        case.check(
            "seed_cases.a002",
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
        wait_stage("seed.collision.initial_answering", run, tab, "answering").await?;
        language(run, tab, &mut case).await?;
        let answering = document(run, tab).await?;
        run.browser.evaluate(&tab.session,&format!(r#"(() => {{
            window.__seedLeak={}.split(' ').map(word=>{{const n=document.createElement('span'); n.hidden=true;n.textContent=word;document.body.append(n);return n;}});
        }})()"#,json!(words))).await?;
        case.check(
            "seed_cases.a003",
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
            "seed_cases.a004",
            "removing the planted elements restores the entire answering document",
            absent(run, tab, &answering).await?,
        );
        if check_mismatch {
            reenter(
                "seed.collision.mismatch_entry",
                run,
                tab,
                controls[(index + 1) % controls.len()],
            )
            .await?;
            let returned = wait_stage("seed.collision.mismatch_display", run, tab, "display")
                .await
                .is_ok();
            case.check(
                "seed_cases.a005",
                "control mismatch returns to its original display",
                crate::state_inputs::all!(
                    returned,
                    phrase("seed.collision.mismatch_phrase", run, tab)
                        .await?
                        .collision(&observer::collision_phrase(index + 1, words))
                ),
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
        phrase("seed.collision.unlock_phrase", run, tab).await?;
        click(run, tab, "seed-backup-answer").await?;
        wait_stage("seed.collision.unlock_answering", run, tab, "answering").await?;
        reenter("seed.collision.complete_entry", run, tab, words).await?;
        wait_stage("seed.collision.completed", run, tab, "inactive").await?;
        language(run, tab, &mut case).await?;
        case.check(
            "seed_cases.a006",
            "control full re-entry is durably recorded",
            read(
                "reader.call.seed.collision_completion",
                &run.dump_at("file.seed_cases.dump.001", tab).await?,
                pass,
            )?
            .seed_backups_at("reader.aux.call.seed.collision_completion.seed_backups")?
                == ["full_reentry"],
        );
        let old = worker.clone();
        click(run, tab, "redisplay").await?;
        *worker = run.worker(tab, Some(&old), false).await?;
        run.submit(tab, "unlock", pass).await?;
        skip("seed.collision.redisplay_skip", run, tab).await?;
        let old = worker.clone();
        click(run, tab, "redisplay").await?;
        *worker = run.worker(tab, Some(&old), false).await?;
        run.submit(tab, "unlock", pass).await?;
        phrase("seed.collision.redisplay_phrase", run, tab).await?;
        click(run, tab, "seed-backup-answer").await?;
        wait_stage("seed.collision.redisplay_answering", run, tab, "answering").await?;
        let redisplay = document(run, tab).await?;
        language(run, tab, &mut case).await?;
        click(run, tab, "seed-backup-skip").await?;
        wait_stage("seed.collision.redisplay_inactive", run, tab, "inactive").await?;
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
                "seed_cases.a007",
                "answering document and fields are identical under different seeds",
                documents.answering == baseline.answering,
            );
            case.check(
                "seed_cases.a008",
                "locked document and fields are identical under different seeds",
                documents.locked == baseline.locked,
            );
            case.check(
                "seed_cases.a009",
                "re-display answering document and fields are identical under different seeds",
                documents.redisplay == baseline.redisplay,
            );
            case.check(
                "seed_cases.a010",
                "wrong-passphrase document and fields are identical under different seeds",
                documents.wrong_pass == baseline.wrong_pass,
            );
        } else {
            baseline = Some(documents);
        }
        language(run, tab, &mut case).await?;
        case.finish(cases);
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
        "seed_cases.a011",
        "CNF-44: page text makes none of the reserved claims",
        language_clear(run, tab).await?,
    );
    Ok(())
}

async fn reenter(site: &'static str, run: &Run<'_>, tab: &Tab, words: &str) -> Result<(), String> {
    let observer = observer::Call::begin(site, "seed.reenter", Some(&tab.session), json!({}));
    observer.fact(
        "words_input",
        observer::reentry_matches(site, &tab.session, words),
    );

    let cleared = run.browser.evaluate(&tab.session, &format!(
        "(() => {{ const f=document.getElementById('tau-seed-backup-input'); f.value={}; document.getElementById('tau-seed-backup-check').click(); return f.value === ''; }})()", json!(words))).await?;
    if !observer.fact("field_cleared", cleared == true) {
        return Err("re-entry field not cleared immediately".into());
    }
    Ok(())
}

async fn allocate(
    site: &'static str,
    run: &Run<'_>,
    worker: &Worker,
    family: &str,
) -> Result<Value, String> {
    seed_operations::allocation(site, worker, family);
    run.browser.evaluate(&worker.session, &format!(
        "(async()=>{{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href); return JSON.parse(await m.test_allocate({}));}})()",json!(family))).await
}

async fn gated(
    site: &'static str,
    run: &Run<'_>,
    worker: &Worker,
    case: &mut Case,
) -> Result<(), String> {
    for family in FAMILIES {
        case.check(
            "seed_cases.a012",
            &format!("{family}: allocation refuses with the seed-backup gate's reason"),
            allocate(site, run, worker, family).await?["refused"]
                == tau_web::allocation::Refusal::BackupMissing.to_string(),
        );
    }
    Ok(())
}

async fn refused_dispatch(
    site: &'static str,
    run: &Run<'_>,
    worker: &Worker,
    args: &Value,
    case: &mut Case,
) -> Result<(), String> {
    let _dispatch = seed_operations::Dispatch::begin(site, run, worker, args);
    let before = run.inspect(worker).await?;
    take(run.seen);
    let command = run
        .harness_run("seed_cases.rs#1", worker, args.clone())
        .await?;
    let collect = run
        .harness_collect("seed_cases.rs#2", worker, args.clone())
        .await?;
    let observed = take(run.seen);
    case.check(
        "seed_cases.a013",
        "command and collection refuse before relay/SSH contact and append",
        command == json!({"outcome":{"refused":"seed_backup"}})
            && collect == command
            && observed.relay_accepted == 0
            && observed.ssh_connections == 0
            && run.inspect(worker).await? == before,
    );
    Ok(())
}

fn read(site: &'static str, files: &Files, pass: &str) -> Result<reader::Opened, String> {
    reader::read_at(site, &store_files(files), pass)
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
    let _scenario_span = completion::scenario("seed_cases.run");
    run.browser
        .call(
            None,
            "Target.activateTarget",
            json!({"targetId":tab.target}),
        )
        .await?;
    *worker = run.worker(tab, None, false).await?;
    let saved = store_files(&run.dump_at("file.seed_cases.dump.002", tab).await?);
    let selected = selection::value("TAU_TRACER_SEED_CASE").unwrap_or_else(|_| "all".into());
    let full_run = selected == "all";
    let documents = collision_controls(run, tab, worker, pass, tracer, full_run, cases).await?;
    if full_run || selected == "create" || selected == "mismatch" {
        let mut case = Case::new(
            "seed_cases.c002",
            if tracer {
                "seed-backup create, hidden answer and mismatch: tracer"
            } else {
                "seed-backup create, hidden answer and mismatch: served"
            },
        );
        run.put(tab, &Files::new()).await?;
        *worker = run.reload("seed_cases.rs::reload#2", tab, worker).await?;
        run.submit(tab, "create", pass).await?;
        let words = phrase("seed.create.initial_phrase", run, tab).await?;
        let before = run.dump_at("file.seed_cases.dump.003", tab).await?;
        let opened = read("reader.call.seed.created", &before, pass)?;
        case.check(
            "seed_cases.a014",
            "all twelve numbered words are the reader's record-0 mnemonic",
            crate::state_inputs::all!(
                words.mnemonic(
                    &opened.mnemonic_operand_at("reader.aux.call.seed.created.mnemonic")?
                ),
                words.split(' ').count() == 12
            ),
        );
        let text = run
            .browser
            .evaluate(
                &tab.session,
                "document.getElementById('tau-seed-backup-state').textContent",
            )
            .await?;
        case.check(
            "seed_cases.a015",
            "page explains all three allocation families are refused until recorded",
            text.as_str()
                .is_some_and(|t| t.contains("machines, relay passes and handoffs are refused")),
        );
        refused_dispatch(
            "seed.create.refused_dispatch",
            run,
            worker,
            &args("fixture"),
            &mut case,
        )
        .await?;
        if tracer {
            gated("seed.create.display_allocations", run, worker, &mut case).await?;
        }
        case.check(
            "seed_cases.a016",
            "nothing appended at display",
            file_inputs::equal_primary(
                "seed_cases.a016.1",
                "seed_cases.a016",
                &(run.dump_at("file.seed_cases.dump.004", tab).await?),
                &(before),
            ),
        );
        language(run, tab, &mut case).await?;
        click(run, tab, "seed-backup-answer").await?;
        wait_stage("seed.create.answering", run, tab, "answering").await?;
        case.check(
            "seed_cases.a017",
            "answering document and fields equal an independent seed's document",
            absent(run, tab, &documents.answering).await?,
        );
        language(run, tab, &mut case).await?;
        let different = bip39::Mnemonic::from_entropy(&[17; 16])
            .map_err(|e| e.to_string())?
            .to_string();
        reenter("seed.create.mismatch_entry", run, tab, &different).await?;
        let returned = wait_stage("seed.create.mismatch_display", run, tab, "display")
            .await
            .is_ok();
        case.check(
            "seed_cases.a018",
            "different valid mnemonic returns to the original display",
            crate::state_inputs::all!(
                returned,
                phrase("seed.create.mismatch_phrase", run, tab)
                    .await?
                    .same_as(&words)
            ),
        );
        case.check(
            "seed_cases.a019",
            "reader finds no completion after mismatch",
            crate::state_inputs::all!(
                file_inputs::equal_primary(
                    "seed_cases.a019.1",
                    "seed_cases.a019",
                    &(run.dump_at("file.seed_cases.dump.005", tab).await?),
                    &(before),
                ),
                read(
                    "reader.call.seed.mismatch_absence",
                    &run.dump_at("file.seed_cases.dump.006", tab).await?,
                    pass,
                )?
                .seed_backups_at("reader.aux.call.seed.mismatch_absence.seed_backups")?
                .is_empty()
            ),
        );
        if tracer {
            gated("seed.create.mismatch_allocations", run, worker, &mut case).await?;
        }
        language(run, tab, &mut case).await?;
        case.finish(cases);
    }
    if full_run {
        for full in [true, false] {
            let mut case = Case::new(
                "seed_cases.c003",
                match (tracer, full) {
                    (true, true) => "seed-backup full re-entry and restart: tracer",
                    (false, true) => "seed-backup full re-entry and restart: served",
                    (true, false) => "seed-backup explicit skip and restart: tracer",
                    (false, false) => "seed-backup explicit skip and restart: served",
                },
            );
            run.put(tab, &Files::new()).await?;
            *worker = run.reload("seed_cases.rs::reload#3", tab, worker).await?;
            run.submit(tab, "create", pass).await?;
            let words = phrase("seed.completion.initial_phrase", run, tab).await?;
            click(run, tab, "seed-backup-answer").await?;
            wait_stage("seed.completion.answering", run, tab, "answering").await?;
            case.check(
                "seed_cases.a020",
                "completion's answering document equals an independent seed's document",
                absent(run, tab, &documents.answering).await?,
            );
            if full {
                reenter(
                    "seed.completion.full_entry",
                    run,
                    tab,
                    &format!("  {}\n", words.replace(' ', "\t")),
                )
                .await?;
            } else {
                click(run, tab, "seed-backup-skip").await?;
            }
            wait_stage("seed.completion.inactive", run, tab, "inactive").await?;
            let completion = if full { "full_reentry" } else { "skipped" };
            let opened = read(
                "reader.call.seed.completion",
                &run.dump_at("file.seed_cases.dump.007", tab).await?,
                pass,
            )?;
            case.check(
                "seed_cases.a021",
                "independent reader decrypts this seed's distinct completion with no words",
                opened.seed_backups_at("reader.aux.call.seed.completion.seed_backups")?
                    == [completion]
                    && opened.records.len() == 2,
            );
            let text = run.view_at("view.seed.completion_text", tab).await?;
            case.check(
                "seed_cases.a022",
                "page states which completion was recorded",
                text.completion_text(full),
            );
            language(run, tab, &mut case).await?;
            if tracer {
                for family in FAMILIES {
                    case.check(
                        "seed_cases.a023",
                        &format!("{family}: first index admitted"),
                        allocate("seed.completion.first_allocations", run, worker, family).await?["identity"]["index"] == 0,
                    );
                }
                let opened = read(
                    "reader.call.seed.allocations_after_completion",
                    &run.dump_at("file.seed_cases.dump.008", tab).await?,
                    pass,
                )?;
                let reservations: Vec<Value> = opened
                    .records
                    .iter()
                    .filter_map(|(_, p)| {
                        crate::journal::event(p)
                            .ok()?
                            .pointer("/allocation/reserve")
                            .cloned()
                    })
                    .collect();
                case.check(
                    "seed_cases.a024",
                    "reader sees all three reservations after completion",
                    reservations.len() == 3
                        && reservations.iter().enumerate().all(|(source_index, r)| {
                            let _source_slot =
                                semantic::Slot::new("reader.aux.seed_allocation", source_index);
                            r["seed"]
                                == opened
                                    .seed_id_at("reader.aux.call.seed.allocations.seed_id")
                                    .unwrap()
                                && r["index"] == 0
                        }),
                );
            }
            *worker = run.reload("seed_cases.rs::reload#4", tab, worker).await?;
            run.submit(tab, "unlock", pass).await?;
            case.check(
                "seed_cases.a025",
                "restart shows no seed-backup ceremony and retains the same record",
                run.inspect(worker).await?["seed_backup_stage"] == "inactive"
                    && read(
                        "reader.call.seed.completion_reopened",
                        &run.dump_at("file.seed_cases.dump.009", tab).await?,
                        pass,
                    )?
                    .seed_backups_at("reader.aux.call.seed.completion_reopened.seed_backups")?
                        == [completion],
            );
            if tracer {
                for family in FAMILIES {
                    case.check(
                        "seed_cases.a026",
                        &format!("{family}: next index after reopen"),
                        allocate("seed.completion.next_allocations", run, worker, family).await?["identity"]["index"] == 1,
                    );
                }
            }
            case.finish(cases);
        }
    }
    if tracer && (full_run || selected == "failed-append") {
        for full in [false, true] {
            let mut case = Case::new(
                "seed_cases.c004",
                if full {
                    "seed-backup full re-entry failed OPFS move"
                } else {
                    "seed-backup skip failed OPFS move"
                },
            );
            run.put(tab, &Files::new()).await?;
            *worker = run.reload("seed_cases.rs::reload#5", tab, worker).await?;
            run.submit(tab, "create", pass).await?;
            let words = phrase("seed.failed_append.initial_phrase", run, tab).await?;
            let before = store_files(
                &file_inputs::dump_at(run, tab, DUMP, "seed.failed_append.baseline").await?,
            );
            click(run, tab, "seed-backup-answer").await?;
            wait_stage("seed.failed_append.answering", run, tab, "answering").await?;
            run.browser.evaluate(&worker.session,"(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href); await m.test_seed_backup_fail_append();})()").await?;
            if full {
                reenter("seed.failed_append.full_entry", run, tab, &words).await?;
            } else {
                click(run, tab, "seed-backup-skip").await?;
            }
            {
                let observation = observer::Call::begin(
                    "seed.failed_append.observed",
                    "serial.observation",
                    Some(&tab.session),
                    json!({"bound":300,"false_sleep_ms":50,"requires_ready":false,"completion":if full {"full_reentry"} else {"skip"}}),
                );
                for poll in 0..300 {
                    observation.attempt(poll + 1);
                    if observation.poll(
                        poll + 1,
                        observation.inspect(run, worker).await?["seed_backup_stage"]
                            == "append_failed",
                    ) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            let state = run.inspect(worker).await?;
            case.check(
                "seed_cases.a027",
                "failed completion is not applied and still owed",
                state["seed_backup_owed"] == true && state["seed_backup_completion"].is_null(),
            );
            let page = run
                .browser
                .evaluate(&tab.session, "document.body.textContent")
                .await?;
            case.check(
                "seed_cases.a028",
                "page says not recorded, still owed, reload and unlock",
                page.as_str().is_some_and(|t| {
                    t.contains("not recorded")
                        && t.contains("Reload and unlock")
                        && t.contains("seed-backup ceremony is still owed")
                }),
            );
            gated("seed.failed_append.allocations", run, worker, &mut case).await?;
            language(run, tab, &mut case).await?;
            *worker = run.reload("seed_cases.rs::reload#6", tab, worker).await?;
            run.submit(tab, "unlock", pass).await?;
            case.check(
                "seed_cases.a029",
                "next unlock owes the same words and reader finds no completion",
                crate::state_inputs::all!(
                    phrase("seed.failed_append.reopened_phrase", run, tab)
                        .await?
                        .same_as(&words),
                    read(
                        "reader.call.seed.failed_completion_absence",
                        &run.dump_at("file.seed_cases.dump.010", tab).await?,
                        pass,
                    )?
                    .seed_backups_at("reader.aux.call.seed.failed_completion_absence.seed_backups")?
                    .is_empty(),
                    read(
                        "reader.call.seed.failed_completion_current",
                        &run.dump_at("file.seed_cases.dump.011", tab).await?,
                        pass,
                    )?
                    .records
                        == reader::read_at(
                            "reader.call.seed.failed_completion_baseline",
                            &before,
                            pass,
                        )?
                        .records
                ),
            );
            case.finish(cases);
        }
    }
    if full_run {
        let mut case = Case::new(
            "seed_cases.c005",
            if tracer {
                "seed-backup creation-finishing unlock: tracer"
            } else {
                "seed-backup creation-finishing unlock: served"
            },
        );
        run.put(
            tab,
            &reader::build_at("file.seed_cases.build.002", pass, &[]),
        )
        .await?;
        *worker = run.reload("seed_cases.rs::reload#7", tab, worker).await?;
        run.submit(tab, "unlock", pass).await?;
        case.check(
            "seed_cases.a030",
            "envelope-only unlock displays the mnemonic the reader finds in new record 0",
            phrase("seed.envelope.phrase", run, tab).await?.mnemonic(
                &(read(
                    "reader.call.seed.envelope_finished",
                    &run.dump_at("file.seed_cases.dump.012", tab).await?,
                    pass,
                )?
                .mnemonic_operand_at("reader.aux.call.seed.envelope_finished.mnemonic")?),
            ),
        );
        case.finish(cases);
        for answering in [false, true] {
            for trigger in ["lock", "hidden", "pagehide", "pageshow", "close", "crash"] {
                let mut case = Case::new(
                    "seed_cases.c006",
                    &format!(
                        "seed-backup interrupted {} by {trigger}: {}",
                        if answering { "answering" } else { "display" },
                        if tracer { "tracer" } else { "served" }
                    ),
                );
                run.put(tab, &Files::new()).await?;
                *worker = run.reload("seed_cases.rs::reload#8", tab, worker).await?;
                run.submit(tab, "create", pass).await?;
                let words = phrase("seed.interrupt.initial_phrase", run, tab).await?;
                let before = store_files(&run.dump_at("file.seed_cases.dump.013", tab).await?);
                if answering {
                    click(run, tab, "seed-backup-answer").await?;
                    wait_stage("seed.interrupt.answering", run, tab, "answering").await?;
                }
                run.browser
                    .evaluate(
                        &tab.session,
                        "document.getElementById('tau-seed-backup-input').value='discard this entry'",
                    )
                    .await?;
                let old = worker.clone();
                let interruption = operation_windows::Operation::begin(
                    "seed.interrupt",
                    &old,
                    history::active_case_id()
                        .and_then(|id| {
                            id.rsplit_once(".p")
                                .and_then(|(_, n)| n.parse::<usize>().ok())
                        })
                        .is_some_and(|n| {
                            ["lock", "hidden", "pagehide", "pageshow", "close", "crash"]
                                .get((n - 1) % 6)
                                == Some(&trigger)
                        }),
                );
                match trigger {
                    "lock" => interruption.page(
                        &tab.session,
                        "document.getElementById(\"tau-lock\").click()",
                    ),
                    "pagehide" | "pageshow" => interruption.page(
                        &tab.session,
                        &format!(
                            "dispatchEvent(new PageTransitionEvent({},{{persisted:{}}}))",
                            json!(trigger),
                            trigger == "pageshow"
                        ),
                    ),
                    "close" | "crash" => {
                        if trigger == "crash" {
                            interruption.expect(Some(&tab.session), "Page.crash", json!({}));
                        }
                        interruption.expect(
                            None,
                            "Target.closeTarget",
                            json!({"targetId":tab.target}),
                        );
                    }
                    "hidden" => {
                        interruption.expect(
                            None,
                            "Target.createTarget",
                            json!({"url":"about:blank"}),
                        );
                    }
                    _ => {}
                }
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
                        interruption.expect(None, "Target.activateTarget", json!({"targetId":id}));
                        interruption.expect(None, "Target.closeTarget", json!({"targetId":id}));
                        interruption.expect(
                            None,
                            "Target.activateTarget",
                            json!({"targetId":tab.target}),
                        );
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
                interruption.finish();
                case.check(
                    "seed_cases.a031",
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
                case.check("seed_cases.a032",
&format!("{trigger}: next unlock still owes same seed-backup ceremony with nothing appended"),
crate::state_inputs::all!(
phrase("seed.interrupt.reopened_phrase", run,tab).await?.same_as(&words),
file_inputs::equal_primary("seed_cases.a032.1", "seed_cases.a032", &(store_files(&run.dump_at("file.seed_cases.dump.014", tab).await?)), &(before))
));
                language(run, tab, &mut case).await?;
                case.finish(cases);
            }
        }
        // Re-display retires execution while preserving logical sessions and unresolved effects.
        let mut case = Case::new(
            "seed_cases.c007",
            if tracer {
                "seed-backup re-display ends dispatch connections and waits"
            } else {
                "seed-backup re-display requires passphrase: served"
            },
        );
        skip("seed.redisplay.initial_skip", run, tab).await?;
        let mut before = run.inspect(worker).await?;
        let mut socket_input = None;
        if tracer {
            setup_cases::approve("seed.redisplay.setup_approve", run, tab, worker).await?;
            binding_cases::prepare(run, tab, worker, pass).await?;
            take(run.seen);
            fresh_pace(run.relay);
            let mut request = args("fixture");
            request["command"] = LOCK_COMMAND.into();
            let exec_input = fixture_inputs::static_wait(run, worker, &case.id, "exec");
            let socket = fixture_inputs::static_wait(run, worker, &case.id, "socket");
            fixture_inputs::static_start(&exec_input, Some(&socket), run, worker, request).await?;
            socket_input = Some(socket);
            case.check(
                "seed_cases.a033",
                "running command reached fixture exec",
                settle_for(
                    "seed.redisplay.running_exec",
                    run.seen,
                    20,
                    json!({"command":"lock_command"}),
                    |s, observation| {
                        fixture_predicates::exec(s, LOCK_COMMAND, &exec_input, observation)
                    },
                )
                .await,
            );
            before = run.inspect(worker).await?;
            run.browser.evaluate(&worker.session,&format!("self.__seedHeld = {}.then(r=>{{self.__seedHeldDone=true;return r;}}); self.__seedHeldDone=false; true",run_expression(&args("fixture")))).await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
            case.check(
                "seed_cases.a034",
                "held request is waiting without a second intent",
                run.browser
                    .evaluate(&worker.session, "self.__seedHeldDone")
                    .await?
                    == false
                    && run.inspect(worker).await? == before,
            );
        }
        let old = worker.clone();
        if let Some(input) = socket_input.as_ref() {
            fixture_inputs::seed_click(input, run, tab, &old, "redisplay").await?;
        } else {
            click(run, tab, "redisplay").await?;
        }
        *worker = run.worker(tab, Some(&old), false).await?;
        case.check(
            "seed_cases.a035",
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
            let gone = settle_for(
                "seed.redisplay.socket_closed",
                run.seen,
                20,
                json!({}),
                |s, observation| {
                    fixture_predicates::socket(s, true, socket_input.as_ref().unwrap(), observation)
                },
            )
            .await;
            case.check(
                "seed_cases.a036",
                "before words, relay and SSH connections ended and held worker is gone",
                gone && run
                    .sshd
                    .all_ended_at(Some("seed.redisplay.ssh_closed"), json!({}))
                    .await
                    && !run.live_workers(tab).contains(&old),
            );
        }
        drop(socket_input);
        run.submit(tab, "unlock", pass).await?;
        let words = phrase("seed.redisplay.phrase", run, tab).await?;
        language(run, tab, &mut case).await?;
        refused_dispatch(
            "seed.reentry.displayed_refusal",
            run,
            worker,
            &args("fixture"),
            &mut case,
        )
        .await?;
        click(run, tab, "seed-backup-answer").await?;
        wait_stage("seed.redisplay.answering", run, tab, "answering").await?;
        let expected = retained_public_configuration(&documents.redisplay, tracer);
        case.check(
            "seed_cases.a037",
            "re-display removes words while retaining exactly the admitted public endpoint and model",
            absent(run, tab, &expected).await?,
        );
        refused_dispatch(
            "seed.reentry.answering_refusal",
            run,
            worker,
            &args("fixture"),
            &mut case,
        )
        .await?;
        reenter("seed.redisplay.full_entry", run, tab, &words).await?;
        wait_stage("seed.redisplay.inactive", run, tab, "inactive").await?;
        case.check(
            "seed_cases.a038",
            "re-display journals another completion",
            read(
                "reader.call.seed.redisplay_completion",
                &run.dump_at("file.seed_cases.dump.015", tab).await?,
                pass,
            )?
            .seed_backups_at("reader.aux.call.seed.redisplay_completion.seed_backups")?
                == ["skipped", "full_reentry"],
        );
        if tracer {
            let after = run.inspect(worker).await?;
            case.check(
                "seed_cases.a039",
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
                "seed_cases.a040",
                "no second exec after completion",
                observed.ssh_exec.is_empty(),
            );
        }
        let old = worker.clone();
        click(run, tab, "redisplay").await?;
        *worker = run.worker(tab, Some(&old), false).await?;
        let persisted = store_files(&run.dump_at("file.seed_cases.dump.016", tab).await?);
        run.submit(tab, "unlock", WRONG_PASSPHRASE).await?;
        case.check(
            "seed_cases.a041",
            "wrong passphrase shows no word and journals nothing",
            crate::state_inputs::all!(
                absent(
                    run,
                    tab,
                    &retained_public_configuration(&documents.wrong_pass, tracer)
                )
                .await?,
                file_inputs::equal_primary(
                    "seed_cases.a041.1",
                    "seed_cases.a041",
                    &(store_files(&run.dump_at("file.seed_cases.dump.017", tab).await?)),
                    &(persisted),
                )
            ),
        );
        case.finish(cases);
    }
    run.put(tab, &saved).await?;
    *worker = run.reload("seed_cases.rs::reload#9", tab, worker).await?;
    run.submit(tab, "unlock", pass).await?;
    Ok(())
}
