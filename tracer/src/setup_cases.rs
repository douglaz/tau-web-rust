//! Setup approval and per-entry answers through the page, in both builds.
use super::*;

pub(super) async fn click(run: &Run<'_>, tab: &Tab, selector: &str) -> Result<(), String> {
    run.browser
        .evaluate(
            &tab.session,
            &format!("document.querySelector({}).click()", json!(selector)),
        )
        .await?;
    Ok(())
}
pub(super) async fn approve(
    site: &'static str,
    run: &Run<'_>,
    tab: &Tab,
    worker: &Worker,
) -> Result<(), String> {
    let observer = observer::Call::begin(site, "setup.approve", Some(&tab.session), json!({}));

    let existing = observer.inspect(run, worker).await?["setup"]
        .as_array()
        .is_some_and(|m| !m.is_empty());
    observer.domain(json!({"existing":existing,"required_setup_count":2}));
    if existing {
        return Ok(());
    }
    click(run, tab, "#tau-setup-approve").await?;
    for poll in 0..300 {
        observer.attempt(poll + 1);
        if observer.poll(
            poll + 1,
            observer.inspect(run, worker).await?["setup"]
                .as_array()
                .is_some_and(|m| m.len() == 2),
        ) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err("setup approval did not finish".into())
}
async fn no_preselection(run: &Run<'_>, tab: &Tab) -> Result<bool, String> {
    Ok(run.browser.evaluate(&tab.session,r#"(()=>{
      const groups=[...document.querySelectorAll('[data-class-answers]')];
      const buttons=groups.flatMap(g=>[...g.children]);
      return groups.length===2 && buttons.length===6 && buttons.every(b=>
        b.tagName==='BUTTON' && b.type==='button' && !b.hasAttribute('checked') &&
        !b.hasAttribute('selected') && !b.hasAttribute('autofocus') &&
        !b.checked && !b.selected && !b.autofocus && document.activeElement!==b && !b.closest('form'));
    })()"#).await?==true)
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
    let _scenario_span = completion::scenario("setup_cases.run");
    run.browser
        .call(
            None,
            "Target.activateTarget",
            json!({"targetId":tab.target}),
        )
        .await?;
    *worker = run.worker(tab, None, false).await?;
    let saved = store_files(&run.dump_at("file.setup_cases.dump.001", tab).await?);
    run.put(tab, &Files::new()).await?;
    *worker = run.reload("setup_cases.rs::reload#1", tab, worker).await?;
    let build = if tracer { "tracer" } else { "served" };
    let mut ceremony = Case::new(
        "setup_cases.c001",
        &format!("setup ceremony refusal: {build}"),
    );
    let before = run.dump_at("file.setup_cases.dump.002", tab).await?;
    ceremony.check(
        "setup_cases.a001",
        "locked approval changes nothing",
        crate::state_inputs::all!(
            file_windows::setup_approve(run, worker).await?["error"] == "locked",
            file_inputs::equal_primary(
                "setup_cases.a001.1",
                "setup_cases.a001",
                &(run.dump_at("file.setup_cases.dump.003", tab).await?),
                &(before),
            )
        ),
    );
    run.submit(tab, "create", pass).await?;
    let before = run.dump_at("file.setup_cases.dump.004", tab).await?;
    ceremony.check(
        "setup_cases.a002",
        "active ceremony refuses approval with no record",
        crate::state_inputs::all!(
            file_windows::setup_approve(run, worker).await?["error"] == "seed_backup",
            file_inputs::equal_primary(
                "setup_cases.a002.1",
                "setup_cases.a002",
                &(run.dump_at("file.setup_cases.dump.005", tab).await?),
                &(before),
            )
        ),
    );
    ceremony.finish(cases);
    seed_cases::skip("setup.ceremony.skip", run, tab).await?;
    let mut card = Case::new(
        "setup_cases.c002",
        &format!("setup batch card and indices: {build}"),
    );
    let before = run.inspect(worker).await?;
    let rendered = run
        .browser
        .evaluate(
            &tab.session,
            "document.getElementById('tau-setup').textContent",
        )
        .await?;
    let text = rendered.as_str().unwrap_or("");
    card.check(
        "setup_cases.a003",
        "all fixture entries, facts, cost and recurring meaning appear before approval",
        [
            "fixture:",
            "fixture-other:",
            "Fixture vendor",
            "Fixture machine",
            "Fixture region",
            "1000 sat per month",
            "2000 sat per month",
            "3000 sat per month",
            "36000 sat per year",
            "bound alone in its own session",
            "from the moment it is created",
            "destroyed or abandoned",
            "whether or not setup finishes",
            "never pays",
            "cannot stop",
            "only you can",
            "fixture data",
        ]
        .iter()
        .all(|s| text.contains(s)),
    );
    let opened = reader::read_at(
        "reader.call.setup.pre_approval",
        &store_files(&run.dump_at("file.setup_cases.dump.006", tab).await?),
        pass,
    )?;
    card.check(
        "setup_cases.a004",
        "no approval or reservation before click",
        opened.records.len() == 2 && before["setup"] == json!([]),
    );
    take(run.seen);
    let report = run
        .harness_run("setup_cases.rs#1", worker, args("fixture"))
        .await?;
    let seen = take(run.seen);
    card.check(
        "setup_cases.a005",
        "unapproved command refuses before contact with no append",
        report["outcome"] == json!({"refused":"no-entry","machine":"fixture"})
            && seen.relay_accepted == 0
            && seen.ssh_connections == 0
            && run.inspect(worker).await? == before,
    );
    approve("setup.card.approve", run, tab, worker).await?;
    let after = run.inspect(worker).await?;
    let opened = reader::read_at(
        "reader.call.setup.approved",
        &store_files(&run.dump_at("file.setup_cases.dump.007", tab).await?),
        pass,
    )?;
    let approval: Value = crate::journal::event(&opened.records[2].1).map_err(|e| e.to_string())?;
    let approval = &approval["setup"]["approval"];
    card.check(
        "setup_cases.a006",
        "one approval records exactly the offer and both indices",
        opened.records.len() == 3
            && approval["monthly_sat"] == 3000
            && approval["annual_sat"] == 36000
            && approval["entries"].as_array().is_some_and(|entries| {
                entries.iter().enumerate().all(|(i, a)| {
                    let _source_slot = semantic::Slot::new("reader.aux.setup_approved", i);
                    a["entry"] == before["setup_offer"][i]
                        && a["identity"]["index"] == i
                        && a["identity"]["family"] == "machines"
                        && a["identity"]["seed"]
                            == opened
                                .seed_id_at("reader.aux.call.setup.approved.seed_id")
                                .unwrap()
                })
            })
            && after["setup"]
                .as_array()
                .is_some_and(|m| m.iter().all(|m| m["class"].is_null())),
    );
    card.finish(cases);
    let mut boundary = Case::new(
        "setup_cases.c003",
        &format!("setup rejects non-operator inputs: {build}"),
    );
    let before = run
        .inspect_state_at("state.setup.invalid.before", worker)
        .await?;
    let files = run.dump_at("file.setup_cases.dump.008", tab).await?;
    for key in [
        "class",
        "answer",
        "access_model",
        "setup",
        "entries",
        "question",
    ] {
        let mut request = args("fixture");
        request[key] = "sealed".into();
        for collect in [false, true] {
            let report = file_windows::setup_request(run, worker, request.clone(), collect).await?;
            boundary.check(
                "setup_cases.a007",
                &format!("{key}, collect={collect}: refuses without a record or state change"),
                crate::state_inputs::all!(
                    report["outcome"]["refused"] == "request",
                    run.inspect_state_at("state.setup.invalid.after", worker)
                        .await?
                        .same_at("setup_cases.a007", &before, &[""]),
                    file_inputs::equal_primary(
                        "setup_cases.a007.1",
                        "setup_cases.a007",
                        &(run.dump_at("file.setup_cases.dump.009", tab).await?),
                        &(files),
                    )
                ),
            );
        }
    }
    // Deliver through the worker's ordinary page-message handler, with exact malformed shapes.
    for message in [
        json!({"setup_approve":true,"entries":[]}),
        json!({"question":"custom"}),
        json!({"setup_answer":["fixture","yes"]}),
        json!({"setup_answer":{"machine":"fixture-other","answer":"sealed"}}),
        json!({"setup_answer":{"machine":"fixture-other","answer":"yes","access_model":"sealed"}}),
        json!({"setup_approve":"sealed"}),
    ] {
        file_windows::setup_page(run, worker, message.clone()).await?;
        boundary.check(
            "setup_cases.a008",
            &format!("page message {message} changes nothing"),
            crate::state_inputs::all!(
                run.inspect_state_at("state.setup.message.after", worker)
                    .await?
                    .same_at("setup_cases.a008", &before, &[""]),
                file_inputs::equal_primary(
                    "setup_cases.a008.1",
                    "setup_cases.a008",
                    &(run.dump_at("file.setup_cases.dump.010", tab).await?),
                    &(files),
                )
            ),
        );
    }
    boundary.finish(cases);
    let mut class = Case::new(
        "setup_cases.c004",
        &format!("setup class questions with nothing preselected: {build}"),
    );
    class.check(
        "setup_cases.a009",
        "no checked, selected, autofocus, focus or default action",
        no_preselection(run, tab).await?,
    );
    let text = run
        .browser
        .evaluate(
            &tab.session,
            "document.getElementById('tau-setup').textContent",
        )
        .await?;
    class.check("setup_cases.a010", "shipped wording and all three exact answers",["Will this machine serve people you have never met, for example by renting out space on it or hosting other people's accounts?","Yes","No, only me and people I know","Not sure","never holds spendable keys and is always bound alone"].iter().all(|s|text.as_str().unwrap_or("").contains(s)));
    *worker = run.reload("setup_cases.rs::reload#2", tab, worker).await?;
    run.submit(tab, "unlock", pass).await?;
    class.check(
        "setup_cases.a011",
        "reload remembers no draft answer",
        no_preselection(run, tab).await?,
    );
    for (machine, answer) in [("fixture", "not_sure"), ("fixture-other", "no")] {
        let class_input = observer::class_source(run, tab, machine, answer).await?;
        {
            let observation = observer::Call::begin(
                "setup.class.answer_applied",
                "serial.observation",
                Some(&tab.session),
                json!({"bound":300,"false_sleep_ms":50,"requires_ready":false,"machine":match machine {"fixture"=>"first","fixture-other"=>"second",_=>"unknown"},"answer":answer,"build":if tracer {"tracer"} else {"served"}}),
            );
            observation.causal_input(class_input);
            for poll in 0..300 {
                observation.attempt(poll + 1);
                if observation.poll(
                    poll + 1,
                    observation.class_ready(&observation.inspect(run, worker).await?, machine),
                ) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    let state = run.inspect(worker).await?;
    let opened = reader::read_at(
        "reader.call.setup.classified",
        &store_files(&run.dump_at("file.setup_cases.dump.011", tab).await?),
        pass,
    )?;
    let values: Vec<Value> = opened
        .records
        .iter()
        .map(|(_, p)| crate::journal::event(p).unwrap())
        .collect();
    class.check(
        "setup_cases.a012",
        "reader finds not sure as multi-tenant, no as single-purpose, maintained profile",
        values[3]["setup"]["class"]
            == json!({"machine":"fixture","answer":"not_sure","class":"multi_tenant"})
            && values[4]["setup"]["class"]
                == json!({"machine":"fixture-other","answer":"no","class":"single_purpose"})
            && state["setup"].as_array().unwrap().iter().all(|m| {
                m["access"] == json!({"model":"maintained","profile":"ad-hoc","revision":3})
            }),
    );
    let before = run.dump_at("file.setup_cases.dump.012", tab).await?;
    let second =
        file_windows::setup_answer(run, worker, json!({"machine":"fixture","answer":"yes"}))
            .await?;
    class.check(
        "setup_cases.a013",
        "second answer refuses with no record",
        crate::state_inputs::all!(
            second["error"].is_string(),
            file_inputs::equal_primary(
                "setup_cases.a013.1",
                "setup_cases.a013",
                &(run.dump_at("file.setup_cases.dump.013", tab).await?),
                &(before),
            )
        ),
    );
    class.finish(cases);
    run.put(tab, &saved).await?;
    *worker = run.reload("setup_cases.rs::reload#3", tab, worker).await?;
    run.submit(tab, "unlock", pass).await?;
    Ok(())
}
