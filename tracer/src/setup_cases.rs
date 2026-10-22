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
pub(super) async fn approve(run: &Run<'_>, tab: &Tab, worker: &Worker) -> Result<(), String> {
    if run.inspect(worker).await?["setup"]
        .as_array()
        .is_some_and(|m| !m.is_empty())
    {
        return Ok(());
    }
    click(run, tab, "#tau-setup-approve").await?;
    for _ in 0..300 {
        if run.inspect(worker).await?["setup"]
            .as_array()
            .is_some_and(|m| m.len() == 2)
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err("setup approval did not finish".into())
}
async fn act(run: &Run<'_>, worker: &Worker, expression: &str) -> Result<Value, String> {
    run.browser.evaluate(&worker.session,&format!("(async()=>{{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await {expression});}})()")).await
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
    run.browser
        .call(
            None,
            "Target.activateTarget",
            json!({"targetId":tab.target}),
        )
        .await?;
    *worker = run.worker(tab, None, false).await?;
    let saved = store_files(&run.dump(tab).await?);
    run.put(tab, &Files::new()).await?;
    *worker = run.reload(tab, worker).await?;
    let build = if tracer { "tracer" } else { "served" };
    let mut ceremony = Case::new(&format!("setup ceremony refusal: {build}"));
    let before = run.dump(tab).await?;
    ceremony.check(
        "locked approval changes nothing",
        act(run, worker, "m.setup_approve()").await?["error"] == "locked"
            && run.dump(tab).await? == before,
    );
    run.submit(tab, "create", pass).await?;
    let before = run.dump(tab).await?;
    ceremony.check(
        "active ceremony refuses approval with no record",
        act(run, worker, "m.setup_approve()").await?["error"] == "seed_backup"
            && run.dump(tab).await? == before,
    );
    cases.push(ceremony);
    seed_cases::skip(run, tab).await?;
    let mut card = Case::new(&format!("setup batch card and indices: {build}"));
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
    let opened = reader::read(&store_files(&run.dump(tab).await?), pass)?;
    card.check(
        "no approval or reservation before click",
        opened.records.len() == 2 && before["setup"] == json!([]),
    );
    take(run.seen);
    let report = run.harness_run(worker, args("fixture")).await?;
    let seen = take(run.seen);
    card.check(
        "unapproved command refuses before contact with no append",
        report["outcome"] == json!({"refused":"no-entry","machine":"fixture"})
            && seen.relay_accepted == 0
            && seen.ssh_connections == 0
            && run.inspect(worker).await? == before,
    );
    approve(run, tab, worker).await?;
    let after = run.inspect(worker).await?;
    let opened = reader::read(&store_files(&run.dump(tab).await?), pass)?;
    let approval: Value =
        serde_json::from_slice(&opened.records[2].1).map_err(|e| e.to_string())?;
    let approval = &approval["setup"]["approval"];
    card.check(
        "one approval records exactly the offer and both indices",
        opened.records.len() == 3
            && approval["monthly_sat"] == 3000
            && approval["annual_sat"] == 36000
            && approval["entries"].as_array().is_some_and(|entries| {
                entries.iter().enumerate().all(|(i, a)| {
                    a["entry"] == before["setup_offer"][i]
                        && a["identity"]["index"] == i
                        && a["identity"]["family"] == "machines"
                        && a["identity"]["seed"] == opened.seed_id().unwrap()
                })
            })
            && after["setup"]
                .as_array()
                .is_some_and(|m| m.iter().all(|m| m["class"].is_null())),
    );
    cases.push(card);
    let mut boundary = Case::new(&format!("setup rejects non-operator inputs: {build}"));
    let before = run.inspect(worker).await?;
    let files = run.dump(tab).await?;
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
            let report = if collect {
                run.harness_collect(worker, request.clone()).await?
            } else {
                run.harness_run(worker, request.clone()).await?
            };
            boundary.check(
                &format!("{key}, collect={collect}: refuses without a record or state change"),
                report["outcome"]["refused"] == "request"
                    && run.inspect(worker).await? == before
                    && run.dump(tab).await? == files,
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
        run.browser
            .evaluate(
                &worker.session,
                &format!("(async()=>{{await onmessage({{data:{message}}}); return true}})()"),
            )
            .await?;
        boundary.check(
            &format!("page message {message} changes nothing"),
            run.inspect(worker).await? == before && run.dump(tab).await? == files,
        );
    }
    cases.push(boundary);
    let mut class = Case::new(&format!(
        "setup class questions with nothing preselected: {build}"
    ));
    class.check(
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
    class.check("shipped wording and all three exact answers",["Will this machine serve people you have never met, for example by renting out space on it or hosting other people's accounts?","Yes","No, only me and people I know","Not sure","never holds spendable keys and is always bound alone"].iter().all(|s|text.as_str().unwrap_or("").contains(s)));
    *worker = run.reload(tab, worker).await?;
    run.submit(tab, "unlock", pass).await?;
    class.check(
        "reload remembers no draft answer",
        no_preselection(run, tab).await?,
    );
    for (machine, answer) in [("fixture", "not_sure"), ("fixture-other", "no")] {
        click(
            run,
            tab,
            &format!("[data-machine='{machine}'] [data-answer='{answer}']"),
        )
        .await?;
        for _ in 0..300 {
            if run.inspect(worker).await?["setup"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["entry"]["machine"] == machine && !m["class"].is_null())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    let state = run.inspect(worker).await?;
    let opened = reader::read(&store_files(&run.dump(tab).await?), pass)?;
    let values: Vec<Value> = opened
        .records
        .iter()
        .map(|(_, p)| serde_json::from_slice(p).unwrap())
        .collect();
    class.check(
        "reader finds not sure as multi-tenant, no as single-purpose, maintained profile",
        values[3]["setup"]["class"]
            == json!({"machine":"fixture","answer":"not_sure","class":"multi_tenant"})
            && values[4]["setup"]["class"]
                == json!({"machine":"fixture-other","answer":"no","class":"single_purpose"})
            && state["setup"].as_array().unwrap().iter().all(|m| {
                m["access"] == json!({"model":"maintained","profile":"ad-hoc","revision":3})
            }),
    );
    let before = run.dump(tab).await?;
    let second = act(
        run,
        worker,
        &format!(
            "m.setup_answer({})",
            json!(json!({"machine":"fixture","answer":"yes"}).to_string())
        ),
    )
    .await?;
    class.check(
        "second answer refuses with no record",
        second["error"].is_string() && run.dump(tab).await? == before,
    );
    cases.push(class);
    run.put(tab, &saved).await?;
    *worker = run.reload(tab, worker).await?;
    run.submit(tab, "unlock", pass).await?;
    Ok(())
}
