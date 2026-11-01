//! Real page approval pauses the real fixture inference loop before its companion call.
use super::*;
use inference_cases::module;

fn minimum() -> Value {
    json!({"version":2,"listeners":{"inbound":[{"proto":"tcp","port":22,"from":"any"}],"outbound":[]},"services":[],"key_material":{"spendable":false,"permitted":[]},"drift_checks":[],"required":[],"default_credentials":"none"})
}
fn initial(caller: &'static str) -> Files {
    let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut events = vec![json!({"seed":{"mnemonic":words}})];
    events.extend(reader::setup_events_at(caller, words, &["fixture"]));
    events.push(
        json!({"setup":{"class":{"machine":"fixture","answer":"no","class":"single_purpose"}}}),
    );
    reader::build_at("file.declaration_cases.build.001", PASSPHRASE, &events)
}
fn message(proposal: Value, tool: Value) -> Value {
    json!({"fixture_message":{"tool_calls":[tool],"proposal":proposal}})
}
fn done() -> Value {
    json!({"name":"done","arguments":{"machine":"fixture"}})
}
pub(super) async fn prepare(
    site: &'static str,
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    files: &Files,
) -> Result<inputs::Session, String> {
    let _observer =
        observer::Call::begin(site, "declaration.prepare", Some(&tab.session), json!({}));
    _observer.fact("files_input", observer::files_match(site, files));

    run.aggregator.state.lock().unwrap().script.clear();
    run.put(tab, files).await?;
    *worker = run
        .reload("declaration_cases.rs::reload#1", tab, worker)
        .await?;
    module(
        run,
        worker,
        &format!(
            "return m.test_inference_origin({});",
            json!(run.aggregator.origin)
        ),
    )
    .await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    setup_cases::click(run, tab, "[data-bind=fixture]").await?;
    let binding_observer = observer::Call::begin(
        "declaration.prepare.binding",
        "declaration.prepare.binding",
        Some(&tab.session),
        json!({}),
    );
    let mut identity = None;
    for poll in 0..300 {
        binding_observer.attempt(poll + 1);
        let state = binding_observer.inspect(run, worker).await?;
        let first = state["sessions"].as_array().and_then(|s| s.first());
        if binding_observer.poll(poll + 1, first.is_some()) {
            let s = first.unwrap();
            identity = s["identity"].as_str().map(str::to_owned);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(binding_observer);
    completion::prerequisite("declaration.session.bound", identity.is_some());
    let session = identity.ok_or("declaration fixture binding")?;
    let session = observer::session_input(&session);
    if _observer.fact(
        "account_absent",
        _observer.inspect(run, worker).await?["inference_account"].is_null(),
    ) {
        // Repeated entry is refused by production; only a fresh store needs this fixture key.
        let key = run.aggregator.state.lock().unwrap().account.clone();
        module(
            run,
            worker,
            &format!(
                "return await m.test_inference_account(new TextEncoder().encode({}));",
                json!(key)
            ),
        )
        .await?;
    }
    let confirmation = observer::Call::begin(
        "declaration.prepare.confirmation",
        "declaration.prepare.confirmation",
        Some(&tab.session),
        json!({}),
    );
    if completion::rejects(
        "declaration.inference.confirmed",
        !confirmation.fact(
            "confirmed",
            module(run, worker, "return await m.test_confirm_inference();").await? == true,
        ),
    ) {
        return Err("fresh declaration session lacks synthetic confirmed limits".into());
    }
    drop(confirmation);
    let value = json!({"session":session,"text":"Run hermes as user operator on TCP port 443; connect to api.example:443","document_source":null});
    run.browser
        .evaluate(
            &tab.session,
            &format!(
                "document.querySelector('[data-goal-card={session}] textarea').value={};",
                json!(value["text"])
            ),
        )
        .await?;
    setup_cases::click(run, tab, &format!("[data-goal-enter={session:?}]")).await?;
    let goal_observer = observer::Call::begin(
        "declaration.prepare.goal_card",
        "declaration.prepare.goal_card",
        Some(&tab.session),
        json!({}),
    );
    goal_observer.fact("session_input", observer::session_matches(&session));
    for poll in 0..300 {
        goal_observer.attempt(poll + 1);
        if goal_observer.poll(
            poll + 1,
            run.browser
                .evaluate(
                    &tab.session,
                    &format!("!!document.querySelector('[data-goal-accept={session}]')"),
                )
                .await?
                == true,
        ) {
            completion::prerequisite("declaration.goal.accept_card", true);
            return Ok(session);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err("declaration goal card not accepted".into())
}
pub(super) async fn start(
    run: &Run<'_>,
    tab: &Tab,
    session: &str,
    script: Vec<Value>,
) -> Result<(), String> {
    run.aggregator.state.lock().unwrap().script = script.into();
    setup_cases::click(run, tab, &format!("[data-goal-accept={session:?}]")).await
}
pub(super) async fn wait_card(
    site: &'static str,
    run: &Run<'_>,
    tab: &Tab,
    worker: &Worker,
    session: &inputs::Session,
) -> Result<file_windows::Pending, String> {
    let observer =
        observer::Call::begin(site, "declaration.wait_card", Some(&tab.session), json!({}));
    observer.fact("session_input", observer::session_matches(session));

    for poll in 0..300 {
        observer.attempt(poll + 1);
        if observer.poll(
            poll + 1,
            run.browser
                .evaluate(
                    &tab.session,
                    &format!("!!document.querySelector('[data-requirements-card={session}]')"),
                )
                .await?
                == true,
        ) {
            let state = observer.pending(run, worker).await?;
            return Ok(state.pending());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let state = observer.inspect(run, worker).await?;
    let page = run
        .browser
        .evaluate(
            &tab.session,
            "document.getElementById('tau-setup').textContent",
        )
        .await?;
    Err(format!(
        "declaration card did not appear: sessions={}; last inference={}; page={page}",
        state["sessions"],
        state["inference_calls"]
            .as_array()
            .and_then(|calls| calls.last())
            .unwrap_or(&Value::Null)
    ))
}

// The first proposal case must observe unauthorized continuation too: when proposal
// handling is broken, the real loop reaches its next inference and terminal page outcome.
// Waiting only for a card would hide that safety failure behind polling exhaustion.
async fn wait_proposal_or_outcome(
    site: &'static str,
    run: &Run<'_>,
    tab: &Tab,
    session: &inputs::Session,
) -> Result<(), String> {
    let observer = observer::Call::begin(
        site,
        "declaration.wait_proposal_or_outcome",
        Some(&tab.session),
        json!({}),
    );
    observer.fact("session_input", observer::session_matches(session));

    for poll in 0..300 {
        observer.attempt(poll + 1);
        if observer.poll(poll+1, run.browser.evaluate(&tab.session, &format!(
            "!!document.querySelector('[data-requirements-card={session}]') || !!document.querySelector('[data-goal-outcome={session}]')"
        )).await? == true) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err("neither pending proposal nor loop outcome observed".into())
}
pub(super) async fn outcome(
    site: &'static str,
    run: &Run<'_>,
    tab: &Tab,
    session: &inputs::Session,
) -> Result<String, String> {
    let observer =
        observer::Call::begin(site, "declaration.outcome", Some(&tab.session), json!({}));
    observer.fact("session_input", observer::session_matches(session));

    for poll in 0..300 {
        observer.attempt(poll + 1);
        let value = run
            .browser
            .evaluate(
                &tab.session,
                &format!(
                    "document.querySelector('[data-goal-outcome={session}]')?.textContent ?? null"
                ),
            )
            .await?;
        let text = value.as_str();
        if observer.poll(poll + 1, text.is_some()) {
            let text = text.unwrap();
            return Ok(text.into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err("declaration loop did not stop".into())
}
async fn answer(
    run: &Run<'_>,
    worker: &Worker,
    pending: &file_windows::Pending,
    value: Value,
) -> Result<Value, String> {
    file_windows::answer(run, worker, pending, value).await
}

pub(super) async fn run(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let _scenario_span = completion::scenario("declaration_cases.run");
    let original = store_files(&run.dump_at("file.declaration_cases.dump.001", tab).await?);
    let session = {
        let source_parameter = &initial("reader.aux.call.declaration.initial.first");
        observer::files_input("declaration.initial.prepare", source_parameter);
        prepare(
            "declaration.initial.prepare",
            run,
            tab,
            worker,
            source_parameter,
        )
        .await
    }?;
    let mut d = minimum();
    d["listeners"]["inbound"]
        .as_array_mut()
        .unwrap()
        .push(json!({"proto":"tcp","port":443,"from":"any"}));
    d["listeners"]["outbound"] = json!([{"proto":"tcp","host":"api.example","port":443}]);
    d["services"] = json!([{"name":"hermes","scope":{"kind":"user","account":"operator"},"lifecycle":"running-at-delivery"}]);
    let proposal = json!({"kind":"declaration","machine":"fixture","declaration":d});
    let job = json!({"name":"request_harness_job","arguments":{"machine":"fixture","job":"fetch_artifact","arguments":{}}});
    let from = run.aggregator.requests.lock().unwrap().len();
    start(
        run,
        tab,
        &session,
        vec![message(proposal.clone(), job), done()],
    )
    .await?;
    let mut case = Case::new(
        "declaration_cases.c001",
        "declaration proposal waits on the actual page and commits exact goal additions before its companion",
    );
    wait_proposal_or_outcome(
        "declaration.initial.wait_proposal_or_outcome",
        run,
        tab,
        &session,
    )
    .await?;
    let state = file_windows::pending("declaration.initial.pending", None, run, worker).await?;
    let pending = state.pending();
    let completions = run
        .aggregator
        .requests
        .lock()
        .unwrap()
        .iter()
        .skip(from)
        .filter(|r| r.starts_with(b"POST /completion "))
        .count();
    let page_outcome = run
        .browser
        .evaluate(
            &tab.session,
            &format!(
                "document.querySelector('[data-goal-outcome={session}]')?.textContent ?? null"
            ),
        )
        .await?;
    let waiting = pending["proposal"] == proposal
        && state["setup"][0]["declaration"].is_null()
        && state["calls"] == json!([])
        && completions == 1
        && page_outcome.is_null();
    println!(
        "   preapproval observation: pending={}, approved={}, completions={completions}, outcome={page_outcome}",
        pending.is_object(),
        state["setup"][0]["declaration"].is_object()
    );
    case.check("declaration_cases.a001", "before approval the exact candidate is pending, with no companion or subsequent inference continuation", waiting);
    if !waiting {
        // Preserve and print the actual safety verdict; no missing-card error or later
        // click failure should mask it. Fixed runs still take the full click/replay path.
        case.finish(cases);
        return Ok(());
    }
    let text = run
        .browser
        .evaluate(
            &tab.session,
            "document.querySelector('[data-requirements-card]').textContent",
        )
        .await?;
    let text = text.as_str().unwrap_or("");
    case.check(
        "declaration_cases.a002",
        "plain-language card renders every typed fact and emptiness",
        [
            "version 2",
            "tcp port 22 from any",
            "tcp port 443 from any",
            "api.example",
            "hermes",
            "user account operator",
            "running at delivery",
            "forbidden",
            "explicit empty set",
            "Default credentials: none",
        ]
        .iter()
        .all(|v| text.contains(v)),
    );
    case.check("declaration_cases.a003", "buttons have no selected answer",run.browser.evaluate(&tab.session,"[...document.querySelectorAll('[data-requirements-decision]')].length===2 && [...document.querySelectorAll('[data-requirements-decision]')].every(b=>b.type==='button'&&!b.autofocus&&!b.hasAttribute('checked')&&!b.hasAttribute('selected')&&document.activeElement!==b)").await?==true);
    let before = store_files(&run.dump_at("file.declaration_cases.dump.002", tab).await?);
    let state = run.inspect(worker).await?;
    case.check(
        "declaration_cases.a004",
        "candidate is transient and no tool intent or subsequent inference dispatched",
        state["setup"][0]["declaration"].is_null()
            && state["calls"] == json!([])
            && run
                .aggregator
                .requests
                .lock()
                .unwrap()
                .iter()
                .skip(from)
                .filter(|r| r.starts_with(b"POST /completion "))
                .count()
                == 1,
    );
    for bad in [
        json!({"session":session,"machine":"fixture-other","candidate":pending["candidate"],"decision":"approve"}),
        json!({"session":session,"machine":"fixture","candidate":0,"decision":"approve"}),
        json!({"session":session,"machine":"fixture","candidate":pending["candidate"],"decision":"approve","declaration":minimum()}),
    ] {
        case.check(
            "declaration_cases.a005",
            "wrong machine, stale identity and replacement data change no record",
            crate::state_inputs::all!(
                answer(run, worker, &pending, bad)
                    .await?
                    .get("error")
                    .is_some(),
                file_inputs::equal_primary(
                    "declaration_cases.a005.1",
                    "declaration_cases.a005",
                    &(store_files(&run.dump_at("file.declaration_cases.dump.003", tab).await?)),
                    &(before),
                )
            ),
        );
    }
    let call = json!({"name":"done","arguments":{"machine":"fixture"}});
    let refused = module(
        run,
        worker,
        &format!(
            "return JSON.parse(await m.test_model_tool({},{}));",
            json!(session),
            json!(call.to_string())
        ),
    )
    .await?;
    case.check(
        "declaration_cases.a006",
        "common model admission blocks another dispatch",
        refused["refused"] == "proposal approval pending",
    );
    setup_cases::click(run, tab, "[data-requirements-decision=approve]").await?;
    case.check(
        "declaration_cases.a007",
        "approval releases the companion and then ordinary done",
        outcome("declaration.initial.outcome", run, tab, &session).await?
            == "Goal loop ended: done.",
    );
    let state = run.inspect(worker).await?;
    case.check(
        "declaration_cases.a008",
        "exact approved declaration and original maintained contract are visible",
        state["setup"][0]["declaration"] == d
            && state["setup"][0]["access"]
                == json!({"model":"maintained","profile":"ad-hoc","revision":3}),
    );
    let approved = store_files(&run.dump_at("file.declaration_cases.dump.004", tab).await?);
    let read = reader::read_at("reader.call.declaration.approved", &approved, PASSPHRASE)?;
    let records: Vec<Value> = read
        .records
        .iter()
        .map(|(_, b)| serde_json::from_slice(b).unwrap())
        .collect();
    case.check(
        "declaration_cases.a009",
        "independent encrypted reader finds exactly one durable candidate",
        records
            .iter()
            .filter(|v| v.pointer("/setup/requirements").is_some())
            .count()
            == 1
            && records
                .iter()
                .any(|v| v.pointer("/setup/requirements/proposal") == Some(&proposal)),
    );
    let request = run
        .aggregator
        .requests
        .lock()
        .unwrap()
        .iter()
        .skip(from)
        .filter(|r| r.starts_with(b"POST /completion "))
        .cloned()
        .collect::<Vec<_>>();
    let bodies: Vec<Value> = request
        .iter()
        .map(|r| {
            serde_json::from_slice(&r[r.windows(4).position(|p| p == b"\r\n\r\n").unwrap() + 4..])
                .unwrap()
        })
        .collect();
    let context: Value =
        serde_json::from_str(bodies[1]["messages"][0]["content"].as_str().unwrap()).unwrap();
    case.check(
        "declaration_cases.a010",
        "companion keeps its truthful unavailable boundary",
        context["history"][0]["result"]["content"]["refused"] == "job unavailable"
            && context["approved_requirements"][0]["value"] == proposal
            && bodies
                .iter()
                .all(|b| b["tools"].as_array().unwrap().len() == 4),
    );
    let context: Value =
        serde_json::from_str(bodies[0]["messages"][0]["content"].as_str().unwrap()).unwrap();
    case.check(
        "declaration_cases.a011",
        "goal and complete pinned minimum reach the real inference request",
        context["goal"]["text"]
            .as_str()
            .unwrap()
            .contains("api.example")
            && context["declaration_minimum"] == minimum(),
    );
    case.check("declaration_cases.a012",
"duplicate approval appends nothing",
crate::state_inputs::all!(
answer(run,worker,&pending,json!({"session":session,"machine":"fixture","candidate":pending["candidate"],"decision":"approve"})).await?.get("error").is_some(),
file_inputs::equal_primary("declaration_cases.a012.1", "declaration_cases.a012", &(store_files(&run.dump_at("file.declaration_cases.dump.005", tab).await?)), &(approved))
));
    case.finish(cases);

    let session = {
        let source_parameter = &approved;
        observer::files_input("declaration.tighten.prepare", source_parameter);
        prepare(
            "declaration.tighten.prepare",
            run,
            tab,
            worker,
            source_parameter,
        )
        .await
    }?;
    let mut case = Case::new(
        "declaration_cases.c002",
        "class tightening is separately approved and survives unlock with the original answer",
    );
    start(
        run,
        tab,
        &session,
        vec![message(
            json!({"kind":"tighten_class","machine":"fixture","class":"multi_tenant"}),
            done(),
        )],
    )
    .await?;
    wait_card("declaration.tighten.wait_card", run, tab, worker, &session).await?;
    case.check(
        "declaration_cases.a013",
        "replayed declaration is retained before tightening click",
        run.inspect(worker).await?["setup"][0]["declaration"] == d
            && run.inspect(worker).await?["setup"][0]["class"] == "single_purpose",
    );
    setup_cases::click(run, tab, "[data-requirements-decision=approve]").await?;
    case.check(
        "declaration_cases.a014",
        "proposal on done approves before unchanged terminal call",
        outcome("declaration.tighten.outcome", run, tab, &session).await?
            == "Goal loop ended: done.",
    );
    let files = store_files(&run.dump_at("file.declaration_cases.dump.006", tab).await?);
    *worker = run
        .reload("declaration_cases.rs::reload#2", tab, worker)
        .await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    let state = run.inspect(worker).await?;
    case.check(
        "declaration_cases.a015",
        "replay restores tightened class, answer and declaration, without live work",
        state["setup"][0]["answer"] == "no"
            && state["setup"][0]["class"] == "multi_tenant"
            && state["setup"][0]["declaration"] == d
            && state["sessions"] == json!([]),
    );
    reader::read_at("reader.call.declaration.tightened", &files, PASSPHRASE)?;
    case.finish(cases);

    for (decision, label) in [("reject", "rejection"), ("end", "session end")] {
        let session = {
            let source_parameter = &initial("reader.aux.call.declaration.initial.decision");
            observer::files_input("declaration.cancel.prepare", source_parameter);
            prepare(
                "declaration.cancel.prepare",
                run,
                tab,
                worker,
                source_parameter,
            )
            .await
        }?;
        module(run, worker, "self.stoppedGoalOutcome=null;const post=self.postMessage.bind(self);self.postMessage=(data,...args)=>{if(data.store?.goal_outcome||data.store?.goal_history)self.stoppedGoalOutcome=(data.store.goal_outcome??data.store.goal_history).outcome;return post(data,...args);};return true;").await?;
        start(
            run,
            tab,
            &session,
            vec![message(
                json!({"kind":"declaration","machine":"fixture","declaration":minimum()}),
                done(),
            )],
        )
        .await?;
        let pending = wait_card("declaration.cancel.wait_card", run, tab, worker, &session).await?;
        let mut case = Case::new(
            "declaration_cases.c003",
            &format!("declaration {label} cancels its waiter without a canonical approval"),
        );
        if decision == "reject" {
            setup_cases::click(run, tab, "[data-requirements-decision=reject]").await?;
            case.check(
                "declaration_cases.a016",
                "rejection ends loop",
                outcome("declaration.cancel.rejection_outcome", run, tab, &session)
                    .await?
                    .contains("proposal rejected"),
            );
        } else {
            module(run, worker, "await m.end_sessions(); return true;").await?;
            // Read the real loop's published result after the end step has returned.
            // There is no race against a timeout: a retained, unresolved waiter leaves
            // null here, while cancellation publishes its named stopped outcome.
            let stopped = module(run, worker, "return self.stoppedGoalOutcome;").await?;
            let cancelled = stopped["refused"] == "sessions ended"
                && stopped["historical"] == true
                && stopped["actionable"] == false
                && stopped.get("done").is_none()
                && stopped.get("body").is_none();
            println!("   end-step loop outcome: {stopped}");
            case.check(
                "declaration_cases.a017",
                "session end settles approval wait with safe non-actionable historical outcome",
                cancelled,
            );
            if !cancelled {
                case.finish(cases);
                return Ok(());
            }
        }
        let files = store_files(&run.dump_at("file.declaration_cases.dump.007", tab).await?);
        case.check("declaration_cases.a018",
"late approval makes no record",
crate::state_inputs::all!(
answer(run,worker,&pending,json!({"session":session,"machine":"fixture","candidate":pending["candidate"],"decision":"approve"})).await?.get("error").is_some(),
file_inputs::equal_primary("declaration_cases.a018.1", "declaration_cases.a018", &(store_files(&run.dump_at("file.declaration_cases.dump.008", tab).await?)), &(files))
));
        case.check(
            "declaration_cases.a019",
            "declaration remains unanswered",
            run.inspect(worker).await?["setup"][0]["declaration"].is_null(),
        );
        case.finish(cases);
    }

    let session = {
        let source_parameter = &initial("reader.aux.call.declaration.initial.proposal_writer");
        observer::files_input("declaration.writer.prepare", source_parameter);
        prepare(
            "declaration.writer.prepare",
            run,
            tab,
            worker,
            source_parameter,
        )
        .await
    }?;
    module(run,worker,"self.renderedProposal=0;self.stoppedGoalOutcome=null;const post=self.postMessage.bind(self);self.postMessage=(data,...args)=>{if(data.requirements_store||data.store?.sessions?.some(s=>s.pending_requirements))self.renderedProposal++;if(data.store?.goal_outcome||data.store?.goal_history)self.stoppedGoalOutcome=(data.store.goal_outcome??data.store.goal_history).outcome;return post(data,...args);};self.proposalPoint=new Promise(ready=>m.test_hold_session_point('proposal_writer',new Promise(release=>self.releaseProposal=release),ready));return true;").await?;
    start(
        run,
        tab,
        &session,
        vec![message(
            json!({"kind":"declaration","machine":"fixture","declaration":minimum()}),
            done(),
        )],
    )
    .await?;
    module(run,worker,"await self.proposalPoint;self.writerAcquired=new Promise(ready=>self.writerHeld=m.test_writer(new Promise(release=>self.releaseWriter=release),ready));await self.writerAcquired;self.releaseProposal();await new Promise(r=>setTimeout(r,0));self.proposalEnd=m.end_sessions();await new Promise(r=>setTimeout(r,0));self.releaseWriter();await self.writerHeld;await self.proposalEnd;return true;").await?;
    // End has returned after both queued writer users ran. Read both observations
    // unconditionally: a late proposal publishes a card and leaves a new waiter
    // without an outcome, because it missed end's earlier sender cancellation.
    let observed = module(
        run,
        worker,
        "return {publications:self.renderedProposal,outcome:self.stoppedGoalOutcome};",
    )
    .await?;
    println!("   proposal-writer end observation: {observed}");
    let mut case = Case::new(
        "declaration_cases.c004",
        "session end queued behind the proposal writer publishes no late approval card",
    );
    case.check(
        "declaration_cases.a020",
        "proposal writer publishes no approval card after end begins",
        observed["publications"] == 0,
    );
    case.check(
        "declaration_cases.a021",
        "proposal writer settles the loop with the sessions ended outcome",
        observed["outcome"]["refused"] == "sessions ended"
            && observed["outcome"]["historical"] == true
            && observed["outcome"]["actionable"] == false
            && observed["outcome"].get("done").is_none()
            && observed["outcome"].get("body").is_none(),
    );
    case.finish(cases);
    for phase in [
        "requirements_writer",
        "move",
        "requirements_committed",
        "requirements_dispatch",
        "failed_append",
    ] {
        let session = {
            let source_parameter = &initial("reader.aux.call.declaration.initial.requirements");
            observer::files_input("declaration.approval_phase.prepare", source_parameter);
            prepare(
                "declaration.approval_phase.prepare",
                run,
                tab,
                worker,
                source_parameter,
            )
            .await
        }?;
        module(run,worker,"self.goalFinished=new Promise(resolve=>{const post=self.postMessage.bind(self);self.postMessage=(data,...args)=>{if(data.store?.goal_outcome||data.store?.goal_history)resolve((data.store.goal_outcome??data.store.goal_history).outcome);return post(data,...args);};});return true;").await?;
        start(
            run,
            tab,
            &session,
            vec![message(
                json!({"kind":"declaration","machine":"fixture","declaration":minimum()}),
                done(),
            )],
        )
        .await?;
        let pending = wait_card(
            "declaration.approval_phase.wait_card",
            run,
            tab,
            worker,
            &session,
        )
        .await?;
        if phase == "failed_append" {
            module(
                run,
                worker,
                "await m.test_seed_backup_fail_append();return true;",
            )
            .await?;
        } else if phase == "move" {
            module(run,worker,"self.approvalPoint=new Promise(ready=>m.test_hold_move(new Promise(release=>self.releaseApproval=release),ready));return true;").await?;
        } else {
            module(run,worker,&format!("self.approvalPoint=new Promise(ready=>m.test_hold_session_point({},new Promise(release=>self.releaseApproval=release),ready));return true;",json!(phase))).await?;
        }
        let act = json!({"session":session,"machine":"fixture","candidate":pending["candidate"],"decision":"approve"});
        module(
            run,
            worker,
            &format!(
                "self.answerReturn=m.requirements_answer({});return true;",
                json!(act.to_string())
            ),
        )
        .await?;
        if phase != "failed_append" {
            if phase == "requirements_writer" {
                module(run,worker,"await self.approvalPoint;self.writerAcquired=new Promise(ready=>self.writerHeld=m.test_writer(new Promise(release=>self.releaseWriter=release),ready));await self.writerAcquired;self.releaseApproval();await new Promise(r=>setTimeout(r,0));self.approvalEnd=m.end_sessions();await new Promise(r=>setTimeout(r,0));self.releaseWriter();await self.writerHeld;await self.approvalEnd;return true;").await?;
            } else {
                module(run,worker,"await self.approvalPoint;self.approvalEnd=m.end_sessions();await new Promise(r=>setTimeout(r,0));self.releaseApproval();await self.approvalEnd;return true;").await?;
            }
        }
        let result=module(run,worker,"return await Promise.race([self.goalFinished,new Promise(resolve=>setTimeout(()=>resolve({test_timeout:true}),2000))]);").await?;
        let mut case = Case::new(
            "declaration_cases.c005",
            &format!("declaration approval stops safely at {phase}"),
        );
        case.check(
            "declaration_cases.a022",
            "no companion done dispatch after cancellation or failed append",
            result["done"] != true && result.get("refused").is_some(),
        );
        if !["failed_append", "requirements_dispatch"].contains(&phase) {
            case.check(
                "declaration_cases.a023",
                "operator act also refuses ending after its awaited append",
                module(
                    run,
                    worker,
                    "return JSON.parse(await self.answerReturn).error;",
                )
                .await?
                    == "sessions ended",
            );
        }
        let files = store_files(&run.dump_at("file.declaration_cases.dump.009", tab).await?);
        let opened = reader::read_at("reader.call.declaration.lifecycle", &files, PASSPHRASE)?;
        let approved = opened.records.iter().any(|(_, b)| {
            serde_json::from_slice::<Value>(b)
                .unwrap()
                .pointer("/setup/requirements")
                .is_some()
        });
        case.check(
            "declaration_cases.a024",
            "only a completed durable append restores facts",
            approved == !["requirements_writer", "failed_append"].contains(&phase),
        );
        *worker = run
            .reload("declaration_cases.rs::reload#3", tab, worker)
            .await?;
        run.submit(tab, "unlock", PASSPHRASE).await?;
        let state = run.inspect(worker).await?;
        case.check(
            "declaration_cases.a025",
            "unlock restores facts only and no live waiter or goal loop",
            state["sessions"] == json!([])
                && state["setup"][0]["declaration"].is_object() == approved,
        );
        case.finish(cases);
    }
    run.put(tab, &original).await?;
    *worker = run
        .reload("declaration_cases.rs::reload#4", tab, worker)
        .await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    Ok(())
}
