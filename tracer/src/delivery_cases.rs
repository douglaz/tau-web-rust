//! Supplies typed fixture facts, drives ordinary worker messages/page buttons, and inspects
//! encrypted records independently. This driver computes no delivery verdict.
use super::*;
use inference_cases::module;
fn minimum() -> Value {
    json!({"version":2,"listeners":{"inbound":[{"proto":"tcp","port":22,"from":"any"}],"outbound":[]},"services":[],"key_material":{"spendable":false,"permitted":[]},"drift_checks":[],"required":[],"default_credentials":"none"})
}
fn service(name: &str, lifecycle: &str) -> Value {
    json!({"name":name,"scope":{"kind":"system"},"lifecycle":lifecycle})
}
fn measured(v: Value) -> Value {
    json!({"read":"value","value":v})
}
pub(super) fn clean() -> Value {
    json!({"inbound":measured(json!([{"proto":"tcp","port":22,"from":"any"}])),"outbound":measured(json!([])),
        "services":measured(json!([])),"spendable":measured(json!(false)),"permitted":measured(json!([])),
        "required":measured(json!([])),"credentials":measured(json!([])),"fixed_default_credentials":measured(json!(true)),
        "sshd_posture":measured(json!(true)),"placing_session":false})
}
fn initial(caller: &'static str, d: Option<Value>) -> Files {
    let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut events = vec![json!({"seed":{"mnemonic":words}})];
    events.extend(reader::setup_events_at(caller, words, &["fixture"]));
    events.push(
        json!({"setup":{"class":{"machine":"fixture","answer":"no","class":"single_purpose"}}}),
    );
    if let Some(d) = d {
        events.push(json!({"setup":{"requirements":{"session":"fixture-contract","candidate":0,
        "access":{"model":"maintained","profile":"ad-hoc","revision":tau_web::dispatch::ad_hoc_revision()},
        "proposal":{"kind":"declaration","machine":"fixture","declaration":d}}}}));
    }
    reader::build_at("file.delivery_cases.build.001", PASSPHRASE, &events)
}
async fn prepare(
    site: &'static str,
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    d: Option<Value>,
) -> Result<inputs::Session, String> {
    let observer = observer::Call::begin(site, "delivery.prepare", Some(&tab.session), json!({}));
    observer.fact("declaration_input", observer::declaration_matches(site, &d));

    run.put(tab, &initial("reader.aux.call.delivery.prepare.initial", d))
        .await?;
    *worker = run
        .reload("delivery_cases.rs::reload#1", tab, worker)
        .await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    setup_cases::click(run, tab, "[data-bind=fixture]").await?;
    for poll in 0..300 {
        observer.attempt(poll + 1);
        let state = observer.inspect(run, worker).await?;
        let identity = state["sessions"]
            .as_array()
            .and_then(|v| v.first())
            .and_then(|v| v["identity"].as_str());
        if observer.poll(poll + 1, identity.is_some()) {
            let s = identity.unwrap();
            return Ok(observer::session_input(s));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err("delivery binding not observed".into())
}
async fn inject(run: &Run<'_>, worker: &Worker, session: &str, m: &Value) -> Result<(), String> {
    module(
        run,
        worker,
        &format!(
            "await m.test_delivery_fixture({},'fixture',{});return true;",
            json!(session),
            json!(m.to_string())
        ),
    )
    .await?;
    Ok(())
}
async fn action(run: &Run<'_>, worker: &Worker, v: Value) -> Result<Value, String> {
    module(
        run,
        worker,
        &format!(
            "const post=self.postMessage;let report;self.postMessage=(data,...args)=>{{if(data.store)report=data.store;return post.call(self,data,...args);}};try{{await self.onmessage({{data:{{delivery:{v}}}}});}}finally{{self.postMessage=post;}}if(!report)throw new Error('no worker delivery response');return {{...report,state:report.store_state,...(report.store_error?{{error:report.store_error}}:{{}})}};"
        ),
    )
    .await
}
fn request(session: &str) -> Value {
    json!({"action":"check","session":session,"machine":"fixture"})
}
async fn check(
    site: &'static str,
    run: &Run<'_>,
    tab: &Tab,
    worker: &Worker,
    session: &inputs::Session,
    m: &Value,
) -> Result<Value, String> {
    let observer = observer::Call::begin(site, "delivery.check", Some(&tab.session), json!({}));
    observer.fact("measurement_input", observer::measurement_matches(site, m));
    observer.fact("session_input", observer::session_matches(session));

    inject(run, worker, session, m).await?;
    // This is the actual served button and worker handler. Wait on a distinct recorded check.
    let before = observer.inspect(run, worker).await?["records"]
        .as_array()
        .map_or(0, Vec::len);
    setup_cases::click(run, tab, "[data-delivery-check=fixture]").await?;
    for poll in 0..300 {
        observer.attempt(poll + 1);
        let state = observer.inspect(run, worker).await?;
        if observer.poll(poll+1, state["records"].as_array().map_or(0, Vec::len) > before
            && state["delivery"][0]["last_check"].is_object()
            && run
                .browser
                .evaluate(
                    &tab.session,
                    "document.querySelector('[data-delivery-check=fixture]')?.disabled === false",
                )
                .await?
                == true) {
            return Ok(state["delivery"][0].clone());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err("delivery check produced no durable result".into())
}
async fn card(
    site: &'static str,
    run: &Run<'_>,
    tab: &Tab,
    needle: &str,
) -> Result<String, String> {
    let observer = observer::Call::begin(
        site,
        "delivery.card",
        Some(&tab.session),
        json!({"needle":match needle {"Last recorded check against its journaled declaration:"=>"recorded-check","handed over with findings"=>"findings-verdict","Fixed lockdown fixture check"=>"lockdown-finding","delivery report success"=>"report-output",_=>"unknown"}}),
    );

    for poll in 0..300 {
        observer.attempt(poll + 1);
        let v = run
            .browser
            .evaluate(
                &tab.session,
                "document.querySelector('[data-delivery-card=fixture]')?.textContent ?? ''",
            )
            .await?;
        let text = v.as_str().unwrap_or_default();
        if observer.poll(poll + 1, text.contains(needle)) {
            return Ok(text.into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(format!("delivery card did not display {needle}"))
}
async fn refresh(run: &Run<'_>, worker: &Worker) -> Result<(), String> {
    module(run,worker,"await self.onmessage({data:{delivery:{action:'check',machine:'fixture',session:'absent'}}});return true;").await?;
    Ok(())
}

pub(super) async fn run(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let _scenario_span = completion::scenario("delivery_cases.run");
    let original = store_files(&run.dump_at("file.delivery_cases.dump.001", tab).await?);
    if selection::value("TAU_TRACER_DELIVERY_CASE").as_deref() == Ok("reports") {
        reports(run, tab, worker, cases).await?;
        run.put(tab, &original).await?;
        *worker = run
            .reload("delivery_cases.rs::reload#2", tab, worker)
            .await?;
        if !original.is_empty() {
            run.submit(tab, "unlock", PASSPHRASE).await?;
        }
        return Ok(());
    }
    if selection::value("TAU_TRACER_DELIVERY_CASE").as_deref() == Ok("incomplete") {
        incomplete_attempts(run, tab, worker, cases).await?;
        run.put(tab, &original).await?;
        *worker = run
            .reload("delivery_cases.rs::reload#3", tab, worker)
            .await?;
        if !original.is_empty() {
            run.submit(tab, "unlock", PASSPHRASE).await?;
        }
        return Ok(());
    }
    let session = {
        let source_parameter = None;
        observer::declaration_input("delivery.no_declaration.prepare", &source_parameter);
        prepare(
            "delivery.no_declaration.prepare",
            run,
            tab,
            worker,
            source_parameter,
        )
        .await
    }?;
    let before = run.dump_at("file.delivery_cases.dump.002", tab).await?;
    let operation =
        operation_windows::Operation::begin("delivery.absent", worker, session.original_matches());
    operation.module(worker, &format!("const post=self.postMessage;let report;self.postMessage=(data,...args)=>{{if(data.store)report=data.store;return post.call(self,data,...args);}};try{{await self.onmessage({{data:{{delivery:{v}}}}});}}finally{{self.postMessage=post;}}if(!report)throw new Error('no worker delivery response');return {{...report,state:report.store_state,...(report.store_error?{{error:report.store_error}}:{{}})}};",v=json!({"action":"check","session":session,"machine":"fixture"})));
    let response = action(run, worker, request(&session)).await?;
    operation.finish();
    let mut case = Case::new(
        "delivery_cases.c001",
        "delivery refuses absent declaration and untrusted worker measurements",
    );
    case.check(
        "delivery_cases.a001",
        "no declaration writes no result or delivery",
        crate::state_inputs::all!(
            file_inputs::equal_primary(
                "delivery_cases.a001.1",
                "delivery_cases.a001",
                &(before),
                &(run.dump_at("file.delivery_cases.dump.003", tab).await?),
            ),
            response["delivery"][0]["verdict"] != "Delivered"
        ),
    );
    let session = {
        let source_parameter = Some(minimum());
        observer::declaration_input("delivery.untrusted.prepare", &source_parameter);
        prepare(
            "delivery.untrusted.prepare",
            run,
            tab,
            worker,
            source_parameter,
        )
        .await
    }?;
    for mut bad in [
        request(&session),
        json!({"action":"check","machine":"fixture","session":session,"finding_class":"lifecycle"}),
        json!({"action":"waive_finding","machine":"fixture","session":session}),
    ] {
        if bad["action"] == "check" && bad.get("measurements").is_none() {
            bad["measurements"] = clean();
        }
        let response = module(
            run,
            worker,
            &format!(
                "return JSON.parse(await m.delivery_request({}));",
                json!(bad.to_string())
            ),
        )
        .await?;
        case.check(
            "delivery_cases.a002",
            "measurement/waiver request is explicitly refused",
            response.get("error").is_some(),
        );
    }
    let state = action(run, worker, request(&session)).await?;
    case.check(
        "delivery_cases.a003",
        "no supplied fixture evidence remains unavailable",
        state["delivery"][0]["verdict"] != "Delivered"
            && state["delivery"][0]["last_check"]["result"]["complete"] == false,
    );
    case.finish(cases);

    let session = {
        let source_parameter = Some(minimum());
        observer::declaration_input("delivery.card.prepare", &source_parameter);
        prepare("delivery.card.prepare", run, tab, worker, source_parameter).await
    }?;
    let delivered = {
        let source_parameter = &clean();
        observer::measurement_input("delivery.card.initial_check", source_parameter);
        check(
            "delivery.card.initial_check",
            run,
            tab,
            worker,
            &session,
            source_parameter,
        )
        .await
    }?;
    let mut case = Case::new(
        "delivery_cases.c002",
        "delivery card uses durable fixture results and actual application names as text",
    );
    for name in ["Hermes", "<b data-delivery-injected>application</b>"] {
        let v = action(
            run,
            worker,
            json!({"action":"application","session":session,"machine":"fixture","name":name}),
        )
        .await?;
        case.check(
            "delivery_cases.a004",
            "application association is published",
            v["delivery"][0]["applications"]
                .as_array()
                .is_some_and(|v| v.contains(&json!(name))),
        );
    }
    let before = store_files(&run.dump_at("file.delivery_cases.dump.004", tab).await?);
    let operation = operation_windows::Operation::begin(
        "delivery.duplicate",
        worker,
        session.original_matches(),
    );
    operation.module(worker, &format!("const post=self.postMessage;let report;self.postMessage=(data,...args)=>{{if(data.store)report=data.store;return post.call(self,data,...args);}};try{{await self.onmessage({{data:{{delivery:{v}}}}});}}finally{{self.postMessage=post;}}if(!report)throw new Error('no worker delivery response');return {{...report,state:report.store_state,...(report.store_error?{{error:report.store_error}}:{{}})}};",v=json!({"action":"application","session":session,"machine":"fixture","name":"Hermes"})));
    let duplicate = action(
        run,
        worker,
        json!({"action":"application","session":session,"machine":"fixture","name":"Hermes"}),
    )
    .await?;
    operation.finish();
    case.check(
        "delivery_cases.a005",
        "exact duplicate name refused without write",
        crate::state_inputs::all!(
            duplicate.get("error").is_some(),
            file_inputs::equal_primary(
                "delivery_cases.a005.1",
                "delivery_cases.a005",
                &(before),
                &(store_files(&run.dump_at("file.delivery_cases.dump.005", tab).await?)),
            )
        ),
    );
    {
        let observation = observer::Call::begin(
            "delivery.card.applications_visible",
            "serial.observation",
            Some(&tab.session),
            json!({"bound":300,"false_sleep_ms":20,"requires_ready":false,"count":2}),
        );
        for poll in 0..300 {
            observation.attempt(poll + 1);
            if observation.poll(
                poll + 1,
                observation
                    .page_predicate(
                        run,
                        &tab.session,
                        "document.querySelectorAll('[data-delivery-application]').length",
                    )
                    .await?
                    .equals_two(),
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    let text = card(
        "delivery.card.visible",
        run,
        tab,
        "Last recorded check against its journaled declaration:",
    )
    .await?;
    case.check("delivery_cases.a006", "actual card claims fixture delivery with coverage and both exact sentences",delivered["verdict"]=="Delivered"
        && text.contains(tau_web::delivery::FIXTURE_LIMIT)
        && text.contains("Delivered covers the declared machine state and the fixed lockdown checks.")
        && text.contains("It does not mean Hermes works")
            && text.contains("Hermes is an AI that acts on this server by itself. tau-web's promises cover what tau-web's AI does, not what Hermes does.")
        && text.contains("<b data-delivery-injected>application</b> is an AI") && text.contains("It does not mean <b data-delivery-injected>application</b> works"));
    case.check(
        "delivery_cases.a007",
        "application name creates no HTML element",
        run.browser
            .evaluate(
                &tab.session,
                "document.querySelector('[data-delivery-card] [data-delivery-injected]')===null",
            )
            .await?
            == true,
    );
    let files = store_files(&run.dump_at("file.delivery_cases.dump.006", tab).await?);
    let opened = reader::read_at("reader.call.delivery.results", &files, PASSPHRASE)?;
    case.check(
        "delivery_cases.a008",
        "independent encrypted reader observes check and exact names",
        opened.records.iter().any(|(_, b)| {
            crate::journal::event(b).unwrap()["delivery"]["check"]["result"]["delivered"] == true
        }) && opened
            .records
            .iter()
            .any(|(_, b)| crate::journal::event(b).unwrap()["delivery"]["name"] == "Hermes"),
    );
    *worker = run
        .reload("delivery_cases.rs::reload#4", tab, worker)
        .await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    let restored = run.inspect(worker).await?;
    let text = card(
        "delivery.card.reopened",
        run,
        tab,
        "Last recorded check against its journaled declaration:",
    )
    .await?;
    case.check(
        "delivery_cases.a009",
        "reopen restores card with no running session",
        restored["delivery"][0]["verdict"] == "Delivered"
            && restored["sessions"] == json!([])
            && text.contains("Fixture"),
    );
    case.finish(cases);

    let enabled = service("daemon", "enabled-survives-reboot");
    let volatile = service("volatile", "running-at-delivery");
    for notes in [1, 2, 3] {
        let mut d = minimum();
        d["services"] = if notes == 1 {
            json!([enabled])
        } else if notes == 2 {
            json!([volatile])
        } else {
            json!([enabled, volatile])
        };
        let session = {
            let source_parameter = Some(d.clone());
            observer::declaration_input("delivery.notes.prepare", &source_parameter);
            prepare("delivery.notes.prepare", run, tab, worker, source_parameter).await
        }?;
        let mut m = clean();
        m["services"]=measured(Value::Array(d["services"].as_array().unwrap().iter().map(|s|json!({"service":s,"state":if s["name"]=="daemon"{"enabled_restart_not_demonstrated"}else{"stopped_since_restart"},"running_after_last_placement":false})).collect()));
        let result = {
            let source_parameter = &m;
            observer::measurement_input("delivery.notes.initial_check", source_parameter);
            check(
                "delivery.notes.initial_check",
                run,
                tab,
                worker,
                &session,
                source_parameter,
            )
            .await
        }?;
        let text = card(
            "delivery.notes.card",
            run,
            tab,
            "Last recorded check against its journaled declaration:",
        )
        .await?;
        let mut case = Case::new(
            "delivery_cases.c003",
            &format!("delivery consumes lifecycle evidence notes combination {notes}"),
        );
        case.check(
            "delivery_cases.a010",
            "passing labels accompany the actual Delivered card",
            result["verdict"] == "Delivered"
                && result["findings"] == json!([])
                && (notes == 2 || text.contains("enabled, restart not demonstrated"))
                && (notes == 1 || text.contains("stopped since a restart, as approved")),
        );
        let state = run.inspect(worker).await?;
        case.check(
            "delivery_cases.a011",
            "inspection has the same service-associated evidence notes",
            state["delivery"][0]["last_check"]["result"]["notes"]
                == result["last_check"]["result"]["notes"],
        );
        if notes == 3 {
            m["sshd_posture"] = measured(json!(false));
            let result = {
                let source_parameter = &m;
                observer::measurement_input("delivery.notes.fixed_finding", source_parameter);
                check(
                    "delivery.notes.fixed_finding",
                    run,
                    tab,
                    worker,
                    &session,
                    source_parameter,
                )
                .await
            }?;
            case.check(
                "delivery_cases.a012",
                "independent fixed finding survives both labels",
                result["verdict"] == "handed over with findings"
                    && result["placement_eligible"] == false
                    && result["findings"].as_array().unwrap().len() == 1,
            );
            m["sshd_posture"] = measured(json!(true));
            m["placing_session"] = json!(true);
            let result = {
                let source_parameter = &m;
                observer::measurement_input("delivery.notes.placing", source_parameter);
                check(
                    "delivery.notes.placing",
                    run,
                    tab,
                    worker,
                    &session,
                    source_parameter,
                )
                .await
            }?;
            case.check(
                "delivery_cases.a013",
                "placing-session restriction turns stopped restart note into lifecycle finding",
                result["verdict"] == "handed over with findings"
                    && result["placement_eligible"] == true
                    && result["findings"][0]["class"] == "lifecycle",
            );
            m["placing_session"] = json!(false);
            let result = {
                let source_parameter = &m;
                observer::measurement_input("delivery.notes.standing", source_parameter);
                check(
                    "delivery.notes.standing",
                    run,
                    tab,
                    worker,
                    &session,
                    source_parameter,
                )
                .await
            }?;
            case.check(
                "delivery_cases.a014",
                "restart note never clears a standing lifecycle finding",
                result["verdict"] == "handed over with findings",
            );
        }
        case.finish(cases);
    }
    let mut d = minimum();
    d["services"] = json!([volatile]);
    let session = {
        let source_parameter = Some(d);
        observer::declaration_input("delivery.finding.prepare", &source_parameter);
        prepare(
            "delivery.finding.prepare",
            run,
            tab,
            worker,
            source_parameter,
        )
        .await
    }?;
    let mut m = clean();
    m["services"] = measured(
        json!([{"service":volatile,"state":"difference","running_after_last_placement":false}]),
    );
    let before = {
        let source_parameter = &m;
        observer::measurement_input("delivery.finding.initial_check", source_parameter);
        check(
            "delivery.finding.initial_check",
            run,
            tab,
            worker,
            &session,
            source_parameter,
        )
        .await
    }?;
    let mut case = Case::new(
        "delivery_cases.c004",
        "delivery keeps lifecycle-only findings visible until recheck and refuses acceptance",
    );
    let text = card(
        "delivery.finding.card",
        run,
        tab,
        "handed over with findings",
    )
    .await?;
    case.check(
        "delivery_cases.a015",
        "one lifecycle finding is handed over with every finding shown",
        before["verdict"] == "handed over with findings"
            && run
                .browser
                .evaluate(
                    &tab.session,
                    "document.querySelector('[data-delivery-verdict=fixture]')?.textContent",
                )
                .await?
                == "handed over with findings"
            && before["findings"].as_array().unwrap().len() == 1
            && text.contains("lifecycle: Service volatile"),
    );
    for act in ["accept_finding", "waive_finding"] {
        let v = action(
            run,
            worker,
            json!({"action":act,"session":session,"machine":"fixture"}),
        )
        .await?;
        case.check(
            "delivery_cases.a016",
            "accept/waive cannot clear finding",
            v.get("error").is_some() && v["delivery"][0]["findings"] == before["findings"],
        );
    }
    m["sshd_posture"] = measured(json!(false));
    let mixed = {
        let source_parameter = &m;
        observer::measurement_input("delivery.finding.mixed_check", source_parameter);
        check(
            "delivery.finding.mixed_check",
            run,
            tab,
            worker,
            &session,
            source_parameter,
        )
        .await
    }?;
    let text = card(
        "delivery.finding.mixed_card",
        run,
        tab,
        "Fixed lockdown fixture check",
    )
    .await?;
    case.check(
        "delivery_cases.a017",
        "ordinary card retains every mixed-class finding",
        mixed["findings"].as_array().unwrap().len() == 2
            && text.contains("lifecycle: Service volatile")
            && text.contains("lockdown: Fixed lockdown fixture check"),
    );
    reader::read_at(
        "reader.call.delivery.findings",
        &store_files(&run.dump_at("file.delivery_cases.dump.007", tab).await?),
        PASSPHRASE,
    )?;
    m["sshd_posture"] = measured(json!(true));
    m["services"]["value"][0]["state"] = json!("running");
    m["services"]["value"][0]["running_after_last_placement"] = json!(true);
    case.check(
        "delivery_cases.a018",
        "successful recheck after fix clears finding",
        {
            let source_parameter = &m;
            observer::measurement_input("delivery.finding.fixed_check", source_parameter);
            check(
                "delivery.finding.fixed_check",
                run,
                tab,
                worker,
                &session,
                source_parameter,
            )
            .await
        }?["verdict"]
            == "Delivered",
    );
    module(run,worker,"await m.test_delivery_state(JSON.stringify({kind:'findings_unknown',machine:'fixture'}));return true;").await?;
    refresh(run, worker).await?;
    let state = run.inspect(worker).await?;
    case.check(
        "delivery_cases.a019",
        "fixture restore seam prevents delivery and placement",
        state["delivery"][0]["verdict"] != "Delivered"
            && state["delivery"][0]["findings_unknown"] == true
            && state["delivery"][0]["placement_eligible"] == false,
    );
    {
        let source_parameter = &m;
        observer::measurement_input("delivery.finding.restored_check", source_parameter);
        check(
            "delivery.finding.restored_check",
            run,
            tab,
            worker,
            &session,
            source_parameter,
        )
        .await
    }?;
    module(run,worker,&format!("await m.test_delivery_state(JSON.stringify({{kind:'subsequent_placement',machine:'fixture',session:{}}}));await m.end_sessions();return true;",json!(session))).await?;
    let state = run.inspect(worker).await?;
    case.check(
        "delivery_cases.a020",
        "session end preserves last verdict and subsequent placement evidence",
        state["delivery"][0]["verdict"] == "Delivered"
            && state["delivery"][0]["subsequent_placement_sessions"] == json!([session]),
    );
    case.finish(cases);

    for phase in ["delivery_read", "delivery_writer", "move", "failed_append"] {
        let session = {
            let source_parameter = Some(minimum());
            observer::declaration_input("delivery.lifecycle.prepare", &source_parameter);
            prepare(
                "delivery.lifecycle.prepare",
                run,
                tab,
                worker,
                source_parameter,
            )
            .await
        }?;
        inject(run, worker, &session, &clean()).await?;
        if phase == "failed_append" {
            module(
                run,
                worker,
                "await m.test_seed_backup_fail_append();return true;",
            )
            .await?;
        } else if phase == "move" {
            module(run,worker,"self.deliveryPoint=new Promise(ready=>m.test_hold_move(new Promise(release=>self.releaseDelivery=release),ready));return true;").await?;
        } else {
            module(run,worker,&format!("self.deliveryPoint=new Promise(ready=>m.test_hold_session_point({},new Promise(release=>self.releaseDelivery=release),ready));return true;",json!(phase))).await?;
        }
        module(
            run,
            worker,
            &format!(
                "self.deliveryAnswer=m.delivery_request({});return true;",
                json!(request(&session).to_string())
            ),
        )
        .await?;
        if phase != "failed_append" {
            if phase == "delivery_writer" {
                module(run,worker,"await self.deliveryPoint;self.deliveryWriterReady=new Promise(ready=>self.deliveryWriter=m.test_writer(new Promise(release=>self.releaseDeliveryWriter=release),ready));await self.deliveryWriterReady;self.releaseDelivery();await new Promise(r=>setTimeout(r,0));self.deliveryEnd=m.end_sessions();await new Promise(r=>setTimeout(r,0));return true;").await?;
            } else {
                module(run,worker,"await self.deliveryPoint;self.deliveryEnd=m.end_sessions();await new Promise(r=>setTimeout(r,0));return true;").await?;
            }
            if phase == "move" {
                module(
                    run,
                    worker,
                    "self.releaseDelivery();await self.deliveryEnd;return true;",
                )
                .await?;
            } else {
                let answer=module(run,worker,"return await Promise.race([self.deliveryAnswer.then(JSON.parse),new Promise(r=>setTimeout(()=>r({test_timeout:true}),2000))]);").await?;
                let mut case = Case::new(
                    "delivery_cases.c005",
                    &format!("delivery stops while {phase} is suspended"),
                );
                case.check(
                    "delivery_cases.a021",
                    "ended check answers explicitly before fixture release",
                    answer["state"] == "stopped" && answer["error"] == "sessions ended",
                );
                case.finish(cases);
                module(run,worker,if phase == "delivery_writer" {
                    "self.releaseDeliveryWriter();await self.deliveryWriter;await self.deliveryEnd;return true;"
                } else {
                    "self.releaseDelivery();await self.deliveryEnd;return true;"
                }).await?;
            }
        }
        let answer = module(run, worker, "return JSON.parse(await self.deliveryAnswer);").await?;
        let mut case = Case::new(
            "delivery_cases.c006",
            &format!("delivery grants no late publication at {phase}"),
        );
        case.check(
            "delivery_cases.a022",
            "failed or ended request reports no Delivered card",
            if phase == "failed_append" {
                answer.get("error").is_some() && answer["delivery"][0]["verdict"] != "Delivered"
            } else {
                answer["state"] == "stopped" && answer.get("delivery").is_none()
            },
        );
        let files = store_files(&run.dump_at("file.delivery_cases.dump.008", tab).await?);
        let opened = reader::read_at("reader.call.delivery.lifecycle", &files, PASSPHRASE)?;
        let count = opened
            .records
            .iter()
            .filter(|(_, b)| crate::journal::event(b).unwrap().get("delivery").is_some())
            .count();
        case.check(
            "delivery_cases.a023",
            "only a begun whole append can replay a check",
            count == usize::from(phase == "move"),
        );
        case.finish(cases);
    }
    incomplete_attempts(run, tab, worker, cases).await?;
    amendment(run, tab, worker, cases).await?;
    reports(run, tab, worker, cases).await?;
    run.put(tab, &original).await?;
    *worker = run
        .reload("delivery_cases.rs::reload#5", tab, worker)
        .await?;
    if !original.is_empty() {
        run.submit(tab, "unlock", PASSPHRASE).await?;
    }
    Ok(())
}

async fn incomplete_attempts(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let volatile = service("volatile", "running-at-delivery");
    let enabled = service("daemon", "enabled-survives-reboot");
    for unavailable in ["failed", "missing"] {
        for finding in [false, true] {
            let mut d = minimum();
            d["services"] = json!([volatile, enabled]);
            let session = {
                let source_parameter = Some(d);
                observer::declaration_input("delivery.incomplete.prepare", &source_parameter);
                prepare(
                    "delivery.incomplete.prepare",
                    run,
                    tab,
                    worker,
                    source_parameter,
                )
                .await
            }?;
            let mut m = clean();
            m["services"] = measured(json!([
                {"service":volatile,"state":if finding {"difference"} else {"running"},"running_after_last_placement":false},
                {"service":enabled,"state":"enabled_restart_not_demonstrated","running_after_last_placement":false}
            ]));
            let completed = {
                let source_parameter = &m;
                observer::measurement_input(
                    "delivery.incomplete.completed_check",
                    source_parameter,
                );
                check(
                    "delivery.incomplete.completed_check",
                    run,
                    tab,
                    worker,
                    &session,
                    source_parameter,
                )
                .await
            }?["last_check"]
                .clone();
            module(run,worker,&format!("await m.test_delivery_state(JSON.stringify({{kind:'subsequent_placement',machine:'fixture',session:{}}}));return true;",json!(session))).await?;
            m["services"] = json!({"read":unavailable});
            let attempt = {
                let source_parameter = &m;
                observer::measurement_input("delivery.incomplete.partial_check", source_parameter);
                check(
                    "delivery.incomplete.partial_check",
                    run,
                    tab,
                    worker,
                    &session,
                    source_parameter,
                )
                .await
            }?["last_check"]
                .clone();
            let verdict = if finding {
                "handed over with findings"
            } else {
                "Delivered"
            };
            let mut case = Case::new(
                "delivery_cases.c007",
                &format!(
                    "delivery {unavailable} attempt after placement retains completed verdict (finding={finding}) through end and reopen"
                ),
            );
            module(run, worker, "await m.end_sessions();return true;").await?;
            for phase in ["ended", "reopened"] {
                if phase == "reopened" {
                    *worker = run
                        .reload("delivery_cases.rs::reload#6", tab, worker)
                        .await?;
                    run.submit(tab, "unlock", PASSPHRASE).await?;
                }
                let state = run.inspect(worker).await?;
                let shown = &state["delivery"][0];
                let text = card(
                    match phase {
                        "ended" => "delivery.incomplete.ended_card",
                        "reopened" => "delivery.incomplete.reopened_card",
                        _ => "observer.unknown_phase",
                    },
                    run,
                    tab,
                    "Last recorded check against its journaled declaration:",
                )
                .await?;
                case.check("delivery_cases.a024", &format!("{phase}: production state retains completed verdict and distinct unavailable attempt"),
                    shown["verdict"] == verdict && shown["last_completed_check"] == completed
                    && shown["last_check"] == attempt && shown["last_check"]["result"]["complete"] == false
                    && shown["subsequent_placement_sessions"] == json!([session])
                    && shown["verdict_is_historical"] == true && shown["placement_eligible"] == false
                    && shown["findings"].as_array().unwrap().len() == usize::from(finding));
                case.check("delivery_cases.a025", &format!("{phase}: ordinary card shows pending placement, failed-attempt facts and historical evidence label"),
                    text.contains(&format!("Placement since the last check in session {session}; final lifecycle demonstration not supplied."))
                    && text.contains("Latest attempt incomplete; no final demonstration recorded.")
                    && text.contains("Last completed check (historical result):")
                    && text.contains("enabled, restart not demonstrated")
                    && text.contains(&format!("\"services\":{{\"read\":\"{unavailable}\"}}"))
                    && text.contains("\"inbound\":{\"read\":\"value\"")
                    && run.browser.evaluate(&tab.session,"document.querySelector('[data-delivery-verdict=fixture]')?.textContent").await? == verdict);
            }
            let opened = reader::read_at(
                "reader.call.delivery.incomplete",
                &store_files(&run.dump_at("file.delivery_cases.dump.009", tab).await?),
                PASSPHRASE,
            )?;
            let checks: Vec<Value> = opened
                .records
                .iter()
                .filter_map(|(_, bytes)| {
                    let v: Value = crate::journal::event(bytes).unwrap();
                    v["delivery"]["check"]
                        .as_object()
                        .map(|_| v["delivery"]["check"].clone())
                })
                .collect();
            case.check("delivery_cases.a026", "independent encrypted reader sees both completed evidence and actual partial measurements",
                checks == vec![completed, attempt]);
            case.finish(cases);
        }
    }
    Ok(())
}
async fn amendment(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let mut d = minimum();
    let declared = service("amended", "running-at-delivery");
    d["services"] = json!([declared]);
    let session = {
        let source_parameter = &initial("reader.aux.call.delivery.amendment.initial", Some(d));
        observer::files_input("delivery.amendment.prepare", source_parameter);
        declaration_cases::prepare(
            "delivery.amendment.prepare",
            run,
            tab,
            worker,
            source_parameter,
        )
        .await
    }?;
    let mut facts = clean();
    facts["services"] = measured(
        json!([{"service":declared,"state":"difference","running_after_last_placement":false}]),
    );
    let before = {
        let source_parameter = &facts;
        observer::measurement_input("delivery.amendment.initial_check", source_parameter);
        check(
            "delivery.amendment.initial_check",
            run,
            tab,
            worker,
            &session,
            source_parameter,
        )
        .await
    }?;
    inject(run, worker, &session, &clean()).await?;
    declaration_cases::start(
        run,
        tab,
        &session,
        vec![json!({"fixture_message":{
            "proposal":{"kind":"declaration","machine":"fixture","declaration":minimum()},
            "tool_calls":[{"name":"done","arguments":{"machine":"fixture"}}]
        }})],
    )
    .await?;
    let pending =
        declaration_cases::wait_card("delivery.amendment.wait_card", run, tab, worker, &session)
            .await?;
    let refusal = action(run, worker, request(&session)).await?;
    let mut case = Case::new(
        "delivery_cases.c008",
        "delivery amendment retains findings and rejects stale measurement authority before recheck",
    );
    case.check(
        "delivery_cases.a027",
        "pending amendment supplies no delivery authority",
        refusal.get("error").is_some() && refusal["delivery"][0]["findings"] == before["findings"],
    );
    let answer = json!({"session":session,"machine":"fixture","candidate":pending["candidate"],"decision":"approve"});
    module(
        run,
        worker,
        &format!("await self.onmessage({{data:{{requirements_answer:{answer}}}}});return true;"),
    )
    .await?;
    declaration_cases::outcome("delivery.amendment.outcome", run, tab, &session).await?;
    let state = run.inspect(worker).await?;
    case.check(
        "delivery_cases.a028",
        "journaled amendment alone keeps findings and old check identity",
        state["delivery"][0]["findings"] == before["findings"]
            && state["delivery"][0]["current_declaration_checked"] == false,
    );
    let refusal = action(run, worker, request(&session)).await?;
    case.check(
        "delivery_cases.a029",
        "old-declaration fixture cannot become new-declaration evidence",
        refusal.get("error").is_some() && refusal["delivery"][0]["findings"] == before["findings"],
    );
    let checked = {
        let source_parameter = &clean();
        observer::measurement_input("delivery.amendment.recheck", source_parameter);
        check(
            "delivery.amendment.recheck",
            run,
            tab,
            worker,
            &session,
            source_parameter,
        )
        .await
    }?;
    case.check(
        "delivery_cases.a030",
        "complete recheck against amendment clears the service finding",
        checked["verdict"] == "Delivered" && checked["findings"] == json!([]),
    );
    reader::read_at(
        "reader.call.delivery.amendment",
        &store_files(&run.dump_at("file.delivery_cases.dump.010", tab).await?),
        PASSPHRASE,
    )?;
    case.finish(cases);
    Ok(())
}
async fn reports(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let mut d = minimum();
    let declared = service("daemon", "running-at-delivery");
    d["services"] = json!([declared]);
    // This uses the actual inference, model tool dispatch, SSH fixture and encrypted job path.
    let session = {
        let source_parameter = &initial("reader.aux.call.delivery.report_success.initial", Some(d));
        observer::files_input("delivery.report_success.prepare", source_parameter);
        declaration_cases::prepare(
            "delivery.report_success.prepare",
            run,
            tab,
            worker,
            source_parameter,
        )
        .await
    }?;
    binding_cases::prepare(run, tab, worker, PASSPHRASE).await?;
    let mut m = clean();
    m["services"] = measured(
        json!([{"service":declared,"state":"difference","running_after_last_placement":false}]),
    );
    {
        let source_parameter = &m;
        observer::measurement_input("delivery.report_success.initial_check", source_parameter);
        check(
            "delivery.report_success.initial_check",
            run,
            tab,
            worker,
            &session,
            source_parameter,
        )
        .await
    }?;
    let before = run
        .inspect_state_at("state.delivery.success.before", worker)
        .await?
        .project("/delivery/0");
    let target = json!({"machine":"fixture","relay":run.relay.url,"host":"127.0.0.1","port":run.sshd.port,"user":SSH_USER});
    module(
        run,
        worker,
        &format!("return m.test_model_target({});", json!(target.to_string())),
    )
    .await?;
    fresh_pace(run.relay);
    let command = "printf 'delivery report success'; exit 0";
    let from = run.seen.lock().unwrap().ssh_exec.len();
    declaration_cases::start(
        run,
        tab,
        &session,
        vec![
            json!({"name":"exec","arguments":{"machine":"fixture","command":command}}),
            json!({"name":"done","arguments":{"machine":"fixture"}}),
        ],
    )
    .await?;
    declaration_cases::outcome("delivery.report_success.outcome", run, tab, &session).await?;
    let after = run
        .inspect_state_at("state.delivery.success.after", worker)
        .await?
        .project("/delivery/0");
    let mut case = Case::new(
        "delivery_cases.c009",
        "successful real model exec report cannot clear a stopped-service delivery finding",
    );
    case.check(
        "delivery_cases.a031",
        "actual model command ran once and finished with success",
        run.seen.lock().unwrap().ssh_exec.len() == from + 1
            && after["reports"]
                .as_array()
                .is_some_and(|r| r.iter().any(|r| r["terminal"]["exit_status"] == 0)),
    );
    case.check(
        "delivery_cases.a032",
        "report changes no verdict findings or placement eligibility",
        after.same_at(
            "delivery_cases.a032",
            &before,
            &["/verdict", "/findings", "/placement_eligible"],
        ),
    );
    refresh(run, worker).await?;
    let text = card(
        "delivery.report_success.card",
        run,
        tab,
        "delivery report success",
    )
    .await?;
    case.check(
        "delivery_cases.a033",
        "report label and output are neutral text",
        text.contains("delivery report success")
            && text.contains("Checks the AI wrote — not part of Delivered")
            && !text.contains("✓")
            && !text.contains("verified"),
    );
    let from = run.seen.lock().unwrap().ssh_exec.len();
    {
        let source_parameter = &m;
        observer::measurement_input("delivery.report_success.recheck", source_parameter);
        check(
            "delivery.report_success.recheck",
            run,
            tab,
            worker,
            &session,
            source_parameter,
        )
        .await
    }?;
    case.check(
        "delivery_cases.a034",
        "recheck never reexecutes historical reports",
        run.seen.lock().unwrap().ssh_exec.len() == from,
    );
    reader::read_at(
        "reader.call.delivery.report_success",
        &store_files(&run.dump_at("file.delivery_cases.dump.011", tab).await?),
        PASSPHRASE,
    )?;
    case.finish(cases);

    let session = {
        let source_parameter = &initial(
            "reader.aux.call.delivery.report_failure.initial",
            Some(minimum()),
        );
        observer::files_input("delivery.report_failure.prepare", source_parameter);
        declaration_cases::prepare(
            "delivery.report_failure.prepare",
            run,
            tab,
            worker,
            source_parameter,
        )
        .await
    }?;
    binding_cases::prepare(run, tab, worker, PASSPHRASE).await?;
    {
        let source_parameter = &clean();
        observer::measurement_input("delivery.report_failure.initial_check", source_parameter);
        check(
            "delivery.report_failure.initial_check",
            run,
            tab,
            worker,
            &session,
            source_parameter,
        )
        .await
    }?;
    let before = run
        .inspect_state_at("state.delivery.failure.before", worker)
        .await?
        .project("/delivery/0");
    module(
        run,
        worker,
        &format!("return m.test_model_target({});", json!(target.to_string())),
    )
    .await?;
    fresh_pace(run.relay);
    declaration_cases::start(run,tab,&session,vec![json!({"name":"exec","arguments":{"machine":"fixture","command":"printf 'report failed'; exit 7"}}),json!({"name":"done","arguments":{"machine":"fixture"}})]).await?;
    declaration_cases::outcome("delivery.report_failure.outcome", run, tab, &session).await?;
    let after = run
        .inspect_state_at("state.delivery.failure.after", worker)
        .await?
        .project("/delivery/0");
    let mut case = Case::new(
        "delivery_cases.c010",
        "failing real model report cannot spoil clean delivery or block placement",
    );
    case.check(
        "delivery_cases.a035",
        "failing report is recorded as exit 7",
        after["reports"]
            .as_array()
            .is_some_and(|r| r.iter().any(|r| r["terminal"]["exit_status"] == 7)),
    );
    case.check(
        "delivery_cases.a036",
        "failure changes no delivery finding or placement",
        crate::state_inputs::all!(
            after["verdict"] == "Delivered",
            after.same_at(
                "delivery_cases.a036",
                &before,
                &["/findings", "/placement_eligible"],
            )
        ),
    );
    let files = store_files(&run.dump_at("file.delivery_cases.dump.012", tab).await?);
    reader::read_at("reader.call.delivery.report_failure", &files, PASSPHRASE)?;
    let from = run.seen.lock().unwrap().ssh_exec.len();
    *worker = run
        .reload("delivery_cases.rs::reload#7", tab, worker)
        .await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    case.check(
        "delivery_cases.a037",
        "reentry restores reports and never schedules commands",
        run.seen.lock().unwrap().ssh_exec.len() == from
            && run.inspect(worker).await?["delivery"][0]["verdict"] == "Delivered",
    );
    case.finish(cases);
    Ok(())
}
