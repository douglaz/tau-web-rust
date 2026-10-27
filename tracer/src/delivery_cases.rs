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
fn clean() -> Value {
    json!({"inbound":measured(json!([{"proto":"tcp","port":22,"from":"any"}])),"outbound":measured(json!([])),
        "services":measured(json!([])),"spendable":measured(json!(false)),"permitted":measured(json!([])),
        "required":measured(json!([])),"credentials":measured(json!([])),"fixed_default_credentials":measured(json!(true)),
        "sshd_posture":measured(json!(true)),"placing_session":false})
}
fn initial(d: Option<Value>) -> Files {
    let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut events = vec![json!({"seed":{"mnemonic":words}})];
    events.extend(reader::setup_events(words, &["fixture"]));
    events.push(
        json!({"setup":{"class":{"machine":"fixture","answer":"no","class":"single_purpose"}}}),
    );
    if let Some(d) = d {
        events.push(json!({"setup":{"requirements":{"session":"fixture-contract","candidate":0,
        "access":{"model":"maintained","profile":"ad-hoc","revision":tau_web::dispatch::ad_hoc_revision()},
        "proposal":{"kind":"declaration","machine":"fixture","declaration":d}}}}));
    }
    reader::build(PASSPHRASE, &events)
}
async fn prepare(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    d: Option<Value>,
) -> Result<String, String> {
    run.put(tab, &initial(d)).await?;
    *worker = run.reload(tab, worker).await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    setup_cases::click(run, tab, "[data-bind=fixture]").await?;
    for _ in 0..300 {
        let state = run.inspect(worker).await?;
        if let Some(s) = state["sessions"]
            .as_array()
            .and_then(|v| v.first())
            .and_then(|v| v["identity"].as_str())
        {
            return Ok(s.into());
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
    run: &Run<'_>,
    tab: &Tab,
    worker: &Worker,
    session: &str,
    m: &Value,
) -> Result<Value, String> {
    inject(run, worker, session, m).await?;
    // This is the actual served button and worker handler. Wait on a distinct recorded check.
    let before = run.inspect(worker).await?["records"]
        .as_array()
        .map_or(0, Vec::len);
    setup_cases::click(run, tab, "[data-delivery-check=fixture]").await?;
    for _ in 0..300 {
        let state = run.inspect(worker).await?;
        if state["records"].as_array().map_or(0, Vec::len) > before
            && state["delivery"][0]["last_check"].is_object()
            && run
                .browser
                .evaluate(
                    &tab.session,
                    "document.querySelector('[data-delivery-check=fixture]')?.disabled === false",
                )
                .await?
                == true
        {
            return Ok(state["delivery"][0].clone());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err("delivery check produced no durable result".into())
}
async fn card(run: &Run<'_>, tab: &Tab, needle: &str) -> Result<String, String> {
    for _ in 0..300 {
        let v = run
            .browser
            .evaluate(
                &tab.session,
                "document.querySelector('[data-delivery-card=fixture]')?.textContent ?? ''",
            )
            .await?;
        let text = v.as_str().unwrap_or_default();
        if text.contains(needle) {
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
    let original = store_files(&run.dump(tab).await?);
    if std::env::var("TAU_TRACER_DELIVERY_CASE").as_deref() == Ok("reports") {
        reports(run, tab, worker, cases).await?;
        run.put(tab, &original).await?;
        *worker = run.reload(tab, worker).await?;
        if !original.is_empty() {
            run.submit(tab, "unlock", PASSPHRASE).await?;
        }
        return Ok(());
    }
    if std::env::var("TAU_TRACER_DELIVERY_CASE").as_deref() == Ok("incomplete") {
        incomplete_attempts(run, tab, worker, cases).await?;
        run.put(tab, &original).await?;
        *worker = run.reload(tab, worker).await?;
        if !original.is_empty() {
            run.submit(tab, "unlock", PASSPHRASE).await?;
        }
        return Ok(());
    }
    let session = prepare(run, tab, worker, None).await?;
    let before = run.dump(tab).await?;
    let response = action(run, worker, request(&session)).await?;
    let mut case =
        Case::new("delivery refuses absent declaration and untrusted worker measurements");
    case.check(
        "no declaration writes no result or delivery",
        before == run.dump(tab).await? && response["delivery"][0]["verdict"] != "Delivered",
    );
    let session = prepare(run, tab, worker, Some(minimum())).await?;
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
            "measurement/waiver request is explicitly refused",
            response.get("error").is_some(),
        );
    }
    let state = action(run, worker, request(&session)).await?;
    case.check(
        "no supplied fixture evidence remains unavailable",
        state["delivery"][0]["verdict"] != "Delivered"
            && state["delivery"][0]["last_check"]["result"]["complete"] == false,
    );
    cases.push(case);

    let session = prepare(run, tab, worker, Some(minimum())).await?;
    let delivered = check(run, tab, worker, &session, &clean()).await?;
    let mut case = Case::new(
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
            "application association is published",
            v["delivery"][0]["applications"]
                .as_array()
                .is_some_and(|v| v.contains(&json!(name))),
        );
    }
    let before = store_files(&run.dump(tab).await?);
    let duplicate = action(
        run,
        worker,
        json!({"action":"application","session":session,"machine":"fixture","name":"Hermes"}),
    )
    .await?;
    case.check(
        "exact duplicate name refused without write",
        duplicate.get("error").is_some() && before == store_files(&run.dump(tab).await?),
    );
    for _ in 0..300 {
        if run
            .browser
            .evaluate(
                &tab.session,
                "document.querySelectorAll('[data-delivery-application]').length",
            )
            .await?
            == 2
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let text = card(
        run,
        tab,
        "Last recorded check against its journaled declaration:",
    )
    .await?;
    case.check("actual card claims fixture delivery with coverage and both exact sentences",delivered["verdict"]=="Delivered"
        && text.contains(tau_web::delivery::FIXTURE_LIMIT)
        && text.contains("Delivered covers the declared machine state and the fixed lockdown checks.")
        && text.contains("It does not mean Hermes works")
            && text.contains("Hermes is an AI that acts on this server by itself. tau-web's promises cover what tau-web's AI does, not what Hermes does.")
        && text.contains("<b data-delivery-injected>application</b> is an AI") && text.contains("It does not mean <b data-delivery-injected>application</b> works"));
    case.check(
        "application name creates no HTML element",
        run.browser
            .evaluate(
                &tab.session,
                "document.querySelector('[data-delivery-card] [data-delivery-injected]')===null",
            )
            .await?
            == true,
    );
    let files = store_files(&run.dump(tab).await?);
    let opened = reader::read(&files, PASSPHRASE)?;
    case.check(
        "independent encrypted reader observes check and exact names",
        opened.records.iter().any(|(_, b)| {
            serde_json::from_slice::<Value>(b).unwrap()["delivery"]["check"]["result"]["delivered"]
                == true
        }) && opened.records.iter().any(|(_, b)| {
            serde_json::from_slice::<Value>(b).unwrap()["delivery"]["name"] == "Hermes"
        }),
    );
    *worker = run.reload(tab, worker).await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    let restored = run.inspect(worker).await?;
    let text = card(
        run,
        tab,
        "Last recorded check against its journaled declaration:",
    )
    .await?;
    case.check(
        "reopen restores card with no running session",
        restored["delivery"][0]["verdict"] == "Delivered"
            && restored["sessions"] == json!([])
            && text.contains("Fixture"),
    );
    cases.push(case);

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
        let session = prepare(run, tab, worker, Some(d.clone())).await?;
        let mut m = clean();
        m["services"]=measured(Value::Array(d["services"].as_array().unwrap().iter().map(|s|json!({"service":s,"state":if s["name"]=="daemon"{"enabled_restart_not_demonstrated"}else{"stopped_since_restart"},"running_after_last_placement":false})).collect()));
        let result = check(run, tab, worker, &session, &m).await?;
        let text = card(
            run,
            tab,
            "Last recorded check against its journaled declaration:",
        )
        .await?;
        let mut case = Case::new(&format!(
            "delivery consumes lifecycle evidence notes combination {notes}"
        ));
        case.check(
            "passing labels accompany the actual Delivered card",
            result["verdict"] == "Delivered"
                && result["findings"] == json!([])
                && (notes == 2 || text.contains("enabled, restart not demonstrated"))
                && (notes == 1 || text.contains("stopped since a restart, as approved")),
        );
        let state = run.inspect(worker).await?;
        case.check(
            "inspection has the same service-associated evidence notes",
            state["delivery"][0]["last_check"]["result"]["notes"]
                == result["last_check"]["result"]["notes"],
        );
        if notes == 3 {
            m["sshd_posture"] = measured(json!(false));
            let result = check(run, tab, worker, &session, &m).await?;
            case.check(
                "independent fixed finding survives both labels",
                result["verdict"] == "handed over with findings"
                    && result["placement_eligible"] == false
                    && result["findings"].as_array().unwrap().len() == 1,
            );
            m["sshd_posture"] = measured(json!(true));
            m["placing_session"] = json!(true);
            let result = check(run, tab, worker, &session, &m).await?;
            case.check(
                "placing-session restriction turns stopped restart note into lifecycle finding",
                result["verdict"] == "handed over with findings"
                    && result["placement_eligible"] == true
                    && result["findings"][0]["class"] == "lifecycle",
            );
            m["placing_session"] = json!(false);
            let result = check(run, tab, worker, &session, &m).await?;
            case.check(
                "restart note never clears a standing lifecycle finding",
                result["verdict"] == "handed over with findings",
            );
        }
        cases.push(case);
    }
    let mut d = minimum();
    d["services"] = json!([volatile]);
    let session = prepare(run, tab, worker, Some(d)).await?;
    let mut m = clean();
    m["services"] = measured(
        json!([{"service":volatile,"state":"difference","running_after_last_placement":false}]),
    );
    let before = check(run, tab, worker, &session, &m).await?;
    let mut case = Case::new(
        "delivery keeps lifecycle-only findings visible until recheck and refuses acceptance",
    );
    let text = card(run, tab, "handed over with findings").await?;
    case.check(
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
            "accept/waive cannot clear finding",
            v.get("error").is_some() && v["delivery"][0]["findings"] == before["findings"],
        );
    }
    m["sshd_posture"] = measured(json!(false));
    let mixed = check(run, tab, worker, &session, &m).await?;
    let text = card(run, tab, "Fixed lockdown fixture check").await?;
    case.check(
        "ordinary card retains every mixed-class finding",
        mixed["findings"].as_array().unwrap().len() == 2
            && text.contains("lifecycle: Service volatile")
            && text.contains("lockdown: Fixed lockdown fixture check"),
    );
    reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
    m["sshd_posture"] = measured(json!(true));
    m["services"]["value"][0]["state"] = json!("running");
    m["services"]["value"][0]["running_after_last_placement"] = json!(true);
    case.check(
        "successful recheck after fix clears finding",
        check(run, tab, worker, &session, &m).await?["verdict"] == "Delivered",
    );
    module(run,worker,"await m.test_delivery_state(JSON.stringify({kind:'findings_unknown',machine:'fixture'}));return true;").await?;
    refresh(run, worker).await?;
    let state = run.inspect(worker).await?;
    case.check(
        "fixture restore seam prevents delivery and placement",
        state["delivery"][0]["verdict"] != "Delivered"
            && state["delivery"][0]["findings_unknown"] == true
            && state["delivery"][0]["placement_eligible"] == false,
    );
    check(run, tab, worker, &session, &m).await?;
    module(run,worker,&format!("await m.test_delivery_state(JSON.stringify({{kind:'subsequent_placement',machine:'fixture',session:{}}}));await m.end_sessions();return true;",json!(session))).await?;
    let state = run.inspect(worker).await?;
    case.check(
        "session end preserves last verdict and subsequent placement evidence",
        state["delivery"][0]["verdict"] == "Delivered"
            && state["delivery"][0]["subsequent_placement_sessions"] == json!([session]),
    );
    cases.push(case);

    for phase in ["delivery_read", "delivery_writer", "move", "failed_append"] {
        let session = prepare(run, tab, worker, Some(minimum())).await?;
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
                let mut case = Case::new(&format!("delivery stops while {phase} is suspended"));
                case.check(
                    "ended check answers explicitly before fixture release",
                    answer["state"] == "stopped" && answer["error"] == "sessions ended",
                );
                cases.push(case);
                module(run,worker,if phase == "delivery_writer" {
                    "self.releaseDeliveryWriter();await self.deliveryWriter;await self.deliveryEnd;return true;"
                } else {
                    "self.releaseDelivery();await self.deliveryEnd;return true;"
                }).await?;
            }
        }
        let answer = module(run, worker, "return JSON.parse(await self.deliveryAnswer);").await?;
        let mut case = Case::new(&format!("delivery grants no late publication at {phase}"));
        case.check(
            "failed or ended request reports no Delivered card",
            if phase == "failed_append" {
                answer.get("error").is_some() && answer["delivery"][0]["verdict"] != "Delivered"
            } else {
                answer["state"] == "stopped" && answer.get("delivery").is_none()
            },
        );
        let files = store_files(&run.dump(tab).await?);
        let opened = reader::read(&files, PASSPHRASE)?;
        let count = opened
            .records
            .iter()
            .filter(|(_, b)| {
                serde_json::from_slice::<Value>(b)
                    .unwrap()
                    .get("delivery")
                    .is_some()
            })
            .count();
        case.check(
            "only a begun whole append can replay a check",
            count == usize::from(phase == "move"),
        );
        cases.push(case);
    }
    incomplete_attempts(run, tab, worker, cases).await?;
    amendment(run, tab, worker, cases).await?;
    reports(run, tab, worker, cases).await?;
    run.put(tab, &original).await?;
    *worker = run.reload(tab, worker).await?;
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
            let session = prepare(run, tab, worker, Some(d)).await?;
            let mut m = clean();
            m["services"] = measured(json!([
                {"service":volatile,"state":if finding {"difference"} else {"running"},"running_after_last_placement":false},
                {"service":enabled,"state":"enabled_restart_not_demonstrated","running_after_last_placement":false}
            ]));
            let completed = check(run, tab, worker, &session, &m).await?["last_check"].clone();
            module(run,worker,&format!("await m.test_delivery_state(JSON.stringify({{kind:'subsequent_placement',machine:'fixture',session:{}}}));return true;",json!(session))).await?;
            m["services"] = json!({"read":unavailable});
            let attempt = check(run, tab, worker, &session, &m).await?["last_check"].clone();
            let verdict = if finding {
                "handed over with findings"
            } else {
                "Delivered"
            };
            let mut case = Case::new(&format!(
                "delivery {unavailable} attempt after placement retains completed verdict (finding={finding}) through end and reopen"
            ));
            module(run, worker, "await m.end_sessions();return true;").await?;
            for phase in ["ended", "reopened"] {
                if phase == "reopened" {
                    *worker = run.reload(tab, worker).await?;
                    run.submit(tab, "unlock", PASSPHRASE).await?;
                }
                let state = run.inspect(worker).await?;
                let shown = &state["delivery"][0];
                let text = card(
                    run,
                    tab,
                    "Last recorded check against its journaled declaration:",
                )
                .await?;
                case.check(&format!("{phase}: production state retains completed verdict and distinct unavailable attempt"),
                    shown["verdict"] == verdict && shown["last_completed_check"] == completed
                    && shown["last_check"] == attempt && shown["last_check"]["result"]["complete"] == false
                    && shown["subsequent_placement_sessions"] == json!([session])
                    && shown["verdict_is_historical"] == true && shown["placement_eligible"] == false
                    && shown["findings"].as_array().unwrap().len() == usize::from(finding));
                case.check(&format!("{phase}: ordinary card shows pending placement, failed-attempt facts and historical evidence label"),
                    text.contains(&format!("Placement since the last check in session {session}; final lifecycle demonstration not supplied."))
                    && text.contains("Latest attempt incomplete; no final demonstration recorded.")
                    && text.contains("Last completed check (historical result):")
                    && text.contains("enabled, restart not demonstrated")
                    && text.contains(&format!("\"services\":{{\"read\":\"{unavailable}\"}}"))
                    && text.contains("\"inbound\":{\"read\":\"value\"")
                    && run.browser.evaluate(&tab.session,"document.querySelector('[data-delivery-verdict=fixture]')?.textContent").await? == verdict);
            }
            let opened = reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
            let checks: Vec<Value> = opened
                .records
                .iter()
                .filter_map(|(_, bytes)| {
                    let v: Value = serde_json::from_slice(bytes).unwrap();
                    v["delivery"]["check"]
                        .as_object()
                        .map(|_| v["delivery"]["check"].clone())
                })
                .collect();
            case.check("independent encrypted reader sees both completed evidence and actual partial measurements",
                checks == vec![completed, attempt]);
            cases.push(case);
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
    let session = declaration_cases::prepare(run, tab, worker, &initial(Some(d))).await?;
    let mut facts = clean();
    facts["services"] = measured(
        json!([{"service":declared,"state":"difference","running_after_last_placement":false}]),
    );
    let before = check(run, tab, worker, &session, &facts).await?;
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
    let pending = declaration_cases::wait_card(run, tab, worker, &session).await?;
    let refusal = action(run, worker, request(&session)).await?;
    let mut case = Case::new(
        "delivery amendment retains findings and rejects stale measurement authority before recheck",
    );
    case.check(
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
    declaration_cases::outcome(run, tab, &session).await?;
    let state = run.inspect(worker).await?;
    case.check(
        "journaled amendment alone keeps findings and old check identity",
        state["delivery"][0]["findings"] == before["findings"]
            && state["delivery"][0]["current_declaration_checked"] == false,
    );
    let refusal = action(run, worker, request(&session)).await?;
    case.check(
        "old-declaration fixture cannot become new-declaration evidence",
        refusal.get("error").is_some() && refusal["delivery"][0]["findings"] == before["findings"],
    );
    let checked = check(run, tab, worker, &session, &clean()).await?;
    case.check(
        "complete recheck against amendment clears the service finding",
        checked["verdict"] == "Delivered" && checked["findings"] == json!([]),
    );
    reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
    cases.push(case);
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
    let session = declaration_cases::prepare(run, tab, worker, &initial(Some(d))).await?;
    binding_cases::prepare(run, tab, worker, PASSPHRASE).await?;
    let mut m = clean();
    m["services"] = measured(
        json!([{"service":declared,"state":"difference","running_after_last_placement":false}]),
    );
    check(run, tab, worker, &session, &m).await?;
    let before = run.inspect(worker).await?["delivery"][0].clone();
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
    declaration_cases::outcome(run, tab, &session).await?;
    let after = run.inspect(worker).await?["delivery"][0].clone();
    let mut case = Case::new(
        "successful real model exec report cannot clear a stopped-service delivery finding",
    );
    case.check(
        "actual model command ran once and finished with success",
        run.seen.lock().unwrap().ssh_exec.len() == from + 1
            && after["reports"]
                .as_array()
                .is_some_and(|r| r.iter().any(|r| r["terminal"]["exit_status"] == 0)),
    );
    case.check(
        "report changes no verdict findings or placement eligibility",
        before["verdict"] == after["verdict"]
            && before["findings"] == after["findings"]
            && before["placement_eligible"] == after["placement_eligible"],
    );
    refresh(run, worker).await?;
    let text = card(run, tab, "delivery report success").await?;
    case.check(
        "report label and output are neutral text",
        text.contains("delivery report success")
            && text.contains("Checks the AI wrote — not part of Delivered")
            && !text.contains("✓")
            && !text.contains("verified"),
    );
    let from = run.seen.lock().unwrap().ssh_exec.len();
    check(run, tab, worker, &session, &m).await?;
    case.check(
        "recheck never reexecutes historical reports",
        run.seen.lock().unwrap().ssh_exec.len() == from,
    );
    reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
    cases.push(case);

    let session = declaration_cases::prepare(run, tab, worker, &initial(Some(minimum()))).await?;
    binding_cases::prepare(run, tab, worker, PASSPHRASE).await?;
    check(run, tab, worker, &session, &clean()).await?;
    let before = run.inspect(worker).await?["delivery"][0].clone();
    module(
        run,
        worker,
        &format!("return m.test_model_target({});", json!(target.to_string())),
    )
    .await?;
    fresh_pace(run.relay);
    declaration_cases::start(run,tab,&session,vec![json!({"name":"exec","arguments":{"machine":"fixture","command":"printf 'report failed'; exit 7"}}),json!({"name":"done","arguments":{"machine":"fixture"}})]).await?;
    declaration_cases::outcome(run, tab, &session).await?;
    let after = run.inspect(worker).await?["delivery"][0].clone();
    let mut case =
        Case::new("failing real model report cannot spoil clean delivery or block placement");
    case.check(
        "failing report is recorded as exit 7",
        after["reports"]
            .as_array()
            .is_some_and(|r| r.iter().any(|r| r["terminal"]["exit_status"] == 7)),
    );
    case.check(
        "failure changes no delivery finding or placement",
        after["verdict"] == "Delivered"
            && after["findings"] == before["findings"]
            && after["placement_eligible"] == before["placement_eligible"],
    );
    let files = store_files(&run.dump(tab).await?);
    reader::read(&files, PASSPHRASE)?;
    let from = run.seen.lock().unwrap().ssh_exec.len();
    *worker = run.reload(tab, worker).await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    case.check(
        "reentry restores reports and never schedules commands",
        run.seen.lock().unwrap().ssh_exec.len() == from
            && run.inspect(worker).await?["delivery"][0]["verdict"] == "Delivered",
    );
    cases.push(case);
    Ok(())
}
