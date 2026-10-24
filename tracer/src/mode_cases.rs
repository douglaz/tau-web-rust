//! Installation history display and signature-lowering refusal before relay contact.
use super::*;

pub(super) async fn run(
    run: &Run<'_>,
    tab: &Tab,
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
    let original = store_files(&run.dump(tab).await?);
    let mnemonic = reader::read(&original, pass)?.mnemonic()?;
    let mut events = vec![json!({"seed":{"mnemonic":mnemonic}})];
    events.extend(reader::setup_events(
        &mnemonic,
        &["fixture", "fixture-other"],
    ));
    for machine in ["fixture", "fixture-other"] {
        events.push(
            json!({"setup":{"class":{"machine":machine,"answer":"no","class":"single_purpose"}}}),
        );
    }
    let identity = events[2]["setup"]["approval"]["entries"][0]["identity"].clone();
    let session = format!("session-{}", events.len());
    events.push(json!({"exposure":{"session":session,"bound_set":[{"machine":"fixture","identity":identity}],"accepted_modes":["no_artifact_pin"]}}));
    run.put(tab, &reader::build(pass, &events)).await?;
    *worker = run.reload(tab, worker).await?;
    run.submit(tab, "unlock", pass).await?;
    binding_cases::prepare(run, tab, worker, pass).await?;
    let build = if tracer { "tracer" } else { "served" };
    let mut case = Case::new(&format!(
        "acceptable weaker modes and pre-contact signature refusal: {build}"
    ));
    let before = run.inspect(worker).await?;
    let labels = json!(["An installation with no artifact pin"]);
    case.check(
        "the rebound session lists exactly the installation mode",
        before["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["bound_set"] == json!(["fixture"]) && s["standing_modes"] == labels),
    );
    case.check(
        "inspection records the installation as unpinned",
        before["installations"] == json!([{"machine":"fixture","installation":"unpinned"}]),
    );
    let rendered = run
        .browser
        .evaluate(
            &tab.session,
            "document.querySelector('[data-machine=fixture]').innerText",
        )
        .await?;
    case.check(
        "fixture's section renders the exact installation and standing label",
        rendered.as_str().is_some_and(|s| {
            s.lines().any(|line| line == "Installation: unpinned.")
                && s.lines()
                    .any(|line| line == "Standing mode: An installation with no artifact pin.")
        }),
    );
    let page = run
        .browser
        .evaluate(&tab.session, "document.documentElement.outerHTML")
        .await?;
    let artifact: toml::Value = toml::from_str(
        tau_web::BUNDLE
            .iter()
            .find(|(name, _)| *name == "artifact-alpine.toml")
            .unwrap()
            .1,
    )
    .unwrap();
    let mut needles = vec![
        artifact["bootstrap"]["url"].as_str().unwrap(),
        artifact["bootstrap"]["sha256"].as_str().unwrap(),
    ];
    for key in artifact["packages"]["keys"].as_array().unwrap() {
        needles.extend([
            key["name"].as_str().unwrap(),
            key["sha256"].as_str().unwrap(),
        ]);
    }
    let report = run.browser.evaluate(&worker.session, "(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m.open());})()").await?;
    for surface in [page.to_string(), before.to_string(), report.to_string()] {
        case.check(
            "no artifact pin or package signer is claimed",
            needles.iter().all(|n| !surface.contains(n))
                && !["\"hash\"", "\"signer\"", "\"sha256\""]
                    .iter()
                    .any(|n| surface.contains(n)),
        );
    }
    for (bytes, form) in [
        ("printf '%s\\n' 'SigLevel = Never'", "signature_level_never"),
        (
            "printf '%s\\n' 'SigLevel = Optional TrustAll'",
            "untrusted_repository",
        ),
    ] {
        take(run.seen);
        fresh_pace(run.relay);
        let before = run.inspect(worker).await?;
        let mut request = args("fixture");
        request["command"] = bytes.into();
        let report = run.harness_run(worker, request).await?;
        run.sshd.all_ended().await;
        let seen = take(run.seen);
        case.check(
            "lowering refused before relay or SSH contact and exec",
            report["outcome"]
                == json!({"refused":"signature-lowering","machine":"fixture","form":form})
                && seen.relay_accepted == 0
                && seen.ssh_connections == 0
                && seen.ssh_exec.is_empty(),
        );
        let after = run.inspect(worker).await?;
        case.check(
            "exactly one refusal, no intent, unchanged modes",
            after["records"].as_array().unwrap().len()
                == before["records"].as_array().unwrap().len() + 1
                && after["calls"] == before["calls"]
                && after["commands"] == before["commands"]
                && after["mode_acceptances"] == before["mode_acceptances"]
                && after["sessions"] == before["sessions"]
                && after["signature_refusals"].as_array().unwrap().last()
                    == Some(&json!({"machine":"fixture","form":form})),
        );
        let opened = reader::read(&store_files(&run.dump(tab).await?), pass)?;
        let event: Value =
            serde_json::from_slice(&opened.records.last().unwrap().1).map_err(|e| e.to_string())?;
        case.check(
            "independent reader reads the exact refusal record",
            event == json!({"signature_refusal":{"machine":"fixture","form":form}}),
        );
    }
    if tracer {
        for (machine, bytes, status) in [
            ("fixture-other", "printf '%s\\n' 'SigLevel = Never'", 0),
            ("fixture", "echo ok; exit 7", 7),
        ] {
            fresh_pace(run.relay);
            take(run.seen);
            let mut request = args(machine);
            request["command"] = bytes.into();
            let report = run.harness_run(worker, request).await?;
            let observed = take(run.seen);
            let after = run.inspect(worker).await?;
            case.check(
                "controls complete with a journaled terminal",
                report["outcome"]["done"] == true
                    && report["outcome"]["exit_status"] == status
                    && report["outcome"]["job_record"]["job"]
                        .as_str()
                        .is_some_and(|job| {
                            observed.ssh_exec
                                == vec![
                                    tau_web::jobs::launch(job, machine, bytes.as_bytes())
                                        .into_bytes(),
                                ]
                        })
                    && after["terminals"].as_array().unwrap().iter().any(|t| {
                        t["call"] == report["outcome"]["call"] && t["exit_status"] == status
                    }),
            );
        }
        let before = run.inspect(worker).await?;
        run.sshd.present_other.store(true, Ordering::SeqCst);
        fresh_pace(run.relay);
        take(run.seen);
        let report = run.harness_run(worker, args("fixture")).await?;
        run.sshd.present_other.store(false, Ordering::SeqCst);
        run.sshd.all_ended().await;
        let observed = take(run.seen);
        let after = run.inspect(worker).await?;
        case.check(
            "wrong host key halts without entering any mode",
            report["outcome"]["refused"] == "host-key"
                && before["mode_acceptances"] == after["mode_acceptances"]
                && before["sessions"] == after["sessions"]
                && before["records"] == after["records"]
                && observed.ssh_exec.is_empty()
                && observed.ssh_auth.is_empty(),
        );
    }
    cases.push(case);
    run.put(tab, &original).await?;
    *worker = run.reload(tab, worker).await?;
    run.submit(tab, "unlock", pass).await?;
    Ok(())
}
