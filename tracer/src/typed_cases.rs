//! Typed barriers on the real pinned connection, using independently written stores.
use super::*;

pub(super) fn intent(call: u64, operation: &str) -> Value {
    let facts =
        json!({"arguments":{"size":"small"},"cost_bound":12,"bundle_commit":tau_web::SPEC_COMMIT});
    let approved = json!({"resource":{"entry":"fixture"},"target":{"entry":"fixture"},"operation":operation,"session":"fixture-session","requester":"session","facts":facts});
    json!({"operation_intent":{"call":call,"resource":{"entry":"fixture"},"target":{"entry":"fixture"},"operation":operation,"session":"fixture-session","requester":"session","facts":facts,"approved":approved}})
}

async fn restore(
    run: &Run<'_>,
    tab: &Tab,
    worker: Worker,
    events: &[Value],
) -> Result<Worker, String> {
    run.put(tab, &reader::build(PASSPHRASE, events)).await?;
    let worker = run.reload(tab, &worker).await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    Ok(worker)
}

pub(super) async fn run(
    run: &Run<'_>,
    tab: &Tab,
    mut worker: Worker,
    args: &dyn Fn(&str) -> Value,
    cases: &mut Vec<Case>,
) -> Result<Worker, String> {
    let saved = store_files(&run.dump(tab).await?);
    let events = reader::read(&saved, PASSPHRASE)?
        .records
        .iter()
        .map(|(_, p)| serde_json::from_slice(p).map_err(|e| e.to_string()))
        .collect::<Result<Vec<Value>, _>>()?;
    let original = events[..2].to_vec();
    let mut events = original.clone();
    let call = events.len() as u64;
    events.push(intent(call, "reset"));
    worker = restore(run, tab, worker, &events).await?;
    let mut case = Case::new("typed reset bars commands before contact until durable confirmation");
    fresh_pace(run.relay);
    take(run.seen);
    let before = run.inspect(&worker).await?;
    let report = run.harness_run(&worker, args("fixture")).await?;
    run.sshd.all_ended().await;
    let seen = take(run.seen);
    case.check(
        "unresolved reset is named; no relay or SSH contact, no intent",
        report["outcome"]["refused"] == "barrier"
            && report["outcome"]["calls"][0]["call"] == call
            && seen.relay_accepted == 0
            && seen.ssh_connections == 0
            && run.inspect(&worker).await? == before,
    );
    events.push(json!({"operation_observation":{"resource":{"entry":"fixture"},"operation":"reset","reports":"confirmed","calls":[call]}}));
    worker = restore(run, tab, worker, &events).await?;
    fresh_pace(run.relay);
    take(run.seen);
    let report = run.harness_run(&worker, args("fixture")).await?;
    let seen = take(run.seen);
    case.check(
        "confirming observation permits command",
        report["outcome"]["done"] == true && exec_command_is(&seen, COMMAND),
    );
    reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
    cases.push(case);

    for continuation in [
        "destructive_reinstall",
        "abandonment",
        "as_if_done",
        "as_if_not_done",
    ] {
        let mut events = original.clone();
        let call = events.len() as u64;
        events.push(intent(call, "reset"));
        let disposition = events.len() as u64;
        events.push(json!({"disposition":{"machine":"fixture","calls":[call],"continuation":continuation,"uncertainty":"effect not established"}}));
        worker = restore(run, tab, worker, &events).await?;
        let mut case = Case::new(&format!(
            "typed running-system disposition {continuation}: pinned attempt and collection stay permitted"
        ));
        let destructive = ["destructive_reinstall", "abandonment"].contains(&continuation);
        for when in ["before collection", "after collection"] {
            fresh_pace(run.relay);
            take(run.seen);
            let report = run.harness_run(&worker, args("fixture")).await?;
            run.sshd.all_ended().await;
            let seen = take(run.seen);
            case.check(&format!("{when}: run_command obeys continuation"),
                if destructive { report["outcome"]==json!({"refused":"disposition","disposition":disposition,"continuation":continuation}) && seen.relay_accepted==0 && seen.ssh_connections==0 }
                else { report["outcome"]["done"]==true && exec_command_is(&seen,COMMAND) });
            if when == "before collection" {
                fresh_pace(run.relay);
                take(run.seen);
                let before = run.inspect(&worker).await?;
                let report = run.harness_collect(&worker, args("fixture")).await?;
                run.sshd.all_ended().await;
                let seen = take(run.seen);
                let after = run.inspect(&worker).await?;
                case.check("bare pinned attempt reaches relay and sshd, collects no jobs and appends no intent",
                    report["outcome"]["collected"]==json!([]) && seen.relay_dials.len()==1 && seen.ssh_connections>0 && seen.ssh_exec.is_empty()
                    && after["records"]==before["records"] && after["standing"]==before["standing"]);
            }
        }
        let state = run.inspect(&worker).await?;
        case.check(
            "typed call stays disposed with unknown outcome and choice remains in force",
            state["typed_calls"][0]["state"] == "disposed"
                && state["typed_calls"][0]["outcome"] == "unknown"
                && state["standing"]["fixture"]["continuation"] == continuation,
        );
        reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
        cases.push(case);
    }
    restore(run, tab, worker, &original).await
}
