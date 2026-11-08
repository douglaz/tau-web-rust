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
    run.put(
        tab,
        &reader::build_at("file.typed_cases.build.001", PASSPHRASE, events),
    )
    .await?;
    let mut worker = run.reload("typed_cases.rs::reload#1", tab, &worker).await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare(run, tab, &mut worker, PASSPHRASE).await?;
    Ok(worker)
}

pub(super) async fn run(
    run: &Run<'_>,
    tab: &Tab,
    mut worker: Worker,
    args: &dyn Fn(&str) -> Value,
    cases: &mut Vec<Case>,
) -> Result<Worker, String> {
    let _scenario_span = completion::scenario("typed_cases.run");
    let saved = store_files(&run.dump_at("file.typed_cases.dump.001", tab).await?);
    let events = reader::read_at("reader.call.typed.original", &saved, PASSPHRASE)?
        .records
        .iter()
        .map(|(_, p)| crate::journal::event(p).map_err(|e| e.to_string()))
        .collect::<Result<Vec<Value>, _>>()?;
    let original = events[..3].to_vec();
    let mut events = original.clone();
    let call = events.len() as u64;
    events.push(intent(call, "reset"));
    worker = restore(run, tab, worker, &events).await?;
    let mut case = Case::new(
        "typed_cases.c001",
        "typed reset bars commands before contact until durable confirmation",
    );
    fresh_pace(run.relay);
    take(run.seen);
    let before = run
        .inspect_state_at("state.typed.reset.before", &worker)
        .await?;
    let report = run
        .harness_run("typed_cases.rs#1", &worker, args("fixture"))
        .await?;
    run.sshd
        .all_ended_at(
            Some("typed.reset.connection_end"),
            json!({"ignored_result":true}),
        )
        .await;
    let seen = take(run.seen);
    case.check(
        "typed_cases.a001",
        "unresolved reset is named; no relay or SSH contact, no intent",
        crate::state_inputs::all!(
            report["outcome"]["refused"] == "barrier",
            report["outcome"]["calls"][0]["call"] == call,
            seen.relay_accepted == 0,
            seen.ssh_connections == 0,
            run.inspect_state_at("state.typed.reset.after", &worker)
                .await?
                .same_at("typed_cases.a001", &before, &[""])
        ),
    );
    events.push(json!({"operation_observation":{"resource":{"entry":"fixture"},"operation":"reset","reports":"confirmed","calls":[call]}}));
    worker = restore(run, tab, worker, &events).await?;
    fresh_pace(run.relay);
    take(run.seen);
    let report = run
        .harness_run("typed_cases.rs#2", &worker, args("fixture"))
        .await?;
    let seen = take(run.seen);
    case.check(
        "typed_cases.a002",
        "confirming observation permits command",
        report["outcome"]["done"] == true && exec_command_is(&seen, COMMAND),
    );
    reader::read_at(
        "reader.call.typed.reset_confirmed",
        &store_files(&run.dump_at("file.typed_cases.dump.002", tab).await?),
        PASSPHRASE,
    )?;
    case.finish(cases);

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
        let mut case = Case::new(
            "typed_cases.c002",
            &format!(
                "typed running-system disposition {continuation}: pinned attempt and collection stay permitted"
            ),
        );
        let destructive = ["destructive_reinstall", "abandonment"].contains(&continuation);
        for when in ["before collection", "after collection"] {
            fresh_pace(run.relay);
            take(run.seen);
            let report = run
                .harness_run("typed_cases.rs#3", &worker, args("fixture"))
                .await?;
            run.sshd
                .all_ended_at(
                    Some("typed.disposition.command_end"),
                    json!({"ignored_result":true,"phase":when}),
                )
                .await;
            let seen = take(run.seen);
            case.check("typed_cases.a003", &format!("{when}: run_command obeys continuation"),
                if destructive { report["outcome"]==json!({"refused":"disposition","disposition":disposition,"continuation":continuation}) && seen.relay_accepted==0 && seen.ssh_connections==0 }
                else { report["outcome"]["done"]==true && exec_command_is(&seen,COMMAND) });
            if when == "before collection" {
                fresh_pace(run.relay);
                take(run.seen);
                let before = run
                    .inspect_state_at("state.typed.collection.before", &worker)
                    .await?;
                let report = run
                    .harness_collect("typed_cases.rs#4", &worker, args("fixture"))
                    .await?;
                run.sshd
                    .all_ended_at(
                        Some("typed.disposition.collection_end"),
                        json!({"ignored_result":true,"phase":"before collection"}),
                    )
                    .await;
                let seen = take(run.seen);
                let after = run
                    .inspect_state_at("state.typed.collection.after", &worker)
                    .await?;
                case.check("typed_cases.a004",
"bare pinned attempt reaches relay and sshd, collects no jobs and appends no intent",
crate::state_inputs::all!(
report["outcome"]["collected"]==json!([]),
seen.relay_dials.len()==1,
seen.ssh_connections>0,
seen.ssh_exec.is_empty(),
after.same_at("typed_cases.a004", &before, &["/records", "/standing"])
));
            }
        }
        let state = run.inspect(&worker).await?;
        case.check(
            "typed_cases.a005",
            "typed call stays disposed with unknown outcome and choice remains in force",
            state["typed_calls"][0]["state"] == "disposed"
                && state["typed_calls"][0]["outcome"] == "unknown"
                && state["standing"]["fixture"]["continuation"] == continuation,
        );
        reader::read_at(
            "reader.call.typed.disposition_confirmed",
            &store_files(&run.dump_at("file.typed_cases.dump.003", tab).await?),
            PASSPHRASE,
        )?;
        case.finish(cases);
    }
    restore(run, tab, worker, &original).await
}
