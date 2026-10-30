//! Originating-session admission after a real queued writer, through SessionDriver.
use super::*;

fn target(run: &Run<'_>, command: &str) -> Value {
    json!({"machine":"fixture","relay":run.relay.url,"host":"127.0.0.1",
        "port":run.sshd.port,"user":SSH_USER,"command":command})
}

async fn holding_job(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
) -> Result<(Vec<Value>, u64, String), String> {
    reset(run, tab, worker, &base()).await?;
    let result = run
        .harness_run(worker, target(run, "printf origin-held-job"))
        .await?;
    if result["outcome"]["done"] != true {
        return Err(format!("origin collection prerequisite: {result}"));
    }
    let state = run.inspect(worker).await?;
    let intent = &state["calls"]
        .as_array()
        .ok_or("calls")?
        .last()
        .ok_or("call")?;
    let call = intent["call"].as_u64().ok_or("call identity")?;
    let job = intent["job"].as_str().ok_or("job identity")?.to_string();
    job_cases::wait_end(run, &job).await?;
    let opened = reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
    let mut events = Vec::new();
    let mut removed = false;
    for (_, bytes) in opened.records {
        let event: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if event["job_terminal"]["call"] == call {
            removed = true;
            break;
        }
        events.push(event);
    }
    if !removed {
        return Err("completed real job has no terminal to withhold".into());
    }
    Ok((events, call, job))
}

async fn prepare_goal(run: &Run<'_>, worker: &Worker, session: &str) -> Result<(), String> {
    let report = goal(run, worker, session, None).await?;
    if report.get("error").is_some() {
        return Err(format!("origin goal prerequisite: {report}"));
    }
    let report = accept(run, worker, session).await?;
    if report.get("error").is_some() {
        return Err(format!("origin goal acceptance prerequisite: {report}"));
    }
    Ok(())
}

fn tool_result(requests: &[Value]) -> Value {
    requests.last().map(context).unwrap_or(Value::Null)["history"][0]["result"]["content"].clone()
}

fn provenance(state: &Value, command: &str, session: &str) -> bool {
    state["calls"].as_array().is_some_and(|calls| {
        calls
            .iter()
            .any(|c| c["command"] == hex::encode(command) && c["provenance"]["session"] == session)
    })
}

pub(super) async fn run(
    run: &Run<'_>,
    tab: &Tab,
    worker: &mut Worker,
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let initial = base();
    let (holding, holding_call, holding_id) = holding_job(run, tab, worker).await?;
    for job in [false, true] {
        for transition in ["eligible", "ended", "exhausted"] {
            let session = reset(run, tab, worker, if job { &holding } else { &initial }).await?;
            if module(run, worker, "return m.test_confirm_inference();").await? != true {
                return Err("origin fixture confirmation missing".into());
            }
            prepare_goal(run, worker, &session).await?;
            let command = format!("printf origin-queued-{transition}");
            let request = if job {
                call(
                    "request_harness_job",
                    json!({"machine":"fixture","job":"fetch_artifact","arguments":{}}),
                )
            } else {
                exec(&command)
            };
            run.aggregator.state.lock().unwrap().script = vec![request.clone(), done()].into();
            module(run, worker, "self.originReady=new Promise(ready=>m.test_hold_session_point('connection_writer',new Promise(release=>self.releaseOrigin=release),ready));self.originQueued=new Promise(ready=>m.test_hold_session_point('connection_queued',Promise.resolve(),ready));return true;").await?;
            let from = run.aggregator.requests.lock().unwrap().len();
            module(
                run,
                worker,
                &format!(
                    "self.originGoal=m.run_goal({});await Promise.race([self.originReady,self.originGoal.then(result=>{{throw new Error('goal ended before connection admission: '+result)}})]);return true;",
                    json!(session)
                ),
            )
            .await?;
            module(run, worker, &format!("self.rebindReady=new Promise(ready=>self.rebindWork=m.test_writer_rebind({},{},new Promise(release=>self.releaseRebind=release),ready));await self.rebindReady;self.releaseOrigin();await self.originQueued;return true;",json!(session),json!(transition))).await?;
            take(run.seen);
            fresh_pace(run.relay);
            let binding = module(
                run,
                worker,
                "self.releaseRebind();return JSON.parse(await self.rebindWork);",
            )
            .await?;
            let current = binding["current"]
                .as_str()
                .ok_or("current session")?
                .to_string();
            let mut case = Case::new(&format!(
                "goal {} queued admission preserves originating runtime session: {transition}",
                if job { "job" } else { "exec" }
            ));
            println!(
                "   original={session} current={current} requested={request} holding_call={holding_call} holding_job={holding_id}"
            );
            case.check("actual SessionDriver reached admission before the writer transition; lock poll was pending", binding["original"] == session);
            case.check("writer retained the eligible object or ended it and bound a distinct live successor before admission resumed",
                if transition == "eligible" { current == session && binding["same_object"] == true && binding["ended"] == false }
                else { current != session && binding["same_object"] == false && binding["ended"] == true });
            let before = binding["before"].clone();
            if job {
                case.check("real original job is locally unresolved and remotely complete before admission",
                    before["jobs"].as_array().is_some_and(Vec::is_empty)
                        && run.sshd.machine.observe().get(&holding_id).is_some_and(|j| j.ended.is_some()));
            }
            let outcome = module(run, worker, "return JSON.parse(await self.originGoal);").await?;
            let observed = take(run.seen);
            let after = run.inspect(worker).await?;
            println!(
                "   outcome={outcome} tool_result={}",
                tool_result(&bodies(run, from))
            );
            if transition == "eligible" {
                case.check(
                    "unchanged eligible original completes its real goal loop",
                    outcome["done"] == true,
                );
                if job {
                    let result = tool_result(&bodies(run, from));
                    case.check("eligible original collects the real holding job once with its original identity and output",
                        result["held"] == true && result["calls"][0]["call"] == holding_call
                            && result["calls"][0]["job"] == holding_id
                            && result["calls"][0]["state"] == "finished"
                            && result["calls"][0]["stdout"] == "origin-held-job"
                            && observed.ssh_exec.len() == 1 && job_cases::only_reads(&observed)
                            && before["commands"] == after["commands"]
                            && after["jobs"].as_array().is_some_and(|jobs| jobs.iter().any(|j| j["call"] == holding_call)));
                } else {
                    case.check("eligible original executes the exact command and records its originating session",
                        tool_result(&bodies(run, from))["stdout"] == format!("origin-queued-{transition}")
                            && observed.ssh_exec.len() == 1 && provenance(&after, &command, &session));
                }
            } else {
                println!(
                    "   admission observations: relay={} ssh={} operations={:?} commands_before={} commands_after={} jobs_before={} jobs_after={}",
                    observed.relay_accepted,
                    observed.ssh_connections,
                    observed
                        .ssh_exec
                        .iter()
                        .map(|b| String::from_utf8_lossy(b)
                            .lines()
                            .next()
                            .unwrap_or_default()
                            .to_string())
                        .collect::<Vec<_>>(),
                    before["commands"],
                    after["commands"],
                    before["jobs"],
                    after["jobs"]
                );
                case.check(&format!("ended original {session} must not contact the relay or SSH under successor {current}: {request}"),
                    observed.relay_accepted == 0 && observed.relay_dials.is_empty()
                        && observed.ssh_connections == 0 && observed.ssh_exec.is_empty());
                case.check(&format!("stale {} from {session} must not append intent, command, refusal or job evidence under {current}", if job { "job collection" } else { "command" }),
                    ["calls", "commands", "jobs", "terminals", "connection_refusals", "signature_refusals"]
                        .iter().all(|field| before[*field] == after[*field]));
                let record_count = before["records"]
                    .as_array()
                    .ok_or("baseline records")?
                    .len();
                let opened = reader::read(&store_files(&run.dump(tab).await?), PASSPHRASE)?;
                case.check("independent journal reader sees only permitted inference cleanup after end, with no stale-tool append",
                    opened.records.iter().skip(record_count).all(|(_, bytes)| {
                        serde_json::from_slice::<Value>(bytes).is_ok_and(|event| {
                            event.get("inference_intent").is_some() || event.get("inference_terminal").is_some()
                        })
                    }));
                case.check(
                    "ended goal returns refusal instead of continuing",
                    outcome.get("refused").is_some() && outcome["done"] != true,
                );

                if !case.failures.is_empty() {
                    cases.push(case);
                    continue;
                }

                // The independently admitted successor uses its own ordinary goal route.
                module(run, worker, "return m.test_confirm_inference();").await?;
                prepare_goal(run, worker, &current).await?;
                fresh_pace(run.relay);
                let from = run.aggregator.requests.lock().unwrap().len();
                let outcome = drive(run, worker, &current, vec![request.clone(), done()]).await?;
                let result = tool_result(&bodies(run, from));
                let observed = take(run.seen);
                case.check("independently admitted successor completes useful work through its own SessionDriver", outcome["done"] == true && if job {
                    result["calls"][0]["call"] == holding_call && result["calls"][0]["job"] == holding_id && result["calls"][0]["stdout"] == "origin-held-job"
                        && observed.ssh_exec.len() == 1 && job_cases::only_reads(&observed)
                } else {
                    result["stdout"] == format!("origin-queued-{transition}")
                        && provenance(&run.inspect(worker).await?, &command, &current)
                });
            }
            fresh_pace(run.relay);
            let operator_command = "printf permitted-operator-origin";
            let operator = run
                .harness_run(worker, target(run, operator_command))
                .await?;
            case.check(
                "permitted machine-selected operator dispatch retains the current eligible session",
                operator["outcome"]["done"] == true
                    && operator["outcome"]["stdout"] == "permitted-operator-origin"
                    && provenance(&run.inspect(worker).await?, operator_command, &current),
            );
            cases.push(case);
        }
    }
    Ok(())
}
