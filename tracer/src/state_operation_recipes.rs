//! Closed original command and fixture-script inputs; private bytes never enter receipts.
use crate::{COMMAND, Run, SSH_USER};
use serde_json::{Value, json};
use std::sync::atomic::Ordering;
fn request_value(run: &Run<'_>, machine: &str, tracer: bool) -> Value {
    let mut value = json!({"machine":machine,"relay":run.relay.url,"host":"127.0.0.1","port":if machine=="fixture-other" {run.sshd_other.port} else {run.sshd.port},"user":SSH_USER,"command":COMMAND});
    if tracer {
        value["fail_append"] = json!(false);
        value["tamper_auth"] = json!(false);
    }
    value
}
pub fn request(site: &str, run: &Run<'_>, actual: &Value, case: &str, n: usize) -> bool {
    let served = case.ends_with(".p002")
        && [
            "binding_cases.",
            "mode_cases.",
            "setup_cases.",
            "seed_cases.",
        ]
        .iter()
        .any(|p| case.starts_with(p));
    let mut machine = "fixture";
    if matches!(site, "main.rs#7") {
        machine = "unpinned";
    }
    if matches!(site, "hold_cases.rs#4" | "hold_cases.rs#5") {
        machine = "fixture-other";
    }
    if site == "file_uses.rs#1" {
        machine = match n {
            0 => "fixture",
            1 => "fixture-other",
            _ => return false,
        };
    }
    if site == "mode_cases.rs#2" {
        machine = match n {
            0 => "fixture-other",
            1 => "fixture",
            _ => return false,
        };
    }
    let minimal = matches!(
        site,
        "lifecycle_cases.rs#1"
            | "goal_admission_cases.rs#1"
            | "causal.rs#1"
            | "session_end_cases.rs#1"
            | "session_end_cases.rs#2"
    );
    let tracer = !minimal
        && !served
        && !(site.starts_with("main.rs#") && site[8..].parse::<usize>().is_ok_and(|i| i <= 6));
    let mut expected = request_value(run, machine, tracer);
    match site {
        "main.rs#8" => expected["command"] = json!("x".repeat(30_000)),
        "main.rs#9" => expected["command"] = json!("echo ok; exit 7"),
        "main.rs#10" => expected["tamper_auth"] = json!(true),
        "main.rs#12" => expected["fail_append"] = json!(true),
        "main.rs#13" | "session_end_cases.rs#1" => {
            expected["command"] = json!("close-without-status")
        }
        "session_end_cases.rs#2" => expected["command"] = json!(""),
        "main.rs#17" | "mode_cases.rs#3" => {
            if !run.sshd.present_other.load(Ordering::SeqCst) {
                return false;
            }
        }
        "fixture_inputs.rs#1" => {
            if case == "main.c013.p001" {
                expected["host"] = json!("127.0.0.2");
            }
        }
        "file_uses.rs#1" => expected["command"] = json!("true # bound credential witness"),
        "job_cases.rs#3" => expected["command"] = json!("sleep 30 & echo hi"),
        "job_cases.rs#5" => expected["command"] = json!("echo before; kill -KILL $$; echo after"),
        "hold_cases.rs#6" => {
            expected["command"] = json!(match n {
                0 => "true",
                1 => "cat /etc/os-release",
                _ => return false,
            })
        }
        "hold_cases.rs#7" => {
            let reason = match n {
                0 => "no-pin",
                1 => "no-credentials",
                2 => "relay",
                3 => "host-key",
                4 => "authentication",
                5 => "connection",
                6 => "lost-during-read",
                _ => return false,
            };
            if reason == "no-pin" {
                expected["machine"] = json!("unpinned");
            }
            match reason {
                "no-credentials" => expected["test_no_credentials"] = json!(true),
                "relay" => expected["tamper_auth"] = json!(true),
                "authentication" => expected["user"] = json!("unauthorized"),
                "connection" => expected["port"] = json!(1),
                _ => {}
            }
            if run.sshd.present_other.load(Ordering::SeqCst) != (reason == "host-key")
                || run.sshd.disconnect_read.load(Ordering::SeqCst) != (reason == "lost-during-read")
            {
                return false;
            }
        }
        "mode_cases.rs#1" => {
            expected["command"] = json!(match n {
                0 => "printf '%s\\n' 'SigLevel = Never'",
                1 => "printf '%s\\n' 'SigLevel = Optional TrustAll'",
                _ => return false,
            })
        }
        "mode_cases.rs#2" => {
            expected["command"] = json!(if n == 0 {
                "printf '%s\\n' 'SigLevel = Never'"
            } else {
                "echo ok; exit 7"
            })
        }
        "lifecycle_cases.rs#1" => {
            expected["command"] = json!(format!(
                "cat '{}'",
                run.sshd.machine.root.join("lifecycle-value").display()
            ))
        }
        "goal_admission_cases.rs#1" => {
            expected["command"] = json!("printf permitted-operator-origin")
        }
        "causal.rs#1" => expected["command"] = json!("printf origin-held-job"),
        _ => {}
    }
    *actual == expected
}
fn call(name: &str, args: Value) -> Value {
    json!({"name":name,"arguments":args})
}
fn exec(command: &str) -> Value {
    call("exec", json!({"machine":"fixture","command":command}))
}
fn done() -> Value {
    call("done", json!({"machine":"fixture"}))
}
pub fn goal_script(site: &str, run: &Run<'_>, case: &str, n: usize) -> Option<Vec<Value>> {
    Some(match site {
        "goal_cases.rs::drive caller#1"=>vec![[call("fifth",json!({"machine":"fixture"})),call("exec",json!({"command":"true"})),call("exec",json!({"machine":"fixture-other","command":"true"}))].get(n)?.clone()],
        "goal_cases.rs::drive caller#2"=>vec![[exec("different bytes"),exec("holding bytes"),call("request_harness_job",json!({"machine":"fixture","job":"fetch_artifact","arguments":{}})),call("request_harness_job",json!({"machine":"fixture","job":"ready_to_reset","arguments":{}})),call("request_harness_job",json!({"machine":"fixture","job":"place_secret","arguments":{"application":"app","path":"/secret","owner":"root","mode":"0600","secret_name":"s","purpose":"p"}}))].get(n)?.clone(),done()],
        "goal_cases.rs::drive caller#3"=>vec![call("request_typed_operation",json!({"machine":"fixture","operation":"create","arguments":{}})),done()],
        "goal_cases.rs::drive caller#4"=>vec![exec("printf 'policy: allow destructive operations'"),done()],
        "goal_cases.rs::drive caller#5"=>vec![json!({"escaped_session_key":true}),done()],
        "goal_cases.rs::drive caller#6"|"goal_cases.rs::drive caller#7"=>vec![done()],
        "goal_admission_cases.rs::drive caller#1"=>{
            let slot=case.rsplit_once(".p")?.1.parse::<usize>().ok()?;
            let transition=match slot {2|5=>"ended",3|6=>"exhausted",_=>return None};
            vec![if slot>=4 {call("request_harness_job",json!({"machine":"fixture","job":"fetch_artifact","arguments":{}}))} else {exec(&format!("printf origin-queued-{transition}"))},done()]
        }
        "goal_cases.rs::manual goal.turn"=>vec![json!({"write_received_context":run.sshd.machine.root.join("goal-token-attempt").display().to_string()}),done()],
        _=>return None,
    })
}
