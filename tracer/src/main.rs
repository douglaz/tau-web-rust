//! The tracer (twr-ggw.2): one recorded command over a pinned SSH connection through a relay
//! fixture, run by the harness worker in headless Chrome, with each case asserted on what the
//! fixtures observed. Also the served build's checks.
//!
//! ```text
//! tracer run <served-dir> <tracer-dir>   the tracer; Chrome from $CHROME, which must be set
//! tracer check-absence <dir>             AC5: no test key, pin source, journal or test switch
//! tracer check-csp <dir>                 AC6: the page's policy is exactly ARC-33's
//! ```
//!
//! `scripts/tracer.sh` builds both directories and runs the first.

mod cdp;
mod checks;
mod fixtures;
mod keys;

use fixtures::{Observed, Seen};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tau_web::testonly::{PINS, SSH_USER};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["check-absence", dir] => checks::absence(Path::new(dir)),
        ["check-csp", dir] => checks::csp(Path::new(dir)),
        ["run", served, tracer] => run(Path::new(served), Path::new(tracer)).await,
        _ => Err(
            "usage: tracer run <served-dir> <tracer-dir> | check-absence <dir> | check-csp <dir>"
                .into(),
        ),
    };
    if let Err(e) = result {
        eprintln!("FAIL: {e}");
        std::process::exit(1);
    }
}

/// The command case 1 records and sends, with quoting and a non-ASCII byte sequence, so "byte
/// for byte" bites. The fixture sshd runs nothing: it answers these exact bytes with the output
/// below, both streams and a non-zero exit, and anything else with a failure, so "output and
/// exit status" bites too.
const COMMAND: &str =
    "printf '%s\\n' 'tau-web tracer — recorded, then sent'; echo 'to stderr' >&2; exit 7";
const STDOUT: &str = "tau-web tracer — recorded, then sent\n";
const STDERR: &str = "to stderr\n";
const EXIT_STATUS: u32 = 7;

/// One case's verdict: the assertions that failed, empty when it passed.
struct Case {
    name: &'static str,
    failures: Vec<String>,
}

impl Case {
    fn new(name: &'static str) -> Case {
        println!("\n== {name}");
        Case {
            name,
            failures: Vec::new(),
        }
    }

    fn check(&mut self, what: &str, holds: bool) {
        println!("   [{}] {what}", if holds { "ok" } else { "FAILED" });
        if !holds {
            self.failures.push(what.to_string());
        }
    }
}

async fn run(served: &Path, tracer: &Path) -> Result<(), String> {
    let chrome = std::env::var("CHROME").map_err(|_| {
        "CHROME is not set: the tracer needs a Chrome or Chromium binary and never skips"
            .to_string()
    })?;
    let served_page = served.join("index.html");
    let served_policy = checks::page_policy(
        &std::fs::read_to_string(&served_page)
            .map_err(|e| format!("{}: {e}", served_page.display()))?,
    )?;

    let seen = Observed::default();
    let tls = fixtures::tls();
    let sshd = fixtures::sshd(
        seen.clone(),
        fixtures::Answer {
            command: COMMAND,
            stdout: STDOUT,
            stderr: STDERR,
            exit_status: EXIT_STATUS,
        },
    )
    .await;
    let relay = fixtures::relay(
        seen.clone(),
        tls.acceptor.clone(),
        vec![("127.0.0.1".into(), sshd.port)],
    )
    .await;
    let served_origin = fixtures::https(
        served.to_path_buf(),
        tls.acceptor.clone(),
        Some(served_policy.clone()),
    )
    .await;
    let tracer_origin = fixtures::https(
        tracer.to_path_buf(),
        tls.acceptor.clone(),
        Some(served_policy.clone()),
    )
    .await;
    println!(
        "fixture sshd 127.0.0.1:{}, relay fixture {}",
        sshd.port, relay.url
    );
    println!("served build at {served_origin}, tracer build at {tracer_origin}");

    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"));
    std::fs::create_dir_all(&target).map_err(|e| format!("{}: {e}", target.display()))?;
    let profile = target.join(format!("tracer-chrome-{}", std::process::id()));
    let browser = cdp::Browser::launch(&chrome, profile, &tls.spki_sha256).await?;
    let outcome = cases(
        &browser,
        &seen,
        &sshd,
        &relay.url,
        &served_origin,
        &tracer_origin,
        &served_policy,
    )
    .await;
    browser.close().await;

    let cases = outcome?;
    println!("\n== summary");
    for case in &cases {
        match case.failures.as_slice() {
            [] => println!("   PASS {}", case.name),
            failures => println!("   FAIL {}: {}", case.name, failures.join("; ")),
        }
    }
    let failed: Vec<_> = cases
        .iter()
        .filter(|c| !c.failures.is_empty())
        .map(|c| c.name)
        .collect();
    if failed.is_empty() {
        println!("TRACER PASS");
        Ok(())
    } else {
        Err(format!("tracer cases failed: {}", failed.join(", ")))
    }
}

/// What the fixtures observed since the last call, which starts the next case from nothing.
fn take(seen: &Observed) -> Seen {
    std::mem::take(&mut *seen.lock().expect("observations lock"))
}

fn show(seen: &Seen) {
    println!("   fixtures observed: {seen:?}");
}

/// Opens `url` in a new page and waits for its harness worker to report ready; the page's
/// session and the worker's.
async fn open(browser: &cdp::Browser, url: &str) -> Result<(String, String), String> {
    let from = browser.event_count();
    let page = browser
        .call(None, "Target.createTarget", json!({ "url": "about:blank" }))
        .await?;
    let attached = browser
        .call(
            None,
            "Target.attachToTarget",
            json!({ "targetId": page["targetId"], "flatten": true }),
        )
        .await?;
    let session = attached["sessionId"]
        .as_str()
        .ok_or("no page session")?
        .to_string();
    for method in ["Page.enable", "Runtime.enable", "Log.enable"] {
        browser.call(Some(&session), method, json!({})).await?;
    }
    browser
        .call(
            Some(&session),
            "Target.setAutoAttach",
            json!({ "autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true }),
        )
        .await?;
    browser
        .call(Some(&session), "Page.navigate", json!({ "url": url }))
        .await?;
    let worker = browser
        .wait_for(from, 30, |e| {
            e["method"] == "Target.attachedToTarget"
                && e["sessionId"] == session.as_str()
                && e["params"]["targetInfo"]["type"] == "worker"
        })
        .await
        .ok_or_else(|| format!("{url}: no harness worker started in 30 s"))?;
    let worker = worker["params"]["sessionId"]
        .as_str()
        .ok_or("no worker session")?
        .to_string();
    browser
        .call(Some(&worker), "Runtime.enable", json!({}))
        .await?;
    for _ in 0..300 {
        let state = browser
            .evaluate(
                &session,
                "document.getElementById('status')?.dataset.state ?? ''",
            )
            .await?;
        match state.as_str() {
            Some("ready") => return Ok((session, worker)),
            Some("failed") => {
                let status = browser
                    .evaluate(&session, "document.getElementById('status').textContent")
                    .await?;
                return Err(format!("{url}: {status}"));
            }
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    Err(format!(
        "{url}: the harness worker did not report ready in 30 s"
    ))
}

/// Errors the page or its worker reported: exceptions, `console.error`, and log entries.
fn errors_since(browser: &cdp::Browser, from: usize, sessions: &[&str]) -> Vec<String> {
    browser.events.lock().expect("events lock")[from..]
        .iter()
        .filter(|e| sessions.iter().any(|s| e["sessionId"] == *s))
        .filter_map(|e| match e["method"].as_str()? {
            "Runtime.exceptionThrown" => Some(e["params"]["exceptionDetails"].to_string()),
            "Runtime.consoleAPICalled" if e["params"]["type"] == "error" => {
                Some(e["params"]["args"].to_string())
            }
            "Log.entryAdded" if e["params"]["entry"]["level"] == "error" => {
                Some(e["params"]["entry"]["text"].to_string())
            }
            _ => None,
        })
        .collect()
}

/// Has the harness worker run one command, and returns its report. The page offers no way to:
/// this evaluates in the worker's own context, over its DevTools session, and calls `run_command`
/// on the module the worker already loaded (the same URL, so the same initialized module).
async fn harness_run(browser: &cdp::Browser, worker: &str, args: Value) -> Result<Value, String> {
    let request = serde_json::to_string(&args.to_string()).expect("a JSON string");
    let report = browser
        .evaluate(
            worker,
            &format!(
                "(async () => {{
                    const module = await import(new URL('./pkg/tau_web.js', self.location.href).href);
                    return JSON.parse(await module.run_command({request}));
                }})()"
            ),
        )
        .await?;
    println!("   harness reported: {report}");
    Ok(report)
}

async fn cases(
    browser: &cdp::Browser,
    seen: &Observed,
    sshd: &fixtures::Sshd,
    relay: &str,
    served_origin: &str,
    tracer_origin: &str,
    served_policy: &str,
) -> Result<Vec<Case>, String> {
    let mut cases = Vec::new();
    let pinned = PINS
        .iter()
        .find(|(machine, _)| *machine == "fixture")
        .map(|(_, pin)| pin.to_string())
        .expect("the pin source pins `fixture`");
    let args = |machine: &str| {
        json!({
            "machine": machine,
            "relay": relay,
            "host": "127.0.0.1",
            "port": sshd.port,
            "user": SSH_USER,
            "command": COMMAND,
            "fail_append": false,
            "tamper_auth": false,
        })
    };

    // The served build loads, and its harness worker runs a request on what it has stored: nothing.
    let mut case =
        Case::new("the served build loads, and holds no pin, key, journal or request hook");
    let from = browser.event_count();
    let (page, worker) = open(browser, &format!("{served_origin}/")).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let errors = errors_since(browser, from, &[&page, &worker]);
    println!("   errors reported: {errors:?}");
    case.check("the harness worker reported ready", true);
    case.check(
        "the page and its worker reported no error",
        errors.is_empty(),
    );
    let globals = browser
        .evaluate(
            &page,
            "({ tauWeb: typeof window.tauWeb,
                workers: Object.getOwnPropertyNames(window).filter(name => {
                    try { return window[name] instanceof Worker; } catch { return false; }
                }) })",
        )
        .await?;
    println!("   page globals: {globals}");
    case.check(
        "the page defines no request hook: typeof window.tauWeb is \"undefined\", and no global holds the worker",
        globals == json!({ "tauWeb": "undefined", "workers": [] }),
    );
    take(seen);
    let report = harness_run(browser, &worker, args("fixture")).await?;
    let observed = take(seen);
    show(&observed);
    case.check(
        "called in its worker on the machine the tracer build pins, the served harness refused for the missing pin (CHN-R4)",
        report == json!({ "outcome": { "refused": "no-pin" } }),
    );
    case.check(
        "the relay fixture accepted no TCP connection, and the sshd saw none",
        observed.relay_accepted == 0 && observed.ssh_connections == 0,
    );
    cases.push(case);

    let (page, worker) = open(browser, &format!("{tracer_origin}/")).await?;

    // Case 4 (AC6): the policy Chrome loaded is the served page's, and it is enforced.
    let mut case = Case::new("4. the page runs under ARC-33's policy (AC6)");
    let loaded = browser
        .evaluate(
            &page,
            "Array.from(document.querySelectorAll('meta[http-equiv=\"Content-Security-Policy\" i]'), m => m.content)",
        )
        .await?;
    println!("   policy in the loaded page: {loaded}");
    println!("   policy in the served page: {served_policy}");
    let tokens = |policy: &str| {
        policy
            .split_ascii_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    case.check(
        "the loaded page carries the served page's policy, token for token",
        loaded.as_array().is_some_and(|policies| {
            policies.len() == 1
                && tokens(policies[0].as_str().unwrap_or_default()) == tokens(served_policy)
        }),
    );
    let probe = browser
        .evaluate(
            &page,
            "new Promise(resolve => {
                const violations = [];
                document.addEventListener('securitypolicyviolation', e =>
                    violations.push({ directive: e.effectiveDirective, disposition: e.disposition }));
                const script = document.createElement('script');
                script.textContent = 'window.tracerInlineRan = true;';
                document.head.append(script);
                setTimeout(() => resolve({ ran: window.tracerInlineRan === true, violations }), 500);
            })",
        )
        .await?;
    println!("   page, inline script injected: {probe}");
    case.check(
        "the injected inline script did not run",
        probe["ran"] == false,
    );
    case.check(
        "it raised an enforced script-src violation",
        probe["violations"].as_array().is_some_and(|v| {
            v.iter().any(|v| {
                v["directive"]
                    .as_str()
                    .is_some_and(|d| d.starts_with("script-src"))
                    && v["disposition"] == "enforce"
            })
        }),
    );
    // A `ws:` socket is outside `connect-src https: wss:`: Chrome refuses it with a connect-src
    // violation, in the page under its meta policy and in the worker under its response's.
    let socket_probe = "new Promise(resolve => {
        const violations = [];
        (self.document ?? self).addEventListener('securitypolicyviolation', e =>
            violations.push({ directive: e.effectiveDirective, blocked: e.blockedURI, disposition: e.disposition }));
        let opened = false;
        try {
            const socket = new WebSocket('ws://127.0.0.1:9/');
            socket.onopen = () => { opened = true; };
        } catch (e) {
            violations.push({ thrown: e.name });
        }
        setTimeout(() => resolve({ opened, violations }), 1000);
    })";
    let refused = |probe: &Value| {
        probe["opened"] == false
            && probe["violations"].as_array().is_some_and(|v| {
                v.iter()
                    .any(|v| v["directive"] == "connect-src" && v["disposition"] == "enforce")
            })
    };
    let page_ws = browser.evaluate(&page, socket_probe).await?;
    let worker_ws = browser.evaluate(&worker, socket_probe).await?;
    println!("   page, a ws: socket opened: {page_ws}");
    println!("   worker, a ws: socket opened: {worker_ws}");
    case.check("connect-src refuses ws: in the page", refused(&page_ws));
    case.check(
        "connect-src refuses ws: in the worker, under its response's policy",
        refused(&worker_ws),
    );
    let case_4 = cases.len();
    cases.push(case);

    // Case 3 (AC3): no pin, no contact.
    let mut case = Case::new("3. a machine with no pin is refused before any contact (AC3)");
    take(seen);
    let report = harness_run(browser, &worker, args("unpinned")).await?;
    let observed = take(seen);
    show(&observed);
    case.check(
        "the harness refused for the missing pin",
        report["outcome"]["refused"] == "no-pin",
    );
    case.check(
        "the relay fixture accepted no TCP connection",
        observed.relay_accepted == 0,
    );
    case.check(
        "the relay fixture dialed nothing",
        observed.relay_dials.is_empty(),
    );
    case.check(
        "the fixture sshd saw no connection",
        observed.ssh_connections == 0,
    );
    case.check(
        "nothing is pinned afterwards",
        report["pinned_after"].is_null(),
    );
    case.check(
        "nothing was journaled",
        report["journal_entries"] == json!([]),
    );
    cases.push(case);

    // Case 5: the relay fixture's AUTH check is real.
    let mut case = Case::new("5. a wrongly signed AUTH is refused, and nothing is dialed");
    let mut tampered = args("fixture");
    tampered["tamper_auth"] = true.into();
    let report = harness_run(browser, &worker, tampered).await?;
    let observed = take(seen);
    show(&observed);
    let one_connection = |observed: &Seen| {
        observed.relay_accepted == 1
            && observed.relay_connections == [format!("/v1/tcp/127.0.0.1/{}", sshd.port)]
    };
    case.check(
        "the relay fixture accepted exactly one connection, upgraded on the sshd's path",
        one_connection(&observed),
    );
    case.check(
        "the harness got {\"ok\": false, \"reason\": \"auth\"} and close 1008",
        report["outcome"] == json!({ "refused": "relay", "reason": "auth", "close_code": 1008 }),
    );
    case.check(
        "the relay fixture refused at check 2 of WIR-6 (paid-tcp-relay 844e834), with close 1008",
        observed.relay_refusals == [("auth".into(), "2 signature".into(), 1008)],
    );
    case.check(
        "the relay fixture dialed nothing",
        observed.relay_dials.is_empty(),
    );
    case.check(
        "the fixture sshd saw no connection",
        observed.ssh_connections == 0,
    );
    cases.push(case);

    // Case 1 (AC1): recorded, then sent; and it reconciles.
    let mut case = Case::new("1. the command is recorded, then sent, and reconciles (AC1)");
    let report = harness_run(browser, &worker, args("fixture")).await?;
    let observed = take(seen);
    show(&observed);
    let outcome = &report["outcome"];
    let recorded = outcome["recorded"]
        .as_str()
        .and_then(|h| hex::decode(h).ok())
        .unwrap_or_default();
    case.check("the harness completed the command", outcome["done"] == true);
    case.check(
        "the relay fixture accepted one connection, checked the AUTH, dialed the sshd once, refused nothing",
        one_connection(&observed)
            && observed.relay_dials == [format!("127.0.0.1:{}", sshd.port)]
            && observed.relay_refusals.is_empty(),
    );
    case.check(
        "the fixture sshd admitted the test client key",
        observed
            .ssh_auth
            .iter()
            .any(|(user, _, admitted)| user == "tracer" && *admitted),
    );
    case.check(
        "the fixture sshd received exactly the journal entry, byte for byte",
        observed.ssh_exec == [recorded.clone()],
    );
    case.check(
        "the journal entry is the command",
        recorded == COMMAND.as_bytes(),
    );
    case.check(
        "the harness's read-back matches what it sent",
        outcome["sent"] == outcome["recorded"] && outcome["recorded_machine"] == "fixture",
    );
    case.check(
        "the journal holds that one entry",
        report["journal_entries"] == json!([hex::encode(COMMAND)]),
    );
    case.check(
        "the output and exit status came back",
        outcome["stdout"] == STDOUT
            && outcome["stderr"] == STDERR
            && outcome["exit_status"] == EXIT_STATUS
            && observed.ssh_exit == [EXIT_STATUS],
    );
    case.check(
        "one exec on a channel: no pty, shell or subsystem (ARC-7)",
        observed.ssh_other_requests.is_empty(),
    );
    case.check(
        "the host key presented was the pin",
        outcome["host_key"] == pinned.as_str(),
    );

    // ... and with the journal's append made to fail, nothing is sent.
    let mut failing = args("fixture");
    failing["fail_append"] = true.into();
    let report = harness_run(browser, &worker, failing).await?;
    // Every byte the harness sent before it closed has reached the sshd once the connection has
    // ended there, so an exec sent before the append cannot still be in flight.
    let ended = sshd.all_ended().await;
    let observed = take(seen);
    show(&observed);
    case.check(
        "a failed append: the sshd connection ended before its observations were read",
        ended,
    );
    case.check(
        "a failed append: the harness reports the refusal",
        report["outcome"]["refused"] == "journal",
    );
    case.check(
        "a failed append: the sshd admitted the client and received no exec request",
        observed.ssh_auth.iter().any(|(_, _, admitted)| *admitted) && observed.ssh_exec.is_empty(),
    );
    case.check(
        "a failed append: nothing was journaled",
        report["journal_entries"] == json!([]),
    );
    cases.push(case);
    let case_1_in_this_session = cases.len() - 1;

    // Case 2 (AC2): a host key other than the pin halts, before authentication, once.
    let mut case = Case::new("2. a host key other than the pin halts the connection (AC2)");
    sshd.present_other.store(true, Ordering::SeqCst);
    let report = harness_run(browser, &worker, args("fixture")).await?;
    tokio::time::sleep(Duration::from_secs(2)).await; // room for a reconnect, which must not come
    sshd.present_other.store(false, Ordering::SeqCst);
    let observed = take(seen);
    show(&observed);
    let other = keys::fingerprint(&keys::HOST_KEY_OTHER);
    case.check(
        "the harness halted in the key check, naming both fingerprints",
        report["outcome"] == json!({ "refused": "host-key", "pinned": pinned, "presented": other }),
    );
    case.check(
        "the fixture sshd saw no authentication attempt and no exec",
        observed.ssh_auth.is_empty() && observed.ssh_exec.is_empty(),
    );
    case.check(
        "nothing was journaled",
        report["journal_entries"] == json!([]),
    );
    case.check(
        "exactly one connection: no automatic reconnect (ARC-41)",
        one_connection(&observed)
            && observed.relay_dials.len() == 1
            && observed.ssh_connections == 1,
    );
    cases.push(case);

    let both =
        cases[case_4].failures.is_empty() && cases[case_1_in_this_session].failures.is_empty();
    println!(
        "\ncase 4 and case 1 in the same browser session: {}",
        if both {
            "both passed"
        } else {
            "not both passed"
        }
    );
    Ok(cases)
}
