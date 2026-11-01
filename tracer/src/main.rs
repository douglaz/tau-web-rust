//! The tracer (twr-ggw.2): one recorded command over a pinned SSH connection through a relay
//! fixture, run by the harness worker in headless Chrome, with each case asserted on what the
//! fixtures observed; with the relay refusals a correct client meets (twr-ggw.3); and the local
//! store (twr-ggw.5): create and unlock, fail closed, append before apply, lock, one writer,
//! persistent storage and no plaintext, asserted on what the browser holds and the fixtures saw.
//! Also the served build's checks, and, under `cargo test`, the relay matrix (`matrix`) and the
//! local store's independent reader (`reader`).
//!
//! ```text
//! tracer run <served-dir> <tracer-dir>   the tracer; Chrome from $CHROME, which must be set
//! tracer check-absence <dir>             AC5: no fixture-derived key, pin source or test switch
//! tracer check-csp <dir>                 AC6: the page's policy is exactly ARC-33's
//! ```
//!
//! `scripts/tracer.sh` builds both directories and runs the first.

mod aggregator;
mod auxiliary;
mod binding_cases;
mod catalogue;
mod causal;
mod cdp;
mod checks;
mod completion;
mod counter_inputs;
mod declaration_cases;
mod declaration_reader;
mod delivery_cases;
mod delivery_reader;
mod file_domains;
mod file_inputs;
mod file_installations;
mod file_recipes;
mod file_uses;
mod file_windows;
mod fixture_inputs;
mod fixture_predicates;
mod fixtures;
mod goal_cases;
mod history;
mod hold_cases;
mod inference_cases;
mod inference_reader;
mod inputs;
mod inventory;
mod job_cases;
mod key_inputs;
mod keys;
mod logical_checks;
mod machine;
#[cfg(test)]
mod matrix;
mod mode_cases;
mod observer;
mod operation_windows;
mod page_queries;
mod predicate_inputs;
mod reader;
mod reader_checks;
mod requirements;
mod seed_cases;
mod seed_operations;
mod selection;
mod semantic;
mod semantic_domains;
mod served_checks;
mod session_operands;
mod settle_inputs;
mod setup_cases;
mod state_inputs;
mod state_operation_domains;
mod state_operation_recipes;
mod state_reload_domains;
mod strict_json;
mod timing_output;
use logical_checks::Observe as _;
mod typed_cases;
mod view_domains;
mod view_inputs;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use fixtures::{Event, Observed, Seen};
use reader::Files;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};
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
        ["check-absence", dir] => checks::absence(Path::new(dir)).and_then(|()| {
            let preflight = json!({"schema":1,"duration_ns":completion::now(),"auxiliary_calls":auxiliary::snapshot(),"served_checks":served_checks::snapshot()});
            auxiliary::validate_preflight(&preflight, true)?;
            served_checks::validate_absence(&preflight,Path::new(dir))?;
            println!("TRACER_PREFLIGHT {preflight}");
            Ok(())
        }),
        ["check-csp", dir] => checks::csp(Path::new(dir)),
        ["list"] => {
            println!("{}", catalogue::cases());
            Ok(())
        }
        ["verify", capture, served, tracer] => {
            completion::verify_capture(Path::new(capture), Path::new(served), Path::new(tracer))
        }
        ["run" | "full", served, tracer, rest @ ..] => {
            completion::supervise(
                "full",
                Path::new(served),
                Path::new(tracer),
                &rest.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
            .await
        }
        ["targeted", served, tracer, rest @ ..] => {
            completion::supervise(
                "targeted",
                Path::new(served),
                Path::new(tracer),
                &rest.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
            .await
        }
        [
            "execute",
            mode @ ("full" | "targeted"),
            served,
            tracer,
            rest @ ..,
        ] => {
            match selection::admit(
                mode,
                &rest.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            ) {
                Ok(selected) => match selection::install(selected) {
                    Ok(()) => run(Path::new(served), Path::new(tracer), mode).await,
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            }
        }
        _ => Err(
            "usage: tracer run <served-dir> <tracer-dir> | check-absence <dir> | check-csp <dir>"
                .into(),
        ),
    };
    if let Err(e) = result {
        if args.first().is_some_and(|s| s == "targeted") {
            eprintln!("TARGETED FAIL");
        }
        eprintln!("FAIL: {e}");
        std::process::exit(1);
    }
}

/// The command case 1 records and sends, with quoting and a non-ASCII byte sequence, so "byte
/// for byte" bites. The fixture runs these exact bytes in a real shell, yielding both streams
/// and a nonzero exit, so "output and exit status" bites too.
const COMMAND: &str =
    "printf '%s\\n' 'tau-web tracer — recorded, then sent'; echo 'to stderr' >&2; exit 7";
const STDOUT: &str = "tau-web tracer — recorded, then sent\n";
const STDERR: &str = "to stderr\n";
const EXIT_STATUS: u32 = 7;
/// A finite command running when the lock ends its connection.
const LOCK_COMMAND: &str = "sleep 15 # tau-web tracer: running when the lock comes";

/// The passphrases the tracer types. The tracer build's is not ASCII, so its UTF-8 bytes are what
/// the worker counts and derives from.
const SERVED_PASSPHRASE: &str = "the served build's local passphrase";
const PASSPHRASE: &str = "tracer build — correct horse battery staple";
const WRONG_PASSPHRASE: &str = "tracer build — correct horse battery stapler";
const HOST_PASSPHRASE: &str = "a store the independent reader built";

/// The store's directory in the origin-private file system.
const STORE: &str = "tau-web-store/";

/// One case's verdict: the assertions that failed, empty when it passed.
struct Case {
    id: String,
    site: &'static str,
    name: String,
    failures: Vec<String>,
    assertions: Vec<Value>,
    branches: std::collections::BTreeMap<&'static str, &'static str>,
    start: u64,
    end: u64,
}

impl Case {
    fn new(site: &'static str, name: &str) -> Case {
        println!("\n== {name}");
        let id = catalogue::case_id(site, name);
        let start = history::event(json!({"event":"case_start","id":id}));
        Case {
            id,
            site,
            name: name.into(),
            failures: Vec::new(),
            assertions: Vec::new(),
            branches: std::collections::BTreeMap::new(),
            start,
            end: 0,
        }
    }

    fn finish(mut self, cases: &mut Vec<Case>) {
        self.end = history::event(json!({"event":"case_end","id":self.id}));
        println!(
            "TRACER_CASE_TIMING {}",
            json!({"id":self.id,"start_ns":self.start,"end_ns":self.end})
        );
        cases.push(self);
    }

    fn branch(&mut self, name: &'static str, value: &'static str) {
        if self.branches.insert(name, value).is_some() {
            self.failures
                .push(format!("duplicate scenario branch: {name}"));
        }
    }
}

async fn run(served: &Path, tracer: &Path, mode: &str) -> Result<(), String> {
    completion::now();
    let execution_span = completion::Span::start("execution");
    let provenance = completion::provenance(served, tracer)?;
    let mut timings = Vec::new();
    let chrome = std::env::var("CHROME").map_err(|_| {
        "CHROME is not set: the tracer needs a Chrome or Chromium binary and never skips"
            .to_string()
    })?;
    let served_page = served.join("index.html");
    let served_policy = checks::page_policy(
        &std::fs::read_to_string(&served_page)
            .map_err(|e| format!("{}: {e}", served_page.display()))?,
    )?;

    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"));
    std::fs::create_dir_all(&target).map_err(|e| format!("{}: {e}", target.display()))?;
    let profile = target.join(format!("tracer-chrome-{}", std::process::id()));
    if profile.exists() {
        return Err("browser profile is not fresh".into());
    }
    let fixture_span = completion::Span::start("fixtures");
    let seen = Observed::default();
    let tls = fixtures::tls();
    let aggregator = aggregator::Aggregator::start(tls.acceptor.clone(), tls.cert.clone()).await;
    aggregator::register_original(&aggregator);
    let sshd = fixtures::sshd(seen.clone()).await;
    let sshd_other = fixtures::sshd(seen.clone()).await;
    causal::register(&seen, &sshd, &sshd_other);
    let relay = fixtures::relay(seen.clone(), tls.acceptor.clone(), vec![], false).await;
    fixture_inputs::register(&seen, &relay, &sshd);
    let (served_origin, served_requests) = fixtures::https(
        served.to_path_buf(),
        tls.acceptor.clone(),
        Some(served_policy.clone()),
    )
    .await;
    let (tracer_origin, tracer_requests) = fixtures::https(
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
    timings.push(fixture_span.finish());

    let browser_span = completion::Span::start("browser");
    let browser = match cdp::Browser::launch(&chrome, profile, &tls.spki_sha256).await {
        Ok(browser) => browser,
        Err(error) => {
            browser_span.fail();
            let cleanup_span = completion::Span::start("cleanup");
            sshd.cleanup_at(Some("cleanup.ssh.primary")).await;
            sshd_other.cleanup_at(Some("cleanup.ssh.other")).await;
            cleanup_span.finish();
            return Err(error);
        }
    };
    timings.push(browser_span.finish());
    let context = Run {
        browser: &browser,
        aggregator: &aggregator,
        seen: &seen,
        sshd: &sshd,
        sshd_other: &sshd_other,
        relay: &relay,
        messages: RefCell::default(),
        uncleared: RefCell::default(),
        same_browser: RefCell::new(false),
    };
    let mut cases = Vec::new();
    let groups_span = completion::Span::start("groups");
    history::start();
    let outcome = run_cases(
        &context,
        &served_origin,
        &tracer_origin,
        &served_policy,
        &[&served_requests, &tracer_requests],
        &mut cases,
    )
    .await;
    timings.push(groups_span.finish());
    let same_browser = *context.same_browser.borrow();
    drop(context);
    let cleanup_span = completion::Span::start("cleanup");
    let browser_clean = browser.close().await;
    let sshd_clean = sshd.cleanup_at(Some("cleanup.ssh.primary")).await;
    let other_clean = sshd_other.cleanup_at(Some("cleanup.ssh.other")).await;
    let cleanup = browser_clean && sshd_clean && other_clean;
    timings.push(cleanup_span.finish());

    // The summary names every case that ran, even when one stopped the run.
    println!("\n== summary ({} cases)", cases.len());
    for case in &cases {
        match case.failures.as_slice() {
            [] => println!("   PASS {}", case.name),
            failures => println!("   FAIL {}: {}", case.name, failures.join("; ")),
        }
    }
    let failed: Vec<_> = cases
        .iter()
        .filter(|c| !c.failures.is_empty())
        .map(|c| c.name.as_str())
        .collect();
    inputs::finish();
    let report = completion::report(
        mode,
        &provenance,
        &cases,
        timings,
        outcome.is_ok() && failed.is_empty(),
        same_browser,
        cleanup,
    )?;
    println!("TRACER_EVIDENCE {report}");
    execution_span.finish();
    if let Err(e) = outcome {
        Err(format!(
            "the run stopped after {} cases: {e}; cases failed: {}",
            cases.len(),
            failed.join(", ")
        ))
    } else if failed.is_empty() && cleanup {
        // Only the supervising process can publish a gate verdict, after checking actual exit.
        Ok(())
    } else if !cleanup {
        Err("tracer cleanup did not complete".into())
    } else {
        Err(format!("tracer cases failed: {}", failed.join(", ")))
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        if self.end == 0 {
            println!(
                "TRACER_CASE_TIMING {}",
                json!({"id":self.id,"start_ns":self.start,"end_ns":completion::now(),"status":"incomplete"})
            );
        }
    }
}

/// What the fixtures observed since the last call, which starts the next case from nothing.
fn take(seen: &Observed) -> Seen {
    std::mem::take(&mut *seen.lock().expect("observations lock"))
}

fn show(seen: &Seen) {
    println!("   fixtures observed: {seen:?}");
}

/// Waits up to `seconds` until `holds` holds of what the fixtures have observed so far.
async fn settle_for(
    site: &'static str,
    seen: &Observed,
    seconds: u64,
    extra: Value,
    holds: impl Fn(&Seen, &observer::Call) -> bool,
) -> bool {
    let observation = observer::Call::begin(
        site,
        "fixture.wait",
        None,
        causal::wait_domain(site, seconds, extra),
    );
    observation.fact("fixture_input", causal::source_seen(seen));
    for poll in 0..seconds * 20 {
        observation.attempt(poll as usize + 1);
        if observation.poll(
            poll as usize + 1,
            holds(&seen.lock().expect("observations lock"), &observation),
        ) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Waits up to 5 s; the original caller deliberately ignores exhaustion.
async fn settle(reason: &str, seen: &Observed, input: &fixture_inputs::Input) {
    let observation = observer::Call::begin(
        "main.refusal.wait_close",
        "fixture.settle",
        None,
        json!({"reason":reason,"ignored_result":true}),
    );
    observation.fact("fixture_input", causal::source_seen(seen));
    settle_for("fixture.settle.wait", seen, 5, json!({}), |seen, call| {
        fixture_predicates::socket(seen, false, input, call)
    })
    .await;
}

/// Forgets the relay fixture's pace state, so a dialing case never meets a refusal for `pace`
/// left by the one before it.
fn fresh_pace(relay: &fixtures::Relay) {
    relay.pace.lock().expect("pace lock").clear();
}

/// Records every message the page sends its harness workers and every message they send it,
/// from before the first: installed through the DevTools protocol before the page's own scripts
/// run, so the product carries no hook. It reads what structured cloning reads, never through a
/// value's own iterator or an inherited setter. Before a transfer detaches anything, at any depth:
/// - every `ArrayBuffer`, and every typed array's and `DataView`'s whole backing buffer, which
///   structured cloning sends whole, is recorded as `{ "__tracerBinary": <its bytes, base64> }`;
/// - a plain object's own enumerable properties, `__proto__` included, and an array's elements
///   by index, from 0 to `length − 1`;
/// - a `Map` as `{ "__tracerMap": [[key, value], …] }` and a `Set` as `{ "__tracerSet": [member,
///   …] }`, read through `Map.prototype.forEach` and `Set.prototype.forEach` as they were when
///   this installed;
/// - any other object that is not a plain object or an array, which this cannot read, as
///   `{ "__tracerOpaque": <its kind> }`, a finding; so is an array with a named property, which
///   structured cloning sends too, and a message the serializer throws on, as
///   `{ "__tracerOpaque": "unserializable" }`, still sent or failing as it would have.
///
/// The guarded serializer is `__tracerMessages.plain`, for the negative controls.
const HOOK: &str = r#"(() => {
  const log = [];
  Object.defineProperty(window, '__tracerMessages', { value: log });
  const mapForEach = Map.prototype.forEach;
  const setForEach = Set.prototype.forEach;
  const binary = (bytes) => {
    let text = '';
    for (const byte of bytes) text += String.fromCharCode(byte);
    return { __tracerBinary: btoa(text) };
  };
  const plain = (data, seen = new Set()) => {
    if (typeof data === 'bigint') return { __tracerOpaque: 'bigint' };
    if (data === null || typeof data !== 'object') return data;
    if (data instanceof ArrayBuffer) return binary(new Uint8Array(data));
    if (ArrayBuffer.isView(data)) return binary(new Uint8Array(data.buffer));
    if (seen.has(data)) return { __tracerCycle: true };
    seen.add(data);
    const walk = (value) => plain(value, seen);
    const proto = Object.getPrototypeOf(data);
    let out;
    if (Array.isArray(data)) {
      if (Object.keys(data).every((k) => /^(0|[1-9][0-9]*)$/.test(k) && +k < data.length)) {
        out = [];
        for (let i = 0; i < data.length; i++) out.push(walk(data[i]));
      } else out = { __tracerOpaque: 'Array with named properties' };
    } else if (data instanceof Map) {
      out = { __tracerMap: [] };
      mapForEach.call(data, (v, k) => out.__tracerMap.push([walk(k), walk(v)]));
    } else if (data instanceof Set) {
      out = { __tracerSet: [] };
      setForEach.call(data, (v) => out.__tracerSet.push(walk(v)));
    } else if (proto === Object.prototype || proto === null) {
      out = Object.create(null);
      for (const key of Object.keys(data)) out[key] = walk(data[key]);
    } else out = { __tracerOpaque: Object.prototype.toString.call(data).slice(8, -1) };
    seen.delete(data);
    return out;
  };
  const record = (data) => {
    try {
      return plain(data);
    } catch {
      return { __tracerOpaque: 'unserializable' };
    }
  };
  Object.defineProperty(log, 'plain', { value: record });
  const Native = window.Worker;
  window.Worker = class extends Native {
    constructor(...args) {
      super(...args);
      this.addEventListener('message', (event) => log.push({ from: record(event.data) }));
    }
    postMessage(message, transfer) {
      log.push({ to: record(message) });
      return super.postMessage(message, transfer);
    }
  };
})()"#;

/// The page's view: the harness status, the store's one state and its text, the controls it
/// offers, the persistent-storage report, and the visibility.
const VIEW: &str = "(() => {
    const $ = (id) => document.getElementById('tau-'+id);
    return {
        status: ($('status').dataset.state ?? '').replace('harness-', ''),
        store: $('store').dataset.state ?? '',
        text: $('store-state').textContent,
        create: !$('create').hidden,
        unlock: !$('unlock').hidden,
        lock: !$('lock').hidden,
        persist: $('persist').dataset.state ?? '',
        persist_text: $('persist').textContent,
        visibility: document.visibilityState,
    };
})()";

/// Every file in the origin-private file system, recursively, as `path: base64`.
const DUMP: &str = r#"(async () => {
    const snapshot = async () => {
        const out = {};
        const walk = async (directory, prefix) => {
            for await (const [name, handle] of directory.entries()) {
                if (handle.kind === 'directory') {
                    await walk(handle, `${prefix}${name}/`);
                } else {
                    const bytes = new Uint8Array(await (await handle.getFile()).arrayBuffer());
                    let text = '';
                    for (const byte of bytes) text += String.fromCharCode(byte);
                    out[`${prefix}${name}`] = btoa(text);
                }
            }
        };
        await walk(await navigator.storage.getDirectory(), '');
        return out;
    };
    // An append can move a staging file after enumeration but before getFile. Start
    // over, retaining no partial snapshot; a stable or unrelated error still refuses.
    for (let attempt = 0; ; attempt++) {
        try { return await snapshot(); }
        catch (error) {
            if (error.name !== 'NotFoundError' || attempt >= 9) throw error;
        }
    }
})()"#;

/// The page's other storage: local and session storage, IndexedDB's databases, Cache Storage's
/// caches and their entries, and service-worker registrations.
const OTHER_STORAGE: &str = "(async () => ({
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
    databases: await indexedDB.databases(),
    caches: await Promise.all((await caches.keys()).map(async (name) => {
        const cache = await caches.open(name);
        return [name, await Promise.all((await cache.keys()).map(async (request) =>
            [request.url, await (await cache.match(request)).text()]))];
    })),
    service_workers: (await navigator.serviceWorker.getRegistrations()).length,
}))()";

/// A page the tracer opened.
struct Tab {
    session: String,
    target: String,
    origin: String,
}

/// A harness worker: its DevTools session and its target.
#[derive(Clone, PartialEq)]
struct Worker {
    session: String,
    target: String,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Worker")
    }
}

/// The browser, the fixtures, and what the tracer gathers across cases.
struct Run<'a> {
    browser: &'a cdp::Browser,
    aggregator: &'a aggregator::Aggregator,
    seen: &'a Observed,
    sshd: &'a fixtures::Sshd,
    sshd_other: &'a fixtures::Sshd,
    relay: &'a fixtures::Relay,
    /// Every message between a page and its harness workers, gathered before each reload or
    /// close and at the end.
    messages: RefCell<Vec<Value>>,
    /// Submits after which a passphrase field still held text.
    uncleared: RefCell<Vec<String>>,
    same_browser: RefCell<bool>,
}

impl Run<'_> {
    /// Opens `origin` in a new page with the message recorder installed, and waits for its
    /// harness worker and its store state (`in_use`: or for the store to be in use elsewhere).
    async fn open(&self, origin: &str, in_use: bool) -> Result<(Tab, Worker), String> {
        let page = self
            .browser
            .call(None, "Target.createTarget", json!({ "url": "about:blank" }))
            .await?;
        let target = page["targetId"].as_str().ok_or("no target")?.to_string();
        let attached = self
            .browser
            .call(
                None,
                "Target.attachToTarget",
                json!({ "targetId": target, "flatten": true }),
            )
            .await?;
        let session = attached["sessionId"]
            .as_str()
            .ok_or("no page session")?
            .to_string();
        for method in [
            "Page.enable",
            "Runtime.enable",
            "Log.enable",
            "Network.enable",
        ] {
            self.browser.call(Some(&session), method, json!({})).await?;
        }
        self.browser
            .call(
                Some(&session),
                "Fetch.enable",
                json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}]}),
            )
            .await?;
        self.browser
            .call(
                Some(&session),
                "Page.addScriptToEvaluateOnNewDocument",
                json!({ "source": HOOK }),
            )
            .await?;
        self.browser
            .call(
                Some(&session),
                "Target.setAutoAttach",
                json!({ "autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true }),
            )
            .await?;
        self.browser
            .call(
                Some(&session),
                "Page.navigate",
                json!({ "url": format!("{origin}/") }),
            )
            .await?;
        let tab = Tab {
            session,
            target,
            origin: origin.to_string(),
        };
        let worker = self.worker(&tab, None, in_use).await?;
        Ok((tab, worker))
    }

    /// The page's live harness workers, from the attach and detach events of its session.
    fn live_workers(&self, tab: &Tab) -> Vec<Worker> {
        let mut live = Vec::new();
        for e in self.browser.events.lock().expect("events lock").iter() {
            if e["sessionId"] != tab.session.as_str() {
                continue;
            }
            match e["method"].as_str() {
                Some("Target.attachedToTarget")
                    if e["params"]["targetInfo"]["type"] == "worker" =>
                {
                    live.push(Worker {
                        session: e["params"]["sessionId"].as_str().unwrap_or("").into(),
                        target: e["params"]["targetInfo"]["targetId"]
                            .as_str()
                            .unwrap_or("")
                            .into(),
                    });
                }
                Some("Target.detachedFromTarget") => {
                    live.retain(|w| e["params"]["sessionId"] != w.session.as_str());
                }
                _ => {}
            }
        }
        live
    }

    /// The browser's harness worker targets for `origin`.
    async fn harness_targets(&self, origin: &str) -> Result<Vec<String>, String> {
        let targets = self
            .browser
            .call(None, "Target.getTargets", json!({}))
            .await?;
        Ok(targets["targetInfos"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|t| {
                t["type"] == "worker"
                    && t["url"].as_str() == Some(format!("{origin}/worker.js").as_str())
            })
            .filter_map(|t| t["targetId"].as_str().map(str::to_string))
            .collect())
    }

    /// Waits up to 30 s for the page to have one live harness worker other than `old`, to
    /// report it ready, and for its store to show a state; that worker.
    async fn worker(
        &self,
        tab: &Tab,
        old: Option<&Worker>,
        in_use: bool,
    ) -> Result<Worker, String> {
        let call = history::Call::page("runtime.worker", &tab.session);
        let exclusion = observer::worker_input(call.id(), &tab.session, old, in_use);
        completion::prerequisite_request("runtime.worker.ready");
        let from = self.browser.event_count();
        for poll in 0..300 {
            call.attempt(poll + 1);
            let candidate = exclusion.candidate(self, tab, old);
            if call.poll(candidate.is_some()) {
                let worker = candidate.expect("the actual worker-selection predicate passed");
                if let Err(error) = self
                    .browser
                    .call(Some(&worker.session), "Runtime.enable", json!({}))
                    .await
                {
                    if error.contains("Session with given id not found") {
                        call.observe("retry", json!({}));
                        continue;
                    }
                    return Err(error);
                }
                self.browser
                    .call(Some(&worker.session), "Network.enable", json!({}))
                    .await?;
                self.browser.call(Some(&worker.session),"Network.setBlockedURLs",json!({"urlPatterns":[{"urlPattern":"https://127.0.0.1:*/*","block":false},{"urlPattern":"wss://127.0.0.1:*/*","block":false},{"urlPattern":"*://*:*/*","block":true}]})).await?;
                self.browser
                    .call(
                        Some(&worker.session),
                        "Runtime.runIfWaitingForDebugger",
                        json!({}),
                    )
                    .await?;
                call.select(&worker);
                self.settled(tab, in_use).await?;
                completion::prerequisite("runtime.worker.ready", true);
                return Ok(worker.clone());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let live = self.live_workers(tab);
        // Only lifecycle metadata: no console arguments, exception bodies or request data.
        let events: Vec<_> = self.browser.events.lock().unwrap()[from..]
            .iter()
            .filter(|e| {
                matches!(
                    e["method"].as_str(),
                    Some(
                        "Target.attachedToTarget"
                            | "Target.detachedFromTarget"
                            | "Target.targetCrashed"
                            | "Inspector.targetCrashed"
                            | "Inspector.detached"
                            | "Runtime.exceptionThrown"
                            | "Page.frameStartedLoading"
                            | "Page.frameStoppedLoading"
                    )
                )
            })
            .map(|e| {
                json!({"method":e["method"],"page_event":e["sessionId"]==tab.session,"worker_event":live.iter().any(|w|e["sessionId"]==w.session),"type":e["params"]["targetInfo"]["type"],"status":e["params"]["status"],"error_code":e["params"]["errorCode"]})
            })
            .collect();
        println!(
            "   worker timeout: page={} old_present={} live_count={} events={}",
            history::page_id(&tab.session),
            old.is_some(),
            live.len(),
            json!(events)
        );
        // These best-effort observations happen after the wait has already failed.
        let view = match tokio::time::timeout(
            Duration::from_secs(2),
            self.view_at("view.runtime.worker_timeout", tab),
        )
        .await
        {
            Ok(Ok(view)) => json!({"status":view["status"],"store":view["store"]}),
            Ok(Err(_)) => json!({"query":"failed"}),
            Err(_) => json!({"query":"timed_out"}),
        };
        let targets =
            match tokio::time::timeout(Duration::from_secs(2), self.harness_targets(&tab.origin))
                .await
            {
                Ok(Ok(targets)) => json!({"worker_count":targets.len()}),
                Ok(Err(_)) => json!({"query":"failed"}),
                Err(_) => json!({"query":"timed_out"}),
            };
        println!("   worker timeout observations: view={view}, targets={targets}");
        Err(format!(
            "{}: no new harness worker in 30 s (live count {})",
            tab.origin,
            live.len()
        ))
    }

    async fn view_at(&self, site: &'static str, tab: &Tab) -> Result<view_inputs::View, String> {
        view_inputs::read(view_inputs::Origin::Direct(site), self, tab, VIEW).await
    }

    /// Waits up to 30 s for the page to report its worker ready and its store a state that is
    /// not transient; the page's view. The store is in use elsewhere for a moment after a
    /// reload, while the old document's worker still holds the lock, so that state counts only
    /// with `in_use`.
    async fn settled(&self, tab: &Tab, in_use: bool) -> Result<view_inputs::View, String> {
        let call = history::Call::page("runtime.settled", &tab.session);
        observer::settled_input(call.id(), in_use);
        completion::prerequisite_request("runtime.store.ready_nontransient");
        let mut view = view_inputs::View::empty();
        for poll in 0..300 {
            call.attempt(poll + 1);
            completion::prerequisite_request("runtime.store.not_failed");
            view = view_inputs::read(
                view_inputs::Origin::Runtime {
                    call: call.id(),
                    attempt: poll + 1,
                    in_use,
                },
                self,
                tab,
                VIEW,
            )
            .await?;
            if completion::rejects("runtime.store.not_failed", view.failed(call.id(), poll + 1)) {
                return Err(format!("{}: {view}", tab.origin));
            }
            if call.poll(view.ready(call.id(), poll + 1, in_use)) {
                completion::prerequisite("runtime.store.ready_nontransient", true);
                return Ok(view.returned(call.id()));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(format!(
            "{}: the store did not settle in 30 s: {view}",
            tab.origin
        ))
    }

    /// Types `passphrase` into the page's field (and its confirmation, to create), presses
    /// `kind`'s button, and checks the fields are empty at once; the page's view once settled.
    async fn submit(
        &self,
        tab: &Tab,
        kind: &str,
        passphrase: &str,
    ) -> Result<view_inputs::View, String> {
        let _call = history::Call::page("runtime.submit", &tab.session);
        let passphrase_role = observer::passphrase_role(passphrase);
        let passphrase = serde_json::to_string(passphrase).expect("a JSON string");
        let left = self
            .browser
            .evaluate(
                &tab.session,
                &format!(
                    "(() => {{
                        const $ = (id) => document.getElementById('tau-'+id);
                        $('passphrase').value = {passphrase};
                        $('confirm').value = {passphrase};
                        $('{kind}').click();
                        return [$('passphrase').value, $('confirm').value];
                    }})()"
                ),
            )
            .await?;
        let cleared = left == json!(["", ""]);
        observer::submission(_call.id(), kind, passphrase_role, cleared);
        if !cleared {
            self.uncleared.borrow_mut().push(format!("{kind}: {left}"));
        }
        let view = self.settled(tab, false).await?;
        println!("   {kind}: {}", view["text"]);
        Ok(view)
    }

    async fn inspect_state_at(
        &self,
        site: &'static str,
        worker: &Worker,
    ) -> Result<state_inputs::State, String> {
        state_inputs::inspect(site, self, worker).await
    }

    /// The replayed state, read in the worker's own context.
    async fn inspect(&self, worker: &Worker) -> Result<Value, String> {
        seed_operations::operation("inspect", worker, None);
        self.browser
            .evaluate(&worker.session, state_inputs::EXPRESSION)
            .await
    }

    /// Has the harness worker run one command, and returns its report. The page offers no way
    /// to: this evaluates in the worker's own context, over its DevTools session, and calls
    /// `run_command` on the module the worker already loaded (the same URL, so the same
    /// initialized module).
    async fn harness_run(&self, site: &str, worker: &Worker, args: Value) -> Result<Value, String> {
        let operation = state_inputs::Operation::begin(site, "run", worker);
        operation.request(self, worker, &args);
        seed_operations::operation("run", worker, Some(&args));
        let report = self
            .browser
            .evaluate(&worker.session, &run_expression(&args))
            .await?;
        println!("   harness reported: {report}");
        operation.finish();
        Ok(report)
    }

    async fn harness_collect(
        &self,
        site: &str,
        worker: &Worker,
        args: Value,
    ) -> Result<Value, String> {
        let operation = state_inputs::Operation::begin(site, "collect", worker);
        operation.request(self, worker, &args);
        seed_operations::operation("collect", worker, Some(&args));
        let result = self
            .browser
            .evaluate(
                &worker.session,
                &run_expression(&args).replace("module.run_command(", "module.collect_jobs("),
            )
            .await?;
        operation.finish();
        Ok(result)
    }

    /// Starts one command in the worker and returns at once, leaving it in flight.
    async fn harness_start(&self, worker: &Worker, args: Value) -> Result<(), String> {
        self.browser
            .call(
                Some(&worker.session),
                "Runtime.evaluate",
                json!({ "expression": run_expression(&args), "awaitPromise": false }),
            )
            .await
            .map(|_| ())
    }

    /// Gathers the messages the page's recorder holds.
    async fn collect(&self, tab: &Tab) -> Result<(), String> {
        let messages = self
            .browser
            .evaluate(&tab.session, "window.__tracerMessages.splice(0)")
            .await?;
        self.messages
            .borrow_mut()
            .extend(messages.as_array().cloned().unwrap_or_default());
        Ok(())
    }

    /// Reloads the page: a new document, so a new harness worker.
    async fn reload(&self, site: &str, tab: &Tab, old: &Worker) -> Result<Worker, String> {
        let operation = state_inputs::Operation::begin(site, "reload", old);
        operation.reload(tab);
        self.collect(tab).await?;
        self.browser
            .call(Some(&tab.session), "Page.reload", json!({}))
            .await?;
        let worker = self.worker(tab, Some(old), false).await?;
        operation.successor(&worker);
        Ok(worker)
    }

    /// The origin's private file system, every file by path.
    async fn dump_at(&self, site: &'static str, tab: &Tab) -> Result<Files, String> {
        file_inputs::dump_at(self, tab, DUMP, site).await
    }

    /// Replaces the store's directory with `files`, by name.
    async fn put(&self, tab: &Tab, files: &Files) -> Result<(), String> {
        file_inputs::install(self, tab, files).await
    }
}

fn run_expression(args: &Value) -> String {
    let request = serde_json::to_string(&args.to_string()).expect("a JSON string");
    format!(
        "(async () => {{
            const module = await import(new URL('./pkg/tau_web.js', self.location.href).href);
            return JSON.parse(await module.run_command({request}));
        }})()"
    )
}

fn replay_job(outcome: &Value) -> &str {
    outcome["job_record"]["job"].as_str().unwrap_or("")
}

fn exec_command_is(seen: &Seen, command: &str) -> bool {
    matches!(seen.ssh_exec.as_slice(), [bytes] if {
        let id = std::str::from_utf8(bytes).ok().and_then(|s| s.lines().next()).and_then(|s| s.strip_prefix("# tau-web job launch "));
        id.is_some_and(|id| tau_web::jobs::valid_id(id) && bytes == tau_web::jobs::launch(id, "fixture", command.as_bytes()).as_bytes())
    })
}

/// The store's files from a dump of the whole file system.
fn store_files(dumped: &Files) -> Files {
    file_inputs::store_files(dumped)
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

/// Keep the whole event payload, including property names, URLs, stacks and log arguments.
fn console_params(event: &Value) -> Option<&Value> {
    matches!(
        event["method"].as_str(),
        Some("Runtime.consoleAPICalled" | "Log.entryAdded" | "Runtime.exceptionThrown")
    )
    .then_some(&event["params"])
}

#[test]
fn console_custody_searches_entire_payloads_including_property_names_urls_and_stacks() {
    let secret = "a confidential test phrase";
    let needles = reader::encodings("secret", secret.as_bytes());
    for method in [
        "Runtime.consoleAPICalled",
        "Log.entryAdded",
        "Runtime.exceptionThrown",
    ] {
        for params in [
            json!({"args":[{"preview":{"properties":[{"name":secret,"value":"1"}]}}]}),
            json!({"url":secret}),
            json!({"stackTrace":{"description":secret}}),
            json!({"entry":{"args":[secret]}}),
        ] {
            assert!(
                !reader::found(
                    &needles,
                    console_params(&json!({"method":method,"params":params}))
                        .unwrap()
                        .to_string()
                        .as_bytes()
                )
                .is_empty()
            );
        }
    }
}

fn add_inference_needles(run: &Run<'_>, needles: &mut Vec<(String, Vec<u8>)>) {
    needles.extend(run.aggregator.needles());
}

async fn run_cases(
    run: &Run<'_>,
    served_origin: &str,
    tracer_origin: &str,
    served_policy: &str,
    requests: &[&fixtures::Requests],
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let _scenario_span = completion::scenario("main.run");
    if selection::present("TAU_TRACER_DELIVERY").is_some() {
        let (tab, mut worker) = run.open(tracer_origin, false).await?;
        delivery_cases::run(run, &tab, &mut worker, cases).await?;
        return Ok(());
    }
    if selection::present("TAU_TRACER_GOALS").is_some() {
        let (tab, mut worker) = run.open(tracer_origin, false).await?;
        goal_cases::run(run, &tab, &mut worker, cases).await?;
        return Ok(());
    }
    if selection::present("TAU_TRACER_INFERENCE").is_some() {
        let (mut tab, mut worker) = run.open(tracer_origin, false).await?;
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut events = vec![json!({"seed":{"mnemonic":mnemonic}})];
        events.extend(reader::setup_events_at(
            "reader.aux.call.main.inference_setup",
            mnemonic,
            &["fixture", "fixture-other"],
        ));
        for machine in ["fixture", "fixture-other"] {
            events.push(json!({"setup":{"class":{"machine":machine,"answer":"no","class":"single_purpose"}}}));
        }
        run.put(
            &tab,
            &reader::build_at("file.main.build.001", PASSPHRASE, &events),
        )
        .await?;
        inference_cases::run(run, &mut tab, &mut worker, cases).await?;
        inference_cases::no_plaintext(run, &tab, &worker, cases).await?;
        return Ok(());
    }
    let (browser, seen, sshd, relay) = (run.browser, run.seen, run.sshd, run.relay);
    let pinned = PINS
        .iter()
        .find(|(machine, _)| *machine == "fixture")
        .map(|(_, pin)| pin.to_string())
        .expect("the pin source pins `fixture`");
    let args = |machine: &str| {
        json!({
            "machine": machine,
            "relay": relay.url,
            "host": "127.0.0.1",
            "port": if machine == "fixture-other" { run.sshd_other.port } else { sshd.port },
            "user": SSH_USER,
            "command": COMMAND,
            "fail_append": false,
            "tamper_auth": false,
        })
    };
    let served_args = |machine: &str| {
        let mut request = args(machine);
        for key in ["fail_append", "tamper_auth"] {
            request.as_object_mut().unwrap().remove(key);
        }
        request
    };
    let locked = json!({ "outcome": { "refused": "locked" } });

    // The served build loads, and its harness worker runs a request on what it has stored.
    let mut case = Case::new(
        "main.c001",
        "the served build loads, derives bound credentials and has no pin or request hook",
    );
    let from = browser.event_count();
    let (mut served_tab, mut served_worker) = run.open(served_origin, false).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let errors = errors_since(
        browser,
        from,
        &[&served_tab.session, &served_worker.session],
    );
    println!("   errors reported: {errors:?}");
    case.check("main.a001", "the harness worker reported ready", true);
    case.check(
        "main.a002",
        "the page and its worker reported no error",
        errors.is_empty(),
    );
    let globals = browser
        .evaluate(
            &served_tab.session,
            "({ tauWeb: typeof window.tauWeb,
                workers: Object.getOwnPropertyNames(window).filter(name => {
                    try { return window[name] instanceof Worker; } catch { return false; }
                }) })",
        )
        .await?;
    println!("   page globals: {globals}");
    case.check("main.a003",
        "the page defines no request hook: typeof window.tauWeb is \"undefined\", and no global holds the worker",
        globals == json!({ "tauWeb": "undefined", "workers": [] }),
    );
    let view = run.view_at("view.main.initial_served", &served_tab).await?;
    case.check(
        "main.a004",
        "with no store, the page offers Create and nothing else",
        view.primary("main.a004"),
    );
    take(seen);
    let report = run
        .harness_run("main.rs#1", &served_worker, served_args("fixture"))
        .await?;
    let observed = take(seen);
    case.check(
        "main.a005",
        "with no unlocked store, the served harness refuses before any contact (STA-23)",
        report == locked && observed.relay_accepted == 0 && observed.ssh_connections == 0,
    );
    let report = run
        .harness_collect("main.rs#2", &served_worker, served_args("fixture"))
        .await?;
    let observed = take(seen);
    case.check(
        "main.a006",
        "collection also refuses while locked before contact",
        report == locked && observed.relay_accepted == 0 && observed.ssh_connections == 0,
    );
    let view = run.submit(&served_tab, "create", SERVED_PASSPHRASE).await?;
    case.check(
        "main.a007",
        "a store is created in the served build, and the page offers Lock",
        view["store"] == "unlocked" && view["lock"] == true,
    );
    let report = run
        .harness_run("main.rs#3", &served_worker, served_args("fixture"))
        .await?;
    let observed = take(seen);
    case.check(
        "main.a008",
        "owed seed-backup ceremony refuses before contact or append",
        report == json!({"outcome":{"refused":"seed_backup"}})
            && observed.relay_accepted == 0
            && observed.ssh_connections == 0
            && run.inspect(&served_worker).await?["records"] == json!([0]),
    );
    seed_cases::skip("main.served.seed_skip", run, &served_tab).await?;
    let before_approval = run
        .inspect_state_at("state.main.before_approval", &served_worker)
        .await?;
    let report = run
        .harness_run("main.rs#4", &served_worker, served_args("fixture"))
        .await?;
    let observed = take(seen);
    case.check(
        "main.a009",
        "served command before approval names no entry before contact or append",
        crate::state_inputs::all!(
            report["outcome"] == json!({"refused":"no-entry","machine":"fixture"}),
            observed.relay_accepted == 0,
            observed.ssh_connections == 0,
            run.inspect_state_at("state.main.no_entry.after", &served_worker)
                .await?
                .same_at("main.a009", &before_approval, &[""])
        ),
    );
    setup_cases::approve(
        "main.served.setup_approve",
        run,
        &served_tab,
        &served_worker,
    )
    .await?;
    binding_cases::prepare(run, &served_tab, &mut served_worker, SERVED_PASSPHRASE).await?;
    let report = run
        .harness_run("main.rs#5", &served_worker, served_args("fixture"))
        .await?;
    let observed = take(seen);
    show(&observed);
    case.check("main.a010",
        "called in its worker on the machine the tracer build pins, the served harness refused for the missing pin (CHN-R4)",
        report == json!({ "outcome": { "refused": "no-pin" } }),
    );
    case.check(
        "main.a011",
        "the relay fixture accepted no TCP connection, and the sshd saw none",
        observed.relay_accepted == 0 && observed.ssh_connections == 0,
    );
    case.check("main.a012",
        "only the seed, completion, setup approval, two class answers, two approved fixture declarations and two exposure entries were appended",
        run.inspect(&served_worker).await?["records"] == json!([0, 1, 2, 3, 4, 5, 6, 7, 8]),
    );
    let report = run
        .harness_collect("main.rs#6", &served_worker, served_args("fixture"))
        .await?;
    let observed = take(seen);
    case.check(
        "main.a013",
        "served collection refuses the missing pin before contact or append",
        report == json!({"outcome":{"refused":"no-pin"}})
            && observed.relay_accepted == 0
            && observed.ssh_connections == 0
            && run.inspect(&served_worker).await?["records"] == json!([0, 1, 2, 3, 4, 5, 6, 7, 8]),
    );
    case.finish(cases);

    // The tracer build: a store created in the browser, read by the independent reader; and a
    // store the reader built, unlocked in the browser.
    let (mut tab, mut worker) = run.open(tracer_origin, false).await?;
    let mut case = Case::new("main.c002", "create and unlock (twr-ggw.5, CNF-82)");
    let view = run.view_at("view.main.initial_tracer", &tab).await?;
    case.check("main.a014",
        "with no store, the page offers Create, stating the 16-character minimum and a password manager",
        state_inputs::all!(view.primary("main.a014"), browser
                .evaluate(&tab.session, "document.getElementById('tau-create-help').textContent")
                .await?
                .as_str()
                .is_some_and(|t| t.contains("at least 16 characters") && t.contains("password manager")),)
    );
    let short = run.submit(&tab, "create", "fifteen chars!!").await?;
    case.check(
        "main.a015",
        "a passphrase of 15 characters is refused, and Create is still offered",
        short["store"] == "none"
            && short["create"] == true
            && short["text"]
                .as_str()
                .is_some_and(|t| t.contains("at least 16")),
    );
    let view = run.submit(&tab, "create", PASSPHRASE).await?;
    case.check(
        "main.a016",
        "the store is created and unlocked",
        view["store"] == "unlocked",
    );
    let created = store_files(&run.dump_at("file.main.dump.001", &tab).await?);
    let opened = reader::read_at("reader.call.main.created", &created, PASSPHRASE);
    case.check("main.a017",
        "the independent reader reads the browser-written store: the envelope, then record 0, the seed",
        opened.as_ref().is_ok_and(|o| {
            o.records.len() == 1 && o.mnemonic_at("reader.aux.call.main.created.mnemonic").is_ok_and(|m| reader::seed_secrets_at("reader.aux.call.main.created.seed_secrets", o.origin(), &m).is_ok())
        }),
    );
    if let Err(e) = &opened {
        println!("   the reader: {e}");
    }
    case.check("main.a018",
        "the worker's replayed state is record 0 alone",
        run.inspect(&worker).await?
            == json!({ "state": "unlocked", "seed_backup_owed": true, "seed_backup_completion": null, "seed_backup_stage": "showing_words", "locked": false, "records": [0], "commands": [], "calls": [], "terminals": [], "dispositions": [], "standing": {}, "jobs": [], "typed_calls": [], "inference_calls": [], "observations": [], "receipts": [], "association_records": [], "current_installations": {}, "setup": [], "delivery": [], "setup_offer": tau_web::dispatch::fixture_setup(), "sessions":[],"goals":[],"exposure_ledger":[],"connection_refusals":[],"mode_acceptances":[],"signature_refusals":[],"installations":[] }),
    );
    let host = reader::build_at(
        "file.main.build.002",
        HOST_PASSPHRASE,
        &[
            json!({ "seed": { "mnemonic": include_str!("../../tests/vectors/seed-backup-collisions.txt").lines().next().expect("control mnemonic") } }),
            json!({ "command": { "machine": "fixture", "command": hex::encode("built on the host") } }),
        ],
    );
    run.put(&tab, &host).await?;
    worker = run.reload("main.rs::reload#1", &tab, &worker).await?;
    let view = run.submit(&tab, "unlock", HOST_PASSPHRASE).await?;
    case.check("main.a019",
        "a store the independent reader built unlocks in the browser: WebCrypto's PBKDF2 agrees with the host's",
        view["store"] == "unlocked",
    );
    case.check("main.a020",
        "and replays: its command reads back under its number",
        run.inspect(&worker).await?["commands"]
            == json!([{ "number": 1, "machine": "fixture", "command": hex::encode("built on the host") }]),
    );
    case.check(
        "main.a021",
        "the unlock wrote nothing",
        file_inputs::equal_primary(
            "main.a021.1",
            "main.a021",
            &(store_files(&run.dump_at("file.main.dump.002", &tab).await?)),
            &(host),
        ),
    );
    run.put(&tab, &created).await?;
    worker = run.reload("main.rs::reload#2", &tab, &worker).await?;
    let view = run.submit(&tab, "unlock", PASSPHRASE).await?;
    case.check(
        "main.a022",
        "the browser's store, put back, unlocks again",
        view["store"] == "unlocked" && run.inspect(&worker).await?["records"] == json!([0]),
    );
    case.finish(cases);

    // Keep the independent-reader and write-free unlock checks above before any completion.
    seed_cases::skip("main.tracer.seed_skip", run, &tab).await?;
    let completed = store_files(&run.dump_at("file.main.dump.003", &tab).await?);
    if selection::present("TAU_TRACER_MODE_CASE").is_some() {
        mode_cases::run(run, &tab, &mut worker, PASSPHRASE, true, &args, cases).await?;
        mode_cases::run(
            run,
            &served_tab,
            &mut served_worker,
            SERVED_PASSPHRASE,
            false,
            &served_args,
            cases,
        )
        .await?;
        return Ok(());
    }
    if selection::present("TAU_TRACER_HOLD_CASE").is_none()
        && selection::present("TAU_TRACER_SETUP_CASE").is_none()
    {
        seed_cases::run(run, &mut tab, &mut worker, PASSPHRASE, true, &args, cases).await?;
        seed_cases::run(
            run,
            &mut served_tab,
            &mut served_worker,
            SERVED_PASSPHRASE,
            false,
            &served_args,
            cases,
        )
        .await?;
        if selection::present("TAU_TRACER_SEED_CASE").is_some() {
            return Ok(());
        }
        browser
            .call(
                None,
                "Target.activateTarget",
                json!({"targetId":tab.target}),
            )
            .await?;
        worker = run.worker(&tab, None, false).await?;
        run.put(&tab, &completed).await?;
        worker = run.reload("main.rs::reload#3", &tab, &worker).await?;
        run.submit(&tab, "unlock", PASSPHRASE).await?;
    }
    if selection::present("TAU_TRACER_HOLD_CASE").is_none()
        && selection::present("TAU_TRACER_SEED_CASE").is_none()
        && selection::value("TAU_TRACER_SETUP_CASE").as_deref() != Ok("existing")
    {
        setup_cases::run(run, &mut tab, &mut worker, PASSPHRASE, true, &args, cases).await?;
        setup_cases::run(
            run,
            &mut served_tab,
            &mut served_worker,
            SERVED_PASSPHRASE,
            false,
            &served_args,
            cases,
        )
        .await?;
        browser
            .call(
                None,
                "Target.activateTarget",
                json!({"targetId":tab.target}),
            )
            .await?;
        worker = run.worker(&tab, None, false).await?;
        if selection::present("TAU_TRACER_SETUP_CASE").is_some() {
            return Ok(());
        }
        run.submit(&tab, "unlock", PASSPHRASE).await?;
    }
    setup_cases::approve("main.tracer.setup_approve", run, &tab, &worker).await?;
    binding_cases::prepare(run, &tab, &mut worker, PASSPHRASE).await?;
    // A focused fixture run for reproducible unresolved-command mutation checks.
    if selection::present("TAU_TRACER_HOLD_CASE").is_some() {
        hold_cases::run(run, &tab, worker, &args, cases).await?;
        return Ok(());
    }

    // Case 4 (AC6): the policy Chrome loaded is the served page's, and it is enforced.
    let mut case = Case::new("main.c003", "4. the page runs under ARC-33's policy (AC6)");
    let loaded = browser
        .evaluate(
            &tab.session,
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
        "main.a023",
        "the loaded page carries the served page's policy, token for token",
        loaded.as_array().is_some_and(|policies| {
            policies.len() == 1
                && tokens(policies[0].as_str().unwrap_or_default()) == tokens(served_policy)
        }),
    );
    let probe = browser
        .evaluate(
            &tab.session,
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
        "main.a024",
        "the injected inline script did not run",
        probe["ran"] == false,
    );
    case.check(
        "main.a025",
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
    let page_ws = browser.evaluate(&tab.session, socket_probe).await?;
    let worker_ws = browser.evaluate(&worker.session, socket_probe).await?;
    println!("   page, a ws: socket opened: {page_ws}");
    println!("   worker, a ws: socket opened: {worker_ws}");
    case.check(
        "main.a026",
        "connect-src refuses ws: in the page",
        refused(&page_ws),
    );
    case.check(
        "main.a027",
        "connect-src refuses ws: in the worker, under its response's policy",
        refused(&worker_ws),
    );
    let case_4 = cases.len();
    let policy_page = (tab.target.clone(), tab.session.clone());
    case.finish(cases);

    // Case 3 (AC3): no pin, no contact.
    let mut case = Case::new(
        "main.c004",
        "3. a machine with no pin is refused before any contact (AC3)",
    );
    let prior_no_pin = store_files(&run.dump_at("file.main.dump.004", &tab).await?);
    let mnemonic = reader::read_at("reader.call.main.pre_no_pin", &prior_no_pin, PASSPHRASE)?
        .mnemonic_at("reader.aux.call.main.pre_no_pin.mnemonic")?;
    let mut no_pin_events = vec![json!({"seed":{"mnemonic":mnemonic}})];
    no_pin_events.extend(reader::setup_events_at(
        "reader.aux.call.main.no_pin_setup",
        &mnemonic,
        &["fixture", "fixture-other", "unpinned"],
    ));
    run.put(
        &tab,
        &reader::build_at("file.main.build.003", PASSPHRASE, &no_pin_events),
    )
    .await?;
    worker = run.reload("main.rs::reload#4", &tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare(run, &tab, &mut worker, PASSPHRASE).await?;
    take(seen);
    let report = run
        .harness_run("main.rs#7", &worker, args("unpinned"))
        .await?;
    let observed = take(seen);
    show(&observed);
    case.check(
        "main.a028",
        "the harness refused for the missing pin",
        report["outcome"]["refused"] == "no-pin",
    );
    case.check(
        "main.a029",
        "the relay fixture accepted no TCP connection",
        observed.relay_accepted == 0,
    );
    case.check(
        "main.a030",
        "the relay fixture dialed nothing",
        observed.relay_dials.is_empty(),
    );
    case.check(
        "main.a031",
        "the fixture sshd saw no connection",
        observed.ssh_connections == 0,
    );
    case.check(
        "main.a032",
        "nothing is pinned afterwards",
        report["pinned_after"].is_null(),
    );
    case.check(
        "main.a033",
        "nothing was journaled",
        report["journal_entries"] == json!([]),
    );
    run.put(&tab, &prior_no_pin).await?;
    worker = run.reload("main.rs::reload#5", &tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare(run, &tab, &mut worker, PASSPHRASE).await?;
    case.finish(cases);

    let mut case = Case::new(
        "main.c005",
        "oversized launch refuses before intent and contact (twr-ggw.71)",
    );
    let original = store_files(&run.dump_at("file.main.dump.005", &tab).await?);
    let before = run
        .inspect_state_at("state.main.oversize.before", &worker)
        .await?;
    let command = "x".repeat(30_000);
    let bytes = tau_web::jobs::launch_size("fixture", command.as_bytes());
    let mut oversized = args("fixture");
    oversized["command"] = command.into();
    take(seen);
    fresh_pace(relay);
    let operation = operation_windows::Operation::begin(
        "main.oversize",
        &worker,
        oversized == {
            let mut expected = operation_windows::original_request(run, "fixture");
            expected["command"] = json!("x".repeat(30_000));
            expected
        },
    );
    operation.run(&worker, &oversized);
    let report = run.harness_run("main.rs#8", &worker, oversized).await?;
    operation.finish();
    sshd.all_ended_at(
        Some("main.oversize.connection_end"),
        json!({"ignored_result":true}),
    )
    .await;
    let observed = take(seen);
    println!("   oversized launch outcome: {}", report["outcome"]);
    case.check(
        "main.a034",
        "the refusal explains the command is too long, with composed bytes and limit",
        report["outcome"]
            == json!({
                "refused": "launch-too-long",
                "why": "command is too long to launch; shorten the command",
                "bytes": bytes,
                "limit": 131071,
            }),
    );
    case.check(
        "main.a035",
        "no intent, call or record is journaled",
        crate::state_inputs::all!(
            report["journal_entries"] == json!([]),
            run.inspect_state_at("state.main.oversize.after", &worker)
                .await?
                .same_at("main.a035", &before, &[""]),
            file_inputs::equal_primary(
                "main.a035.1",
                "main.a035",
                &(store_files(&run.dump_at("file.main.dump.006", &tab).await?)),
                &(original),
            )
        ),
    );
    case.check(
        "main.a036",
        "the relay accepted no connection and the sshd received no connection or exec",
        observed.relay_accepted == 0
            && observed.relay_dials.is_empty()
            && observed.ssh_connections == 0
            && observed.ssh_exec.is_empty(),
    );
    let mut normal = args("fixture");
    normal["command"] = "echo ok; exit 7".into();
    fresh_pace(relay);
    let report = run.harness_run("main.rs#9", &worker, normal).await?;
    let after = run.inspect(&worker).await?;
    let observed = take(seen);
    case.check(
        "main.a037",
        "the same store admits the next command and records its exit and terminal",
        report["outcome"]["done"] == true
            && report["outcome"]["stdout"] == "ok\n"
            && report["outcome"]["exit_status"] == 7
            && report["journal_entries"] == json!([hex::encode("echo ok; exit 7")])
            && exec_command_is(&observed, "echo ok; exit 7")
            && after["terminals"].as_array().is_some_and(|terminals| {
                terminals.iter().any(|terminal| {
                    terminal["number"] == report["outcome"]["terminal"]
                        && terminal["exit_status"] == 7
                })
            }),
    );
    run.put(&tab, &original).await?;
    worker = run.reload("main.rs::reload#6", &tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare(run, &tab, &mut worker, PASSPHRASE).await?;
    take(seen);
    case.finish(cases);

    // Case 5: the relay fixture's AUTH check is real.
    let mut case = Case::new(
        "main.c006",
        "5. a wrongly signed AUTH is refused, and nothing is dialed",
    );
    let mut tampered = args("fixture");
    tampered["tamper_auth"] = true.into();
    let report = run.harness_run("main.rs#10", &worker, tampered).await?;
    let observed = take(seen);
    show(&observed);
    let one_connection = |observed: &Seen| {
        observed.relay_accepted == 1
            && observed.relay_connections == [format!("/v1/tcp/127.0.0.1/{}", sshd.port)]
    };
    case.check(
        "main.a038",
        "the relay fixture accepted exactly one connection, upgraded on the sshd's path",
        one_connection(&observed),
    );
    case.check(
        "main.a039",
        "the harness got {\"ok\": false, \"reason\": \"auth\"} and close 1008",
        report["outcome"] == json!({ "refused": "relay", "reason": "auth", "close_code": 1008 }),
    );
    case.check(
        "main.a040",
        "the relay fixture refused at check 2 of WIR-6 (paid-tcp-relay 844e834), with close 1008",
        observed.relay_refusals == [("auth".into(), "2 signature".into(), 1008)],
    );
    case.check(
        "main.a041",
        "the relay fixture dialed nothing",
        observed.relay_dials.is_empty(),
    );
    case.check(
        "main.a042",
        "the fixture sshd saw no connection",
        observed.ssh_connections == 0,
    );
    case.finish(cases);

    // Case 1 (AC1): recorded, then sent; and it reconciles.
    let mut case = Case::new(
        "main.c007",
        "1. the command is recorded, then sent, and reconciles (AC1)",
    );
    fresh_pace(relay);
    let report = run
        .harness_run("main.rs#11", &worker, args("fixture"))
        .await?;
    let observed = take(seen);
    show(&observed);
    let journal = reader::read_at(
        "reader.call.main.recorded_command",
        &store_files(&run.dump_at("file.main.dump.007", &tab).await?),
        PASSPHRASE,
    )?;
    let intent: Value = serde_json::from_slice(
        &journal
            .records
            .iter()
            .find(|(n, _)| Some(*n) == report["outcome"]["call"].as_u64())
            .ok_or("missing command intent")
            .checked("main.command.intent")?
            .1,
    )
    .map_err(|e| e.to_string())?;
    let journal_job = intent["intent"]["job"]
        .as_str()
        .ok_or("missing journal job identity")
        .checked("main.command.job")?;
    let journal_machine = intent["intent"]["machine"]
        .as_str()
        .ok_or("missing journal machine")?;
    let journal_command = hex::decode(
        intent["intent"]["command"]
            .as_str()
            .ok_or("missing journal command")?,
    )
    .map_err(|e| e.to_string())?;
    let outcome = &report["outcome"];
    let recorded = outcome["recorded"]
        .as_str()
        .and_then(|h| hex::decode(h).ok())
        .unwrap_or_default();
    case.check(
        "main.a043",
        "the harness completed the command",
        outcome["done"] == true,
    );
    case.check("main.a044",
        "the relay fixture accepted one connection, checked the AUTH, dialed the sshd once, refused nothing",
        one_connection(&observed)
            && observed.relay_dials == [format!("127.0.0.1:{}", sshd.port)]
            && observed.relay_refusals.is_empty(),
    );
    case.check(
        "main.a045",
        "the fixture sshd admitted the derived machine client key",
        observed
            .ssh_auth
            .iter()
            .any(|(user, _, admitted)| user == "tracer" && *admitted),
    );
    case.check(
        "main.a046",
        "the fixture sshd received exactly the journal entry, byte for byte",
        observed.ssh_exec
            == [hex::decode(outcome["sent"].as_str().unwrap_or("")).unwrap_or_default()]
            && outcome["sent"]
                == hex::encode(tau_web::jobs::launch(
                    journal_job,
                    journal_machine,
                    &journal_command,
                ))
            && std::fs::read(sshd.machine.path(journal_job, "command")).ok()
                == Some(journal_command.clone()),
    );
    case.check(
        "main.a047",
        "the journal entry is the command",
        recorded == COMMAND.as_bytes(),
    );
    case.check(
        "main.a048",
        "the harness's read-back matches what it sent",
        outcome["recorded"] == hex::encode(COMMAND) && outcome["recorded_machine"] == "fixture",
    );
    case.check(
        "main.a049",
        "the journal holds that one new entry",
        report["journal_entries"] == json!([hex::encode(COMMAND)]),
    );
    let replayed = run
        .inspect_state_at("state.main.completed.replay", &worker)
        .await?;
    case.check("main.a050",
        "the store holds the command and terminal under their journal identities",
        replayed["records"] == json!((0..=outcome["terminal"].as_u64().unwrap()).collect::<Vec<_>>())
            && replayed["commands"]
                == json!([{ "number": outcome["call"], "machine": "fixture", "command": hex::encode(COMMAND) }])
            && outcome["seq"] == outcome["call"]
            && outcome["terminal"].as_u64() == outcome["call"].as_u64().map(|n|n+1)
            && replayed["calls"][0]["approval"]["harness_pin"]["machine"] == "fixture"
            && replayed["calls"][0]["approval"]["harness_pin"]["fingerprint"] == pinned.as_str()
            && replayed["calls"][0]["state"] == "finished"
            && replayed["terminals"]
                == json!([{ "number": outcome["terminal"], "call": outcome["call"], "exit_status": EXIT_STATUS }]),
    );
    case.check(
        "main.a051",
        "the output and exit status came back",
        outcome["stdout"] == STDOUT
            && outcome["stderr"] == STDERR
            && outcome["exit_status"] == EXIT_STATUS
            && observed.ssh_exit == [0],
    );
    case.check(
        "main.a052",
        "one exec on a channel: no pty, shell or subsystem (ARC-7)",
        observed.ssh_other_requests.is_empty(),
    );
    case.check(
        "main.a053",
        "the host key presented was the pin",
        outcome["host_key"] == pinned.as_str(),
    );
    let logs = observed.relay_logs();
    case.check("main.a054",
        "the relay fixture's log reads challenge sent, AUTH received, accepted, dial, OK sent, then the first forwarded byte (WIR-10, paid-tcp-relay 844e834)",
        logs.len() == 1
            && logs[0].get(..6).is_some_and(|first| {
                first[..5]
                    == [
                        Event::ChallengeSent,
                        Event::AuthReceived,
                        Event::Accepted,
                        Event::Dial(format!("127.0.0.1:{}", sshd.port)),
                        Event::OkSent,
                    ]
                    && matches!(first[5], Event::Forwarded(..))
            }),
    );

    // ... and with the store's append made to fail, nothing is sent.
    let mut failing = args("fixture");
    failing["fail_append"] = true.into();
    fresh_pace(relay);
    let before_failure = run
        .inspect_state_at("state.main.failed.before", &worker)
        .await?;
    let report = run.harness_run("main.rs#12", &worker, failing).await?;
    // Every byte the harness sent before it closed has reached the sshd once the connection has
    // ended there, so an exec sent before the append cannot still be in flight.
    let ended = sshd
        .all_ended_at(
            Some("main.failed_append.connection_end"),
            json!({"ignored_result":false}),
        )
        .await;
    let observed = take(seen);
    show(&observed);
    case.check(
        "main.a055",
        "a failed append: the sshd connection ended before its observations were read",
        ended,
    );
    case.check(
        "main.a056",
        "a failed append: the harness reports the refusal",
        report["outcome"]["refused"] == "journal",
    );
    case.check(
        "main.a057",
        "a failed append: the sshd admitted the client and received no exec request",
        observed.ssh_auth.iter().any(|(_, _, admitted)| *admitted) && observed.ssh_exec.is_empty(),
    );
    case.check(
        "main.a058",
        "a failed append: nothing was journaled",
        report["journal_entries"] == json!([]),
    );
    case.finish(cases);
    let case_1_in_this_session = cases.len() - 1;
    *run.same_browser.borrow_mut() = policy_page == (tab.target.clone(), tab.session.clone());

    // twr-ggw.5 AC2: the failed append above was not applied, and is not replayed.
    let mut case = Case::new(
        "main.c008",
        "a failed append is not applied (twr-ggw.5 AC2, STA-3)",
    );
    let after_failure = run
        .inspect_state_at("state.main.failed.after", &worker)
        .await?;
    println!("   replayed before {before_failure}, after {after_failure}");
    case.check("main.a059",
        "the append failed at a storage call: the move was refused, and the staging file is all it left",
        report["outcome"]["why"].as_str().is_some_and(|why| why.starts_with("move")),
    );
    case.check(
        "main.a060",
        "the replayed state has no record for it",
        after_failure.failed_append_at("main.a060", &before_failure, &replayed),
    );
    worker = run.reload("main.rs::reload#7", &tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    case.check(
        "main.a061",
        "after a reload and an unlock, none appears",
        run.inspect_state_at("state.main.failed.reload", &worker)
            .await?
            .replayed_at("main.a061", &before_failure),
    );
    binding_cases::prepare(run, &tab, &mut worker, PASSPHRASE).await?;
    case.finish(cases);

    let mut case = Case::new(
        "main.c009",
        "close without exit status stays unresolved (twr-ggw.7, STA-8)",
    );
    fresh_pace(relay);
    let mut closing = args("fixture");
    closing["command"] = "close-without-status".into();
    let report = run.harness_run("main.rs#13", &worker, closing).await?;
    let observed = take(seen);
    let call = report["outcome"]["call"].clone();
    let before = run.inspect(&worker).await?;
    case.check(
        "main.a062",
        "the close reports unresolved, with a call identity and no failed or done report",
        report["outcome"]["unresolved"] == true
            && call.as_u64().is_some()
            && report["outcome"].get("refused").is_none()
            && report["outcome"].get("done").is_none()
            && exec_command_is(&observed, "close-without-status")
            && observed.ssh_exit.is_empty(),
    );
    case.check(
        "main.a063",
        "the recorded call is unresolved and has no terminal",
        before["calls"].as_array().is_some_and(|calls| {
            calls
                .iter()
                .any(|c| c["call"] == call && c["state"] == "unresolved")
        }) && before["terminals"]
            .as_array()
            .is_some_and(|ts| ts.iter().all(|t| t["call"] != call)),
    );
    worker = run.reload("main.rs::reload#8", &tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let observed = take(seen);
    case.check(
        "main.a064",
        "replay preserves the unresolved call and sends no second exec",
        run.inspect(&worker).await? == binding_cases::replayed(&before)
            && observed.ssh_exec.is_empty()
            && observed.relay_accepted == 0,
    );
    binding_cases::prepare(run, &tab, &mut worker, PASSPHRASE).await?;
    fresh_pace(relay);
    let commands = before["commands"].clone();
    let held = run
        .harness_run("main.rs#14", &worker, args("fixture"))
        .await?;
    let observed = take(seen);
    case.check("main.a065", "criterion 10: a second command beside the unresolved close is held, reads only, records no intent",
        held["outcome"]["held"] == true && held["outcome"]["calls"][0]["call"] == call
        && held["outcome"]["calls"][0]["state"] == "finished"
        && observed.relay_dials.len() == 1 && job_cases::only_reads(&observed)
        && run.inspect(&worker).await?["commands"] == commands);
    worker = settle_unresolved("settle.main.001", run, &tab, worker).await?;
    case.finish(cases);

    let mut case = Case::new(
        "main.c010",
        "dispositions refuse before contact and continuing permits dispatch (twr-ggw.7, STA-24)",
    );
    let original = store_files(&run.dump_at("file.main.dump.008", &tab).await?);
    let opened = reader::read_at("reader.call.main.pre_disposition", &original, PASSPHRASE)?;
    let mut events: Vec<Value> = opened
        .records
        .iter()
        .map(|(_, plaintext)| serde_json::from_slice(plaintext).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let call = events.len() as u64;
    events.push(json!({"intent":{"call":call,"machine":"fixture","command":hex::encode(COMMAND),"approval":{"harness_pin":{"machine":"fixture","fingerprint":pinned}}}}));
    let destructive = events.len() as u64;
    events.push(json!({"disposition":{"machine":"fixture","calls":[call],"continuation":"destructive_reinstall","uncertainty":"the command outcome is unknown"}}));
    run.put(
        &tab,
        &reader::build_at("file.main.build.004", PASSPHRASE, &events),
    )
    .await?;
    worker = run.reload("main.rs::reload#9", &tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare(run, &tab, &mut worker, PASSPHRASE).await?;
    take(seen);
    fresh_pace(relay);
    let before = run.inspect(&worker).await?;
    let files_before = store_files(&run.dump_at("file.main.dump.009", &tab).await?);
    let operation = operation_windows::Operation::begin("main.disposition", &worker, true);
    operation.run(
        &worker,
        &operation_windows::original_request(run, "fixture"),
    );
    let report = run
        .harness_run("main.rs#15", &worker, args("fixture"))
        .await?;
    operation.finish();
    // If the pre-contact check is removed, the atomic append check still refuses, but the relay sees contact.
    sshd.all_ended_at(
        Some("main.disposition.connection_end"),
        json!({"ignored_result":true}),
    )
    .await;
    let observed = take(seen);
    case.check("main.a066", "a destructive disposition is named, and the relay and sshd saw no connection",
        report["outcome"] == json!({"refused":"disposition","disposition":destructive,"continuation":"destructive_reinstall"})
        && observed.relay_accepted == 0 && observed.ssh_connections == 0);
    case.check(
        "main.a067",
        "the refusal appends nothing",
        crate::state_inputs::all!(
            run.inspect(&worker).await? == before,
            file_inputs::equal_primary(
                "main.a067.1",
                "main.a067",
                &(store_files(&run.dump_at("file.main.dump.010", &tab).await?)),
                &(files_before),
            )
        ),
    );
    events.push(json!({"disposition":{"machine":"fixture","calls":[call],"continuation":"as_if_not_done","uncertainty":"the command outcome is unknown"}}));
    run.put(
        &tab,
        &reader::build_at("file.main.build.005", PASSPHRASE, &events),
    )
    .await?;
    worker = run.reload("main.rs::reload#10", &tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare(run, &tab, &mut worker, PASSPHRASE).await?;
    fresh_pace(relay);
    let report = run
        .harness_run("main.rs#16", &worker, args("fixture"))
        .await?;
    let observed = take(seen);
    let after = run.inspect(&worker).await?;
    case.check(
        "main.a068",
        "a continuing replacement dispatches and commits the exit status terminal",
        report["outcome"]["done"] == true
            && exec_command_is(&observed, COMMAND)
            && after["standing"]["fixture"]["continuation"] == "as_if_not_done"
            && after["standing"]["fixture"]["report"]["replaces"] == destructive
            && after["calls"].as_array().is_some_and(|calls| {
                calls.iter().any(|c| {
                    c["call"] == call && c["state"] == "disposed" && c["outcome"] == "unknown"
                })
            })
            && after["terminals"].as_array().is_some_and(|ts| {
                ts.iter().any(|t| {
                    t["number"] == report["outcome"]["terminal"] && t["exit_status"] == EXIT_STATUS
                })
            }),
    );
    let files = store_files(&run.dump_at("file.main.dump.011", &tab).await?);
    case.check(
        "main.a069",
        "the independent reader reads the browser terminal after the replacement",
        reader::read_at("reader.call.main.replacement_terminal", &files, PASSPHRASE).is_ok(),
    );
    run.put(&tab, &original).await?;
    worker = run.reload("main.rs::reload#11", &tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare(run, &tab, &mut worker, PASSPHRASE).await?;
    take(seen);
    case.finish(cases);

    // Case 2 (AC2): a host key other than the pin halts, before authentication, once.
    let mut case = Case::new(
        "main.c011",
        "2. a host key other than the pin halts the connection (AC2)",
    );
    sshd.present_other.store(true, Ordering::SeqCst);
    fresh_pace(relay);
    let report = run
        .harness_run("main.rs#17", &worker, args("fixture"))
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await; // room for a reconnect, which must not come
    sshd.present_other.store(false, Ordering::SeqCst);
    let observed = take(seen);
    show(&observed);
    let other = keys::fingerprint(&keys::HOST_KEY_OTHER);
    case.check(
        "main.a070",
        "the harness halted in the key check, naming both fingerprints",
        report["outcome"] == json!({ "refused": "host-key", "pinned": pinned, "presented": other }),
    );
    case.check(
        "main.a071",
        "the fixture sshd saw no authentication attempt and no exec",
        observed.ssh_auth.is_empty() && observed.ssh_exec.is_empty(),
    );
    case.check(
        "main.a072",
        "nothing was journaled",
        report["journal_entries"] == json!([]),
    );
    case.check(
        "main.a073",
        "exactly one connection: no automatic reconnect (ARC-41)",
        one_connection(&observed)
            && observed.relay_dials.len() == 1
            && observed.ssh_connections == 1,
    );
    case.finish(cases);

    // Cases 6–8 (twr-ggw.3): the relay refusals a correct client meets. Each is refused at its
    // check of WIR-6 (paid-tcp-relay 844e834) with one frame and close 1008, before any dial.
    let refused = |case: &mut Case, report: &Value, observed: &Seen, reason: &str, host: &str| {
        case.check("main.a074",
            &format!("the harness reported {{\"refused\": \"relay\", \"reason\": \"{reason}\", \"close_code\": 1008}}"),
            report["outcome"] == json!({ "refused": "relay", "reason": reason, "close_code": 1008 }),
        );
        case.check(
            "main.a075",
            "the relay fixture accepted exactly one connection",
            observed.relay_accepted == 1
                && observed.relay_connections == [format!("/v1/tcp/{host}/{}", sshd.port)],
        );
        case.check(
            "main.a076",
            "nothing was dialed, and the fixture sshd saw no connection",
            observed.relay_dials.is_empty() && observed.ssh_connections == 0,
        );
        let logs = observed.relay_logs();
        case.check("main.a077",
            "the relay fixture's log shows no frame from the client after its refusal, but the close",
            logs.len() == 1
                && logs[0]
                    .iter()
                    .position(|e| matches!(e, Event::Refused(r, _) if *r == reason))
                    .is_some_and(|at| {
                        logs[0][at + 1..].iter().all(|e| {
                            matches!(e, Event::CloseSent(1008) | Event::Frame("close"))
                        })
                    }),
        );
    };

    let mut case = Case::new(
        "main.c012",
        "6. a relay key with no pass is refused for `pass` (twr-ggw.3)",
    );
    let saved_pass_store = store_files(&run.dump_at("file.main.dump.012", &tab).await?);
    let mnemonic = reader::read_at(
        "reader.call.main.pre_no_pass",
        &saved_pass_store,
        PASSPHRASE,
    )?
    .mnemonic_at("reader.aux.call.main.pre_no_pass.mnemonic")?;
    let mut no_pass = vec![json!({"seed":{"mnemonic":mnemonic}})];
    no_pass.extend(reader::setup_events_at(
        "reader.aux.call.main.no_pass_setup",
        &mnemonic,
        &["fixture", "fixture-other"],
    ));
    run.put(
        &tab,
        &reader::build_at("file.main.build.006", PASSPHRASE, &no_pass),
    )
    .await?;
    worker = run.reload("main.rs::reload#12", &tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare_without_enrolment(run, &tab, &mut worker, PASSPHRASE).await?;
    take(seen);
    let failed = run
        .harness_run("main.rs#18", &worker, args("fixture"))
        .await?;
    let observed = take(seen);
    case.check(
        "main.a078",
        "no journaled pass refuses no-credentials after the pin lookup without contact",
        failed["outcome"] == json!({"refused":"no-credentials"})
            && observed.relay_accepted == 0
            && observed.ssh_connections == 0,
    );
    run.put(&tab, &saved_pass_store).await?;
    worker = run.reload("main.rs::reload#13", &tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare(run, &tab, &mut worker, PASSPHRASE).await?;
    let enrolled_passes = std::mem::take(&mut *relay.passes.lock().expect("passes lock"));
    let without = args("fixture");
    fresh_pace(relay);
    let (refusal_input, report) =
        fixture_inputs::refusal_run(run, &worker, &case.id, without).await?;
    settle("pass", seen, &refusal_input).await;
    drop(refusal_input);
    let observed = take(seen);
    show(&observed);
    refused(&mut case, &report, &observed, "pass", "127.0.0.1");
    *relay.passes.lock().expect("passes lock") = enrolled_passes;
    case.finish(cases);

    let mut case = Case::new(
        "main.c013",
        "7. an unrecorded destination is refused for `destination` (twr-ggw.3)",
    );
    let mut unrecorded = args("fixture");
    unrecorded["host"] = "127.0.0.2".into();
    fresh_pace(relay);
    let (refusal_input, report) =
        fixture_inputs::refusal_run(run, &worker, &case.id, unrecorded).await?;
    settle("destination", seen, &refusal_input).await;
    drop(refusal_input);
    let observed = take(seen);
    show(&observed);
    refused(&mut case, &report, &observed, "destination", "127.0.0.2");
    case.finish(cases);

    let mut case = Case::new(
        "main.c014",
        "8. a dial the pace does not allow is refused for `pace` (twr-ggw.3)",
    );
    // The sshd's host at its window cap, now: refused for a whole window, whatever the timing.
    relay.pace.lock().expect("pace lock").arm("127.0.0.1");
    let (refusal_input, report) =
        fixture_inputs::refusal_run(run, &worker, &case.id, args("fixture")).await?;
    settle("pace", seen, &refusal_input).await;
    drop(refusal_input);
    fresh_pace(relay);
    let observed = take(seen);
    show(&observed);
    refused(&mut case, &report, &observed, "pace", "127.0.0.1");
    case.finish(cases);

    // twr-ggw.5 AC1: each modification edited into OPFS is refused, the page offers no Create, and OPFS is
    // byte for byte as it was.
    let mut case = Case::new("main.c015", "fail closed (twr-ggw.5 AC1, CNF-82)");
    let baseline = store_files(&run.dump_at("file.main.dump.013", &tab).await?);
    let baseline_state = run.inspect(&worker).await?;
    let foreign = reader::build_at(
        "file.main.build.007",
        PASSPHRASE,
        &[
            json!({ "seed": { "mnemonic": include_str!("../../tests/vectors/seed-backup-collisions.txt").lines().next().expect("control mnemonic") } }),
            json!({ "command": { "machine": "fixture", "command": hex::encode(COMMAND) } }),
        ],
    );
    let variants = file_inputs::refusal_variants(&baseline, &foreign);
    for (what, files, passphrase, tag) in variants {
        run.put(&tab, &files).await?;
        worker = run.reload("main.rs::reload#14", &tab, &worker).await?;
        let view = run.submit(&tab, "unlock", passphrase).await?;
        let after = store_files(&run.dump_at("file.main.dump.014", &tab).await?);
        case.check(
            "main.a079",
            &format!("{what}: unlock is refused, and the page offers neither Create nor Unlock"),
            view["store"] == "refused"
                && view["create"] == false
                && view["unlock"] == false
                && view["lock"] == false,
        );
        if tag {
            case.check(
                "main.a080",
                &format!("{what}: the page claims no certainty about the cause"),
                view["text"]
                    .as_str()
                    .is_some_and(|t| t.contains("wrong passphrase, or the store was modified")),
            );
        }
        case.check(
            "main.a081",
            &format!("{what}: a create request creates nothing, and the store stays refused"),
            run.submit(&tab, "create", PASSPHRASE).await?["store"] == "refused",
        );
        case.check(
            "main.a082",
            &format!("{what}: OPFS is byte-identical afterwards"),
            crate::state_inputs::all!(
                file_inputs::equal_primary("main.a082.1", "main.a082", &(after), &(files)),
                file_inputs::equal_primary(
                    "main.a082.2",
                    "main.a082",
                    &(store_files(&run.dump_at("file.main.dump.015", &tab).await?)),
                    &(files),
                )
            ),
        );
        case.check(
            "main.a083",
            &format!("{what}: the worker runs nothing"),
            run.harness_run("main.rs#19", &worker, args("fixture"))
                .await?
                == locked
                && take(seen).relay_accepted == 0,
        );
    }
    run.put(&tab, &baseline).await?;
    worker = run.reload("main.rs::reload#15", &tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    case.check(
        "main.a084",
        "the store put back unlocks",
        run.inspect(&worker).await? == binding_cases::replayed(&baseline_state),
    );
    binding_cases::prepare(run, &tab, &mut worker, PASSPHRASE).await?;
    case.finish(cases);

    // Full end requires unlock; ordinary hide keeps the eligible worker.
    let mut case = Case::new(
        "main.c016",
        "reload requires unlock again (twr-ggw.5 AC3, CNF-82)",
    );
    let before = run.inspect(&worker).await?;
    let old = worker.clone();
    worker = run.reload("main.rs::reload#16", &tab, &worker).await?;
    relocked(
        run,
        &mut case,
        &tab,
        &old,
        &mut worker,
        &before,
        &args("fixture"),
    )
    .await?;
    case.finish(cases);

    let mut case = Case::new(
        "main.c017",
        "explicit lock requires unlock again, and ends its exec (twr-ggw.5 AC3, CNF-82)",
    );
    // Text typed in both fields and never submitted goes with the lock (SEC-5 row 18).
    let (new_worker, left) = lock_during_command(
        run,
        &mut case,
        &tab,
        worker,
        &args,
        "Lock",
        "(() => {
                    const $ = (id) => document.getElementById('tau-'+id);
                    $('passphrase').value = 'typed, never submitted';
                    $('confirm').value = 'typed, never submitted';
                    $('lock').click();
                    return [$('passphrase').value, $('confirm').value];
                })()",
    )
    .await?;
    worker = new_worker;
    case.check(
        "main.a085",
        &format!("Lock: text typed but not submitted is gone from both fields: {left}"),
        left == json!(["", ""]),
    );
    case.finish(cases);

    worker = settle_unresolved("settle.main.002", run, &tab, worker).await?;
    let mut case = Case::new(
        "main.c018",
        "ordinary page hide retains its worker and scheduled command (CNF-82)",
    );
    browser.evaluate(&tab.session, "window.__tracerVisibility = []; document.addEventListener('visibilitychange', () => window.__tracerVisibility.push(document.visibilityState))").await?;
    let before_hidden = run
        .inspect_state_at("state.main.hidden.before", &worker)
        .await?;
    let original_worker = worker.clone();
    let hidden_operation = operation_windows::Operation::begin("main.hidden", &worker, true);
    hidden_operation.expect(None, "Target.createTarget", json!({"url":"about:blank"}));
    hidden_operation.run(
        &worker,
        &operation_windows::original_request(run, "fixture"),
    );
    let other = browser
        .call(None, "Target.createTarget", json!({"url":"about:blank"}))
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    fresh_pace(relay);
    let hidden_result = run
        .harness_run("main.rs#20", &worker, args("fixture"))
        .await?;
    hidden_operation.finish();
    case.check(
        "main.a086",
        "scheduled command completes while hidden",
        hidden_result["outcome"]["done"] == true,
    );
    case.check(
        "main.a087",
        "same session bindings and context survive hide",
        crate::state_inputs::all!(
            run.inspect_state_at("state.main.hidden.after", &worker)
                .await?
                .same_at("main.a087", &before_hidden, &["/sessions"]),
            run.live_workers(&tab) == vec![original_worker]
        ),
    );
    browser
        .call(
            None,
            "Target.activateTarget",
            json!({"targetId":tab.target}),
        )
        .await?;
    browser
        .call(
            None,
            "Target.closeTarget",
            json!({"targetId":other["targetId"]}),
        )
        .await?;
    let visibility = browser
        .evaluate(&tab.session, "window.__tracerVisibility")
        .await?;
    println!("   visibility seen by the page: {visibility}");
    case.check(
        "main.a088",
        "the page saw the browser's own visibilitychange to hidden, then visible",
        visibility == json!(["hidden", "visible"]),
    );
    // A pagehide alone: the browser fires its own only as the page unloads (the reload case), so
    // the event is dispatched on the real window.
    worker = lock_during_command(
        run,
        &mut case,
        &tab,
        worker,
        &args,
        "pagehide",
        "dispatchEvent(new PageTransitionEvent('pagehide', { persisted: false }))",
    )
    .await?
    .0;
    case.finish(cases);

    worker = settle_unresolved("settle.main.003", run, &tab, worker).await?;
    let mut case = Case::new(
        "main.c019",
        "a killed worker surfaces an unresolved command and requires unlock (twr-ggw.7, CNF-39)",
    );
    take(seen);
    fresh_pace(relay);
    let mut running = args("fixture");
    running["command"] = LOCK_COMMAND.into();
    let exec_input = fixture_inputs::static_wait(run, &worker, &case.id, "exec");
    fixture_inputs::static_start(&exec_input, None, run, &worker, running).await?;
    let received = settle_for(
        "main.crash.running_exec",
        seen,
        20,
        json!({"command":"lock_command"}),
        |s, observation| fixture_predicates::exec(s, LOCK_COMMAND, &exec_input, observation),
    )
    .await;
    case.check(
        "main.a089",
        "before Page.crash the sshd received the running exec",
        received,
    );
    drop(exec_input);
    let before = run.inspect(&worker).await?;
    run.collect(&tab).await?;
    // Neither the page nor the worker runs a handler: the renderer stops at once. In headless
    // Chromium it answers nothing afterwards, so the call is not awaited.
    let _ = tokio::time::timeout(
        Duration::from_secs(3),
        browser.call(Some(&tab.session), "Page.crash", json!({})),
    )
    .await;
    let alive =
        tokio::time::timeout(Duration::from_secs(3), browser.evaluate(&tab.session, "1")).await;
    let worker_alive = tokio::time::timeout(
        Duration::from_secs(3),
        browser.evaluate(&worker.session, "1"),
    )
    .await;
    case.check(
        "main.a090",
        "after Page.crash, neither the page nor its harness worker runs anything",
        !matches!(alive, Ok(Ok(_))) && !matches!(worker_alive, Ok(Ok(_))),
    );
    browser
        .call(
            None,
            "Target.closeTarget",
            json!({ "targetId": tab.target }),
        )
        .await?;
    case.check(
        "main.a091",
        "the killed command's SSH connection ended",
        sshd.all_ended_at(
            Some("main.crash.connection_end"),
            json!({"ignored_result":false}),
        )
        .await,
    );
    take(seen);
    let old = worker.clone();
    (tab, worker) = run.open(tracer_origin, false).await?;
    relocked(
        run,
        &mut case,
        &tab,
        &old,
        &mut worker,
        &before,
        &args("fixture"),
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let observed = take(seen);
    let after = run.inspect(&worker).await?;
    case.check(
        "main.a092",
        "after the crash, the running call is surfaced as unresolved without another exec",
        after["calls"]
            .as_array()
            .and_then(|calls| calls.last())
            .is_some_and(|call| {
                call["command"] == hex::encode(LOCK_COMMAND) && call["state"] == "unresolved"
            })
            && observed.ssh_exec.is_empty()
            && observed.relay_accepted == 0,
    );
    case.finish(cases);

    // Opening another tab hides the first without releasing its writer ownership.
    let mut case = Case::new("main.c020", "one writer (twr-ggw.5, STA-1, STA-7)");
    let first = tab;
    observer::holder_source(&worker);
    let (second, _) = run.open(tracer_origin, true).await?;
    let one = |tab: &Tab| match run.live_workers(tab).as_slice() {
        [w] => Some(w.clone()),
        _ => None,
    };
    let mut views = (view_inputs::View::empty(), view_inputs::View::empty());
    let mut settled = false;
    {
        let observation = observer::Call::begin(
            "main.writer.holder_and_waiter",
            "serial.observation",
            Some(&first.session),
            json!({"bound":300,"false_sleep_ms":100,"requires_ready":true,"pages":"holder_and_waiter"}),
        );
        for poll in 0..300 {
            observation.attempt(poll + 1);
            views = (
                observation.view(run, &first, "first").await?,
                observation.view(run, &second, "second").await?,
            );
            let states = [views.0["store"].as_str(), views.1["store"].as_str()];
            settled =
                observation.holder_and_waiter(&one, (&first, &second), &worker, &views, states);
            if observation.poll(poll + 1, settled) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    println!(
        "   the first tab: {}\n   the second tab: {}",
        views.0, views.1
    );
    if completion::rejects("main.writer.original_holder_and_waiter", !settled) {
        return Err(format!(
            "one writer: the surviving unlocked holder and waiting instance did not remain distinct: {views:?}"
        ));
    }
    let (holder, other, other_view) = if views.0["store"] == "unlocked" {
        println!("   the first tab holds the store");
        (first, second, views.1)
    } else {
        println!("   the second tab holds the store");
        (second, first, views.0)
    };
    let holder_worker = one(&holder)
        .ok_or("no worker")
        .checked("main.writer.holder")?;
    let other_worker = one(&other)
        .ok_or("no worker")
        .checked("main.writer.waiter")?;
    for w in [&holder_worker, &other_worker] {
        browser
            .call(Some(&w.session), "Runtime.enable", json!({}))
            .await?;
    }
    let holder_current = run.view_at("view.main.holder_current", &holder).await?;
    case.check(
        "main.a093",
        "the original hidden holder remains unlocked without another passphrase",
        holder_current.primary("main.a093"),
    );
    let held_by_holder = run.inspect(&holder_worker).await?;
    case.check(
        "main.a094",
        "the other tab says it is waiting for the store, and offers neither Create nor Unlock",
        other_view["store"] == "in-use"
            && other_view["text"].as_str().is_some_and(|t| {
                t.contains("another tab, or this page's previous harness worker, still holds it")
            })
            && other_view["create"] == false
            && other_view["unlock"] == false
            && run.view_at("view.main.waiter_current", &other).await? == other_view,
    );
    case.check(
        "main.a095",
        "the other tab's worker has not read the store",
        run.inspect(&other_worker).await?["state"] == "unopened",
    );
    take(seen);
    case.check(
        "main.a096",
        "the other tab's worker runs nothing, and appends nothing",
        run.harness_run("main.rs#21", &other_worker, args("fixture"))
            .await?
            == locked
            && take(seen).relay_accepted == 0
            && run.inspect(&holder_worker).await? == held_by_holder,
    );
    run.collect(&holder).await?;
    browser
        .call(
            None,
            "Target.closeTarget",
            json!({ "targetId": holder.target }),
        )
        .await?;
    browser
        .call(
            None,
            "Target.activateTarget",
            json!({ "targetId": other.target }),
        )
        .await?;
    let mut view = observer::original_view("main.writer.waiter_unlocked", run, &other).await?;
    {
        let observation = observer::Call::begin(
            "main.writer.waiter_unlocked",
            "serial.observation",
            Some(&other.session),
            json!({"bound":100,"false_sleep_ms":100,"requires_ready":false,"page":"waiter_successor"}),
        );
        for poll in 0..100 {
            observation.attempt(poll + 1);
            if observation.view_poll(poll + 1, &view) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            view = observation.view(run, &other, "source").await?;
        }
    }
    case.check(
        "main.a097",
        "once the holding tab closes, the other offers Unlock",
        view.primary("main.a097"),
    );
    let other_worker = one(&other)
        .ok_or("no worker")
        .checked("main.writer.successor")?;
    browser
        .call(Some(&other_worker.session), "Runtime.enable", json!({}))
        .await?;
    run.submit(&other, "unlock", PASSPHRASE).await?;
    let successor = run.inspect(&other_worker).await?;
    let mut durable = held_by_holder.clone();
    durable["sessions"] = json!([]);
    case.check(
        "main.a098",
        "and unlocks the same durable store without inheriting runtime session authority",
        successor == durable && successor["sessions"] == json!([]),
    );
    (tab, worker) = (other, other_worker);
    case.finish(cases);

    // twr-ggw.5 AC6: the persistent-storage request, refused; then the permission granted, where
    // `persisted()` already reads true and the page makes no request.
    let mut case = Case::new("main.c021", "persistent storage (twr-ggw.5 AC6, STA-23)");
    let statement = "This is a request, not a guarantee: eviction, device loss or corruption can still lose the local store, so the seed backup and recovery remain necessary.";
    for (setting, state, says) in [
        (
            "denied",
            "refused",
            "Persistent storage: the browser refused the request.",
        ),
        ("granted", "granted", "Persistent storage is granted."),
    ] {
        browser
            .call(
                None,
                "Browser.setPermission",
                json!({ "permission": { "name": "persistent-storage" }, "setting": setting, "origin": tab.origin }),
            )
            .await?;
        worker = run.reload("main.rs::reload#17", &tab, &worker).await?;
        let mut view = observer::original_view("main.persistence.shown", run, &tab).await?;
        {
            let observation = observer::Call::begin(
                "main.persistence.shown",
                "serial.observation",
                Some(&tab.session),
                json!({"bound":50,"false_sleep_ms":100,"requires_ready":false,"setting":setting}),
            );
            for poll in 0..50 {
                observation.attempt(poll + 1);
                if observation.view_poll(poll + 1, &view) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                view = observation.view(run, &tab, "source").await?;
            }
        }
        println!("   {setting}: {}", view["persist_text"]);
        let persisted = browser
            .evaluate(&tab.session, "navigator.storage.persisted()")
            .await?;
        case.check(
            "main.a099",
            &format!("permission {setting}: the browser holds the store persisted: {persisted}"),
            persisted == (setting == "granted"),
        );
        case.check("main.a100",
            &format!("permission {setting}: the page shows that {says}, and that this is a request, not a guarantee"),
            view.persistence(state,says,statement),
        );
    }
    browser
        .call(None, "Browser.resetPermissions", json!({}))
        .await?;
    case.finish(cases);

    worker = typed_cases::run(run, &tab, worker, &args, cases).await?;
    job_cases::run(run, &tab, worker, &args, cases).await?;
    binding_cases::run(run, &tab, PASSPHRASE, true, &args, cases).await?;
    binding_cases::run(
        run,
        &served_tab,
        SERVED_PASSPHRASE,
        false,
        &served_args,
        cases,
    )
    .await?;
    if selection::value("TAU_TRACER_SETUP_CASE").as_deref() == Ok("existing") {
        return Ok(());
    }
    worker = run.worker(&tab, None, false).await?;
    served_worker = run.worker(&served_tab, None, false).await?;
    mode_cases::run(run, &tab, &mut worker, PASSPHRASE, true, &args, cases).await?;
    mode_cases::run(
        run,
        &served_tab,
        &mut served_worker,
        SERVED_PASSPHRASE,
        false,
        &served_args,
        cases,
    )
    .await?;
    run.browser
        .call(
            None,
            "Target.activateTarget",
            json!({"targetId":tab.target}),
        )
        .await?;
    worker = run.worker(&tab, None, false).await?;
    inference_cases::run(run, &mut tab, &mut worker, cases).await?;
    inference_cases::no_plaintext(run, &tab, &worker, cases).await?;
    goal_cases::run(run, &tab, &mut worker, cases).await?;
    // twr-ggw.5 AC4, AC5: no plaintext secret in any storage, message, request or log, in both builds.
    run.collect(&tab).await?;
    run.collect(&served_tab).await?;
    let all_messages = auxiliary::leakage_messages(run);
    let console: Vec<String> = browser
        .events
        .lock()
        .expect("events lock")
        .iter()
        .filter_map(console_params)
        .map(Value::to_string)
        .collect();
    let displayed: std::collections::BTreeSet<String> = all_messages
        .iter()
        .filter_map(|m| {
            m.pointer("/from/seed_backup_display")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect();
    let displayed_inputs =
        semantic_domains::auxiliary::AuxiliaryDisplayedInputs::from_messages(&all_messages);
    let displayed_call = auxiliary::standalone(
        "reader.aux.main_displayed",
        displayed_inputs.preview_domain(),
    );
    let displayed_mnemonics: Vec<_> = displayed
        .iter()
        .enumerate()
        .flat_map(|(source_index, p)| {
            let _source_slot = semantic::Slot::new("reader.aux.main_displayed_row", source_index);
            reader::mnemonic_needles_at("reader.aux.call.main.displayed.mnemonic_needles", 0, p)
        })
        .collect();
    drop(displayed_call);
    let requests: Vec<Vec<u8>> = requests
        .iter()
        .flat_map(|r| r.lock().expect("requests lock").clone())
        .collect();
    for (name, page, passphrase, test_keys) in [
        (
            "no plaintext in the served build (twr-ggw.5 AC4, AC5, CNF-15, STG-10)",
            &served_tab,
            SERVED_PASSPHRASE,
            false,
        ),
        (
            "no plaintext in the tracer build (twr-ggw.5 AC4, AC5, CNF-15, STG-10)",
            &tab,
            PASSPHRASE,
            true,
        ),
    ] {
        let mut case = Case::new("main.c022", name);
        let dumped = run.dump_at("file.main.dump.016", page).await?;
        let opened = reader::read_at(
            "reader.call.main.leakage",
            &store_files(&dumped),
            passphrase,
        )?;
        reader_checks::set_auxiliary_inputs(
            opened.origin(),
            semantic_domains::auxiliary::auxiliary_raw_root(
                &opened.records,
                Some(&displayed_inputs),
            ),
        );
        let mut needles =
            reader::needles_at("reader.aux.call.main.leakage.needles", passphrase, &opened)?;
        add_inference_needles(run, &mut needles);
        // Independent of the helper: removing its call must break this search's control.
        case.check(
            "main.a101",
            "per-build search includes every aggregator needle",
            run.aggregator
                .needles()
                .iter()
                .all(|needle| needles.contains(needle)),
        );
        // Include seeds from earlier interrupted/replaced fixture stores, not only the final one.
        for (source_index, phrase) in displayed.iter().enumerate() {
            let _source_slot = semantic::Slot::new("reader.aux.main_displayed_seed", source_index);
            needles.extend(reader::seed_needles_at(
                "reader.aux.call.main.leakage.displayed_seed_needles",
                opened.origin(),
                phrase,
            )?);
        }
        if test_keys {
            needles.extend(reader::encodings(
                "SSH client key, private half",
                &reader::role_key_at(
                    "reader.aux.call.main.leakage.private_key_role_key",
                    opened.origin(),
                    &opened.mnemonic_at("reader.aux.call.main.leakage.private_key_mnemonic")?,
                    0,
                    0,
                )?,
            ));
        }
        needles.sort();
        needles.dedup();

        println!(
            "   {} files in OPFS, {} needles",
            dumped.len(),
            needles.len()
        );
        let in_files: Vec<String> = dumped
            .iter()
            .flat_map(|(path, bytes)| {
                reader::found(&needles, bytes)
                    .into_iter()
                    .map(move |w| format!("{path}: {w}"))
            })
            .collect();
        case.check(
            "main.a102",
            &format!("no OPFS file holds one: {in_files:?}"),
            in_files.is_empty() && !dumped.is_empty(),
        );
        let record_leaks: Vec<_> = opened
            .records
            .iter()
            .skip(1)
            .enumerate()
            .flat_map(|(source_index, (n, bytes))| {
                let _source_slot = semantic::Slot::new("reader.aux.main_record", source_index);
                reader::record_findings(
                    &needles,
                    bytes,
                    &opened
                        .seed_id_at("reader.aux.call.main.leakage.record_seed_id")
                        .expect("reader seed"),
                )
                .into_iter()
                .map(move |what| format!("record {n}: {what}"))
            })
            .collect();
        case.check(
            "main.a103",
            &format!("non-seed decrypted records carry no forbidden plaintext: {record_leaks:?}"),
            record_leaks.is_empty(),
        );
        let other = browser.evaluate(&page.session, OTHER_STORAGE).await?;
        println!("   other storage: {other}");
        case.check("main.a104",
            "local storage, session storage, IndexedDB and Cache Storage hold nothing, and no service worker is registered",
            other == json!({ "local": [], "session": [], "databases": [], "caches": [], "service_workers": 0 }),
        );
        let passphrases = [
            PASSPHRASE,
            WRONG_PASSPHRASE,
            HOST_PASSPHRASE,
            SERVED_PASSPHRASE,
            "fifteen chars!!",
        ];
        if test_keys {
            // Negative controls: the current machine client key, planted as binary in eleven shapes, a
            // passphrase outside a create or unlock message, three objects the serializer
            // cannot read and one it throws on, through the same guarded serializer, the same
            // log and the same check. Each must be reported for its own reason.
            let key = "binary: SSH client key, private half, raw".to_string();
            let mixed = format!("binary: the passphrase {passphrase:?}");
            let unreadable = |kind: &str| format!("unreadable: {kind}");
            let controls = [
                ("a Uint8Array", key.clone()),
                ("an ArrayBuffer", key.clone()),
                ("a Uint32Array nested in an object", key.clone()),
                (
                    "a passphrase in an unlock message that carries something else",
                    mixed,
                ),
                (
                    "a one-byte Uint8Array view over a buffer holding the key outside the view",
                    key.clone(),
                ),
                (
                    "a one-byte DataView over a buffer holding the key outside the view",
                    key.clone(),
                ),
                ("a Uint8Array as a Map's value", key.clone()),
                ("an ArrayBuffer in a Set", key.clone()),
                (
                    "a Uint8Array as an array's named property",
                    unreadable("Array with named properties"),
                ),
                ("a Blob", unreadable("Blob")),
                (
                    "an Error whose message is the passphrase",
                    unreadable("Error"),
                ),
                (
                    "a Uint8Array as a plain object's own enumerable __proto__ property",
                    key.clone(),
                ),
                (
                    "a Uint8Array in an array whose own iterator yields nothing",
                    key.clone(),
                ),
                (
                    "a Uint8Array as the value of a Map whose own iterator yields nothing",
                    key.clone(),
                ),
                (
                    "an ArrayBuffer in a Set whose own iterator yields nothing",
                    key,
                ),
                (
                    "an object whose getter throws in the serializer",
                    unreadable("unserializable"),
                ),
            ];
            let planted = browser
                .evaluate(
                    &page.session,
                    &format!(
                        "(() => {{
                            const key = () => Uint8Array.from(atob('{}'), (c) => c.charCodeAt(0));
                            const outside = () => {{
                                const bytes = new Uint8Array(key().length + 8);
                                bytes.set(key(), 8);
                                return bytes.buffer;
                            }};
                            const empty = (value) => {{
                                value[Symbol.iterator] = function* () {{}};
                                return value;
                            }};
                            const passphrase = {};
                            const log = window.__tracerMessages;
                            const plain = log.plain;
                            const each = (f) => {{
                                try {{
                                    return f();
                                }} catch {{
                                    return {{ threw: true }};
                                }}
                            }};
                            // Synchronous: no worker message is logged between the push
                            // and the splice, which returns exactly the planted controls.
                            const start = log.length;
                            log.push(...[
                                () => ({{ from: plain(key()) }}),
                                () => ({{ from: plain(key().buffer) }}),
                                () => ({{ from: plain({{ store: {{ nested: [new Uint32Array(key().buffer)] }} }}) }}),
                                () => ({{ to: plain({{ unlock: new TextEncoder().encode(passphrase), also: true }}) }}),
                                () => ({{ to: plain({{ unlock: new Uint8Array(outside(), 0, 1) }}) }}),
                                () => ({{ from: plain({{ store: new DataView(outside(), 0, 1) }}) }}),
                                () => ({{ from: plain({{ m: new Map([['k', key()]]) }}) }}),
                                () => ({{ from: plain({{ s: new Set([key().buffer]) }}) }}),
                                () => ({{ from: plain({{ store: Object.assign([1], {{ k: key() }}) }}) }}),
                                () => ({{ from: plain({{ store: new Blob(['x']) }}) }}),
                                () => ({{ from: plain({{ error: new Error(passphrase) }}) }}),
                                () => ({{ from: plain({{ store: Object.defineProperty({{}}, '__proto__', {{
                                    value: key(), enumerable: true, writable: true, configurable: true,
                                }}) }}) }}),
                                () => ({{ from: plain({{ store: empty([key()]) }}) }}),
                                () => ({{ from: plain({{ m: empty(new Map([['k', key()]])) }}) }}),
                                () => ({{ from: plain({{ s: empty(new Set([key().buffer])) }}) }}),
                                () => ({{ from: plain({{ store: {{ get k() {{ throw new Error('k'); }} }} }}) }}),
                            ].map(each));
                            return log.splice(start);
                        }})()",
                        STANDARD.encode(reader::role_key_at("reader.aux.call.main.leakage.serializer_role_key", opened.origin(), &opened.mnemonic_at("reader.aux.call.main.leakage.serializer_mnemonic")?, 0, 0)?),
                        serde_json::to_string(passphrase).expect("a JSON string"),
                    ),
                )
                .await?;
            let planted = planted.as_array().cloned().unwrap_or_default();
            println!("   planted messages: {planted:?}");
            case.check("main.a105",
                "the __proto__ control comes back from __tracerMessages through the DevTools protocol as a member named __proto__",
                planted
                    .get(11)
                    .and_then(|m| m.pointer("/from/store/__proto__"))
                    .is_some(),
            );
            for (i, (control, expected)) in controls.iter().enumerate() {
                let reported = planted
                    .get(i)
                    .map(|m| findings(m, &needles, &passphrases, &displayed_mnemonics).1)
                    .unwrap_or_default();
                println!("   {control}: reported {reported:?}");
                case.check(
                    "main.a106",
                    &format!("negative control, {control}: reported {expected}"),
                    reported.contains(expected),
                );
            }
        }
        // The same guarded serializer and check handle control mnemonics and the final seed.
        // Sessions end with the harness worker; goals and tools run in it.
        for mnemonic in
            std::iter::once(opened.mnemonic_at("reader.aux.call.main.leakage.custody_mnemonic")?)
                .chain(
                    include_str!("../../tests/vectors/seed-backup-collisions.txt")
                        .lines()
                        .map(str::to_string),
                )
        {
            let planted = browser
                .evaluate(
                    &page.session,
                    &format!(
                        r#"(() => {{
                const log=window.__tracerMessages, plain=log.plain;
                const phrase={}, words=phrase.split(' '), start=log.length;
                log.push({{from:plain({{other:phrase}})}}, {{from:plain({{other:words}})}},
                    {{from:plain({{seed_backup_reentry:new TextEncoder().encode(phrase)}})}},
                    {{from:plain({{other:new TextEncoder().encode(phrase)}})}});
                return log.splice(start);
            }})()"#,
                        json!(mnemonic)
                    ),
                )
                .await?;
            for (index, message) in planted
                .as_array()
                .ok_or("seed custody controls missing")?
                .iter()
                .enumerate()
            {
                let expected = match index {
                    0 => "text: the mnemonic, raw",
                    1 => "text: the mnemonic word array",
                    _ => "binary: the mnemonic, raw",
                };
                case.check(
                    "main.a107",
                    &format!("seed custody negative control {index}: {expected}"),
                    findings(message, &needles, &passphrases, &displayed_mnemonics)
                        .1
                        .iter()
                        .any(|s| s == expected),
                );
            }
        }
        for (name, bytes, expected) in [
            (
                "passphrase in re-entry shape",
                passphrase.as_bytes().to_vec(),
                "binary: the passphrase, raw",
            ),
            (
                "data key hex in re-entry shape",
                hex::encode(opened.data_key).into_bytes(),
                "binary: the data key, hex",
            ),
            (
                "earlier store seed id hex",
                reader::seed_id_at(
                    "reader.aux.call.main.leakage.earlier_seed_id",
                    opened.origin(),
                    displayed
                        .iter()
                        .enumerate()
                        .find(|(source_index, p)| {
                            let _source_slot =
                                semantic::Slot::new("reader.aux.main_search", *source_index);
                            ***p != opened
                                .mnemonic_at("reader.aux.call.main.leakage.earlier_search_mnemonic")
                                .unwrap()
                        })
                        .map(|(_, phrase)| phrase)
                        .ok_or("no earlier seed")?,
                )?
                .into_bytes(),
                "binary: the seed identifier, raw",
            ),
        ] {
            let kind = if name.contains("earlier") {
                "other"
            } else {
                "seed_backup_reentry"
            };
            let planted = browser
                .evaluate(
                    &page.session,
                    &format!(
                        r#"(() => {{
                const log=window.__tracerMessages, plain=log.plain, start=log.length;
                log.push({{to:plain({{[{}]:Uint8Array.from(atob({}),c=>c.charCodeAt(0))}})}});
                return log.splice(start)[0];
            }})()"#,
                        json!(kind),
                        json!(STANDARD.encode(bytes))
                    ),
                )
                .await?;
            case.check(
                "main.a108",
                &format!("negative control: {name} is reported"),
                findings(&planted, &needles, &passphrases, &displayed_mnemonics)
                    .1
                    .iter()
                    .any(|s| s == expected),
            );
        }
        for (name, secret) in [
            (
                "mnemonic",
                opened.mnemonic_at("reader.aux.call.main.leakage.console_mnemonic")?,
            ),
            ("passphrase", passphrase.to_string()),
        ] {
            let start = browser.events.lock().expect("events lock").len();
            browser
                .evaluate(
                    &page.session,
                    &format!("console.log({{[{}]:1}})", json!(secret)),
                )
                .await?;
            let events = browser.events.lock().expect("events lock");
            let reported = events[start..]
                .iter()
                .filter_map(console_params)
                .any(|p| !reader::found(&needles, p.to_string().as_bytes()).is_empty());
            case.check(
                "main.a109",
                &format!(
                    "negative control: console object property name holding {name} is reported"
                ),
                reported,
            );
        }
        let mut carrying = Vec::new();
        let mut leaking = Vec::new();
        for message in &all_messages {
            match findings(message, &needles, &passphrases, &displayed_mnemonics) {
                (Some(carried), _) => carrying.push(carried),
                (None, found) if !found.is_empty() => {
                    leaking.push(format!("{message}: {found:?}"));
                }
                _ => {}
            }
        }
        case.check("main.a110",
            &format!("the passphrase reaches the worker only in create, unlock or re-display messages: {} such messages", carrying.len()),
            carrying.iter().any(|p| p == passphrase) && leaking.is_empty(),
        );
        if !leaking.is_empty() {
            println!("   messages carrying a secret: {leaking:?}");
        }
        case.check(
            "main.a111",
            "outside the exact seed-backup display, no worker message carries secret plaintext",
            all_messages
                .iter()
                .filter(|m| m.get("from").is_some())
                .all(|m| {
                    findings(m, &needles, &passphrases, &displayed_mnemonics)
                        .1
                        .is_empty()
                }),
        );
        case.check(
            "main.a112",
            &format!(
                "the passphrase fields were empty after every submit: {:?}",
                run.uncleared.borrow()
            ),
            run.uncleared.borrow().is_empty(),
        );
        let in_requests: Vec<_> = requests
            .iter()
            .flat_map(|r| reader::found(&needles, r))
            .collect();
        case.check("main.a113",
            &format!("the HTTPS fixtures' request lines and bodies hold none ({} requests): {in_requests:?}", requests.len()),
            in_requests.is_empty() && !requests.is_empty(),
        );
        let in_console: Vec<_> = console
            .iter()
            .flat_map(|c| reader::found(&needles, c.as_bytes()))
            .collect();
        case.check(
            "main.a114",
            &format!("the console and log messages hold none: {in_console:?}"),
            in_console.is_empty()
                && console
                    .iter()
                    .all(|c| !passphrases.iter().any(|p| c.contains(p))),
        );
        case.finish(cases);
    }

    let both = cases[case_4].failures.is_empty()
        && cases[case_1_in_this_session].failures.is_empty()
        && *run.same_browser.borrow();
    println!(
        "\ncase 4 and case 1 in the same browser session: {}",
        if both {
            "both passed"
        } else {
            "not both passed"
        }
    );
    *run.same_browser.borrow_mut() = both;
    if completion::rejects("main.same_browser.policy_and_command", !both) {
        return Err("required same-browser policy/command relation failed".into());
    }
    Ok(())
}

/// `value` with every binary payload the hook recorded replaced by null, and those payloads'
/// bytes and the kinds of the objects it could not read, at any depth.
fn binaries(value: &Value, payloads: &mut Vec<Vec<u8>>, opaque: &mut Vec<String>) -> Value {
    match value {
        Value::Object(o) if o.len() == 1 && o.contains_key("__tracerOpaque") => {
            let kind = &o["__tracerOpaque"];
            opaque.push(
                kind.as_str()
                    .map_or_else(|| kind.to_string(), str::to_string),
            );
            value.clone()
        }
        Value::Object(o)
            if o.len() == 1 && o.get("__tracerBinary").is_some_and(Value::is_string) =>
        {
            let text = o["__tracerBinary"].as_str().unwrap_or_default();
            payloads.push(
                STANDARD
                    .decode(text)
                    .unwrap_or_else(|_| text.as_bytes().to_vec()),
            );
            Value::Null
        }
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| (k.clone(), binaries(v, payloads, opaque)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(|v| binaries(v, payloads, opaque)).collect()),
        v => v.clone(),
    }
}

/// What a recorded message carries: every needle in its text and in each binary payload's bytes,
/// every one of `passphrases` in either, and every object the hook could not read. The one
/// create or unlock message, exactly
/// `{"to": {"create" or "unlock": <a passphrase's UTF-8 bytes>}}`, carries its passphrase and
/// is no finding.
fn findings(
    message: &Value,
    needles: &[(String, Vec<u8>)],
    passphrases: &[&str],
    displayed_mnemonics: &[(String, Vec<u8>)],
) -> (Option<String>, Vec<String>) {
    let mut payloads = Vec::new();
    let mut opaque = Vec::new();
    let rest = binaries(message, &mut payloads, &mut opaque);
    if let [bytes] = payloads.as_slice()
        && ["create", "unlock", "seed_backup_redisplay"]
            .iter()
            .any(|kind| rest == json!({ "to": { *kind: null } }))
        && let Some(carried) = passphrases
            .iter()
            .find(|p| p.as_bytes() == bytes.as_slice())
    {
        return (Some(carried.to_string()), Vec::new());
    }
    let display = message.as_object().is_some_and(|o| o.len() == 1)
        && message
            .get("from")
            .and_then(Value::as_object)
            .is_some_and(|o| {
                o.len() == 1
                    && o.get("seed_backup_display")
                        .and_then(Value::as_str)
                        .is_some_and(|phrase| {
                            displayed_mnemonics.iter().any(|(what, bytes)| {
                                what == "the mnemonic, raw" && bytes == phrase.as_bytes()
                            })
                        })
            });
    let reentry = matches!(payloads.as_slice(), [bytes] if std::str::from_utf8(bytes).is_ok())
        && rest == json!({"to":{"seed_backup_reentry":null}});
    let filtered;
    let needles = if display || reentry {
        filtered = needles
            .iter()
            .filter(|n| !(n.0.starts_with("the mnemonic") && displayed_mnemonics.contains(n)))
            .cloned()
            .collect::<Vec<_>>();
        &filtered
    } else {
        needles
    };
    let has = |bytes: &[u8], p: &str| bytes.windows(p.len()).any(|w| w == p.as_bytes());
    let text = rest.to_string();
    let mut found: Vec<String> = reader::found(needles, text.as_bytes())
        .into_iter()
        .map(|w| format!("text: {w}"))
        .chain(opaque.iter().map(|kind| format!("unreadable: {kind}")))
        .collect();
    found.extend(
        passphrases
            .iter()
            .filter(|p| has(text.as_bytes(), p))
            .map(|p| format!("text: the passphrase {p:?}")),
    );
    for bytes in &payloads {
        found.extend(
            reader::found(needles, bytes)
                .into_iter()
                .map(|w| format!("binary: {w}")),
        );
        found.extend(
            passphrases
                .iter()
                .filter(|p| has(bytes, p))
                .map(|p| format!("binary: the passphrase {p:?}")),
        );
    }
    (None, found)
}

#[test]
fn seed_backup_exceptions_exempt_only_displayed_mnemonics() {
    let controls: Vec<_> = include_str!("../../tests/vectors/seed-backup-collisions.txt")
        .lines()
        .collect();
    let displayed = reader::mnemonic_needles(controls[0]);
    let mut needles = reader::seed_needles(controls[0]).unwrap();
    needles.extend(reader::seed_needles(controls[1]).unwrap());
    needles.extend(reader::encodings("the data key", &[42; 32]));
    needles.extend(reader::encodings("the passphrase", PASSPHRASE.as_bytes()));
    let binary =
        |text: &str| json!({"to":{"seed_backup_reentry":{"__tracerBinary":STANDARD.encode(text)}}});
    for message in [
        json!({"from":{"seed_backup_display":controls[0]}}),
        binary(controls[0]),
    ] {
        assert!(
            findings(&message, &needles, &[PASSPHRASE], &displayed)
                .1
                .is_empty()
        );
    }
    for (message, expected) in [
        (binary(PASSPHRASE), "binary: the passphrase, raw"),
        (binary(&hex::encode([42; 32])), "binary: the data key, hex"),
        (
            binary(&reader::seed_id(controls[1]).unwrap()),
            "binary: the seed identifier, raw",
        ),
        (binary(controls[1]), "binary: the mnemonic, raw"),
    ] {
        assert!(
            findings(&message, &needles, &[PASSPHRASE], &displayed)
                .1
                .iter()
                .any(|f| f == expected)
        );
    }
    // Even if another forbidden secret equals the allowed display, it remains a finding.
    let mut overlap = needles.clone();
    overlap.push((
        "the passphrase, raw".into(),
        controls[0].as_bytes().to_vec(),
    ));
    assert!(
        findings(
            &json!({"from":{"seed_backup_display":controls[0]}}),
            &overlap,
            &[],
            &displayed
        )
        .1
        .iter()
        .any(|f| f == "text: the passphrase, raw")
    );
}

/// What a lock of any kind must leave: the old worker gone and one new one, the page offering
/// Unlock, every request refused before any contact, and after an unlock the replayed state as
/// it was (`before`).
async fn relocked(
    run: &Run<'_>,
    case: &mut Case,
    tab: &Tab,
    old: &Worker,
    worker: &mut Worker,
    before: &Value,
    request: &Value,
) -> Result<(), String> {
    let targets = run.harness_targets(&tab.origin).await?;
    println!(
        "   harness worker count: {}, old target present: {}",
        targets.len(),
        targets.contains(&old.target)
    );
    case.check(
        "main.a115",
        "the old worker target is gone, and one new harness worker exists",
        targets.len() == 1 && !targets.contains(&old.target) && targets.contains(&worker.target),
    );
    let view = run.settled(tab, false).await?;
    case.check(
        "main.a116",
        "the page offers Unlock, and nothing else",
        view["store"] == "locked"
            && view["unlock"] == true
            && view["create"] == false
            && view["lock"] == false,
    );
    take(run.seen);
    let report = run
        .harness_run("main.rs#22", worker, request.clone())
        .await?;
    let observed = take(run.seen);
    case.check(
        "main.a117",
        "a command is refused while locked, with no TCP connection at the relay",
        report == json!({ "outcome": { "refused": "locked" } }) && observed.relay_accepted == 0,
    );
    let report = run
        .harness_collect("main.rs#23", worker, request.clone())
        .await?;
    let observed = take(run.seen);
    case.check(
        "main.a118",
        "collection is refused after lock without contact or evidence",
        report == json!({"outcome":{"refused":"locked"}})
            && observed.relay_accepted == 0
            && observed.ssh_connections == 0
            && run.inspect(worker).await?["locked"] == true,
    );
    let view = run.submit(tab, "unlock", PASSPHRASE).await?;
    let replayed = run.inspect(worker).await?;
    println!("   replayed: {replayed}");
    case.check(
        "main.a119",
        "after unlock, the replayed state lists every command recorded before",
        view["store"] == "unlocked"
            && replayed == {
                let mut expected = before.clone();
                expected["sessions"] = json!([]);
                expected
            },
    );
    binding_cases::prepare(run, tab, worker, PASSPHRASE).await?;
    Ok(())
}

/// Explicit continuing disposition between independent browser fixtures.
async fn settle_unresolved(
    site: &'static str,
    run: &Run<'_>,
    tab: &Tab,
    worker: Worker,
) -> Result<Worker, String> {
    let calls = settle_inputs::inspect(site, run, tab, &worker).await?;
    if calls.is_empty() {
        return Ok(worker);
    }
    let files = store_files(&run.dump_at("file.main.dump.017", tab).await?);
    let opened = reader::read_at(
        "reader.call.settle_unresolved.disposition_source",
        &files,
        PASSPHRASE,
    )?;
    let mut events: Vec<Value> = opened
        .records
        .iter()
        .map(|(_, p)| serde_json::from_slice(p).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    events.push(calls.disposition());
    run.put(
        tab,
        &reader::build_at("file.main.build.008", PASSPHRASE, &events),
    )
    .await?;
    let mut worker = run.reload("main.rs::reload#18", tab, &worker).await?;
    run.submit(tab, "unlock", PASSPHRASE).await?;
    binding_cases::prepare(run, tab, &mut worker, PASSPHRASE).await?;
    Ok(worker)
}

/// Runs `LOCK_COMMAND`, locks by `how` once the sshd has its `exec`, and checks the connection ended: the relay fixture sees the client's WebSocket close and the sshd its
/// connection end; then `relocked`, and the running command, in the replayed state, is never sent
/// again. The new worker.
async fn lock_during_command(
    run: &Run<'_>,
    case: &mut Case,
    tab: &Tab,
    worker: Worker,
    args: &dyn Fn(&str) -> Value,
    how: &str,
    lock_expression: &str,
) -> Result<(Worker, Value), String> {
    let _observation = observer::Call::begin(
        "main.lock.command",
        "main.lock_command",
        Some(&tab.session),
        json!({"transition":how}),
    );
    let worker = settle_unresolved("settle.main.004", run, tab, worker).await?;
    take(run.seen);
    fresh_pace(run.relay);
    let mut running = args("fixture");
    running["command"] = LOCK_COMMAND.into();
    let exec_input = fixture_inputs::static_wait(run, &worker, &case.id, "exec");
    let socket_input = fixture_inputs::static_wait(run, &worker, &case.id, "socket");
    fixture_inputs::static_start(
        &exec_input,
        Some(&socket_input),
        run,
        &worker,
        running.clone(),
    )
    .await?;
    let received = settle_for(
        "main.lock_command.exec",
        run.seen,
        20,
        json!({"command":"lock_command"}),
        |s, observation| fixture_predicates::exec(s, LOCK_COMMAND, &exec_input, observation),
    )
    .await;
    case.check(
        "main.a120",
        &format!("{how}: the sshd received the running command's exec"),
        received,
    );
    let before = run.inspect(&worker).await?;
    let numbers = before["commands"].as_array().cloned().unwrap_or_default();
    case.check(
        "main.a121",
        &format!("{how}: it was recorded before it was sent"),
        numbers
            .last()
            .is_some_and(|c| c["command"] == hex::encode(LOCK_COMMAND))
            && before["calls"]
                .as_array()
                .and_then(|calls| calls.last())
                .is_some_and(|c| c["state"] == "unresolved"),
    );
    let lock_result =
        fixture_inputs::page_transition(&socket_input, run, tab, &worker, lock_expression).await?;
    let mut new = match run.worker(tab, Some(&worker), false).await {
        Ok(new) => new,
        Err(e) => {
            case.check(
                "main.a122",
                &format!("{how}: the page ended the harness worker and started a new one ({e})"),
                false,
            );
            return Ok((worker, lock_result));
        }
    };
    let gone = settle_for(
        "main.lock_command.socket_closed",
        run.seen,
        20,
        json!({}),
        |s, observation| fixture_predicates::socket(s, true, &socket_input, observation),
    )
    .await;
    let ended = run
        .sshd
        .all_ended_at(Some("main.lock_command.ssh_closed"), json!({}))
        .await;
    let observed = take(run.seen);
    show(&observed);
    case.check("main.a123",
        &format!("{how}: the relay fixture saw the client's WebSocket close, and the sshd its connection end"),
        gone && ended,
    );
    relocked(run, case, tab, &worker, &mut new, &before, &args("fixture")).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let observed = take(run.seen);
    case.check("main.a124",
        &format!(
            "{how}: the running command is in the replayed state, and the sshd received no second exec"
        ),
        observed.ssh_exec.is_empty() && observed.relay_accepted == 0,
    );
    Ok((new, lock_result))
}
