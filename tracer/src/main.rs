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
//! tracer check-absence <dir>             AC5: no test key, pin source or test switch
//! tracer check-csp <dir>                 AC6: the page's policy is exactly ARC-33's
//! ```
//!
//! `scripts/tracer.sh` builds both directories and runs the first.

mod cdp;
mod checks;
mod fixtures;
mod keys;
#[cfg(test)]
mod matrix;
mod reader;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use fixtures::{Event, Observed, Seen};
use reader::Files;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};
use tau_web::testonly::{PINS, RELAY_SECRET, SSH_CLIENT_SEED, SSH_USER};

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
/// A command the fixture sshd receives and never answers: a command in flight at a lock.
const HELD: &str = "sleep infinity # tau-web tracer: held in flight";

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
            hold: HELD,
        },
    )
    .await;
    // The test relay key's pass: the sshd's host, on any port, for an hour (PAS-6, paid-tcp-relay
    // 844e834: a hand-recorded pass is never unbounded).
    let pass = fixtures::Pass {
        key: keys::relay_public(&RELAY_SECRET),
        hosts: vec!["127.0.0.1".into()],
        expires: SystemTime::now() + Duration::from_secs(3600),
    };
    let relay = fixtures::relay(seen.clone(), tls.acceptor.clone(), vec![pass], false).await;
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

    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"));
    std::fs::create_dir_all(&target).map_err(|e| format!("{}: {e}", target.display()))?;
    let profile = target.join(format!("tracer-chrome-{}", std::process::id()));
    let browser = cdp::Browser::launch(&chrome, profile, &tls.spki_sha256).await?;
    let context = Run {
        browser: &browser,
        seen: &seen,
        sshd: &sshd,
        relay: &relay,
        messages: RefCell::default(),
        uncleared: RefCell::default(),
    };
    let mut cases = Vec::new();
    let outcome = run_cases(
        &context,
        &served_origin,
        &tracer_origin,
        &served_policy,
        &[&served_requests, &tracer_requests],
        &mut cases,
    )
    .await;
    browser.close().await;

    // The summary names every case that ran, even when one stopped the run.
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
    if let Err(e) = outcome {
        Err(format!(
            "the run stopped after {} cases: {e}; cases failed: {}",
            cases.len(),
            failed.join(", ")
        ))
    } else if failed.is_empty() {
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

/// Waits up to `seconds` until `holds` holds of what the fixtures have observed so far.
async fn settle_for(seen: &Observed, seconds: u64, holds: impl Fn(&Seen) -> bool) -> bool {
    for _ in 0..seconds * 20 {
        if holds(&seen.lock().expect("observations lock")) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Waits up to 5 s until `holds` holds of what the fixtures have observed so far.
async fn settle(seen: &Observed, holds: impl Fn(&Seen) -> bool) {
    settle_for(seen, 5, holds).await;
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
    const $ = (id) => document.getElementById(id);
    return {
        status: $('status').dataset.state ?? '',
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
const DUMP: &str = "(async () => {
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
})()";

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
#[derive(Clone, Debug, PartialEq)]
struct Worker {
    session: String,
    target: String,
}

/// The browser, the fixtures, and what the tracer gathers across cases.
struct Run<'a> {
    browser: &'a cdp::Browser,
    seen: &'a Observed,
    sshd: &'a fixtures::Sshd,
    relay: &'a fixtures::Relay,
    /// Every message between a page and its harness workers, gathered before each reload or
    /// close and at the end.
    messages: RefCell<Vec<Value>>,
    /// Submits after which a passphrase field still held text.
    uncleared: RefCell<Vec<String>>,
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
        for method in ["Page.enable", "Runtime.enable", "Log.enable"] {
            self.browser.call(Some(&session), method, json!({})).await?;
        }
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
                json!({ "autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true }),
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
        for _ in 0..300 {
            if let [worker] = self.live_workers(tab).as_slice()
                && Some(worker) != old
            {
                self.browser
                    .call(Some(&worker.session), "Runtime.enable", json!({}))
                    .await?;
                self.settled(tab, in_use).await?;
                return Ok(worker.clone());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(format!(
            "{}: no new harness worker in 30 s ({:?})",
            tab.origin,
            self.live_workers(tab)
        ))
    }

    async fn view(&self, tab: &Tab) -> Result<Value, String> {
        self.browser.evaluate(&tab.session, VIEW).await
    }

    /// Waits up to 30 s for the page to report its worker ready and its store a state that is
    /// not transient; the page's view. The store is in use elsewhere for a moment after a
    /// reload, while the old document's worker still holds the lock, so that state counts only
    /// with `in_use`.
    async fn settled(&self, tab: &Tab, in_use: bool) -> Result<Value, String> {
        let mut view = Value::Null;
        for _ in 0..300 {
            view = self.view(tab).await?;
            if view["status"] == "failed" {
                return Err(format!("{}: {view}", tab.origin));
            }
            let state = view["store"].as_str().unwrap_or_default();
            let transient =
                ["starting", "working", ""].contains(&state) || (state == "in-use" && !in_use);
            if view["status"] == "ready" && !transient {
                return Ok(view);
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
    async fn submit(&self, tab: &Tab, kind: &str, passphrase: &str) -> Result<Value, String> {
        let passphrase = serde_json::to_string(passphrase).expect("a JSON string");
        let left = self
            .browser
            .evaluate(
                &tab.session,
                &format!(
                    "(() => {{
                        const $ = (id) => document.getElementById(id);
                        $('passphrase').value = {passphrase};
                        $('confirm').value = {passphrase};
                        $('{kind}').click();
                        return [$('passphrase').value, $('confirm').value];
                    }})()"
                ),
            )
            .await?;
        if left != json!(["", ""]) {
            self.uncleared.borrow_mut().push(format!("{kind}: {left}"));
        }
        let view = self.settled(tab, false).await?;
        println!("   {kind}: {}", view["text"]);
        Ok(view)
    }

    /// The replayed state, read in the worker's own context.
    async fn inspect(&self, worker: &Worker) -> Result<Value, String> {
        self.browser
            .evaluate(
                &worker.session,
                "(async () => {
                    const module = await import(new URL('./pkg/tau_web.js', self.location.href).href);
                    return JSON.parse(await module.store_state());
                })()",
            )
            .await
    }

    /// Has the harness worker run one command, and returns its report. The page offers no way
    /// to: this evaluates in the worker's own context, over its DevTools session, and calls
    /// `run_command` on the module the worker already loaded (the same URL, so the same
    /// initialized module).
    async fn harness_run(&self, worker: &Worker, args: Value) -> Result<Value, String> {
        let report = self
            .browser
            .evaluate(&worker.session, &run_expression(&args))
            .await?;
        println!("   harness reported: {report}");
        Ok(report)
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
    async fn reload(&self, tab: &Tab, old: &Worker) -> Result<Worker, String> {
        self.collect(tab).await?;
        self.browser
            .call(Some(&tab.session), "Page.reload", json!({}))
            .await?;
        self.worker(tab, Some(old), false).await
    }

    /// The origin's private file system, every file by path.
    async fn dump(&self, tab: &Tab) -> Result<Files, String> {
        let dumped = self.browser.evaluate(&tab.session, DUMP).await?;
        dumped
            .as_object()
            .ok_or("no dump")?
            .iter()
            .map(|(path, b64)| {
                let bytes = STANDARD
                    .decode(b64.as_str().unwrap_or_default())
                    .map_err(|e| format!("{path}: {e}"))?;
                Ok((path.clone(), bytes))
            })
            .collect()
    }

    /// Replaces the store's directory with `files`, by name.
    async fn put(&self, tab: &Tab, files: &Files) -> Result<(), String> {
        let files: serde_json::Map<String, Value> = files
            .iter()
            .map(|(name, bytes)| (name.clone(), STANDARD.encode(bytes).into()))
            .collect();
        self.browser
            .evaluate(
                &tab.session,
                &format!(
                    "(async (files) => {{
                        const root = await navigator.storage.getDirectory();
                        await root.removeEntry('tau-web-store', {{ recursive: true }}).catch(() => {{}});
                        const directory = await root.getDirectoryHandle('tau-web-store', {{ create: true }});
                        for (const [name, b64] of Object.entries(files)) {{
                            const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
                            const writable = await (await directory.getFileHandle(name, {{ create: true }})).createWritable();
                            await writable.write(bytes);
                            await writable.close();
                        }}
                        return true;
                    }})({})",
                    Value::Object(files)
                ),
            )
            .await
            .map(|_| ())
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

/// The store's files from a dump of the whole file system.
fn store_files(dumped: &Files) -> Files {
    dumped
        .iter()
        .filter_map(|(path, bytes)| Some((path.strip_prefix(STORE)?.to_string(), bytes.clone())))
        .collect()
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

async fn run_cases(
    run: &Run<'_>,
    served_origin: &str,
    tracer_origin: &str,
    served_policy: &str,
    requests: &[&fixtures::Requests],
    cases: &mut Vec<Case>,
) -> Result<(), String> {
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
            "port": sshd.port,
            "user": SSH_USER,
            "command": COMMAND,
            "fail_append": false,
            "tamper_auth": false,
            "test_relay_key": "with-pass",
        })
    };
    let locked = json!({ "outcome": { "refused": "locked" } });

    // The served build loads, and its harness worker runs a request on what it has stored.
    let mut case = Case::new("the served build loads, and holds no pin, key or request hook");
    let from = browser.event_count();
    let (served_tab, served_worker) = run.open(served_origin, false).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let errors = errors_since(
        browser,
        from,
        &[&served_tab.session, &served_worker.session],
    );
    println!("   errors reported: {errors:?}");
    case.check("the harness worker reported ready", true);
    case.check(
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
    case.check(
        "the page defines no request hook: typeof window.tauWeb is \"undefined\", and no global holds the worker",
        globals == json!({ "tauWeb": "undefined", "workers": [] }),
    );
    let view = run.view(&served_tab).await?;
    case.check(
        "with no store, the page offers Create and nothing else",
        view["store"] == "none"
            && view["create"] == true
            && view["unlock"] == false
            && view["lock"] == false,
    );
    take(seen);
    let report = run.harness_run(&served_worker, args("fixture")).await?;
    let observed = take(seen);
    case.check(
        "with no unlocked store, the served harness refuses before any contact (STA-23)",
        report == locked && observed.relay_accepted == 0 && observed.ssh_connections == 0,
    );
    let view = run.submit(&served_tab, "create", SERVED_PASSPHRASE).await?;
    case.check(
        "a store is created in the served build, and the page offers Lock",
        view["store"] == "unlocked" && view["lock"] == true,
    );
    let report = run.harness_run(&served_worker, args("fixture")).await?;
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
    case.check(
        "nothing was appended: the store holds the seed record alone",
        run.inspect(&served_worker).await?["records"] == json!([0]),
    );
    cases.push(case);

    // The tracer build: a store created in the browser, read by the independent reader; and a
    // store the reader built, unlocked in the browser.
    let (mut tab, mut worker) = run.open(tracer_origin, false).await?;
    let mut case = Case::new("create and unlock (twr-ggw.5, CNF-82)");
    let view = run.view(&tab).await?;
    case.check(
        "with no store, the page offers Create, stating the 16-character minimum and a password manager",
        view["store"] == "none"
            && view["create"] == true
            && browser
                .evaluate(&tab.session, "document.getElementById('create-help').textContent")
                .await?
                .as_str()
                .is_some_and(|t| t.contains("at least 16 characters") && t.contains("password manager")),
    );
    let short = run.submit(&tab, "create", "fifteen chars!!").await?;
    case.check(
        "a passphrase of 15 characters is refused, and Create is still offered",
        short["store"] == "none"
            && short["create"] == true
            && short["text"]
                .as_str()
                .is_some_and(|t| t.contains("at least 16")),
    );
    let view = run.submit(&tab, "create", PASSPHRASE).await?;
    case.check(
        "the store is created and unlocked",
        view["store"] == "unlocked",
    );
    let created = store_files(&run.dump(&tab).await?);
    let opened = reader::read(&created, PASSPHRASE);
    case.check(
        "the independent reader reads the browser-written store: the envelope, then record 0, the seed",
        opened.as_ref().is_ok_and(|o| {
            o.records.len() == 1 && o.mnemonic().is_ok_and(|m| reader::seed_secrets(&m).is_ok())
        }),
    );
    if let Err(e) = &opened {
        println!("   the reader: {e}");
    }
    case.check(
        "the worker's replayed state is record 0 alone",
        run.inspect(&worker).await?
            == json!({ "state": "unlocked", "locked": false, "records": [0], "commands": [], "calls": [], "terminals": [], "dispositions": [], "standing": {} }),
    );
    let host = reader::build(
        HOST_PASSPHRASE,
        &[
            json!({ "seed": { "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" } }),
            json!({ "command": { "machine": "fixture", "command": hex::encode("built on the host") } }),
        ],
    );
    run.put(&tab, &host).await?;
    worker = run.reload(&tab, &worker).await?;
    let view = run.submit(&tab, "unlock", HOST_PASSPHRASE).await?;
    case.check(
        "a store the independent reader built unlocks in the browser: WebCrypto's PBKDF2 agrees with the host's",
        view["store"] == "unlocked",
    );
    case.check(
        "and replays: its command reads back under its number",
        run.inspect(&worker).await?["commands"]
            == json!([{ "number": 1, "machine": "fixture", "command": hex::encode("built on the host") }]),
    );
    case.check(
        "the unlock wrote nothing",
        store_files(&run.dump(&tab).await?) == host,
    );
    run.put(&tab, &created).await?;
    worker = run.reload(&tab, &worker).await?;
    let view = run.submit(&tab, "unlock", PASSPHRASE).await?;
    case.check(
        "the browser's store, put back, unlocks again",
        view["store"] == "unlocked" && run.inspect(&worker).await?["records"] == json!([0]),
    );
    cases.push(case);

    // Case 4 (AC6): the policy Chrome loaded is the served page's, and it is enforced.
    let mut case = Case::new("4. the page runs under ARC-33's policy (AC6)");
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
    let page_ws = browser.evaluate(&tab.session, socket_probe).await?;
    let worker_ws = browser.evaluate(&worker.session, socket_probe).await?;
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
    let report = run.harness_run(&worker, args("unpinned")).await?;
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
    let report = run.harness_run(&worker, tampered).await?;
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
    fresh_pace(relay);
    let report = run.harness_run(&worker, args("fixture")).await?;
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
        "the journal holds that one new entry",
        report["journal_entries"] == json!([hex::encode(COMMAND)]),
    );
    let replayed = run.inspect(&worker).await?;
    case.check(
        "the store's replayed state holds it as record 1",
        replayed["records"] == json!([0, 1, 2])
            && replayed["commands"]
                == json!([{ "number": 1, "machine": "fixture", "command": hex::encode(COMMAND) }])
            && outcome["seq"] == 1
            && outcome["terminal"] == 2
            && replayed["calls"][0]["approval"]["harness_pin"]["machine"] == "fixture"
            && replayed["calls"][0]["approval"]["harness_pin"]["fingerprint"] == pinned.as_str()
            && replayed["calls"][0]["state"] == "finished"
            && replayed["terminals"]
                == json!([{ "number": 2, "call": 1, "exit_status": EXIT_STATUS }]),
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
    let logs = observed.relay_logs();
    case.check(
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
    let before_failure = run.inspect(&worker).await?;
    let report = run.harness_run(&worker, failing).await?;
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

    // twr-ggw.5 AC2: the failed append above was not applied, and is not replayed.
    let mut case = Case::new("a failed append is not applied (twr-ggw.5 AC2, STA-3)");
    let after_failure = run.inspect(&worker).await?;
    println!("   replayed before {before_failure}, after {after_failure}");
    case.check(
        "the append failed at a storage call: the move was refused, and the staging file is all it left",
        report["outcome"]["why"].as_str().is_some_and(|why| why.starts_with("move")),
    );
    case.check(
        "the replayed state has no record for it",
        after_failure == before_failure && after_failure["records"] == json!([0, 1, 2]),
    );
    worker = run.reload(&tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    case.check(
        "after a reload and an unlock, none appears",
        run.inspect(&worker).await? == before_failure,
    );
    cases.push(case);

    let mut case = Case::new("close without exit status stays unresolved (twr-ggw.7, STA-8)");
    fresh_pace(relay);
    let mut closing = args("fixture");
    closing["command"] = "close-without-status".into();
    let report = run.harness_run(&worker, closing).await?;
    let observed = take(seen);
    let call = report["outcome"]["call"].clone();
    let before = run.inspect(&worker).await?;
    case.check(
        "the close reports unresolved, with a call identity and no failed or done report",
        report["outcome"]["unresolved"] == true
            && call.as_u64().is_some()
            && report["outcome"].get("refused").is_none()
            && report["outcome"].get("done").is_none()
            && observed.ssh_exec == [b"close-without-status".to_vec()]
            && observed.ssh_exit.is_empty(),
    );
    case.check(
        "the recorded call is unresolved and has no terminal",
        before["calls"].as_array().is_some_and(|calls| {
            calls
                .iter()
                .any(|c| c["call"] == call && c["state"] == "unresolved")
        }) && before["terminals"]
            .as_array()
            .is_some_and(|ts| ts.iter().all(|t| t["call"] != call)),
    );
    worker = run.reload(&tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let observed = take(seen);
    case.check(
        "replay preserves the unresolved call and sends no second exec",
        run.inspect(&worker).await? == before
            && observed.ssh_exec.is_empty()
            && observed.relay_accepted == 0,
    );
    cases.push(case);

    let mut case = Case::new(
        "dispositions refuse before contact and continuing permits dispatch (twr-ggw.7, STA-24)",
    );
    let original = store_files(&run.dump(&tab).await?);
    let opened = reader::read(&original, PASSPHRASE)?;
    let mut events: Vec<Value> = opened
        .records
        .iter()
        .map(|(_, plaintext)| serde_json::from_slice(plaintext).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let call = events.len() as u64;
    events.push(json!({"intent":{"call":call,"machine":"fixture","command":hex::encode(COMMAND),"approval":{"harness_pin":{"machine":"fixture","fingerprint":pinned}}}}));
    let destructive = events.len() as u64;
    events.push(json!({"disposition":{"machine":"fixture","calls":[call],"continuation":"destructive_reinstall","uncertainty":"the command outcome is unknown"}}));
    run.put(&tab, &reader::build(PASSPHRASE, &events)).await?;
    worker = run.reload(&tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    take(seen);
    fresh_pace(relay);
    let before = run.inspect(&worker).await?;
    let files_before = store_files(&run.dump(&tab).await?);
    let report = run.harness_run(&worker, args("fixture")).await?;
    // If the pre-contact check is removed, the atomic append check still refuses, but the relay sees contact.
    sshd.all_ended().await;
    let observed = take(seen);
    case.check("a destructive disposition is named, and the relay and sshd saw no connection",
        report["outcome"] == json!({"refused":"disposition","disposition":destructive,"continuation":"destructive_reinstall"})
        && observed.relay_accepted == 0 && observed.ssh_connections == 0);
    case.check(
        "the refusal appends nothing",
        run.inspect(&worker).await? == before
            && store_files(&run.dump(&tab).await?) == files_before,
    );
    events.push(json!({"disposition":{"machine":"fixture","calls":[call],"continuation":"as_if_not_done","uncertainty":"the command outcome is unknown"}}));
    run.put(&tab, &reader::build(PASSPHRASE, &events)).await?;
    worker = run.reload(&tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    fresh_pace(relay);
    let report = run.harness_run(&worker, args("fixture")).await?;
    let observed = take(seen);
    let after = run.inspect(&worker).await?;
    case.check(
        "a continuing replacement dispatches and commits the exit status terminal",
        report["outcome"]["done"] == true
            && observed.ssh_exec == [COMMAND.as_bytes().to_vec()]
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
    let files = store_files(&run.dump(&tab).await?);
    case.check(
        "the independent reader reads the browser terminal after the replacement",
        reader::read(&files, PASSPHRASE).is_ok(),
    );
    run.put(&tab, &original).await?;
    worker = run.reload(&tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    take(seen);
    cases.push(case);

    // Case 2 (AC2): a host key other than the pin halts, before authentication, once.
    let mut case = Case::new("2. a host key other than the pin halts the connection (AC2)");
    sshd.present_other.store(true, Ordering::SeqCst);
    fresh_pace(relay);
    let report = run.harness_run(&worker, args("fixture")).await?;
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

    // Cases 6–8 (twr-ggw.3): the relay refusals a correct client meets. Each is refused at its
    // check of WIR-6 (paid-tcp-relay 844e834) with one frame and close 1008, before any dial.
    let refused = |case: &mut Case, report: &Value, observed: &Seen, reason: &str, host: &str| {
        case.check(
            &format!("the harness reported {{\"refused\": \"relay\", \"reason\": \"{reason}\", \"close_code\": 1008}}"),
            report["outcome"] == json!({ "refused": "relay", "reason": reason, "close_code": 1008 }),
        );
        case.check(
            "the relay fixture accepted exactly one connection",
            observed.relay_accepted == 1
                && observed.relay_connections == [format!("/v1/tcp/{host}/{}", sshd.port)],
        );
        case.check(
            "nothing was dialed, and the fixture sshd saw no connection",
            observed.relay_dials.is_empty() && observed.ssh_connections == 0,
        );
        let logs = observed.relay_logs();
        case.check(
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
    let closed = |s: &Seen| s.relay_log.iter().any(|(_, e)| *e == Event::Frame("close"));

    let mut case = Case::new("6. a relay key with no pass is refused for `pass` (twr-ggw.3)");
    let mut unknown = args("fixture");
    unknown["test_relay_key"] = "no-such-key".into();
    let failed = run.harness_run(&worker, unknown).await;
    let observed = take(seen);
    println!("   an unrecognised test_relay_key: {failed:?}");
    case.check(
        "an unrecognised test_relay_key fails the request, and the relay fixture accepted no connection",
        failed.is_err_and(|e| e.contains("test_relay_key")) && observed.relay_accepted == 0,
    );
    let mut without = args("fixture");
    without["test_relay_key"] = "without-pass".into();
    fresh_pace(relay);
    let report = run.harness_run(&worker, without).await?;
    settle(seen, closed).await;
    let observed = take(seen);
    show(&observed);
    refused(&mut case, &report, &observed, "pass", "127.0.0.1");
    cases.push(case);

    let mut case =
        Case::new("7. an unrecorded destination is refused for `destination` (twr-ggw.3)");
    let mut unrecorded = args("fixture");
    unrecorded["host"] = "127.0.0.2".into();
    fresh_pace(relay);
    let report = run.harness_run(&worker, unrecorded).await?;
    settle(seen, closed).await;
    let observed = take(seen);
    show(&observed);
    refused(&mut case, &report, &observed, "destination", "127.0.0.2");
    cases.push(case);

    let mut case = Case::new("8. a dial the pace does not allow is refused for `pace` (twr-ggw.3)");
    // The sshd's host at its window cap, now: refused for a whole window, whatever the timing.
    relay.pace.lock().expect("pace lock").arm("127.0.0.1");
    let report = run.harness_run(&worker, args("fixture")).await?;
    settle(seen, closed).await;
    fresh_pace(relay);
    let observed = take(seen);
    show(&observed);
    refused(&mut case, &report, &observed, "pace", "127.0.0.1");
    cases.push(case);

    // twr-ggw.5 AC1: each modification edited into OPFS is refused, the page offers no Create, and OPFS is
    // byte for byte as it was.
    let mut case = Case::new("fail closed (twr-ggw.5 AC1, CNF-82)");
    let baseline = store_files(&run.dump(&tab).await?);
    let baseline_state = run.inspect(&worker).await?;
    let flip = |value: &mut Value, field: &str| {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut bytes = URL_SAFE_NO_PAD
            .decode(value[field].as_str().unwrap_or_default())
            .unwrap_or_default();
        if let Some(first) = bytes.first_mut() {
            *first ^= 1;
        }
        value[field] = URL_SAFE_NO_PAD.encode(bytes).into();
    };
    let edited = |name: &str, change: &dyn Fn(&mut Value)| -> Files {
        let mut files = baseline.clone();
        let mut value: Value = serde_json::from_slice(&files[name]).unwrap_or_default();
        change(&mut value);
        let bytes = if name == "envelope.json" {
            value.to_string().into_bytes()
        } else {
            reader::record_bytes(&value)
        };
        files.insert(name.into(), bytes);
        files
    };
    let mut foreign = baseline.clone();
    foreign.insert(
        "1".into(),
        reader::build(
            PASSPHRASE,
            &[
                json!({ "seed": { "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" } }),
                json!({ "command": { "machine": "fixture", "command": hex::encode(COMMAND) } }),
            ],
        )["1"]
            .clone(),
    );
    // The last field: whether the refusal is the envelope's tag, where a wrong passphrase and a
    // modified envelope cannot be told apart.
    let variants: Vec<(&str, Files, &str, bool)> = vec![
        (
            "a wrong passphrase",
            baseline.clone(),
            WRONG_PASSPHRASE,
            true,
        ),
        (
            "a modified envelope: one byte of the salt",
            edited("envelope.json", &|e| flip(e, "salt")),
            PASSPHRASE,
            true,
        ),
        (
            "a modified record: one byte of record 1's ciphertext",
            edited("1", &|r| flip(r, "ciphertext")),
            PASSPHRASE,
            false,
        ),
        (
            "a record from another store, at the same number",
            foreign,
            PASSPHRASE,
            false,
        ),
        (
            "an envelope of an unknown format: version 2",
            edited("envelope.json", &|e| e["version"] = 2.into()),
            PASSPHRASE,
            false,
        ),
    ];
    for (what, files, passphrase, tag) in variants {
        run.put(&tab, &files).await?;
        worker = run.reload(&tab, &worker).await?;
        let view = run.submit(&tab, "unlock", passphrase).await?;
        let after = store_files(&run.dump(&tab).await?);
        case.check(
            &format!("{what}: unlock is refused, and the page offers neither Create nor Unlock"),
            view["store"] == "refused"
                && view["create"] == false
                && view["unlock"] == false
                && view["lock"] == false,
        );
        if tag {
            case.check(
                &format!("{what}: the page claims no certainty about the cause"),
                view["text"]
                    .as_str()
                    .is_some_and(|t| t.contains("wrong passphrase, or the store was modified")),
            );
        }
        case.check(
            &format!("{what}: a create request creates nothing, and the store stays refused"),
            run.submit(&tab, "create", PASSPHRASE).await?["store"] == "refused",
        );
        case.check(
            &format!("{what}: OPFS is byte-identical afterwards"),
            after == files && store_files(&run.dump(&tab).await?) == files,
        );
        case.check(
            &format!("{what}: the worker runs nothing"),
            run.harness_run(&worker, args("fixture")).await? == locked
                && take(seen).relay_accepted == 0,
        );
    }
    run.put(&tab, &baseline).await?;
    worker = run.reload(&tab, &worker).await?;
    run.submit(&tab, "unlock", PASSPHRASE).await?;
    case.check(
        "the store put back unlocks",
        run.inspect(&worker).await? == baseline_state,
    );
    cases.push(case);

    // twr-ggw.5 AC3: reload, explicit lock, page hide and a killed worker each require unlock again.
    let mut case = Case::new("reload requires unlock again (twr-ggw.5 AC3, CNF-82)");
    let before = run.inspect(&worker).await?;
    let old = worker.clone();
    worker = run.reload(&tab, &worker).await?;
    relocked(
        run,
        &mut case,
        &tab,
        &old,
        &worker,
        &before,
        &args("fixture"),
    )
    .await?;
    cases.push(case);

    let mut case = Case::new(
        "explicit lock requires unlock again, and ends a command in flight (twr-ggw.5 AC3, CNF-82)",
    );
    // Text typed in both fields and never submitted goes with the lock (SEC-5 row 18).
    let mut left = Value::Null;
    worker = held_then(run, &mut case, &tab, worker, &args, "Lock", async {
        left = browser
            .evaluate(
                &tab.session,
                "(() => {
                    const $ = (id) => document.getElementById(id);
                    $('passphrase').value = 'typed, never submitted';
                    $('confirm').value = 'typed, never submitted';
                    $('lock').click();
                    return [$('passphrase').value, $('confirm').value];
                })()",
            )
            .await?;
        Ok(())
    })
    .await?;
    case.check(
        &format!("Lock: text typed but not submitted is gone from both fields: {left}"),
        left == json!(["", ""]),
    );
    cases.push(case);

    let mut case = Case::new(
        "page hide requires unlock again, and ends a command in flight (twr-ggw.5 AC3, CNF-82)",
    );
    browser
        .evaluate(
            &tab.session,
            "window.__tracerVisibility = []; document.addEventListener('visibilitychange', () => window.__tracerVisibility.push(document.visibilityState))",
        )
        .await?;
    // The browser's own visibilitychange: in headless Chromium a new tab hides this one.
    worker = held_then(
        run,
        &mut case,
        &tab,
        worker,
        &args,
        "visibilitychange to hidden",
        async {
            let other = browser
                .call(None, "Target.createTarget", json!({ "url": "about:blank" }))
                .await?;
            tokio::time::sleep(Duration::from_millis(500)).await;
            browser
                .call(
                    None,
                    "Target.activateTarget",
                    json!({ "targetId": tab.target }),
                )
                .await?;
            browser
                .call(
                    None,
                    "Target.closeTarget",
                    json!({ "targetId": other["targetId"] }),
                )
                .await
                .map(|_| ())
        },
    )
    .await?;
    let visibility = browser
        .evaluate(&tab.session, "window.__tracerVisibility")
        .await?;
    println!("   visibility seen by the page: {visibility}");
    case.check(
        "the page saw the browser's own visibilitychange to hidden, then visible",
        visibility == json!(["hidden", "visible"]),
    );
    // A pagehide alone: the browser fires its own only as the page unloads (the reload case), so
    // the event is dispatched on the real window.
    worker = held_then(run, &mut case, &tab, worker, &args, "pagehide", async {
        browser
            .evaluate(
                &tab.session,
                "dispatchEvent(new PageTransitionEvent('pagehide', { persisted: false }))",
            )
            .await
            .map(|_| ())
    })
    .await?;
    cases.push(case);

    let mut case = Case::new(
        "a killed worker surfaces an unresolved command and requires unlock (twr-ggw.7, CNF-39)",
    );
    take(seen);
    fresh_pace(relay);
    let mut held = args("fixture");
    held["command"] = HELD.into();
    run.harness_start(&worker, held).await?;
    let received = settle_for(seen, 20, |s| s.ssh_exec == [HELD.as_bytes().to_vec()]).await;
    case.check(
        "before Page.crash the sshd received the held exec",
        received,
    );
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
        "the killed command's SSH connection ended",
        sshd.all_ended().await,
    );
    take(seen);
    let old = worker.clone();
    (tab, worker) = run.open(tracer_origin, false).await?;
    relocked(
        run,
        &mut case,
        &tab,
        &old,
        &worker,
        &before,
        &args("fixture"),
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let observed = take(seen);
    let after = run.inspect(&worker).await?;
    case.check(
        "after the crash, the held call is surfaced as unresolved without another exec",
        after["calls"]
            .as_array()
            .and_then(|calls| calls.last())
            .is_some_and(|call| {
                call["command"] == hex::encode(HELD) && call["state"] == "unresolved"
            })
            && observed.ssh_exec.is_empty()
            && observed.relay_accepted == 0,
    );
    cases.push(case);

    // One writer: while one tab holds the store, the other neither unlocks nor appends. Opening
    // the second tab hides the first, whose worker restarts; either tab's worker may then win the
    // lock, so the roles are read from what the pages and workers report.
    let mut case = Case::new("one writer (twr-ggw.5, STA-1, STA-7)");
    let first = tab;
    let (second, _) = run.open(tracer_origin, true).await?;
    let one = |tab: &Tab| match run.live_workers(tab).as_slice() {
        [w] => Some(w.clone()),
        _ => None,
    };
    let mut views = (Value::Null, Value::Null);
    let mut settled = false;
    for _ in 0..300 {
        views = (run.view(&first).await?, run.view(&second).await?);
        let states = [views.0["store"].as_str(), views.1["store"].as_str()];
        settled = one(&first).is_some_and(|w| w != worker)
            && one(&second).is_some()
            && views.0["status"] == "ready"
            && views.1["status"] == "ready"
            && (states == [Some("locked"), Some("in-use")]
                || states == [Some("in-use"), Some("locked")]);
        if settled {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!(
        "   the first tab: {}\n   the second tab: {}",
        views.0, views.1
    );
    if !settled {
        return Err(format!(
            "one writer: the tabs did not settle with one offering Unlock and the other waiting: {views:?}"
        ));
    }
    let (holder, other, other_view) = if views.0["store"] == "locked" {
        println!("   the first tab holds the store");
        (first, second, views.1)
    } else {
        println!("   the second tab holds the store");
        (second, first, views.0)
    };
    let holder_worker = one(&holder).ok_or("no worker")?;
    let other_worker = one(&other).ok_or("no worker")?;
    for w in [&holder_worker, &other_worker] {
        browser
            .call(Some(&w.session), "Runtime.enable", json!({}))
            .await?;
    }
    let view = run.submit(&holder, "unlock", PASSPHRASE).await?;
    case.check(
        "the tab holding the lock unlocks",
        view["store"] == "unlocked",
    );
    let held_by_holder = run.inspect(&holder_worker).await?;
    case.check(
        "the other tab says it is waiting for the store, and offers neither Create nor Unlock",
        other_view["store"] == "in-use"
            && other_view["text"].as_str().is_some_and(|t| {
                t.contains("another tab, or this page's previous harness worker, still holds it")
            })
            && other_view["create"] == false
            && other_view["unlock"] == false
            && run.view(&other).await? == other_view,
    );
    case.check(
        "the other tab's worker has not read the store",
        run.inspect(&other_worker).await?["state"] == "unopened",
    );
    take(seen);
    case.check(
        "the other tab's worker runs nothing, and appends nothing",
        run.harness_run(&other_worker, args("fixture")).await? == locked
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
    let mut view = run.view(&other).await?;
    for _ in 0..100 {
        if view["store"] == "locked" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        view = run.view(&other).await?;
    }
    case.check(
        "once the holding tab closes, the other offers Unlock",
        view["store"] == "locked" && view["unlock"] == true,
    );
    let other_worker = one(&other).ok_or("no worker")?;
    browser
        .call(Some(&other_worker.session), "Runtime.enable", json!({}))
        .await?;
    run.submit(&other, "unlock", PASSPHRASE).await?;
    case.check(
        "and unlocks the same store",
        run.inspect(&other_worker).await? == held_by_holder,
    );
    (tab, worker) = (other, other_worker);
    cases.push(case);

    // twr-ggw.5 AC6: the persistent-storage request, refused; then the permission granted, where
    // `persisted()` already reads true and the page makes no request.
    let mut case = Case::new("persistent storage (twr-ggw.5 AC6, STA-23)");
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
        worker = run.reload(&tab, &worker).await?;
        let mut view = run.view(&tab).await?;
        for _ in 0..50 {
            if view["persist"] != "" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            view = run.view(&tab).await?;
        }
        println!("   {setting}: {}", view["persist_text"]);
        let persisted = browser
            .evaluate(&tab.session, "navigator.storage.persisted()")
            .await?;
        case.check(
            &format!("permission {setting}: the browser holds the store persisted: {persisted}"),
            persisted == (setting == "granted"),
        );
        case.check(
            &format!("permission {setting}: the page shows that {says}, and that this is a request, not a guarantee"),
            view["persist"] == state
                && view["persist_text"].as_str().is_some_and(|t| t.contains(says) && t.contains(statement)),
        );
    }
    browser
        .call(None, "Browser.resetPermissions", json!({}))
        .await?;
    cases.push(case);

    // twr-ggw.5 AC4, AC5: no plaintext secret in any storage, message, request or log, in both builds.
    run.collect(&tab).await?;
    run.collect(&served_tab).await?;
    let all_messages = run.messages.borrow().clone();
    let mut console = Vec::new();
    for e in browser.events.lock().expect("events lock").iter() {
        if let Some("Runtime.consoleAPICalled" | "Log.entryAdded" | "Runtime.exceptionThrown") =
            e["method"].as_str()
        {
            console.push(e["params"].to_string());
        }
    }
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
        let mut case = Case::new(name);
        let dumped = run.dump(page).await?;
        let opened = reader::read(&store_files(&dumped), passphrase)?;
        let mut needles = reader::needles(passphrase, &opened)?;
        if test_keys {
            needles.extend(
                checks::needles()
                    .into_iter()
                    .filter(|(what, _)| what.contains("key")),
            );
        }
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
            &format!("no OPFS file holds one: {in_files:?}"),
            in_files.is_empty() && !dumped.is_empty(),
        );
        let other = browser.evaluate(&page.session, OTHER_STORAGE).await?;
        println!("   other storage: {other}");
        case.check(
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
            // Negative controls: the test SSH client key, planted as binary in eleven shapes, a
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
                        STANDARD.encode(SSH_CLIENT_SEED),
                        serde_json::to_string(passphrase).expect("a JSON string"),
                    ),
                )
                .await?;
            let planted = planted.as_array().cloned().unwrap_or_default();
            println!("   planted messages: {planted:?}");
            case.check(
                "the __proto__ control comes back from __tracerMessages through the DevTools protocol as a member named __proto__",
                planted
                    .get(11)
                    .and_then(|m| m.pointer("/from/store/__proto__"))
                    .is_some(),
            );
            for (i, (control, expected)) in controls.iter().enumerate() {
                let reported = planted
                    .get(i)
                    .map(|m| findings(m, &needles, &passphrases).1)
                    .unwrap_or_default();
                println!("   {control}: reported {reported:?}");
                case.check(
                    &format!("negative control, {control}: reported {expected}"),
                    reported.contains(expected),
                );
            }
        }
        let mut carrying = Vec::new();
        let mut leaking = Vec::new();
        for message in &all_messages {
            match findings(message, &needles, &passphrases) {
                (Some(carried), _) => carrying.push(carried),
                (None, found) if !found.is_empty() => {
                    leaking.push(format!("{message}: {found:?}"));
                }
                _ => {}
            }
        }
        case.check(
            &format!("the passphrase reaches the worker only as the one create or unlock message: {} such messages", carrying.len()),
            carrying.iter().any(|p| p == passphrase) && leaking.is_empty(),
        );
        if !leaking.is_empty() {
            println!("   messages carrying a secret: {leaking:?}");
        }
        case.check(
            "no message from the worker carries one, in its text or in a binary payload",
            all_messages
                .iter()
                .filter(|m| m.get("from").is_some())
                .all(|m| findings(m, &needles, &passphrases).1.is_empty()),
        );
        case.check(
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
        case.check(
            &format!("the HTTPS fixtures' request lines and bodies hold none ({} requests): {in_requests:?}", requests.len()),
            in_requests.is_empty() && !requests.is_empty(),
        );
        let in_console: Vec<_> = console
            .iter()
            .flat_map(|c| reader::found(&needles, c.as_bytes()))
            .collect();
        case.check(
            &format!("the console and log messages hold none: {in_console:?}"),
            in_console.is_empty()
                && console
                    .iter()
                    .all(|c| !passphrases.iter().any(|p| c.contains(p))),
        );
        cases.push(case);
    }

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
) -> (Option<String>, Vec<String>) {
    let mut payloads = Vec::new();
    let mut opaque = Vec::new();
    let rest = binaries(message, &mut payloads, &mut opaque);
    if let [bytes] = payloads.as_slice()
        && ["create", "unlock"]
            .iter()
            .any(|kind| rest == json!({ "to": { *kind: null } }))
        && let Some(carried) = passphrases
            .iter()
            .find(|p| p.as_bytes() == bytes.as_slice())
    {
        return (Some(carried.to_string()), Vec::new());
    }
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

/// What a lock of any kind must leave: the old worker gone and one new one, the page offering
/// Unlock, every request refused before any contact, and after an unlock the replayed state as
/// it was (`before`).
async fn relocked(
    run: &Run<'_>,
    case: &mut Case,
    tab: &Tab,
    old: &Worker,
    worker: &Worker,
    before: &Value,
    request: &Value,
) -> Result<(), String> {
    let targets = run.harness_targets(&tab.origin).await?;
    println!(
        "   harness workers now: {targets:?}, the old one {}",
        old.target
    );
    case.check(
        "the old worker target is gone, and one new harness worker exists",
        targets.len() == 1 && !targets.contains(&old.target) && targets.contains(&worker.target),
    );
    let view = run.settled(tab, false).await?;
    case.check(
        "the page offers Unlock, and nothing else",
        view["store"] == "locked"
            && view["unlock"] == true
            && view["create"] == false
            && view["lock"] == false,
    );
    take(run.seen);
    let report = run.harness_run(worker, request.clone()).await?;
    let observed = take(run.seen);
    case.check(
        "a command is refused while locked, with no TCP connection at the relay",
        report == json!({ "outcome": { "refused": "locked" } }) && observed.relay_accepted == 0,
    );
    let view = run.submit(tab, "unlock", PASSPHRASE).await?;
    let replayed = run.inspect(worker).await?;
    println!("   replayed: {replayed}");
    case.check(
        "after unlock, the replayed state lists every command recorded before",
        view["store"] == "unlocked" && replayed == *before,
    );
    Ok(())
}

/// Runs `HELD`, which the sshd never answers, locks by `how` once the sshd has its `exec`, and
/// checks the lock ended it: the relay fixture sees the client's WebSocket close and the sshd its
/// connection end; then `relocked`, and the held command, in the replayed state, is never sent
/// again. The new worker.
async fn held_then(
    run: &Run<'_>,
    case: &mut Case,
    tab: &Tab,
    worker: Worker,
    args: &dyn Fn(&str) -> Value,
    how: &str,
    lock: impl std::future::Future<Output = Result<(), String>>,
) -> Result<Worker, String> {
    take(run.seen);
    fresh_pace(run.relay);
    let mut held = args("fixture");
    held["command"] = HELD.into();
    run.harness_start(&worker, held.clone()).await?;
    let received = settle_for(run.seen, 20, |s| s.ssh_exec == [HELD.as_bytes().to_vec()]).await;
    case.check(
        &format!("{how}: the sshd received the held command's exec"),
        received,
    );
    let before = run.inspect(&worker).await?;
    let numbers = before["commands"].as_array().cloned().unwrap_or_default();
    case.check(
        &format!("{how}: it was recorded before it was sent"),
        numbers
            .last()
            .is_some_and(|c| c["command"] == hex::encode(HELD))
            && before["calls"]
                .as_array()
                .and_then(|calls| calls.last())
                .is_some_and(|c| c["state"] == "unresolved"),
    );
    lock.await?;
    let new = match run.worker(tab, Some(&worker), false).await {
        Ok(new) => new,
        Err(e) => {
            case.check(
                &format!("{how}: the page ended the harness worker and started a new one ({e})"),
                false,
            );
            return Ok(worker);
        }
    };
    let gone = settle_for(run.seen, 20, |s| {
        s.relay_log
            .iter()
            .any(|(_, e)| matches!(e, Event::Frame("close") | Event::Ended))
    })
    .await;
    let ended = run.sshd.all_ended().await;
    let observed = take(run.seen);
    show(&observed);
    case.check(
        &format!("{how}: the relay fixture saw the client's WebSocket close, and the sshd its connection end"),
        gone && ended,
    );
    relocked(run, case, tab, &worker, &new, &before, &args("fixture")).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let observed = take(run.seen);
    case.check(
        &format!(
            "{how}: the held command is in the replayed state, and the sshd received no second exec"
        ),
        observed.ssh_exec.is_empty() && observed.relay_accepted == 0,
    );
    Ok(new)
}
