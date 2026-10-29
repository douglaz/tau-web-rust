//! Tracer-only host-key pins and failure switches. Both builds use the store's binding path.

use crate::credential::HostKeyPin;
use crate::harness::PinSource;
#[cfg(target_arch = "wasm32")]
use crate::harness::{BoundJournal, Entry};

/// The SSH user the fixture sshd admits a machine's derived client key for.
pub const SSH_USER: &str = "tracer";

/// Marks the pin source in a build; `tracer check-absence` refuses a served build holding it.
pub const PIN_SOURCE_MARKER: &str = "tau-web test-only host-key pin source";

/// `fixture` and `fixture-other` use the fixture sshd's pinned host key.
/// Every other machine, `unpinned` in the tracer, has none.
pub const PINS: &[(&str, &str)] = &[
    (
        "fixture-other",
        "SHA256:YHPidfDWj7ccV6cBUvdYdmAkCov2RZ7vQ+qVed7PWLY",
    ),
    (
        "fixture",
        "SHA256:YHPidfDWj7ccV6cBUvdYdmAkCov2RZ7vQ+qVed7PWLY",
    ),
];

/// The pin source the tracer runs with: `PINS`, read-only.
pub struct TestPins;

impl PinSource for TestPins {
    fn pin(&self, machine: &str) -> Option<HostKeyPin> {
        PINS.iter()
            .find(|(name, _)| *name == machine)
            .map(|(_, pin)| HostKeyPin(pin.to_string()))
    }
}

/// What `fail_append` needs of the journal: to make its next append fail at a real storage call,
/// and the commands it holds, so the report can name those this request appended.
#[cfg(target_arch = "wasm32")]
#[allow(
    async_fn_in_trait,
    reason = "used generically and only on one thread: the browser's worker"
)]
pub trait FailAppend {
    async fn fail_next_append(&self, fail: bool);
    fn withhold_credentials(&mut self, unavailable: bool);
    async fn commands(&self) -> Vec<(u64, Entry)>;
}

/// One attempt on the tracer's pin source and the live store's derived credentials.
#[cfg(target_arch = "wasm32")]
pub async fn run(
    target: &crate::harness::Target,
    command: &[u8],
    request: &serde_json::Value,
    journal: &mut (impl BoundJournal + FailAppend),
    collect: bool,
) -> Result<serde_json::Value, String> {
    use serde_json::json;
    let before = journal.commands().await.len();
    journal
        .fail_next_append(request["fail_append"] == json!(true))
        .await;
    journal.withhold_credentials(request["test_no_credentials"] == json!(true));
    let outcome = if collect {
        match crate::harness::collect_jobs(
            &TestPins,
            journal,
            target,
            request["tamper_auth"] == json!(true),
        )
        .await
        {
            Ok(records) => json!({"collected": records}),
            Err(refusal) => refusal.to_json(),
        }
    } else {
        let result = crate::harness::run_command(
            &TestPins,
            journal,
            target,
            command,
            request["tamper_auth"] == json!(true),
        )
        .await;
        crate::harness::report(&result)
    };
    journal.fail_next_append(false).await;
    journal.withhold_credentials(false);
    let appended = journal.commands().await;
    Ok(json!({
        "pin_source": PIN_SOURCE_MARKER,
        "outcome": outcome,
        "journal_entries": appended[before.min(appended.len())..].iter()
            .map(|(_, e)| hex::encode(&e.command))
            .collect::<Vec<_>>(),
        "pinned_after": TestPins.pin(&target.machine).map(|pin| pin.0),
    }))
}

#[cfg(target_arch = "wasm32")]
std::thread_local! {
    static COMPLETED_READS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn completed_read() {
    COMPLETED_READS.with(|count| count.set(count.get() + 1));
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn completed_reads() -> u32 {
    COMPLETED_READS.with(std::cell::Cell::get)
}

/// Fixed test selection; session-start selection supplies the production seam later.
pub fn inference_candidate() -> crate::inference::Candidate {
    crate::inference::Candidate {
        slug: "fixture-model".into(),
        maker: "fixture-maker".into(),
        provider: "fixture-provider".into(),
    }
}

#[cfg(target_arch = "wasm32")]
std::thread_local! {static TRANSPORT_APPEND: std::cell::RefCell<Option<String>> = const {std::cell::RefCell::new(None)};}
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn test_transport_append(bytes: String) {
    TRANSPORT_APPEND.with_borrow_mut(|p| *p = Some(bytes));
}
#[cfg(target_arch = "wasm32")]
pub(crate) fn transport_append() -> Option<String> {
    TRANSPORT_APPEND.with_borrow_mut(Option::take)
}

#[cfg(target_arch = "wasm32")]
std::thread_local! {
    static HELD_MOVE: std::cell::RefCell<Option<(js_sys::Promise, js_sys::Function)>> = const { std::cell::RefCell::new(None) };
    static HELD_JOB_READ: std::cell::RefCell<Option<(js_sys::Promise, js_sys::Function)>> = const { std::cell::RefCell::new(None) };
}

/// Suspend one job-record read after opening its SSH channel, before sending its exec.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn test_hold_job_read(release: js_sys::Promise, acquired: js_sys::Function) {
    HELD_JOB_READ.with_borrow_mut(|held| *held = Some((release, acquired)));
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn hold_job_read() -> Result<(), String> {
    let held = HELD_JOB_READ.with_borrow_mut(Option::take);
    if let Some((release, acquired)) = held {
        acquired
            .call0(&wasm_bindgen::JsValue::NULL)
            .map_err(|_| "job read acquired callback")?;
        wasm_bindgen_futures::JsFuture::from(release)
            .await
            .map_err(|_| "job read release promise")?;
    }
    Ok(())
}

/// Suspend the next OPFS move while its append still holds the store writer.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn test_hold_move(release: js_sys::Promise, acquired: js_sys::Function) {
    HELD_MOVE.with_borrow_mut(|held| *held = Some((release, acquired)));
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn hold_move() -> Result<(), String> {
    let held = HELD_MOVE.with_borrow_mut(Option::take);
    if let Some((release, acquired)) = held {
        acquired
            .call0(&wasm_bindgen::JsValue::NULL)
            .map_err(|_| "move acquired callback")?;
        wasm_bindgen_futures::JsFuture::from(release)
            .await
            .map_err(|_| "move release promise")?;
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
std::thread_local! {
    static SESSION_POINTS: std::cell::RefCell<std::collections::BTreeMap<String, (js_sys::Promise, js_sys::Function)>> = const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
    static REKEY_SESSION: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Park exactly one visit to a writer or SSH boundary, without taking the writer.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn test_hold_session_point(
    point: String,
    release: js_sys::Promise,
    acquired: js_sys::Function,
) {
    SESSION_POINTS.with_borrow_mut(|points| points.insert(point, (release, acquired)));
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn session_point(point: &str) {
    let held = SESSION_POINTS.with_borrow_mut(|points| points.remove(point));
    if let Some((release, acquired)) = held {
        acquired
            .call0(&wasm_bindgen::JsValue::NULL)
            .expect("session point callback");
        wasm_bindgen_futures::JsFuture::from(release)
            .await
            .expect("session point release");
    }
}

/// Ask the real SSH driver to start one rekey at the selected boundary.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn test_rekey_session(point: String) {
    REKEY_SESSION.with_borrow_mut(|value| *value = Some(point));
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn rekey_session(point: &str) -> bool {
    REKEY_SESSION.with_borrow_mut(|value| value.take_if(|value| value == point).is_some())
}

/// Bridge a tracer promise to a Send receiver for the SSH handler's authentication wait.
#[cfg(target_arch = "wasm32")]
pub(crate) fn session_point_receiver(point: &str) -> Option<tokio::sync::oneshot::Receiver<()>> {
    let (release, acquired) = SESSION_POINTS.with_borrow_mut(|points| points.remove(point))?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    acquired
        .call0(&wasm_bindgen::JsValue::NULL)
        .expect("session point callback");
    wasm_bindgen_futures::spawn_local(async move {
        wasm_bindgen_futures::JsFuture::from(release)
            .await
            .expect("session point release");
        let _ = sender.send(());
    });
    Some(receiver)
}
