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
