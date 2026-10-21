//! The tracer's test-only parts (twr-ggw.2, twr-ggw.3, twr-ggw.5): the test keys, the host-key
//! pin source, and the test switches the browser test sets on a request (`fail_append`,
//! `tamper_auth`, `test_relay_key`, `test_no_credentials`). The harness worker's `run_command`
//! runs on these and on the local store's journal in the tracer build; the served build runs it
//! on nothing stored. Compiled only with the `tracer` feature; `tracer check-absence` reads the
//! served directory for every one of them, through the marker, switch names and key encodings
//! below. The tracer-only writer and completed-read exports coordinate evidence-append checks.
//!
//! The keys are test keys, not derived from a seed: derivation exists (`crate::seed`), and
//! twr-ggw.11 binds its keys in their place. They are built as the credential types a derived key
//! is (`crate::credential`).

use crate::credential::HostKeyPin;
#[cfg(target_arch = "wasm32")]
use crate::credential::{RelayKey, SshClientKey};
use crate::harness::PinSource;
#[cfg(target_arch = "wasm32")]
use crate::harness::{Entry, Journal};

/// The test SSH client key: an ed25519 seed. The fixture sshd authorizes its public half.
pub const SSH_CLIENT_SEED: [u8; 32] = [
    0x2c, 0x89, 0x9a, 0x04, 0xc3, 0x2b, 0x6f, 0x95, 0x43, 0x34, 0x18, 0x78, 0x20, 0xed, 0x6c, 0x61,
    0xac, 0x10, 0xf3, 0xd1, 0x30, 0xc7, 0x6d, 0x96, 0xef, 0x72, 0xd0, 0xfa, 0x35, 0x1d, 0x63, 0xdc,
];

/// The test relay key: a secp256k1 secret. The relay fixture holds a pass for its public half.
pub const RELAY_SECRET: [u8; 32] = [
    0xd3, 0x46, 0xf4, 0x2a, 0xfe, 0xfa, 0x19, 0xe5, 0xea, 0xf5, 0xdd, 0xf1, 0x7f, 0x25, 0x1d, 0xf6,
    0xef, 0xe5, 0x8e, 0xff, 0xdc, 0x28, 0x1b, 0xc2, 0xdf, 0x5b, 0x5f, 0x4f, 0xe7, 0x56, 0xbc, 0x06,
];

/// A second test relay key, which the relay fixture holds no pass for.
pub const RELAY_SECRET_WITHOUT_PASS: [u8; 32] = [
    0x91, 0xb8, 0xe7, 0xdf, 0xf4, 0x08, 0x91, 0xa8, 0x2c, 0xc6, 0xde, 0x3d, 0x08, 0x1e, 0x2f, 0xbf,
    0xfd, 0x6a, 0xb5, 0xed, 0x05, 0x03, 0x16, 0x85, 0x63, 0x41, 0x44, 0x75, 0x57, 0x70, 0x74, 0x22,
];

/// `RELAY_SECRET`'s public half, the x-only key its AUTH carries.
pub const RELAY_PUBLIC: [u8; 32] = [
    0xa5, 0xc2, 0x5b, 0x05, 0xf1, 0xc9, 0x4b, 0x55, 0x0d, 0x44, 0xd6, 0x61, 0x58, 0x3e, 0xca, 0xf1,
    0x57, 0xad, 0xa6, 0xa9, 0x75, 0xfc, 0x72, 0x49, 0xd1, 0x7c, 0x42, 0x55, 0x79, 0x01, 0x6d, 0xbe,
];

/// `RELAY_SECRET_WITHOUT_PASS`'s public half.
pub const RELAY_PUBLIC_WITHOUT_PASS: [u8; 32] = [
    0xdd, 0x4d, 0xc3, 0x02, 0xd3, 0x1f, 0xfe, 0xd1, 0x07, 0x28, 0x7b, 0x78, 0x6b, 0x36, 0x11, 0x40,
    0xbf, 0xfa, 0x44, 0x69, 0x3a, 0x50, 0x19, 0x9a, 0xaa, 0x0c, 0x78, 0xa9, 0x8b, 0xcf, 0x82, 0x4b,
];

/// The test relay keys `test_relay_key` selects among, by name: `(name, secret, public half)`.
/// A selected key whose secret does not derive its recorded public half fails the request.
/// twr-ggw.11 replaces them with the relay key derived from the seed.
pub const RELAY_KEYS: &[(&str, [u8; 32], [u8; 32])] = &[
    ("with-pass", RELAY_SECRET, RELAY_PUBLIC),
    (
        "without-pass",
        RELAY_SECRET_WITHOUT_PASS,
        RELAY_PUBLIC_WITHOUT_PASS,
    ),
];

/// The SSH user the fixture sshd admits the test client key for.
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
    async fn commands(&self) -> Vec<(u64, Entry)>;
}

/// The test SSH client key, and the test relay key the request selected, as the role 0 and
/// role 3 types.
#[cfg(target_arch = "wasm32")]
struct TestCredentials {
    ssh: SshClientKey,
    relay: RelayKey,
    unavailable: bool,
}

#[cfg(target_arch = "wasm32")]
impl crate::harness::Credentials for TestCredentials {
    fn ssh_key(&self) -> Option<&SshClientKey> {
        (!self.unavailable).then_some(&self.ssh)
    }

    fn relay_key(&self) -> Option<&RelayKey> {
        (!self.unavailable).then_some(&self.relay)
    }
}

/// One attempt on the test sources and the store's journal. `request` sets the test switches:
/// `test_relay_key` names the test relay key the AUTH is signed with, one of `RELAY_KEYS`, and
/// any other value, or none, or a key that does not derive its recorded public half, fails the
/// request before any contact; `fail_append` makes the store's append fail at its move, a real
/// OPFS call; `tamper_auth` sends a wrongly signed AUTH; `test_no_credentials` supplies no keys.
/// The key is chosen by name only: no key material comes from the request. The report adds
/// the commands this request appended and the pin source's view afterwards, for the tracer
/// to check.
#[cfg(target_arch = "wasm32")]
pub async fn run(
    target: &crate::harness::Target,
    command: &[u8],
    request: &serde_json::Value,
    journal: &mut (impl Journal + FailAppend),
    collect: bool,
) -> Result<serde_json::Value, String> {
    use serde_json::json;
    let selector = &request["test_relay_key"];
    let relay = RELAY_KEYS
        .iter()
        .find(|(name, _, _)| selector.as_str() == Some(*name))
        .ok_or_else(|| format!("test_relay_key: no test relay key is named {selector}"))
        .and_then(|(name, secret, public)| {
            let derived: [u8; 32] = k256::schnorr::SigningKey::from_bytes(secret)
                .map_err(|e| format!("test_relay_key {name}: {e}"))?
                .verifying_key()
                .to_bytes()
                .into();
            if derived == *public {
                Ok(RelayKey(*secret))
            } else {
                Err(format!(
                    "test_relay_key {name}: the secret is not its public half's"
                ))
            }
        })?;
    let before = journal.commands().await.len();
    journal
        .fail_next_append(request["fail_append"] == json!(true))
        .await;
    let credentials = TestCredentials {
        ssh: SshClientKey(SSH_CLIENT_SEED),
        relay,
        unavailable: request["test_no_credentials"] == json!(true),
    };
    let outcome = if collect {
        match crate::harness::collect_jobs(
            &TestPins,
            journal,
            &credentials,
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
            &credentials,
            target,
            command,
            request["tamper_auth"] == json!(true),
        )
        .await;
        crate::harness::report(&result)
    };
    journal.fail_next_append(false).await;
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
