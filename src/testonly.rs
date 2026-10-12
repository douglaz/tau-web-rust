//! The tracer's test-only parts (twr-ggw.2, twr-ggw.3): the test keys, the host-key pin source,
//! the in-memory journal, and the test switches the browser test sets on a request
//! (`fail_append`, `tamper_auth`, `test_relay_key`). The harness worker's `run_command` runs on
//! these in the tracer build; the served build runs it on nothing stored. Compiled only with the
//! `tracer` feature; `tracer check-absence` reads the served directory for every one of them,
//! through the markers, switch names and key encodings below.
//!
//! The keys are test keys, nothing derived from a seed (that is twr-ggw.4's and twr-ggw.11's),
//! and the journal is memory, nothing durable (twr-ggw.5's).

use crate::harness::{Entry, Journal, PinSource};

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

/// Marks the in-memory journal in a build; `tracer check-absence` refuses it too.
pub const JOURNAL_MARKER: &str = "tau-web test-only in-memory journal";

/// The host-key pins, by machine: `fixture` is the fixture sshd's pinned host key; any other
/// machine, `unpinned` in the tracer, has none.
pub const PINS: &[(&str, &str)] = &[(
    "fixture",
    "SHA256:YHPidfDWj7ccV6cBUvdYdmAkCov2RZ7vQ+qVed7PWLY",
)];

/// The pin source the tracer runs with: `PINS`, read-only.
pub struct TestPins;

impl PinSource for TestPins {
    fn pin(&self, machine: &str) -> Option<String> {
        PINS.iter()
            .find(|(name, _)| *name == machine)
            .map(|(_, pin)| pin.to_string())
    }
}

/// The journal stand-in: entries in memory, and an append that can be made to fail.
pub struct MemoryJournal {
    pub entries: Vec<Entry>,
    pub refuse_appends: bool,
}

impl Journal for MemoryJournal {
    fn append(&mut self, entry: &Entry) -> Result<u64, String> {
        if self.refuse_appends {
            return Err(format!("{JOURNAL_MARKER}: append refused (made to fail)"));
        }
        self.entries.push(entry.clone());
        Ok(self.entries.len() as u64 - 1)
    }

    fn read(&self, seq: u64) -> Option<Entry> {
        self.entries.get(usize::try_from(seq).ok()?).cloned()
    }
}

/// The test SSH client key, and the test relay key the request selected.
#[cfg(target_arch = "wasm32")]
struct TestCredentials {
    relay: [u8; 32],
}

#[cfg(target_arch = "wasm32")]
impl crate::harness::Credentials for TestCredentials {
    fn ssh_key(&self) -> Option<russh::keys::PrivateKey> {
        use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
        let keypair = Ed25519Keypair::from_seed(&SSH_CLIENT_SEED);
        russh::keys::PrivateKey::new(KeypairData::Ed25519(keypair), "").ok()
    }

    fn relay_key(&self) -> Option<[u8; 32]> {
        Some(self.relay)
    }
}

/// One attempt on the test sources. `request` sets the test switches: `test_relay_key` names
/// the test relay key the AUTH is signed with, one of `RELAY_KEYS`, and any other value, or
/// none, or a key that does not derive its recorded public half, fails the request before any
/// contact; `fail_append` makes the journal refuse its
/// append; `tamper_auth` sends a wrongly signed AUTH. The key is chosen by name only: no key
/// material comes from the request. The report adds the journal's entries and the pin source's
/// view afterwards, for the tracer to check.
#[cfg(target_arch = "wasm32")]
pub async fn run(
    target: &crate::harness::Target,
    command: &[u8],
    request: &serde_json::Value,
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
                Ok(*secret)
            } else {
                Err(format!(
                    "test_relay_key {name}: the secret is not its public half's"
                ))
            }
        })?;
    let mut journal = MemoryJournal {
        entries: Vec::new(),
        refuse_appends: request["fail_append"] == json!(true),
    };
    let outcome = crate::harness::run_command(
        &TestPins,
        &mut journal,
        &TestCredentials { relay },
        target,
        command,
        request["tamper_auth"] == json!(true),
    )
    .await;
    Ok(json!({
        "pin_source": PIN_SOURCE_MARKER,
        "journal": JOURNAL_MARKER,
        "outcome": crate::harness::report(&outcome),
        "journal_entries": journal.entries.iter().map(|e| hex::encode(&e.command)).collect::<Vec<_>>(),
        "pinned_after": TestPins.pin(&target.machine),
    }))
}
