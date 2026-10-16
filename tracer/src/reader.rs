//! An independent reader and writer of the v1 local store (twr-ggw.5), written from credential
//! format v1's "Local encryption envelope" and the record serialization README states, and never
//! calling the harness's store code: reproducing bytes through the same implementation would
//! only show it agrees with itself. Its primitives are `ring`'s (PBKDF2-HMAC-SHA-256,
//! AES-256-GCM, SHA-256), not the RustCrypto crates the harness runs, and the seed's keys are
//! derived with the `bip39` and `bip32` crates.
//!
//! From the passphrase alone it derives the wrapping key, unwraps the data key, decrypts every
//! record and checks each one's AAD and its link to its predecessor. The tracer runs it on the
//! bytes the browser wrote, and builds a store with it for the browser to unlock.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::digest::{SHA256, digest};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::num::NonZeroU32;

pub type Files = BTreeMap<String, Vec<u8>>;

const ITERATIONS: u32 = 600_000;

/// What the reader learned from a store and its passphrase.
pub struct Opened {
    pub wrapping_key: [u8; 32],
    pub data_key: [u8; 32],
    /// Each record's number and plaintext, in order.
    pub records: Vec<(u64, Vec<u8>)>,
}

impl Opened {
    /// The mnemonic the seed record, record 0, carries.
    pub fn mnemonic(&self) -> Result<String, String> {
        let (_, first) = self.records.first().ok_or("no record")?;
        let event: Value = serde_json::from_slice(first).map_err(|e| e.to_string())?;
        event["seed"]["mnemonic"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "record 0 is not the seed".to_string())
    }

    /// Every recorded command, `(number, machine, command bytes)`.
    #[cfg(test)]
    pub fn commands(&self) -> Vec<(u64, String, Vec<u8>)> {
        self.records
            .iter()
            .filter_map(|(number, plaintext)| {
                let event: Value = serde_json::from_slice(plaintext).ok()?;
                let command = if event.get("intent").is_some() {
                    &event["intent"]
                } else {
                    &event["command"]
                };
                Some((
                    *number,
                    command["machine"].as_str()?.to_string(),
                    hex::decode(command["command"].as_str()?).ok()?,
                ))
            })
            .collect()
    }
}

/// Reads the documented plaintext shapes independently of the harness's event types.
fn check_event(number: u64, event: &Value) -> Result<(), String> {
    let object = event.as_object().ok_or("event is not an object")?;
    if object.len() != 1 {
        return Err("event does not name exactly one kind".into());
    }
    let (kind, body) = object.iter().next().expect("one kind");
    let text = |name: &str| {
        body[name]
            .as_str()
            .ok_or_else(|| format!("{kind}: {name} is not text"))
    };
    match kind.as_str() {
        "seed" => {
            text("mnemonic")?;
        }
        "command" | "intent" => {
            text("machine")?;
            hex::decode(text("command")?).map_err(|_| "command is not hex")?;
            if kind == "intent" {
                if let Some(job) = body.get("job")
                    && !job.as_str().is_some_and(|id| {
                        id.len() == 48
                            && id
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                {
                    return Err("intent has invalid job identity".into());
                }
                if body["call"].as_u64() != Some(number) {
                    return Err("intent identity differs from record number".into());
                }
                let approval = &body["approval"];
                if !approval.is_null() {
                    let pin = &approval["harness_pin"];
                    if !approval.as_object().is_some_and(|fields| fields.len() == 1)
                        || !pin.as_object().is_some_and(|fields| fields.len() == 2)
                        || pin["machine"].as_str().is_none()
                        || pin["fingerprint"].as_str().is_none()
                    {
                        return Err("intent admission has no machine or fingerprint".into());
                    }
                }
            }
        }
        "terminal" => {
            if body["call"].as_u64().is_none()
                || body["exit_status"]
                    .as_u64()
                    .and_then(|status| u32::try_from(status).ok())
                    .is_none()
            {
                return Err("terminal has no call identity or exit status".into());
            }
        }
        "job_terminal" | "job_observation" => {
            if body["call"].as_u64().is_none() {
                return Err("job evidence has no call".into());
            }
            let id = text("job")?;
            if id.len() != 48
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("job evidence has invalid identity".into());
            }
            let record = &body["record"];
            match record["kind"].as_str() {
                Some("missing") if kind == "job_observation" => {}
                Some("incomplete") if kind == "job_observation" => {
                    for field in ["machine", "command"] {
                        if !record[field].is_null()
                            && !record[field].as_str().is_some_and(|s| {
                                hex::decode(s).is_ok() && s.to_ascii_lowercase() == s
                            })
                        {
                            return Err("incomplete job bytes are not lowercase hex".into());
                        }
                    }
                }
                Some("present") => {
                    for field in ["machine", "command", "stdout", "stderr"] {
                        let value = record[field].as_str().ok_or("job bytes are not text")?;
                        if hex::decode(value).is_err() || value.to_ascii_lowercase() != value {
                            return Err("job bytes are not lowercase hex".into());
                        }
                    }
                    for field in ["boot", "current_boot"] {
                        if !record[field].as_str().is_some_and(|s| !s.is_empty()) {
                            return Err("job has no boot identity".into());
                        }
                    }
                    if record["pid"]
                        .as_u64()
                        .and_then(|p| u32::try_from(p).ok())
                        .is_none()
                        || record["alive"].as_bool().is_none()
                        || (!record["exit_status"].is_null()
                            && !record["exit_status"].as_u64().is_some_and(|s| s <= 255))
                        || (kind == "job_terminal" && record["exit_status"].is_null())
                    {
                        return Err("job has invalid liveness or exit code".into());
                    }
                }
                _ => return Err("unknown job record kind".into()),
            }
        }
        "disposition" => {
            text("machine")?;
            text("uncertainty")?;
            if ![
                "destructive_reinstall",
                "abandonment",
                "as_if_done",
                "as_if_not_done",
            ]
            .contains(&text("continuation")?)
            {
                return Err("unknown continuation".into());
            }
            if !body["calls"]
                .as_array()
                .is_some_and(|calls| calls.iter().all(|call| call.as_u64().is_some()))
            {
                return Err("disposition has no call identities".into());
            }
        }
        "allocation" => {} // Outside this reader's interpretation.
        _ => return Err(format!("unknown event kind {kind}")),
    }
    Ok(())
}

fn b64(field: &Value, name: &str) -> Result<Vec<u8>, String> {
    let text = field[name]
        .as_str()
        .ok_or_else(|| format!("{name}: not a string"))?;
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|e| format!("{name}: {e}"))
}

fn wrapping_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0; 32];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(ITERATIONS).expect("non-zero"),
        salt,
        passphrase.as_bytes(),
        &mut key,
    );
    key
}

fn aes(key: &[u8; 32]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("a 32-byte key"))
}

fn nonce(bytes: &[u8]) -> Result<Nonce, String> {
    Nonce::try_assume_unique_for_key(bytes).map_err(|_| format!("a {}-byte nonce", bytes.len()))
}

fn open_sealed(
    key: &[u8; 32],
    nonce_bytes: &[u8],
    aad: &str,
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    let mut in_out = sealed.to_vec();
    let plain = aes(key)
        .open_in_place(nonce(nonce_bytes)?, Aad::from(aad.as_bytes()), &mut in_out)
        .map_err(|_| format!("the tag fails under the AAD {aad:?}"))?;
    Ok(plain.to_vec())
}

fn seal(key: &[u8; 32], nonce_bytes: &[u8; 12], aad: &str, plain: &[u8]) -> Vec<u8> {
    let mut in_out = plain.to_vec();
    aes(key)
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*nonce_bytes),
            Aad::from(aad.as_bytes()),
            &mut in_out,
        )
        .expect("AES-GCM seals");
    in_out
}

fn address(bytes: &[u8]) -> String {
    hex::encode(digest(&SHA256, bytes))
}

/// Reads a store's files with its passphrase. Every record must decrypt under the AAD its
/// header and its predecessor's content address give, in order from 0 with no gap.
pub fn read(files: &Files, passphrase: &str) -> Result<Opened, String> {
    let envelope: Value = serde_json::from_slice(files.get("envelope.json").ok_or("no envelope")?)
        .map_err(|e| format!("envelope: {e}"))?;
    let expected = json!({
        "version": 1, "purpose": "local", "kdf": "PBKDF2-SHA256", "iterations": ITERATIONS,
    });
    for (field, value) in expected.as_object().expect("an object") {
        if envelope[field] != *value {
            return Err(format!("envelope {field}: {}", envelope[field]));
        }
    }
    let id = envelope["id"].as_str().ok_or("envelope id")?.to_string();
    let salt = b64(&envelope, "salt")?;
    let wrapping_key = wrapping_key(passphrase, &salt);
    let unwrapped = open_sealed(
        &wrapping_key,
        &b64(&envelope, "nonce")?,
        &format!("tau-web/local/v1/{id}"),
        &b64(&envelope, "wrapped_key")?,
    )?;
    let data_key: [u8; 32] = unwrapped
        .try_into()
        .map_err(|_| "a data key not 32 bytes")?;
    let mut numbers: Vec<u64> = files
        .keys()
        .filter(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()))
        .map(|name| name.parse().map_err(|_| format!("record {name}")))
        .collect::<Result<_, _>>()?;
    numbers.sort_unstable();
    let mut previous = "0".repeat(64);
    let mut records = Vec::new();
    for (expected, number) in (0..).zip(numbers) {
        if number != expected {
            return Err(format!("record {expected} missing"));
        }
        let bytes = &files[&number.to_string()];
        let record: Value =
            serde_json::from_slice(bytes).map_err(|e| format!("record {number}: {e}"))?;
        if record["id"] != id.as_str()
            || record["number"] != number
            || record["previous"] != previous.as_str()
        {
            return Err(format!("record {number}: header {record}"));
        }
        let kind = record["type"].as_str().ok_or("type")?;
        let aad = format!("tau-web/local/v1/{id}/{kind}/{number}/{previous}");
        let plaintext = open_sealed(
            &data_key,
            &b64(&record, "nonce")?,
            &aad,
            &b64(&record, "ciphertext")?,
        )
        .map_err(|e| format!("record {number}: {e}"))?;
        let event: Value =
            serde_json::from_slice(&plaintext).map_err(|e| format!("record {number}: {e}"))?;
        check_event(number, &event).map_err(|e| format!("record {number}: {e}"))?;
        records.push((number, plaintext));
        previous = address(bytes);
    }
    Ok(Opened {
        wrapping_key,
        data_key,
        records,
    })
}

/// Builds a store with `passphrase` holding `events`, record 0 first: the envelope and one file
/// per record, each record in the serialization README states.
pub fn build(passphrase: &str, events: &[Value]) -> Files {
    let random = |n| {
        ring::rand::generate::<[u8; 32]>(&ring::rand::SystemRandom::new())
            .expect("randomness")
            .expose()[..n]
            .to_vec()
    };
    let id = URL_SAFE_NO_PAD.encode(random(16));
    let salt = random(16);
    let data_key: [u8; 32] = random(32).try_into().expect("32 bytes");
    let wrap_nonce: [u8; 12] = random(12).try_into().expect("12 bytes");
    let wrapped = seal(
        &wrapping_key(passphrase, &salt),
        &wrap_nonce,
        &format!("tau-web/local/v1/{id}"),
        &data_key,
    );
    let mut files = Files::new();
    let envelope = json!({
        "version": 1,
        "purpose": "local",
        "id": id,
        "kdf": "PBKDF2-SHA256",
        "iterations": ITERATIONS,
        "salt": URL_SAFE_NO_PAD.encode(&salt),
        "nonce": URL_SAFE_NO_PAD.encode(wrap_nonce),
        "wrapped_key": URL_SAFE_NO_PAD.encode(wrapped),
    });
    files.insert("envelope.json".into(), envelope.to_string().into_bytes());
    let mut previous = "0".repeat(64);
    for (number, event) in events.iter().enumerate() {
        let record_nonce: [u8; 12] = random(12).try_into().expect("12 bytes");
        let aad = format!("tau-web/local/v1/{id}/event/{number}/{previous}");
        let sealed = seal(&data_key, &record_nonce, &aad, event.to_string().as_bytes());
        let bytes = record_bytes(&json!({
            "id": id,
            "type": "event",
            "number": number,
            "previous": previous,
            "nonce": URL_SAFE_NO_PAD.encode(record_nonce),
            "ciphertext": URL_SAFE_NO_PAD.encode(sealed),
        }));
        previous = address(&bytes);
        files.insert(number.to_string(), bytes);
    }
    files
}

/// A record's stored bytes: its members in the stored order (`id`, `type`, `number`,
/// `previous`, `nonce`, `ciphertext`), with no whitespace.
pub fn record_bytes(record: &Value) -> Vec<u8> {
    let members: Vec<String> = ["id", "type", "number", "previous", "nonce", "ciphertext"]
        .iter()
        .map(|name| format!("\"{name}\":{}", record[*name]))
        .collect();
    format!("{{{}}}", members.join(",")).into_bytes()
}

/// Every way a secret could sit in a file or a message: raw, hex in either case, base64 and
/// base64url, and the last two inside a longer encoded value too. There the secret starts at a
/// byte offset `k` modulo 3, so for each `k` it is the characters of `k` filler bytes and the
/// secret that depend on the secret's bits alone.
pub fn encodings(what: &str, bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![
        (format!("{what}, raw"), bytes.to_vec()),
        (format!("{what}, hex"), hex::encode(bytes).into_bytes()),
        (
            format!("{what}, HEX"),
            hex::encode_upper(bytes).into_bytes(),
        ),
    ];
    for (name, engine) in [("base64", STANDARD_NO_PAD), ("base64url", URL_SAFE_NO_PAD)] {
        out.push((format!("{what}, {name}"), engine.encode(bytes).into_bytes()));
        for k in 0..3 {
            let mut value = vec![0; k];
            value.extend_from_slice(bytes);
            let encoded = engine.encode(&value).into_bytes();
            out.push((
                format!("{what}, {name} at offset {k} mod 3"),
                encoded[(8 * k).div_ceil(6)..8 * value.len() / 6].to_vec(),
            ));
        }
    }
    out
}

/// The seed's forbidden plaintext, from its mnemonic: the mnemonic, the entropy, the 64-byte
/// seed and the seed identifier, and roles 0–4's private and public keys at indices 0 and 1
/// (credential format v1: `m/707285'/1'/role'/index'`, every step hardened; roles 0 and 4 are
/// Ed25519 seeds, roles 1–3 secp256k1 secrets with x-only public keys).
pub fn seed_secrets(mnemonic: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    use bip32::{ChildNumber, XPrv};
    let parsed = bip39::Mnemonic::parse_normalized(mnemonic).map_err(|e| e.to_string())?;
    let (entropy, length) = parsed.to_entropy_array();
    let seed = parsed.to_seed_normalized("");
    let mut id = b"tau-web seed id v1\0".to_vec();
    id.extend_from_slice(&seed);
    let id = hex::encode(digest(&SHA256, &id));
    let mut secrets = vec![
        ("the mnemonic".to_string(), mnemonic.as_bytes().to_vec()),
        ("the entropy".to_string(), entropy[..length].to_vec()),
        ("the 64-byte seed".to_string(), seed.to_vec()),
        ("the seed identifier".to_string(), id.clone().into_bytes()),
        (
            "the seed identifier's bytes".to_string(),
            hex::decode(&id).expect("hex"),
        ),
    ];
    let step = |key: &XPrv, i| key.derive_child(ChildNumber::new(i, true).expect("hardened"));
    let top = XPrv::new(seed).map_err(|e| e.to_string())?;
    let version =
        step(&step(&top, 707_285).map_err(|e| e.to_string())?, 1).map_err(|e| e.to_string())?;
    for role in 0..5 {
        let branch = step(&version, role).map_err(|e| e.to_string())?;
        for index in 0..2 {
            let child = step(&branch, index).map_err(|e| e.to_string())?;
            let private: [u8; 32] = child.private_key().to_bytes().into();
            let public = if role == 0 || role == 4 {
                russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&private)
                    .public
                    .0
                    .to_vec()
            } else {
                child.public_key().to_bytes()[1..].to_vec()
            };
            secrets.push((
                format!("role {role} index {index}, private"),
                private.to_vec(),
            ));
            secrets.push((format!("role {role} index {index}, public"), public));
        }
    }
    Ok(secrets)
}

/// Each secret the store and its passphrase hold, in every encoding: the passphrase, the
/// wrapping and data keys, and the seed's.
pub fn needles(passphrase: &str, opened: &Opened) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut secrets = vec![
        ("the passphrase".to_string(), passphrase.as_bytes().to_vec()),
        ("the wrapping key".to_string(), opened.wrapping_key.to_vec()),
        ("the data key".to_string(), opened.data_key.to_vec()),
    ];
    secrets.extend(seed_secrets(&opened.mnemonic()?)?);
    Ok(secrets
        .iter()
        .flat_map(|(what, bytes)| encodings(what, bytes))
        .collect())
}

/// Which needles occur in `bytes`.
pub fn found<'a>(needles: &'a [(String, Vec<u8>)], bytes: &[u8]) -> Vec<&'a str> {
    needles
        .iter()
        .filter(|(_, needle)| bytes.windows(needle.len()).any(|w| w == needle.as_slice()))
        .map(|(what, _)| what.as_str())
        .collect()
}

/// `CNF-82` and `CNF-15`'s host half, against the harness's store on its in-memory storage.
#[cfg(test)]
mod tests {
    use super::*;
    use tau_web::harness::{Entry, Journal};
    use tau_web::store::{MemoryStorage, Pbkdf2, block_on, create, unlock};

    const PASS: &str = "correct horse battery staple";

    fn command(n: u8) -> Entry {
        Entry {
            machine: "fixture".into(),
            command: format!("echo {n}").into_bytes(),
        }
    }

    #[test]
    fn the_encodings_find_a_secret_inside_a_longer_encoded_value() {
        let secret: Vec<u8> = (0x80..0xa0).collect();
        let needles = encodings("the secret", &secret);
        for offset in 0..6 {
            let mut value = vec![0x55; offset];
            value.extend_from_slice(&secret);
            value.extend_from_slice(b"and more");
            for (name, encoded) in [
                ("base64", STANDARD_NO_PAD.encode(&value)),
                ("base64url", URL_SAFE_NO_PAD.encode(&value)),
            ] {
                assert!(
                    !found(&needles, encoded.as_bytes()).is_empty(),
                    "offset {offset}, {name}"
                );
            }
        }
    }

    #[test]
    fn the_reader_reads_a_store_the_harness_wrote() {
        let storage = MemoryStorage::default();
        let mut store = block_on(create(
            storage.clone(),
            &Pbkdf2,
            tau_web::credential::LocalPassphrase::new(PASS.as_bytes().to_vec()),
        ))
        .unwrap();
        for n in 1..=2 {
            block_on(store.append(
                &command(n),
                &tau_web::dispatch::Approval::HarnessPin {
                    machine: "fixture".into(),
                    fingerprint: "SHA256:test-pin".into(),
                },
            ))
            .unwrap();
        }
        block_on(store.terminal(&tau_web::dispatch::Terminal {
            call: 1,
            exit_status: 7,
        }))
        .unwrap();
        block_on(store.dispose(tau_web::dispatch::Disposition {
            machine: "fixture".into(),
            calls: vec![2],
            continuation: tau_web::dispatch::Continuation::AsIfNotDone,
            uncertainty: "the command outcome is unknown".into(),
        }))
        .unwrap();
        let files = storage.files();
        let opened = read(&files, PASS).unwrap();
        assert_eq!(
            opened.records.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            [0, 1, 2, 3, 4]
        );
        assert_eq!(
            opened.commands(),
            [
                (1, "fixture".to_string(), b"echo 1".to_vec()),
                (2, "fixture".to_string(), b"echo 2".to_vec())
            ]
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&opened.records[3].1).unwrap(),
            json!({"terminal":{"call":1,"exit_status":7}})
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&opened.records[4].1).unwrap()["disposition"]["continuation"],
            "as_if_not_done"
        );
        let mnemonic = opened.mnemonic().unwrap();
        assert_eq!(
            seed_secrets(&mnemonic).unwrap()[3].1,
            store.seed().unwrap().id().into_bytes()
        );
        assert!(read(&files, "correct horse battery stapler").is_err());

        // CNF-15, STG-10: no persisted byte holds a secret, in any encoding.
        let needles = needles(PASS, &opened).unwrap();
        assert!(needles.len() > 100);
        for (name, bytes) in &files {
            assert_eq!(found(&needles, bytes), Vec::<&str>::new(), "{name}");
        }
        // Decrypted, the seed is in the seed record alone, as its mnemonic, and no other secret
        // is anywhere.
        for (number, plaintext) in &opened.records {
            let found = found(&needles, plaintext);
            if *number == 0 {
                assert!(found.contains(&"the mnemonic, raw"), "{found:?}");
                assert!(
                    found.iter().all(|what| what.starts_with("the mnemonic")),
                    "the seed record holds only the mnemonic: {found:?}"
                );
            } else {
                assert_eq!(found, Vec::<&str>::new(), "record {number}");
            }
        }
    }

    #[test]
    fn the_harness_unlocks_and_replays_a_store_the_reader_built() {
        let entropy = ring::rand::generate::<[u8; 16]>(&ring::rand::SystemRandom::new())
            .unwrap()
            .expose();
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap().to_string();
        let files = build(
            PASS,
            &[
                json!({ "seed": { "mnemonic": mnemonic } }),
                json!({ "command": { "machine": "fixture", "command": hex::encode("echo 1") } }),
                json!({ "command": { "machine": "other", "command": hex::encode([0xff, 0]) } }),
            ],
        );
        let storage = MemoryStorage::with_files(files.clone());
        let store = block_on(unlock(
            storage.clone(),
            &Pbkdf2,
            tau_web::credential::LocalPassphrase::new(PASS.as_bytes().to_vec()),
        ))
        .unwrap();
        assert_eq!(store.records(), 0..3);
        assert_eq!(
            store.commands(),
            [
                (1, command(1)),
                (
                    2,
                    Entry {
                        machine: "other".into(),
                        command: vec![0xff, 0]
                    }
                )
            ]
        );
        assert_eq!(
            store.seed().unwrap().id().into_bytes(),
            seed_secrets(&mnemonic).unwrap()[3].1
        );
        assert_eq!(storage.files(), files, "an unlock writes nothing");
    }

    #[test]
    fn intent_approval_admits_only_a_pin_or_no_decision() {
        let intent = json!({"intent": {
            "call": 1, "machine": "private machine name", "command": "00"
        }});
        assert!(check_event(1, &intent).is_ok());
        for approval in [
            Value::Null,
            json!({"harness_pin": {"machine": "m", "fingerprint": "SHA256:pin"}}),
        ] {
            let mut event = intent.clone();
            event["intent"]["approval"] = approval;
            assert!(check_event(1, &event).is_ok());
        }
        for approval in [
            json!("legacy_command"),
            json!({"harness_pin": {"machine": "m", "fingerprint": "f", "extra": "private"}}),
            json!({"harness_pin": {"machine": "m", "fingerprint": "f"}, "extra": "private"}),
        ] {
            let mut event = intent.clone();
            event["intent"]["approval"] = approval;
            assert_eq!(
                check_event(1, &event),
                Err("intent admission has no machine or fingerprint".into())
            );
        }
        let mnemonic = bip39::Mnemonic::from_entropy(&[7; 16]).unwrap().to_string();
        let mut event = intent;
        event["intent"]["approval"] = json!("legacy_command");
        let files = build(PASS, &[json!({"seed": {"mnemonic": mnemonic}}), event]);
        assert_eq!(
            read(&files, PASS).err().unwrap(),
            "record 1: intent admission has no machine or fingerprint"
        );
    }

    /// An authentic record the harness cannot read is refused with a reason that quotes none of
    /// its plaintext: the reason reaches the page.
    #[test]
    fn a_refusal_quotes_no_plaintext() {
        let mnemonic = bip39::Mnemonic::from_entropy(&[7; 16]).unwrap().to_string();
        let files = build(
            PASS,
            &[
                json!({ "seed": { "mnemonic": mnemonic } }),
                json!({ "command": mnemonic }),
            ],
        );
        let refused = block_on(unlock(
            MemoryStorage::with_files(files),
            &Pbkdf2,
            tau_web::credential::LocalPassphrase::new(PASS.as_bytes().to_vec()),
        ))
        .err()
        .unwrap();
        assert_eq!(
            refused,
            "record 1: its event is not one this version reads; replay stopped"
        );
    }
}
