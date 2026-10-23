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

    pub fn seed_id(&self) -> Result<String, String> {
        seed_id(&self.mnemonic()?)
    }

    /// Read the encrypted completion independently; require this reader's own seed identifier.
    pub fn seed_backups(&self) -> Result<Vec<String>, String> {
        let id = self.seed_id()?;
        let mut completions = Vec::new();
        for (_, bytes) in &self.records {
            let event: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
            if let Some(record) = event.pointer("/allocation/seed_backup") {
                if record["seed"] != id {
                    return Err("completion names another seed".into());
                }
                if record.as_object().is_none_or(|o| o.len() != 2) {
                    return Err("completion has extra fields".into());
                }
                completions.push(
                    record["completion"]
                        .as_str()
                        .ok_or("completion is not text")?
                        .to_string(),
                );
            }
        }
        Ok(completions)
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
                if let Some(provenance) = body.get("provenance") {
                    exact(provenance, &["target", "session", "requester"])?;
                    target(&provenance["target"])?;
                    if !(provenance["session"].is_null()
                        || provenance["session"].as_str().is_some())
                        || !["session", "operator", "harness_flow"]
                            .contains(&provenance["requester"].as_str().unwrap_or(""))
                    {
                        return Err("invalid command provenance".into());
                    }
                }
                if body.get("request").is_some() {
                    return Err("unknown command request member".into());
                }
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
        "operation_intent" => {
            exact(
                body,
                &[
                    "call",
                    "resource",
                    "target",
                    "operation",
                    "session",
                    "requester",
                    "facts",
                    "approved",
                ],
            )?;
            if body["call"].as_u64() != Some(number) {
                return Err("typed identity differs from record number".into());
            }
            resource(&body["resource"])?;
            target(&body["target"])?;
            if body["resource"] == "inference" || body["target"] == "inference" {
                return Err("typed operation_intent cannot name inference".into());
            }
            if !["create", "reset", "reinstall", "destroy", "read"].contains(&text("operation")?)
                || !["session", "operator", "harness_flow"].contains(&text("requester")?)
            {
                return Err("unknown typed operation or requester".into());
            }
            text("session")?;
            facts(&body["facts"])?;
            exact(
                &body["approved"],
                &[
                    "resource",
                    "target",
                    "operation",
                    "session",
                    "requester",
                    "facts",
                ],
            )?;
            for key in [
                "resource",
                "target",
                "operation",
                "session",
                "requester",
                "facts",
            ] {
                if body[key] != body["approved"][key] {
                    return Err("typed intent differs from its approval".into());
                }
            }
        }
        "operation_observation" => {
            exact(body, &["resource", "operation", "reports", "calls"])?;
            resource(&body["resource"])?;
            if ![
                "create",
                "reset",
                "reinstall",
                "destroy",
                "read",
                "exec",
                "inference",
            ]
            .contains(&text("operation")?)
                || !["confirmed", "ended", "unknown"].contains(&text("reports")?)
                || !body["calls"]
                    .as_array()
                    .is_some_and(|calls| calls.iter().all(|call| call.as_u64().is_some()))
            {
                return Err("invalid typed observation".into());
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
                            && !record["exit_status"].as_u64().is_some_and(|s| s <= 128))
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
        "setup" => check_setup(body)?,
        "allocation" => {
            if let Some(record) = body.get("seed_backup")
                && (record.as_object().is_none_or(|o| o.len() != 2)
                    || record["seed"].as_str().is_none_or(|id| {
                        id.len() != 64
                            || !id
                                .bytes()
                                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    })
                    || ![json!("full_reentry"), json!("skipped")].contains(&record["completion"]))
            {
                return Err("invalid seed-backup record".into());
            }
        }
        _ => return Err(format!("unknown event kind {kind}")),
    }
    Ok(())
}

fn access(value: &Value) -> Result<(), String> {
    exact(value, &["model", "profile", "revision"])?;
    if value["model"] != "maintained"
        || value["profile"] != "ad-hoc"
        || value["revision"]
            .as_u64()
            .is_none_or(|n| u32::try_from(n).is_err())
    {
        return Err("invalid ad-hoc access".into());
    }
    Ok(())
}
fn check_setup(value: &Value) -> Result<(), String> {
    let object = value.as_object().ok_or("setup is not an object")?;
    if object.len() != 1 {
        return Err("setup must name one act".into());
    }
    let (kind, body) = object.iter().next().unwrap();
    match kind.as_str() {
        "approval" => {
            exact(body, &["entries", "monthly_sat", "annual_sat"])?;
            let entries = body["entries"]
                .as_array()
                .filter(|e| !e.is_empty())
                .ok_or("empty setup")?;
            let mut names = std::collections::BTreeSet::new();
            let mut total = 0u64;
            for approved in entries {
                exact(approved, &["entry", "identity", "access"])?;
                let entry = &approved["entry"];
                exact(entry, &["machine", "vendor", "product", "region", "cost"])?;
                for key in ["machine", "vendor", "product", "region"] {
                    if entry[key].as_str().is_none_or(str::is_empty) {
                        return Err("invalid machine fact".into());
                    }
                }
                if !names.insert(entry["machine"].as_str().unwrap()) {
                    return Err("duplicate approved entry".into());
                }
                exact(&entry["cost"], &["amount", "unit", "period"])?;
                if entry["cost"]["unit"] != "sat" || entry["cost"]["period"] != "month" {
                    return Err("invalid recurring cost".into());
                }
                total = total
                    .checked_add(
                        entry["cost"]["amount"]
                            .as_u64()
                            .ok_or("cost is not integer")?,
                    )
                    .ok_or("cost overflow")?;
                let id = &approved["identity"];
                exact(id, &["seed", "derivation_version", "family", "index"])?;
                if id["seed"].as_str().is_none_or(|s| {
                    s.len() != 64
                        || !s
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                }) || id["derivation_version"] != 1
                    || id["family"] != "machines"
                    || !id["index"].as_u64().is_some_and(|n| n < (1 << 31))
                {
                    return Err("invalid approved allocation identity".into());
                }
                if !approved["access"].is_null() {
                    access(&approved["access"])?;
                }
            }
            let monthly = body["monthly_sat"]
                .as_u64()
                .ok_or("monthly total is not integer")?;
            let annual = body["annual_sat"]
                .as_u64()
                .ok_or("annual total is not integer")?;
            let expected_annual = total.checked_mul(12).ok_or("annual cost overflow")?;
            if monthly != total || annual != expected_annual {
                return Err("incorrect setup totals".into());
            }
        }
        "class" => {
            exact(body, &["machine", "answer", "class"])?;
            if !body["machine"].is_string() {
                return Err("class needs a machine".into());
            }
            let class = match body["answer"].as_str() {
                Some("yes" | "not_sure") => "multi_tenant",
                Some("no") => "single_purpose",
                _ => return Err("unknown class answer".into()),
            };
            if body["class"] != class {
                return Err("class differs from answer".into());
            }
        }
        "access" => {
            exact(body, &["machine", "access"])?;
            if !body["machine"].is_string() {
                return Err("access needs a machine".into());
            }
            access(&body["access"])?;
        }
        _ => return Err("unknown setup act".into()),
    }
    Ok(())
}

/// Independent fixture records, preceding every reader-built store's new dispatches.
pub fn setup_events(mnemonic: &str, machines: &[&str]) -> Vec<Value> {
    let seed = seed_id(mnemonic).expect("fixture mnemonic");
    let entries: Vec<_> = machines.iter().enumerate().map(|(index, machine)| json!({
        "entry":{"machine":machine,"vendor":"Fixture vendor","product":"Fixture machine","region":"Fixture region","cost":{"amount":1000,"unit":"sat","period":"month"}},
        "identity":{"seed":seed,"derivation_version":1,"family":"machines","index":index},
        "access":{"model":"maintained","profile":"ad-hoc","revision":3}
    })).collect();
    vec![
        json!({"allocation":{"seed_backup":{"seed":seed,"completion":"skipped"}}}),
        json!({"setup":{"approval":{"entries":entries,"monthly_sat":1000*machines.len(),"annual_sat":12000*machines.len()}}}),
    ]
}

fn exact(value: &Value, fields: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("record body is not an object")?;
    if object.len() != fields.len() || fields.iter().any(|k| !object.contains_key(*k)) {
        return Err("unknown or missing typed member".into());
    }
    Ok(())
}

fn resource(value: &Value) -> Result<(), String> {
    if value == "inference" {
        return Ok(());
    }
    exact(value, &["entry"])?;
    if value["entry"].as_str().is_none() {
        return Err("resource entry is not text".into());
    }
    Ok(())
}

fn target(value: &Value) -> Result<(), String> {
    if value == "inference" {
        return Ok(());
    }
    let object = value.as_object().ok_or("typed target is not an object")?;
    if object.len() == 1
        && (value["entry"].is_string()
            || value["vendor_machine"].is_string()
            || value["allocation_index"]
                .as_u64()
                .is_some_and(|n| n <= u64::from(u32::MAX)))
    {
        return Ok(());
    }
    Err("unknown typed target".into())
}

fn facts(value: &Value) -> Result<(), String> {
    exact(value, &["arguments", "cost_bound", "bundle_commit"])?;
    if value["arguments"]
        .as_object()
        .is_none_or(|a| a.values().any(|v| !v.is_string()))
        || value["cost_bound"].as_u64().is_none()
        || !value["bundle_commit"].is_string()
    {
        return Err("invalid typed facts".into());
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

pub fn seed_id(mnemonic: &str) -> Result<String, String> {
    let seed = bip39::Mnemonic::parse_normalized(mnemonic)
        .map_err(|e| e.to_string())?
        .to_seed_normalized("");
    let mut bytes = b"tau-web seed id v1\0".to_vec();
    bytes.extend_from_slice(&seed);
    Ok(hex::encode(digest(&SHA256, &bytes)))
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
    let mut needles: Vec<_> = secrets
        .drain(..)
        .flat_map(|(what, bytes)| encodings(&what, &bytes))
        .collect();
    needles.extend(seed_needles(&opened.mnemonic()?)?);
    Ok(needles)
}

/// Phrase encodings and structural array detection, independent of public JSON field names.
pub fn mnemonic_needles(mnemonic: &str) -> Vec<(String, Vec<u8>)> {
    let mut needles = encodings("the mnemonic", mnemonic.as_bytes());
    needles.push((
        "the mnemonic word array".into(),
        serde_json::to_vec(&mnemonic.split_ascii_whitespace().collect::<Vec<_>>()).expect("words"),
    ));
    needles
}

pub fn seed_needles(mnemonic: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut needles: Vec<_> = seed_secrets(mnemonic)?
        .into_iter()
        .filter(|(what, _)| what != "the mnemonic")
        .flat_map(|(what, bytes)| encodings(&what, &bytes))
        .collect();
    needles.extend(mnemonic_needles(mnemonic));
    Ok(needles)
}

// Only consecutive string elements of an actual array can be consecutive mnemonic words.
// An object value followed by a field name is never such a pair.
fn word_array(value: &Value, words: &[Value]) -> bool {
    match value {
        Value::Array(items) => {
            items
                .windows(2)
                .any(|pair| words.windows(2).any(|w| w == pair))
                || items.iter().any(|v| word_array(v, words))
        }
        Value::Object(fields) => fields.values().any(|v| word_array(v, words)),
        _ => false,
    }
}

/// Which needles occur in `bytes`, including consecutive mnemonic elements in parsed arrays.
pub fn found<'a>(needles: &'a [(String, Vec<u8>)], bytes: &[u8]) -> Vec<&'a str> {
    let parsed = serde_json::from_slice::<Value>(bytes).ok();
    let text = std::str::from_utf8(bytes).ok();
    needles
        .iter()
        .filter(|(what, needle)| {
            if what == "the mnemonic word array" {
                let words: Vec<Value> = serde_json::from_slice(needle).expect("mnemonic array");
                parsed.as_ref().is_some_and(|v| word_array(v, &words))
            } else if let (Some(text), Ok(needle)) = (text, std::str::from_utf8(needle)) {
                text.contains(needle)
            } else {
                bytes.windows(needle.len()).any(|w| w == needle.as_slice())
            }
        })
        .map(|(what, _)| what.as_str())
        .collect()
}

/// Allocation records carry their own seed association inside encryption. Search all other
/// fields with every needle, including seed identifiers outside those exact positions.
pub fn record_findings<'a>(
    needles: &'a [(String, Vec<u8>)],
    bytes: &[u8],
    seed_id: &str,
) -> Vec<&'a str> {
    let mut event: Value = serde_json::from_slice(bytes).expect("reader checked JSON");
    for path in [
        "/allocation/seed_backup/seed",
        "/allocation/reserve/seed",
        "/allocation/created/seed",
        "/allocation/failed/seed",
        "/allocation/destroyed/seed",
        "/allocation/restore/seed",
        "/allocation/replace/seed",
    ] {
        if let Some(value) = event.pointer_mut(path)
            && value == seed_id
        {
            *value = Value::Null;
        }
    }
    if let Some(entries) = event
        .pointer_mut("/allocation/restore/entries")
        .and_then(Value::as_array_mut)
    {
        for entry in entries {
            if let Some(value) = entry.pointer_mut("/identity/seed")
                && value == seed_id
            {
                *value = Value::Null;
            }
        }
    }
    if let Some(entries) = event
        .pointer_mut("/setup/approval/entries")
        .and_then(Value::as_array_mut)
    {
        for entry in entries {
            if let Some(value) = entry.pointer_mut("/identity/seed")
                && value == seed_id
            {
                *value = Value::Null;
            }
        }
    }
    found(needles, event.to_string().as_bytes())
}

/// `CNF-82` and `CNF-15`'s host half, against the harness's store on its in-memory storage.
#[cfg(test)]
mod tests {
    use super::*;
    use tau_web::harness::{Entry, Journal};
    use tau_web::store::{MemoryStorage, Pbkdf2, block_on, create, unlock};

    #[test]
    fn recorded_access_revision_is_preserved_and_unsupported_shapes_are_refused() {
        let mnemonic = bip39::Mnemonic::from_entropy(&[7; 16]).unwrap().to_string();
        for revision in [4u32, u32::MAX] {
            let mut events = vec![json!({"seed":{"mnemonic":mnemonic}})];
            events.extend(setup_events(&mnemonic, &["fixture", "fixture-other"]));
            events[2]["setup"]["approval"]["entries"][0]["access"]["revision"] = revision.into();
            events.push(
                json!({"setup":{"access":{"machine":"fixture-other","access":{
                    "model":"maintained","profile":"ad-hoc","revision":revision
                }}}}),
            );
            let opened = read(&build(PASS, &events), PASS).unwrap();
            for index in [2, 3] {
                let actual: Value = serde_json::from_slice(&opened.records[index].1).unwrap();
                assert_eq!(actual, events[index]);
            }
        }
        let valid = json!({"model":"maintained","profile":"ad-hoc","revision":4});
        assert!(access(&valid).is_ok());
        for (key, value) in [
            ("model", json!("sealed")),
            ("profile", json!("other")),
            ("revision", json!(u64::from(u32::MAX) + 1)),
            ("revision", json!(-1)),
            ("revision", json!(1.5)),
            ("revision", json!("4")),
            ("revision", json!(true)),
            ("revision", Value::Null),
        ] {
            let mut bad = valid.clone();
            bad[key] = value;
            assert!(access(&bad).is_err(), "{bad}");
        }
        for key in ["model", "profile", "revision"] {
            let mut bad = valid.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(access(&bad).is_err(), "missing {key}");
        }
        let mut extra = valid;
        extra["extra"] = true.into();
        assert!(access(&extra).is_err());
        assert!(access(&json!(["maintained", "ad-hoc", 4])).is_err());
    }

    #[test]
    fn setup_totals_refuse_overflow_and_non_unsigned_integers() {
        let mnemonic = bip39::Mnemonic::from_entropy(&[7; 16]).unwrap().to_string();
        let mut approval = setup_events(&mnemonic, &["fixture"])[1]["setup"].clone();
        approval["approval"]["entries"][0]["entry"]["cost"]["amount"] = json!(u64::MAX);
        approval["approval"]["monthly_sat"] = json!(u64::MAX);
        approval["approval"]["annual_sat"] = Value::Null;
        assert!(
            check_setup(&approval).is_err(),
            "annual overflow with null total"
        );

        let valid = setup_events(&mnemonic, &["fixture"])[1]["setup"].clone();
        for key in ["monthly_sat", "annual_sat"] {
            for value in [
                Value::Null,
                json!(-1),
                json!(1.5),
                json!("12000"),
                json!(true),
            ] {
                let mut bad = valid.clone();
                bad["approval"][key] = value;
                assert!(check_setup(&bad).is_err(), "{key}: {bad}");
            }
        }
        let mut sum = setup_events(&mnemonic, &["fixture", "fixture-other"])[1]["setup"].clone();
        sum["approval"]["entries"][0]["entry"]["cost"]["amount"] = json!(u64::MAX);
        assert!(check_setup(&sum).is_err(), "monthly sum overflow");
        assert!(check_setup(&valid).is_ok());
    }

    #[test]
    fn setup_shapes_are_exact_and_seed_custody_is_position_specific() {
        let mnemonic = bip39::Mnemonic::from_entropy(&[7; 16]).unwrap().to_string();
        let seed = seed_id(&mnemonic).unwrap();
        let mut events = vec![json!({"seed":{"mnemonic":mnemonic}})];
        events.extend(setup_events(&mnemonic, &["fixture", "fixture-other"]));
        events.push(json!({"setup":{"class":{"machine":"fixture","answer":"not_sure","class":"multi_tenant"}}}));
        events.push(json!({"setup":{"access":{"machine":"fixture-other","access":{"model":"maintained","profile":"ad-hoc","revision":3}}}}));
        let opened = read(&build(PASS, &events), PASS).unwrap();
        assert_eq!(opened.records.len(), 5);
        let needles = seed_needles(&mnemonic).unwrap();
        for (_, plain) in &opened.records[1..] {
            assert!(record_findings(&needles, plain, &seed).is_empty());
        }
        for (index, path, value) in [
            (2, "/setup/approval/entries/0/entry/vendor", json!(seed)),
            (2, "/setup/approval/entries/0/identity/seed", json!("wrong")),
            (2, "/setup/approval/monthly_sat", json!(0)),
            (2, "/setup/approval/entries/0/access/model", json!("sealed")),
            (3, "/setup/class/answer", json!("unknown")),
            (3, "/setup/class/class", json!("single_purpose")),
            (4, "/setup/access/access/model", json!("sealed")),
        ] {
            let mut bad = events[index].clone();
            *bad.pointer_mut(path).unwrap() = value;
            if path.ends_with("vendor") {
                assert!(
                    !record_findings(&needles, &serde_json::to_vec(&bad).unwrap(), &seed)
                        .is_empty()
                );
            } else {
                assert!(check_event(index as u64, &bad).is_err(), "{path}");
            }
        }
        for (index, event) in events.iter().enumerate().skip(2) {
            let mut bad = event.clone();
            bad["setup"]
                .as_object_mut()
                .unwrap()
                .values_mut()
                .next()
                .unwrap()["unknown"] = true.into();
            assert!(check_event(index as u64, &bad).is_err());
        }
    }

    const PASS: &str = "correct horse battery staple";

    #[test]
    fn typed_records_are_read_independently_and_replayed_by_the_store() {
        let mnemonic = bip39::Mnemonic::from_entropy(&[7; 16]).unwrap().to_string();
        for operation in ["create", "reset", "reinstall", "destroy", "read"] {
            let intent = super::super::typed_cases::intent(1, operation);
            let observation = json!({"operation_observation":{"resource":{"entry":"fixture"},
                "operation":operation,"reports":"confirmed","calls":[1]}});
            let files = build(
                PASS,
                &[
                    json!({"seed":{"mnemonic":mnemonic}}),
                    intent.clone(),
                    observation.clone(),
                ],
            );
            let opened = read(&files, PASS).unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&opened.records[1].1).unwrap(),
                intent
            );
            assert_eq!(
                serde_json::from_slice::<Value>(&opened.records[2].1).unwrap(),
                observation
            );
            let replayed = block_on(unlock(
                MemoryStorage::with_files(files),
                &Pbkdf2,
                tau_web::credential::LocalPassphrase::new(PASS.as_bytes().to_vec()),
            ))
            .unwrap();
            assert_eq!(
                replayed.dispatch().typed_calls[&1].state,
                if operation == "read" {
                    tau_web::dispatch::CallState::NoEffect
                } else {
                    tau_web::dispatch::CallState::Confirmed { observation: 2 }
                }
            );
            let mut bad = intent.clone();
            bad["operation_intent"]["facts"]["cost_bound"] = json!(99);
            assert!(check_event(1, &bad).is_err());
            let mut bad = observation;
            bad["operation_observation"]["extra"] = json!(true);
            assert!(check_event(2, &bad).is_err());
        }
    }

    #[test]
    fn production_command_provenance_keeps_the_job_evidence_path() {
        let storage = MemoryStorage::default();
        let pass = || tau_web::credential::LocalPassphrase::new(PASS.as_bytes().to_vec());
        let mut store = block_on(create(storage.clone(), &Pbkdf2, pass())).unwrap();
        block_on(store.seed_backup(tau_web::allocation::Completion::Skipped)).unwrap();
        let approval = block_on(store.approve_setup(tau_web::dispatch::fixture_setup())).unwrap();
        let index = approval.entries[0].identity.index;
        let entry = Entry {
            machine: "fixture".into(),
            command: b"true".to_vec(),
            provenance: Some(tau_web::dispatch::CommandProvenance {
                target: tau_web::dispatch::Target::AllocationIndex(index),
                session: Some("later-session".into()),
                requester: tau_web::dispatch::Requester::Operator,
            }),
        };
        let admission = tau_web::dispatch::Approval::HarnessPin {
            machine: "fixture".into(),
            fingerprint: "SHA256:fixture".into(),
        };
        assert_eq!(block_on(store.check("fixture")), Ok(()));
        let call = block_on(store.append(&entry, &admission)).unwrap();
        let opened = read(&storage.files(), PASS).unwrap();
        let intent: Value = serde_json::from_slice(&opened.records[3].1).unwrap();
        assert_eq!(
            intent["intent"]["provenance"],
            json!({"target":{"allocation_index":index},
            "session":"later-session","requester":"operator"})
        );
        assert_eq!(
            intent["intent"]["approval"]["harness_pin"]["fingerprint"],
            "SHA256:fixture"
        );
        assert!(intent["intent"].get("request").is_none());
        let job = store.dispatch().calls[&call].intent.job.clone().unwrap();
        drop(store);
        let mut store = block_on(unlock(
            MemoryStorage::with_files(storage.files()),
            &Pbkdf2,
            pass(),
        ))
        .unwrap();
        assert_eq!(
            store.dispatch().calls[&call].intent.provenance,
            entry.provenance
        );
        let evidence = tau_web::jobs::Evidence {
            call,
            job,
            record: tau_web::jobs::Record::Present {
                machine: hex::encode("fixture"),
                command: hex::encode("true"),
                boot: "fixture-boot".into(),
                current_boot: "fixture-boot".into(),
                pid: 7,
                alive: false,
                exit_status: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            },
        };
        block_on(store.job_evidence(&evidence)).unwrap();
        let opened = read(&store.storage().files(), PASS).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&opened.records[4].1).unwrap()["job_terminal"]["call"],
            call
        );
    }

    #[test]
    fn independent_reader_refuses_typed_exec_and_inference_naming_the_record() {
        let mnemonic = bip39::Mnemonic::from_entropy(&[7; 16]).unwrap().to_string();
        for (operation, inference_resource, inference_target) in [
            ("exec", false, false),
            ("inference", true, true),
            ("create", true, false),
            ("create", false, true),
            ("read", true, true),
        ] {
            let mut event = super::super::typed_cases::intent(1, operation);
            if inference_resource {
                for pointer in [
                    "/operation_intent/resource",
                    "/operation_intent/approved/resource",
                ] {
                    *event.pointer_mut(pointer).unwrap() = json!("inference");
                }
            }
            if inference_target {
                for pointer in [
                    "/operation_intent/target",
                    "/operation_intent/approved/target",
                ] {
                    *event.pointer_mut(pointer).unwrap() = json!("inference");
                }
            }
            let files = build(PASS, &[json!({"seed":{"mnemonic":mnemonic}}), event]);
            let why = read(&files, PASS).err().expect("unsupported typed record");
            assert!(
                why.contains("record 1") && why.contains("typed operation"),
                "{why}"
            );
        }
    }

    fn command(n: u8) -> Entry {
        Entry {
            provenance: None,
            machine: "fixture".into(),
            command: format!("echo {n}").into_bytes(),
        }
    }

    #[test]
    fn collision_controls_allow_public_fields_and_find_mnemonic_arrays_in_records() {
        for mnemonic in include_str!("../../tests/vectors/seed-backup-collisions.txt").lines() {
            let id = seed_id(mnemonic).unwrap();
            let events = vec![
                json!({"seed":{"mnemonic":mnemonic}}),
                json!({"intent":{"call":1,"machine":"other","command":"00",
                    "approval":{"harness_pin":{"machine":"other","fingerprint":"SHA256:test-pin"}},
                    "job":"00".repeat(24)}}),
                json!({"job_observation":{"call":1,"job":"00".repeat(24),"record":{"kind":"missing"}}}),
                json!({"terminal":{"call":1,"exit_status":0}}),
                json!({"allocation":{"seed_backup":{"seed":id,"completion":"skipped"}}}),
                json!({"allocation":{"reserve":{"seed":id,"derivation_version":1,"family":"machines","index":0}}}),
            ];
            let files = build(PASS, &events);
            let replayed = block_on(unlock(
                MemoryStorage::with_files(files.clone()),
                &Pbkdf2,
                tau_web::credential::LocalPassphrase::new(PASS.as_bytes().to_vec()),
            ))
            .unwrap();
            assert_eq!(
                replayed
                    .allocation()
                    .issue(tau_web::allocation::Family::Machines)
                    .unwrap()
                    .index,
                1
            );
            let opened = read(&files, PASS).unwrap();
            let needles = needles(PASS, &opened).unwrap();
            for (number, bytes) in opened.records.iter().skip(1) {
                assert!(
                    record_findings(&needles, bytes, &id).is_empty(),
                    "record {number}"
                );
            }
            let mut id_leak = events[4].clone();
            id_leak["other"] = json!(id);
            assert!(
                record_findings(&needles, id_leak.to_string().as_bytes(), &id)
                    .contains(&"the seed identifier, raw")
            );
            let mut leak = events[1].clone();
            leak["intent"]["words"] = json!(mnemonic.split(' ').collect::<Vec<_>>());
            let mut leaked_events = events.clone();
            leaked_events[1] = leak;
            let leaked = read(&build(PASS, &leaked_events), PASS).unwrap();
            assert!(
                record_findings(&needles, &leaked.records[1].1, &id)
                    .contains(&"the mnemonic word array")
            );
            for shape in [
                json!({"call":"machine","other":"family"}),
                json!({"match":"this","try":"again"}),
            ] {
                assert!(record_findings(&needles, shape.to_string().as_bytes(), &id).is_empty());
            }
        }
    }

    #[test]
    fn allocation_seed_associations_are_exempt_only_at_the_event_fields() {
        for mnemonic in include_str!("../../tests/vectors/seed-backup-collisions.txt").lines() {
            let id = seed_id(mnemonic).unwrap();
            let identity = json!({"seed":id,"derivation_version":1,"family":"machines","index":0});
            let export = json!({"seed":id,"derivation_version":1,
                "next_unused":{"machines":2,"passes":0,"handoffs":0},
                "entries":[{"identity":identity,"status":"created"},
                           {"identity":identity,"status":"failed"}],
                "restored_from_import":false,"seed_backup":"skipped"});
            let events = vec![
                json!({"allocation":{"seed_backup":{"seed":id,"completion":"skipped"}}}),
                json!({"allocation":{"reserve":identity}}),
                json!({"allocation":{"created":identity}}),
                json!({"allocation":{"failed":identity}}),
                json!({"allocation":{"destroyed":identity}}),
                json!({"allocation":{"restore":export}}),
                json!({"allocation":{"replace":{"seed":id}}}),
            ];
            let mut records = vec![json!({"seed":{"mnemonic":mnemonic}})];
            records.extend(events.clone());
            let opened = read(&build(PASS, &records), PASS).unwrap();
            let needles = needles(PASS, &opened).unwrap();
            for ((_, bytes), event) in opened.records.iter().skip(1).zip(events) {
                assert!(record_findings(&needles, bytes, &id).is_empty(), "{event}");
                let mut leak = event.clone();
                leak["allocation"]["other"] = json!(id);
                assert!(
                    record_findings(&needles, leak.to_string().as_bytes(), &id)
                        .contains(&"the seed identifier, raw"),
                    "{leak}"
                );
            }
            for path in ["/seed", "/identity/seed", "/allocation/other/seed"] {
                let mut leak = json!({"seed":null,"identity":{"seed":null},"allocation":{"other":{"seed":null}}});
                *leak.pointer_mut(path).unwrap() = json!(id);
                assert!(
                    record_findings(&needles, leak.to_string().as_bytes(), &id)
                        .contains(&"the seed identifier, raw"),
                    "{path}"
                );
            }
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
        block_on(store.seed_backup(tau_web::allocation::Completion::Skipped)).unwrap();
        let mut entries = tau_web::dispatch::fixture_setup();
        entries[1].machine = "other".into();
        block_on(store.approve_setup(entries)).unwrap();
        for n in 1..=2 {
            let mut entry = command(n);
            if n == 2 {
                entry.machine = "other".into();
            }
            block_on(store.append(
                &entry,
                &tau_web::dispatch::Approval::HarnessPin {
                    machine: entry.machine.clone(),
                    fingerprint: "SHA256:test-pin".into(),
                },
            ))
            .unwrap();
        }
        block_on(store.terminal(&tau_web::dispatch::Terminal {
            call: 3,
            exit_status: 7,
        }))
        .unwrap();
        block_on(store.dispose(tau_web::dispatch::Disposition {
            machine: "other".into(),
            calls: vec![4],
            continuation: tau_web::dispatch::Continuation::AsIfNotDone,
            uncertainty: "the command outcome is unknown".into(),
        }))
        .unwrap();
        let files = storage.files();
        let opened = read(&files, PASS).unwrap();
        assert_eq!(
            opened.records.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            [0, 1, 2, 3, 4, 5, 6]
        );
        assert_eq!(
            opened.commands(),
            [
                (3, "fixture".to_string(), b"echo 1".to_vec()),
                (4, "other".to_string(), b"echo 2".to_vec())
            ]
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&opened.records[5].1).unwrap(),
            json!({"terminal":{"call":3,"exit_status":7}})
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&opened.records[6].1).unwrap()["disposition"]["continuation"],
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
                assert_eq!(
                    record_findings(&needles, plaintext, &opened.seed_id().unwrap()),
                    Vec::<&str>::new(),
                    "record {number}"
                );
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
                        provenance: None,
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

    /// The reader's exit-status ceiling is the job record's own (`src/jobs.rs`): a status above
    /// 128 is refused, as `Record::validate` refuses it.
    #[test]
    fn job_terminal_exit_status_ceiling_is_128() {
        let terminal = |status: u64| {
            json!({"job_terminal": {
                "call": 1,
                "job": "0".repeat(48),
                "record": {
                    "kind": "present", "machine": "6d", "command": "00", "stdout": "", "stderr": "",
                    "boot": "b", "current_boot": "b", "pid": 7, "alive": false,
                    "exit_status": status
                }
            }})
        };
        for status in [0, 1, 128] {
            assert!(check_event(1, &terminal(status)).is_ok(), "status {status}");
        }
        for status in [129, 137, 255] {
            assert_eq!(
                check_event(1, &terminal(status)),
                Err("job has invalid liveness or exit code".into()),
                "status {status}"
            );
        }
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
