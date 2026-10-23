use super::tests::encodings;
use super::*;
use crate::dispatch::fixture::{self, ROOT_PASSWORD, Vendor};
use crate::dispatch::typed_tests::{bound_fresh, bound_request, reopen};
use crate::dispatch::{CallState, Operation};
use crate::redaction::{MARKER, Redacted};

/// Independent absence oracle: derives with bip39/bip32, never the boundary's held set.
fn secrets(store: &Store<MemoryStorage>) -> Vec<(String, Vec<u8>)> {
    use bip32::{ChildNumber, XPrv};
    let phrase = store.seed().unwrap().phrase();
    let parsed = bip39::Mnemonic::parse_normalized(&phrase).unwrap();
    let seed = parsed.to_seed_normalized("");
    let mut out = vec![
        ("mnemonic".into(), phrase.as_bytes().to_vec()),
        ("seed".into(), seed.to_vec()),
        ("data key".into(), store.key.0.to_vec()),
    ];
    let child = |key: &XPrv, index| {
        key.derive_child(ChildNumber::new(index, true).unwrap())
            .unwrap()
    };
    let top = child(&child(&XPrv::new(seed).unwrap(), 707_285), 1);
    for entry in store.allocation().entries() {
        let roles: &[u32] = match entry.identity.family {
            Family::Machines => &[0, 1, 2],
            Family::Passes => &[3],
            Family::Handoffs => &[4],
        };
        for &role in roles {
            let key = child(&child(&top, role), entry.identity.index);
            out.push((
                format!("role {role} index {}", entry.identity.index),
                key.private_key().to_bytes().to_vec(),
            ));
        }
    }
    out
}

fn absence_needles(secrets: &[(String, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
    secrets
        .iter()
        .flat_map(|(name, value)| encodings(name, value))
        .chain(encodings("passphrase", b"fixture passphrase only"))
        .chain(encodings("wrapping key", &[7; 32]))
        .collect()
}

fn plaintext(store: &Store<MemoryStorage>, number: u64) -> Vec<u8> {
    let record: RecordJson =
        serde_json::from_slice(&store.storage().files()[&number.to_string()]).unwrap();
    cipher(&store.key.0)
        .decrypt(
            &decode::<12>("nonce", &record.nonce).unwrap().into(),
            Payload {
                msg: &URL_SAFE_NO_PAD.decode(&record.ciphertext).unwrap(),
                aad: record_aad(&record.id, &record.kind, number, &record.previous).as_bytes(),
            },
        )
        .unwrap()
}

/// Search all plaintext records, plus decoded response bodies. Record 0's intentional mnemonic
/// is the sole exclusion; searches report a label and encoding, never secret bytes.
fn journal_findings(store: &Store<MemoryStorage>, needles: &[(String, Vec<u8>)]) -> Vec<String> {
    let mut found = Vec::new();
    for number in store.records() {
        let plaintext = plaintext(store, number);
        let value: Value = serde_json::from_slice(&plaintext).unwrap();
        let mut haystacks = vec![("plaintext", plaintext)];
        if let Some(body) = value.get("operation_response") {
            haystacks.push((
                "decoded response",
                hex::decode(body["body"].as_str().unwrap()).unwrap(),
            ));
        }
        for (where_, bytes) in haystacks {
            for (label, needle) in needles {
                if number == 0 && label.starts_with("mnemonic,") {
                    continue;
                }
                if bytes.windows(needle.len()).any(|w| w == needle) {
                    found.push(format!("record {number}, {where_}: {label}"));
                }
            }
        }
    }
    found
}

fn output_findings(output: &Redacted, needles: &[(String, Vec<u8>)]) -> Vec<String> {
    needles
        .iter()
        .filter(|(_, needle)| output.as_bytes().windows(needle.len()).any(|w| w == needle))
        .map(|(label, _)| format!("returned output: {label}"))
        .collect()
}

fn root_response() -> (Store<MemoryStorage>, Redacted, u64) {
    let (_, mut store, _) = bound_fresh();
    let request = bound_request(&store, Operation::Reset, "fixture");
    let mut vendor = Vendor {
        response: Some(
            serde_json::to_vec(&json!({"root_password":ROOT_PASSWORD,"other":"kept"})).unwrap(),
        ),
        ..Default::default()
    };
    let (call, output) =
        block_on(vendor.run_response(&mut store, Some(&request.session), &request)).unwrap();
    (store, output.unwrap(), call)
}

#[test]
fn cnf14_journal_contains_no_root_password() {
    let (store, output, call) = root_response();
    let mut needles = absence_needles(&secrets(&store));
    needles.extend(encodings("root password", ROOT_PASSWORD.as_bytes()));
    let found = journal_findings(&store, &needles);
    assert!(found.is_empty(), "{}", found.join("; "));
    let number = store.next - 1;
    let event: Value = serde_json::from_slice(&plaintext(&store, number)).unwrap();
    assert_eq!(event["operation_response"]["call"], call);
    assert_eq!(
        hex::decode(event["operation_response"]["body"].as_str().unwrap()).unwrap(),
        output.as_bytes()
    );
    assert_eq!(
        serde_json::from_slice::<Value>(output.as_bytes()).unwrap(),
        json!({"root_password":MARKER,"other":"kept"})
    );
    assert_eq!(
        store.dispatch().typed_calls[&call].state,
        CallState::Unresolved
    );
}

#[test]
fn cnf14_model_context_contains_no_root_password() {
    let (store, output, _) = root_response();
    let mut needles = absence_needles(&secrets(&store));
    needles.extend(encodings("root password", ROOT_PASSWORD.as_bytes()));
    let found = output_findings(&output, &needles);
    assert!(found.is_empty(), "{}", found.join("; "));
}

#[test]
fn declared_fields_keep_null_absence_and_other_members_and_refuse_non_json() {
    for body in [
        b"{\"other\":42}".as_slice(),
        b"{\"root_password\":null,\"other\":42}",
    ] {
        let (_, mut store, _) = bound_fresh();
        let request = bound_request(&store, Operation::Reset, "fixture");
        let mut vendor = Vendor {
            response: Some(body.to_vec()),
            ..Default::default()
        };
        let (_, output) =
            block_on(vendor.run_response(&mut store, Some(&request.session), &request)).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(output.unwrap().as_bytes()).unwrap(),
            serde_json::from_slice::<Value>(body).unwrap()
        );
    }
    let (_, mut store, _) = bound_fresh();
    let request = bound_request(&store, Operation::Reset, "fixture");
    let before = store.next;
    let mut body = ROOT_PASSWORD.as_bytes().to_vec();
    body.extend_from_slice(store.seed().unwrap().phrase().as_bytes());
    let mut vendor = Vendor {
        response: Some(body.clone()),
        ..Default::default()
    };
    let error =
        block_on(vendor.run_response(&mut store, Some(&request.session), &request)).unwrap_err();
    assert_eq!(store.next, before + 1, "only the intent commits");
    assert_eq!(
        store.dispatch().typed_calls[&before].state,
        CallState::Unresolved
    );
    let error = format!("{error:?}");
    for (_, needle) in absence_needles(&secrets(&store))
        .into_iter()
        .chain(encodings("root password", ROOT_PASSWORD.as_bytes()))
    {
        assert!(
            !error.as_bytes().windows(needle.len()).any(|w| w == needle),
            "refusal disclosed a credential"
        );
    }
    assert!(!error.as_bytes().windows(body.len()).any(|w| w == body));
    assert_eq!(
        error,
        "Storage(\"response is not JSON for declared fields\")"
    );
}

#[test]
fn cnf17_each_held_credential_is_absent_from_journal_and_model_context() {
    let (_, mut store, _) = bound_fresh();
    // Cover all listed identities, including failed/destroyed tombstones and reserved entries.
    for family in [Family::Passes, Family::Handoffs] {
        let identity = block_on(store.allocate(family)).unwrap();
        block_on(store.observe(allocation::Event::Failed(identity))).unwrap();
        let identity = block_on(store.allocate(family)).unwrap();
        block_on(store.observe(allocation::Event::Created(identity.clone()))).unwrap();
        block_on(store.observe(allocation::Event::Destroyed(identity))).unwrap();
    }
    let secrets = secrets(&store);
    let needles = absence_needles(&secrets);
    let mut failures = Vec::new();
    for (label, secret) in &secrets {
        let request = bound_request(&store, Operation::Read, "fixture");
        let call =
            block_on(Vendor::default().run(&mut store, Some(&request.session), &request)).unwrap();
        let body = [b"prefix:".as_slice(), secret, b":suffix"].concat();
        let output = block_on(fixture::injected_response(&mut store, call, &body)).unwrap();
        failures.extend(output_findings(&output, &needles));
        if !output
            .as_bytes()
            .windows(MARKER.len())
            .any(|w| w == MARKER.as_bytes())
        {
            failures.push(format!("{label}: no marker"));
        }
    }
    failures.extend(journal_findings(&store, &needles));
    assert!(failures.is_empty(), "{}", failures.join("; "));
}

#[test]
fn live_session_holdings_are_scanned_even_without_a_listed_derivation() {
    let (_, mut store, _) = bound_fresh();
    let session_secret = [23u8; 32];
    store.sessions.push(Rc::new(Session::new(
        "extra-session".into(),
        "fixture".into(),
        crate::credential::SshClientKey(session_secret),
    )));
    let request = bound_request(&store, Operation::Read, "fixture");
    let call =
        block_on(Vendor::default().run(&mut store, Some(&request.session), &request)).unwrap();
    let output = block_on(fixture::injected_response(
        &mut store,
        call,
        &session_secret,
    ))
    .unwrap();
    let needles = encodings("session client key", &session_secret);
    assert!(output_findings(&output, &needles).is_empty());
    assert!(journal_findings(&store, &needles).is_empty());
    assert_eq!(output.as_bytes(), MARKER.as_bytes());
}

#[test]
fn nested_json_pointers_cover_only_the_declared_value() {
    let (_, mut store, _) = bound_fresh();
    let request = bound_request(&store, Operation::Read, "fixture");
    let call =
        block_on(Vendor::default().run(&mut store, Some(&request.session), &request)).unwrap();
    let output = block_on(store.operation_response(
        call,
        br#"{"a/b":{"~key":[{"password":123},null]},"other":true}"#,
        &["/a~1b/~0key/0/password", "/a~1b/~0key/1", "/absent"],
    ))
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(output.as_bytes()).unwrap(),
        json!({"a/b":{"~key":[{"password":MARKER},null]},"other":true})
    );
}

#[test]
fn scan_runs_after_json_serialization_and_only_declared_password_fields_are_redacted() {
    let (_, mut store, _) = bound_fresh();
    let request = bound_request(&store, Operation::Read, "fixture");
    let call =
        block_on(Vendor::default().run(&mut store, Some(&request.session), &request)).unwrap();
    let phrase = store.seed().unwrap().phrase();
    let escaped = phrase.replace(' ', "\\u0020");
    let body = format!(
        "{{\"root_password\":\"{ROOT_PASSWORD}\",\"copy\":\"{ROOT_PASSWORD}\",\"echo\":\"{escaped}\"}}"
    );
    let output =
        block_on(store.operation_response(call, body.as_bytes(), &["/root_password"])).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(output.as_bytes()).unwrap(),
        json!({"root_password":MARKER,"copy":ROOT_PASSWORD,"echo":MARKER})
    );
    let call =
        block_on(Vendor::default().run(&mut store, Some(&request.session), &request)).unwrap();
    let output = block_on(fixture::injected_response(
        &mut store,
        call,
        ROOT_PASSWORD.as_bytes(),
    ))
    .unwrap();
    assert_eq!(
        output.as_bytes(),
        ROOT_PASSWORD.as_bytes(),
        "no root-password heuristic in injected bytes"
    );
}

#[test]
fn encoded_partial_and_transformed_values_are_outside_the_exact_scan() {
    let (_, mut store, _) = bound_fresh();
    let phrase = store.seed().unwrap().phrase();
    let values = [
        hex::encode(phrase.as_bytes()).into_bytes(),
        URL_SAFE_NO_PAD.encode(phrase.as_bytes()).into_bytes(),
        phrase.as_bytes()[1..].to_vec(),
        phrase.to_uppercase().into_bytes(),
    ];
    for value in values {
        let request = bound_request(&store, Operation::Read, "fixture");
        let call =
            block_on(Vendor::default().run(&mut store, Some(&request.session), &request)).unwrap();
        let output = block_on(fixture::injected_response(&mut store, call, &value)).unwrap();
        assert_eq!(output.as_bytes(), value);
    }
}

#[test]
fn response_append_failure_releases_no_output_and_latches_the_store() {
    for at in 1..=3 {
        let (storage, mut store, _) = bound_fresh();
        let request = bound_request(&store, Operation::Reset, "fixture");
        let call =
            block_on(Vendor::default().run(&mut store, Some(&request.session), &request)).unwrap();
        let before = store.next;
        storage.fault(Fault::Fail(at));
        let error =
            block_on(store.operation_response(call, ROOT_PASSWORD.as_bytes(), &[])).unwrap_err();
        assert!(error.contains("made to fail"));
        assert_eq!(store.next, before);
        assert_eq!(
            store.dispatch().typed_calls[&call].state,
            CallState::Unresolved
        );
        assert!(store.response_calls.is_empty());
        assert!(
            block_on(store.operation_response(call, b"safe", &[]))
                .unwrap_err()
                .contains("earlier append failed")
        );
    }
}

/// Craft authenticated tail records for replay refusals, without using the response writer.
fn append_value(store: &Store<MemoryStorage>, value: Value) {
    let number = store.next;
    let previous = hex::encode(store.previous.0);
    let nonce = [42u8; 12];
    let ciphertext = cipher(&store.key.0)
        .encrypt(
            &nonce.into(),
            Payload {
                msg: &serde_json::to_vec(&value).unwrap(),
                aad: record_aad(&store.id, EVENT, number, &previous).as_bytes(),
            },
        )
        .unwrap();
    let record = RecordJson {
        id: store.id.clone(),
        kind: EVENT.into(),
        number,
        previous,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    store
        .storage()
        .memory()
        .files
        .insert(number.to_string(), serde_json::to_vec(&record).unwrap());
}

#[test]
fn response_replay_preserves_call_state_and_refuses_invalid_records_without_plaintext() {
    let (storage, mut store, extra) = bound_fresh();
    let request = bound_request(&store, Operation::Reset, "fixture");
    let call =
        block_on(Vendor::default().run(&mut store, Some(&request.session), &request)).unwrap();
    let old = reopen(&storage, extra);
    assert_eq!(
        old.dispatch().typed_calls,
        store.dispatch().typed_calls,
        "older journal without responses"
    );
    for bad in [
        json!({"operation_response":{"call":999999,"body":""}}),
        json!({"operation_response":{"call":call,"body":"FF"}}),
        json!({"operation_response":{"call":call,"body":"f"}}),
        json!({"operation_response":{"call":call,"body":ROOT_PASSWORD}}),
        json!({"operation_response":{"call":call,"body":"","extra":ROOT_PASSWORD}}),
        json!({"operation_response":[call, ""]}),
    ] {
        let storage = MemoryStorage::with_files(storage.files());
        let store = reopen(&storage, extra);
        let before = store.next;
        append_value(&store, bad);
        let error = block_on(unlock(
            store.storage().clone(),
            &crate::dispatch::typed_tests::FixedKdf,
            LocalPassphrase::new(b"fixture passphrase only".to_vec()),
        ))
        .err()
        .unwrap();
        assert!(error.contains(&format!("record {before}:")), "{error}");
        assert!(!error.contains(ROOT_PASSWORD));
    }
    let output = block_on(store.operation_response(call, b"safe response", &[])).unwrap();
    assert_eq!(output.as_bytes(), b"safe response");
    let reopened = reopen(&storage, extra);
    assert_eq!(
        reopened.dispatch().typed_calls,
        store.dispatch().typed_calls
    );
    assert!(reopened.response_calls.contains(&call));
    let files = storage.files();
    assert!(
        block_on(store.operation_response(call, b"again", &[]))
            .unwrap_err()
            .contains("already has")
    );
    assert_eq!(storage.files(), files);
    append_value(
        &store,
        json!({"operation_response":{"call":call,"body":""}}),
    );
    let error = block_on(unlock(
        storage,
        &crate::dispatch::typed_tests::FixedKdf,
        LocalPassphrase::new(b"fixture passphrase only".to_vec()),
    ))
    .err()
    .unwrap();
    assert!(error.contains(&format!("record {}:", store.next)) && error.contains("already has"));

    let (storage, mut store, _) = bound_fresh();
    let command = Entry {
        machine: "fixture".into(),
        command: b"true".to_vec(),
        provenance: None,
    };
    let call = block_on(store.append(
        &command,
        &crate::dispatch::Approval::HarnessPin {
            machine: "fixture".into(),
            fingerprint: "SHA256:fixture".into(),
        },
    ))
    .unwrap();
    let before = store.next;
    append_value(
        &store,
        json!({"operation_response":{"call":call,"body":""}}),
    );
    let error = block_on(unlock(
        storage,
        &crate::dispatch::typed_tests::FixedKdf,
        LocalPassphrase::new(b"fixture passphrase only".to_vec()),
    ))
    .err()
    .unwrap();
    assert!(
        error.contains(&format!("record {before}:")) && error.contains("no earlier typed call")
    );
}
