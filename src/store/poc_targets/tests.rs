use super::*;
use crate::harness::PinSource;
use crate::jobs::Elevation;
use crate::poc::targets::StoredPins;

struct Fixed;
impl Kdf for Fixed {
    async fn derive(&self, _: LocalPassphrase, _: &Salt) -> Result<WrappingKey, String> {
        Ok(WrappingKey([9; 32]))
    }
}
fn pass() -> LocalPassphrase {
    LocalPassphrase::new(b"local target test passphrase".to_vec())
}
fn fresh() -> Store<MemoryStorage> {
    block_on(create(MemoryStorage::default(), &Fixed, pass())).unwrap()
}
fn ready() -> Store<MemoryStorage> {
    let mut store = fresh();
    block_on(store.seed_backup(allocation::Completion::Skipped)).unwrap();
    store
}
fn reopen(store: &Store<MemoryStorage>) -> Result<Store<MemoryStorage>, String> {
    block_on(unlock(
        MemoryStorage::with_files(store.storage.files()),
        &Fixed,
        pass(),
    ))
}
fn enrollment() -> Enrollment {
    Enrollment {
        target: TargetRecord {
            machine: "machine-a".into(),
            relay: "wss://relay.invalid/".into(),
            profile: "v1".into(),
            host: "192.0.2.1".into(),
            port: 22,
            user: "arch".into(),
            elevation: Elevation::None,
            pin: format!(
                "SHA256:{}",
                base64::engine::general_purpose::STANDARD_NO_PAD.encode([3; 32])
            ),
        },
        approve_existing: true,
        class_answer: ClassAnswer::No,
        approve_maintained_access: true,
    }
}
fn enroll(store: &mut Store<MemoryStorage>) {
    block_on(store.poc_enroll(enrollment())).unwrap();
}

#[test]
fn poc_targets_atomic_encrypted_enrollment_replay_and_public_identity() {
    let mut store = ready();
    enroll(&mut store);
    let files = store.storage.files();
    for bytes in files.values() {
        let text = String::from_utf8_lossy(bytes);
        for protected in ["machine-a", "192.0.2.1", "relay.invalid"] {
            assert!(!text.contains(protected));
        }
    }
    assert_eq!(store.allocation().next_unused().machines, 1);
    assert_eq!(store.allocation().next_unused().passes, 1);
    let keys = store.poc_public_keys("machine-a").unwrap();
    let line = keys["authorized_keys"].as_str().unwrap();
    let encoded = line.strip_prefix("ssh-ed25519 ").unwrap();
    let wire = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    assert_eq!(&wire[..19], b"\0\0\0\x0bssh-ed25519\0\0\0\x20");
    let identity = &store.dispatch.approved_entries["machine-a"]
        .approved
        .identity;
    let key = store
        .seed()
        .unwrap()
        .ssh_client_key(identity.derivation_version, identity.index)
        .unwrap();
    assert_eq!(&wire[19..], &key.public_key());
    assert_eq!(
        keys["relay_pubkey"],
        hex::encode(store.relay_key().unwrap().public_key())
    );
    assert_eq!(keys["relay_pubkey"].as_str().unwrap().len(), 64);
    let mut reopened = reopen(&store).unwrap();
    assert_eq!(reopened.poc_public_keys("machine-a").unwrap(), keys);
    assert_eq!(
        reopened.poc_target("machine-a"),
        store.poc_target("machine-a")
    );
    let pins = StoredPins::from_record(reopened.poc_target("machine-a").unwrap()).unwrap();
    assert_eq!(pins.pin("machine-a").unwrap().0, enrollment().target.pin);
    assert!(pins.pin("missing").is_none());
    assert!(reopened.poc_target("missing").is_none());
    assert_eq!(reopened.storage.files(), files);
    let first = block_on(reopened.poc_bind("machine-a")).unwrap();
    let bound_records = reopened.records().end;
    assert_eq!(block_on(reopened.poc_bind("machine-a")).unwrap(), first);
    assert_eq!(reopened.records().end, bound_records);
    assert!(
        reopened
            .dispatch
            .check_installation("machine-a")
            .unwrap_err()
            .contains("declaration missing")
    );
}

#[test]
fn poc_targets_idempotent_immutable_and_replayed_rebinding() {
    let mut store = ready();
    enroll(&mut store);
    let before = store.storage.files();
    enroll(&mut store);
    assert_eq!(store.storage.files(), before);
    for field in [
        "host",
        "relay",
        "profile",
        "port",
        "user",
        "pin",
        "elevation",
        "class",
    ] {
        let mut changed = enrollment();
        match field {
            "host" => changed.target.host = "192.0.2.2".into(),
            "relay" => changed.target.relay = "wss://other.invalid/".into(),
            "profile" => changed.target.profile = "v2".into(),
            "port" => changed.target.port = 2222,
            "user" => changed.target.user = "root".into(),
            "pin" => {
                changed.target.pin = format!(
                    "SHA256:{}",
                    base64::engine::general_purpose::STANDARD_NO_PAD.encode([4; 32])
                )
            }
            "elevation" => changed.target.elevation = Elevation::SudoNoninteractive,
            _ => changed.class_answer = ClassAnswer::Yes,
        }
        assert!(block_on(store.poc_enroll(changed)).is_err(), "{field}");
        assert_eq!(store.storage.files(), before);
    }
    let first = block_on(store.poc_bind("machine-a")).unwrap();
    let mut successor = reopen(&store).unwrap();
    enroll(&mut successor);
    let next = block_on(successor.poc_bind("machine-a")).unwrap();
    assert_eq!(first, next);
    assert_eq!(successor.allocation().next_unused().machines, 1);
    assert_eq!(successor.allocation().next_unused().passes, 1);
}

#[test]
fn poc_targets_prerequisites_collision_and_pass_reuse() {
    let mut unbacked = fresh();
    assert!(block_on(unbacked.poc_enroll(enrollment())).is_err());
    let mut store = ready();
    for existing in [false, true] {
        let mut request = enrollment();
        if existing {
            request.approve_existing = false;
        } else {
            request.approve_maintained_access = false;
        }
        assert!(block_on(store.poc_enroll(request)).is_err());
    }
    let pass = block_on(store.allocate(Family::Passes)).unwrap();
    enroll(&mut store);
    assert_eq!(store.poc_targets["machine-a"].relay_identity, pass);
    assert_eq!(store.allocation().next_unused().passes, 1);
    let mut fixture = ready();
    block_on(fixture.approve_setup(crate::dispatch::fixture_setup())).unwrap();
    let before = fixture.storage.files();
    assert!(
        block_on(fixture.poc_enroll(enrollment()))
            .unwrap_err()
            .contains("another setup approval")
    );
    assert_eq!(fixture.storage.files(), before);
    let mut history = ready();
    let intent = Intent {
        call: history.next,
        machine: "machine-a".into(),
        command: hex::encode(b"true"),
        approval: Some(Approval::LegacyCommand),
        job: None,
        provenance: None,
    };
    let n = block_on(history.commit(&Event::Intent(intent.clone()))).unwrap();
    history.apply_intent(n, intent).unwrap();
    assert!(
        block_on(history.poc_enroll(enrollment()))
            .unwrap_err()
            .contains("unrelated command history")
    );
}

#[test]
fn poc_targets_append_failure_and_interrupted_enrollment_recover_without_reallocation() {
    for fault in [
        Fault::Fail(1),
        Fault::Fail(2),
        Fault::Fail(3),
        Fault::LandThenFail(3),
    ] {
        let mut store = ready();
        store.storage.fault(fault);
        assert!(block_on(store.poc_enroll(enrollment())).is_err());
        assert!(store.poc_target("machine-a").is_none());
        assert!(
            block_on(store.poc_enroll(enrollment())).is_err(),
            "failed append latches"
        );
        let mut successor = reopen(&store).unwrap();
        enroll(&mut successor);
        assert_eq!(successor.allocation().next_unused().machines, 1);
        assert_eq!(successor.allocation().next_unused().passes, 1);
        block_on(successor.poc_bind("machine-a")).unwrap();
    }
}

#[test]
fn poc_targets_old_journal_replay_and_conflicting_authenticated_record_fail_closed() {
    let old = ready();
    let bytes = old.storage.files();
    let replayed = reopen(&old).unwrap();
    assert_eq!(replayed.storage.files(), bytes);
    assert!(replayed.poc_targets.is_empty());
    let mut store = ready();
    enroll(&mut store);
    let mut conflict = store.poc_targets["machine-a"].clone();
    conflict.target.elevation = Elevation::SudoNoninteractive;
    let n = store.records().end;
    block_on(store.commit(&Event::PocTarget(conflict))).unwrap();
    let reason = reopen(&store).err().unwrap();
    assert!(reason.contains(&format!("record {n}")));
    assert!(reason.contains("immutable"));
}

#[test]
fn poc_targets_operator_messages_and_suspension_are_admitted_explicitly() {
    let mut local = Local::new(MemoryStorage::default(), Fixed);
    assert_eq!(block_on(local.poc_enroll("{}"))["error"], "locked");
    block_on(local.open());
    let created = block_on(local.create(pass()));
    assert_eq!(created["state"], "unlocked");
    assert_eq!(block_on(local.poc_enroll("{}"))["error"], "seed_backup");
    local.seed_backup_answer();
    block_on(local.seed_backup_complete(None));
    let value = json!({"target":enrollment().target,"approve_existing":true,"class_answer":"no","approve_maintained_access":true});
    let mut extra = value.clone();
    extra["unexpected"] = json!(true);
    assert_eq!(
        block_on(local.poc_enroll(&extra.to_string()))["error"],
        "invalid existing-machine enrollment"
    );
    assert!(
        block_on(local.poc_enroll(&value.to_string()))
            .get("error")
            .is_none()
    );
    assert_eq!(
        local.poc_public_keys("unknown")["refused"],
        "machine has no stored target or pin"
    );
    let store = local.store().unwrap();
    store.authority.suspend();
    assert!(block_on(store.poc_enroll(enrollment())).is_err());
    assert!(block_on(store.poc_bind("machine-a")).is_err());
    assert!(store.poc_public_keys("machine-a").is_err());
    store.authority.revalidated().unwrap();
    assert!(store.poc_public_keys("machine-a").is_ok());
}

#[test]
fn poc_targets_positional_enrollment_and_target_messages_create_no_authority() {
    let storage = MemoryStorage::default();
    let mut local = Local::new(storage.clone(), Fixed);
    block_on(local.open());
    block_on(local.create(pass()));
    local.seed_backup_answer();
    block_on(local.seed_backup_complete(None));
    let target = enrollment().target;
    let positional_target = json!([
        target.machine,
        target.relay,
        target.profile,
        target.host,
        target.port,
        target.user,
        target.elevation,
        target.pin
    ]);
    let positional_enrollment = json!([enrollment().target, true, "no", true]);
    let nested_positional = json!({
        "target": positional_target,
        "approve_existing": true,
        "class_answer": "no",
        "approve_maintained_access": true
    });
    let both_positional = json!([positional_target, true, "no", true]);
    let before = storage.files();
    let allocation = local.store().unwrap().allocation().clone();
    for malformed in [positional_enrollment, nested_positional, both_positional] {
        assert_eq!(
            block_on(local.poc_enroll(&malformed.to_string()))["error"],
            "invalid existing-machine enrollment"
        );
        assert_eq!(storage.files(), before);
        let store = local.store().unwrap();
        assert_eq!(store.allocation(), &allocation);
        assert!(store.poc_target("machine-a").is_none());
        assert!(store.dispatch.approved_entries.is_empty());
        assert!(store.relay_key().is_none());
    }
}

fn assert_poc_echoes_absent(value: &Value, keys: &[&[u8]]) {
    let serialized = value.to_string();
    for key in keys {
        let key_text = std::str::from_utf8(key).unwrap();
        let embedded =
            base64::engine::general_purpose::STANDARD.encode([b"x".as_slice(), key].concat());
        assert!(
            !serialized.contains(key_text),
            "raw credential escaped protection"
        );
        assert!(
            !serialized.contains(&hex::encode(key)),
            "hex credential escaped protection"
        );
        assert!(
            !serialized.contains(&embedded),
            "embedded container escaped protection"
        );
    }
    match value {
        Value::String(text) => {
            if let Ok(decoded) = hex::decode(text) {
                let decoded = String::from_utf8_lossy(&decoded);
                for key in keys {
                    let key_text = std::str::from_utf8(key).unwrap();
                    let embedded = base64::engine::general_purpose::STANDARD
                        .encode([b"x".as_slice(), key].concat());
                    assert!(
                        !decoded.contains(key_text),
                        "journal evidence retained a raw credential"
                    );
                    assert!(
                        !decoded.contains(&embedded),
                        "journal evidence retained an encoded container"
                    );
                }
                if let Ok(nested) = serde_json::from_str::<Value>(&decoded) {
                    assert_poc_echoes_absent(&nested, keys);
                }
            }
            if let Ok(nested) = serde_json::from_str::<Value>(text) {
                assert_poc_echoes_absent(&nested, keys);
            }
        }
        Value::Array(values) => {
            for value in values {
                assert_poc_echoes_absent(value, keys);
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                assert_poc_echoes_absent(&Value::String(key.clone()), keys);
                assert_poc_echoes_absent(value, keys);
            }
        }
        _ => {}
    }
}

fn assert_poc_decrypted_journal_private(store: &Store<MemoryStorage>, keys: &[&[u8]]) {
    assert_poc_decrypted_journal_private_counts(store, keys, 1);
}

fn assert_poc_decrypted_journal_private_counts(
    store: &Store<MemoryStorage>,
    keys: &[&[u8]],
    expected_observations: usize,
) {
    let files = store.storage.files();
    let mut reader = Store::new(
        store.storage.clone(),
        DataKey(store.key.0),
        store.id.clone(),
    );
    let mut observations = 0;
    let mut terminals = 0;
    for number in store.records() {
        let bytes = &files[&number.to_string()];
        let event = reader.open(number, bytes).unwrap();
        if matches!(&event, Event::JobObservation(_)) {
            observations += 1;
        }
        if matches!(&event, Event::JobTerminal(_)) {
            terminals += 1;
        }
        assert_poc_echoes_absent(&serde_json::to_value(&event).unwrap(), keys);
        reader.previous = Address(Sha256::digest(bytes).into());
    }
    assert_eq!(observations, expected_observations);
    assert_eq!(terminals, 1);
}

#[test]
fn poc_machine_launch_and_collection_evidence_protect_key_echoes_after_rotation_and_end() {
    const OLD: &[u8] = b"old-secret-key-1234";
    const NEW: &[u8] = b"new-secret-key-5678";
    let mut store = ready();
    enroll(&mut store);
    store.fixture_requirements("machine-a");
    let entry = Entry {
        machine: "machine-a".into(),
        command: b"printf service-state".to_vec(),
        provenance: None,
    };
    let call = block_on(store.append(
        &entry,
        &Approval::HarnessPin {
            machine: entry.machine.clone(),
            fingerprint: enrollment().target.pin,
        },
    ))
    .unwrap();
    store.remember_poc_credential(OLD);
    let job = store.dispatch.calls[&call].intent.job.clone().unwrap();
    let command = store.dispatch.calls[&call].intent.command.clone();
    let payload = |key: &[u8]| {
        let raw = std::str::from_utf8(key).unwrap();
        let encoded =
            base64::engine::general_purpose::STANDARD.encode([b"x".as_slice(), key].concat());
        // The nested string exercises decoded values before serialization can hide them.
        let escaped = format!("\\u{:04x}{}", u32::from(key[0]), &raw[1..]);
        format!("raw: {raw}; encoded: {encoded}; nested: {{\"copy\":\"{escaped}\"}}")
    };
    let mut evidence = crate::jobs::Evidence {
        call,
        job,
        record: crate::jobs::Record::Present {
            machine: hex::encode("machine-a"),
            command,
            boot: "boot-a".into(),
            current_boot: "boot-a".into(),
            pid: 42,
            alive: true,
            exit_status: None,
            stdout: hex::encode(OLD),
            stderr: hex::encode(r#"{"copy":"\u006fld-secret-key-1234"}"#),
        },
    };
    let before_running = store.storage.files();
    let running = store
        .protect_job_report(crate::jobs::uncommitted(
            &evidence,
            &entry.machine,
            &store.dispatch.calls[&call].intent.command,
        ))
        .unwrap();
    assert_eq!(running.state, crate::jobs::State::Running);
    assert!(running.stdout.contains(crate::redaction::MARKER));
    assert_poc_echoes_absent(&serde_json::to_value(&running).unwrap(), &[OLD]);
    assert_eq!(store.storage.files(), before_running);
    // An incomplete launch observation is journalable; a running read is only released.
    if let crate::jobs::Record::Present { pid, alive, .. } = &mut evidence.record {
        *pid = 0;
        *alive = false;
    }
    let launched = block_on(store.job_evidence(&evidence)).unwrap();
    assert_eq!(launched.state, crate::jobs::State::Incomplete);
    assert!(launched.stdout.contains(crate::redaction::MARKER));
    assert_poc_echoes_absent(&serde_json::to_value(&launched).unwrap(), &[OLD]);
    store.remember_poc_credential(NEW);
    store.end_inference_sessions();
    if let crate::jobs::Record::Present {
        stdout,
        stderr,
        exit_status,
        alive,
        ..
    } = &mut evidence.record
    {
        *stdout = hex::encode(format!("{}\n{}", payload(OLD), payload(NEW)));
        *stderr = hex::encode(payload(NEW));
        *exit_status = Some(0);
        *alive = false;
    }
    let collected = block_on(store.job_evidence(&evidence)).unwrap();
    assert_eq!(collected.state, crate::jobs::State::Finished);
    assert_poc_echoes_absent(&serde_json::to_value(&collected).unwrap(), &[OLD, NEW]);
    let nested = json!({"nested":[{"value":payload(OLD)}, {"value":payload(NEW)}]});
    assert_poc_echoes_absent(&store.protect_output(&nested).unwrap(), &[OLD, NEW]);
    for key in [OLD, NEW] {
        let raw = std::str::from_utf8(key).unwrap();
        let escaped = format!("\\u{:04x}{}", u32::from(key[0]), &raw[1..]);
        let encoded =
            base64::engine::general_purpose::STANDARD.encode([b"x".as_slice(), key].concat());
        for value in [
            json!(raw),
            json!(format!("{{\"copy\":\"{escaped}\"}}")),
            json!(format!("limit: {encoded}")),
        ] {
            assert_poc_echoes_absent(&store.protect_output(&value).unwrap(), &[OLD, NEW]);
        }
        let split = key.len() / 2;
        let scanned = store.scan_output(&[&key[..split], &key[split..]]).unwrap();
        assert!(!scanned.windows(key.len()).any(|window| window == key));
    }
    assert_poc_decrypted_journal_private(&store, &[OLD, NEW]);
    let reopened = reopen(&store).unwrap();
    assert!(
        reopened.poc_credential_filters.is_empty(),
        "fingerprints are never journaled"
    );
    assert_poc_decrypted_journal_private(&reopened, &[OLD, NEW]);
}

#[test]
fn poc_marker_collision_refuses_evidence_before_any_append() {
    let mut store = ready();
    store.remember_poc_credential(b"<redacted>");
    let before = store.storage.files();
    let evidence = crate::jobs::Evidence {
        call: 0,
        job: "a".repeat(48),
        record: crate::jobs::Record::Present {
            machine: hex::encode("machine-a"),
            command: hex::encode("true"),
            boot: "boot-a".into(),
            current_boot: "boot-a".into(),
            pid: 42,
            alive: false,
            exit_status: Some(0),
            stdout: hex::encode("<redacted>"),
            stderr: String::new(),
        },
    };
    let why = block_on(store.job_evidence(&evidence)).unwrap_err();
    assert_eq!(why, "protected output unavailable");
    assert_eq!(store.storage.files(), before);
    assert!(store.failed.is_none());
}

#[test]
fn poc_targets_access_snapshot_revision_is_preserved_and_conflicts_refuse() {
    let mut store = ready();
    let access = Access {
        model: crate::dispatch::AccessModel::Maintained,
        profile: "ad-hoc".into(),
        revision: Access::ad_hoc().revision.checked_add(7).unwrap(),
    };
    // An authenticated enrollment made under a different compiled profile revision.
    let record = Record {
        target: enrollment().target,
        machine_identity: store.allocation().issue(Family::Machines).unwrap(),
        relay_identity: store.allocation().issue(Family::Passes).unwrap(),
        class_answer: ClassAnswer::No,
        access: access.clone(),
    };
    block_on(store.commit(&Event::PocTarget(record.clone()))).unwrap();
    let mut recovered = reopen(&store).unwrap();
    assert_eq!(
        recovered.dispatch.approved_entries["machine-a"]
            .approved
            .access,
        Some(access.clone())
    );
    assert_eq!(recovered.poc_targets["machine-a"].access, access);
    let before = recovered.storage.files();
    enroll(&mut recovered);
    assert_eq!(recovered.storage.files(), before);
    let mut conflict = record;
    conflict.access.revision += 1;
    let number = recovered.records().end;
    block_on(recovered.commit(&Event::PocTarget(conflict))).unwrap();
    let reason = reopen(&recovered).err().unwrap();
    assert!(reason.contains(&format!("record {number}")));
    assert!(reason.contains("immutable"));
}

#[test]
fn poc_targets_access_snapshot_rejects_unapproved_model_or_profile() {
    for invalid_model in [true, false] {
        let mut store = ready();
        let mut access = Access::ad_hoc();
        if invalid_model {
            access.model = crate::dispatch::AccessModel::Sealed;
        } else {
            access.profile = "other-profile".into();
        }
        let record = Record {
            target: enrollment().target,
            machine_identity: store.allocation().issue(Family::Machines).unwrap(),
            relay_identity: store.allocation().issue(Family::Passes).unwrap(),
            class_answer: ClassAnswer::No,
            access,
        };
        let before = store.storage.files();
        assert!(store.poc_projections(&record).is_err());
        assert_eq!(store.storage.files(), before);
        let number = store.records().end;
        block_on(store.commit(&Event::PocTarget(record))).unwrap();
        let reason = reopen(&store).err().unwrap();
        assert!(reason.contains(&format!("record {number}")));
        assert!(reason.contains("unsupported ad-hoc access"));
    }
}

#[test]
fn poc_rotated_marker_credentials_refuse_job_and_operation_evidence_without_append() {
    const OLD: &[u8] = b"<redacted>";
    const NEW: &[u8] = b"new-rotation-secret-1234";
    let mut store = ready();
    enroll(&mut store);
    store.fixture_requirements("machine-a");
    let entry = Entry {
        machine: "machine-a".into(),
        command: b"printf service-state".to_vec(),
        provenance: None,
    };
    let call = block_on(store.append(
        &entry,
        &Approval::HarnessPin {
            machine: entry.machine.clone(),
            fingerprint: enrollment().target.pin,
        },
    ))
    .unwrap();
    store.remember_poc_credential(OLD);
    store.remember_poc_credential(NEW);
    assert_eq!(
        store.poc_credential_filters.len(),
        1,
        "retained generations share a single boundary"
    );
    store.end_inference_sessions();
    let evidence = crate::jobs::Evidence {
        call,
        job: store.dispatch.calls[&call].intent.job.clone().unwrap(),
        record: crate::jobs::Record::Present {
            machine: hex::encode(&entry.machine),
            command: store.dispatch.calls[&call].intent.command.clone(),
            boot: "boot-a".into(),
            current_boot: "boot-a".into(),
            pid: 42,
            alive: false,
            exit_status: Some(0),
            stdout: hex::encode(NEW),
            stderr: String::new(),
        },
    };
    let before = store.storage.files();
    assert!(
        store
            .protect_output(&json!(std::str::from_utf8(NEW).unwrap()))
            .is_err()
    );
    assert!(block_on(store.job_evidence(&evidence)).is_err());
    assert_eq!(store.storage.files(), before);
    assert!(!matches!(
        store.dispatch.calls[&call].state,
        crate::dispatch::CallState::Finished { .. }
    ));

    let (_, mut operation_store, _) = crate::dispatch::typed_tests::bound_fresh();
    let request = crate::dispatch::typed_tests::bound_request(
        &operation_store,
        crate::dispatch::Operation::Read,
        "fixture",
    );
    let operation = block_on(crate::dispatch::fixture::Vendor::default().run(
        &mut operation_store,
        Some(&request.session),
        &request,
    ))
    .unwrap();
    operation_store.remember_poc_credential(OLD);
    operation_store.remember_poc_credential(NEW);
    operation_store.end_inference_sessions();
    let before = operation_store.storage.files();
    assert!(block_on(operation_store.operation_response(operation, NEW, &[])).is_err());
    assert_eq!(operation_store.storage.files(), before);
    // The ordinary holder boundary also uses the marker: it must not recreate a retired key.
    let held = Zeroizing::new(operation_store.key.0.to_vec());
    assert!(block_on(operation_store.operation_response(operation, &held, &[])).is_err());
    assert_eq!(operation_store.storage.files(), before);
    assert!(!operation_store.response_calls.contains(&operation));
}

#[test]
fn poc_isolated_encoded_machine_evidence_is_protected_before_each_journal_sink() {
    let standard = base64::engine::general_purpose::STANDARD
        .encode([b"\xfb".as_slice(), b"secret123".as_slice()].concat());
    let mixed_hex = format!("a{}", "7A7e".repeat(6));
    let cases: Vec<(&[u8], String, String)> = vec![
        (b"secret123", format!("trace-{standard}"), standard),
        (b"z~z~z~z~z~z~", mixed_hex.clone(), mixed_hex),
        (
            b"secret123",
            "x\" y \"\\u0073ecret123\"".into(),
            "\\u0073ecret123".into(),
        ),
        (
            b"secret123",
            "\\u0073ecret123".into(),
            "\\u0073ecret123".into(),
        ),
    ];
    for (key, payload, encoded) in cases {
        assert!(!payload.contains(std::str::from_utf8(key).unwrap()));
        let mut store = ready();
        enroll(&mut store);
        store.fixture_requirements("machine-a");
        let entry = Entry {
            machine: "machine-a".into(),
            command: b"printf service-state".to_vec(),
            provenance: None,
        };
        let call = block_on(store.append(
            &entry,
            &Approval::HarnessPin {
                machine: entry.machine.clone(),
                fingerprint: enrollment().target.pin,
            },
        ))
        .unwrap();
        store.remember_poc_credential(key);
        let mut evidence = crate::jobs::Evidence {
            call,
            job: store.dispatch.calls[&call].intent.job.clone().unwrap(),
            record: crate::jobs::Record::Present {
                machine: hex::encode(&entry.machine),
                command: store.dispatch.calls[&call].intent.command.clone(),
                boot: "boot-a".into(),
                current_boot: "boot-a".into(),
                pid: 0,
                alive: false,
                exit_status: None,
                stdout: hex::encode(payload.as_bytes()),
                stderr: String::new(),
            },
        };
        let launched = block_on(store.job_evidence(&evidence)).unwrap();
        assert_eq!(launched.state, crate::jobs::State::Incomplete);
        assert!(launched.stdout.contains(crate::redaction::MARKER));
        assert!(!launched.stdout.contains(&encoded));
        assert_poc_echoes_absent(&serde_json::to_value(&launched).unwrap(), &[key]);
        store.end_inference_sessions();
        if let crate::jobs::Record::Present {
            pid, exit_status, ..
        } = &mut evidence.record
        {
            *pid = 42;
            *exit_status = Some(0);
        }
        let collected = block_on(store.job_evidence(&evidence)).unwrap();
        assert_eq!(collected.state, crate::jobs::State::Finished);
        assert!(collected.stdout.contains(crate::redaction::MARKER));
        assert!(!collected.stdout.contains(&encoded));
        assert_poc_echoes_absent(&serde_json::to_value(&collected).unwrap(), &[key]);
        assert_poc_decrypted_journal_private(&store, &[key]);
        for report in &store.dispatch.jobs {
            assert!(!report.stdout.contains(&encoded));
            if let crate::jobs::Record::Present { stdout, .. } = &report.evidence.record {
                let decoded = String::from_utf8(hex::decode(stdout).unwrap()).unwrap();
                assert!(!decoded.contains(&encoded));
                assert!(decoded.contains(crate::redaction::MARKER));
            }
        }
        let recovered = reopen(&store).unwrap();
        assert_poc_decrypted_journal_private(&recovered, &[key]);
        for report in &recovered.dispatch.jobs {
            assert!(!report.stdout.contains(&encoded));
        }
    }
}

#[test]
fn poc_target_credential_admission_precedes_every_durable_change() {
    for field in [
        "machine", "host", "user", "relay", "profile", "encoded", "pin",
    ] {
        let mut store = ready();
        let key = if field == "pin" {
            b"fixture-pin-key-4827".as_slice()
        } else {
            b"fixture-key-4827".as_slice()
        };
        store.remember_poc_credential(key);
        store.remember_poc_credential(b"current-rotated-key-9751");
        let mut request = enrollment();
        let text = std::str::from_utf8(key).unwrap();
        match field {
            "machine" => request.target.machine = text.into(),
            "host" => request.target.host = format!("{text}.invalid"),
            "user" => request.target.user = text.into(),
            "profile" => request.target.profile = text.into(),
            "relay" => request.target.relay = format!("wss://relay.invalid/{text}/"),
            "encoded" => {
                request.target.machine =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key)
            }
            _ => {
                let mut pin = [0u8; 32];
                pin[..key.len()].copy_from_slice(key);
                request.target.pin = format!(
                    "SHA256:{}",
                    base64::engine::general_purpose::STANDARD_NO_PAD.encode(pin)
                );
            }
        }
        request.target.validate().unwrap();
        let files = store.storage.files();
        let allocation = store.allocation().clone();
        let end = store.records().end;
        let error = block_on(store.poc_enroll(request)).unwrap_err();
        assert!(error.contains("protected or unscannable"), "{field}");
        assert!(!error.contains(text));
        assert_eq!(store.storage.files(), files);
        assert_eq!(store.records().end, end);
        assert_eq!(store.allocation(), &allocation);
        assert!(store.dispatch.approved_entries.is_empty());
        assert!(store.poc_targets.is_empty());
        // Inspect authenticated plaintext and fresh-worker replay without any remembered filter.
        let replayed = reopen(&store).unwrap();
        assert!(replayed.poc_targets.is_empty());
        let mut reader = Store::new(
            store.storage.clone(),
            DataKey(store.key.0),
            store.id.clone(),
        );
        for number in 0..end {
            let bytes = &files[&number.to_string()];
            let event = reader.open(number, bytes).unwrap();
            assert!(!serde_json::to_string(&event).unwrap().contains(text));
            assert!(!matches!(event, Event::PocTarget(_)));
            reader.previous = Address(Sha256::digest(bytes).into());
        }
    }
    let mut control = ready();
    control.remember_poc_credential(b"fixture-key-4827");
    enroll(&mut control);
    assert!(reopen(&control).unwrap().poc_target("machine-a").is_some());
    let mut missing = ready();
    let id = block_on(missing.synthetic_scan_fixture(
        "credential".into(),
        Zeroizing::new(b"required-secret-1234".to_vec()),
    ))
    .unwrap();
    missing.clear_scan_working_copies();
    let files = missing.storage.files();
    assert!(block_on(missing.poc_enroll(enrollment())).is_err());
    assert_eq!(files, missing.storage.files());
    assert!(!id.is_empty());
}

#[test]
fn poc_operator_declaration_approval_admits_production_commands_and_replays() {
    use crate::goals::Tool;
    let mut store = ready();
    enroll(&mut store);
    let session = block_on(store.poc_bind("machine-a")).unwrap();
    let proposal = json!({"kind":"declaration","machine":"machine-a","declaration":crate::declaration::ad_hoc_minimum()});
    assert!(block_on(store.check("machine-a")).is_err());
    let files = store.storage.files();
    assert!(
        store.poc_propose_requirements(&session, &proposal).is_err(),
        "missing goal"
    );
    block_on(store.enter_goal(&session, "Install a small service".into(), None)).unwrap();
    assert!(
        store.poc_propose_requirements(&session, &proposal).is_err(),
        "missing acting acceptance"
    );
    block_on(store.accept_mode(&session, crate::modes::Mode::NoBrief)).unwrap();
    let before = store.storage.files();
    let mut malformed = proposal.clone();
    malformed["declaration"]["version"] = 1.into();
    assert!(
        store
            .poc_propose_requirements(&session, &malformed)
            .is_err()
    );
    let mut wrong = proposal.clone();
    wrong["machine"] = "wrong-machine".into();
    assert!(store.poc_propose_requirements(&session, &wrong).is_err());
    assert!(
        store
            .poc_propose_requirements("wrong-session", &proposal)
            .is_err()
    );
    assert_eq!(before, store.storage.files());
    store.poc_propose_requirements(&session, &proposal).unwrap();
    let candidate = store.pending_requirements[&session].candidate;
    assert!(block_on(store.approve_requirements("wrong-session", "machine-a", candidate)).is_err());
    assert!(block_on(store.approve_requirements(&session, "wrong-machine", candidate)).is_err());
    assert!(block_on(store.approve_requirements(&session, "machine-a", candidate + 1)).is_err());
    store
        .reject_requirements(&session, "machine-a", candidate)
        .unwrap();
    store.poc_propose_requirements(&session, &proposal).unwrap();
    let replacement = store.pending_requirements[&session].candidate;
    assert_ne!(replacement, candidate);
    assert!(block_on(store.approve_requirements(&session, "machine-a", candidate)).is_err());
    assert!(
        store
            .check_tool(
                &session,
                &Tool::Exec {
                    machine: "machine-a".into(),
                    command: "true".into()
                }
            )
            .is_err()
    );
    let approval_number = store.records().end;
    block_on(store.approve_requirements(&session, "machine-a", replacement)).unwrap();
    block_on(store.check("machine-a")).unwrap();
    let mut reader = Store::new(
        store.storage.clone(),
        DataKey(store.key.0),
        store.id.clone(),
    );
    reader.previous =
        Address(Sha256::digest(&store.storage.files()[&(approval_number - 1).to_string()]).into());
    let event = reader
        .open(
            approval_number,
            &store.storage.files()[&approval_number.to_string()],
        )
        .unwrap();
    let value = serde_json::to_value(event).unwrap();
    assert_eq!(value["setup"]["requirements"]["proposal"], proposal);
    assert_eq!(value["setup"]["requirements"]["session"], session);
    let replayed = reopen(&store).unwrap();
    block_on(replayed.check("machine-a")).unwrap();
    assert_ne!(files, store.storage.files());
}

#[test]
fn poc_isolated_encoding_evidence_journal_and_replay_regressions() {
    let key = b"fixture-key-4827";
    for encoded in crate::poc::inference::tests::poc_encoded_forms(key) {
        let mut store = ready();
        enroll(&mut store);
        store.fixture_requirements("machine-a");
        let entry = Entry {
            machine: "machine-a".into(),
            command: b"true".to_vec(),
            provenance: None,
        };
        let call = block_on(store.append(
            &entry,
            &Approval::HarnessPin {
                machine: entry.machine.clone(),
                fingerprint: enrollment().target.pin,
            },
        ))
        .unwrap();
        store.remember_poc_credential(key);
        store.remember_poc_credential(b"rotated-current-key-9751");
        let intent = &store.dispatch.calls[&call].intent;
        let evidence = crate::jobs::Evidence {
            call,
            job: intent.job.clone().unwrap(),
            record: crate::jobs::Record::Present {
                machine: hex::encode("machine-a"),
                command: intent.command.clone(),
                boot: "boot".into(),
                current_boot: "boot".into(),
                pid: 42,
                alive: false,
                exit_status: Some(0),
                stdout: hex::encode(&encoded),
                stderr: String::new(),
            },
        };
        let report = block_on(store.job_evidence(&evidence)).unwrap();
        assert!(!report.stdout.contains(&encoded), "{encoded}");
        let mut reader = Store::new(
            store.storage.clone(),
            DataKey(store.key.0),
            store.id.clone(),
        );
        let files = store.storage.files();
        for number in 0..store.records().end {
            let bytes = &files[&number.to_string()];
            let event = reader.open(number, bytes).unwrap();
            let text = serde_json::to_string(&event).unwrap();
            assert!(!text.contains(&encoded));
            assert!(!text.contains(&hex::encode(&encoded)));
            reader.previous = Address(Sha256::digest(bytes).into());
        }
        let replayed = reopen(&store).unwrap();
        assert!(replayed.poc_credential_filters.is_empty());
        assert_eq!(replayed.storage.files(), files);
    }
}

#[test]
fn poc_admission_budget_exhaustion_and_ended_approval_fail_closed() {
    let mut store = ready();
    let files = store.storage.files();
    // Exhaust a parent synchronous scope to prove admission cannot reset its capacity.
    let refused = crate::poc::inference::work::scope(|| {
        crate::poc::inference::work::charge(512 * 1024 * 1024)?;
        block_on(store.poc_enroll(enrollment()))
    });
    assert!(refused.is_err());
    assert_eq!(store.storage.files(), files);
    assert_eq!(store.allocation().next_unused().machines, 0);
    assert_eq!(store.allocation().next_unused().passes, 0);
    enroll(&mut store);
    let session = block_on(store.poc_bind("machine-a")).unwrap();
    block_on(store.enter_goal(&session, "Inspect the service".into(), None)).unwrap();
    block_on(store.accept_mode(&session, crate::modes::Mode::NoBrief)).unwrap();
    store.poc_propose_requirements(&session,&json!({"kind":"declaration","machine":"machine-a","declaration":crate::declaration::ad_hoc_minimum()})).unwrap();
    let candidate = store.pending_requirements[&session].candidate;
    store.end_inference_sessions();
    let files = store.storage.files();
    assert!(block_on(store.approve_requirements(&session, "machine-a", candidate)).is_err());
    assert_eq!(store.storage.files(), files);
    assert!(block_on(store.check("machine-a")).is_err());
}

fn poc_pending_job(store: &mut Store<MemoryStorage>, output: &[u8]) -> crate::jobs::Evidence {
    poc_pending_command(store, output, b"true")
}

fn poc_pending_command(
    store: &mut Store<MemoryStorage>,
    output: &[u8],
    command: &[u8],
) -> crate::jobs::Evidence {
    enroll(store);
    let session = block_on(store.poc_bind("machine-a")).unwrap();
    block_on(store.enter_goal(&session, "Inspect a small service".into(), None)).unwrap();
    block_on(store.accept_mode(&session, crate::modes::Mode::NoBrief)).unwrap();
    store.poc_propose_requirements(&session, &json!({"kind":"declaration","machine":"machine-a","declaration":crate::declaration::ad_hoc_minimum()})).unwrap();
    let candidate = store.pending_requirements[&session].candidate;
    block_on(store.approve_requirements(&session, "machine-a", candidate)).unwrap();
    let entry = Entry {
        machine: "machine-a".into(),
        command: command.to_vec(),
        provenance: None,
    };
    let call = block_on(store.append(
        &entry,
        &Approval::HarnessPin {
            machine: entry.machine.clone(),
            fingerprint: enrollment().target.pin,
        },
    ))
    .unwrap();
    let intent = &store.dispatch.calls[&call].intent;
    crate::jobs::Evidence {
        call,
        job: intent.job.clone().unwrap(),
        record: crate::jobs::Record::Present {
            machine: hex::encode("machine-a"),
            command: intent.command.clone(),
            boot: "boot-a".into(),
            current_boot: "boot-a".into(),
            pid: 42,
            alive: false,
            exit_status: Some(7),
            stdout: hex::encode(output),
            stderr: String::new(),
        },
    }
}

fn poc_package_output(size: usize) -> Vec<u8> {
    b"Package abc012345 xyz789 installed successfully.\n"
        .iter()
        .copied()
        .cycle()
        .take(size)
        .collect()
}

#[test]
fn poc_comparison_collision_replays_the_committed_projection() {
    let mut store = ready();
    let evidence = poc_pending_job(&mut store, b"ordinary package output");
    let command = store.dispatch.calls[&evidence.call].intent.command.clone();
    store.remember_poc_credential(b"true");
    let report = block_on(store.job_evidence(&evidence)).unwrap();
    let recovered = reopen(&store).unwrap();
    assert_eq!(store.dispatch.jobs, recovered.dispatch.jobs);
    assert_eq!(store.dispatch.calls, recovered.dispatch.calls);
    assert_eq!(store.dispatch.calls[&evidence.call].intent.command, command);
    assert_eq!(command, hex::encode("true"));
    assert!(matches!(
        report.comparison,
        crate::jobs::Comparison::Finding { .. }
    ));
    assert_eq!(block_on(store.collectable("machine-a")).unwrap().len(), 0);
    assert_eq!(
        block_on(recovered.collectable("machine-a")).unwrap().len(),
        0
    );
    let mut recovered = recovered;
    recovered.remember_poc_credential(b"true");
    let live = block_on(crate::harness::BoundJournal::release(
        &store,
        serde_json::to_value(&report).unwrap(),
    ))
    .unwrap();
    let replayed = block_on(crate::harness::BoundJournal::release(
        &recovered,
        serde_json::to_value(recovered.dispatch.jobs.last()).unwrap(),
    ))
    .unwrap();
    assert_eq!(live, replayed);
    assert_eq!(live["agreement"], "finding");
    assert_eq!(live["journal"], hex::encode(crate::redaction::MARKER));
    assert_eq!(
        live["record"]["command"],
        hex::encode(crate::redaction::MARKER)
    );
    let files = store.storage.files();
    assert!(block_on(store.job_evidence(&evidence)).is_err());
    assert_eq!(store.storage.files(), files);
    assert_eq!(store.dispatch.calls.len(), 1);
}

#[test]
fn poc_comparison_collision_failed_append_keeps_projection_and_hold() {
    let mut store = ready();
    let evidence = poc_pending_job(&mut store, b"ordinary package output");
    store.remember_poc_credential(b"true");
    let files = store.storage.files();
    let calls = store.dispatch.calls.clone();
    store.storage.fault(Fault::Fail(1));
    assert!(
        block_on(store.job_evidence(&evidence))
            .unwrap_err()
            .contains("fail")
    );
    assert_eq!(store.storage.files(), files);
    assert_eq!(store.dispatch.calls, calls);
    assert!(store.dispatch.jobs.is_empty());
    assert!(store.dispatch.terminals.is_empty());
    assert_eq!(block_on(store.collectable("machine-a")).unwrap().len(), 1);
    let recovered = reopen(&store).unwrap();
    assert_eq!(recovered.dispatch.calls, calls);
    assert!(block_on(recovered.check("machine-a")).is_err());
}

#[test]
fn poc_boundary_key_two_stream_settlement_release_and_replay() {
    let mut store = ready();
    let output = poc_package_output(262144);
    let stderr = poc_package_output(16384);
    let mut evidence = poc_pending_job(&mut store, &output);
    if let crate::jobs::Record::Present { stderr: field, .. } = &mut evidence.record {
        *field = hex::encode(&stderr);
    }
    let key = b"boundary-key-123";
    assert_eq!(key.len(), 16);
    store.remember_poc_credential(key);
    let report = block_on(store.job_evidence(&evidence)).unwrap();
    let released = block_on(crate::harness::BoundJournal::release(
        &store,
        serde_json::to_value(&report).unwrap(),
    ))
    .unwrap();
    assert_eq!(report.stdout.as_bytes(), output);
    assert_eq!(report.stderr.as_bytes(), stderr);
    assert_eq!(released["stdout"], String::from_utf8(output).unwrap());
    assert_eq!(released["stderr"], String::from_utf8(stderr).unwrap());
    let recovered = reopen(&store).unwrap();
    assert_eq!(recovered.dispatch.jobs.last(), Some(&report));
    assert_eq!(recovered.dispatch.calls.len(), 1);
    assert_eq!(recovered.dispatch.terminals.len(), 1);
    assert!(
        block_on(recovered.collectable("machine-a"))
            .unwrap()
            .is_empty()
    );
    assert_eq!(recovered.storage.files(), store.storage.files());
}

fn poc_served_job(store: &Store<MemoryStorage>, report: &crate::jobs::Report) -> Value {
    let intent = &store.dispatch.calls[&report.evidence.call].intent;
    let command = hex::decode(&intent.command).unwrap();
    let elevation = store.poc_target(&intent.machine).unwrap().elevation;
    let done = crate::harness::Done {
        seq: intent.call,
        sent: crate::jobs::launch_with_elevation(
            intent.job.as_deref().unwrap(),
            &intent.machine,
            &command,
            elevation,
        )
        .into_bytes(),
        recorded: Entry {
            machine: intent.machine.clone(),
            command,
            provenance: intent.provenance.clone(),
        },
        stdout: report.stdout.as_bytes().to_vec(),
        stderr: report.stderr.as_bytes().to_vec(),
        exit_status: report.exit_status.unwrap(),
        terminal: report.number.unwrap(),
        host_key: store.poc_target(&intent.machine).unwrap().pin.clone(),
        evidence: report.clone(),
    };
    crate::harness::response(done.report())
}

fn poc_assert_release_invariant(size: usize, long: bool) {
    let mut store = ready();
    let output = if long {
        String::from_utf8(poc_package_output(327680)).unwrap()
    } else {
        hex::encode(poc_package_output(size))
    };
    let command = if long {
        "#".repeat(8192)
    } else {
        "true".into()
    };
    let mut evidence = poc_pending_command(&mut store, output.as_bytes(), command.as_bytes());
    if long {
        store.remember_poc_credential(b"previous-normal-key-482700");
        if let crate::jobs::Record::Present { stderr, .. } = &mut evidence.record {
            *stderr = hex::encode(poc_package_output(24576));
        }
    }
    store.remember_poc_credential(b"normal-synthetic-key-482700");
    let files = store.storage.files();
    let calls = store.dispatch.calls.clone();
    match block_on(store.job_evidence(&evidence)) {
        Ok(report) => {
            assert_eq!(store.dispatch.terminals.len(), 1);
            let value = poc_served_job(&store, &report);
            let released = store
                .protect_command_results(&value)
                .expect("a committed terminal must survive the complete served release");
            assert_eq!(released["outcome"]["stdout"], output);
            assert_eq!(
                released["outcome"]["job_record"]["record"]["stdout"],
                hex::encode(&output)
            );
            assert_eq!(reopen(&store).unwrap().dispatch.jobs, store.dispatch.jobs);
            assert!(block_on(store.collectable("machine-a")).unwrap().is_empty());
            block_on(store.check("machine-a")).unwrap();
            let settled = store.storage.files();
            assert!(block_on(store.job_evidence(&evidence)).is_err());
            assert_eq!(store.storage.files(), settled);
        }
        Err(why) => {
            assert!(why.contains("bound"), "{why}");
            assert_eq!(store.storage.files(), files);
            assert_eq!(store.dispatch.calls, calls);
            assert!(store.dispatch.terminals.is_empty());
            assert!(store.dispatch.jobs.is_empty());
            assert_eq!(block_on(store.collectable("machine-a")).unwrap().len(), 1);
            assert!(block_on(store.check("machine-a")).is_err());
            let recovered = reopen(&store).unwrap();
            assert_eq!(recovered.dispatch.calls, store.dispatch.calls);
            assert_eq!(recovered.dispatch.jobs, store.dispatch.jobs);
            assert_eq!(store.dispatch.calls.len(), 1);
        }
    }
}

#[test]
fn poc_served_release_181890_never_withholds_after_terminal_commit() {
    poc_assert_release_invariant(181890, false);
}
#[test]
fn poc_served_release_183300_never_withholds_after_terminal_commit() {
    poc_assert_release_invariant(183300, false);
}
#[test]
fn poc_served_release_long_command_never_withholds_after_terminal_commit() {
    poc_assert_release_invariant(327680, true);
}
#[test]
fn poc_release_bound_never_withholds_after_terminal_commit() {
    poc_assert_release_invariant(185344, false);
}

#[test]
fn poc_normal_job_settlement_preserves_full_output_and_replay_without_relaunch() {
    for (size, stderr_size, key, rotated, textual_hex) in [
        (65536, 0, true, false, false),
        (262144, 0, true, false, false),
        (393216, 0, false, false, false),
        (262144, 16384, true, false, false),
        (262144, 0, true, true, false),
        (262144, 0, true, false, true),
        (262144, 16384, true, true, false),
        (327680, 24576, true, true, false),
    ] {
        eprintln!(
            "ordinary settlement: stdout={size}, stderr={stderr_size}, key={key}, rotated={rotated}, textual_hex={textual_hex}"
        );
        let started = std::time::Instant::now();
        let mut store = ready();
        let output = if textual_hex {
            hex::encode(poc_package_output(size / 2)).into_bytes()
        } else {
            poc_package_output(size)
        };
        let stderr = poc_package_output(stderr_size);
        let mut evidence = poc_pending_job(&mut store, &output);
        if let crate::jobs::Record::Present { stderr: field, .. } = &mut evidence.record {
            *field = hex::encode(&stderr);
        }
        if rotated {
            store.remember_poc_credential(b"previous-normal-key-482700");
        }
        if key {
            store.remember_poc_credential(b"normal-synthetic-key-482700");
        }
        assert_eq!(block_on(store.collectable("machine-a")).unwrap().len(), 1);
        assert!(block_on(store.check("machine-a")).is_err());
        // A nonterminal observation remains collectable; only the truthful finish clears it.
        let mut observation = evidence.clone();
        if let crate::jobs::Record::Present {
            exit_status, pid, ..
        } = &mut observation.record
        {
            *exit_status = None;
            *pid = 0;
        }
        for _ in 0..2 {
            assert_eq!(
                block_on(store.job_evidence(&observation)).unwrap().state,
                crate::jobs::State::Incomplete
            );
        }
        let uncommitted = block_on(crate::harness::BoundJournal::uncommitted(
            &store,
            &evidence,
            "machine-a",
            &store.dispatch.calls[&evidence.call].intent.command,
        ))
        .unwrap();
        assert_eq!(uncommitted.number, None);
        assert_eq!(uncommitted.stdout.as_bytes(), output);
        assert_eq!(uncommitted.stderr.as_bytes(), stderr);
        let report = block_on(store.job_evidence(&evidence)).unwrap();
        assert_eq!(report.state, crate::jobs::State::Finished);
        assert_eq!(report.exit_status, Some(7));
        assert_eq!(report.stdout.as_bytes(), output);
        assert_eq!(report.stderr.as_bytes(), stderr);
        assert_eq!(report.evidence, evidence);
        let released = block_on(crate::harness::BoundJournal::release(
            &store,
            serde_json::to_value(&report).unwrap(),
        ))
        .unwrap();
        assert_eq!(released["stdout"].as_str().unwrap().as_bytes(), output);
        assert_eq!(released["stderr"].as_str().unwrap().as_bytes(), stderr);
        assert_eq!(released["record"]["stdout"], hex::encode(&output));
        assert_eq!(released["record"]["stderr"], hex::encode(&stderr));
        assert_eq!(released["exit_status"], 7);
        assert_poc_decrypted_journal_private_counts(
            &store,
            &[
                b"normal-synthetic-key-482700",
                b"previous-normal-key-482700",
            ],
            2,
        );

        assert!(matches!(
            store.dispatch.calls[&evidence.call].state,
            crate::dispatch::CallState::Finished { exit_status: 7, .. }
        ));
        assert!(block_on(store.collectable("machine-a")).unwrap().is_empty());
        block_on(store.check("machine-a")).unwrap();
        let files = store.storage.files();
        assert!(block_on(store.job_evidence(&evidence)).is_err());
        assert_eq!(files, store.storage.files());
        let recovered = reopen(&store).unwrap();
        assert_eq!(recovered.dispatch.jobs.last().unwrap(), &report);
        assert_eq!(
            recovered.dispatch.calls.len(),
            1,
            "collection/replay never creates another intent"
        );
        assert_eq!(recovered.dispatch.terminals.len(), 1);
        assert!(
            block_on(recovered.collectable("machine-a"))
                .unwrap()
                .is_empty()
        );
        block_on(recovered.check("machine-a")).unwrap();
        let replay_release = block_on(crate::harness::BoundJournal::release(
            &recovered,
            serde_json::to_value(&report).unwrap(),
        ))
        .unwrap();
        assert_eq!(replay_release, released);
        assert_eq!(recovered.storage.files(), files);
        eprintln!(
            "ordinary settlement/release/replay passed in {:?}",
            started.elapsed()
        );
    }
}

#[test]
fn poc_large_job_echoes_are_protected_in_authenticated_events_and_released_reports() {
    let old = b"previous-normal-key-482700";
    let current = b"normal-synthetic-key-482700";
    for key in [old.as_slice(), current.as_slice()] {
        let forms = [
            String::from_utf8(key.to_vec()).unwrap(),
            base64::engine::general_purpose::STANDARD.encode(key),
            base64::engine::general_purpose::STANDARD.encode(
                serde_json::to_vec(
                    &json!({"nested":base64::engine::general_purpose::STANDARD.encode(key)}),
                )
                .unwrap(),
            ),
        ];
        for encoded in forms {
            let mut output = poc_package_output(65536);
            output.extend_from_slice(encoded.as_bytes());
            let mut store = ready();
            let evidence = poc_pending_job(&mut store, &output);
            store.remember_poc_credential(old);
            store.remember_poc_credential(current);
            let mut observation = evidence.clone();
            if let crate::jobs::Record::Present {
                exit_status, pid, ..
            } = &mut observation.record
            {
                *exit_status = None;
                *pid = 0;
            }
            block_on(store.job_evidence(&observation)).unwrap();
            let report = block_on(store.job_evidence(&evidence)).unwrap();
            assert_eq!(report.exit_status, Some(7));
            assert!(report.stdout.contains(crate::redaction::MARKER));
            assert!(!report.stdout.contains(&encoded));
            let released = block_on(crate::harness::BoundJournal::release(
                &store,
                serde_json::to_value(&report).unwrap(),
            ))
            .unwrap();
            assert_eq!(released["exit_status"], 7);
            assert_poc_echoes_absent(&released, &[old, current]);
            assert_poc_decrypted_journal_private(&store, &[old, current]);
            if let crate::jobs::Record::Present { stdout, .. } = &report.evidence.record {
                assert_eq!(hex::decode(stdout).unwrap(), report.stdout.as_bytes());
            }
            assert!(block_on(store.collectable("machine-a")).unwrap().is_empty());
            block_on(store.check("machine-a")).unwrap();
            let recovered = reopen(&store).unwrap();
            assert_eq!(recovered.dispatch.jobs.last().unwrap(), &report);
            assert_poc_decrypted_journal_private(&recovered, &[old, current]);
        }
    }
}
#[test]
fn poc_job_evidence_complexity_refuses_before_append_and_cannot_reset_parent_budget() {
    let mut store = ready();
    let mut output = "safe".to_string();
    for _ in 0..20 {
        output = serde_json::to_string(&output).unwrap();
    }
    let mut evidence = poc_pending_job(&mut store, output.as_bytes());
    store.remember_poc_credential(b"normal-synthetic-key-482700");
    let files = store.storage.files();
    let start = std::time::Instant::now();
    let why = block_on(store.job_evidence(&evidence)).unwrap_err();
    assert!(why.contains("bound") || why.contains("depth"), "{why}");
    assert!(start.elapsed() < std::time::Duration::from_secs(15));
    assert_eq!(store.storage.files(), files);
    assert_eq!(block_on(store.collectable("machine-a")).unwrap().len(), 1);
    assert!(block_on(store.check("machine-a")).is_err());
    if let crate::jobs::Record::Present { stdout, .. } = &mut evidence.record {
        *stdout = hex::encode(poc_package_output(65536));
    }
    assert!(
        crate::poc::inference::work::scope(|| {
            crate::poc::inference::work::charge(512 * 1024 * 1024)?;
            block_on(store.job_evidence(&evidence))
        })
        .is_err()
    );
    assert_eq!(store.storage.files(), files);
    assert_eq!(
        block_on(store.job_evidence(&evidence)).unwrap().exit_status,
        Some(7)
    );
    assert!(block_on(store.collectable("machine-a")).unwrap().is_empty());
}

#[test]
fn poc_job_generated_hex_cannot_reintroduce_a_remembered_credential() {
    for (old, output, current) in [
        (
            b"6162636465666768".as_slice(),
            b"abcdefgh".as_slice(),
            b"other-short-key-4827".as_slice(),
        ),
        (
            b"3c72656461637465643e".as_slice(),
            b"current-synthetic-key-4827".as_slice(),
            b"current-synthetic-key-4827".as_slice(),
        ),
    ] {
        let mut store = ready();
        let evidence = poc_pending_job(&mut store, output);
        store.remember_poc_credential(old);
        store.remember_poc_credential(current);
        let files = store.storage.files();
        assert!(block_on(store.job_evidence(&evidence)).is_err());
        assert_eq!(files, store.storage.files());
        assert_eq!(block_on(store.collectable("machine-a")).unwrap().len(), 1);
    }
}

#[test]
fn poc_job_lossy_text_cannot_reintroduce_a_placed_secret() {
    let mut store = ready();
    let raw = b"\xffreplacement-collision";
    let evidence = poc_pending_job(&mut store, raw);
    block_on(store.synthetic_scan_fixture(
        "representation check".into(),
        Zeroizing::new(String::from_utf8_lossy(raw).as_bytes().to_vec()),
    ))
    .unwrap();
    store.remember_poc_credential(b"unrelated-normal-key-482700");
    let files = store.storage.files();
    assert_eq!(
        block_on(store.job_evidence(&evidence)).unwrap_err(),
        "protected output unavailable"
    );
    assert_eq!(store.storage.files(), files);
    assert_eq!(block_on(store.collectable("machine-a")).unwrap().len(), 1);
    assert!(block_on(store.check("machine-a")).is_err());
}

#[test]
fn poc_page_single_acceptance_keeps_checks_and_waits_for_operator_declaration() {
    let mut local = Local::new(MemoryStorage::default(), Fixed);
    block_on(local.open());
    assert_eq!(block_on(local.create(pass()))["state"], "unlocked");
    local.seed_backup_answer();
    block_on(local.seed_backup_complete(None));
    let store = local.store().unwrap();
    enroll(store);
    let session = block_on(store.poc_bind("machine-a")).unwrap();
    block_on(store.enter_goal(&session, "Inspect a service".into(), None)).unwrap();
    let request = json!({"session":session,"checks":["true"]}).to_string();
    assert!(block_on(local.poc_accept(&request)).get("error").is_none());
    let task = block_on(
        local
            .store()
            .unwrap()
            .poc_page_start(&session, vec!["true".into()]),
    )
    .unwrap();
    assert_eq!(task.requests, 0);
    assert_eq!(task.checks, ["true"]);
    assert_eq!(task.status, crate::store::poc::Status::Paused);
    assert!(
        local
            .store()
            .unwrap()
            .pending_requirements_view(&session)
            .is_null()
    );
    assert!(
        block_on(local.poc_accept(&json!({"session":session,"checks":["false"]}).to_string()))
            .get("error")
            .is_some()
    );
    let same = block_on(
        local
            .store()
            .unwrap()
            .poc_start(&session, vec!["true".into()]),
    )
    .unwrap();
    assert_eq!(same.id, task.id);
    assert_eq!(
        local
            .store()
            .unwrap()
            .conduct_acceptances
            .iter()
            .filter(|acceptance| acceptance.session == session)
            .count(),
        1
    );
}
