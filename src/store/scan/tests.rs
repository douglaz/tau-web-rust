use super::*;
use crate::harness::Journal;
use crate::store::inference::tests::ready;

fn fixture(value: &[u8]) -> (Store<MemoryStorage>, String) {
    let mut store = ready();
    let identity = block_on(
        store.synthetic_scan_fixture("service access".into(), Zeroizing::new(value.to_vec())),
    )
    .unwrap();
    (store, identity)
}
fn inventory(id: &str) -> Vec<Required> {
    vec![Required {
        identity: id.into(),
        name: "service access".into(),
    }]
}

#[test]
fn original_raw_windows_cross_every_chunk_boundary_before_either_sink() {
    let secret = b"\xff\xfeoriginal-secret-123456";
    let (store, _) = fixture(secret);
    for split in 1..secret.len() {
        let a = [b"out:".as_slice(), &secret[..split]].concat();
        let b = [&secret[split..], b":end"].concat();
        assert_eq!(
            store.scan_output(&[&a, &b]).unwrap().as_slice(),
            b"out:<redacted secret: service access>:end"
        );
    }
    assert_eq!(
        store
            .scan_output(&[b"a legitimate nonmatch"])
            .unwrap()
            .as_slice(),
        b"a legitimate nonmatch"
    );
    assert_eq!(
        store
            .scan_output(&[&secret[..secret.len() - 1]])
            .unwrap()
            .as_slice(),
        &secret[..secret.len() - 1]
    );
    let both_sinks = json!({"stdout":hex::encode(secret),"transcript_only":{"copy":String::from_utf8_lossy(secret)}});
    let safe = store.protect_output(&both_sinks).unwrap();
    assert_eq!(
        safe["stdout"],
        hex::encode("<redacted secret: service access>")
    );
}

#[test]
fn authenticated_reload_retains_identity_material_and_ciphertext_across_working_copy_end() {
    let secret = b"original-independent-reference-123";
    let (mut store, id) = fixture(secret);
    let before = store.storage.files();
    let original_material = store.scans.working_material_bytes(&id).unwrap();
    let revision = store.scan_revision();
    store.authority.suspend();
    store.suspend_clocks();
    store.authority.revalidated().unwrap();
    assert_eq!(
        store.scan_revision(),
        revision,
        "freeze does not replace references"
    );
    assert_eq!(
        store.scan_output(&[secret]).unwrap().as_slice(),
        b"<redacted secret: service access>"
    );
    store.clear_scan_working_copies();
    assert!(store.scan_readiness().is_err());
    assert!(store.protect_output(&json!("legitimate output")).is_err());
    block_on(store.reload_scan_references()).unwrap();
    assert_eq!(
        store.scans.working_material_bytes(&id).unwrap().as_slice(),
        original_material.as_slice()
    );
    assert_eq!(
        store.storage.files(),
        before,
        "read-only reload performs no encryption/write"
    );
    assert_eq!(
        store.scan_output(&[secret]).unwrap().as_slice(),
        b"<redacted secret: service access>"
    );
    store.end_inference_sessions();
    assert!(store.scans.working_material_bytes(&id).is_none());
    assert!(store.scan_readiness().is_err());
    assert_eq!(
        store.storage.files(),
        before,
        "end does not retire persistent material"
    );
    let mut reopened = block_on(unlock(
        MemoryStorage::with_files(before.clone()),
        &crate::store::inference::tests::Fixed,
        LocalPassphrase::new(b"inference fixture passphrase".to_vec()),
    ))
    .unwrap();
    block_on(reopened.load_scan_references(inventory(&id))).unwrap();
    assert_eq!(
        reopened
            .scans
            .working_material_bytes(&id)
            .unwrap()
            .as_slice(),
        original_material.as_slice()
    );
    assert_eq!(
        reopened.scan_output(&[secret]).unwrap().as_slice(),
        b"<redacted secret: service access>"
    );
    assert_eq!(reopened.storage.files(), before);
}

#[test]
fn identified_missing_tampered_wrong_identity_and_invalid_inventory_never_become_empty_ready() {
    let (mut store, id) = fixture(b"original-independent-reference-123");
    let name = format!("scan-{id}");
    let blob = store.storage.files()[&name].clone();
    block_on(store.storage.write(&name, b"{}")).unwrap();
    assert!(block_on(store.reload_scan_references()).is_err());
    assert!(store.scan_readiness().is_err());
    block_on(store.storage.write(&name, &blob)).unwrap();
    block_on(store.reload_scan_references()).unwrap();
    let other = "b".repeat(48);
    block_on(store.storage.write(&format!("scan-{other}"), &blob)).unwrap();
    assert!(
        block_on(store.load_scan_references(inventory(&other))).is_err(),
        "AAD binds identity"
    );
    assert!(store.scan_readiness().is_err());
    let mut different_store = ready();
    block_on(different_store.storage.write(&name, &blob)).unwrap();
    assert!(
        block_on(different_store.load_scan_references(inventory(&id))).is_err(),
        "store data key/AAD differs"
    );
    assert!(
        block_on(store.load_scan_references(inventory(&"c".repeat(48)))).is_err(),
        "required missing file"
    );
    assert!(store.scan_readiness().is_err());
    assert!(block_on(store.load_scan_references(inventory("invalid"))).is_err());
    assert!(store.scan_readiness().is_err());
    let mut clean = ready();
    assert!(block_on(clean.load_scan_references(inventory("invalid"))).is_err());
    assert!(
        clean.scan_readiness().is_err(),
        "invalid required inventory cannot arm empty set"
    );
    block_on(store.load_scan_references(inventory(&id))).unwrap();
}

#[test]
fn exact_encrypted_representation_refuses_each_noncanonical_or_invalid_member() {
    let (mut store, id) = fixture(b"original-independent-reference-123");
    let filename = format!("scan-{id}");
    let original = store.storage.files()[&filename].clone();
    let blob: Blob = serde_json::from_slice(&original).unwrap();
    let nonce = decode::<12>("nonce", &blob.nonce).unwrap();
    let aad = format!("tau-web/local/v1/{}/scan/{id}", store.id);
    let plaintext = cipher(&store.key.0)
        .decrypt(
            &nonce.into(),
            Payload {
                msg: &URL_SAFE_NO_PAD.decode(&blob.ciphertext).unwrap(),
                aad: aad.as_bytes(),
            },
        )
        .unwrap();
    let text = String::from_utf8(plaintext.clone()).unwrap();
    let value: Value = serde_json::from_slice(&plaintext).unwrap();
    let mut invalid = vec![
        format!(" {text}"),
        format!("{text}\n"),
        text.replace("\"key\":", "\"extra\":0,\"key\":"),
        text.replace("\"key\":", "\"length\":16,\"key\":"),
    ];
    for field in ["key", "reference", "length"] {
        let mut bad = value.clone();
        bad.as_object_mut().unwrap().remove(field);
        invalid.push(bad.to_string());
    }
    for field in ["key", "reference"] {
        for bad in [
            json!(vec![0; 31]),
            json!(vec![0; 33]),
            json!("not bytes"),
            json!([-1]),
            json!([256]),
        ] {
            let mut v = value.clone();
            v[field] = bad;
            invalid.push(v.to_string());
        }
    }
    for bad in [json!(15), json!(-1), json!(16.0), json!("16")] {
        let mut v = value.clone();
        v["length"] = bad;
        invalid.push(v.to_string());
    }
    for text in invalid {
        let ciphertext = cipher(&store.key.0)
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: text.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .unwrap();
        let bytes = serde_json::to_vec(&Blob {
            nonce: blob.nonce.clone(),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
        .unwrap();
        block_on(store.storage.write(&filename, &bytes)).unwrap();
        assert!(block_on(store.reload_scan_references()).is_err());
        assert!(store.scan_readiness().is_err());
    }
    for bytes in [
        format!(" {}", String::from_utf8_lossy(&original)),
        format!(
            "{{\"nonce\":\"{}\",\"nonce\":\"{}\",\"ciphertext\":\"{}\"}}",
            blob.nonce, blob.nonce, blob.ciphertext
        ),
        format!(
            "{{\"nonce\":\"{}=\",\"ciphertext\":\"{}\"}}",
            blob.nonce, blob.ciphertext
        ),
    ] {
        block_on(store.storage.write(&filename, bytes.as_bytes())).unwrap();
        assert!(block_on(store.reload_scan_references()).is_err());
    }
    block_on(store.storage.write(&filename, &original)).unwrap();
    block_on(store.reload_scan_references()).unwrap();
}

#[test]
fn real_job_terminal_historical_and_uncommitted_nested_routes_scan_raw_before_decoding() {
    let secret = b"\xff\xfeoriginal-secret-123456";
    let (mut store, _) = fixture(secret);
    let session = store.sessions[0].identity.clone();
    block_on(store.enter_goal(&session, "fixture output check".into(), None)).unwrap();
    block_on(store.accept_mode(&session, crate::modes::Mode::NoBrief)).unwrap();
    store
        .propose_requirements(
            &session,
            42,
            crate::declaration::Proposal::Declaration {
                machine: "fixture".into(),
                declaration: crate::declaration::ad_hoc_minimum(),
            },
            &crate::goals::Tool::Done {
                machine: "fixture".into(),
            },
        )
        .unwrap();
    block_on(store.approve_requirements(&session, "fixture", 42)).unwrap();
    let entry = Entry {
        machine: "fixture".into(),
        command: b"fixture output".to_vec(),
        provenance: Some(crate::dispatch::CommandProvenance {
            target: crate::dispatch::Target::Entry("fixture".into()),
            session: Some(session),
            requester: crate::dispatch::Requester::Session,
        }),
    };
    let call = block_on(store.append(
        &entry,
        &Approval::HarnessPin {
            machine: "fixture".into(),
            fingerprint: "fixture-pin".into(),
        },
    ))
    .unwrap();
    let job = store.dispatch.calls[&call].intent.job.clone().unwrap();
    let evidence = crate::jobs::Evidence {
        call,
        job,
        record: crate::jobs::Record::Present {
            machine: hex::encode("fixture"),
            command: hex::encode(&entry.command),
            boot: "boot-one".into(),
            current_boot: "boot-one".into(),
            pid: 1,
            alive: false,
            exit_status: Some(0),
            stdout: hex::encode(secret),
            stderr: hex::encode([b"err:".as_slice(), secret].concat()),
        },
    };
    let uncommitted = crate::jobs::uncommitted(&evidence, "fixture", &hex::encode(&entry.command));
    let release = store
        .protect_output(&json!({"held":{"job_record":uncommitted},"transcript_only":uncommitted}))
        .unwrap();
    assert_eq!(
        release["held"]["job_record"]["stdout"],
        "<redacted secret: service access>"
    );
    assert_eq!(
        release["transcript_only"]["record"]["stdout"],
        hex::encode("<redacted secret: service access>")
    );
    let report = block_on(store.job_evidence(&evidence)).unwrap();
    assert_eq!(report.stdout, "<redacted secret: service access>");
    assert_eq!(report.stderr, "err:<redacted secret: service access>");
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains(&hex::encode(secret))
    );
    let historical = store
        .protect_output(&serde_json::to_value(&store.dispatch.jobs).unwrap())
        .unwrap();
    assert!(!historical.to_string().contains(&hex::encode(secret)));
}

#[test]
fn partial_authenticated_load_failure_clears_every_temporary_working_copy() {
    let (mut store, id) = fixture(b"original-independent-secret-1234");
    let mut entries = inventory(&id);
    let invalid = "f".repeat(48);
    block_on(store.storage.write(&format!("scan-{invalid}"), b"{}")).unwrap();
    entries.push(Required {
        identity: invalid,
        name: "other service".into(),
    });
    assert!(block_on(store.load_scan_references(entries)).is_err());
    assert!(store.scans.working_material_bytes(&id).is_none());
    assert!(store.scan_readiness().is_err());
}
