use super::*;
use crate::dispatch::*;

struct Fixed;
impl Kdf for Fixed {
    async fn derive(&self, _: LocalPassphrase, _: &Salt) -> Result<WrappingKey, String> {
        Ok(WrappingKey([7; 32]))
    }
}
fn pass() -> LocalPassphrase {
    LocalPassphrase::new(b"setup fixture passphrase".to_vec())
}
// Test-only fixture writer: missing facts enter through an authenticated record and replay.
fn setup_fixture_record(store: &mut Store<MemoryStorage>, record: SetupRecord) {
    block_on(store.commit(&Event::Setup(record))).unwrap();
}

fn fresh() -> Store<MemoryStorage> {
    block_on(create(MemoryStorage::default(), &Fixed, pass())).unwrap()
}
fn reopen(store: &Store<MemoryStorage>) -> Store<MemoryStorage> {
    block_on(unlock(
        MemoryStorage::with_files(store.storage.files()),
        &Fixed,
        pass(),
    ))
    .unwrap()
}
fn completed() -> Store<MemoryStorage> {
    let mut store = fresh();
    block_on(store.seed_backup(allocation::Completion::Skipped)).unwrap();
    store
}
fn approved() -> Store<MemoryStorage> {
    let mut store = completed();
    block_on(store.approve_setup(fixture_setup())).unwrap();
    store
}
fn entry(machine: &str, target: Target) -> Entry {
    Entry {
        machine: machine.into(),
        command: b"true".to_vec(),
        provenance: Some(CommandProvenance {
            target,
            session: None,
            requester: Requester::Session,
        }),
    }
}
fn pin() -> Approval {
    Approval::HarnessPin {
        machine: "fixture".into(),
        fingerprint: "SHA256:fixture".into(),
    }
}
fn events(store: &Store<MemoryStorage>) -> Vec<Value> {
    let mut previous = Address([0; 32]);
    store
        .records()
        .map(|n| {
            let bytes = &store.storage.files()[&n.to_string()];
            let reader = Store::new(
                store.storage.clone(),
                DataKey(store.key.0),
                store.id.clone(),
            );
            let mut reader = reader;
            reader.previous = Address(previous.0);
            let event = reader.open(n, bytes).unwrap();
            previous = Address(Sha256::digest(bytes).into());
            serde_json::to_value(&event).unwrap()
        })
        .collect()
}

#[test]
fn batch_indices_precede_any_create_and_match_the_card() {
    let mut store = completed();
    let mut vendor = crate::dispatch::fixture::Vendor::default();
    let request = crate::dispatch::typed_tests::request(Operation::Create);
    let before = store.storage.files();
    assert_eq!(
        block_on(vendor.run(&mut store, None, &request)),
        Err(OperationError::Policy(RequestRefusal::BoundSet))
    );
    assert!(vendor.received.is_empty());
    assert_eq!(store.storage.files(), before);
    assert!(store.allocation().entries().is_empty());
    let card = fixture_setup();
    let approval = block_on(store.approve_setup(card.clone())).unwrap();
    assert_eq!(
        approval
            .entries
            .iter()
            .map(|a| a.entry.clone())
            .collect::<Vec<_>>(),
        card
    );
    assert_eq!((approval.monthly_sat, approval.annual_sat), (3000, 36000));
    assert_eq!(
        approval
            .entries
            .iter()
            .map(|a| a.identity.index)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert_eq!(
        store
            .allocation()
            .entries()
            .iter()
            .map(|a| a.identity.clone())
            .collect::<Vec<_>>(),
        approval
            .entries
            .iter()
            .map(|a| a.identity.clone())
            .collect::<Vec<_>>()
    );
    block_on(store.answer_class("fixture".into(), ClassAnswer::No)).unwrap();
    let caller = block_on(store.bind("fixture")).unwrap();
    let mut request = request;
    request.session = caller.clone();
    request.approved.as_mut().unwrap().session = caller.clone();
    let call = block_on(vendor.run(&mut store, Some(&caller), &request)).unwrap();
    let records = events(&store);
    assert_eq!(
        records[2]["setup"]["approval"],
        serde_json::to_value(&approval).unwrap()
    );
    assert!(
        records[..2]
            .iter()
            .all(|e| e.get("setup").is_none() && e.pointer("/allocation/reserve").is_none())
    );
    assert_eq!(call, 5);
    assert!(records[5].get("operation_intent").is_some());
    assert_eq!(store.allocation().next_unused().machines, 2);
}

#[test]
fn second_setup_approval_with_distinct_names_is_refused_without_journaling() {
    let mut store = approved();
    let records = store.records();
    let files = store.storage.files();
    let setup = store.dispatch.setup_view();
    let allocation = store.allocation().export();
    let mut entries = fixture_setup();
    for entry in &mut entries {
        entry.machine.push_str("-later");
    }
    assert_eq!(
        block_on(store.approve_setup(entries)).unwrap_err(),
        "setup already approved or empty"
    );
    assert_eq!(store.records(), records);
    assert_eq!(store.storage.files(), files);
    assert_eq!(store.dispatch.setup_view(), setup);
    assert_eq!(store.allocation().export(), allocation);
    assert!(store.failed.is_none());
}

#[test]
fn replay_refuses_second_setup_approval_with_distinct_names_naming_only_the_record() {
    let mut store = completed();
    let mut approval = block_on(store.approve_setup(fixture_setup())).unwrap();
    let mut allocation = store.allocation().clone();
    for approved in &mut approval.entries {
        approved.entry.machine.push_str("-later");
        approved.identity = allocation.issue(Family::Machines).unwrap();
        allocation
            .apply(&allocation::Event::Reserve(approved.identity.clone()))
            .unwrap();
    }
    let number = store.next;
    setup_fixture_record(&mut store, SetupRecord::Approval(approval));
    let why = block_on(unlock(
        MemoryStorage::with_files(store.storage.files()),
        &Fixed,
        pass(),
    ))
    .err()
    .expect("a second setup approval must refuse replay");
    assert_eq!(
        why,
        format!("record {number}: setup already approved or empty; replay stopped")
    );
}

#[test]
fn approval_uses_the_allocation_cores_ceremony_gate() {
    let mut store = fresh();
    let before = store.storage.files();
    assert_eq!(
        block_on(store.approve_setup(fixture_setup())).unwrap_err(),
        allocation::Refusal::BackupMissing.to_string()
    );
    assert_eq!(store.storage.files(), before);
    let export = store.allocation().export();
    block_on(store.record(allocation::Event::Restore(export))).unwrap();
    let before = store.storage.files();
    assert_eq!(
        block_on(store.approve_setup(fixture_setup())).unwrap_err(),
        allocation::Refusal::Restored.to_string()
    );
    assert_eq!(store.storage.files(), before);
    let mut store = fresh();
    store.storage.fault(Fault::Fail(3));
    assert!(block_on(store.seed_backup(allocation::Completion::Skipped)).is_err());
    let before = store.storage.files();
    assert!(block_on(store.approve_setup(fixture_setup())).is_err());
    assert_eq!(store.storage.files(), before);
    let mut store = completed();
    assert!(block_on(store.approve_setup(fixture_setup())).is_ok());
}

#[test]
fn approval_failure_and_every_kill_boundary_apply_only_committed_indices() {
    let base = completed();
    for fault in [
        Fault::Fail(1),
        Fault::Fail(2),
        Fault::Fail(3),
        Fault::LandThenFail(3),
        Fault::Die(1),
        Fault::Die(2),
        Fault::Die(3),
        Fault::Die(4),
    ] {
        let mut store = reopen(&base);
        let original = store.storage.files();
        store.storage.fault(fault);
        let result = block_on(store.approve_setup(fixture_setup()));
        let landed = matches!(fault, Fault::LandThenFail(3) | Fault::Die(4));
        assert_eq!(result.is_ok(), matches!(fault, Fault::Die(4)));
        assert_eq!(
            store.dispatch.approved_entries.len(),
            if result.is_ok() { 2 } else { 0 }
        );
        if result.is_err() {
            assert!(store.failed.is_some());
            assert!(store.allocation().entries().is_empty());
        }
        let mut replayed = reopen(&store);
        assert_eq!(
            replayed.dispatch.approved_entries.len(),
            if landed { 2 } else { 0 }
        );
        assert_eq!(
            replayed.allocation().next_unused().machines,
            if landed { 2 } else { 0 }
        );
        if landed {
            assert_eq!(
                block_on(replayed.allocate(Family::Machines)).unwrap().index,
                2
            );
        } else {
            assert_eq!(store.storage.files().get("2"), original.get("2"));
        }
    }
}

#[test]
fn worker_reports_no_preselected_class_and_not_sure_is_multi_tenant() {
    let mut local = Local::new(MemoryStorage::default(), Fixed);
    block_on(local.open());
    assert!(block_on(local.setup_approve())["error"].is_string());
    block_on(local.create(pass()));
    let before = local.inspect();
    assert!(block_on(local.setup_approve())["error"].is_string());
    assert_eq!(local.inspect(), before);
    local.seed_backup_answer();
    block_on(local.seed_backup_complete(None));
    let report = block_on(local.setup_approve());
    assert_eq!(report["setup"].as_array().unwrap().len(), 2);
    for m in report["setup"].as_array().unwrap() {
        assert!(m["class"].is_null());
        assert!(m["answer"].is_null());
    }
    assert!(
        local
            .store()
            .unwrap()
            .dispatch
            .approved_entries
            .values()
            .all(|m| m.class.is_none())
    );
    let before = local.inspect();
    let files = local.storage.files();
    for input in [
        r#"{"machine":"stray","answer":"yes"}"#,
        r#"{"machine":"fixture","answer":"sealed"}"#,
        r#"{"machine":"fixture","answer":"no","access_model":"sealed"}"#,
        r#"{"machine":"fixture","answer":"yes","question":"custom"}"#,
    ] {
        assert!(block_on(local.setup_answer(input))["error"].is_string());
        assert_eq!(local.inspect(), before);
        assert_eq!(local.storage.files(), files);
    }
    let report = block_on(local.setup_answer(r#"{"machine":"fixture","answer":"not_sure"}"#));
    assert_eq!(report["setup"][0]["class"], "multi_tenant");
    let store = local.store().unwrap();
    let records = events(store);
    assert_eq!(records[3]["setup"]["class"]["class"], "multi_tenant");
    let after = local.inspect();
    let files = local.storage.files();
    assert!(
        block_on(local.setup_answer(r#"{"machine":"fixture","answer":"no"}"#))["error"].is_string()
    );
    assert_eq!(local.inspect(), after);
    assert_eq!(local.storage.files(), files);
}

#[test]
fn class_answer_requires_an_object_without_changing_records_files_or_state() {
    let mut local = Local::new(MemoryStorage::default(), Fixed);
    block_on(local.open());
    block_on(local.create(pass()));
    local.seed_backup_answer();
    block_on(local.seed_backup_complete(None));
    block_on(local.setup_approve());
    let before = local.inspect();
    assert!(
        before["setup"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["answer"].is_null() && entry["class"].is_null())
    );
    let records = local.store().unwrap().records();
    let files = local.storage.files();
    for input in [
        r#"["fixture","yes"]"#,
        r#"["fixture","not_sure"]"#,
        r#""fixture""#,
        "1",
        "true",
        "null",
    ] {
        assert!(
            block_on(local.setup_answer(input))["error"].is_string(),
            "{input}"
        );
        assert_eq!(local.store().unwrap().records(), records, "{input}");
        assert_eq!(local.storage.files(), files, "{input}");
        assert_eq!(local.inspect(), before, "{input}");
    }
}

#[test]
fn access_comes_from_the_compiled_profile_and_no_input_seals() {
    assert!(
        crate::TENANT_PROFILES
            .iter()
            .find(|(n, _)| *n == "ad-hoc")
            .unwrap()
            .1
            .contains(&format!("Profile revision: {} (", ad_hoc_revision()))
    );
    assert_eq!(ad_hoc_revision(), 3);
    let mut store = approved();
    for machine in store.dispatch.approved_entries.values() {
        assert_eq!(machine.approved.access, Some(Access::ad_hoc()));
    }
    for key in [
        "class",
        "answer",
        "access_model",
        "setup",
        "entries",
        "question",
        "goal",
        "proposal",
    ] {
        let before = store.storage.files();
        let view = store.dispatch.setup_view();
        let mut request = crate::dispatch::typed_tests::request(Operation::Create);
        request.facts.arguments.insert(key.into(), "sealed".into());
        request.approved.as_mut().unwrap().facts = request.facts.clone();
        assert_eq!(
            block_on(store.operation(&request)),
            Err(OperationError::Policy(RequestRefusal::Facts))
        );
        assert_eq!(store.storage.files(), before);
        assert_eq!(store.dispatch.setup_view(), view);
        let mut value = json!({"machine":"fixture","command":"true"});
        value[key] = "sealed".into();
        assert!(!crate::harness::valid_request(&value));
    }
    let mut record = events(&store)[2].clone();
    record["setup"]["approval"]["entries"][0]["access"]["model"] = "sealed".into();
    let mut crafted = completed();
    let event: Event = serde_json::from_value(record).unwrap();
    block_on(crafted.commit(&event)).unwrap();
    let why = block_on(unlock(
        MemoryStorage::with_files(crafted.storage.files()),
        &Fixed,
        pass(),
    ))
    .err()
    .unwrap();
    assert!(
        why.contains("record 2") && !why.contains("Fixture vendor"),
        "{why}"
    );
}

#[test]
fn recorded_profile_revision_replays_unchanged_and_allows_binding_after_answer() {
    for revision in [ad_hoc_revision() + 1, u32::MAX] {
        for separate_access in [false, true] {
            let source = approved();
            let mut approval: SetupRecord =
                serde_json::from_value(events(&source)[2]["setup"].clone()).unwrap();
            let mut store = completed();
            if let SetupRecord::Approval(record) = &mut approval {
                for entry in &mut record.entries {
                    entry.identity.seed = store.allocation().seed().into();
                }
                record.entries[0].access = if separate_access {
                    None
                } else {
                    Some(Access {
                        revision,
                        ..Access::ad_hoc()
                    })
                };
            }
            setup_fixture_record(&mut store, approval);
            if separate_access {
                setup_fixture_record(
                    &mut store,
                    SetupRecord::Access(AccessRecord {
                        machine: "fixture".into(),
                        access: Access {
                            revision,
                            ..Access::ad_hoc()
                        },
                    }),
                );
            }
            let mut local = Local::new(store.storage.clone(), Fixed);
            block_on(local.open());
            let files = local.storage.files();
            assert_eq!(block_on(local.unlock(pass()))["state"], "unlocked");
            assert_eq!(local.storage.files(), files);
            assert_eq!(local.inspect()["setup"][0]["access"]["revision"], revision);
            let store = local.store().unwrap();
            assert_eq!(
                store.dispatch.check_binding("fixture"),
                Err(BindingRefusal::ClassMissing)
            );
            block_on(store.answer_class("fixture".into(), ClassAnswer::No)).unwrap();
            assert_eq!(store.dispatch.check_binding("fixture"), Ok(()));
            let replayed = reopen(store);
            assert_eq!(replayed.dispatch.check_binding("fixture"), Ok(()));
            assert_eq!(
                replayed.dispatch.setup_view()[0]["access"]["revision"],
                revision
            );
        }
    }
}

#[test]
fn binding_checks_each_missing_fact_and_reopen_needs_no_associate() {
    let mut store = approved();
    assert_eq!(
        store.dispatch.check_binding("stray"),
        Err(BindingRefusal::NoEntry)
    );
    assert_eq!(
        store.dispatch.check_binding("fixture"),
        Err(BindingRefusal::ClassMissing)
    );
    block_on(store.answer_class("fixture".into(), ClassAnswer::No)).unwrap();
    assert_eq!(store.dispatch.check_binding("fixture"), Ok(()));
    let replayed = reopen(&store);
    assert_eq!(replayed.dispatch.check_binding("fixture"), Ok(()));
    for (i, name) in [(0, "fixture"), (1, "fixture-other")] {
        assert_eq!(
            replayed.dispatch.resolve(&Target::Entry(name.into())),
            Some(Resource::Entry(name.into()))
        );
        assert_eq!(
            replayed.dispatch.resolve(&Target::AllocationIndex(i)),
            Some(Resource::Entry(name.into()))
        );
        assert_eq!(replayed.dispatch.current_installations[name], 0);
    }
    let mut approval: SetupRecord =
        serde_json::from_value(events(&store)[2]["setup"].clone()).unwrap();
    if let SetupRecord::Approval(a) = &mut approval {
        a.entries[0].access = None;
    }
    let mut absent = completed();
    if let SetupRecord::Approval(a) = &mut approval {
        for entry in &mut a.entries {
            entry.identity.seed = absent.allocation().seed().into();
        }
    }
    setup_fixture_record(&mut absent, approval);
    let mut absent = reopen(&absent);
    block_on(absent.answer_class("fixture".into(), ClassAnswer::Yes)).unwrap();
    assert_eq!(
        absent.dispatch.check_binding("fixture"),
        Err(BindingRefusal::AccessMissing)
    );
    assert_eq!(
        reopen(&absent).dispatch.check_binding("fixture"),
        Err(BindingRefusal::AccessMissing)
    );
}

#[test]
fn commands_require_an_approved_entry_and_matching_provenance_without_latching() {
    let mut store = completed();
    let before = store.storage.files();
    assert_eq!(
        block_on(store.check("fixture")),
        Err(AppendRefusal::Policy(DispatchRefusal::NoEntry {
            machine: "fixture".into()
        }))
    );
    assert_eq!(
        block_on(store.append(&entry("fixture", Target::Entry("fixture".into())), &pin())),
        Err(AppendRefusal::Policy(DispatchRefusal::NoEntry {
            machine: "fixture".into()
        }))
    );
    let request = crate::dispatch::typed_tests::request(Operation::Create);
    assert_eq!(
        store.check_operation(&request),
        Err(RequestRefusal::Unmapped)
    );
    assert_eq!(
        block_on(store.operation(&request)),
        Err(OperationError::Policy(RequestRefusal::Unmapped))
    );
    assert_eq!(store.storage.files(), before);
    assert!(store.failed.is_none());
    block_on(store.approve_setup(fixture_setup())).unwrap();
    let extra = block_on(store.allocate(Family::Machines)).unwrap();
    for target in [Target::Entry("fixture".into()), Target::Inference] {
        assert!(
            store
                .associate(Association {
                    target,
                    entry: "fixture".into()
                })
                .is_err()
        );
    }
    assert!(
        store
            .associate(Association {
                target: Target::VendorMachine("stray".into()),
                entry: "stray".into()
            })
            .is_err()
    );
    assert!(
        store
            .associate(Association {
                target: Target::AllocationIndex(0),
                entry: "fixture-other".into()
            })
            .is_err()
    );
    assert_eq!(
        store.associate(Association {
            target: Target::AllocationIndex(extra.index + 1),
            entry: "fixture".into()
        }),
        Err("allocation index not reserved".into())
    );
    for target in [
        Target::AllocationIndex(extra.index),
        Target::VendorMachine("vendor-id".into()),
    ] {
        store
            .associate(Association {
                target,
                entry: "fixture".into(),
            })
            .unwrap();
    }
    let replayed = reopen(&store);
    assert_eq!(
        replayed
            .dispatch
            .resolve(&Target::AllocationIndex(extra.index)),
        None
    );
    assert_eq!(
        replayed
            .dispatch
            .resolve(&Target::VendorMachine("vendor-id".into())),
        None
    );
    for target in [
        Target::Entry("fixture-other".into()),
        Target::AllocationIndex(1),
        Target::VendorMachine("unknown".into()),
    ] {
        let before = store.storage.files();
        assert_eq!(
            block_on(store.append(&entry("fixture", target), &pin())),
            Err(AppendRefusal::Policy(DispatchRefusal::Provenance))
        );
        assert_eq!(store.storage.files(), before);
        assert!(store.failed.is_none());
    }
    for target in [
        Target::Entry("fixture".into()),
        Target::AllocationIndex(0),
        Target::VendorMachine("vendor-id".into()),
    ] {
        let call = block_on(store.append(&entry("fixture", target), &pin())).unwrap();
        block_on(store.terminal(&Terminal {
            call,
            exit_status: 0,
        }))
        .unwrap();
    }
}

#[test]
fn replay_refuses_invalid_setup_records_naming_only_the_record() {
    let original = approved();
    let approval = events(&original)[2]["setup"].clone();
    let class = json!({"class":{"machine":"fixture","answer":"yes","class":"multi_tenant"}});
    let access = json!({"access":{"machine":"fixture","access":{"model":"maintained","profile":"ad-hoc","revision":3}}});
    let mut cases = Vec::new();
    for (path, value) in [
        ("/approval/entries/1/entry/machine", json!("fixture")),
        ("/approval/entries/0/entry/machine", json!("")),
        ("/approval/entries/0/entry/vendor", json!("")),
        ("/approval/entries/0/entry/product", json!("")),
        ("/approval/entries/0/entry/region", json!("")),
        ("/approval/entries/0/identity/index", json!(1)),
        ("/approval/entries/0/identity/derivation_version", json!(2)),
        ("/approval/entries/0/access/model", json!("sealed")),
        ("/approval/entries/0/access/model", json!("unknown")),
        ("/approval/monthly_sat", json!(1)),
    ] {
        let mut bad = approval.clone();
        *bad.pointer_mut(path).unwrap() = value;
        cases.push(vec![bad]);
    }
    for access in [
        json!({"model":"maintained","profile":"other","revision":4}),
        json!({"model":"maintained","profile":"ad-hoc"}),
        json!({"model":"maintained","profile":"ad-hoc","revision":4,"extra":true}),
        json!({"model":"maintained","profile":"ad-hoc","revision":u64::from(u32::MAX) + 1}),
        json!({"model":"maintained","profile":"ad-hoc","revision":-1}),
        json!({"model":"maintained","profile":"ad-hoc","revision":1.5}),
        json!({"model":"maintained","profile":"ad-hoc","revision":"4"}),
        json!({"model":"maintained","profile":"ad-hoc","revision":true}),
        json!({"model":"maintained","profile":"ad-hoc","revision":null}),
    ] {
        let mut bad = approval.clone();
        bad["approval"]["entries"][0]["access"] = access.clone();
        cases.push(vec![bad]);
        let mut without_access = approval.clone();
        without_access["approval"]["entries"][0]["access"] = Value::Null;
        cases.push(vec![
            without_access,
            json!({"access":{"machine":"fixture","access":access}}),
        ]);
    }
    cases.push(vec![approval.clone(), approval.clone()]);
    cases.push(vec![class.clone()]);
    cases.push(vec![access]);
    cases.push(vec![approval.clone(), class.clone(), class.clone()]);
    for (path, value) in [
        ("/class/answer", json!("unknown")),
        ("/class/class", json!("unknown")),
        ("/class/class", json!("single_purpose")),
    ] {
        let mut bad = class.clone();
        *bad.pointer_mut(path).unwrap() = value;
        cases.push(vec![approval.clone(), bad]);
    }
    for records in cases {
        let mut store = completed();
        for mut record in records {
            if let Some(entries) = record
                .pointer_mut("/approval/entries")
                .and_then(Value::as_array_mut)
            {
                for entry in entries {
                    entry["identity"]["seed"] = store.allocation().seed().into();
                }
            }
            // Serialize the malformed shape with the test writer; the live writer cannot emit it.
            let event = json!({"setup":record});
            let number = store.next;
            let previous = hex::encode(store.previous.0);
            let nonce = [number as u8; 12];
            let ciphertext = cipher(&store.key.0)
                .encrypt(
                    &nonce.into(),
                    Payload {
                        msg: event.to_string().as_bytes(),
                        aad: record_aad(&store.id, EVENT, number, &previous).as_bytes(),
                    },
                )
                .unwrap();
            let bytes = serde_json::to_vec(&RecordJson {
                id: store.id.clone(),
                kind: EVENT.into(),
                number,
                previous,
                nonce: URL_SAFE_NO_PAD.encode(nonce),
                ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            })
            .unwrap();
            block_on(store.storage.write(&number.to_string(), &bytes)).unwrap();
            store.next += 1;
            store.previous = Address(Sha256::digest(&bytes).into());
        }
        let why = block_on(unlock(
            MemoryStorage::with_files(store.storage.files()),
            &Fixed,
            pass(),
        ))
        .err()
        .expect("corrupt setup must refuse replay");
        assert!(
            why.contains("record ") && !why.contains("Fixture vendor"),
            "{why}"
        );
    }
    let mut missing = fresh();
    let mut record = approval;
    for entry in record["approval"]["entries"].as_array_mut().unwrap() {
        entry["identity"]["seed"] = missing.allocation().seed().into();
    }
    let event: Event = serde_json::from_value(json!({"setup":record})).unwrap();
    block_on(missing.commit(&event)).unwrap();
    let why = block_on(unlock(
        MemoryStorage::with_files(missing.storage.files()),
        &Fixed,
        pass(),
    ))
    .err()
    .unwrap();
    assert!(
        why.contains("record 1") && why.contains("seed-backup"),
        "{why}"
    );
}

#[test]
fn class_answers_share_the_worker_lock_ceremony_and_allocation_gates() {
    let mut local = Local::new(MemoryStorage::default(), Fixed);
    block_on(local.open());
    let answer = r#"{"machine":"fixture","answer":"yes"}"#;
    let before = local.inspect();
    assert_eq!(block_on(local.setup_answer(answer))["error"], "locked");
    assert_eq!(local.inspect(), before);
    block_on(local.create(pass()));
    let before = local.inspect();
    assert_eq!(block_on(local.setup_answer(answer))["error"], "seed_backup");
    assert_eq!(local.inspect(), before);
    local.seed_backup_answer();
    block_on(local.seed_backup_complete(None));
    block_on(local.setup_approve());
    let store = local.store().unwrap();
    let export = store.allocation().export();
    block_on(store.record(allocation::Event::Restore(export))).unwrap();
    let before = local.inspect();
    let files = local.storage.files();
    assert_eq!(
        block_on(local.setup_answer(answer))["error"],
        allocation::Refusal::Restored.to_string()
    );
    assert_eq!(local.inspect(), before);
    assert_eq!(local.storage.files(), files);
}
