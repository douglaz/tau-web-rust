use super::*;
use crate::dispatch::*;

struct Fixed;
impl Kdf for Fixed {
    async fn derive(&self, _: LocalPassphrase, _: &Salt) -> Result<WrappingKey, String> {
        Ok(WrappingKey([7; 32]))
    }
}
fn pass() -> LocalPassphrase {
    LocalPassphrase::new(b"binding fixture passphrase".to_vec())
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
fn approved() -> Store<MemoryStorage> {
    let mut store = fresh();
    block_on(store.seed_backup(allocation::Completion::Skipped)).unwrap();
    block_on(store.approve_setup(fixture_setup())).unwrap();
    for machine in ["fixture", "fixture-other"] {
        block_on(store.answer_class(machine.into(), ClassAnswer::No)).unwrap();
    }
    store
}

#[test]
fn binding_act_requires_an_approved_entry() {
    let mut store = fresh();
    let before = store.storage.files();
    assert_eq!(block_on(store.bind("fixture")), Err("NoEntry".into()));
    assert_eq!(store.storage.files(), before);
}

#[test]
fn binding_act_requires_journaled_class() {
    let mut store = fresh();
    block_on(store.seed_backup(allocation::Completion::Skipped)).unwrap();
    block_on(store.approve_setup(fixture_setup())).unwrap();
    let files = store.storage.files();
    assert_eq!(block_on(store.bind("fixture")), Err("ClassMissing".into()));
    assert_eq!(store.storage.files(), files);
    assert!(store.sessions().is_empty());
}

#[test]
fn binding_act_requires_journaled_access() {
    let store = approved();
    // The same authenticated access:null fixture used by setup replay: no live edit stands
    // in for a missing journaled prerequisite.
    let mut approval = store
        .dispatch
        .approved_entries
        .values()
        .map(|m| m.approved.clone())
        .collect::<Vec<_>>();
    for a in &mut approval {
        a.access = None;
    }
    let mut missing = fresh();
    block_on(missing.seed_backup(allocation::Completion::Skipped)).unwrap();
    for a in &mut approval {
        a.identity.seed = missing.allocation().seed().into();
    }
    block_on(
        missing.commit(&Event::Setup(SetupRecord::Approval(SetupApproval {
            entries: approval,
            monthly_sat: 3000,
            annual_sat: 36000,
        }))),
    )
    .unwrap();
    let mut missing = reopen(&missing);
    block_on(missing.answer_class("fixture".into(), ClassAnswer::No)).unwrap();
    let files = missing.storage.files();
    assert_eq!(
        block_on(missing.bind("fixture")),
        Err("AccessMissing".into())
    );
    assert!(missing.sessions().is_empty());
    assert_eq!(missing.storage.files(), files);
}

#[test]
fn session_inspection_enumerates_only_its_machine_client_key() {
    let mut store = approved();
    let id = block_on(store.bind("fixture-other")).unwrap();
    let session = block_on(store.connection_session("fixture-other")).unwrap();
    assert_eq!(
        session.inspect(),
        json!({"identity":id,"bound_set":["fixture-other"],"given":[{"row":3,"machine":"fixture-other"}]})
    );
    assert_eq!(
        session.client_key("fixture-other").unwrap().public_key(),
        store
            .seed()
            .unwrap()
            .ssh_client_key(1, 1)
            .unwrap()
            .public_key()
    );
    assert!(session.client_key("fixture").is_none());
}

#[test]
fn unbound_attempt_records_refusal_and_never_binds() {
    let mut store = approved();
    let before = store.records().end;
    assert!(matches!(
        block_on(store.connection_session("fixture")),
        Err(AdmissionRefusal::Unbound)
    ));
    assert!(store.sessions().is_empty());
    assert!(store.exposure_ledger().is_empty());
    assert!(store.commands().is_empty());
    assert_eq!(store.records().end, before + 1);
    assert_eq!(
        store.connection_refusals(),
        &[ConnectionRefusal {
            machine: "fixture".into(),
            reason: Reason::Unbound
        }]
    );
    let replayed = reopen(&store);
    assert_eq!(replayed.connection_refusals(), store.connection_refusals());
    let files = store.storage.files();
    assert!(matches!(
        block_on(store.connection_session("unknown")),
        Err(AdmissionRefusal::NoEntry)
    ));
    assert_eq!(store.storage.files(), files);
    store.storage.fault(Fault::Fail(1));
    assert!(matches!(
        block_on(store.connection_session("fixture")),
        Err(AdmissionRefusal::Journal(_))
    ));
    assert!(store.failed.is_some());
    assert!(store.sessions().is_empty());
}

#[test]
fn a_machine_has_at_most_one_live_binding() {
    let mut store = approved();
    let id = block_on(store.bind("fixture")).unwrap();
    let files = store.storage.files();
    assert_eq!(block_on(store.bind("fixture")), Err("already bound".into()));
    assert_eq!(store.storage.files(), files);
    assert_eq!(store.sessions().len(), 1);
    assert_eq!(store.sessions()[0]["identity"], id);
}

#[test]
fn exposure_replays_but_live_sessions_do_not_and_failed_append_binds_nothing() {
    let mut store = approved();
    let first = block_on(store.bind("fixture")).unwrap();
    let expected = store.exposure_ledger().to_vec();
    assert_eq!(expected.len(), 1);
    assert_eq!(expected[0].bound_set[0].machine, "fixture");
    let mut replayed = reopen(&store);
    assert_eq!(replayed.exposure_ledger(), expected);
    assert!(replayed.sessions().is_empty());
    assert!(matches!(
        block_on(replayed.connection_session("fixture")),
        Err(AdmissionRefusal::Unbound)
    ));
    let second = block_on(replayed.bind("fixture")).unwrap();
    assert_ne!(first, second);
    assert_eq!(replayed.exposure_ledger().len(), 2);
    let mut failed = approved();
    failed.storage.fault(Fault::Fail(1));
    assert!(block_on(failed.bind("fixture")).is_err());
    assert!(failed.sessions().is_empty());
    assert!(failed.exposure_ledger().is_empty());
}

#[test]
fn adapter_refuses_outside_bound_set_before_any_approval() {
    let mut store = approved();
    let caller = block_on(store.bind("fixture")).unwrap();
    let other = block_on(store.bind("fixture-other")).unwrap();
    store
        .associate(Association {
            target: Target::VendorMachine("other-id".into()),
            entry: "fixture-other".into(),
        })
        .unwrap();
    let mut request = crate::dispatch::typed_tests::request(Operation::Reset);
    request.requester = Requester::Session;
    request.session = caller.clone();
    request.approved = None;
    let mut vendor = crate::dispatch::fixture::Vendor::default();
    let files = store.storage.files();
    for target in [
        Target::Entry("fixture-other".into()),
        Target::AllocationIndex(1),
        Target::VendorMachine("other-id".into()),
    ] {
        request.target = target;
        assert_eq!(
            block_on(vendor.run(&mut store, Some(&caller), &request)),
            Err(OperationError::Policy(RequestRefusal::BoundSet)),
            "before any approval screen renders"
        );
        request.operation = Operation::Read;
        assert_eq!(
            block_on(vendor.status(
                &mut store,
                Some(&caller),
                &request,
                Operation::Reset,
                Reports::Unknown
            )),
            Err(OperationError::Policy(RequestRefusal::BoundSet))
        );
        request.operation = Operation::Reset;
    }
    request.target = Target::Entry("fixture".into());
    request.session = other;
    assert_eq!(
        block_on(vendor.run(&mut store, Some(&caller), &request)),
        Err(OperationError::Policy(RequestRefusal::BoundSet)),
        "caller is never supplied by the request"
    );
    assert!(vendor.received.is_empty());
    assert_eq!(store.storage.files(), files);
    request.session = caller.clone();
    assert_eq!(
        block_on(vendor.run(&mut store, Some(&caller), &request)),
        Err(OperationError::Policy(RequestRefusal::Facts))
    );
    request.approved = Some(OperationApproval {
        resource: Resource::Entry("fixture".into()),
        target: request.target.clone(),
        operation: request.operation,
        session: caller.clone(),
        requester: request.requester,
        facts: request.facts.clone(),
    });
    assert!(block_on(vendor.run(&mut store, Some(&caller), &request)).is_ok());
}

#[test]
fn adapter_refuses_caller_present_requester_relabelling() {
    let mut store = approved();
    let caller = block_on(store.bind("fixture")).unwrap();
    let mut vendor = crate::dispatch::fixture::Vendor::default();
    let files = store.storage.files();
    for requester in [Requester::Operator, Requester::HarnessFlow] {
        let mut request = crate::dispatch::typed_tests::request(Operation::Reset);
        request.target = Target::Entry("fixture-other".into());
        request.session = caller.clone();
        request.requester = requester;
        request.approved = Some(OperationApproval {
            resource: Resource::Entry("fixture-other".into()),
            target: request.target.clone(),
            operation: request.operation,
            session: caller.clone(),
            requester,
            facts: request.facts.clone(),
        });
        assert_eq!(store.check_bound_operation(None, &request), Ok(()));
        assert_eq!(
            block_on(vendor.run(&mut store, Some(&caller), &request)),
            Err(OperationError::Policy(RequestRefusal::BoundSet)),
            "caller-present {requester:?} cannot bypass the bound set"
        );
        request.operation = Operation::Read;
        request.approved.as_mut().unwrap().operation = Operation::Read;
        assert_eq!(
            block_on(vendor.status(
                &mut store,
                Some(&caller),
                &request,
                Operation::Reset,
                Reports::Confirmed,
            )),
            Err(OperationError::Policy(RequestRefusal::BoundSet))
        );
        assert!(vendor.received.is_empty());
        assert_eq!(store.storage.files(), files);
    }
}

fn restored_only_other() -> Store<MemoryStorage> {
    let mut source = approved();
    let mut export = serde_json::to_value(source.allocation().export()).unwrap();
    export["entries"]
        .as_array_mut()
        .unwrap()
        .retain(|e| e["identity"]["index"] == 1);
    let export = serde_json::from_value(export).unwrap();
    block_on(source.commit(&Event::Allocation(allocation::Event::Restore(export)))).unwrap();
    reopen(&source)
}

#[test]
fn replay_refuses_exposure_for_an_unlisted_identity() {
    let mut source = restored_only_other();
    let number = source.records().end;
    let identity = source.dispatch.approved_entries["fixture"]
        .approved
        .identity
        .clone();
    let exposure = Exposure {
        session: format!("session-{number}"),
        bound_set: vec![BoundMachine {
            machine: "fixture".into(),
            identity,
        }],
    };
    block_on(source.commit(&Event::Exposure(exposure))).unwrap();
    let why = block_on(unlock(
        MemoryStorage::with_files(source.storage.files()),
        &Fixed,
        pass(),
    ))
    .err()
    .expect("unlisted exposure must refuse replay");
    assert_eq!(
        why,
        format!(
            "record {number}: exposure identity is not listed under the current seed; replay stopped"
        )
    );
}

#[test]
fn binding_uses_ceremony_allocated_and_restored_listed_identities_only() {
    let mut restored = restored_only_other();
    let files = restored.storage.files();
    assert_eq!(
        block_on(restored.bind("fixture")),
        Err("binding identity is not listed under the current seed".into())
    );
    assert_eq!(restored.storage.files(), files);
    assert!(restored.sessions().is_empty());
    block_on(restored.bind("fixture-other")).unwrap();
    assert_eq!(
        reopen(&restored).exposure_ledger(),
        restored.exposure_ledger()
    );
    let mut store = fresh();
    assert!(block_on(store.approve_setup(fixture_setup())).is_err());
    assert!(block_on(store.bind("fixture")).is_err());
    assert!(block_on(store.allocate(Family::Passes)).is_err());
    for completion in [
        allocation::Completion::Skipped,
        allocation::Completion::FullReentry,
    ] {
        let mut store = fresh();
        if completion == allocation::Completion::Skipped {
            block_on(store.seed_backup(completion)).unwrap();
        } else {
            let words = store.seed().unwrap().phrase();
            block_on(store.seed_backup_reentry(Zeroizing::new(words.as_bytes().to_vec()))).unwrap();
        }
        block_on(store.approve_setup(fixture_setup())).unwrap();
        for machine in ["fixture", "fixture-other"] {
            block_on(store.answer_class(machine.into(), ClassAnswer::No)).unwrap();
            block_on(store.bind(machine)).unwrap();
            let session = block_on(store.connection_session(machine)).unwrap();
            let identity = &store.dispatch.approved_entries[machine].approved.identity;
            assert_eq!(
                session.client_key(machine).unwrap().public_key(),
                store
                    .seed()
                    .unwrap()
                    .ssh_client_key(identity.derivation_version, identity.index)
                    .unwrap()
                    .public_key()
            );
        }
        for listed_pass in [false, true] {
            let mut source = reopen(&store);
            if listed_pass {
                block_on(source.allocate(Family::Passes)).unwrap();
            }
            let export = source.allocation().export();
            block_on(source.commit(&Event::Allocation(allocation::Event::Restore(
                export.clone(),
            ))))
            .unwrap();
            let mut restored = reopen(&source);
            for machine in ["fixture", "fixture-other"] {
                block_on(restored.bind(machine)).unwrap();
            }
            assert_eq!(restored.allocation().entries(), export.entries());
            assert_eq!(restored.allocation().next_unused(), export.next_unused());
            assert_eq!(restored.relay_key().is_some(), listed_pass);
            if listed_pass {
                assert_eq!(
                    restored.relay_key().unwrap().public_key(),
                    restored
                        .seed()
                        .unwrap()
                        .relay_key(1, 0)
                        .unwrap()
                        .public_key()
                );
            }
            for family in [Family::Machines, Family::Passes] {
                assert_eq!(
                    block_on(restored.allocate(family)),
                    Err(allocation::Refusal::Restored.to_string())
                );
            }
        }
    }
}

#[test]
fn replay_refuses_malformed_or_unapproved_binding_records_without_plaintext() {
    let source = approved();
    let identity = &source.dispatch.approved_entries["fixture"]
        .approved
        .identity;
    let number = source.records().end;
    let valid = json!({"exposure":{"session":format!("session-{number}"),"bound_set":[{"machine":"fixture","identity":identity}]}});
    let mut unknown = valid.clone();
    unknown["exposure"]["bound_set"][0]["machine"] = "unknown private fixture text".into();
    let mut wrong_index = valid.clone();
    wrong_index["exposure"]["bound_set"][0]["identity"]["index"] = 99.into();
    let mut extra = valid.clone();
    extra["exposure"]["key"] = "private fixture text".into();
    let mut array = valid.clone();
    array["exposure"] = json!([format!("session-{number}"), valid["exposure"]["bound_set"]]);
    for event in [
        unknown,
        wrong_index,
        extra,
        array,
        json!({"connection_refusal":{"machine":"unknown private fixture text","reason":"unbound"}}),
        json!({"connection_refusal":{"machine":"fixture","reason":"other"}}),
        json!({"connection_refusal":["fixture","unbound"]}),
    ] {
        let mut crafted = Store::new(
            MemoryStorage::with_files(source.storage.files()),
            DataKey(source.key.0),
            source.id.clone(),
        );
        block_on(crafted.replay()).unwrap();
        let plaintext = serde_json::to_vec(&event).unwrap();
        // Write authenticated malformed plaintext at the real commit boundary, without using
        // Event deserialization to pre-filter the fixture.
        let previous = hex::encode(crafted.previous.0);
        let nonce = [4; 12];
        let ciphertext = cipher(&crafted.key.0)
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plaintext,
                    aad: record_aad(&crafted.id, EVENT, number, &previous).as_bytes(),
                },
            )
            .unwrap();
        let record = RecordJson {
            id: crafted.id.clone(),
            kind: EVENT.into(),
            number,
            previous,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        };
        block_on(
            crafted
                .storage
                .write(&number.to_string(), &serde_json::to_vec(&record).unwrap()),
        )
        .unwrap();
        let why = block_on(unlock(
            MemoryStorage::with_files(crafted.storage.files()),
            &Fixed,
            pass(),
        ))
        .err()
        .unwrap();
        assert!(
            why.contains(&format!("record {number}")) && !why.contains("private fixture text"),
            "{why}"
        );
    }
}

#[test]
fn page_binding_is_refused_while_locked_or_in_seed_backup() {
    let mut local = Local::new(MemoryStorage::default(), Fixed);
    block_on(local.open());
    assert_eq!(
        block_on(local.bind(r#"{"machine":"fixture"}"#))["error"],
        "locked"
    );
    block_on(local.create(pass()));
    let before = local.storage.files();
    assert_eq!(
        block_on(local.bind(r#"{"machine":"fixture"}"#))["error"],
        "seed_backup"
    );
    assert_eq!(local.storage.files(), before);
}
