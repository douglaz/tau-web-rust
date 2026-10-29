use super::*;
use crate::dispatch::{self, CallState, Operation, ReceiptBinding, ReceiptOperation, Resource};
use serde_json::json;

/// Authenticated pre-receipt event shapes, explicitly without the new optional members.
#[test]
fn legacy_encrypted_intents_and_observations_replay_without_resealing_or_receipt_authority() {
    let (_, mut store, _) = dispatch::typed_tests::fresh();
    let call = store.records().end;
    let approval = json!({"resource":{"entry":"fixture"},"target":{"entry":"fixture"},
        "operation":"reset","session":"legacy-session","requester":"session",
        "facts":{"arguments":{},"cost_bound":0,"bundle_commit":"d029ebd9f632696bb027a22559d774d165685947"}});
    let mut old_intent = approval.clone();
    old_intent["call"] = json!(call);
    old_intent["approved"] = approval;
    let legacy = json!({"operation_intent":old_intent});
    let event: Event = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(&event).unwrap(),
        legacy,
        "legacy event encoding is unchanged"
    );
    block_on(store.commit(&event)).unwrap();
    let after_intent = store.storage.files();
    let mut replayed = reopen(&store).unwrap();
    assert_eq!(
        replayed.storage.files(),
        after_intent,
        "unlock never reseals old records"
    );
    assert_eq!(
        replayed.dispatch.typed_calls[&call].intent.receipt_binding,
        None
    );
    assert_eq!(
        replayed.dispatch.typed_calls[&call]
            .intent
            .approved
            .receipt_binding,
        None
    );
    assert!(replayed.dispatch.receipts.is_empty());
    let receipt = dispatch::Receipt {
        source: dispatch::ReceiptSource::BrowserVendorTls,
        call,
        resource: Resource::Entry("fixture".into()),
        target: dispatch::Target::Entry("fixture".into()),
        binding: ReceiptBinding {
            operation: ReceiptOperation::Restart,
            account: 41,
            signed_request: 73,
        },
        validated: true,
        returned_vendor: None,
    };
    assert!(
        block_on(replayed.operation_receipt(receipt))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        replayed.dispatch.typed_calls[&call].state,
        CallState::Unresolved
    );
    let old_observation = json!({"operation_observation":{"resource":{"entry":"fixture"},
        "operation":"reset","reports":"confirmed","calls":[call]}});
    let observation: Event = serde_json::from_value(old_observation.clone()).unwrap();
    assert_eq!(serde_json::to_value(&observation).unwrap(), old_observation);
    let number = block_on(replayed.commit(&observation)).unwrap();
    let files = replayed.storage.files();
    let restored = reopen(&replayed).unwrap();
    assert_eq!(restored.storage.files(), files);
    assert_eq!(
        restored.dispatch.typed_calls[&call].state,
        CallState::Confirmed {
            observation: number
        }
    );
    assert_eq!(restored.dispatch.observations.len(), 1);
    assert_eq!(
        restored.dispatch.receipts.len(),
        1,
        "old read never becomes another receipt"
    );
    assert!(restored.sessions.is_empty());
    for (name, bytes) in after_intent {
        assert_eq!(restored.storage.files()[&name], bytes);
    }
}

fn reopen(store: &Store<MemoryStorage>) -> Result<Store<MemoryStorage>, String> {
    block_on(unlock(
        MemoryStorage::with_files(store.storage.files()),
        &dispatch::typed_tests::FixedKdf,
        LocalPassphrase::new(b"fixture passphrase only".to_vec()),
    ))
}

#[test]
fn replay_rejects_receipt_binding_different_from_the_journaled_approval() {
    let (_, mut store, _) = dispatch::typed_tests::fresh();
    let mut request = dispatch::typed_tests::request(Operation::Reset);
    request.receipt_binding = Some(ReceiptBinding {
        operation: ReceiptOperation::Restart,
        account: 41,
        signed_request: 73,
    });
    request.approved.as_mut().unwrap().receipt_binding = request.receipt_binding.clone();
    let mut intent = store
        .dispatch
        .prepare(store.records().end, &request)
        .unwrap();
    let number = intent.call;
    intent.approved.receipt_binding.as_mut().unwrap().account += 1;
    block_on(store.commit(&Event::OperationIntent(intent))).unwrap();
    let why = reopen(&store)
        .err()
        .expect("replay must enforce approval equality");
    assert!(
        why.contains(&format!("record {number}"))
            && why.contains("intent differs from its approval"),
        "{why}"
    );
}

#[test]
fn replay_rejects_unreserved_or_conflicting_associations() {
    for target in [
        dispatch::Target::AllocationIndex(900),
        dispatch::Target::AllocationIndex(0),
    ] {
        let (_, mut store, _) = dispatch::typed_tests::fresh();
        let number = store.records().end;
        block_on(
            store.commit(&Event::Association(
                dispatch::Association {
                    target,
                    entry: "other".into(),
                }
                .into(),
            )),
        )
        .unwrap();
        let why = reopen(&store)
            .err()
            .expect("invalid association must stop replay");
        assert!(why.contains(&format!("record {number}")), "{why}");
        assert!(
            why.contains("not reserved") || why.contains("already associated"),
            "{why}"
        );
    }
}

#[test]
fn receipt_binding_refuses_positional_arrays_duplicate_members_and_unknown_fields() {
    for bytes in [
        r#"["restart",41,73]"#,
        r#"{"operation":"restart","account":41,"account":42,"signed_request":73}"#,
        r#"{"operation":"restart","account":41,"signed_request":73,"extra":0}"#,
        r#"{"operation":"restart","account":41}"#,
        r#"{"operation":"reinstall","account":41,"signed_request":73}"#,
    ] {
        assert!(
            serde_json::from_str::<ReceiptBinding>(bytes).is_err(),
            "{bytes}"
        );
    }
    assert!(
        serde_json::from_str::<ReceiptBinding>(
            r#"{"operation":"restart","account":41,"signed_request":73}"#
        )
        .is_ok()
    );
}
