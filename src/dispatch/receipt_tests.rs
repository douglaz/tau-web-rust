//! Fixture receipt inputs exercise the production writer and replay, not a vendor adapter.
use super::*;
use crate::dispatch::typed_tests::{fresh, request};
use crate::store::{self, Fault, MemoryStorage, OperationError, Store, block_on};

fn reopen(store: &Store<MemoryStorage>) -> Store<MemoryStorage> {
    // No fixture mappings, bindings, sessions, or approvals are supplied after unlock.
    block_on(store::unlock(
        MemoryStorage::with_files(store.storage().files()),
        &typed_tests::FixedKdf,
        crate::credential::LocalPassphrase::new(b"fixture passphrase only".to_vec()),
    ))
    .unwrap()
}

fn bound_request(operation: ReceiptOperation) -> Request {
    let mut r = request(operation.operation());
    r.receipt_binding = Some(ReceiptBinding {
        operation,
        account: 41,
        signed_request: 73,
    });
    r.approved.as_mut().unwrap().receipt_binding = r.receipt_binding.clone();
    r
}

fn receipt(intent: &OperationIntent) -> Receipt {
    Receipt {
        source: ReceiptSource::BrowserVendorTls,
        call: intent.call,
        resource: intent.resource.clone(),
        target: intent.target.clone(),
        binding: intent.receipt_binding.clone().unwrap(),
        validated: true,
        returned_vendor: (intent.operation == Operation::Create).then(|| "returned-id".into()),
    }
}

fn association(entry: &str) -> Association {
    Association {
        target: Target::VendorMachine("returned-id".into()),
        entry: entry.into(),
    }
}

fn assert_held(store: &Store<MemoryStorage>, call: u64) {
    assert_eq!(
        store
            .dispatch()
            .unresolved(&Resource::Entry("fixture".into())),
        [call]
    );
    assert!(matches!(store.check_operation(&request(Operation::Reset)),
        Err(RequestRefusal::Barrier { calls }) if calls == [call]));
}

#[test]
fn receipt_correlation_refusals_and_nearest_success_retain_every_input() {
    for wrong in [
        "call",
        "resource",
        "target",
        "account",
        "signed_request",
        "operation",
        "validated",
        "arbitrary_response",
        "job_output",
        "notify_event",
        "proposed_text",
    ] {
        let (_, mut store, _) = fresh();
        let intent = block_on(store.operation(&bound_request(ReceiptOperation::Restart))).unwrap();
        let good = receipt(&intent);
        let mut bad = good.clone();
        match wrong {
            "call" => bad.call += 1000,
            "resource" => bad.resource = Resource::Entry("other".into()),
            "target" => bad.target = Target::VendorMachine("different".into()),
            "account" => bad.binding.account += 1,
            "signed_request" => bad.binding.signed_request += 1,
            "operation" => bad.binding.operation = ReceiptOperation::Stop,
            "validated" => bad.validated = false,
            "arbitrary_response" => bad.source = ReceiptSource::ArbitraryResponse,
            "job_output" => bad.source = ReceiptSource::JobOutput,
            "notify_event" => bad.source = ReceiptSource::NotifyEvent,
            "proposed_text" => bad.source = ReceiptSource::ProposedText,
            _ => unreachable!(),
        }
        assert!(
            block_on(store.operation_receipt(bad.clone()))
                .unwrap()
                .is_empty(),
            "{wrong}: mismatched receipt must not settle"
        );
        assert_held(&store, intent.call);
        let mut replayed = reopen(&store);
        assert_held(&replayed, intent.call);
        assert_eq!(
            replayed.dispatch().receipts[0].receipt,
            bad,
            "{wrong}: complete evidence retained"
        );
        assert_eq!(
            block_on(replayed.operation_receipt(good.clone())).unwrap(),
            [intent.call],
            "{wrong}: nearest valid success"
        );
        let again = reopen(&replayed);
        assert!(again.dispatch().unresolved(&intent.resource).is_empty());
        assert_eq!(again.dispatch().receipts.len(), 2);
        assert_eq!(again.dispatch().receipts[1].receipt, good);
        assert!(again.dispatch().observations.is_empty());
    }
}

#[test]
fn receipts_are_operation_limited_and_robot_keeps_read_confirmation() {
    for op in [
        Operation::Create,
        Operation::Reset,
        Operation::Destroy,
        Operation::Reinstall,
        Operation::Read,
    ] {
        for bound in [false, true] {
            let (_, mut store, _) = fresh();
            let mut r = bound_request(ReceiptOperation::Restart);
            r.operation = op;
            r.approved.as_mut().unwrap().operation = op;
            if !bound {
                r.receipt_binding = None;
                r.approved.as_mut().unwrap().receipt_binding = None;
            }
            let intent = block_on(store.operation(&r)).unwrap();
            let mut evidence = receipt(&OperationIntent {
                receipt_binding: Some(ReceiptBinding {
                    operation: ReceiptOperation::Restart,
                    account: 41,
                    signed_request: 73,
                }),
                ..intent.clone()
            });
            evidence.binding.operation = ReceiptOperation::Restart;
            let settled = block_on(store.operation_receipt(evidence)).unwrap();
            assert_eq!(
                settled,
                if bound && op == Operation::Reset {
                    vec![intent.call]
                } else {
                    vec![]
                },
                "{op:?}, bound={bound}"
            );
            let mut replayed = reopen(&store);
            if !bound && op.mutation() {
                let read = replayed.dispatch().observation(
                    intent.resource.clone(),
                    op,
                    Reports::Confirmed,
                );
                assert_eq!(
                    block_on(replayed.operation_observation(read)).unwrap(),
                    [intent.call],
                    "Robot/unbound read fixture keeps its previous authority"
                );
            }
        }
    }
}

#[test]
fn order_requires_both_durable_constituents_in_either_arrival_order() {
    for receipt_first in [false, true] {
        for replay_between in [false, true] {
            let (_, mut store, _) = fresh();
            let intent =
                block_on(store.operation(&bound_request(ReceiptOperation::Order))).unwrap();
            store = reopen(&store); // Before either constituent.
            let evidence = receipt(&intent);
            if receipt_first {
                assert!(
                    block_on(store.operation_receipt(evidence.clone()))
                        .unwrap()
                        .is_empty()
                );
            } else {
                block_on(store.associate(association("fixture"))).unwrap();
            }
            assert_held(&store, intent.call);
            if replay_between {
                store = reopen(&store);
            }
            assert_held(&store, intent.call);
            if receipt_first {
                block_on(store.associate(association("fixture"))).unwrap();
            } else {
                assert_eq!(
                    block_on(store.operation_receipt(evidence.clone())).unwrap(),
                    [intent.call]
                );
            }
            let after = reopen(&store);
            for state in [&store, &after] {
                assert!(state.dispatch().unresolved(&intent.resource).is_empty());
                assert!(
                    state.sessions().is_empty(),
                    "replay restores no live authority"
                );
                assert_eq!(state.dispatch().receipts[0].receipt, evidence);
                assert_eq!(
                    state.dispatch().receipts[0].settled,
                    if receipt_first {
                        vec![]
                    } else {
                        vec![intent.call]
                    },
                    "later association must not rewrite the receipt's historical outcome"
                );
                assert_eq!(
                    state
                        .dispatch()
                        .resolve(&Target::VendorMachine("returned-id".into())),
                    Some(intent.resource.clone())
                );
                let report = state.dispatch().check_disposition(
                    state.records().end,
                    &Disposition {
                        machine: "fixture".into(),
                        calls: vec![intent.call],
                        continuation: Continuation::AsIfDone,
                        uncertainty: "fixture".into(),
                    },
                );
                let DispositionReport::Refused { issues, .. } = report else {
                    panic!("settled call is ineligible")
                };
                assert!(
                    matches!(
                        issues[0].settling_record,
                        Some(SettlingRecord::Receipt {
                            association: Some(_),
                            ..
                        })
                    ),
                    "diagnostics retain both constituent records"
                );
            }
        }
    }
}

#[test]
fn order_missing_id_and_wrong_entry_do_not_gain_association_authority() {
    for missing_id in [true, false] {
        let (_, mut store, _) = fresh();
        let intent = block_on(store.operation(&bound_request(ReceiptOperation::Order))).unwrap();
        block_on(store.associate(association(if missing_id { "fixture" } else { "other" })))
            .unwrap();
        let mut evidence = receipt(&intent);
        if missing_id {
            evidence.returned_vendor = None;
        }
        assert!(
            block_on(store.operation_receipt(evidence))
                .unwrap()
                .is_empty()
        );
        assert_held(&reopen(&store), intent.call);
        if !missing_id {
            let files = store.storage().files();
            assert_eq!(
                block_on(store.associate(association("fixture"))),
                Err("target already associated".into())
            );
            assert_eq!(
                store.storage().files(),
                files,
                "conflicting ownership writes nothing"
            );
        } else {
            assert_eq!(
                block_on(store.operation_receipt(receipt(&intent))).unwrap(),
                [intent.call]
            );
        }
    }
}

#[test]
fn receipt_and_association_append_failures_latch_without_live_effect_and_landed_records_replay_once()
 {
    for association_fails in [false, true] {
        for fault in [
            Fault::Fail(1),
            Fault::Fail(2),
            Fault::Fail(3),
            Fault::LandThenFail(3),
        ] {
            let (_, mut store, _) = fresh();
            let intent =
                block_on(store.operation(&bound_request(ReceiptOperation::Order))).unwrap();
            if association_fails {
                block_on(store.operation_receipt(receipt(&intent))).unwrap();
            } else {
                block_on(store.associate(association("fixture"))).unwrap();
            }
            let before = store.dispatch().clone();
            store.storage().fault(fault);
            let result = if association_fails {
                block_on(store.associate(association("fixture")))
            } else {
                block_on(store.operation_receipt(receipt(&intent))).map(|_| ())
            };
            assert!(result.is_err());
            assert_held(&store, intent.call);
            assert_eq!(store.dispatch().receipts, before.receipts);
            assert_eq!(store.dispatch().associations, before.associations);
            assert_eq!(
                store.dispatch().association_records,
                before.association_records
            );
            let latched_files = store.storage().files();
            assert!(
                block_on(store.operation_receipt(receipt(&intent)))
                    .unwrap_err()
                    .contains("earlier append failed")
            );
            let mut fresh_association = association("fixture");
            fresh_association.target = Target::VendorMachine("another-id".into());
            assert!(
                block_on(store.associate(fresh_association))
                    .unwrap_err()
                    .contains("earlier append failed")
            );
            // An admitted duplicate performs no append, even when the writer is latched.
            if !association_fails {
                block_on(store.associate(association("fixture"))).unwrap();
            }
            assert_eq!(store.storage().files(), latched_files);
            let landed = matches!(fault, Fault::LandThenFail(_));
            let mut replayed = reopen(&store);
            assert_eq!(
                replayed.dispatch().unresolved(&intent.resource).is_empty(),
                landed
            );
            assert_eq!(
                replayed.dispatch().receipts.len(),
                usize::from(association_fails || landed)
            );
            assert_eq!(
                replayed.dispatch().association_records.len(),
                2 + usize::from(!association_fails || landed)
            );
            let again = reopen(&replayed);
            assert_eq!(again.dispatch().receipts, replayed.dispatch().receipts);
            assert_eq!(
                again.dispatch().association_records,
                replayed.dispatch().association_records
            );
            assert!(replayed.sessions().is_empty());
            if !landed {
                let mut successor = bound_request(ReceiptOperation::Order);
                successor.session = "successor".into();
                successor.target = Target::AllocationIndex(0);
                successor.approved.as_mut().unwrap().session = successor.session.clone();
                successor.approved.as_mut().unwrap().target = successor.target.clone();
                assert!(
                    matches!(block_on(replayed.operation(&successor)), Err(OperationError::Policy(RequestRefusal::Barrier { calls })) if calls == [intent.call]),
                    "new session and index cannot retry an uncertain mutation"
                );
            }
        }
    }
}

#[test]
fn receipt_binding_is_approved_context_and_replay_checks_intent_equality() {
    let (_, mut store, _) = fresh();
    for change_approval in [false, true] {
        let mut r = bound_request(ReceiptOperation::Restart);
        if change_approval {
            r.approved
                .as_mut()
                .unwrap()
                .receipt_binding
                .as_mut()
                .unwrap()
                .account += 1;
        } else {
            r.receipt_binding.as_mut().unwrap().signed_request += 1;
        }
        let files = store.storage().files();
        assert_eq!(
            block_on(store.operation(&r)),
            Err(OperationError::Policy(RequestRefusal::Facts))
        );
        assert_eq!(store.storage().files(), files);
    }
    let mut intent = store
        .dispatch()
        .prepare(
            store.records().end,
            &bound_request(ReceiptOperation::Restart),
        )
        .unwrap();
    intent.receipt_binding = None;
    let call = intent.call;
    assert_eq!(
        store.dispatch_mut().operation_intent(call, intent),
        Err("intent differs from its approval".into())
    );
    assert!(store.dispatch().typed_calls.is_empty());
}

#[test]
fn response_bytes_and_late_receipts_do_not_create_new_authority_or_reopen_dispositions() {
    let (_, mut store, _) = fresh();
    let intent = block_on(store.operation(&bound_request(ReceiptOperation::Stop))).unwrap();
    block_on(store.operation_response(intent.call, br#"{"success":true}"#, &[])).unwrap();
    assert_held(&store, intent.call);
    let disposition = Disposition {
        machine: "fixture".into(),
        calls: vec![intent.call],
        continuation: Continuation::Abandonment,
        uncertainty: "unknown".into(),
    };
    block_on(store.dispose(disposition)).unwrap();
    let state = store.dispatch().typed_calls[&intent.call].state.clone();
    assert!(
        block_on(store.operation_receipt(receipt(&intent)))
            .unwrap()
            .is_empty()
    );
    let after = reopen(&store);
    assert_eq!(after.dispatch().typed_calls[&intent.call].state, state);
    assert!(after.dispatch().standing.contains_key("fixture"));
    assert_eq!(after.dispatch().current_installations["fixture"], 0);
    assert!(after.dispatch().observations.is_empty());
}

#[test]
fn receipt_before_intent_never_settles_a_future_call_when_association_arrives() {
    let (_, mut store, _) = fresh();
    let mut future = store
        .dispatch()
        .prepare(
            store.records().end + 1,
            &bound_request(ReceiptOperation::Order),
        )
        .unwrap();
    // Receipt is durable before the subsequently guessed intent id exists.
    assert!(
        block_on(store.operation_receipt(receipt(&future)))
            .unwrap()
            .is_empty()
    );
    future = block_on(store.operation(&bound_request(ReceiptOperation::Order))).unwrap();
    block_on(store.associate(association("fixture"))).unwrap();
    assert_held(&store, future.call);
    assert_held(&reopen(&store), future.call);
    assert_eq!(
        block_on(store.operation_receipt(receipt(&future))).unwrap(),
        [future.call]
    );
}
