//! Independent Markdown-contract tests, without witness projections.
use super::*;
use crate::dispatch::typed_tests::{fresh, request};
use crate::dispatch::*;

fn protection(slots: &[&str]) -> EvidenceProtection {
    EvidenceProtection::transient("received input".into(), slots).unwrap()
}
fn bound(op: ReceiptOperation) -> Request {
    let mut r = request(op.operation());
    r.receipt_binding = Some(ReceiptBinding {
        operation: op,
        account: 41,
        signed_request: 73,
    });
    r.approved.as_mut().unwrap().receipt_binding = r.receipt_binding.clone();
    r
}
fn receipt(i: &OperationIntent) -> Receipt {
    Receipt {
        source: ReceiptSource::BrowserVendorTls,
        call: i.call,
        resource: i.resource.clone(),
        target: i.target.clone(),
        binding: i.receipt_binding.clone().unwrap(),
        validated: true,
        returned_vendor: Some("received-literal".into()),
    }
}
fn association(entry: &str, id: &str) -> Association {
    Association {
        entry: entry.into(),
        target: Target::VendorMachine(id.into()),
    }
}
fn reopen(s: &Store<MemoryStorage>) -> Result<Store<MemoryStorage>, String> {
    block_on(unlock(
        MemoryStorage::with_files(s.storage.files()),
        &crate::dispatch::typed_tests::FixedKdf,
        LocalPassphrase::new(b"fixture passphrase only".to_vec()),
    ))
}
fn json_receipt(s: &Store<MemoryStorage>) -> Value {
    serde_json::to_value(s.dispatch.receipts.last().unwrap()).unwrap()
}

#[test]
fn canonical_presence_display_omission_and_every_genuine_operand_remain_distinct() {
    for slot in [
        "call",
        "resource",
        "target",
        "binding/account",
        "binding/signed_request",
        "returned_vendor",
    ] {
        let (_, mut s, _) = fresh();
        let intent = block_on(s.operation(&bound(ReceiptOperation::Order))).unwrap();
        block_on(s.associate(association("fixture", "received-literal"))).unwrap();
        let result =
            block_on(s.protected_operation_receipt(receipt(&intent), protection(&[slot]))).unwrap();
        assert_eq!(
            result,
            if slot == "returned_vendor" {
                vec![]
            } else {
                vec![intent.call]
            },
            "{slot}: genuine pre-omission comparisons"
        );
        let p = json_receipt(&s);
        assert!(
            p["receipt"].pointer(&format!("/facts/{slot}")).is_none(),
            "{slot}: original absent"
        );
        assert_eq!(p["receipt"]["withheld"][0]["slot"], slot);
        let reopened = reopen(&s).unwrap();
        assert_eq!(json_receipt(&reopened), p);
        if slot == "returned_vendor" {
            assert_eq!(
                s.dispatch.identity_exclusions("other"),
                [s.dispatch.receipts[0].number]
            );
            assert_eq!(
                s.dispatch.typed_calls[&intent.call].state,
                CallState::Unresolved
            );
            assert!(
                !serde_json::to_string(&s.dispatch.receipts)
                    .unwrap()
                    .contains("received-literal")
            );
        } else {
            assert!(s.dispatch.identity_exclusions("other").is_empty());
        }
    }
    let (_, mut s, _) = fresh();
    let intent = block_on(s.operation(&bound(ReceiptOperation::Order))).unwrap();
    let mut absent = receipt(&intent);
    absent.returned_vendor = None;
    block_on(s.protected_operation_receipt(absent, protection(&["target"]))).unwrap();
    let p = json_receipt(&s);
    assert_eq!(p["receipt"]["relations"]["returned_vendor"], "absent");
    assert!(p["receipt"]["facts"].get("returned_vendor").is_none());
    assert!(s.dispatch.identity_exclusions("other").is_empty());
    block_on(s.associate(association("fixture", "received-literal"))).unwrap();
    assert_eq!(
        block_on(s.operation_receipt(receipt(&intent))).unwrap(),
        [intent.call]
    );
    let record = s.dispatch.receipts.last().unwrap();
    let projected = s
        .dispatch
        .project_receipt(
            record,
            protection(&["returned_vendor", "resource", "target"]),
        )
        .unwrap();
    assert_eq!(
        projected.value()["receipt"]["relations"]["returned_vendor"],
        "retained"
    );
    assert_eq!(projected.value()["settled"], json!([intent.call]));
    let evidence: StoredReceipt =
        serde_json::from_value(projected.value()["receipt"].clone()).unwrap();
    assert!(
        s.dispatch.validate_receipt(s.next, &evidence).is_err(),
        "a display-only returned omission cannot become canonical withheld presence"
    );
    assert!(s.dispatch.identity_exclusions("other").is_empty());
}

#[test]
fn stop_and_restart_need_no_returned_identity_and_missing_bindings_never_gain_relations() {
    for op in [ReceiptOperation::Stop, ReceiptOperation::Restart] {
        for presence in ["absent", "retained", "withheld"] {
            let (_, mut s, _) = fresh();
            let intent = block_on(s.operation(&bound(op))).unwrap();
            let mut raw = receipt(&intent);
            if presence == "absent" {
                raw.returned_vendor = None;
            }
            let p = if presence == "withheld" {
                protection(&["returned_vendor", "binding/account"])
            } else {
                protection(&["target"])
            };
            assert_eq!(
                block_on(s.protected_operation_receipt(raw, p)).unwrap(),
                [intent.call]
            );
            assert!(s.dispatch.identity_exclusions("other").is_empty());
            assert!(matches!(
                reopen(&s).unwrap().dispatch.typed_calls[&intent.call].state,
                CallState::ReceiptConfirmed { .. }
            ));
        }
    }
    let (_, mut s, _) = fresh();
    let i = block_on(s.operation(&request(Operation::Reset))).unwrap();
    let raw = Receipt {
        source: ReceiptSource::BrowserVendorTls,
        call: i.call,
        resource: i.resource.clone(),
        target: i.target.clone(),
        binding: ReceiptBinding {
            operation: ReceiptOperation::Restart,
            account: 41,
            signed_request: 73,
        },
        validated: true,
        returned_vendor: None,
    };
    assert!(
        block_on(s.protected_operation_receipt(
            raw,
            protection(&["binding/account", "binding/signed_request"])
        ))
        .unwrap()
        .is_empty()
    );
    let p = json_receipt(&s);
    for slot in ["operation", "account", "signed_request"] {
        assert_eq!(p["receipt"]["relations"][slot], "different");
    }
}

#[test]
fn retained_and_withheld_constituents_in_both_orders_preserve_historical_settlement() {
    for first in ["receipt", "association"] {
        for hidden in ["neither", "receipt", "association"] {
            let (_, mut s, _) = fresh();
            let i = block_on(s.operation(&bound(ReceiptOperation::Order))).unwrap();
            for step in [
                first,
                if first == "receipt" {
                    "association"
                } else {
                    "receipt"
                },
            ] {
                if step == "receipt" {
                    if hidden == "receipt" {
                        block_on(s.protected_operation_receipt(
                            receipt(&i),
                            protection(&["returned_vendor"]),
                        ))
                        .unwrap();
                    } else {
                        block_on(s.operation_receipt(receipt(&i))).unwrap();
                    }
                } else if hidden == "association" {
                    block_on(s.association_evidence(
                        association("fixture", "received-literal"),
                        protection(&["target"]),
                    ))
                    .unwrap();
                } else {
                    block_on(s.associate(association("fixture", "received-literal"))).unwrap();
                }
                s = reopen(&s).unwrap();
            }
            let confirmed = hidden == "neither";
            assert_eq!(
                s.dispatch.typed_calls[&i.call].state != CallState::Unresolved,
                confirmed,
                "{first}/{hidden}"
            );
            assert_eq!(
                s.dispatch.receipts[0].settled,
                if confirmed && first == "association" {
                    vec![i.call]
                } else {
                    vec![]
                },
                "historical vector never rewritten"
            );
            if hidden == "association" {
                assert_eq!(
                    s.dispatch
                        .resolve(&Target::VendorMachine("received-literal".into())),
                    None
                );
                block_on(s.associate(association("fixture", "received-literal"))).unwrap();
                assert!(matches!(
                    s.dispatch.typed_calls[&i.call].state,
                    CallState::ReceiptConfirmed {
                        association: Some(_),
                        ..
                    }
                ));
                assert!(s.dispatch.receipts[0].settled.is_empty());
            }
        }
    }
}

#[test]
fn permanent_all_record_exclusion_and_quarantine_conflicts_do_not_revoke_existing_mappings() {
    let (_, mut s, _) = fresh();
    let i = block_on(s.operation(&bound(ReceiptOperation::Order))).unwrap();
    let first = s.next;
    block_on(s.protected_operation_receipt(receipt(&i), protection(&["returned_vendor"]))).unwrap();
    let second = s.next;
    block_on(s.association_evidence(association("fixture", "unknown-2"), protection(&["target"])))
        .unwrap();
    block_on(s.dispose(Disposition {
        machine: "fixture".into(),
        calls: vec![i.call],
        continuation: Continuation::AsIfDone,
        uncertainty: "unknown".into(),
    }))
    .unwrap();
    block_on(s.associate(association("fixture", "safe-recovery"))).unwrap();
    assert_eq!(s.dispatch.identity_exclusions("other"), [first, second]);
    let mut excluded = bound(ReceiptOperation::Order);
    excluded.target = Target::Entry("other".into());
    let a = excluded.approved.as_mut().unwrap();
    a.target = excluded.target.clone();
    a.resource = Resource::Entry("other".into());
    let before = s.storage.files();
    assert!(
        matches!(block_on(s.operation(&excluded)),Err(OperationError::Policy(RequestRefusal::IdentityExclusion {records})) if records==[first,second])
    );
    assert_eq!(before, s.storage.files(), "refused before intent or send");
    for _ in 0..2 {
        block_on(s.associate(association("other", "quarantined-literal"))).unwrap();
    }
    assert_eq!(
        s.dispatch
            .association_records
            .iter()
            .filter(|a| !a.association.admitted())
            .count(),
        3
    );
    assert_eq!(
        s.dispatch
            .resolve(&Target::VendorMachine("quarantined-literal".into())),
        None
    );
    assert_eq!(
        block_on(s.associate(association("fixture", "quarantined-literal"))).unwrap_err(),
        "identity_conflict"
    );
    let before = s.records();
    block_on(s.association_evidence(
        association("fixture", "vendor-7"),
        protection(&["target", "entry"]),
    ))
    .unwrap();
    assert_eq!(
        before,
        s.records(),
        "genuine same-map duplicate before omission"
    );
    assert_eq!(
        block_on(s.association_evidence(association("other", "vendor-7"), protection(&["target"])))
            .unwrap_err(),
        "target already associated"
    );
    assert_eq!(
        s.dispatch
            .resolve(&Target::VendorMachine("vendor-7".into())),
        Some(Resource::Entry("fixture".into()))
    );
    s = reopen(&s).unwrap();
    assert_eq!(s.dispatch.identity_exclusions("other"), [first, second]);
    assert!(s.dispatch.standing.contains_key("fixture"));
    assert!(
        s.dispatch
            .check_operation(
                &Resource::Entry("other".into()),
                Operation::Read,
                Requester::Session
            )
            .is_ok()
    );
    assert!(
        s.dispatch
            .check_operation(
                &Resource::Entry("fixture".into()),
                Operation::Reset,
                Requester::Session
            )
            .is_ok()
    );
    let raw = Event::Association(association("fixture", "another-retained").into());
    block_on(s.commit(&raw)).unwrap();
    assert!(
        reopen(&s)
            .err()
            .unwrap()
            .contains("raw VendorMachine association after identity risk")
    );
}

#[test]
fn every_wrong_correlation_and_source_stays_visible_without_excluding_another_entry() {
    for wrong in [
        "call",
        "resource",
        "target",
        "operation",
        "account",
        "signed_request",
        "validated",
        "arbitrary",
        "job",
        "notify",
        "proposed",
    ] {
        let (_, mut s, _) = fresh();
        let i = block_on(s.operation(&bound(ReceiptOperation::Order))).unwrap();
        let mut raw = receipt(&i);
        match wrong {
            "call" => raw.call += 1000,
            "resource" => raw.resource = Resource::Entry("other".into()),
            "target" => raw.target = Target::VendorMachine("wrong".into()),
            "operation" => raw.binding.operation = ReceiptOperation::Restart,
            "account" => raw.binding.account += 1,
            "signed_request" => raw.binding.signed_request += 1,
            "validated" => raw.validated = false,
            "arbitrary" => raw.source = ReceiptSource::ArbitraryResponse,
            "job" => raw.source = ReceiptSource::JobOutput,
            "notify" => raw.source = ReceiptSource::NotifyEvent,
            "proposed" => raw.source = ReceiptSource::ProposedText,
            _ => unreachable!(),
        }
        let slots = match wrong {
            "call" => vec!["call", "returned_vendor"],
            "resource" => vec!["resource", "returned_vendor"],
            "target" => vec!["target", "returned_vendor"],
            "account" => vec!["binding/account", "returned_vendor"],
            "signed_request" => vec!["binding/signed_request", "returned_vendor"],
            _ => vec!["returned_vendor"],
        };
        assert!(
            block_on(s.protected_operation_receipt(raw, protection(&slots)))
                .unwrap()
                .is_empty()
        );
        s = reopen(&s).unwrap();
        assert!(
            s.dispatch.identity_exclusions("other").is_empty(),
            "{wrong}"
        );
        block_on(s.associate(association("other", "other-safe"))).unwrap();
        block_on(s.associate(association("fixture", "received-literal"))).unwrap();
        assert_eq!(
            block_on(s.operation_receipt(receipt(&i))).unwrap(),
            [i.call],
            "{wrong}: eligible neighbor"
        );
    }
}

#[test]
fn qualifying_retained_receipts_block_cross_entry_adoption_even_without_a_mapping() {
    let (_, mut s, _) = fresh();
    let i = block_on(s.operation(&bound(ReceiptOperation::Order))).unwrap();
    block_on(s.protected_operation_receipt(receipt(&i), protection(&["target", "resource"])))
        .unwrap();
    let before = s.storage.files();
    assert_eq!(
        block_on(s.associate(association("other", "received-literal"))).unwrap_err(),
        "identity_conflict"
    );
    assert_eq!(before, s.storage.files());
    block_on(s.associate(association("fixture", "received-literal"))).unwrap();
    assert!(matches!(
        s.dispatch.typed_calls[&i.call].state,
        CallState::ReceiptConfirmed { .. }
    ));
}

#[test]
fn protected_append_failures_have_no_live_apply_and_landed_evidence_replays_exactly_once() {
    for owner in ["receipt", "association"] {
        for fault in [
            Fault::Fail(1),
            Fault::Fail(2),
            Fault::Fail(3),
            Fault::LandThenFail(3),
        ] {
            let (_, mut s, _) = fresh();
            let i = block_on(s.operation(&bound(ReceiptOperation::Order))).unwrap();
            let before = s.dispatch.clone();
            s.storage.fault(fault);
            let result = if owner == "receipt" {
                block_on(
                    s.protected_operation_receipt(receipt(&i), protection(&["returned_vendor"])),
                )
                .map(|_| ())
            } else {
                block_on(s.association_evidence(
                    association("fixture", "received-literal"),
                    protection(&["target"]),
                ))
            };
            let why = result.unwrap_err();
            assert!(
                why.contains(if matches!(fault, Fault::LandThenFail(_)) {
                    "landed, then reported failure"
                } else {
                    "made to fail"
                }),
                "{owner}: {why}"
            );
            assert_eq!(s.dispatch.receipts, before.receipts);
            assert_eq!(s.dispatch.association_records, before.association_records);
            assert_eq!(s.dispatch.associations, before.associations);
            let diagnostic = serde_json::to_value(s.uncommitted_evidence().unwrap()).unwrap();
            assert_eq!(diagnostic.as_object().unwrap().len(), 2);
            assert_eq!(diagnostic["committed"], false);
            assert!(diagnostic.get(owner).is_some());
            assert!(!diagnostic.to_string().contains("received-literal"));
            assert!(
                block_on(s.associate(association("fixture", "fresh-id")))
                    .unwrap_err()
                    .contains("earlier append failed")
            );
            let files = s.storage.files();
            let reopened = reopen(&s).unwrap();
            assert_eq!(reopened.storage.files(), files);
            let landed = matches!(fault, Fault::LandThenFail(_));
            assert_eq!(reopened.dispatch.has_identity_risk(), landed);
            assert_eq!(
                reopened.dispatch.typed_calls[&i.call].state,
                CallState::Unresolved
            );
            let twice = reopen(&reopened).unwrap();
            assert_eq!(twice.dispatch.receipts, reopened.dispatch.receipts);
            assert_eq!(
                twice.dispatch.association_records,
                reopened.dispatch.association_records
            );
            assert!(twice.uncommitted_evidence().is_none());
        }
    }
}

#[test]
fn raw_and_stored_decoders_are_closed_and_protected_causality_is_checked_on_replay() {
    let (_, mut s, _) = fresh();
    let i = block_on(s.operation(&bound(ReceiptOperation::Order))).unwrap();
    let raw = receipt(&i);
    let value = serde_json::to_value(&raw).unwrap();
    for bad in [
        json!([]),
        json!(["browser_vendor_tls",i.call,{"entry":"fixture"},{"entry":"fixture"},{"operation":"order","account":41,"signed_request":73},true,null]),
        {
            let mut v = value.clone();
            v.as_object_mut().unwrap().remove("returned_vendor");
            v
        },
        {
            let mut v = value.clone();
            v["returned_withheld"] = json!(true);
            v
        },
        {
            let mut v = value.clone();
            v["binding"] = json!(["order", 41, 73]);
            v
        },
    ] {
        assert!(serde_json::from_value::<Receipt>(bad).is_err());
    }
    let duplicate = format!(
        "{{\"call\":{},\"call\":{},\"source\":\"browser_vendor_tls\",\"resource\":{{\"entry\":\"fixture\"}},\"target\":{{\"entry\":\"fixture\"}},\"binding\":{{\"operation\":\"order\",\"account\":41,\"signed_request\":73}},\"validated\":true,\"returned_vendor\":null}}",
        i.call, i.call
    );
    assert!(serde_json::from_str::<Receipt>(&duplicate).is_err());
    assert!(serde_json::from_str::<StoredReceipt>(&duplicate).is_err());
    let good = s
        .dispatch
        .protect_receipt(
            s.next,
            raw,
            protection(&["returned_vendor", "binding/account"]),
        )
        .unwrap();
    let original = serde_json::to_value(&good).unwrap();
    for (pointer, bad) in [
        ("/version", json!(2)),
        ("/relations/call", json!("different")),
        ("/relations/intent/call", json!(s.next + 1)),
        ("/relations/resource", json!("different")),
        ("/facts/binding/account", json!(41)),
        ("/facts/returned_vendor", Value::Null),
        ("/withheld/0/slot", json!("unknown")),
        ("/custody/substitutions", json!([{}])),
        ("/custody/names/0/ordinal", json!(2)),
        ("/withheld/0/marker", json!("[withheld:wrong]")),
    ] {
        let mut v = original.clone();
        let parts = pointer.rsplit_once('/').unwrap();
        if let Some(dst) = v.pointer_mut(pointer) {
            *dst = bad;
        } else {
            v.pointer_mut(parts.0)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(parts.1.into(), bad);
        }
        match serde_json::from_value::<StoredReceipt>(v) {
            Err(_) => {}
            Ok(e) => assert!(
                s.dispatch.validate_receipt(s.next, &e).is_err(),
                "{pointer}"
            ),
        }
    }
    let assoc = s
        .dispatch
        .protect_association(
            s.next,
            association("fixture", "hidden"),
            protection(&["target", "entry"]),
        )
        .unwrap()
        .unwrap();
    let original = serde_json::to_value(assoc).unwrap();
    for (pointer, bad) in [
        ("/relations/approved_entry/setup", json!(s.next)),
        ("/relations/approved_entry/index", json!(u32::MAX)),
        ("/relations/target_kind", json!("allocation_index")),
        ("/relations/admission", json!("mapped")),
        ("/relations/reason", json!("none")),
        (
            "/relations/alias_checks",
            json!([{"record":0,"result":"unavailable"}]),
        ),
    ] {
        let mut v = original.clone();
        *v.pointer_mut(pointer).unwrap() = bad;
        let e: StoredAssociation = serde_json::from_value(v).unwrap();
        assert!(
            s.dispatch.validate_association(s.next, &e).is_err(),
            "{pointer}"
        );
    }
    let mut bad = serde_json::to_value(&good).unwrap();
    bad["relations"]["resource"] = json!("different");
    let event: Event = serde_json::from_value(json!({"operation_receipt":bad})).unwrap();
    let number = block_on(s.commit(&event)).unwrap();
    let why = reopen(&s).err().unwrap();
    assert!(why.contains(&format!("record {number}")) && why.contains("contradicts relation"));
}

#[test]
fn protected_associations_reference_actual_setup_index_and_legacy_allocation_projection_stays_read_only()
 {
    let (_, mut s, extra) = fresh();
    let number = s.next;
    block_on(s.association_evidence(association("other", "other-id"), protection(&["entry"])))
        .unwrap();
    let a = &s.dispatch.association_records.last().unwrap().association;
    let StoredAssociation::Protected(p) = a else {
        panic!("protected")
    };
    assert_eq!(
        p.relations.approved_entry.setup,
        s.dispatch.setup_approval.unwrap()
    );
    assert_eq!(
        p.relations.approved_entry.index,
        s.dispatch.approved_entries["other"].approved.identity.index
    );
    assert!(p.relations.approved_entry.setup < number);
    assert!(p.facts.entry.is_none());
    assert_eq!(
        s.dispatch
            .resolve(&Target::VendorMachine("other-id".into())),
        Some(Resource::Entry("other".into()))
    );
    let allocation = s
        .dispatch
        .association_records
        .iter()
        .find(|a| a.association.target() == Some(&Target::AllocationIndex(extra)))
        .unwrap();
    let projection = s
        .dispatch
        .project_association(allocation, protection(&["target", "entry"]))
        .unwrap();
    assert_eq!(
        projection.value()["association"]["relations"]["admission"],
        "mapped"
    );
    let evidence: StoredAssociation =
        serde_json::from_value(projection.value()["association"].clone()).unwrap();
    assert!(s.dispatch.validate_association(s.next, &evidence).is_err());
    let files = s.storage.files();
    let again = reopen(&s).unwrap();
    assert_eq!(again.storage.files(), files);
    assert_eq!(again.dispatch.associations, s.dispatch.associations);
}

#[test]
fn typed_call_and_barrier_displays_keep_binding_presence_and_canonical_authority() {
    for binding in [false, true] {
        let (_, mut s, _) = fresh();
        let r = if binding {
            bound(ReceiptOperation::Restart)
        } else {
            request(Operation::Reset)
        };
        let i = block_on(s.operation(&r)).unwrap();
        let canonical = s.dispatch.typed_calls[&i.call].clone();
        for slot in [
            "resource",
            "target",
            "receipt_binding/account",
            "receipt_binding/signed_request",
            "approved/resource",
            "approved/target",
            "approved/receipt_binding/account",
            "approved/receipt_binding/signed_request",
        ] {
            let p = s
                .dispatch
                .project_typed_call(&canonical, protection(&[slot]));
            let barrier = s.dispatch.project_operation_intent(&i, protection(&[slot]));
            if slot.contains("receipt_binding/") && !binding {
                assert!(p.is_err() && barrier.is_err());
            } else {
                let p = p.unwrap();
                assert!(p.value().pointer(&format!("/{slot}")).is_none());
                assert_eq!(p.value()["call"], i.call);
                assert_eq!(p.value()["state"], "unresolved");
                assert!(
                    barrier
                        .unwrap()
                        .value()
                        .pointer(&format!("/{slot}"))
                        .is_none()
                );
            }
            assert_eq!(s.dispatch.typed_calls[&i.call], canonical);
        }
    }
}

#[test]
fn legacy_duplicate_is_read_without_resealing_and_live_duplicate_does_not_append() {
    let (_, mut s, _) = fresh();
    let raw = association("fixture", "legacy-duplicate");
    block_on(s.associate(raw.clone())).unwrap();
    let before = s.storage.files();
    let records = s.dispatch.association_records.clone();
    block_on(s.associate(raw.clone())).unwrap();
    assert_eq!(s.storage.files(), before);
    assert_eq!(s.dispatch.association_records, records);
    let event = Event::Association(raw.into());
    let encoded = serde_json::to_value(&event).unwrap();
    assert_eq!(
        encoded,
        json!({"association":{"target":{"vendor_machine":"legacy-duplicate"},"entry":"fixture"}})
    );
    block_on(s.commit(&event)).unwrap();
    let bytes = s.storage.files();
    let r = reopen(&s).unwrap();
    assert_eq!(r.dispatch.association_records, records);
    assert_eq!(r.storage.files(), bytes);
}

#[test]
fn retained_quarantine_never_settles_or_enters_a_disposition_constituent() {
    let (_, mut s, _) = fresh();
    let i = block_on(s.operation(&bound(ReceiptOperation::Order))).unwrap();
    let mut other = bound(ReceiptOperation::Order);
    other.target = Target::Entry("other".into());
    let a = other.approved.as_mut().unwrap();
    a.target = other.target.clone();
    a.resource = Resource::Entry("other".into());
    let j = block_on(s.operation(&other)).unwrap();
    block_on(s.protected_operation_receipt(receipt(&i), protection(&["returned_vendor"]))).unwrap();
    block_on(s.associate(association("other", "received-literal"))).unwrap();
    assert!(
        block_on(s.operation_receipt(receipt(&j)))
            .unwrap()
            .is_empty(),
        "retained quarantine is never a receipt constituent"
    );
    assert_eq!(
        s.dispatch
            .resolve(&Target::VendorMachine("received-literal".into())),
        None
    );
    assert_eq!(s.dispatch.typed_calls[&j.call].state, CallState::Unresolved);
    s = reopen(&s).unwrap();
    assert_eq!(s.dispatch.typed_calls[&j.call].state, CallState::Unresolved);
    let d = Disposition {
        machine: "other".into(),
        calls: vec![j.call],
        continuation: Continuation::AsIfNotDone,
        uncertainty: "unknown".into(),
    };
    assert!(matches!(
        block_on(s.dispose(d)).unwrap(),
        DispositionReport::Accepted { .. }
    ));
    let report = serde_json::to_value(&s.dispatch.dispositions).unwrap();
    assert!(!report.to_string().contains("receipt_confirmed"));
}

#[test]
fn every_quarantine_has_exactly_all_earlier_risks_and_no_future_or_irrelevant_alias() {
    let (_, mut s, _) = fresh();
    let i = block_on(s.operation(&bound(ReceiptOperation::Order))).unwrap();
    let first = s.next;
    block_on(s.protected_operation_receipt(receipt(&i), protection(&["returned_vendor"]))).unwrap();
    let second = s.next;
    block_on(s.association_evidence(association("fixture", "hidden"), protection(&["target"])))
        .unwrap();
    for hidden in [false, true] {
        let evidence = s
            .dispatch
            .protect_association(
                s.next,
                association("other", "candidate"),
                if hidden {
                    protection(&["target"])
                } else {
                    EvidenceProtection::default()
                },
            )
            .unwrap()
            .unwrap();
        let v = serde_json::to_value(evidence).unwrap();
        assert_eq!(
            v["relations"]["alias_checks"],
            json!([{"record":first,"result":"unavailable"},{"record":second,"result":"unavailable"}])
        );
        for records in [
            vec![],
            vec![first],
            vec![second, first],
            vec![first, first, second],
            vec![first, second, s.next],
            vec![0, first, second],
        ] {
            let mut bad = v.clone();
            bad["relations"]["alias_checks"] = json!(
                records
                    .iter()
                    .map(|n| json!({"record":n,"result":"unavailable"}))
                    .collect::<Vec<_>>()
            );
            let parsed: StoredAssociation = serde_json::from_value(bad).unwrap();
            assert!(
                s.dispatch.validate_association(s.next, &parsed).is_err(),
                "{records:?}"
            );
        }
        let parsed: StoredAssociation = serde_json::from_value(v).unwrap();
        assert!(s.dispatch.validate_association(s.next, &parsed).is_ok());
    }
}

fn unavailable_name(
    association: NameAssociation,
    ordinal: u64,
    associations: Vec<NameAssociation>,
    marker: &str,
) -> NameRow {
    NameRow {
        association,
        ordinal,
        name: None,
        name_withheld: Some(WithheldFact {
            slot: "name".into(),
            marker: marker.into(),
            associations,
        }),
    }
}

fn unregistered_custody() -> EvidenceCustody {
    // Synthetic lease identity chosen independently of every raw evidence operand.
    serde_json::from_value(json!({
        "version":1,"substitutions":[],"names":[{
            "association":{"kind":"unregistered","id":"91".repeat(24)},
            "ordinal":1,"name":"unregistered input"
        }]
    }))
    .unwrap()
}

fn unregistered_protection(slot: &str) -> EvidenceProtection {
    let custody = unregistered_custody();
    EvidenceProtection::from_custody(
        vec![WithheldFact {
            slot: slot.into(),
            marker: "[withheld:unregistered input]".into(),
            associations: vec![custody.names[0].association.clone()],
        }],
        custody,
    )
    .unwrap()
}

#[test]
fn unregistered_receipt_copied_name_withholding_preserves_stored_label_and_settlement() {
    let (_, mut s, _) = fresh();
    let intent = block_on(s.operation(&bound(ReceiptOperation::Order))).unwrap();
    block_on(s.associate(association("fixture", "received-literal"))).unwrap();
    block_on(s.protected_operation_receipt(receipt(&intent), unregistered_protection("target")))
        .unwrap();
    let record = s.dispatch.receipts.last().unwrap();
    let canonical = serde_json::to_vec(record).unwrap();
    let stored_bytes = s.storage.files();
    let StoredReceipt::Protected(p) = &record.receipt else {
        panic!("protected receipt")
    };
    // Positive neighbors must pass before applying the copied-name obligation.
    s.dispatch
        .validate_receipt(record.number, &record.receipt)
        .unwrap();
    assert_eq!(record.settled, [intent.call]);
    assert_eq!(p.custody, Some(unregistered_custody()));
    let unchanged = s
        .dispatch
        .project_receipt(record, EvidenceProtection::default())
        .unwrap();
    assert_eq!(unchanged.value()["receipt"]["custody"], json!(p.custody));

    let mut custody = unregistered_custody();
    let a = custody.names[0].association.clone();
    custody.names[0] = unavailable_name(a.clone(), 1, vec![a.clone()], "[withheld:#1]");
    let mut invalid = custody.clone();
    invalid.names[0].name_withheld.as_mut().unwrap().marker =
        "[withheld:unregistered input]".into();
    assert!(EvidenceProtection::from_custody(vec![], invalid).is_err());
    let mut invalid = custody.clone();
    invalid.names[0].name = Some("unregistered input".into());
    assert!(EvidenceProtection::from_custody(vec![], invalid).is_err());
    let operand = EvidenceProtection::from_custody(vec![], custody.clone())
        .expect("valid unregistered copied-name obligation");
    let projected = s
        .dispatch
        .project_receipt(record, operand.clone())
        .expect("valid unregistered copied-name projection");
    let v = projected.value();
    assert_eq!(
        v["receipt"]["custody"]["names"],
        json!([{
            "association":a,"ordinal":1,
            "name_withheld":{"slot":"name","marker":"[withheld:#1]","associations":[a]}
        }])
    );
    assert_eq!(
        v["receipt"]["withheld"],
        json!([{
            "slot":"target","marker":"[withheld:#1]","associations":[a]
        }])
    );
    assert_eq!(v["receipt"]["facts"], json!(p.facts));
    assert_eq!(v["receipt"]["relations"], json!(p.relations));
    assert_eq!(v["number"], record.number);
    assert_eq!(v["settled"], json!([intent.call]));
    let copied = ReceiptRecord {
        number: record.number,
        receipt: serde_json::from_value(v["receipt"].clone()).unwrap(),
        settled: record.settled.clone(),
    };
    assert_eq!(
        s.dispatch
            .project_receipt(&copied, operand.clone())
            .unwrap()
            .value(),
        v
    );
    assert!(
        s.dispatch
            .project_receipt(
                &copied,
                EvidenceProtection::from_custody(vec![], unregistered_custody()).unwrap()
            )
            .is_err()
    );

    // Projection shape parsing grants no new stored authority, at construction or replay.
    assert_eq!(
        s.dispatch
            .validate_receipt(record.number, &copied.receipt)
            .unwrap_err(),
        "unregistered name"
    );
    assert_eq!(
        s.dispatch
            .protect_receipt(s.next, receipt(&intent), operand)
            .unwrap_err(),
        "unregistered name"
    );
    let mut wrong = unregistered_custody();
    wrong.names[0].name = Some("different retained name".into());
    assert!(EvidenceProtection::from_custody(vec![], wrong.clone()).is_err());
    let mut bad = serde_json::to_value(&record.receipt).unwrap();
    bad["custody"] = json!(wrong);
    let bad: StoredReceipt = serde_json::from_value(bad).unwrap();
    assert_eq!(
        s.dispatch
            .validate_receipt(record.number, &bad)
            .unwrap_err(),
        "unregistered name"
    );
    assert_eq!(serde_json::to_vec(record).unwrap(), canonical);
    assert_eq!(s.storage.files(), stored_bytes);
    assert_eq!(
        serde_json::to_vec(reopen(&s).unwrap().dispatch.receipts.last().unwrap()).unwrap(),
        canonical
    );
    assert!(s.dispatch.identity_exclusions("other").is_empty());
}

#[test]
fn unregistered_association_copied_name_preserves_admission_and_alias_checks() {
    let (_, mut s, _) = fresh();
    let intent = block_on(s.operation(&bound(ReceiptOperation::Order))).unwrap();
    block_on(s.protected_operation_receipt(receipt(&intent), protection(&["returned_vendor"])))
        .unwrap();
    let risk = s.dispatch.receipts.last().unwrap().number;
    block_on(s.association_evidence(
        association("other", "candidate"),
        unregistered_protection("entry"),
    ))
    .unwrap();
    let record = s.dispatch.association_records.last().unwrap();
    let canonical = serde_json::to_vec(record).unwrap();
    let stored_bytes = s.storage.files();
    s.dispatch
        .validate_association(record.number, &record.association)
        .unwrap();
    let unchanged = s
        .dispatch
        .project_association(record, EvidenceProtection::default())
        .unwrap();
    assert_eq!(
        unchanged.value()["association"]["custody"],
        json!(unregistered_custody())
    );
    assert_eq!(
        unchanged.value()["association"]["relations"]["admission"],
        "quarantined"
    );
    assert_eq!(
        unchanged.value()["association"]["relations"]["alias_checks"],
        json!([{"record":risk,"result":"unavailable"}])
    );
    let mut custody = unregistered_custody();
    let a = custody.names[0].association.clone();
    custody.names[0] = unavailable_name(a.clone(), 1, vec![a], "[withheld:#1]");
    let operand = EvidenceProtection::from_custody(vec![], custody.clone()).unwrap();
    let projected = s
        .dispatch
        .project_association(record, operand.clone())
        .unwrap();
    let v = projected.value();
    assert_eq!(v["association"]["custody"], json!(custody));
    assert_eq!(
        v["association"]["facts"],
        unchanged.value()["association"]["facts"]
    );
    assert_eq!(
        v["association"]["facts"]["target"],
        json!({"vendor_machine":"candidate"})
    );
    assert_eq!(
        v["association"]["relations"],
        unchanged.value()["association"]["relations"]
    );
    assert_eq!(v["number"], record.number);
    let copied = AssociationRecord {
        number: record.number,
        association: serde_json::from_value(v["association"].clone()).unwrap(),
    };
    assert_eq!(
        s.dispatch
            .project_association(&copied, operand.clone())
            .unwrap()
            .value(),
        v
    );
    assert!(
        s.dispatch
            .project_association(
                &copied,
                EvidenceProtection::from_custody(vec![], unregistered_custody()).unwrap()
            )
            .is_err()
    );
    assert_eq!(
        s.dispatch
            .validate_association(record.number, &copied.association)
            .unwrap_err(),
        "unregistered name"
    );
    assert_eq!(
        s.dispatch
            .protect_association(s.next, association("other", "candidate"), operand)
            .unwrap_err(),
        "unregistered name"
    );
    assert_eq!(serde_json::to_vec(record).unwrap(), canonical);
    assert_eq!(s.storage.files(), stored_bytes);
    assert_eq!(
        serde_json::to_vec(
            reopen(&s)
                .unwrap()
                .dispatch
                .association_records
                .last()
                .unwrap()
        )
        .unwrap(),
        canonical
    );
    assert!(
        s.dispatch
            .resolve(&Target::VendorMachine("candidate".into()))
            .is_none()
    );
}

#[test]
fn unregistered_projection_union_reindexes_names_and_keeps_useful_neighbors() {
    let (_, mut s, _) = fresh();
    let intent = block_on(s.operation(&bound(ReceiptOperation::Order))).unwrap();
    block_on(s.associate(association("fixture", "received-literal"))).unwrap();
    let mut custody = unregistered_custody();
    let a = custody.names[0].association.clone();
    let b = NameAssociation::Transient {
        id: "92".repeat(24),
    };
    custody.names[0].ordinal = 2;
    custody.names.insert(
        0,
        NameRow {
            association: b.clone(),
            ordinal: 1,
            name: Some("retained neighbor".into()),
            name_withheld: None,
        },
    );
    let first = EvidenceProtection::from_custody(
        vec![WithheldFact {
            slot: "target".into(),
            marker: "[withheld:#2]".into(),
            associations: vec![a.clone()],
        }],
        custody,
    )
    .unwrap();
    block_on(s.protected_operation_receipt(receipt(&intent), first)).unwrap();
    let record = s.dispatch.receipts.last().unwrap();
    let canonical = serde_json::to_vec(record).unwrap();
    s.dispatch
        .validate_receipt(record.number, &record.receipt)
        .unwrap();
    s.dispatch
        .project_receipt(record, EvidenceProtection::default())
        .unwrap();
    let c = NameAssociation::Transient {
        id: "93".repeat(24),
    };
    let operand = EvidenceProtection::from_custody(
        vec![WithheldFact {
            slot: "target".into(),
            marker: "[withheld:#1,#2]".into(),
            associations: vec![a.clone(), c.clone()],
        }],
        EvidenceCustody {
            version: 1,
            substitutions: vec![],
            names: vec![
                unavailable_name(a.clone(), 1, vec![a.clone(), c.clone()], "[withheld:#1,#2]"),
                NameRow {
                    association: c.clone(),
                    ordinal: 2,
                    name: Some("incoming neighbor".into()),
                    name_withheld: None,
                },
            ],
        },
    )
    .unwrap();
    let projected = s.dispatch.project_receipt(record, operand.clone()).unwrap();
    let v = projected.value();
    assert_eq!(
        v["receipt"]["custody"]["names"],
        json!([
            {"association":b,"ordinal":1,"name":"retained neighbor"},
            {"association":a,"ordinal":2,"name_withheld":{
                "slot":"name","marker":"[withheld:#2,#3]","associations":[a,c]}},
            {"association":c,"ordinal":3,"name":"incoming neighbor"}
        ])
    );
    assert_eq!(
        v["receipt"]["withheld"],
        json!([{
            "slot":"target","marker":"[withheld:#2,#3]","associations":[a,c]
        }])
    );
    assert_eq!(v["receipt"]["facts"]["returned_vendor"], "received-literal");
    assert_eq!(v["receipt"]["facts"]["binding"]["account"], 41);
    assert_eq!(v["settled"], json!([intent.call]));
    let copied = ReceiptRecord {
        number: record.number,
        receipt: serde_json::from_value(v["receipt"].clone()).unwrap(),
        settled: record.settled.clone(),
    };
    assert_eq!(
        s.dispatch
            .project_receipt(&copied, operand)
            .unwrap()
            .value(),
        v
    );
    assert_eq!(serde_json::to_vec(record).unwrap(), canonical);
    assert_eq!(
        serde_json::to_vec(reopen(&s).unwrap().dispatch.receipts.last().unwrap()).unwrap(),
        canonical
    );
}

#[test]
fn projection_withholds_copied_name_without_changing_canonical_custody_or_history() {
    let (_, mut s, _) = fresh();
    let intent = block_on(s.operation(&bound(ReceiptOperation::Order))).unwrap();
    block_on(s.associate(association("fixture", "received-literal"))).unwrap();
    block_on(s.protected_operation_receipt(receipt(&intent), protection(&["target"]))).unwrap();
    let record = s.dispatch.receipts.last().unwrap();
    assert_eq!(record.settled, [intent.call]);
    let canonical = serde_json::to_vec(record).unwrap();
    let StoredReceipt::Protected(p) = &record.receipt else {
        panic!("protected receipt")
    };
    let mut custody = p.custody.clone().unwrap();
    let a = custody.names[0].association.clone();
    custody.names[0] = unavailable_name(a.clone(), 1, vec![a], "[withheld:#1]");
    let operand = EvidenceProtection::from_custody(vec![], custody).unwrap();
    let projected = s.dispatch.project_receipt(record, operand.clone()).unwrap();
    let v = projected.value();
    assert_eq!(
        v["receipt"]["custody"]["names"][0]["name_withheld"]["marker"],
        "[withheld:#1]"
    );
    assert!(v["receipt"]["custody"]["names"][0].get("name").is_none());
    assert_eq!(v["receipt"]["withheld"][0]["marker"], "[withheld:#1]");
    assert_eq!(
        v["receipt"]["relations"],
        serde_json::to_value(&p.relations).unwrap()
    );
    assert_eq!(v["receipt"]["facts"]["returned_vendor"], "received-literal");
    assert_eq!(v["receipt"]["facts"]["binding"]["account"], 41);
    assert_eq!(v["number"], record.number);
    assert_eq!(v["settled"], json!([intent.call]));
    let projected_record = ReceiptRecord {
        number: record.number,
        receipt: StoredReceipt::Protected(serde_json::from_value(v["receipt"].clone()).unwrap()),
        settled: record.settled.clone(),
    };
    assert_eq!(
        s.dispatch
            .project_receipt(&projected_record, operand)
            .unwrap()
            .value(),
        v
    );
    let restore = EvidenceProtection::from_custody(vec![], p.custody.clone().unwrap()).unwrap();
    assert!(
        s.dispatch
            .project_receipt(&projected_record, restore)
            .is_err()
    );
    let mut wrong = p.custody.clone().unwrap();
    wrong.names[0].name = Some("different name".into());
    assert!(
        s.dispatch
            .project_receipt(
                record,
                EvidenceProtection::from_custody(vec![], wrong).unwrap()
            )
            .is_err()
    );
    assert_eq!(serde_json::to_vec(record).unwrap(), canonical);
    assert_eq!(
        serde_json::to_vec(reopen(&s).unwrap().dispatch.receipts.last().unwrap()).unwrap(),
        canonical
    );
}

#[test]
fn projection_union_reindexes_unavailable_names_and_multi_association_markers() {
    for indexed in [false, true] {
        let (_, mut s, _) = fresh();
        let intent = block_on(s.operation(&bound(ReceiptOperation::Order))).unwrap();
        let mut first = protection(&["target"]);
        if indexed {
            let a = NameAssociation::Transient {
                id: "ef".repeat(24),
            };
            let c = EvidenceCustody {
                version: 1,
                substitutions: vec![],
                names: vec![unavailable_name(a.clone(), 1, vec![a], "[withheld:#1]")],
            };
            first = EvidenceProtection::from_custody(
                vec![WithheldFact {
                    slot: "target".into(),
                    marker: "[withheld:#1]".into(),
                    associations: vec![c.names[0].association.clone()],
                }],
                c,
            )
            .unwrap();
        }
        block_on(s.protected_operation_receipt(receipt(&intent), first)).unwrap();
        let record = s.dispatch.receipts.last().unwrap();
        let canonical = serde_json::to_vec(record).unwrap();
        let b = NameAssociation::Transient {
            id: "ab".repeat(24),
        };
        let c = NameAssociation::Transient {
            id: "cd".repeat(24),
        };
        let operand = EvidenceProtection::from_custody(
            vec![WithheldFact {
                slot: "resource".into(),
                marker: "[withheld:#1,#2]".into(),
                associations: vec![b.clone(), c.clone()],
            }],
            EvidenceCustody {
                version: 1,
                substitutions: vec![],
                names: vec![
                    unavailable_name(b.clone(), 1, vec![b.clone(), c.clone()], "[withheld:#1,#2]"),
                    unavailable_name(c.clone(), 2, vec![b.clone()], "[withheld:#1]"),
                ],
            },
        )
        .unwrap();
        let projected = s.dispatch.project_receipt(record, operand.clone()).unwrap();
        let v = projected.value();
        let names = &v["receipt"]["custody"]["names"];
        assert_eq!(names[1]["association"], json!(b));
        assert_eq!(names[1]["ordinal"], 2);
        assert_eq!(names[1]["name_withheld"]["marker"], "[withheld:#2,#3]");
        assert_eq!(names[2]["association"], json!(c));
        assert_eq!(names[2]["name_withheld"]["marker"], "[withheld:#2]");
        assert_eq!(v["receipt"]["withheld"][0]["slot"], "resource");
        assert_eq!(v["receipt"]["withheld"][0]["marker"], "[withheld:#2,#3]");
        assert_eq!(v["receipt"]["withheld"][1]["marker"], "[withheld:#1]");
        assert_eq!(v["receipt"]["facts"]["returned_vendor"], "received-literal");
        assert_eq!(v["receipt"]["facts"]["call"], intent.call);
        let projected_record = ReceiptRecord {
            number: record.number,
            receipt: StoredReceipt::Protected(
                serde_json::from_value(v["receipt"].clone()).unwrap(),
            ),
            settled: record.settled.clone(),
        };
        assert_eq!(
            s.dispatch
                .project_receipt(&projected_record, operand)
                .unwrap()
                .value(),
            v
        );
        assert_eq!(serde_json::to_vec(record).unwrap(), canonical);
    }
}
