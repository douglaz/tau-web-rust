use super::*;

pub(super) fn unchanged(
    s: &Store<MemoryStorage>,
    files: &BTreeMap<String, Vec<u8>>,
    next: u64,
    previous: [u8; 32],
) {
    assert_eq!(&s.storage.files(), files);
    assert_eq!(s.next, next);
    assert_eq!(s.previous.0, previous);
    assert!(s.failed.is_none());
}

#[test]
fn poc_journal_goal_literal_boundary_and_escape_tail_are_atomic() {
    for tail in [false, true] {
        let mut s = crate::store::inference::tests::ready();
        let session = s.sessions[0].identity.clone();
        let (text, key) = if tail {
            (
                "prefix\nabcdefghijklmno".to_string(),
                "nabcdefghijklmno".to_string(),
            )
        } else {
            (
                "ordinary goal".to_string(),
                format!("{}\",\"text\":\"", session),
            )
        };
        s.remember_poc_credential(key.as_bytes());
        let files = s.storage.files();
        let next = s.next;
        let previous = s.previous.0;
        let error = block_on(s.enter_goal(&session, text, None)).unwrap_err();
        assert!(!error.contains(&key));
        unchanged(&s, &files, next, previous);
        assert!(s.goal(&session).is_none());
        // A safe append remains possible in the same worker after refusal.
        block_on(s.accept_mode(&session, Mode::NoBrief)).unwrap();
        assert_eq!(s.next, next + 1);
    }
}

#[test]
fn poc_journal_mode_acceptance_uses_the_common_literal_boundary() {
    let mut s = crate::store::inference::tests::ready();
    let session = s.sessions[0].identity.clone();
    let event = Event::ModeAcceptance(Acceptance {
        session: session.clone(),
        mode: Mode::NoBrief,
    });
    let bytes = serde_json::to_string(&event).unwrap();
    let key = &bytes[..20];
    s.remember_poc_credential(key.as_bytes());
    let files = s.storage.files();
    let next = s.next;
    let previous = s.previous.0;
    let error = block_on(s.accept_mode(&session, Mode::NoBrief)).unwrap_err();
    assert!(!error.contains(key));
    unchanged(&s, &files, next, previous);
    assert!(s.conduct_acceptances.is_empty());
    block_on(s.enter_goal(&session, "safe goal".into(), None)).unwrap();
}

#[test]
fn poc_journal_both_job_variants_preserve_pending_and_local_abandon() {
    // Fix every generated identifier so configuration and later adoption cannot vary with the seed.
    let _identifiers = FixedIdentifiers::new();
    for exit in [Some(0), None] {
        let mut s = ready();
        let task = create_task(&mut s);
        let task = proposal(&mut s, &task);
        let call = append(&mut s, &task, &task.start_session);
        let task = s.poc_task(&task.id).unwrap();
        let pending = task.pending.as_ref().unwrap();
        let key = format!("{}\",\"record\"", &pending.job[pending.job.len() - 8..]);
        s.remember_poc_credential(key.as_bytes());
        let files = s.storage.files();
        let next = s.next;
        let previous = s.previous.0;
        let ev = crate::jobs::Evidence {
            call,
            job: pending.job.clone(),
            record: record(&task, exit, "ordinary output"),
        };
        let error = block_on(s.job_evidence(&ev)).unwrap_err();
        assert!(!error.contains(&key));
        unchanged(&s, &files, next, previous);
        assert_eq!(s.poc_task(&task.id).unwrap(), task);
        assert_eq!(s.dispatch.collectable("fixture").len(), 1);
        let abandoned = change(&mut s, &task, Change::Abandon);
        assert_eq!(abandoned.pending, task.pending);
        assert_eq!(s.dispatch.collectable("fixture").len(), 1);
        assert_eq!(reopen(&s).poc_task(&task.id).unwrap(), abandoned);
    }
}

#[test]
fn poc_journal_admission_is_symbolic_across_decimal_widths_and_upper_domain() {
    // Fix every generated identifier so configuration and later adoption cannot vary with the seed.
    let _identifiers = FixedIdentifiers::new();
    let mut s = ready();
    let task = create_task(&mut s);
    for revision in [
        9u64,
        10,
        99,
        100,
        u64::from(u32::MAX) - 1,
        u64::MAX - 1,
        u64::MAX,
    ] {
        let key = format!(
            "{}\",\"expected\":{revision},",
            &task.id[task.id.len() - 4..]
        );
        let files = s.storage.files();
        assert!(
            s.poc_configuration_key(key.as_bytes()).is_err(),
            "future decimal envelope admitted"
        );
        assert_eq!(s.storage.files(), files);
        assert!(s.poc_credential_filters.is_empty());
    }
    s.poc_configuration_key(b"ordinary-later-key-482700")
        .unwrap();
    s.remember_poc_credential(b"ordinary-later-key-482700");
    let task = change(
        &mut s,
        &task,
        Change::Raise(Limits {
            requests: 20,
            steps: 40,
        }),
    );
    let mut task = task;
    while task.revision < 100 {
        let previous = task.revision;
        task = change(
            &mut s,
            &task,
            Change::Raise(Limits {
                requests: 20,
                steps: 40,
            }),
        );
        assert_eq!(task.revision, previous + 1);
        if [9, 99].contains(&previous) {
            assert_eq!(reopen(&s).poc_task(&task.id).unwrap(), task);
        }
    }
    assert_eq!(
        change(&mut s, &task, Change::Abandon).status,
        Status::Abandoned
    );
}

#[test]
fn poc_journal_creation_checks_future_goal_before_create_for_retained_generations() {
    // Fix every generated identifier so configuration and later adoption cannot vary with the seed.
    let _identifiers = FixedIdentifiers::new();
    for rotate in [false, true] {
        let mut s = ready();
        let session = s.sessions[0].identity.clone();
        // Current Create is safe: only the later Goal event contains this suffix span.
        let key = b"small service\",\"source\":\"";
        s.poc_configuration_key(key).unwrap();
        s.remember_poc_credential(key);
        if rotate {
            s.remember_poc_credential(b"replacement-credential-482700");
        }
        let files = s.storage.files();
        let next = s.next;
        let previous = s.previous.0;
        let error = block_on(s.poc_create(&session, vec!["true".into()])).unwrap_err();
        assert!(!error.contains(std::str::from_utf8(key).unwrap()));
        unchanged(&s, &files, next, previous);
        assert!(s.poc.is_empty());
    }
}

#[test]
fn poc_journal_restoration_keeps_original_goal_without_new_admission() {
    // Fix every generated identifier so configuration and later adoption cannot vary with the seed.
    let _identifiers = FixedIdentifiers::new();
    let mut s = ready();
    let task = create_task(&mut s);
    let mut s = reopen(&s);
    let session = fresh(&mut s);
    // A future decimal suffix is absent from this immediate session and record.
    let key = b"session-999999\",\"text\":\"";
    s.remember_poc_credential(key);
    s.remember_poc_credential(b"replacement-credential-482700");
    let files = s.storage.files();
    let next = s.next;
    let previous = s.previous.0;
    assert!(s.poc_authority(&task.id, &session).is_ok());
    unchanged(&s, &files, next, previous);
    assert_eq!(s.poc_task(&task.id).unwrap(), task);
    assert_eq!(s.goal(&session).unwrap().text, task.goal);
    assert_eq!(
        change(&mut s, &task, Change::Abandon).status,
        Status::Abandoned
    );
}

#[test]
fn poc_journal_arbitrary_payload_refusal_keeps_abandon_effective() {
    // Fix every generated identifier so configuration and later adoption cannot vary with the seed.
    let _identifiers = FixedIdentifiers::new();
    let mut s = ready();
    let task = create_task(&mut s);
    let task = change(&mut s, &task, Change::Request);
    let key = b"payload-tail\",\"tool\":";
    s.poc_configuration_key(key).unwrap();
    s.remember_poc_credential(key);
    s.remember_poc_credential(b"replacement-credential-482700");
    let files = s.storage.files();
    let next = s.next;
    let previous = s.previous.0;
    let error = block_on(s.poc_change(
        &task.id,
        task.revision,
        Change::Propose {
            call_id: "arbitrary-payload-tail".into(),
            tool: exec("true"),
        },
    ))
    .unwrap_err();
    assert!(!error.contains(std::str::from_utf8(key).unwrap()));
    unchanged(&s, &files, next, previous);
    assert_eq!(s.poc_task(&task.id).unwrap(), task);
    assert_eq!(
        change(&mut s, &task, Change::Abandon).status,
        Status::Abandoned
    );
}

#[test]
fn poc_journal_no_key_store_preserves_seed_account_and_replay() {
    let mut s = ready();
    assert!(s.poc_credential_filters.is_empty());
    let task = create_task(&mut s);
    let seed = s.seed().unwrap().id();
    let reopened = reopen(&s);
    assert_eq!(reopened.seed().unwrap().id(), seed);
    assert!(reopened.inference.account.is_some());
    assert_eq!(reopened.poc_task(&task.id).unwrap(), task);
    s.next = u64::from(u32::MAX);
    let files = s.storage.files();
    let previous = s.previous.0;
    assert!(
        block_on(s.poc_change(&task.id, task.revision, Change::Abandon))
            .unwrap_err()
            .contains("2^32nd")
    );
    unchanged(&s, &files, u64::from(u32::MAX), previous);
}

#[test]
fn poc_journal_work_refusal_is_key_free_and_write_free() {
    // Fix every generated identifier so configuration and later adoption cannot vary with the seed.
    let _identifiers = FixedIdentifiers::new();
    let mut s = crate::store::inference::tests::ready();
    let session = s.sessions[0].identity.clone();
    let key = b"protected output withheld";
    // Independent registration preserves the credential/work-error overlap that admission refuses.
    s.remember_poc_credential(key);
    let files = s.storage.files();
    let next = s.next;
    let previous = s.previous.0;
    let error = crate::poc::inference::work::scope(|| {
        crate::poc::inference::work::charge(512 * 1024 * 1024)?;
        block_on(s.accept_mode(&session, Mode::NoBrief))
    })
    .unwrap_err();
    assert!(!error.contains(std::str::from_utf8(key).unwrap()));
    unchanged(&s, &files, next, previous);
    assert!(s.conduct_acceptances.is_empty());
    block_on(s.accept_mode(&session, Mode::NoBrief)).unwrap();
}

#[test]
fn poc_journal_resume_wait_admission_and_adoption_are_atomic() {
    // Fix every generated identifier so configuration and later adoption cannot vary with the seed.
    let _identifiers = FixedIdentifiers::new();
    for key in [
        "\",\"running\":true}}}}}",
        "\",\"running\":false}}}}}",
        "inspects it again\",\"running\":true",
    ] {
        for open in [false, true] {
            let mut s = ready();
            if open {
                create_task(&mut s);
            }
            s.poc_configuration_key(b"ordinary-resume-key-482700")
                .unwrap();
            s.remember_poc_credential(b"ordinary-resume-key-482700");
            let files = s.storage.files();
            let next = s.next;
            let previous = s.previous.0;
            let tasks = s.poc.clone();
            let filters = s.poc_credential_filters.len();
            let error = s.poc_configuration_key(key.as_bytes()).unwrap_err();
            assert!(!error.contains(key));
            unchanged(&s, &files, next, previous);
            assert_eq!(s.poc, tasks);
            assert_eq!(s.poc_credential_filters.len(), filters);
        }
        // An independently registered prior generation must gate adoption before Create.
        let mut s = ready();
        let session = s.sessions[0].identity.clone();
        s.remember_poc_credential(key.as_bytes());
        s.remember_poc_credential(b"replacement-resume-key-482700");
        let files = s.storage.files();
        let next = s.next;
        let previous = s.previous.0;
        assert_eq!(
            block_on(s.poc_create(&session, vec!["true".into()])).unwrap_err(),
            "task refused"
        );
        unchanged(&s, &files, next, previous);
        assert!(s.poc.is_empty());
    }
    // Ordinary accepted configuration follows the real Inspect/Wait path with both states.
    let mut s = ready();
    let task = create_task(&mut s);
    let task = proposal(&mut s, &task);
    s.poc_configuration_key(b"ordinary-resume-key-482700")
        .unwrap();
    s.remember_poc_credential(b"ordinary-resume-key-482700");
    append(&mut s, &task, &task.start_session);
    for running in [true, false] {
        let task = s.poc_task(&task.id).unwrap();
        let task = change(&mut s, &task, Change::Inspect);
        let waited = change(
            &mut s,
            &task,
            Change::Wait {
                why: if running {
                    "recorded job is running; Resume inspects it again"
                } else {
                    "observation unavailable"
                }
                .into(),
                running,
            },
        );
        assert_eq!(waited.pending, task.pending);
        assert_eq!(s.dispatch.calls.len(), 1);
        assert_eq!(reopen(&s).poc_task(&task.id).unwrap(), waited);
    }
}

#[test]
fn poc_journal_resume_command_admission_and_adoption_are_atomic() {
    // Fix every generated identifier so configuration and later adoption cannot vary with the seed.
    let _identifiers = FixedIdentifiers::new();
    for key in [
        "{\"command\":{\"binding\":{\"task\":\"",
        "\"revision\":18446744073709551615,\"session\":",
        "\"call\":18446744073709551615,\"machine\":",
        "abcdef012345\",\"provenance\":{",
        "\"requester\":\"session\"}}}}}",
    ] {
        for open in [false, true] {
            let mut s = ready();
            if open {
                create_task(&mut s);
            }
            s.remember_poc_credential(b"ordinary-resume-key-482700");
            let files = s.storage.files();
            let next = s.next;
            let previous = s.previous.0;
            let filters = s.poc_credential_filters.len();
            let error = s.poc_configuration_key(key.as_bytes()).unwrap_err();
            assert!(!error.contains(key));
            unchanged(&s, &files, next, previous);
            assert_eq!(s.poc_credential_filters.len(), filters);
        }
        let mut s = ready();
        let session = s.sessions[0].identity.clone();
        s.remember_poc_credential(key.as_bytes());
        s.remember_poc_credential(b"replacement-resume-key-482700");
        let files = s.storage.files();
        let next = s.next;
        let previous = s.previous.0;
        assert_eq!(
            block_on(s.poc_create(&session, vec!["true".into()])).unwrap_err(),
            "task refused"
        );
        unchanged(&s, &files, next, previous);
        assert!(s.poc.is_empty());
    }
    let mut s = ready();
    let task = create_task(&mut s);
    let task = proposal(&mut s, &task);
    s.poc_configuration_key(b"ordinary-resume-key-482700")
        .unwrap();
    s.remember_poc_credential(b"ordinary-resume-key-482700");
    for key in [
        format!("{}\",\"revision\":99,", &task.id[task.id.len() - 6..]),
        format!("{}\"}},\"intent\":", task.start_session),
        format!("{}\",\"command\":\"", task.machine),
    ] {
        assert!(s.poc_configuration_key(key.as_bytes()).is_err());
    }
    let call = block_on(s.poc_append(
        &binding(&task, &task.start_session),
        &entry(&task, &task.start_session),
        &approval(),
    ))
    .unwrap();
    assert_eq!(s.dispatch.calls.len(), 1);
    assert_eq!(
        s.poc_task(&task.id).unwrap().pending.as_ref().unwrap().call,
        call
    );
    // The original binding cannot append a second command after the first durable intent.
    assert!(
        block_on(s.poc_append(
            &binding(&task, &task.start_session),
            &entry(&task, &task.start_session),
            &approval()
        ))
        .is_err()
    );
    assert_eq!(s.dispatch.calls.len(), 1);
}

#[test]
fn poc_journal_requirements_refusal_preserves_pending_approval() {
    // Fix every generated identifier so configuration and later adoption cannot vary with the seed.
    let _identifiers = FixedIdentifiers::new();
    let mut s = ready_without_requirements();
    let session = s.sessions[0].identity.clone();
    s.propose_requirements(
        &session,
        42,
        crate::declaration::Proposal::Declaration {
            machine: "fixture".into(),
            declaration: crate::declaration::ad_hoc_minimum(),
        },
        &exec("true"),
    )
    .unwrap();
    let key = b"\"setup\":{\"requirements\":";
    // Reach commit independently of configuration admission policy.
    s.remember_poc_credential(key);
    let pending = s.pending_requirements_view(&session);
    let pending_raw = s.pending_requirements[&session].clone();
    assert!(!pending.is_null());
    let dispatch = format!("{:?}", s.dispatch);
    let files = s.storage.files();
    let next = s.next;
    let previous = s.previous.0;
    let error = block_on(s.approve_requirements(&session, "fixture", 42)).unwrap_err();
    assert_eq!(error, "journal refused");
    assert!(!error.contains(std::str::from_utf8(key).unwrap()));
    unchanged(&s, &files, next, previous);
    assert_eq!(s.pending_requirements_view(&session), pending);
    assert_eq!(
        s.pending_requirements[&session].candidate,
        pending_raw.candidate
    );
    assert_eq!(
        s.pending_requirements[&session].proposal,
        pending_raw.proposal
    );
    assert_eq!(format!("{:?}", s.dispatch), dispatch);
    // Explicit rejection remains usable; refusal creates no implicit declaration approval.
    s.reject_requirements(&session, "fixture", 42).unwrap();
    create_task(&mut s);
}

#[test]
fn poc_journal_protected_association_refusal_preserves_prior_diagnostic() {
    // Fix every generated identifier so configuration and later adoption cannot vary with the seed.
    let _identifiers = FixedIdentifiers::new();
    use crate::dispatch::{
        Association, EvidenceDiagnostic, EvidenceProtection, StoredAssociation, Target,
    };
    for prior in [false, true] {
        let mut s = ready();
        if prior {
            s.uncommitted_evidence = Some(EvidenceDiagnostic::Association {
                committed: false,
                association: StoredAssociation::from(Association {
                    target: Target::VendorMachine("prior-target".into()),
                    entry: "fixture".into(),
                }),
            });
        }
        let diagnostic = s.uncommitted_evidence.clone();
        let key = b"{\"association\":{\"kind\":\"protected\"";
        s.poc_configuration_key(key).unwrap();
        s.remember_poc_credential(key);
        let files = s.storage.files();
        let next = s.next;
        let previous = s.previous.0;
        let dispatch = format!("{:?}", s.dispatch);
        assert_eq!(
            block_on(s.association_evidence(
                Association {
                    target: Target::VendorMachine("new-synthetic-target".into()),
                    entry: "fixture".into(),
                },
                EvidenceProtection::default()
            )),
            Err("journal refused".into())
        );
        unchanged(&s, &files, next, previous);
        assert_eq!(s.uncommitted_evidence, diagnostic);
        assert_eq!(format!("{:?}", s.dispatch), dispatch);
        create_task(&mut s);
        assert_eq!(s.uncommitted_evidence, diagnostic);
    }
}

#[test]
fn poc_journal_protected_receipt_refusal_preserves_prior_diagnostic() {
    // Fix every generated identifier so configuration and later adoption cannot vary with the seed.
    let _identifiers = FixedIdentifiers::new();
    use crate::dispatch::{
        Association, EvidenceDiagnostic, EvidenceProtection, Operation, Receipt, ReceiptBinding,
        ReceiptOperation, ReceiptSource, StoredAssociation, Target,
    };
    for prior in [false, true] {
        let (_, mut s, _) = crate::dispatch::typed_tests::fresh();
        let mut request = crate::dispatch::typed_tests::request(Operation::Reset);
        request.receipt_binding = Some(ReceiptBinding {
            operation: ReceiptOperation::Restart,
            account: 41,
            signed_request: 73,
        });
        request.approved.as_mut().unwrap().receipt_binding = request.receipt_binding.clone();
        let intent = block_on(s.operation(&request)).unwrap();
        let receipt = Receipt {
            source: ReceiptSource::BrowserVendorTls,
            call: intent.call,
            resource: intent.resource.clone(),
            target: intent.target.clone(),
            binding: intent.receipt_binding.clone().unwrap(),
            validated: true,
            returned_vendor: None,
        };
        if prior {
            s.uncommitted_evidence = Some(EvidenceDiagnostic::Association {
                committed: false,
                association: StoredAssociation::from(Association {
                    target: Target::VendorMachine("prior-target".into()),
                    entry: "fixture".into(),
                }),
            });
        }
        let diagnostic = s.uncommitted_evidence.clone();
        let key = b"{\"operation_receipt\":{\"kind\":\"protected\"";
        s.poc_configuration_key(key).unwrap();
        s.remember_poc_credential(key);
        let files = s.storage.files();
        let next = s.next;
        let previous = s.previous.0;
        let dispatch = format!("{:?}", s.dispatch);
        assert_eq!(
            block_on(s.protected_operation_receipt(receipt.clone(), EvidenceProtection::default())),
            Err("journal refused".into())
        );
        unchanged(&s, &files, next, previous);
        assert_eq!(s.uncommitted_evidence, diagnostic);
        assert_eq!(format!("{:?}", s.dispatch), dispatch);
        // A distinct, safe receipt can still settle the original operation without a resend.
        block_on(s.operation_receipt(receipt)).unwrap();
        assert_eq!(s.dispatch.typed_calls.len(), 1);
        assert!(s.uncommitted_evidence.is_none());
    }
}

#[test]
fn poc_journal_protected_diagnostics_survive_real_storage_failure() {
    use crate::dispatch::{Association, EvidenceDiagnostic, EvidenceProtection, Target};
    for fault in [Fault::Fail(1), Fault::Fail(2), Fault::LandThenFail(3)] {
        let mut s = ready();
        s.storage.fault(fault);
        assert!(
            block_on(s.association_evidence(
                Association {
                    target: Target::VendorMachine("failed-synthetic-target".into()),
                    entry: "fixture".into(),
                },
                EvidenceProtection::default()
            ))
            .is_err()
        );
        assert!(s.failed.is_some());
        assert!(matches!(
            s.uncommitted_evidence(),
            Some(EvidenceDiagnostic::Association {
                committed: false,
                ..
            })
        ));

        use crate::dispatch::{
            Operation, Receipt, ReceiptBinding, ReceiptOperation, ReceiptSource,
        };
        let (_, mut s, _) = crate::dispatch::typed_tests::fresh();
        let mut request = crate::dispatch::typed_tests::request(Operation::Reset);
        request.receipt_binding = Some(ReceiptBinding {
            operation: ReceiptOperation::Restart,
            account: 41,
            signed_request: 73,
        });
        request.approved.as_mut().unwrap().receipt_binding = request.receipt_binding.clone();
        let intent = block_on(s.operation(&request)).unwrap();
        let receipt = Receipt {
            source: ReceiptSource::BrowserVendorTls,
            call: intent.call,
            resource: intent.resource.clone(),
            target: intent.target.clone(),
            binding: intent.receipt_binding.clone().unwrap(),
            validated: true,
            returned_vendor: None,
        };
        s.storage.fault(fault);
        assert!(
            block_on(s.protected_operation_receipt(receipt, EvidenceProtection::default()))
                .is_err()
        );
        assert!(s.failed.is_some());
        assert!(matches!(
            s.uncommitted_evidence(),
            Some(EvidenceDiagnostic::Receipt {
                committed: false,
                ..
            })
        ));
    }
}
