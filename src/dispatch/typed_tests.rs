use super::*;
use crate::credential::{LocalPassphrase, WrappingKey};
use crate::harness::{AppendRefusal, Entry, Journal};
use crate::store::{self, Fault, Kdf, MemoryStorage, OperationError, Salt, Store, block_on};

struct FixedKdf;
impl Kdf for FixedKdf {
    async fn derive(&self, _: LocalPassphrase, _: &Salt) -> Result<WrappingKey, String> {
        Ok(WrappingKey([7; 32]))
    }
}

fn pass() -> LocalPassphrase {
    LocalPassphrase::new(b"fixture passphrase only".to_vec())
}

pub(super) fn associations() -> Vec<Association> {
    vec![
        Association {
            target: Target::Entry("fixture".into()),
            entry: "fixture".into(),
        },
        Association {
            target: Target::AllocationIndex(0),
            entry: "fixture".into(),
        },
        Association {
            target: Target::AllocationIndex(1),
            entry: "fixture".into(),
        },
        Association {
            target: Target::VendorMachine("vendor-7".into()),
            entry: "fixture".into(),
        },
        Association {
            target: Target::Entry("other".into()),
            entry: "other".into(),
        },
    ]
}

fn associate(store: &mut Store<MemoryStorage>) {
    for association in associations() {
        store.associate(association).unwrap();
    }
}

fn fresh() -> (MemoryStorage, Store<MemoryStorage>) {
    let storage = MemoryStorage::default();
    let mut store = block_on(store::create(storage.clone(), &FixedKdf, pass())).unwrap();
    associate(&mut store);
    (storage, store)
}

fn reopen(storage: &MemoryStorage) -> Store<MemoryStorage> {
    let mut store = block_on(store::unlock(
        MemoryStorage::with_files(storage.files()),
        &FixedKdf,
        pass(),
    ))
    .unwrap();
    associate(&mut store);
    store
}

pub(super) fn request(operation: Operation) -> Request {
    let facts = Facts {
        arguments: BTreeMap::from([("size".into(), "small".into())]),
        cost_bound: 12,
        bundle_commit: crate::SPEC_COMMIT.into(),
    };
    let target = Target::Entry("fixture".into());
    let approved = OperationApproval {
        resource: Resource::Entry("fixture".into()),
        target: target.clone(),
        operation,
        session: "session-1".into(),
        facts: facts.clone(),
    };
    Request {
        target,
        operation,
        session: "session-1".into(),
        requester: Requester::Session,
        facts,
        approved: Some(approved),
    }
}

fn approve(request: &mut Request, resource: Resource) {
    request.approved = Some(OperationApproval {
        resource,
        target: request.target.clone(),
        operation: request.operation,
        session: request.session.clone(),
        facts: request.facts.clone(),
    });
}

fn choice(calls: &[u64], continuation: Continuation) -> Disposition {
    Disposition {
        machine: "fixture".into(),
        calls: calls.to_vec(),
        continuation,
        uncertainty: "effect not established".into(),
    }
}

fn command() -> Entry {
    Entry {
        provenance: None,
        machine: "fixture".into(),
        command: b"true".to_vec(),
    }
}
fn pin() -> Approval {
    Approval::HarnessPin {
        machine: "fixture".into(),
        fingerprint: "SHA256:fixture".into(),
    }
}

fn command_refused(store: &mut Store<MemoryStorage>, refusal: Option<DispatchRefusal>) {
    let expected = refusal.map_or(Ok(()), |refusal| Err(AppendRefusal::Policy(refusal)));
    assert_eq!(block_on(store.check("fixture")), expected);
    if expected.is_err() {
        let before = store.records();
        assert_eq!(
            block_on(store.append(&command(), &pin())),
            expected.map(|()| 0)
        );
        assert_eq!(store.records(), before);
    }
}

const CHOICES: [Continuation; 4] = [
    Continuation::DestructiveReinstall,
    Continuation::Abandonment,
    Continuation::AsIfDone,
    Continuation::AsIfNotDone,
];

#[test]
fn typed_record_before_send_survives_every_kill_boundary() {
    let (storage, _) = fresh();
    let files = storage.files();
    for at in 1..=4 {
        let storage = MemoryStorage::with_files(files.clone());
        let mut store = reopen(&storage);
        // Reopen's storage is a new worker; fault the exact storage it owns.
        let active = store.storage().clone();
        active.fault(Fault::Die(at));
        let mut vendor = fixture::Vendor::default();
        let result = block_on(vendor.run(&mut store, &request(Operation::Create)));
        assert_eq!(result.is_ok(), at == 4);
        drop(store);
        let replayed = reopen(&active);
        assert_eq!(replayed.records(), 0..if at == 4 { 2 } else { 1 });
        assert_eq!(replayed.dispatch().typed_calls.len(), usize::from(at == 4));
        if at == 4 {
            let recorded = &replayed.dispatch().typed_calls[&1];
            assert_eq!(recorded.state, CallState::Unresolved);
            assert_eq!(
                recorded.intent.approved,
                request(Operation::Create).approved.unwrap()
            );
            assert_eq!(
                vendor.received.as_slice(),
                std::slice::from_ref(&recorded.intent)
            );
        } else {
            assert!(
                vendor.received.is_empty(),
                "no send before committed intent at kill {at}"
            );
        }
    }
    // Kill the actual request future at the record/send boundary after a successful append.
    let (_, mut store) = fresh();
    let active = store.storage().clone();
    let mut vendor = fixture::Vendor {
        pause_before_send: true,
        ..Default::default()
    };
    let request = request(Operation::Create);
    {
        use std::future::Future;
        let mut run = std::pin::pin!(vendor.run(&mut store, &request));
        assert!(
            run.as_mut()
                .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
                .is_pending()
        );
    }
    drop(store);
    let replayed = reopen(&active);
    assert_eq!(
        replayed.dispatch().typed_calls[&1].state,
        CallState::Unresolved
    );
    assert_eq!(
        replayed.dispatch().typed_calls[&1].intent.approved,
        request.approved.unwrap()
    );
    assert!(
        vendor.received.is_empty(),
        "worker gone between record and send"
    );
}

#[test]
fn lost_create_new_call_session_route_and_index_are_refused_after_replay() {
    let (storage, mut store) = fresh();
    let mut vendor = fixture::Vendor::default();
    assert_eq!(fixture::Vendor::RETRY_SAFETY, "reconcile-before-retry");
    let call = block_on(vendor.run(&mut store, &request(Operation::Create))).unwrap();
    assert_eq!(
        vendor.received[0],
        store.dispatch().typed_calls[&call].intent
    );
    for store in [&mut store, &mut reopen(&storage)] {
        assert_eq!(
            store.dispatch().typed_calls[&call].state,
            CallState::Unresolved
        );
        let before = store.storage().files();
        for requester in [
            Requester::Session,
            Requester::Operator,
            Requester::HarnessFlow,
        ] {
            for target in [
                Target::Entry("fixture".into()),
                Target::AllocationIndex(0),
                Target::AllocationIndex(1),
                Target::VendorMachine("vendor-7".into()),
            ] {
                let mut next = request(Operation::Create);
                next.target = target;
                next.session = "successor-session".into();
                next.requester = requester;
                approve(&mut next, Resource::Entry("fixture".into()));
                let expected = RequestRefusal::Barrier { calls: vec![call] };
                assert_eq!(store.check_operation(&next), Err(expected.clone()));
                assert_eq!(
                    block_on(store.operation(&next)),
                    Err(OperationError::Policy(expected))
                );
            }
        }
        assert_eq!(
            store.storage().files(),
            before,
            "every refusal journals nothing"
        );
        let mut other = request(Operation::Create);
        other.target = Target::Entry("other".into());
        approve(&mut other, Resource::Entry("other".into()));
        assert!(block_on(vendor.run(store, &other)).is_ok());
    }
    // Every actual requester route above shares this check.
}

#[test]
fn approved_facts_are_required_and_are_exactly_what_the_fixture_receives() {
    let (_, mut store) = fresh();
    let mut vendor = fixture::Vendor::default();
    let before = store.storage().files();
    let mut changed = request(Operation::Create);
    changed.facts.cost_bound += 1;
    assert_eq!(
        block_on(vendor.run(&mut store, &changed)),
        Err(OperationError::Policy(RequestRefusal::Facts))
    );
    changed.approved = None;
    assert_eq!(
        block_on(vendor.run(&mut store, &changed)),
        Err(OperationError::Policy(RequestRefusal::Facts))
    );
    changed.target = Target::AllocationIndex(999);
    assert_eq!(
        block_on(vendor.run(&mut store, &changed)),
        Err(OperationError::Policy(RequestRefusal::Unmapped))
    );
    assert_eq!(store.storage().files(), before);
    assert!(vendor.received.is_empty());
    let call = block_on(vendor.run(&mut store, &request(Operation::Create))).unwrap();
    assert_eq!(
        vendor.received[0],
        store.dispatch().typed_calls[&call].intent
    );
    assert_eq!(vendor.received[0].facts, vendor.received[0].approved.facts);
}

#[test]
fn status_reads_pass_and_failed_observation_append_keeps_barrier() {
    for operation in [Operation::Create, Operation::Reset, Operation::Reinstall] {
        let (_, mut store) = fresh();
        let mut vendor = fixture::Vendor::default();
        let call = block_on(vendor.run(&mut store, &request(operation))).unwrap();
        assert!(store.check_operation(&request(Operation::Read)).is_ok());
        block_on(vendor.status(
            &mut store,
            &request(Operation::Read),
            operation,
            Reports::Ended,
        ))
        .unwrap();
        assert_eq!(
            store.dispatch().typed_calls[&call].state,
            CallState::Unresolved
        );
        let snapshot = store.storage().files();
        for (fault, landed) in [(Fault::Fail(3), false), (Fault::LandThenFail(3), true)] {
            let mut worker = reopen(&MemoryStorage::with_files(snapshot.clone()));
            let storage = worker.storage().clone();
            let read = worker.dispatch().observation(
                Resource::Entry("fixture".into()),
                operation,
                Reports::Confirmed,
            );
            storage.fault(fault);
            assert!(block_on(worker.operation_observation(read)).is_err());
            assert_eq!(
                worker.dispatch().typed_calls[&call].state,
                CallState::Unresolved
            );
            assert_eq!(
                worker.check_operation(&request(operation)),
                Err(RequestRefusal::Barrier { calls: vec![call] })
            );
            let why = if landed {
                "move: landed, then reported failure"
            } else {
                "move: made to fail"
            };
            assert_eq!(
                block_on(worker.operation(&request(Operation::Read))),
                Err(OperationError::Storage(format!(
                    "an earlier append failed ({why}), so none follows until the worker restarts"
                ))),
                "failed-append latch"
            );
            let replayed = reopen(&storage);
            assert_eq!(
                replayed.dispatch().typed_calls[&call].state == CallState::Unresolved,
                !landed
            );
        }
    }
}

#[test]
fn reset_and_reinstall_stop_commands_at_check_and_append_until_confirmation() {
    for operation in [Operation::Reset, Operation::Reinstall, Operation::Destroy] {
        let (_, mut store) = fresh();
        let intent = block_on(store.operation(&request(operation))).unwrap();
        let call = intent.call;
        let before = store.storage().files();
        command_refused(
            &mut store,
            Some(DispatchRefusal::TypedBarrier {
                calls: vec![intent],
            }),
        );
        assert!(
            matches!(block_on(store.check("fixture")), Err(AppendRefusal::Policy(DispatchRefusal::TypedBarrier { calls })) if calls[0].call == call)
        );
        assert_eq!(store.storage().files(), before);
        let read = store.dispatch().observation(
            Resource::Entry("fixture".into()),
            operation,
            Reports::Confirmed,
        );
        assert_eq!(block_on(store.operation_observation(read)).unwrap(), [call]);
        command_refused(&mut store, None);
        assert!(block_on(store.append(&command(), &pin())).is_ok());
    }
}

#[test]
fn disposition_matrix_reads_and_commands_in_core_store_and_replay() {
    for operation in [
        Operation::Create,
        Operation::Reset,
        Operation::Reinstall,
        Operation::Destroy,
        Operation::Exec,
    ] {
        for continuation in CHOICES {
            let (storage, mut store) = fresh();
            let call = if operation == Operation::Exec {
                block_on(store.append(&command(), &pin())).unwrap()
            } else {
                block_on(store.operation(&request(operation))).unwrap().call
            };
            block_on(store.dispose(choice(&[call], continuation))).unwrap();
            for store in [&mut store, &mut reopen(&storage)] {
                let standing = store.dispatch().standing["fixture"].clone();
                command_refused(
                    store,
                    continuation
                        .destructive()
                        .then_some(DispatchRefusal::Disposition(DestructiveDisposition {
                            disposition: standing.number,
                            continuation,
                        })),
                );
                for requester in [
                    Requester::Session,
                    Requester::Operator,
                    Requester::HarnessFlow,
                ] {
                    let mut worker = reopen(store.storage());
                    let mut entry = command();
                    entry.provenance = Some(CommandProvenance {
                        target: Target::AllocationIndex(0),
                        session: Some("session-2".into()),
                        requester,
                    });
                    let before = worker.storage().files();
                    let expected = Err(AppendRefusal::Policy(DispatchRefusal::Disposition(
                        DestructiveDisposition {
                            disposition: standing.number,
                            continuation,
                        },
                    )));
                    if continuation.destructive() {
                        assert_eq!(block_on(worker.check(&entry.machine)), expected);
                        assert_eq!(
                            block_on(worker.append(&entry, &pin())),
                            expected.map(|()| 0)
                        );
                        assert_eq!(worker.storage().files(), before);
                    } else {
                        assert_eq!(block_on(worker.check(&entry.machine)), Ok(()));
                        let id = block_on(worker.append(&entry, &pin())).unwrap();
                        assert_eq!(
                            worker.dispatch().calls[&id].intent.provenance,
                            entry.provenance
                        );
                    }
                }
                let mut vendor = fixture::Vendor::default();
                block_on(vendor.status(
                    store,
                    &request(Operation::Read),
                    operation,
                    Reports::Unknown,
                ))
                .unwrap();
                assert_eq!(store.dispatch().standing["fixture"], standing);
                command_refused(
                    store,
                    continuation
                        .destructive()
                        .then_some(DispatchRefusal::Disposition(DestructiveDisposition {
                            disposition: standing.number,
                            continuation,
                        })),
                );
                let expected = if operation == Operation::Exec {
                    vec![store.dispatch().calls[&call].intent.clone()]
                } else {
                    vec![]
                };
                assert_eq!(
                    block_on(store.collectable("fixture")).unwrap(),
                    expected,
                    "collection must include the disposed command and no typed call"
                );
                for intent in expected {
                    let evidence = crate::jobs::Evidence {
                        call: intent.call,
                        job: intent.job.unwrap(),
                        record: crate::jobs::Record::Present {
                            machine: hex::encode(&intent.machine),
                            command: intent.command,
                            boot: "fixture-boot".into(),
                            current_boot: "fixture-boot".into(),
                            pid: 7,
                            alive: false,
                            exit_status: Some(0),
                            stdout: String::new(),
                            stderr: String::new(),
                        },
                    };
                    let report = block_on(store.job_evidence(&evidence)).unwrap();
                    assert!(report.number.is_some());
                    assert_eq!(store.dispatch().jobs.last().unwrap(), &report);
                }
                assert_eq!(store.dispatch().standing["fixture"], standing);
                command_refused(
                    store,
                    continuation
                        .destructive()
                        .then_some(DispatchRefusal::Disposition(DestructiveDisposition {
                            disposition: standing.number,
                            continuation,
                        })),
                );
                // The pinned SSH attempt is exercised by the browser cases.
                if !continuation.destructive() {
                    let mut command_worker = reopen(store.storage());
                    assert!(
                        block_on(command_worker.append(&command(), &pin())).is_ok(),
                        "continuing choice dispatches a new command"
                    );
                    assert!(
                        matches!(&standing.report, DispositionReport::Accepted { assumption: Some(Assumption { continuation: recorded, outcome: Unknown::Unknown }), .. } if *recorded == continuation)
                    );
                    if operation.mutation() {
                        assert!(
                            block_on(store.operation(&request(operation))).is_ok(),
                            "explicit reissue"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn continuation_reach_permissions_and_durable_end() {
    for continuation in [
        Continuation::DestructiveReinstall,
        Continuation::Abandonment,
    ] {
        let (_, mut initial) = fresh();
        let call = block_on(initial.operation(&request(Operation::Reset)))
            .unwrap()
            .call;
        block_on(initial.dispose(choice(&[call], continuation))).unwrap();
        let saved = initial.storage().files();
        let permitted = if continuation == Continuation::Abandonment {
            Operation::Destroy
        } else {
            Operation::Reinstall
        };
        for operation in [
            Operation::Create,
            Operation::Reset,
            Operation::Reinstall,
            Operation::Destroy,
        ] {
            let mut r = request(operation);
            r.requester = Requester::HarnessFlow;
            assert_eq!(
                initial.check_operation(&r),
                if operation == permitted {
                    Ok(())
                } else {
                    Err(RequestRefusal::Continuation {
                        in_force: DestructiveDisposition {
                            disposition: initial.dispatch().standing["fixture"].number,
                            continuation,
                        },
                    })
                }
            );
        }
        assert_eq!(
            initial.check_operation(&request(Operation::Destroy)),
            Err(RequestRefusal::Continuation {
                in_force: DestructiveDisposition {
                    disposition: initial.dispatch().standing["fixture"].number,
                    continuation,
                }
            }),
            "session destroy is not abandonment flow"
        );
        assert!(initial.dispatch().check_command("other").is_ok());
        let mut r = request(permitted);
        r.requester = Requester::HarnessFlow;
        let mut failing = reopen(&MemoryStorage::with_files(saved.clone()));
        let storage = failing.storage().clone();
        storage.fault(Fault::Fail(3));
        assert_eq!(
            block_on(failing.operation(&r)),
            Err(OperationError::Storage("move: made to fail".into()))
        );
        assert!(failing.dispatch().standing.contains_key("fixture"));
        assert!(reopen(&storage).dispatch().standing.contains_key("fixture"));
        let mut store = reopen(&MemoryStorage::with_files(saved));
        let intent = block_on(store.operation(&r)).unwrap();
        for store in [&store, &reopen(store.storage())] {
            assert!(!store.dispatch().standing.contains_key("fixture"));
            assert_eq!(
                store.check_operation(&r),
                Err(RequestRefusal::Barrier {
                    calls: vec![intent.call]
                })
            );
            assert_eq!(
                store.dispatch().check_command("fixture"),
                Err(DispatchRefusal::TypedBarrier {
                    calls: vec![intent.clone()]
                })
            );
            for operation in [
                Operation::Create,
                Operation::Reset,
                Operation::Reinstall,
                Operation::Destroy,
            ] {
                assert_eq!(
                    store.check_operation(&request(operation)),
                    Err(RequestRefusal::Barrier {
                        calls: vec![intent.call]
                    })
                );
            }
            assert_eq!(
                store.dispatch().current_installations["fixture"],
                u64::from(permitted == Operation::Reinstall)
            );
        }
    }
}

#[test]
fn replacements_drop_calls_permanently_and_later_evidence_keeps_unknown_outcome() {
    let (_, mut store) = fresh();
    let mut vendor = fixture::Vendor::default();
    let create = block_on(vendor.run(&mut store, &request(Operation::Create))).unwrap();
    let exec = block_on(store.append(&command(), &pin())).unwrap();
    let first =
        block_on(store.dispose(choice(&[create, exec], Continuation::DestructiveReinstall)))
            .unwrap();
    let DispositionReport::Accepted { number: first, .. } = first else {
        panic!()
    };
    let replacement = block_on(store.dispose(choice(&[exec], Continuation::Abandonment))).unwrap();
    assert!(
        matches!(replacement, DispositionReport::Accepted { replaces: Some(n), ref dropped, .. } if n == first && dropped == &[create])
    );
    let observation = store.dispatch().observation(
        Resource::Entry("fixture".into()),
        Operation::Create,
        Reports::Confirmed,
    );
    assert!(
        block_on(store.operation_observation(observation))
            .unwrap()
            .is_empty()
    );
    let mut replayed = reopen(store.storage());
    for store in [&mut store, &mut replayed] {
        let before = store.storage().files();
        let refusal = block_on(store.dispose(choice(&[create], Continuation::AsIfDone))).unwrap();
        assert!(
            matches!(refusal, DispositionReport::Refused { ref issues, .. } if issues[0].settled_by == Some(first) && issues[0].settling_record.is_some())
        );
        assert_eq!(store.storage().files(), before);
        assert!(
            matches!(store.dispatch().typed_calls[&create].state, CallState::Disposed { disposition, outcome: Unknown::Unknown } if disposition == first)
        );
        assert_eq!(store.dispatch().observations.len(), 1);
        assert_eq!(
            store.dispatch().standing["fixture"]
                .disposition
                .continuation,
            Continuation::Abandonment
        );
        assert_eq!(
            store.check_operation(&request(Operation::Reinstall)),
            Err(RequestRefusal::Continuation {
                in_force: DestructiveDisposition {
                    disposition: store.dispatch().standing["fixture"].number,
                    continuation: Continuation::Abandonment,
                }
            })
        );
        assert!(
            matches!(&store.dispatch().standing["fixture"].report, DispositionReport::Accepted { dropped, .. } if dropped == &[create])
        );
    }
}

#[test]
fn partial_disposition_keeps_abandonment_flow_barred_until_every_call_is_disposed() {
    let (_, mut store) = fresh();
    let mut vendor = fixture::Vendor::default();
    let create = block_on(vendor.run(&mut store, &request(Operation::Create))).unwrap();
    let exec = block_on(store.append(&command(), &pin())).unwrap();
    block_on(store.dispose(choice(&[create], Continuation::Abandonment))).unwrap();
    let mut destroy = request(Operation::Destroy);
    destroy.requester = Requester::HarnessFlow;
    assert_eq!(
        store.check_operation(&destroy),
        Err(RequestRefusal::Barrier { calls: vec![exec] })
    );
    block_on(store.dispose(choice(&[create, exec], Continuation::Abandonment))).unwrap();
    assert_eq!(
        store.check_operation(&request(Operation::Destroy)),
        Err(RequestRefusal::Continuation {
            in_force: DestructiveDisposition {
                disposition: store.dispatch().standing["fixture"].number,
                continuation: Continuation::Abandonment,
            }
        })
    );
    let intent = block_on(store.operation(&destroy)).unwrap();
    for store in [&store, &reopen(store.storage())] {
        assert!(!store.dispatch().standing.contains_key("fixture"));
        assert_eq!(
            store.check_operation(&request(Operation::Destroy)),
            Err(RequestRefusal::Barrier {
                calls: vec![intent.call]
            })
        );
    }
}

#[test]
fn delayed_status_cannot_settle_a_later_reissue() {
    let (_, mut store) = fresh();
    let first = block_on(store.operation(&request(Operation::Create)))
        .unwrap()
        .call;
    let delayed = store.dispatch().observation(
        Resource::Entry("fixture".into()),
        Operation::Create,
        Reports::Confirmed,
    );
    block_on(store.dispose(choice(&[first], Continuation::AsIfNotDone))).unwrap();
    let next = block_on(store.operation(&request(Operation::Create)))
        .unwrap()
        .call;
    assert!(
        block_on(store.operation_observation(delayed))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.dispatch().typed_calls[&next].state,
        CallState::Unresolved
    );
    assert!(store.dispatch().standing.contains_key("fixture"));
}

#[test]
fn typed_disposition_naming_refusals_and_invalid_replayed_replacements_are_reported() {
    let (_, mut store) = fresh();
    let call = block_on(store.operation(&request(Operation::Reset)))
        .unwrap()
        .call;
    let before = store.storage().files();
    for mut invalid in [
        choice(&[], Continuation::Abandonment),
        choice(&[999], Continuation::Abandonment),
        choice(&[call], Continuation::Abandonment),
    ] {
        if invalid.calls == [call] {
            invalid.machine = "other".into();
        }
        let resource = Resource::Entry(invalid.machine.clone());
        let unresolved_now = store.dispatch().unresolved(&resource);
        let report = block_on(store.dispose(invalid)).unwrap();
        let DispositionReport::Refused { unresolved, .. } = report else {
            panic!("must refuse naming")
        };
        assert_eq!(unresolved, unresolved_now);
        assert_eq!(store.storage().files(), before);
    }
    // An authenticated historical record that the live naming test refuses ends nothing.
    let mut wrong_resource = choice(&[call], Continuation::Abandonment);
    wrong_resource.machine = "other".into();
    block_on(store.dispatch_fixture_record(store::Event::Disposition(wrong_resource))).unwrap();
    for store in [&store, &reopen(store.storage())] {
        assert_eq!(
            store.dispatch().typed_calls[&call].state,
            CallState::Unresolved
        );
        assert!(store.dispatch().standing.is_empty());
        assert!(matches!(
            store.dispatch().dispositions[0].report,
            DispositionReport::Refused { .. }
        ));
        assert_eq!(
            store.check_operation(&request(Operation::Reset)),
            Err(RequestRefusal::Barrier { calls: vec![call] })
        );
        assert!(store.dispatch().check_command("other").is_ok());
    }
    let observation = store.dispatch().observation(
        Resource::Entry("fixture".into()),
        Operation::Reset,
        Reports::Confirmed,
    );
    block_on(store.operation_observation(observation)).unwrap();
    let next = block_on(store.operation(&request(Operation::Reset)))
        .unwrap()
        .call;
    let before = store.storage().files();
    let report = block_on(store.dispose(choice(&[call], Continuation::Abandonment))).unwrap();
    assert!(
        matches!(report, DispositionReport::Refused { ref issues, ref unresolved }
        if matches!(issues[0].settling_record, Some(SettlingRecord::Observation(_))) && unresolved == &[next])
    );
    assert_eq!(store.storage().files(), before);
    block_on(store.dispose(choice(&[next], Continuation::AsIfDone))).unwrap();
    // Naming the already confirmed older call is not the replacement exception.
    block_on(
        store.dispatch_fixture_record(store::Event::Disposition(choice(
            &[call, next],
            Continuation::Abandonment,
        ))),
    )
    .unwrap();
    let replayed = reopen(store.storage());
    assert_eq!(
        replayed.dispatch().standing["fixture"]
            .disposition
            .continuation,
        Continuation::AsIfDone
    );
    assert!(matches!(
        replayed.dispatch().dispositions.last().unwrap().report,
        DispositionReport::Refused { .. }
    ));
    assert!(replayed.dispatch().check_command("fixture").is_ok());
}

#[test]
fn later_confirming_fixture_evidence_is_journaled_without_removing_the_standing_choice() {
    let (_, mut store) = fresh();
    let mut vendor = fixture::Vendor::default();
    let call = block_on(vendor.run(&mut store, &request(Operation::Reset))).unwrap();
    block_on(store.dispose(choice(&[call], Continuation::Abandonment))).unwrap();
    let standing = store.dispatch().standing["fixture"].clone();
    assert!(
        block_on(vendor.status(
            &mut store,
            &request(Operation::Read),
            Operation::Reset,
            Reports::Confirmed
        ))
        .unwrap()
        .is_empty()
    );
    for store in [&store, &reopen(store.storage())] {
        assert_eq!(store.dispatch().standing["fixture"], standing);
        assert_eq!(
            store.dispatch().observations[0].observation.reports,
            Reports::Confirmed
        );
        assert!(matches!(
            store.dispatch().typed_calls[&call].state,
            CallState::Disposed {
                outcome: Unknown::Unknown,
                ..
            }
        ));
    }
}

#[test]
fn inspection_reports_typed_records_drops_assumptions_and_refused_replay() {
    let (storage, mut store) = fresh();
    let create = block_on(store.operation(&request(Operation::Create)))
        .unwrap()
        .call;
    let exec = block_on(store.append(&command(), &pin())).unwrap();
    block_on(store.dispose(choice(&[create, exec], Continuation::DestructiveReinstall))).unwrap();
    block_on(store.dispose(choice(&[exec], Continuation::AsIfNotDone))).unwrap();
    block_on(
        store.dispatch_fixture_record(store::Event::Disposition(choice(
            &[create],
            Continuation::Abandonment,
        ))),
    )
    .unwrap();
    let observation = store.dispatch().observation(
        Resource::Entry("fixture".into()),
        Operation::Create,
        Reports::Confirmed,
    );
    block_on(store.operation_observation(observation)).unwrap();
    drop(store);
    let mut local = store::Local::new(MemoryStorage::with_files(storage.files()), FixedKdf);
    assert_eq!(block_on(local.open())["state"], "locked");
    assert_eq!(block_on(local.unlock(pass()))["state"], "unlocked");
    let report = local.inspect();
    assert_eq!(report["typed_calls"][0]["state"], "disposed");
    assert_eq!(
        report["dispositions"][0]["resource"],
        serde_json::json!({"entry":"fixture"})
    );
    assert_eq!(report["dispositions"][0]["machine"], "fixture");
    assert_eq!(report["typed_calls"][0]["outcome"], "unknown");
    assert_eq!(
        report["standing"]["fixture"]["report"]["dropped"],
        serde_json::json!([create])
    );
    assert_eq!(
        report["standing"]["fixture"]["report"]["assumption"],
        serde_json::json!({"continuation":"as_if_not_done","outcome":"unknown"})
    );
    assert_eq!(report["dispositions"][2]["report"]["decision"], "refused");
    assert_eq!(
        report["dispositions"][2]["report"]["issues"][0]["settled_by"],
        3
    );
    assert_eq!(
        report["observations"][0]["observation"]["reports"],
        "confirmed"
    );
    assert_eq!(report["current_installations"]["fixture"], 0);
}

#[test]
fn journal_assignment_alone_keeps_the_running_system_barrier_without_associations() {
    let (storage, mut store) = fresh();
    let call = block_on(store.operation(&request(Operation::Reset)))
        .unwrap()
        .call;
    let replayed = block_on(store::unlock(
        MemoryStorage::with_files(storage.files()),
        &FixedKdf,
        pass(),
    ))
    .unwrap();
    assert!(replayed.dispatch().associations.is_empty());
    assert_eq!(
        replayed
            .dispatch()
            .unresolved(&Resource::Entry("fixture".into())),
        [call]
    );
    assert!(
        matches!(replayed.dispatch().check_command("fixture"),Err(DispatchRefusal::TypedBarrier { calls }) if calls[0].call==call)
    );
}

#[test]
fn operation_writer_refuses_commands_and_inference_without_storage_failure() {
    let (_, mut store) = fresh();
    let before = store.storage().files();
    for operation in [Operation::Exec, Operation::Inference] {
        assert_eq!(
            block_on(store.operation(&request(operation))),
            Err(OperationError::Policy(
                RequestRefusal::UnsupportedOperation { operation }
            ))
        );
    }
    assert_eq!(store.storage().files(), before);
    assert!(block_on(store.operation(&request(Operation::Create))).is_ok());
}
