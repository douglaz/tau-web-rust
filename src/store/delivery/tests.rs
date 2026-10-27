use super::*;
use crate::declaration::*;
use crate::delivery::tests::{clean, service};
use crate::delivery::{Measured, ServiceFact, ServiceState};
use crate::goals::Tool;
use crate::store::inference::tests::Fixed;

fn pass() -> LocalPassphrase {
    LocalPassphrase::new(b"delivery fixture passphrase".to_vec())
}
fn ready() -> (Store<MemoryStorage>, String) {
    let mut s = block_on(create(MemoryStorage::default(), &Fixed, pass())).unwrap();
    block_on(s.seed_backup(allocation::Completion::Skipped)).unwrap();
    block_on(s.approve_setup(crate::dispatch::fixture_setup())).unwrap();
    for m in ["fixture", "fixture-other"] {
        block_on(s.answer_class(m.into(), crate::dispatch::ClassAnswer::No)).unwrap();
    }
    let session = block_on(s.bind("fixture")).unwrap();
    block_on(s.enter_goal(&session, "fixture delivery".into(), None)).unwrap();
    block_on(s.accept_mode(&session, Mode::NoBrief)).unwrap();
    (s, session)
}
fn approve(s: &mut Store<MemoryStorage>, session: &str, d: Declaration, n: u64) {
    s.propose_requirements(
        session,
        n,
        Proposal::Declaration {
            machine: "fixture".into(),
            declaration: d,
        },
        &Tool::Done {
            machine: "fixture".into(),
        },
    )
    .unwrap();
    block_on(s.approve_requirements(session, "fixture", n)).unwrap();
}
fn reopen(s: &Store<MemoryStorage>) -> Store<MemoryStorage> {
    block_on(unlock(
        MemoryStorage::with_files(s.storage.files()),
        &Fixed,
        pass(),
    ))
    .unwrap()
}
fn check(s: &mut Store<MemoryStorage>, session: &str, m: Measurements) {
    let a = s.delivery_authority(session, "fixture").unwrap();
    block_on(s.delivery_check(session, a, m)).unwrap();
}
fn view(s: &Store<MemoryStorage>) -> Value {
    s.delivery_view()
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["machine"] == "fixture")
        .unwrap()
        .clone()
}
fn stopped() -> (Declaration, Measurements) {
    let mut d = ad_hoc_minimum();
    let service = service("daemon", Lifecycle::RunningAtDelivery);
    d.services = Field::Value(vec![service.clone()]);
    let mut m = clean();
    m.services = Measured::Value(vec![ServiceFact {
        service,
        state: ServiceState::Difference,
        running_after_last_placement: false,
    }]);
    (d, m)
}
#[test]
fn delivery_journals_replays_all_findings_and_amendment_requires_recheck() {
    let (mut s, session) = ready();
    assert!(
        s.delivery_authority(&session, "fixture").is_err(),
        "no declaration cannot pass"
    );
    let (d, mut m) = stopped();
    approve(&mut s, &session, d, 1);
    check(&mut s, &session, m.clone());
    assert_eq!(view(&s)["verdict"], "handed over with findings");
    assert_eq!(
        view(&s)["findings"].as_array().unwrap().len(),
        1,
        "lifecycle-only finding stays visible"
    );
    assert_eq!(view(&s)["placement_eligible"], true);
    let files = s.storage.files();
    assert!(s.refuse_finding_acceptance().is_err());
    assert_eq!(files, s.storage.files());
    assert_eq!(
        view(&reopen(&s))["findings"],
        view(&s)["findings"],
        "encrypted replay restores lifecycle finding"
    );
    m.sshd_posture = Measured::Value(false);
    check(&mut s, &session, m.clone());
    assert_eq!(view(&s)["findings"].as_array().unwrap().len(), 2);
    assert_eq!(view(&s)["placement_eligible"], false);
    let authority = s.delivery_authority(&session, "fixture").unwrap();
    approve(&mut s, &session, ad_hoc_minimum(), 2);
    assert_eq!(
        view(&s)["findings"].as_array().unwrap().len(),
        2,
        "amendment alone retains every finding"
    );
    assert!(
        block_on(s.delivery_check(&session, authority, clean())).is_err(),
        "stale check cannot confer authority"
    );
    m.services = Measured::Value(vec![]);
    check(&mut s, &session, m);
    assert_eq!(
        view(&s)["findings"].as_array().unwrap().len(),
        1,
        "fixed lockdown cannot be amended away"
    );
    check(&mut s, &session, clean());
    assert_eq!(view(&s)["verdict"], "Delivered");
    let reopened = reopen(&s);
    assert_eq!(view(&reopened)["verdict"], "Delivered");
    assert!(reopened.sessions.is_empty(), "replay resumes no session");
    approve(&mut s, &session, ad_hoc_minimum(), 3);
    assert_ne!(
        view(&s)["verdict"],
        "Delivered",
        "amendment never reinterprets the previous check"
    );
}
#[test]
fn delivery_appends_fail_closed_and_landed_error_replays_without_current_authority() {
    for fault in [
        Fault::Fail(1),
        Fault::Fail(2),
        Fault::Fail(3),
        Fault::LandThenFail(3),
    ] {
        let (mut s, session) = ready();
        let (d, m) = stopped();
        approve(&mut s, &session, d, 1);
        check(&mut s, &session, m);
        let before = view(&s);
        let mut fixed = clean();
        if let Field::Value(services) = &s.dispatch.approved_entries["fixture"]
            .declaration
            .as_ref()
            .unwrap()
            .services
        {
            fixed.services = Measured::Value(
                services
                    .iter()
                    .map(|service| ServiceFact {
                        service: service.clone(),
                        state: ServiceState::Running,
                        running_after_last_placement: false,
                    })
                    .collect(),
            );
        }
        let a = s.delivery_authority(&session, "fixture").unwrap();
        s.storage.fault(fault);
        assert!(block_on(s.delivery_check(&session, a.clone(), fixed.clone())).is_err());
        assert_eq!(
            view(&s),
            before,
            "failed append cannot clear findings or deliver"
        );
        assert!(
            block_on(s.delivery_check(&session, a, fixed)).is_err(),
            "failure latch stops another append"
        );
        let r = reopen(&s);
        assert_eq!(
            view(&r)["verdict"] == "Delivered",
            matches!(fault, Fault::LandThenFail(3)),
            "only landed result replays"
        );
    }
}
#[test]
fn delivery_unknown_restore_and_ended_session_do_not_manufacture_delivery() {
    let (mut s, session) = ready();
    approve(&mut s, &session, ad_hoc_minimum(), 1);
    check(&mut s, &session, clean());
    block_on(s.fixture_delivery_record(Record::FindingsUnknown {
        machine: "fixture".into(),
    }))
    .unwrap();
    assert_ne!(view(&s)["verdict"], "Delivered");
    assert_eq!(view(&s)["placement_eligible"], false);
    assert_eq!(view(&reopen(&s))["findings_unknown"], true);
    let mut m = clean();
    m.inbound = Measured::Missing;
    check(&mut s, &session, m);
    assert_eq!(
        view(&s)["findings_unknown"],
        true,
        "missing evidence cannot become empty findings"
    );
    check(&mut s, &session, clean());
    assert_eq!(view(&s)["verdict"], "Delivered");
    block_on(s.fixture_delivery_record(Record::SubsequentPlacement {
        machine: "fixture".into(),
        session: session.clone(),
    }))
    .unwrap();
    let before = view(&s);
    let a = s.delivery_authority(&session, "fixture").unwrap();
    s.end_inference_sessions();
    assert!(block_on(s.delivery_check(&session, a, clean())).is_err());
    assert_eq!(
        view(&s),
        before,
        "ending preserves the last verdict and subsequent placement evidence"
    );
    assert_eq!(
        view(&reopen(&s))["subsequent_placement_sessions"],
        json!([session])
    );
}

#[test]
fn delivery_incomplete_attempt_retains_completed_verdict_and_placement_through_replay() {
    for unavailable in [Measured::Failed, Measured::Missing] {
        for finding in [false, true] {
            let (mut s, session) = ready();
            let (d, mut m) = stopped();
            approve(&mut s, &session, d, 1);
            if !finding && let Measured::Value(facts) = &mut m.services {
                facts[0].state = ServiceState::Running;
            }
            check(&mut s, &session, m.clone());
            let completed = view(&s)["last_check"].clone();
            let verdict = if finding {
                "handed over with findings"
            } else {
                "Delivered"
            };
            assert_eq!(view(&s)["verdict"], verdict);
            block_on(s.fixture_delivery_record(Record::SubsequentPlacement {
                machine: "fixture".into(),
                session: session.clone(),
            }))
            .unwrap();
            m.services = unavailable.clone();
            check(&mut s, &session, m);
            let attempt = view(&s)["last_check"].clone();
            assert_eq!(attempt["result"]["complete"], false);
            s.end_inference_sessions();
            for shown in [view(&s), view(&reopen(&s))] {
                assert_eq!(
                    shown["verdict"], verdict,
                    "incomplete attempt retains the completed verdict"
                );
                assert_eq!(
                    shown["last_completed_check"], completed,
                    "completed evidence is retained separately"
                );
                assert_eq!(
                    shown["last_check"], attempt,
                    "partial observations remain distinct"
                );
                assert_eq!(
                    shown["last_check"]["measurements"]["services"],
                    serde_json::to_value(&unavailable).unwrap()
                );
                assert_eq!(
                    shown["subsequent_placement_sessions"],
                    json!([session]),
                    "incomplete attempt cannot retire placement evidence"
                );
                assert_eq!(
                    shown["findings"].as_array().unwrap().len(),
                    usize::from(finding),
                    "incomplete attempt cannot clear a finding"
                );
                assert_eq!(
                    shown["verdict_is_historical"], true,
                    "retained verdict is historical, not a final demonstration"
                );
                assert_eq!(
                    shown["placement_eligible"], false,
                    "historical result grants no current placement eligibility"
                );
            }
        }
    }
}

#[test]
fn delivery_historical_clean_check_never_hides_unknown_new_findings_or_changed_authority() {
    for change in ["first", "unknown", "new_finding", "amendment", "class"] {
        let (mut s, session) = ready();
        let (d, mut m) = stopped();
        approve(&mut s, &session, d.clone(), 1);
        if let Measured::Value(facts) = &mut m.services {
            facts[0].state = ServiceState::Running;
        }
        if change != "first" {
            check(&mut s, &session, m.clone());
            assert_eq!(view(&s)["verdict"], "Delivered");
        }
        match change {
            "unknown" => block_on(s.fixture_delivery_record(Record::FindingsUnknown {
                machine: "fixture".into(),
            }))
            .unwrap(),
            "new_finding" => m.sshd_posture = Measured::Value(false),
            "amendment" => approve(&mut s, &session, d, 2),
            "class" => {
                s.propose_requirements(
                    &session,
                    2,
                    Proposal::TightenClass {
                        machine: "fixture".into(),
                        class: crate::dispatch::MachineClass::MultiTenant,
                    },
                    &Tool::Done {
                        machine: "fixture".into(),
                    },
                )
                .unwrap();
                block_on(s.approve_requirements(&session, "fixture", 2)).unwrap();
            }
            "first" => {}
            _ => unreachable!(),
        }
        m.services = Measured::Failed;
        check(&mut s, &session, m);
        s.end_inference_sessions();
        for shown in [view(&s), view(&reopen(&s))] {
            assert_ne!(
                shown["verdict"], "Delivered",
                "{change}: historical clean result is not current authority"
            );
            assert_eq!(shown["last_check"]["result"]["complete"], false);
            if change == "first" {
                assert!(shown["last_completed_check"].is_null());
            }
            if change == "unknown" {
                assert_eq!(shown["findings_unknown"], true);
            }
            if change == "new_finding" {
                assert_eq!(shown["verdict"], "handed over with findings");
                assert_eq!(shown["findings"][0]["field"], "sshd_posture");
            }
            if matches!(change, "amendment" | "class") {
                assert_eq!(shown["completed_declaration_current"], false);
            }
        }
    }
}

#[test]
fn delivery_complete_recheck_retires_placement_and_preserves_historical_notes_until_then() {
    let (mut s, session) = ready();
    let (mut d, mut m) = stopped();
    let enabled = service("enabled", Lifecycle::EnabledSurvivesReboot);
    if let Field::Value(services) = &mut d.services {
        services.push(enabled.clone());
    }
    if let Measured::Value(facts) = &mut m.services {
        facts[0].state = ServiceState::StoppedSinceRestart;
        facts.push(ServiceFact {
            service: enabled,
            state: ServiceState::EnabledRestartNotDemonstrated,
            running_after_last_placement: false,
        });
    }
    approve(&mut s, &session, d, 1);
    check(&mut s, &session, m.clone());
    let completed = view(&s)["last_check"].clone();
    assert_eq!(completed["result"]["notes"].as_array().unwrap().len(), 2);
    block_on(s.fixture_delivery_record(Record::SubsequentPlacement {
        machine: "fixture".into(),
        session: session.clone(),
    }))
    .unwrap();
    let mut missing = m.clone();
    missing.services = Measured::Missing;
    check(&mut s, &session, missing);
    assert_eq!(
        view(&reopen(&s))["last_completed_check"]["result"]["notes"],
        completed["result"]["notes"],
        "historical Delivered keeps both applicable evidence labels"
    );
    check(&mut s, &session, m.clone());
    assert_eq!(
        view(&s)["verdict"],
        "handed over with findings",
        "complete stopped post-placement read cannot reuse a historical pass"
    );
    if let Measured::Value(facts) = &mut m.services {
        facts[0].state = ServiceState::Running;
        facts[0].running_after_last_placement = true;
    }
    check(&mut s, &session, m);
    let shown = view(&reopen(&s));
    assert_eq!(shown["verdict"], "Delivered");
    assert_eq!(shown["subsequent_placement_sessions"], json!([]));
    assert_eq!(shown["last_completed_check"], shown["last_check"]);
    assert_eq!(shown["verdict_is_historical"], false);
}

#[test]
fn delivery_recorded_placing_session_cannot_be_omitted_by_later_evidence() {
    let (mut s, session) = ready();
    let mut d = ad_hoc_minimum();
    let service = service("volatile", Lifecycle::RunningAtDelivery);
    d.services = Field::Value(vec![service.clone()]);
    approve(&mut s, &session, d, 1);
    let mut m = clean();
    m.services = Measured::Value(vec![ServiceFact {
        service,
        state: ServiceState::StoppedSinceRestart,
        running_after_last_placement: false,
    }]);
    check(&mut s, &session, m.clone());
    assert_eq!(view(&s)["verdict"], "Delivered");
    block_on(s.fixture_delivery_record(Record::SubsequentPlacement {
        machine: "fixture".into(),
        session: session.clone(),
    }))
    .unwrap();
    check(&mut s, &session, m);
    assert_eq!(
        view(&s)["verdict"],
        "handed over with findings",
        "recorded placing session overrides an omitted qualification"
    );
    assert_eq!(view(&reopen(&s))["findings"][0]["class"], "lifecycle");
}
#[test]
fn delivery_application_names_are_exact_unique_per_machine_and_credential_safe() {
    let (mut s, session) = ready();
    approve(&mut s, &session, ad_hoc_minimum(), 1);
    for name in ["Hermes", "hermes", "<img src=x onerror=alert(1)>"] {
        block_on(s.record_application(&session, "fixture", name.into())).unwrap();
    }
    assert!(block_on(s.record_application(&session, "fixture", "Hermes".into())).is_err());
    block_on(s.fixture_delivery_record(Record::Application {
        machine: "fixture-other".into(),
        name: "Hermes".into(),
    }))
    .unwrap();
    block_on(
        s.set_inference_account(crate::credential::InferenceAccountCredential::new(
            b"fixture-private-account".to_vec(),
        )),
    )
    .unwrap();
    let files = s.storage.files();
    assert!(
        block_on(s.record_application(&session, "fixture", "fixture-private-account".into()))
            .is_err()
    );
    assert_eq!(
        files,
        s.storage.files(),
        "credential-bearing name never appended"
    );
    assert_eq!(
        view(&reopen(&s))["applications"],
        json!(["Hermes", "hermes", "<img src=x onerror=alert(1)>"])
    );
}

#[test]
fn delivery_display_rechecks_current_credential_holdings() {
    let (mut s, session) = ready();
    approve(&mut s, &session, ad_hoc_minimum(), 1);
    block_on(s.record_application(&session, "fixture", "later-held-fixture-value".into())).unwrap();
    block_on(
        s.set_inference_account(crate::credential::InferenceAccountCredential::new(
            b"later-held-fixture-value".to_vec(),
        )),
    )
    .unwrap();
    let shown = view(&s);
    assert!(
        shown.get("applications").is_none(),
        "current credential holdings withhold a previously safe application name"
    );
    assert!(!shown.to_string().contains("later-held-fixture-value"));
}
fn craft(s: &mut Store<MemoryStorage>, event: Value) {
    let n = s.next;
    let previous = hex::encode(s.previous.0);
    let nonce = [44u8; 12];
    let bytes = serde_json::to_vec(&event).unwrap();
    let ciphertext = cipher(&s.key.0)
        .encrypt(
            &nonce.into(),
            Payload {
                msg: &bytes,
                aad: record_aad(&s.id, EVENT, n, &previous).as_bytes(),
            },
        )
        .unwrap();
    let record = RecordJson {
        id: s.id.clone(),
        kind: EVENT.into(),
        number: n,
        previous,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    block_on(
        s.storage
            .write(&n.to_string(), &serde_json::to_vec(&record).unwrap()),
    )
    .unwrap();
}
#[test]
fn delivery_replay_rejects_fabricated_results_authority_schema_and_session() {
    for change in [
        "result",
        "authority",
        "machine",
        "session",
        "extra",
        "missing",
    ] {
        let (mut s, session) = ready();
        approve(&mut s, &session, ad_hoc_minimum(), 1);
        let a = s.delivery_authority(&session, "fixture").unwrap();
        let m = clean();
        let result = crate::delivery::evaluate(&a.declaration, a.class, &m, &[], false);
        let mut event = json!({"delivery":{"kind":"check","check":{"session":session,"authority":a,"measurements":m,"result":result}}});
        let c = &mut event["delivery"]["check"];
        match change {
            "result" => c["result"]["delivered"] = json!(false),
            "authority" => c["authority"]["requirements"] = json!(100),
            "machine" => c["authority"]["machine"] = json!("fixture-other"),
            "session" => c["session"] = json!("foreign-session"),
            "extra" => c["extra"] = json!(true),
            "missing" => {
                c["measurements"].as_object_mut().unwrap().remove("inbound");
            }
            _ => unreachable!(),
        }
        let number = s.next;
        craft(&mut s, event);
        let why = block_on(unlock(
            MemoryStorage::with_files(s.storage.files()),
            &Fixed,
            pass(),
        ))
        .err()
        .expect("fabricated delivery must refuse replay");
        assert!(why.contains(&format!("record {number}")), "{change}: {why}");
    }
}
#[test]
fn delivery_forbidden_amendments_refuse_approval_append_and_replay() {
    for private in [false, true] {
        let (mut s, session) = ready();
        approve(&mut s, &session, ad_hoc_minimum(), 1);
        // The operator's existing tightening path journals the class change first.
        s.propose_requirements(
            &session,
            2,
            Proposal::TightenClass {
                machine: "fixture".into(),
                class: crate::dispatch::MachineClass::MultiTenant,
            },
            &Tool::Done {
                machine: "fixture".into(),
            },
        )
        .unwrap();
        block_on(s.approve_requirements(&session, "fixture", 2)).unwrap();
        let mut d = ad_hoc_minimum();
        if private {
            d.key_material.permitted = Field::Value(vec![Material {
                kind: MaterialKind::PrivateNonSpendable,
                r#where: "/private".into(),
            }]);
        } else {
            d.key_material.spendable = Field::Value(true);
        }
        let proposal = Proposal::Declaration {
            machine: "fixture".into(),
            declaration: d,
        };
        assert!(
            s.propose_requirements(
                &session,
                3,
                proposal.clone(),
                &Tool::Done {
                    machine: "fixture".into()
                }
            )
            .is_err(),
            "forbidden amendment refuses before approval"
        );
        // Bypass retention to exercise the approval and append defenses independently.
        s.pending_requirements.insert(
            session.clone(),
            goals::Pending {
                candidate: 3,
                proposal: proposal.clone(),
            },
        );
        let files = s.storage.files();
        assert!(block_on(s.approve_requirements(&session, "fixture", 3)).is_err());
        assert_eq!(files, s.storage.files());
        let record = ApprovalRecord {
            session,
            candidate: 3,
            access: crate::dispatch::Access::ad_hoc(),
            proposal,
        };
        assert!(
            block_on(
                s.setup_record(crate::dispatch::SetupRecord::Requirements(Box::new(
                    record.clone()
                )))
            )
            .is_err(),
            "append revalidates class/material"
        );
        let n = s.next;
        craft(&mut s, json!({"setup":{"requirements":record}}));
        let why = block_on(unlock(
            MemoryStorage::with_files(s.storage.files()),
            &Fixed,
            pass(),
        ))
        .err()
        .expect("forbidden amendment replay");
        assert!(why.contains(&format!("record {n}")), "{why}");
    }
}

#[test]
fn delivery_bound_machine_cannot_borrow_another_machines_complete_requirements() {
    let (mut s, session) = ready();
    approve(&mut s, &session, ad_hoc_minimum(), 1);
    block_on(
        s.setup_record(crate::dispatch::SetupRecord::Requirements(Box::new(
            ApprovalRecord {
                session: "independent-contract".into(),
                candidate: 2,
                access: crate::dispatch::Access::ad_hoc(),
                proposal: Proposal::Declaration {
                    machine: "fixture-other".into(),
                    declaration: ad_hoc_minimum(),
                },
            },
        ))),
    )
    .unwrap();
    let before = s.storage.files();
    assert!(
        s.delivery_authority(&session, "fixture-other").is_err(),
        "a fully declared foreign machine is still outside this session"
    );
    let a = s.journaled_delivery_authority("fixture-other").unwrap();
    assert!(
        block_on(s.delivery_check(&session, a, clean())).is_err(),
        "foreign machine receives no delivery authority"
    );
    assert_eq!(s.storage.files(), before);
}

fn forbidden_amendment(boundary: &str) {
    let (mut s, session) = ready();
    approve(&mut s, &session, ad_hoc_minimum(), 1);
    block_on(
        s.setup_record(crate::dispatch::SetupRecord::Requirements(Box::new(
            ApprovalRecord {
                session: session.clone(),
                candidate: 2,
                access: crate::dispatch::Access::ad_hoc(),
                proposal: Proposal::TightenClass {
                    machine: "fixture".into(),
                    class: crate::dispatch::MachineClass::MultiTenant,
                },
            },
        ))),
    )
    .unwrap();
    let mut d = ad_hoc_minimum();
    d.key_material.spendable = Field::Value(true);
    let proposal = Proposal::Declaration {
        machine: "fixture".into(),
        declaration: d,
    };
    let record = ApprovalRecord {
        session: session.clone(),
        candidate: 3,
        access: crate::dispatch::Access::ad_hoc(),
        proposal: proposal.clone(),
    };
    match boundary {
        "approval" => {
            s.pending_requirements.insert(
                session.clone(),
                goals::Pending {
                    candidate: 3,
                    proposal,
                },
            );
            assert!(
                block_on(s.approve_requirements(&session, "fixture", 3)).is_err(),
                "forbidden material refuses at approval"
            );
        }
        "append" => assert!(
            block_on(s.setup_record(crate::dispatch::SetupRecord::Requirements(Box::new(record))))
                .is_err(),
            "forbidden material refuses at append"
        ),
        "replay" => {
            craft(&mut s, json!({"setup":{"requirements":record}}));
            assert!(
                block_on(unlock(
                    MemoryStorage::with_files(s.storage.files()),
                    &Fixed,
                    pass()
                ))
                .is_err(),
                "forbidden material refuses at replay"
            );
        }
        _ => unreachable!(),
    }
}
#[test]
fn delivery_material_is_rechecked_at_approval() {
    forbidden_amendment("approval");
}
#[test]
fn delivery_material_is_rechecked_at_append() {
    forbidden_amendment("append");
}
#[test]
fn delivery_material_is_rechecked_at_replay() {
    forbidden_amendment("replay");
}
