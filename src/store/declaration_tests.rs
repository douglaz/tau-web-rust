use super::*;
use crate::declaration::{Declaration, Proposal};
use crate::dispatch::{ClassAnswer, MachineClass, Operation, Requester, Resource, Target};
use crate::goals::Tool;
use crate::store::inference::tests::{Fixed, ready};

fn session(s: &Store<MemoryStorage>) -> String {
    s.sessions[0].identity.clone()
}
fn start() -> Store<MemoryStorage> {
    let mut s = ready();
    let identity = session(&s);
    block_on(s.enter_goal(
        &identity,
        "Run a web service on port 443 contacting api.example".into(),
        None,
    ))
    .unwrap();
    block_on(s.accept_mode(&identity, Mode::NoBrief)).unwrap();
    s
}
fn minimum() -> Value {
    serde_json::to_value(crate::declaration::ad_hoc_minimum()).unwrap()
}
fn proposal(d: Value) -> Proposal {
    Proposal::parse(&json!({"kind":"declaration","machine":"fixture","declaration":d})).unwrap()
}
fn done() -> Tool {
    Tool::Done {
        machine: "fixture".into(),
    }
}
fn propose(s: &mut Store<MemoryStorage>, p: Proposal) {
    s.propose_requirements(&session(s), 42, p, &done()).unwrap();
}
fn reopen(s: &Store<MemoryStorage>) -> Result<Store<MemoryStorage>, String> {
    block_on(unlock(
        MemoryStorage::with_files(s.storage.files()),
        &Fixed,
        LocalPassphrase::new(b"inference fixture passphrase".to_vec()),
    ))
}

#[test]
fn declaration_minimum_is_the_complete_pinned_contract() {
    let d = minimum();
    assert_eq!(
        d,
        json!({"version":2,"listeners":{"inbound":[{"proto":"tcp","port":22,"from":"any"}],"outbound":[]},"services":[],"key_material":{"spendable":false,"permitted":[]},"drift_checks":[],"required":[],"default_credentials":"none"})
    );
    assert!(
        crate::TENANT_PROFILES
            .iter()
            .find(|(n, _)| *n == "ad-hoc")
            .unwrap()
            .1
            .contains("delivery-declaration-v1.md")
    );
}

#[test]
fn declaration_requires_every_field_and_nested_member_without_filling_defaults() {
    for pointer in [
        "/version",
        "/listeners",
        "/listeners/inbound",
        "/listeners/outbound",
        "/services",
        "/key_material",
        "/key_material/spendable",
        "/key_material/permitted",
        "/drift_checks",
        "/required",
        "/default_credentials",
        "/listeners/inbound/0/proto",
        "/listeners/inbound/0/port",
        "/listeners/inbound/0/from",
    ] {
        let mut d = minimum();
        let (parent, field) = pointer.rsplit_once('/').unwrap();
        d.pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(Declaration::parse(&d).is_err(), "missing {pointer}");
    }
    for (pointer, value) in [
        ("/version", json!(1)),
        ("/version", json!("2")),
        ("/version", json!(3)),
        ("/services", json!(null)),
        ("/listeners/inbound", json!({})),
        ("/listeners/inbound/0/port", json!(0)),
        ("/listeners/inbound/0/port", json!(65536)),
        ("/listeners/inbound/0/proto", json!("tcp;id")),
        ("/listeners/inbound/0/from", json!("internet")),
        ("/listeners/inbound/0", json!(["tcp", 22, "any"])),
        ("/key_material", json!([false, []])),
    ] {
        let mut d = minimum();
        *d.pointer_mut(pointer).unwrap() = value;
        assert!(Declaration::parse(&d).is_err(), "{pointer}: {d}");
    }
    let mut extra = minimum();
    extra["command"] = json!("id");
    assert!(Declaration::parse(&extra).is_err());
}

#[test]
fn declaration_checks_cannot_claim_bundle_provenance_or_supply_procedures() {
    for field in ["required", "drift_checks"] {
        for check in [
            json!("id"),
            json!({"name":"invented","command":"id","expect":"root"}),
            json!({"name":"invented","check":"id","expect":"root","provenance":"signed_bundle"}),
        ] {
            let mut d = minimum();
            d[field] = json!([check]);
            let s = start();
            let files = s.storage.files();
            assert!(Declaration::parse(&d).is_err());
            assert_eq!(s.storage.files(), files);
        }
    }
}

#[test]
fn declaration_service_scope_name_and_account_grammars_are_independent() {
    let service = |name: &str, scope: Value| json!({"name":name,"scope":scope,"lifecycle":"running-at-delivery"});
    let parse = |s: Value| {
        let mut d = minimum();
        d["services"] = json!([s]);
        Declaration::parse(&d)
    };
    for name in ["_ok", "hermes", "a:b.c-d_1"] {
        assert!(parse(service(name, json!({"kind":"system"}))).is_ok());
    }
    assert!(parse(service(&"a".repeat(247), json!({"kind":"system"}))).is_ok());
    for name in [
        "",
        "-option",
        "a@b",
        "a.service",
        "a.socket",
        "a.timer",
        "a;id",
        "a\n",
        "a b",
        "$(id)",
        &"a".repeat(248),
    ] {
        assert!(
            parse(service(name, json!({"kind":"system"}))).is_err(),
            "{name:?}"
        );
    }
    for account in ["a", "_", "user-name_1", &"a".repeat(32)] {
        assert!(parse(service("hermes", json!({"kind":"user","account":account}))).is_ok());
    }
    for account in ["", "1user", "Upper", "a.b", "a;id", &"a".repeat(33)] {
        assert!(
            parse(service("hermes", json!({"kind":"user","account":account}))).is_err(),
            "{account:?}"
        );
    }
    for scope in [
        json!({"kind":"system","account":"user"}),
        json!({"kind":"user"}),
        json!({}),
        json!("system"),
        json!(["system"]),
    ] {
        assert!(parse(service("hermes", scope)).is_err());
    }
    let mut missing = service("hermes", json!({"kind":"system"}));
    missing.as_object_mut().unwrap().remove("scope");
    assert!(parse(missing).is_err());
}

#[test]
fn declaration_pending_is_not_authority_and_exact_approval_survives_reopen() {
    let mut s = start();
    let identity = session(&s);
    let mut d = minimum();
    d["listeners"]["inbound"]
        .as_array_mut()
        .unwrap()
        .push(json!({"proto":"tcp","port":443,"from":"any"}));
    d["listeners"]["outbound"] = json!([{"proto":"tcp","host":"api.example","port":443}]);
    d["services"] = json!([{"name":"hermes","scope":{"kind":"user","account":"operator"},"lifecycle":"enabled-survives-reboot"}]);
    let p = proposal(d.clone());
    let before = s.storage.files();
    propose(&mut s, p.clone());
    assert_eq!(s.storage.files(), before);
    assert!(s.dispatch.check_installation("fixture").is_err());
    assert!(s.check_tool(&identity, &done()).is_err());
    assert!(block_on(s.approve_requirements("wrong-session", "fixture", 42)).is_err());
    assert!(block_on(s.approve_requirements(&identity, "fixture-other", 42)).is_err());
    assert!(block_on(s.approve_requirements(&identity, "fixture", 43)).is_err());
    assert_eq!(s.storage.files(), before);
    block_on(s.approve_requirements(&identity, "fixture", 42)).unwrap();
    assert_eq!(
        s.dispatch.approved_entries["fixture"].declaration.as_ref(),
        Some(&Declaration::parse(&d).unwrap())
    );
    assert!(s.dispatch.check_installation("fixture").is_ok());
    let committed = s.storage.files();
    assert!(block_on(s.approve_requirements(&identity, "fixture", 42)).is_err());
    assert_eq!(s.storage.files(), committed);
    let r = reopen(&s).unwrap();
    assert_eq!(r.dispatch.setup_view(), s.dispatch.setup_view());
    assert!(r.sessions.is_empty() && r.pending_requirements.is_empty());
}

#[test]
fn declaration_unspecified_and_explicit_empty_remain_distinct_after_replay() {
    for field in [
        "/listeners/inbound",
        "/listeners/outbound",
        "/services",
        "/key_material/spendable",
        "/key_material/permitted",
        "/drift_checks",
        "/required",
        "/default_credentials",
    ] {
        let mut s = start();
        let mut d = minimum();
        *d.pointer_mut(field).unwrap() = json!("unspecified");
        // Schema meaning is independent of the ad-hoc proposal's signed minimum.
        assert!(Declaration::parse(&d).is_ok());
        if field != "/key_material/spendable" {
            let mut empty = minimum();
            *empty.pointer_mut(field).unwrap() = json!([]);
            assert_eq!(
                serde_json::to_value(Declaration::parse(&empty).unwrap()).unwrap(),
                empty
            );
        }
        if field == "/listeners/inbound" {
            let before = s.storage.files();
            assert!(
                s.propose_requirements(&session(&s), 42, proposal(d), &done())
                    .is_err()
            );
            assert!(s.pending_requirements.is_empty());
            assert_eq!(s.storage.files(), before);
            continue;
        }
        propose(&mut s, proposal(d.clone()));
        block_on(s.approve_requirements(&session(&s), "fixture", 42)).unwrap();
        let r = reopen(&s).unwrap();
        assert_eq!(
            serde_json::to_value(
                r.dispatch.approved_entries["fixture"]
                    .declaration
                    .as_ref()
                    .unwrap()
            )
            .unwrap(),
            d
        );
    }
}

#[test]
fn declaration_ad_hoc_minimum_is_preserved_at_proposal_approval_and_append() {
    for inbound in [
        json!([]),
        json!([{"proto":"tcp","port":443,"from":"any"}]),
        json!([{"proto":"udp","port":22,"from":"any"}]),
        json!([{"proto":"tcp","port":22,"from":"peers"}]),
        json!([{"proto":"tcp","port":22,"from":"none"}]),
        json!("unspecified"),
    ] {
        let mut s = start();
        let identity = session(&s);
        let mut d = minimum();
        d["listeners"]["inbound"] = inbound;
        // These remain valid schema values. They cannot be additions to ad-hoc's minimum.
        assert!(Declaration::parse(&d).is_ok());
        let p = proposal(d.clone());
        let before = s.storage.files();
        assert_eq!(
            s.propose_requirements(&identity, 42, p.clone(), &done()),
            Err("ad-hoc declaration must preserve signed inbound minimum".into()),
            "proposal must retain TCP/22/from-any: {d}"
        );
        assert!(s.pending_requirements.is_empty());
        assert!(s.pending_requirements_view(&identity).is_null());
        assert_eq!(s.storage.files(), before);

        // Independently inject impossible transient state to check approval's own revalidation.
        s.pending_requirements.insert(
            identity.clone(),
            goals::Pending {
                candidate: 42,
                proposal: p.clone(),
            },
        );
        assert!(s.pending_requirements_view(&identity).is_null());
        assert_eq!(
            block_on(s.approve_requirements(&identity, "fixture", 42)),
            Err("ad-hoc declaration must preserve signed inbound minimum".into())
        );
        assert_eq!(s.storage.files(), before);
        assert!(s.dispatch.approved_entries["fixture"].declaration.is_none());

        let record = crate::declaration::ApprovalRecord {
            session: identity,
            candidate: 42,
            access: crate::dispatch::Access::ad_hoc(),
            proposal: p,
        };
        assert!(
            block_on(
                s.setup_record(crate::dispatch::SetupRecord::Requirements(Box::new(
                    record.clone()
                )))
            )
            .is_err()
        );
        assert_eq!(s.storage.files(), before);
    }
}

#[test]
fn declaration_replay_refuses_ad_hoc_minimum_removed_from_new_records() {
    for inbound in [
        json!([]),
        json!("unspecified"),
        json!([{"proto":"tcp","port":443,"from":"any"}]),
        json!([{"proto":"tcp","port":22,"from":"peers"}]),
    ] {
        let s = start();
        let mut d = minimum();
        d["listeners"]["inbound"] = inbound;
        let record = json!({"session":session(&s),"candidate":42,"access":{"model":"maintained","profile":"ad-hoc","revision":3},"proposal":{"kind":"declaration","machine":"fixture","declaration":d}});
        raw_record(&s, &json!({"setup":{"requirements":record}}));
        let files = s.storage.files();
        assert!(
            reopen(&s)
                .err()
                .expect("approval dropping minimum must refuse replay")
                .contains("ad-hoc declaration must preserve signed inbound minimum")
        );
        assert_eq!(s.storage.files(), files);
    }
}

#[test]
fn declaration_tightening_is_operator_approved_one_way_and_preserves_answer() {
    let mut s = start();
    let identity = session(&s);
    propose(
        &mut s,
        Proposal::TightenClass {
            machine: "fixture".into(),
            class: MachineClass::MultiTenant,
        },
    );
    assert_eq!(
        s.dispatch.approved_entries["fixture"].class,
        Some(MachineClass::SinglePurpose)
    );
    block_on(s.approve_requirements(&identity, "fixture", 42)).unwrap();
    let r = reopen(&s).unwrap();
    let m = &r.dispatch.approved_entries["fixture"];
    assert_eq!(m.answer, Some(ClassAnswer::No));
    assert_eq!(m.class, Some(MachineClass::MultiTenant));
    assert_eq!(m.requirements.len(), 1);
    for class in [MachineClass::SinglePurpose, MachineClass::MultiTenant] {
        assert!(
            s.propose_requirements(
                &identity,
                43,
                Proposal::TightenClass {
                    machine: "fixture".into(),
                    class
                },
                &done()
            )
            .is_err()
        );
    }
    let mut d = minimum();
    d["key_material"]["spendable"] = json!(true);
    assert!(
        s.propose_requirements(&identity, 44, proposal(d), &done())
            .is_err()
    );
    let mut d = minimum();
    d["key_material"]["permitted"] = json!([{"kind":"private-non-spendable","where":"/vault/key"}]);
    assert!(
        s.propose_requirements(&identity, 44, proposal(d), &done())
            .is_err()
    );
}

#[test]
fn declaration_failures_and_landed_errors_release_no_authority_or_continuation() {
    for fault in [
        Fault::Fail(1),
        Fault::Fail(2),
        Fault::Fail(3),
        Fault::LandThenFail(3),
    ] {
        let mut s = start();
        propose(&mut s, proposal(minimum()));
        s.storage.fault(fault);
        assert!(block_on(s.approve_requirements(&session(&s), "fixture", 42)).is_err());
        assert!(s.dispatch.approved_entries["fixture"].declaration.is_none());
        assert!(s.pending_requirements.is_empty());
        assert!(s.failed.is_some());
        let r = reopen(&s).unwrap();
        assert_eq!(
            r.dispatch.approved_entries["fixture"].declaration.is_some(),
            matches!(fault, Fault::LandThenFail(3))
        );
        assert!(r.pending_requirements.is_empty() && r.sessions.is_empty());
    }
}

#[test]
fn declaration_session_end_cancels_and_late_approval_cannot_resume() {
    let mut s = start();
    let identity = session(&s);
    propose(&mut s, proposal(minimum()));
    let before = s.storage.files();
    s.end_inference_sessions();
    assert!(s.pending_requirements.is_empty());
    assert!(block_on(s.approve_requirements(&identity, "fixture", 42)).is_err());
    assert_eq!(s.storage.files(), before);
}

#[test]
fn declaration_pending_blocks_new_inference_preparation_without_an_intent() {
    let mut s = start();
    let identity = session(&s);
    propose(&mut s, proposal(minimum()));
    let before = s.storage.files();
    assert!(
        block_on(s.inference_prepare(
            &identity,
            crate::inference::Intent::AccountRead {
                call: 0,
                session: identity.clone()
            },
            "https://127.0.0.1",
            json!({})
        ))
        .is_err()
    );
    assert_eq!(s.storage.files(), before);
}

#[test]
fn declaration_current_credentials_are_checked_before_retention_rendering_and_commit() {
    let mut s = start();
    let identity = session(&s);
    let mut d = minimum();
    d["services"] = json!([{"name":"fixture-account-private-value","scope":{"kind":"system"},"lifecycle":"running-at-delivery"}]);
    let before = s.storage.files();
    assert!(
        s.propose_requirements(&identity, 42, proposal(d), &done())
            .is_err()
    );
    assert!(s.pending_requirements.is_empty());
    assert_eq!(s.storage.files(), before);
    // A credential newly held while the card waits invalidates both its rendering and commit.
    let mut d = minimum();
    d["services"] = json!([{"name":"new-private-value","scope":{"kind":"system"},"lifecycle":"running-at-delivery"}]);
    propose(&mut s, proposal(d));
    s.inference.account = Some(crate::credential::InferenceAccountCredential::new(
        b"new-private-value".to_vec(),
    ));
    assert!(s.pending_requirements_view(&identity).is_null());
    assert!(block_on(s.approve_requirements(&identity, "fixture", 42)).is_err());
    assert!(s.pending_requirements.is_empty());
    assert_eq!(s.storage.files(), before);
}

#[test]
fn declaration_tightening_refuses_incompatible_existing_material_and_failed_writes() {
    for private in [false, true] {
        let mut s = start();
        let mut d = minimum();
        if private {
            d["key_material"]["permitted"] =
                json!([{"kind":"private-non-spendable","where":"/vault/key"}]);
        } else {
            d["key_material"]["spendable"] = json!(true);
        }
        propose(&mut s, proposal(d));
        block_on(s.approve_requirements(&session(&s), "fixture", 42)).unwrap();
        let before = s.storage.files();
        assert!(
            s.propose_requirements(
                &session(&s),
                43,
                Proposal::TightenClass {
                    machine: "fixture".into(),
                    class: MachineClass::MultiTenant
                },
                &done()
            )
            .is_err()
        );
        assert_eq!(s.storage.files(), before);
    }
    for fault in [
        Fault::Fail(1),
        Fault::Fail(2),
        Fault::Fail(3),
        Fault::LandThenFail(3),
    ] {
        let mut s = start();
        propose(
            &mut s,
            Proposal::TightenClass {
                machine: "fixture".into(),
                class: MachineClass::MultiTenant,
            },
        );
        s.storage.fault(fault);
        assert!(block_on(s.approve_requirements(&session(&s), "fixture", 42)).is_err());
        assert_eq!(
            s.dispatch.approved_entries["fixture"].class,
            Some(MachineClass::SinglePurpose)
        );
        let r = reopen(&s).unwrap();
        assert_eq!(
            r.dispatch.approved_entries["fixture"].class,
            Some(if matches!(fault, Fault::LandThenFail(3)) {
                MachineClass::MultiTenant
            } else {
                MachineClass::SinglePurpose
            })
        );
    }
}

#[test]
fn declaration_exec_and_job_admission_and_command_append_require_each_current_fact() {
    use crate::harness::Journal;
    for missing in ["class", "access", "declaration", "pending"] {
        let mut s = start();
        s.fixture_requirements("fixture");
        let identity = session(&s);
        if missing == "pending" {
            propose(&mut s, proposal(minimum()));
        } else {
            let m = s.dispatch.approved_entries.get_mut("fixture").unwrap();
            match missing {
                "class" => m.class = None,
                "access" => m.approved.access = None,
                _ => m.declaration = None,
            }
        }
        let before = s.storage.files();
        for tool in [
            Tool::Exec {
                machine: "fixture".into(),
                command: "printf read".into(),
            },
            Tool::Job {
                machine: "fixture".into(),
                job: crate::goals::Job::FetchArtifact,
                arguments: json!({}),
            },
        ] {
            assert!(s.check_tool(&identity, &tool).is_err(), "{missing}");
        }
        let entry = crate::harness::Entry {
            machine: "fixture".into(),
            command: b"install anything".to_vec(),
            provenance: None,
        };
        let approval = crate::dispatch::Approval::HarnessPin {
            machine: "fixture".into(),
            fingerprint: "SHA256:fixture".into(),
        };
        assert!(block_on(s.check("fixture")).is_err());
        assert!(block_on(s.append(&entry, &approval)).is_err());
        assert_eq!(s.storage.files(), before);
        // Typed reads and inference preflight can still obtain a proposal.
        if missing != "pending" {
            assert!(s.check_goal_start(&identity).is_ok());
        }
    }
}

#[test]
fn declaration_create_guard_covers_aliases_requesters_and_append_without_contact() {
    let (storage, mut s, extra) = crate::dispatch::typed_tests::fresh();
    s.dispatch
        .approved_entries
        .get_mut("fixture")
        .unwrap()
        .declaration = None;
    let before = storage.files();
    for target in [
        Target::Entry("fixture".into()),
        Target::AllocationIndex(0),
        Target::AllocationIndex(extra),
        Target::VendorMachine("vendor-7".into()),
    ] {
        for requester in [
            Requester::Session,
            Requester::Operator,
            Requester::HarnessFlow,
        ] {
            let mut request = crate::dispatch::typed_tests::request(Operation::Create);
            request.target = target.clone();
            request.requester = requester;
            let a = request.approved.as_mut().unwrap();
            a.target = target.clone();
            a.requester = requester;
            assert!(s.dispatch.check_request(&request).is_err());
            assert!(block_on(s.operation(&request)).is_err());
        }
    }
    assert_eq!(storage.files(), before);
    assert_eq!(
        s.dispatch.resolve(&Target::AllocationIndex(extra)),
        Some(Resource::Entry("fixture".into()))
    );
}

#[test]
fn declaration_create_refuses_each_missing_fact_at_adapter_and_append_for_every_requester() {
    for missing in ["class", "access", "declaration"] {
        let (storage, mut s, _) = crate::dispatch::typed_tests::bound_fresh();
        let machine = s.dispatch.approved_entries.get_mut("fixture").unwrap();
        match missing {
            "class" => machine.class = None,
            "access" => machine.approved.access = None,
            _ => machine.declaration = None,
        }
        let before = storage.files();
        for requester in [
            Requester::Session,
            Requester::Operator,
            Requester::HarnessFlow,
        ] {
            let mut request =
                crate::dispatch::typed_tests::bound_request(&s, Operation::Create, "fixture");
            request.requester = requester;
            request.approved.as_mut().unwrap().requester = requester;
            let caller = (requester == Requester::Session).then_some(request.session.as_str());
            let mut vendor = crate::dispatch::fixture::Vendor::default();
            assert!(
                matches!(
                    block_on(vendor.run(&mut s, caller, &request)),
                    Err(OperationError::Policy(
                        crate::dispatch::RequestRefusal::InstallationFacts { .. }
                    ))
                ),
                "{missing} {requester:?}"
            );
            assert!(matches!(
                block_on(s.operation(&request)),
                Err(OperationError::Policy(
                    crate::dispatch::RequestRefusal::InstallationFacts { .. }
                ))
            ));
            assert!(vendor.received.is_empty());
            assert_eq!(storage.files(), before);
        }
    }
}

fn raw_record(s: &Store<MemoryStorage>, value: &Value) {
    // An independently authenticated impossible record, to exercise replay rather than entry.
    let number = s.next;
    let nonce = [91; 12];
    let previous = hex::encode(s.previous.0);
    let ciphertext = cipher(&s.key.0)
        .encrypt(
            &nonce.into(),
            Payload {
                msg: &serde_json::to_vec(value).unwrap(),
                aad: record_aad(&s.id, EVENT, number, &previous).as_bytes(),
            },
        )
        .unwrap();
    let record = RecordJson {
        id: s.id.clone(),
        kind: EVENT.into(),
        number,
        previous,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    block_on(
        s.storage
            .write(&number.to_string(), &serde_json::to_vec(&record).unwrap()),
    )
    .unwrap();
}

#[test]
fn declaration_replay_checks_schema_semantics_profile_and_candidate_uniqueness() {
    for variant in [
        "version",
        "missing",
        "scope",
        "account",
        "checks",
        "class",
        "profile",
        "array",
        "duplicate",
    ] {
        let mut s = start();
        propose(&mut s, proposal(minimum()));
        block_on(s.approve_requirements(&session(&s), "fixture", 42)).unwrap();
        let mut r =
            serde_json::to_value(&s.dispatch.approved_entries["fixture"].requirements[0]).unwrap();
        if variant != "duplicate" {
            r["candidate"] = json!(43);
        }
        match variant {
            "version" => r["proposal"]["declaration"]["version"] = json!(1),
            "missing" => {
                r["proposal"]["declaration"]
                    .as_object_mut()
                    .unwrap()
                    .remove("required");
            }
            "scope" => {
                r["proposal"]["declaration"]["services"] = json!([{"name":"app","scope":{"kind":"system","account":"root"},"lifecycle":"running-at-delivery"}])
            }
            "account" => {
                r["proposal"]["declaration"]["services"] = json!([{"name":"app","scope":{"kind":"user","account":"1bad"},"lifecycle":"running-at-delivery"}])
            }
            "checks" => {
                r["proposal"]["declaration"]["required"] =
                    json!([{"name":"procedure","check":"do-not-echo-this-procedure","expect":"ok"}])
            }
            "class" => {
                r["proposal"] =
                    json!({"kind":"tighten_class","machine":"fixture","class":"single_purpose"})
            }
            "profile" => r["access"]["revision"] = json!(99),
            "array" => {
                r["proposal"]["declaration"]["listeners"]["inbound"][0] = json!(["tcp", 22, "any"])
            }
            _ => {}
        }
        raw_record(&s, &json!({"setup":{"requirements":r}}));
        let why = reopen(&s)
            .err()
            .expect("invalid canonical requirements must refuse replay");
        assert!(
            why.contains(&format!("record {}", s.next)),
            "{variant}: {why}"
        );
        assert!(!why.contains("do-not-echo-this-procedure"));
    }
}

#[test]
fn declaration_replay_rechecks_material_against_the_effective_tightened_class() {
    let mut s = start();
    propose(
        &mut s,
        Proposal::TightenClass {
            machine: "fixture".into(),
            class: MachineClass::MultiTenant,
        },
    );
    block_on(s.approve_requirements(&session(&s), "fixture", 42)).unwrap();
    let mut d = minimum();
    d["key_material"]["spendable"] = json!(true);
    let record = json!({"setup":{"requirements":{"session":session(&s),"candidate":43,"access":{"model":"maintained","profile":"ad-hoc","revision":3},"proposal":{"kind":"declaration","machine":"fixture","declaration":d}}}});
    raw_record(&s, &record);
    assert!(reopen(&s).is_err());
}

#[test]
fn declaration_loop_checks_end_after_approval_before_invoking_the_companion() {
    struct EndAtApproval {
        ended: bool,
        dispatched: bool,
    }
    impl crate::goals::Driver for EndAtApproval {
        fn ending(&self) -> bool {
            self.ended
        }
        async fn turn(&mut self, _: &Value) -> Value {
            json!({"call":42,"finished":true,"status":200,"body":json!({"choices":[{"message":{"tool_calls":[{"name":"done","arguments":{"machine":"fixture"}}],"proposal":{"kind":"declaration","machine":"fixture","declaration":minimum()}}}]}).to_string()})
        }
        async fn proposal(&mut self, _: u64, _: Proposal, _: &Tool) -> Result<(), String> {
            self.ended = true;
            Ok(())
        }
        async fn tool(&mut self, _: &Tool) -> Value {
            self.dispatched = true;
            json!({"done":true})
        }
    }
    let mut driver = EndAtApproval {
        ended: false,
        dispatched: false,
    };
    let goal = crate::goals::Goal {
        session: "session".into(),
        text: "goal".into(),
        source: crate::goals::SOURCE.into(),
        document_source: None,
    };
    assert_eq!(
        block_on(crate::goals::run(&mut driver, &goal, "fixture", None))["refused"],
        "sessions ended"
    );
    assert!(!driver.dispatched);
}
