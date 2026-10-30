use super::*;
use crate::clock::{Observation, Pair, Rate, TICKS};
use crate::inference::{self, Journal as InferenceJournal, Transport};
use crate::inference_limits::Confirmed;
use crate::store::inference::tests::{Fake, candidate, ready, request};

fn observation(seconds: u64) -> Observation {
    let p = Pair {
        monotonic: seconds * TICKS,
        wall: seconds * TICKS,
    };
    let r = Rate {
        numerator: 1,
        denominator: 1,
    };
    Observation {
        sent: p,
        received: p,
        earliest: seconds,
        latest: seconds,
        minimum: r,
        maximum: r,
    }
}

#[test]
fn original_expiry_fences_real_inference_send_and_ends_only_affected_session() {
    let mut store = ready();
    let other = block_on(store.bind("fixture-other")).unwrap();
    store
        .consume_confirmed_limits(
            Confirmed {
                session: other.clone(),
                account_record: store.inference.account_record.unwrap(),
                choice_generation: "synthetic-other".into(),
                profile: "inference-profile-fixture-v1".into(),
                cap_hundredths: 10,
                unit: "account units".into(),
                lifetime_seconds: 1800,
            },
            observation(100),
        )
        .unwrap();
    let mut transport = Fake::default();
    let infer = |store: &mut Store<MemoryStorage>, transport: &mut Fake, machine: &str, now| {
        let mut request = request();
        request["machine"] = machine.into();
        block_on(inference::infer(
            store,
            transport,
            "https://127.0.0.1:1",
            Some(&candidate()),
            &request,
            || now,
        ))
    };
    assert_eq!(
        infer(&mut store, &mut transport, "fixture", 100)["finished"],
        true
    );
    transport.key_id = Some("other-key-id");
    assert_eq!(
        infer(&mut store, &mut transport, "fixture-other", 100)["finished"],
        true
    );
    assert_eq!(
        infer(&mut store, &mut transport, "fixture", 999)["finished"],
        true
    );
    let before = transport.seen.len();
    assert_eq!(
        infer(&mut store, &mut transport, "fixture", 1000)["refused"],
        "session expired"
    );
    assert_eq!(
        transport.seen.len(),
        before,
        "no new probe, mint or completion at expiry equality"
    );
    assert!(store.sessions[0].given.borrow().is_empty());
    assert_eq!(
        infer(&mut store, &mut transport, "fixture-other", 1000)["finished"],
        true
    );
    assert_eq!(store.limit_state(&other)["original_expiry"], 1900);
    assert!(
        !store.inference.ended,
        "the Store and other session remain unlocked"
    );
}

#[test]
fn repaired_never_transmitted_mint_keeps_original_call_body_and_consumed_slot() {
    let mut store = ready();
    let session = store.sessions[0].identity.clone();
    let mut transport = Fake::default();
    block_on(inference::send(
        &mut store,
        &mut transport,
        &session,
        inference::Intent::AccountRead {
            call: 0,
            session: session.clone(),
        },
        "https://127.0.0.1:1",
        Value::Null,
    ))
    .unwrap();
    let (cap, expires) = block_on(store.mint_bounds(&session, 100)).unwrap();
    let (call, original) = block_on(store.inference_prepare(
        &session,
        inference::Intent::Mint {
            call: 0,
            session: session.clone(),
            cap: cap.clone(),
            expires,
            evidence: None,
        },
        "https://127.0.0.1:1",
        json!({"cap":cap,"expires":expires}),
    ))
    .unwrap();
    let original_body = original.body.to_string();
    let record_count = store.records().count();
    store.authority.suspend();
    store.suspend_clocks();
    assert!(!block_on(store.authorize(&original, 200)));
    assert!(store.take_unsent_mint(call).is_err());
    store
        .inference
        .limits
        .borrow_mut()
        .get_mut(&session)
        .unwrap()
        .clock
        .repair(observation(200))
        .unwrap();
    store.authority.revalidated().unwrap();
    assert!(
        !block_on(store.authorize(&original, 200)),
        "old operation generation remains stale after repair"
    );
    let continued = store.take_unsent_mint(call).unwrap();
    assert_eq!(continued.call, call);
    assert_eq!(*continued.body, original_body);
    assert_eq!(
        store.records().count(),
        record_count,
        "same intent, no replacement mint"
    );
    assert!(block_on(store.authorize(&continued, 200)));
    let response = block_on(transport.exchange(&continued)).unwrap();
    let finished = block_on(store.inference_finish(call, &response, &continued)).unwrap();
    assert_eq!(finished.report["finished"], true);
    assert!(
        store.take_unsent_mint(call).is_err(),
        "possible transmission is never retried"
    );
    assert_eq!(transport.seen.iter().filter(|r| r.0 == "/keys").count(), 1);
    assert_eq!(store.limit_state(&session)["original_expiry"], expires);
    store.end_inference_sessions();
    assert!(
        store.take_unsent_mint(call).is_err(),
        "actual end cannot revive"
    );
}

#[test]
fn stale_binding_and_changed_scan_revision_cannot_authorize_a_real_completion() {
    let mut store = ready();
    let live = store.sessions[0].clone();
    let stale = Session::new(
        live.identity.clone(),
        "fixture".into(),
        crate::credential::SshClientKey([0; 32]),
    );
    assert!(store.check_current_session(&live).is_ok());
    assert!(
        store.check_current_session(&stale).is_err(),
        "original ownership, not a copied identity"
    );
    let mut transport = Fake::default();
    crate::store::inference::tests::infer(&mut store, &mut transport);
    let (call, request) = block_on(store.inference_prepare(
        &live.identity,
        inference::Intent::Completion {
            call: 0,
            session: live.identity.clone(),
            key_id: String::new(),
            model: "fixture-model".into(),
            requested_provider: "fixture-provider".into(),
            zdr: true,
        },
        "https://127.0.0.1:1",
        json!({"messages":[{"content":"safe"}]}),
    ))
    .unwrap();
    store.clear_scan_working_copies();
    assert!(
        !block_on(store.authorize(&request, 100)),
        "release is bound to reference revision even when the set is empty"
    );
    assert!(
        store
            .inference_calls()
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["call"] == call && c["state"] == "unresolved")
    );
    assert!(!block_on(store.actionable(&request, 100)));
}

#[test]
fn exact_observed_exhaustion_and_profile_refusals_fence_real_inference_without_renewal() {
    for refusal in [
        None,
        Some("account_balance"),
        Some("key_cap_exhausted"),
        Some("key_expired"),
    ] {
        let mut store = ready();
        let mut transport = Fake {
            cost: Some("0.099999999999999999999999999999999999"),
            ..Fake::default()
        };
        let first = crate::store::inference::tests::infer(&mut store, &mut transport);
        assert!(
            first.get("body").is_some(),
            "nearest eligible below exact cap: {first}"
        );
        let original = store.limit_state(&store.sessions[0].identity);
        transport.cost = Some("0.000000000000000000000000000000000001");
        transport.charge_refusal = refusal;
        let result = crate::store::inference::tests::infer(&mut store, &mut transport);
        let state = store.limit_state(&store.sessions[0].identity);
        assert_eq!(state["original_expiry"], original["original_expiry"]);
        if refusal == Some("account_balance") {
            assert!(
                !store.sessions[0].ended.get(),
                "account balance is a request refusal, never key exhaustion"
            );
        } else {
            assert!(
                store.sessions[0].ended.get(),
                "exact exhaustion or evidenced key refusal ends affected session"
            );
            assert!(result.get("body").is_none());
            let sent = transport.seen.len();
            crate::store::inference::tests::infer(&mut store, &mut transport);
            assert_eq!(
                transport.seen.len(),
                sent,
                "no replacement mint or renewed cap"
            );
        }
    }
}

#[test]
fn confirmed_profile_rates_and_historical_choice_generation_are_not_invented() {
    let mut store = ready();
    let session = store.sessions[0].identity.clone();
    let mut transport = Fake::default();
    crate::store::inference::tests::infer(&mut store, &mut transport);
    let original = store.inference.limits.borrow()[&session].confirmed.clone();
    let mut reopened = block_on(unlock(
        MemoryStorage::with_files(store.storage.files()),
        &crate::store::inference::tests::Fixed,
        LocalPassphrase::new(b"inference fixture passphrase".to_vec()),
    ))
    .unwrap();
    let fresh = block_on(reopened.bind("fixture")).unwrap();
    let mut choice = original.clone();
    choice.session = fresh;
    assert!(
        reopened
            .consume_confirmed_limits(choice.clone(), observation(101))
            .is_err(),
        "choice generation is never reused across replay"
    );
    choice.choice_generation = "new-synthetic-choice".into();
    let mut invalid = observation(101);
    invalid.minimum.numerator = 2;
    invalid.maximum.numerator = 2;
    assert!(
        reopened
            .consume_confirmed_limits(choice.clone(), invalid)
            .is_err(),
        "rates must be evidenced by the selected fixture profile"
    );
    reopened
        .consume_confirmed_limits(choice, observation(101))
        .unwrap();
}

#[test]
fn affected_session_end_retains_original_scan_material_for_another_entitled_session() {
    let mut s = ready();
    let other = block_on(s.bind("fixture-other")).unwrap();
    s.consume_confirmed_limits(
        Confirmed {
            session: other.clone(),
            account_record: s.inference.account_record.unwrap(),
            choice_generation: "synthetic-other-scan".into(),
            profile: "inference-profile-fixture-v1".into(),
            cap_hundredths: 10,
            unit: "account units".into(),
            lifetime_seconds: 1800,
        },
        observation(100),
    )
    .unwrap();
    let secret = b"shared-lifecycle-reference-123456";
    let id = block_on(s.synthetic_scan_fixture(
        "shared service".into(),
        zeroize::Zeroizing::new(secret.to_vec()),
    ))
    .unwrap();
    let material = s.scans.working_material_bytes(&id).unwrap();
    let mut transport = Fake::default();
    crate::store::inference::tests::infer(&mut s, &mut transport);
    transport.key_id = Some("other-shared-key");
    let mut req = request();
    req["machine"] = "fixture-other".into();
    assert_eq!(
        block_on(inference::infer(
            &mut s,
            &mut transport,
            "https://127.0.0.1:1",
            Some(&candidate()),
            &req,
            || 100
        ))["finished"],
        true
    );
    let first = s.sessions[0].identity.clone();
    assert!(
        s.check_session_authority(
            &first,
            Pair {
                monotonic: 1000 * TICKS,
                wall: 1000 * TICKS
            }
        )
        .is_err()
    );
    assert!(
        s.check_session_authority(
            &other,
            Pair {
                monotonic: 1000 * TICKS,
                wall: 1000 * TICKS
            }
        )
        .is_ok()
    );
    assert_eq!(
        s.scans.working_material_bytes(&id).unwrap().as_slice(),
        material.as_slice()
    );
    assert_eq!(
        s.scan_output(&[secret]).unwrap().as_slice(),
        b"<redacted secret: shared service>"
    );
    assert_eq!(
        block_on(inference::infer(
            &mut s,
            &mut transport,
            "https://127.0.0.1:1",
            Some(&candidate()),
            &req,
            || 1000
        ))["finished"],
        true
    );
    s.end_inference_sessions();
    assert!(s.scans.working_material_bytes(&id).is_none());
}

#[test]
fn ended_predecessor_does_not_shadow_fresh_binding_and_original_scan_reload() {
    for reason in ["expiry", "exhaustion", "end"] {
        let mut store = ready();
        let secret = b"original-rebind-scan-value-1234";
        let identity = block_on(
            store.synthetic_scan_fixture("service access".into(), Zeroizing::new(secret.to_vec())),
        )
        .unwrap();
        let name = format!("scan-{identity}");
        let blob = store.storage.files()[&name].clone();
        let material = store.scans.working_material_bytes(&identity).unwrap();
        let old = store.sessions[0].clone();
        assert!(
            block_on(store.bind("fixture")).is_err(),
            "live duplicate refused"
        );
        let mut transport = Fake::default();
        assert_eq!(
            crate::store::inference::tests::infer(&mut store, &mut transport)["finished"],
            true
        );
        {
            let mut limits = store.inference.limits.borrow_mut();
            let limits = limits.get_mut(&old.identity).unwrap();
            match reason {
                "expiry" => {
                    limits.clock.repair(observation(1000)).unwrap();
                }
                "exhaustion" => limits
                    .spent
                    .add(&crate::inference_limits::Decimal::parse("0.10").unwrap()),
                _ => limits.ended = Some("session ended".into()),
            }
        }
        assert!(store.check_current_session(&old).is_err());
        let files = store.storage.files();
        assert!(block_on(store.connection_session_for("fixture", Some(&old))).is_err());
        assert_eq!(store.storage.files(), files);
        assert!(old.ended.get());
        assert!(store.scans.working_material_bytes(&identity).is_none());
        let fresh = block_on(store.bind("fixture")).unwrap();
        assert_ne!(fresh, old.identity);
        store.synthetic_confirm_limits(100).unwrap();
        assert_eq!(
            block_on(store.connection_session("fixture"))
                .unwrap()
                .identity,
            fresh
        );
        assert_eq!(block_on(store.session("fixture")).unwrap(), fresh);
        assert!(store.check_current_session(&old).is_err());
        let files = store.storage.files();
        assert!(block_on(store.connection_session_for("fixture", Some(&old))).is_err());
        assert_eq!(store.storage.files(), files);
        assert!(store.goal(&fresh).is_none());
        assert_eq!(store.limit_state(&fresh)["observed_spend"], "0");
        assert_eq!(
            store
                .scans
                .working_material_bytes(&identity)
                .unwrap()
                .as_slice(),
            material.as_slice()
        );
        assert_eq!(store.storage.files()[&name], blob);
        assert_eq!(
            store
                .protect_output(&json!(std::str::from_utf8(secret).unwrap()))
                .unwrap(),
            "<redacted secret: service access>"
        );
        transport.key_id = Some("fresh-key-id");
        assert_eq!(
            crate::store::inference::tests::infer(&mut store, &mut transport)["finished"],
            true
        );
        assert_eq!(
            store.inference_calls().as_array().unwrap().last().unwrap()["intent"]["completion"]["session"],
            fresh
        );
        assert!(old.given.borrow().is_empty());
    }
}

#[test]
fn established_late_exhaustion_ends_while_clock_and_worker_authority_are_withheld() {
    for usage in [
        "0.10",
        "0.099999999999999999999999999999999999",
        "issuer-exhausted",
    ] {
        let mut store = ready();
        let other = block_on(store.bind("fixture-other")).unwrap();
        store.synthetic_confirm_limits(100).unwrap();
        let live = store.sessions[0].clone();
        let mut transport = Fake {
            cost: Some("0"),
            ..Fake::default()
        };
        assert_eq!(
            crate::store::inference::tests::infer(&mut store, &mut transport)["finished"],
            true
        );
        let (call, request) = block_on(store.inference_prepare(
            &live.identity,
            inference::Intent::Completion {
                call: 0,
                session: live.identity.clone(),
                key_id: String::new(),
                model: "fixture-model".into(),
                requested_provider: "fixture-provider".into(),
                zdr: true,
            },
            "https://127.0.0.1:1",
            json!({"messages":[]}),
        ))
        .unwrap();
        assert!(block_on(store.authorize(&request, 100)));
        transport.cost = Some(if usage == "issuer-exhausted" {
            "0"
        } else {
            usage
        });
        transport.charge_refusal = (usage == "issuer-exhausted").then_some("key_cap_exhausted");
        let response = block_on(transport.exchange(&request)).unwrap();
        store.authority.suspend();
        store.suspend_clocks();
        store.clear_scan_working_copies();
        let report = block_on(store.inference_finish(call, &response, &request)).unwrap();
        assert!(report.report.get("body").is_none());
        assert!(
            store
                .inference_calls()
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["call"] == call && c["state"] == "finished")
        );
        let exhausted = usage != "0.099999999999999999999999999999999999";
        assert_eq!(live.ended.get(), exhausted);
        assert!(
            !store
                .sessions
                .iter()
                .find(|s| s.identity == other)
                .unwrap()
                .ended
                .get()
        );
        assert!(!store.inference.ended);
        assert!(
            store
                .inference_revocations()
                .contains(&"fixture-key-id".into())
        );
        assert!(store.check_current_session(&live).is_err());
        let pair = observation(200).sent;
        let verification = block_on(store.inference_prepare(
            &live.identity,
            inference::Intent::ClockRead {
                call: 0,
                session: live.identity.clone(),
                sent: pair,
            },
            "https://127.0.0.1:1",
            Value::Null,
        ));
        if exhausted {
            assert!(live.given.borrow().is_empty());
            assert!(
                verification.is_err(),
                "ended session cannot obtain verification authority"
            );
        } else {
            let (clock_call, clock_request) = verification.unwrap();
            clock_request.clock_sent.set(Some(pair));
            clock_request.clock_received.set(Some(pair));
            let response = inference::Response {
                status: 200,
                body: Zeroizing::new(br#"{"issuer_time":200}"#.to_vec()),
            };
            let finished =
                block_on(store.inference_finish(clock_call, &response, &clock_request)).unwrap();
            assert!(
                finished.report.get("refused").is_none(),
                "{}",
                finished.report
            );
            store.authority.revalidated().unwrap();
            assert!(store.check_current_session(&live).is_ok());
            assert_eq!(store.limit_state(&live.identity)["original_expiry"], 1000);
        }
    }
}
