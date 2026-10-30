use super::*;
use crate::dispatch::typed_tests::{bound_fresh, bound_request, reopen};

fn approval(store: &Store<MemoryStorage>, reset: &str) -> Approval {
    let r = bound_request(store, Operation::Reinstall, "fixture");
    Approval {
        reset: reset.into(),
        entry: "fixture".into(),
        session: r.session,
        facts: r.facts,
        modes: vec![],
    }
}
fn ready() -> (MemoryStorage, Store<MemoryStorage>, u32) {
    let (storage, mut s, extra) = bound_fresh();
    s.synthetic_dedicated_path("fixture").unwrap();
    (storage, s, extra)
}
fn read(s: &mut Store<MemoryStorage>, a: &Approval, confirmed: bool) -> u64 {
    let activation = block_on(s.dedicated_activation(&a.session, &a.entry)).unwrap();
    block_on(s.dedicated_activation_read(&a.session, &a.entry, activation, confirmed)).unwrap()
}
#[test]
fn independent_dedicated_approvals_keep_original_checks_and_actual_reset_boundary() {
    let (_, mut s, _) = ready();
    let a = approval(&s, "reset-a");
    let b = approval(&s, "reset-b");
    let ai = block_on(s.approve_reinstall(a.clone())).unwrap();
    let bi = block_on(s.approve_reinstall(b.clone())).unwrap();
    let before = s.reinstall_approvals();
    // Ordinary visibility delivers no suspension/end to this same worker-owned authority.
    let generation = s.authority.generation();
    assert_eq!(s.reinstall_approvals(), before);
    assert_eq!(s.authority.generation(), generation);
    assert!(block_on(s.dispatch_reinstall(ai, &a.reset, &a.entry, 0)).is_err());
    let no = read(&mut s, &a, false);
    assert!(block_on(s.dispatch_reinstall(ai, &a.reset, &a.entry, no)).is_err());
    block_on(s.withdraw_reinstall(bi, &b.reset, &b.entry)).unwrap();
    assert_eq!(s.reinstall_approvals()[0]["state"], "standing");
    assert_eq!(s.reinstall_approvals()[1]["state"], "withdrawn");
    let yes = read(&mut s, &a, true);
    let pending = block_on(s.dispatch_reinstall(ai, &a.reset, &a.entry, yes)).unwrap();
    let mut sends = 0;
    s.dedicated_reset_current(&pending).unwrap();
    sends += 1;
    assert!(s.dedicated_reset_current(&pending).is_err());
    assert_eq!(sends, 1);
    assert_eq!(s.dispatch.current_installations["fixture"], 1);
    assert!(block_on(s.withdraw_reinstall(ai, &a.reset, &a.entry)).is_err());
    assert!(block_on(s.dispatch_reinstall(bi, &b.reset, &b.entry, yes)).is_err());
}
#[test]
fn stale_read_changed_binding_failed_withdrawal_and_rendering_end_do_not_invent_consent() {
    let (storage, mut s, extra) = ready();
    let a = approval(&s, "reset-a");
    let ai = block_on(s.approve_reinstall(a.clone())).unwrap();
    let yes = read(&mut s, &a, true);
    let newer = block_on(s.dedicated_activation(&a.session, &a.entry)).unwrap();
    assert!(block_on(s.dispatch_reinstall(ai, &a.reset, &a.entry, yes)).is_err());
    let yes = block_on(s.dedicated_activation_read(&a.session, &a.entry, newer, true)).unwrap();
    let pending = block_on(s.dispatch_reinstall(ai, &a.reset, &a.entry, yes)).unwrap();
    s.authority.suspend();
    s.authority.revalidated().unwrap();
    assert!(
        s.dedicated_reset_current(&pending).is_err(),
        "old actual-send continuation never revives"
    );
    let mut successor = reopen(&storage, extra);
    successor.synthetic_dedicated_path("fixture").unwrap();
    assert_eq!(successor.reinstall_approvals()[0]["state"], "dispatched");
    assert!(successor.dedicated_reset_current(&pending).is_err());
    let (storage, mut s, extra) = ready();
    let a = approval(&s, "undispatched");
    let ai = block_on(s.approve_reinstall(a.clone())).unwrap();
    storage.fault(Fault::Fail(1));
    assert!(block_on(s.withdraw_reinstall(ai, &a.reset, &a.entry)).is_err());
    assert_eq!(
        s.reinstall_approvals()[0]["state"],
        "standing",
        "failed append is not withdrawal"
    );
    s.end_inference_sessions();
    assert_eq!(s.reinstall_approvals()[0]["state"], "no longer usable");
    assert_eq!(s.reinstall_approvals()[0]["withdrawal_offer"], false);
    let mut successor = reopen(&storage, extra);
    assert_eq!(
        successor.reinstall_approvals()[0]["state"],
        "no longer usable"
    );
    successor.synthetic_dedicated_path("fixture").unwrap();
    assert!(block_on(successor.withdraw_reinstall(ai, &a.reset, &a.entry)).is_err());
    assert!(block_on(successor.dispatch_reinstall(ai, &a.reset, &a.entry, 0)).is_err());
}
#[test]
fn dedicated_approval_is_unavailable_to_stage_one_path_and_failed_read_never_dispatches() {
    let (storage, mut s, _) = bound_fresh();
    let a = approval(&s, "reset");
    assert!(block_on(s.approve_reinstall(a.clone())).is_err());
    s.synthetic_dedicated_path("fixture").unwrap();
    let ai = block_on(s.approve_reinstall(a.clone())).unwrap();
    let activation = block_on(s.dedicated_activation(&a.session, &a.entry)).unwrap();
    storage.fault(Fault::Fail(1));
    assert!(block_on(s.dedicated_activation_read(&a.session, &a.entry, activation, true)).is_err());
    assert!(block_on(s.dispatch_reinstall(ai, &a.reset, &a.entry, s.next - 1)).is_err());
    assert_eq!(s.dispatch.current_installations["fixture"], 0);
}

#[test]
fn prior_activation_and_separate_dispositions_do_not_replace_original_approval_checks() {
    for continuation in [
        crate::dispatch::Continuation::AsIfDone,
        crate::dispatch::Continuation::AsIfNotDone,
        crate::dispatch::Continuation::DestructiveReinstall,
    ] {
        let (_, mut s, _) = ready();
        let a = approval(&s, "original-reset");
        let old = block_on(s.dedicated_activation(&a.session, &a.entry)).unwrap();
        let ai = block_on(s.approve_reinstall(a.clone())).unwrap();
        let old_read =
            block_on(s.dedicated_activation_read(&a.session, &a.entry, old, true)).unwrap();
        assert!(
            block_on(s.dispatch_reinstall(ai, &a.reset, &a.entry, old_read)).is_err(),
            "activation must be newer than approval"
        );
        let request = bound_request(&s, Operation::Reset, "fixture");
        let call = block_on(s.operation(&request)).unwrap();
        let yes = read(&mut s, &a, true);
        assert!(
            block_on(s.dispatch_reinstall(ai, &a.reset, &a.entry, yes)).is_err(),
            "normal unresolved barrier still applies"
        );
        block_on(s.dispose(crate::dispatch::Disposition {
            machine: a.entry.clone(),
            calls: vec![call.call],
            continuation,
            uncertainty: "effect unknown".into(),
        }))
        .unwrap();
        assert_eq!(
            s.reinstall_approvals()[0]["state"],
            "standing",
            "disposition does not withdraw independent approval"
        );
        let yes = read(&mut s, &a, true);
        let pending = block_on(s.dispatch_reinstall(ai, &a.reset, &a.entry, yes)).unwrap();
        s.dedicated_reset_current(&pending).unwrap();
    }
}

#[test]
fn dedicated_replay_requires_original_binding_and_canonical_object_shape() {
    let (_, mut s, _) = ready();
    let a = approval(&s, "shape-reset");
    let event = Event::DedicatedReinstall(Record::Approve(a.clone()));
    let n = s.next;
    let seal = |value: &Value| {
        use aes_gcm::aead::{Aead, Payload};
        use base64::Engine;
        let previous = hex::encode(s.previous.0);
        let nonce = [77; 12];
        let ciphertext = cipher(&s.key.0)
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &serde_json::to_vec(value).unwrap(),
                    aad: record_aad(&s.id, EVENT, n, &previous).as_bytes(),
                },
            )
            .unwrap();
        serde_json::to_vec(&RecordJson {
            id: s.id.clone(),
            kind: EVENT.into(),
            number: n,
            previous,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
        .unwrap()
    };
    let mut value = serde_json::to_value(&event).unwrap();
    assert!(s.open(n, &seal(&value)).is_ok());
    value["dedicated_reinstall"]["approve"] = json!([
        a.reset.clone(),
        a.entry.clone(),
        a.session.clone(),
        a.facts.clone(),
        a.modes.clone()
    ]);
    assert!(
        s.open(n, &seal(&value)).is_err(),
        "positional approval is not its journal object"
    );
    let mut wrong = a;
    wrong.session = "not-the-rendering-session".into();
    assert!(s.replay_reinstall(n, &Record::Approve(wrong)).is_err());
}
