use super::*;
use crate::dispatch::*;
use crate::modes::{Lowering, Mode};

struct Fixed;
impl Kdf for Fixed {
    async fn derive(&self, _: LocalPassphrase, _: &Salt) -> Result<WrappingKey, String> {
        Ok(WrappingKey([7; 32]))
    }
}
fn pass() -> LocalPassphrase {
    LocalPassphrase::new(b"mode fixture passphrase".to_vec())
}
fn approved() -> Store<MemoryStorage> {
    let mut store = block_on(create(MemoryStorage::default(), &Fixed, pass())).unwrap();
    block_on(store.seed_backup(allocation::Completion::Skipped)).unwrap();
    block_on(store.approve_setup(fixture_setup())).unwrap();
    for machine in ["fixture", "fixture-other"] {
        block_on(store.answer_class(machine.into(), ClassAnswer::No)).unwrap();
        store.fixture_requirements(machine);
    }
    store
}
fn reopen(store: &Store<MemoryStorage>) -> Store<MemoryStorage> {
    block_on(unlock(
        MemoryStorage::with_files(store.storage.files()),
        &Fixed,
        pass(),
    ))
    .unwrap()
}
fn both() -> (Store<MemoryStorage>, String) {
    let mut store = approved();
    let session = block_on(store.bind_with_modes("fixture", &[Mode::NoArtifactPin])).unwrap();
    block_on(store.accept_mode(&session, Mode::NoBrief)).unwrap();
    (store, session)
}
fn command(machine: &str, session: Option<&str>, bytes: &[u8]) -> Entry {
    Entry {
        machine: machine.into(),
        command: bytes.to_vec(),
        provenance: Some(CommandProvenance {
            target: Target::Entry(machine.into()),
            session: session.map(str::to_string),
            requester: Requester::Session,
        }),
    }
}
fn approval() -> Approval {
    Approval::HarnessPin {
        machine: "fixture".into(),
        fingerprint: "SHA256:fixture".into(),
    }
}
fn request(operation: Operation, session: &str, modes: Vec<Mode>) -> Request {
    let facts = Facts {
        arguments: Default::default(),
        cost_bound: 0,
        bundle_commit: crate::SPEC_COMMIT.into(),
    };
    Request {
        receipt_binding: None,
        target: Target::Entry("fixture".into()),
        operation,
        session: session.into(),
        requester: Requester::Session,
        facts: facts.clone(),
        approved: Some(OperationApproval {
            receipt_binding: None,
            resource: Resource::Entry("fixture".into()),
            target: Target::Entry("fixture".into()),
            operation,
            session: session.into(),
            requester: Requester::Session,
            facts,
            restated_modes: modes,
        }),
    }
}
fn view(store: Store<MemoryStorage>) -> (Value, Value) {
    let mut local = Local::new(MemoryStorage::default(), Fixed);
    local.state = State::Unlocked(Box::new(store));
    (local.report(None), local.inspect())
}

fn acceptance_events(store: &Store<MemoryStorage>) -> Vec<Value> {
    store
        .records()
        .filter_map(|number| {
            let record: RecordJson =
                serde_json::from_slice(&store.storage.files()[&number.to_string()]).unwrap();
            let bytes = cipher(&store.key.0)
                .decrypt(
                    &decode::<12>("nonce", &record.nonce).unwrap().into(),
                    Payload {
                        msg: &URL_SAFE_NO_PAD.decode(&record.ciphertext).unwrap(),
                        aad: record_aad(&record.id, &record.kind, number, &record.previous)
                            .as_bytes(),
                    },
                )
                .unwrap();
            let event: Value = serde_json::from_slice(&bytes).unwrap();
            if event.get("mode_acceptance").is_some()
                || event.pointer("/exposure/accepted_modes").is_some()
            {
                Some(event)
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn mode_acceptance_windows_and_atomic_binding() {
    for first in [vec![], vec![Mode::NoArtifactPin]] {
        let mut store = approved();
        let session = block_on(store.bind_with_modes("fixture", &first)).unwrap();
        let files = store.storage.files();
        assert!(block_on(store.bind_with_modes("fixture", &[Mode::NoArtifactPin])).is_err());
        assert!(block_on(store.accept_mode(&session, Mode::NoArtifactPin)).is_err());
        assert!(block_on(store.bind_with_modes("fixture-other", &[Mode::NoBrief])).is_err());
        assert!(
            block_on(
                store.bind_with_modes("fixture-other", &[Mode::NoArtifactPin, Mode::NoArtifactPin])
            )
            .is_err()
        );
        assert_eq!(store.storage.files(), files);
        let mut store = reopen(&store);
        let files = store.storage.files();
        assert!(
            block_on(store.bind_with_modes("fixture", &[Mode::NoArtifactPin])).is_err(),
            "late installation acceptance"
        );
        assert!(block_on(store.accept_mode(&session, Mode::NoBrief)).is_err());
        assert!(store.sessions().is_empty());
        assert_eq!(store.storage.files(), files);
        let session = block_on(store.bind("fixture")).unwrap();
        block_on(store.append(&command("fixture", Some(&session), b"echo ok"), &approval()))
            .unwrap();
        let files = store.storage.files();
        assert!(
            block_on(store.accept_mode(&session, Mode::NoBrief)).is_err(),
            "late conduct acceptance"
        );
        assert!(block_on(store.accept_mode("unknown", Mode::NoBrief)).is_err());
        assert_eq!(store.storage.files(), files);
    }
    let (mut store, session) = both();
    let files = store.storage.files();
    assert!(block_on(store.accept_mode(&session, Mode::NoBrief)).is_err());
    assert_eq!(store.storage.files(), files);
    for fault in [Fault::Fail(1), Fault::Fail(3), Fault::LandThenFail(3)] {
        let mut store = approved();
        store.storage.fault(fault);
        assert!(block_on(store.bind_with_modes("fixture", &[Mode::NoArtifactPin])).is_err());
        assert!(store.sessions().is_empty());
        assert!(store.mode_acceptances().is_empty());
        let restored = reopen(&store);
        assert!(restored.sessions().is_empty());
        assert_eq!(
            restored.installation_unpinned("fixture"),
            matches!(fault, Fault::LandThenFail(_))
        );
        assert_eq!(
            restored.exposure_ledger().len(),
            usize::from(matches!(fault, Fault::LandThenFail(_)))
        );
    }
}

#[test]
fn mode_trust_display_lists_every_mode_without_artifact_claims() {
    let (store, _) = both();
    let replayed = reopen(&store);
    let expected = json!([
        "An installation with no artifact pin",
        "Acting on a goal with no brief"
    ]);
    let (report, inspection) = view(store);
    let artifact: toml::Value = toml::from_str(
        crate::BUNDLE
            .iter()
            .find(|(name, _)| *name == "artifact-alpine.toml")
            .unwrap()
            .1,
    )
    .unwrap();
    let mut needles = vec![
        artifact["bootstrap"]["url"].as_str().unwrap(),
        artifact["bootstrap"]["sha256"].as_str().unwrap(),
    ];
    for key in artifact["packages"]["keys"].as_array().unwrap() {
        needles.extend([
            key["name"].as_str().unwrap(),
            key["sha256"].as_str().unwrap(),
        ]);
    }
    for surface in [report, inspection] {
        assert_eq!(
            surface["sessions"][0]["standing_modes"], expected,
            "trust display completeness"
        );
        assert_eq!(
            surface["installations"],
            json!([{"machine":"fixture","installation":"unpinned"}])
        );
        assert_eq!(surface["mode_acceptances"].as_array().unwrap().len(), 2);
        assert!(
            surface["mode_acceptances"]
                .as_array()
                .unwrap()
                .iter()
                .all(|a| a["standing"] == true)
        );
        let text = surface.to_string();
        for needle in &needles {
            assert!(!text.contains(needle), "artifact claim leaked: {needle}");
        }
        for field in ["hash", "signer", "sha256"] {
            assert!(!text.contains(&format!("\"{field}\"")));
        }
    }
    let (report, inspection) = view(replayed);
    for surface in [report, inspection] {
        assert_eq!(
            surface["installations"],
            json!([{"machine":"fixture","installation":"unpinned"}])
        );
        assert_eq!(surface["sessions"], json!([]));
        assert_eq!(surface["mode_acceptances"][0]["standing"], true);
        assert_eq!(surface["mode_acceptances"][1]["standing"], false);
    }
    let (store, _) = both();
    let mut replayed = reopen(&store);
    block_on(replayed.bind("fixture")).unwrap();
    assert_eq!(
        replayed.sessions()[0]["standing_modes"],
        json!(["An installation with no artifact pin"])
    );
}

#[test]
fn mode_restatement_uses_target_set_at_destroy_and_reinstall() {
    for operation in [Operation::Destroy, Operation::Reinstall] {
        let (mut store, session) = both();
        let mut vendor = fixture::Vendor::default();
        for wrong in [
            vec![],
            vec![Mode::NoArtifactPin],
            vec![Mode::NoBrief],
            vec![Mode::NoArtifactPin, Mode::NoBrief, Mode::NoBrief],
            vec![Mode::NoBrief, Mode::NoArtifactPin],
        ] {
            let req = request(operation, &session, wrong);
            let files = store.storage.files();
            assert!(
                block_on(vendor.run(&mut store, Some(&session), &req)).is_err(),
                "adapter bypassed restatement"
            );
            assert!(
                block_on(store.operation(&req)).is_err(),
                "direct store bypassed restatement"
            );
            assert!(vendor.received.is_empty());
            assert_eq!(store.storage.files(), files);
        }
        let req = request(
            operation,
            &session,
            vec![Mode::NoArtifactPin, Mode::NoBrief],
        );
        let id = block_on(vendor.run(&mut store, Some(&session), &req)).unwrap();
        assert_eq!(
            vendor.received[0].restated_modes,
            vec![Mode::NoArtifactPin, Mode::NoBrief]
        );
        assert_eq!(
            store.dispatch.typed_calls[&id].intent.restated_modes,
            vec![Mode::NoArtifactPin, Mode::NoBrief]
        );
        assert_eq!(
            store.dispatch.typed_calls[&id]
                .intent
                .approved
                .restated_modes,
            vec![Mode::NoArtifactPin, Mode::NoBrief]
        );
        let replayed = reopen(&store);
        assert_eq!(
            replayed.dispatch.typed_calls[&id].intent.restated_modes,
            vec![Mode::NoArtifactPin, Mode::NoBrief]
        );
        assert_eq!(
            replayed.standing_modes("fixture"),
            vec![Mode::NoArtifactPin]
        );
    }
    for requester in [Requester::Operator, Requester::HarnessFlow] {
        for operation in [Operation::Destroy, Operation::Reinstall] {
            for live in [true, false] {
                let (mut store, _) = both();
                if !live {
                    store = reopen(&store);
                }
                let expected = if live {
                    vec![Mode::NoArtifactPin, Mode::NoBrief]
                } else {
                    vec![Mode::NoArtifactPin]
                };
                let mut vendor = fixture::Vendor::default();
                let mut req = request(operation, "outside-session", expected.clone());
                req.requester = requester;
                req.approved.as_mut().unwrap().requester = requester;
                for wrong in [
                    vec![],
                    vec![Mode::NoBrief],
                    vec![Mode::NoArtifactPin, Mode::NoBrief, Mode::NoBrief],
                ] {
                    req.approved.as_mut().unwrap().restated_modes = wrong;
                    let files = store.storage.files();
                    assert!(
                        block_on(vendor.run(&mut store, None, &req)).is_err(),
                        "non-session requester bypassed restatement"
                    );
                    assert!(block_on(store.operation(&req)).is_err());
                    assert!(vendor.received.is_empty());
                    assert_eq!(store.storage.files(), files);
                }
                if !live {
                    req.approved.as_mut().unwrap().restated_modes =
                        vec![Mode::NoArtifactPin, Mode::NoBrief];
                    assert!(
                        block_on(vendor.run(&mut store, None, &req)).is_err(),
                        "ended conduct mode is extra"
                    );
                }
                req.approved.as_mut().unwrap().restated_modes = expected.clone();
                let id = block_on(vendor.run(&mut store, None, &req)).unwrap();
                assert_eq!(
                    store.dispatch.typed_calls[&id].intent.restated_modes,
                    expected
                );
                assert_eq!(
                    vendor.received[0].restated_modes,
                    if live {
                        vec![Mode::NoArtifactPin, Mode::NoBrief]
                    } else {
                        vec![Mode::NoArtifactPin]
                    }
                );
            }
        }
    }
    for operation in [Operation::Create, Operation::Reset, Operation::Read] {
        let (mut store, session) = both();
        let files = store.storage.files();
        assert!(
            block_on(store.operation(&request(
                operation,
                &session,
                vec![Mode::NoArtifactPin, Mode::NoBrief]
            )))
            .is_err()
        );
        assert_eq!(store.storage.files(), files);
        let intent = block_on(store.operation(&request(operation, &session, vec![]))).unwrap();
        assert!(intent.restated_modes.is_empty());
        assert!(
            !serde_json::to_value(&intent)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("restated_modes")
        );
        assert!(
            reopen(&store).dispatch.typed_calls[&intent.call]
                .intent
                .restated_modes
                .is_empty()
        );
    }
}

#[test]
fn mode_lowering_refuses_each_form_before_intent_and_records_it() {
    let refused = [
        (
            "echo 'SigLevel = Never' >> /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        (
            "sed -i 's/^SigLevel.*/SigLevel = Never/' /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        ("LocalFileSigLevel = Never", Lowering::SignatureLevelNever),
        (
            "RemoteFileSigLevel=DatabaseNever",
            Lowering::SignatureLevelNever,
        ),
        (
            "printf 'SigLevel=PackageNever'",
            Lowering::SignatureLevelNever,
        ),
        (
            "SigLevel = Optional TrustAll",
            Lowering::UntrustedRepository,
        ),
        (
            "cat > /etc/pacman.conf <<'EOF'\n[omarchy]\nSigLevel = Optional TrustAll\nEOF",
            Lowering::UntrustedRepository,
        ),
        (
            "SigLevel = Required PackageTrustAll",
            Lowering::UntrustedRepository,
        ),
        ("SigLevel = DatabaseTrustAll", Lowering::UntrustedRepository),
        (
            "echo SigLevel = 'Never' > /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        (
            "echo SigLevel = Required 'PackageTrustAll' > /etc/pacman.conf",
            Lowering::UntrustedRepository,
        ),
        (
            "echo 'SigLevel' = Never >> /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        (
            "echo SigLevel '=' DatabaseNever >> /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        (
            "echo SigLevel=\"Never\" >> /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        (
            "echo SigLevel = \"Optional TrustAll\" >> /etc/pacman.conf",
            Lowering::UntrustedRepository,
        ),
        (
            "echo SigLevel = Optional 'TrustAll' >> /etc/pacman.conf",
            Lowering::UntrustedRepository,
        ),
        (
            "echo SigLevel = \\Never >> /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        (
            "echo SigLevel = $'Never' >> /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        (
            "printf '%s\\n' 'SigLevel = Required' 'SigLevel = Never'",
            Lowering::SignatureLevelNever,
        ),
        (
            "printf '%s\\n' 'SigLevel = Required' 'SigLevel = TrustAll'",
            Lowering::UntrustedRepository,
        ),
        (
            "printf '%s\\n' '[options]' 'LocalFileSigLevel = Required' 'SigLevel = Never' > /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        (
            "printf '%s\\n' '[options]' 'LocalFileSigLevel = Required' 'SigLevel = Optional TrustAll' > /etc/pacman.conf",
            Lowering::UntrustedRepository,
        ),
        (
            "echo SigLevel = Required SigLevel = Never",
            Lowering::SignatureLevelNever,
        ),
        (
            "echo \"SigLevel = Required\" \"RemoteFileSigLevel = DatabaseNever\"",
            Lowering::SignatureLevelNever,
        ),
        (
            "echo SigLevel = Required 'RemoteFileSigLevel' = Never",
            Lowering::SignatureLevelNever,
        ),
        (
            "echo SigLevel = {Never,} >> /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        (
            "echo SigLevel = $x Never >> /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        (
            "echo SigLevel = \"$x\" Never >> /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        (
            "echo SigLevel = `true` Never >> /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        (
            "echo SigLevel = $(true) TrustAll >> /etc/pacman.conf",
            Lowering::UntrustedRepository,
        ),
        (
            "echo SigLevel$x = Never >> /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        (
            "echo SigLevel ${x} = Never >> /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        (
            "echo SigLevel `true` = Never >> /etc/pacman.conf",
            Lowering::SignatureLevelNever,
        ),
        (
            "echo SigLevel $(true) = TrustAll >> /etc/pacman.conf",
            Lowering::UntrustedRepository,
        ),
        (
            "echo SigLevel = Required; echo Never",
            Lowering::SignatureLevelNever,
        ),
        ("echo SigLevel = 'Never'more", Lowering::SignatureLevelNever),
        ("echo /SigLevel=Never", Lowering::SignatureLevelNever),
    ];
    let mut refused: Vec<_> = refused
        .into_iter()
        .map(|(text, form)| (text.to_string(), form))
        .collect();
    // Every supported delimiter can surround a directive, the equals sign, or a value.
    for (open, close) in [
        ("'", "'"),
        ("\"", "\""),
        ("$'", "'"),
        ("$\"", "\""),
        ("\\", ""),
    ] {
        for text in [
            format!("echo {open}SigLevel{close} = Never"),
            format!("echo SigLevel {open}={close} Never"),
            format!("echo SigLevel = {open}DatabaseNever{close}"),
            format!("echo SigLevel = Required {open}PackageTrustAll{close}"),
        ] {
            let form = if text.contains("PackageTrustAll") {
                Lowering::UntrustedRepository
            } else {
                Lowering::SignatureLevelNever
            };
            refused.push((text, form));
        }
    }
    let (mut store, session) = both();
    for (bytes, form) in refused {
        let before = store.records().end;
        let calls = store.dispatch.call_ids();
        let commands = store.commands().to_vec();
        let record = SignatureRefusal {
            machine: "fixture".into(),
            form,
        };
        let result = block_on(store.append(
            &command("fixture", Some(&session), bytes.as_bytes()),
            &approval(),
        ));
        assert_eq!(store.commands(), commands, "no intent was journaled");
        assert_eq!(
            store.dispatch.call_ids(),
            calls,
            "no dispatch call was added"
        );
        assert_eq!(
            result,
            Err(AppendRefusal::SignatureLowering(record.clone())),
            "{bytes}"
        );
        assert_eq!(
            store.records().end,
            before + 1,
            "exactly one refusal record"
        );
        assert_eq!(store.signature_refusals().last(), Some(&record));
        assert_eq!(
            reopen(&store).signature_refusals(),
            store.signature_refusals()
        );
    }
    let expected = serde_json::to_value(store.signature_refusals()).unwrap();
    let (_, inspection) = view(store);
    assert_eq!(inspection["signature_refusals"], expected);
    for bytes in [
        format!(
            "cat > /etc/pacman.conf <<'EOF'\n{}\nEOF",
            include_str!("../../tests/vectors/pacman-c8ccc368.conf")
        ),
        "pacman -Syu --noconfirm".into(),
        "echo ok; exit 7".into(),
        "# SigLevel = Never".into(),
        "SigLevel = Nevermore".into(),
        "OtherSigLevel = Never".into(),
        "SigLevel = Optional".into(),
        "siglevel = Never".into(),
        "SigLevel = UntrustedRepository".into(),
        "echo SigLevel = 'Optional' >> /etc/pacman.conf".into(),
        "echo \"SigLevel = Required DatabaseOptional\" >> /etc/pacman.conf".into(),
        "echo SigLevel = 'Nevermore'".into(),
        "printf '%s\\n' 'SigLevel = Required DatabaseOptional' 'LocalFileSigLevel = Optional'"
            .into(),
        "echo SigLevel = Nev'er'".into(),
        "echo SigLevel = Nev{er,}".into(),
        "printf 'SigLevel = Required\\tNever'".into(),
    ] {
        let (mut store, session) = both();
        assert!(
            block_on(store.append(
                &command("fixture", Some(&session), bytes.as_bytes()),
                &approval()
            ))
            .is_ok(),
            "admitted: {bytes}"
        );
        assert!(store.signature_refusals().is_empty());
    }
    for restarted in [false, true] {
        let (mut store, _) = both();
        if restarted {
            store = reopen(&store);
            block_on(store.bind("fixture")).unwrap();
        }
        assert!(matches!(
            block_on(store.append(&command("fixture", None, b"SigLevel=Never"), &approval())),
            Err(AppendRefusal::SignatureLowering(_))
        ));
    }
    for bytes in [b"SigLevel=Never".as_slice(), b"SigLevel=TrustAll"] {
        let (mut store, _) = both();
        assert!(
            block_on(store.append(&command("fixture-other", None, bytes), &approval())).is_ok()
        );
    }
    let (mut store, _) = both();
    store.storage.fault(Fault::Fail(1));
    assert!(matches!(
        block_on(store.append(&command("fixture", None, b"SigLevel=Never"), &approval())),
        Err(AppendRefusal::Storage(_))
    ));
    assert!(store.failed.is_some());
    assert!(store.commands().is_empty());
    assert!(store.signature_refusals().is_empty());
    assert!(block_on(store.append(&command("fixture", None, b"true"), &approval())).is_err());
}

#[test]
fn modes_never_entered_by_failing() {
    let (mut store, session) = both();
    let standing = store.standing_modes("fixture");
    let acceptances = store.mode_acceptances();
    let records = acceptance_events(&store);
    let unchanged = |store: &Store<MemoryStorage>| {
        assert_eq!(
            acceptance_events(store),
            records,
            "failure journaled a mode"
        );
        assert_eq!(
            store.mode_acceptances(),
            acceptances,
            "failure entered a mode"
        );
        assert_eq!(store.standing_modes("fixture"), standing);
    };
    assert!(block_on(store.bind("fixture")).is_err());
    unchanged(&store);
    assert!(block_on(store.bind("missing")).is_err());
    unchanged(&store);
    assert!(block_on(store.connection_session("fixture-other")).is_err());
    unchanged(&store);
    assert!(block_on(store.operation(&request(Operation::Destroy, &session, vec![]))).is_err());
    unchanged(&store);
    assert!(
        block_on(store.append(
            &command("fixture", Some(&session), b"SigLevel=Never"),
            &approval()
        ))
        .is_err()
    );
    unchanged(&store);
    let call =
        block_on(store.append(&command("fixture", Some(&session), b"true"), &approval())).unwrap();
    assert!(
        block_on(store.append(&command("fixture", Some(&session), b"true"), &approval())).is_err()
    );
    unchanged(&store);
    block_on(store.dispose(Disposition {
        machine: "fixture".into(),
        calls: vec![call],
        continuation: Continuation::DestructiveReinstall,
        uncertainty: "the command outcome is unknown".into(),
    }))
    .unwrap();
    assert!(
        block_on(store.append(&command("fixture", Some(&session), b"true"), &approval())).is_err()
    );
    unchanged(&store);
    let (mut store, session) = both();
    let standing = store.standing_modes("fixture");
    let acceptances = store.mode_acceptances();
    let mode_records = acceptance_events(&store);
    block_on(store.operation(&request(Operation::Reset, &session, vec![]))).unwrap();
    assert!(
        block_on(store.append(&command("fixture", Some(&session), b"true"), &approval())).is_err()
    );
    assert_eq!(store.standing_modes("fixture"), standing);
    assert_eq!(store.mode_acceptances(), acceptances);
    assert_eq!(acceptance_events(&store), mode_records);
    // Each missing binding prerequisite is tested with a history mode already standing.
    for prerequisite in ["class", "access", "entry"] {
        let (mut store, _) = both();
        match prerequisite {
            "class" => {
                store
                    .dispatch
                    .approved_entries
                    .get_mut("fixture-other")
                    .unwrap()
                    .class = None
            }
            "access" => {
                store
                    .dispatch
                    .approved_entries
                    .get_mut("fixture-other")
                    .unwrap()
                    .approved
                    .access = None
            }
            _ => {
                store.dispatch.approved_entries.remove("fixture-other");
            }
        }
        let before = store.mode_acceptances();
        let mode_records = acceptance_events(&store);
        assert!(block_on(store.bind("fixture-other")).is_err());
        assert_eq!(acceptance_events(&store), mode_records);
        assert_eq!(store.mode_acceptances(), before);
        assert_eq!(
            store.standing_modes("fixture"),
            vec![Mode::NoArtifactPin, Mode::NoBrief]
        );
    }
}

#[test]
fn mode_replay_refuses_misplaced_acceptances_and_unknown_labels() {
    for mode in [
        "unpinned",
        "no_breif",
        "jump_host",
        "larger_set",
        "untyped_scope",
    ] {
        assert!(serde_json::from_value::<Mode>(json!(mode)).is_err());
    }
    for kind in [
        "late_binding",
        "unknown_session",
        "duplicate",
        "after_command",
        "installation_through_session",
    ] {
        let (mut store, session) = both();
        let number;
        if kind == "late_binding" {
            number = store.next;
            let mut exposure = store.exposure_ledger[0].clone();
            exposure.session = format!("session-{number}");
            block_on(store.commit(&Event::Exposure(exposure))).unwrap();
        } else {
            let mode = if kind == "installation_through_session" {
                Mode::NoArtifactPin
            } else {
                Mode::NoBrief
            };
            let session = if kind == "unknown_session" {
                "unknown".into()
            } else {
                session
            };
            if kind == "after_command" {
                // Separate session with no previous acceptance, so the intent is the only invalidating fact.
                let mut reopened = reopen(&store);
                let new_session = block_on(reopened.bind("fixture")).unwrap();
                block_on(reopened.append(
                    &command("fixture", Some(&new_session), b"true"),
                    &approval(),
                ))
                .unwrap();
                number = reopened.next;
                block_on(reopened.commit(&Event::ModeAcceptance(Acceptance {
                    session: new_session,
                    mode,
                })))
                .unwrap();
                store = reopened;
            } else {
                number = store.next;
                block_on(store.commit(&Event::ModeAcceptance(Acceptance { session, mode })))
                    .unwrap();
            }
        }
        let error = block_on(unlock(
            MemoryStorage::with_files(store.storage.files()),
            &Fixed,
            pass(),
        ))
        .err()
        .expect("misplaced acceptance must refuse replay");
        assert!(error.contains(&format!("record {number}")), "{error}");
        assert!(!error.contains("unknown_session"));
    }
}
