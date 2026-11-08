//! Durable session lifetime; execution retirement never writes End.
use super::*;
use crate::binding::{End, EndReason};

impl<S: Storage> Store<S> {
    pub async fn end_session(&mut self, session: &str) -> Result<(), String> {
        if self.ended_sessions.contains(session) {
            return Ok(());
        }
        if !self.exposure_ledger.iter().any(|e| e.session == session) {
            return Err("unknown session".into());
        }
        let end = End {
            session: session.into(),
            reason: EndReason::Explicit,
        };
        // The caller holds the writer across this append, serializing End and new intents.
        // Neither the permanent fence nor binding release occurs on a failed/uncertain write.
        self.commit(&Event::End(end.clone())).await?;
        self.apply_end(&end)?;
        #[cfg(target_arch = "wasm32")]
        {
            crate::harness::inference::session_ended(session);
        }
        Ok(())
    }

    pub(super) fn apply_end(&mut self, end: &End) -> Result<(), String> {
        if !self
            .exposure_ledger
            .iter()
            .any(|e| e.session == end.session)
        {
            return Err("End names no admitted session".into());
        }
        self.ended_sessions.insert(end.session.clone());
        self.pending_requirements.remove(&end.session);
        if let Some(session) = self.sessions.iter().find(|s| s.identity == end.session) {
            session.ended.set(true);
            session.given.borrow_mut().clear();
        }
        Ok(())
    }

    // Materialize only after the complete history, including every later End, validated.
    pub(super) fn restore_sessions(&mut self) -> Result<(), String> {
        for exposure in &self.exposure_ledger {
            let bound = &exposure.bound_set[0];
            let key = self
                .seed()
                .ok_or("seed unavailable")?
                .ssh_client_key(bound.identity.derivation_version, bound.identity.index)
                .map_err(|_| "session key derivation refused")?;
            let session = Session::new(exposure.session.clone(), bound.machine.clone(), key);
            if self.ended_sessions.contains(&exposure.session) {
                session.ended.set(true);
                session.given.borrow_mut().clear();
            }
            self.sessions.push(Rc::new(session));
        }
        Ok(())
    }

    pub fn session_configuration(
        &self,
        session: &str,
    ) -> Result<crate::poc::inference::Configuration, String> {
        self.exposure_ledger
            .iter()
            .find(|e| e.session == session)
            .map(|e| e.inference_approval.configuration.clone())
            .ok_or("unknown session".into())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::store::inference::tests::{Fixed, ready};
    use std::cell::Cell;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    fn pass() -> LocalPassphrase {
        LocalPassphrase::new(b"inference fixture passphrase".to_vec())
    }
    fn reopen(s: &Store<MemoryStorage>) -> Store<MemoryStorage> {
        block_on(unlock(
            MemoryStorage::with_files(s.storage.files()),
            &Fixed,
            pass(),
        ))
        .unwrap()
    }

    fn replace(s: &Store<MemoryStorage>, number: u64, plaintext: &[u8]) -> MemoryStorage {
        let mut files = s.storage.files();
        let mut record: RecordJson = serde_json::from_slice(&files[&number.to_string()]).unwrap();
        let nonce: [u8; 12] = random().unwrap();
        record.nonce = URL_SAFE_NO_PAD.encode(nonce);
        record.ciphertext = URL_SAFE_NO_PAD.encode(
            cipher(&s.key.0)
                .encrypt(
                    &nonce.into(),
                    Payload {
                        msg: plaintext,
                        aad: record_aad(&s.id, EVENT, number, &record.previous).as_bytes(),
                    },
                )
                .unwrap(),
        );
        files.insert(number.to_string(), serde_json::to_vec(&record).unwrap());
        MemoryStorage::with_files(files)
    }

    fn assert_refused(storage: MemoryStorage, diagnostic: &str) {
        let before = storage.files();
        let mut local = Local::new(storage.clone(), Fixed);
        block_on(local.open());
        let report = block_on(local.unlock(pass()));
        assert_eq!(report["state"], "refused");
        assert!(report.get("sessions").is_none());
        let why = report["reason"].as_str().unwrap();
        assert!(why.contains(diagnostic), "{why}");
        assert!(why.contains("left unchanged") && why.contains("seed record"));
        assert_eq!(storage.files(), before);
        assert!(block_on(local.create(pass()))["error"].is_string());
        assert_eq!(storage.files(), before);
    }

    #[test]
    fn poc_session_v2_refuses_earlier_unknown_malformed_and_duplicate_without_projection() {
        let s = ready();
        let seed_only = block_on(create(MemoryStorage::default(), &Fixed, pass())).unwrap();
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&Event::Seed {
                mnemonic: seed_only.seed().unwrap().phrase().to_string(),
            })
            .unwrap(),
        );
        assert_refused(replace(&seed_only, 0, &plaintext), "unsupported earlier");
        assert_refused(
            replace(
                &s,
                s.next - 1,
                br#"{"command":{"machine":"fixture","command":"74727565"}}"#,
            ),
            "unsupported earlier",
        );
        let mut nested = ready();
        let session = nested.sessions[0].identity.clone();
        block_on(nested.enter_goal(&session, "check a service".into(), None)).unwrap();
        block_on(nested.accept_mode(&session, Mode::NoBrief)).unwrap();
        let task = block_on(nested.poc_create(&session, vec!["true".into()])).unwrap();
        let task =
            block_on(nested.poc_change(&task.id, task.revision, poc::Change::Request)).unwrap();
        let change = poc::Change::Propose {
            call_id: "fixture-call".into(),
            tool: crate::goals::Tool::Typed {
                machine: "fixture".into(),
                operation: crate::dispatch::Operation::Reset,
                arguments: [("sample".into(), "value".into())].into(),
            },
        };
        let event = Event::Poc(poc::Record::Change {
            id: task.id.clone(),
            expected: task.revision,
            change: change.clone(),
        });
        let task = block_on(nested.poc_change(&task.id, task.revision, change)).unwrap();
        assert_eq!(reopen(&nested).poc_task(&task.id).unwrap(), task);
        let repeated = serde_json::to_string(&journal::journal(&event))
            .unwrap()
            .replace(
                "\"sample\":\"value\"",
                "\"sample\":\"first\",\"sample\":\"value\"",
            );
        assert!(
            serde_json::from_str::<journal::Journal<Event>>(&repeated).is_ok(),
            "this map would otherwise silently discard a duplicate"
        );
        assert_refused(
            replace(&nested, nested.next - 1, repeated.as_bytes()),
            "decoding failed",
        );
        for (number, bytes, diagnostic) in [
            (
                0,
                br#"{"seed":{"mnemonic":"not read"}}"#.as_slice(),
                "unsupported earlier",
            ),
            (s.next - 1, br#"{"exposure":{}}"#, "unsupported earlier"),
            (
                0,
                br#"{"journal_version":1,"event":{}}"#,
                "unsupported earlier",
            ),
            (
                0,
                br#"{"journal_version":73,"event":{}}"#,
                "unknown journal version",
            ),
            (
                0,
                br#"{"journal_version":2,"extra":true,"event":{}}"#,
                "decoding failed",
            ),
            (
                0,
                br#"{"journal_version":2,"journal_version":2,"event":{}}"#,
                "decoding failed",
            ),
            (0, br#"{"journal_version":2}"#, "decoding failed"),
        ] {
            assert_refused(replace(&s, number, bytes), diagnostic);
        }
    }

    #[test]
    fn poc_session_restore_retains_goal_approvals_counters_config_and_dormant_binding() {
        let mut s = ready();
        let session = s.sessions[0].identity.clone();
        block_on(s.enter_goal(&session, "install a small service".into(), None)).unwrap();
        block_on(s.accept_mode(&session, Mode::NoBrief)).unwrap();
        s.fixture_requirements("fixture");
        let task = block_on(s.poc_create(&session, vec!["true".into()])).unwrap();
        let task = block_on(s.poc_change(&task.id, task.revision, poc::Change::Request)).unwrap();
        let mut r = reopen(&s);
        assert_eq!(r.sessions[0].identity, session);
        assert_eq!(r.poc_task(&task.id).unwrap(), task);
        assert_eq!(r.goals, s.goals);
        assert_eq!(r.conduct_acceptances, s.conduct_acceptances);
        assert_eq!(r.dispatch.standing, s.dispatch.standing);
        assert_eq!(
            r.session_configuration(&session).unwrap(),
            s.session_configuration(&session).unwrap()
        );
        assert!(r.inference.limits.borrow().is_empty());
        let before = r.storage.files();
        assert_eq!(
            block_on(r.admit_fixture("fixture")),
            Err("already bound".into())
        );
        assert_eq!(r.storage.files(), before);
        assert_eq!(
            block_on(r.bind("fixture-other")),
            Err("explicit inference approval required".into())
        );
        block_on(r.end_session(&session)).unwrap();
        let mut r = reopen(&r);
        assert!(r.sessions[0].ended.get());
        assert!(r.poc_authority(&task.id, &session).is_err());
        let before = r.storage.files();
        block_on(r.end_session(&session)).unwrap();
        assert_eq!(r.storage.files(), before, "End is idempotent");
        let successor = block_on(r.admit_fixture("fixture")).unwrap();
        assert_ne!(successor, session);
        assert!(r.poc_authority(&task.id, &successor).is_err());
        assert_eq!(r.goal(&session).unwrap().text, task.goal);
        assert!(
            r.goal(&successor).is_none(),
            "an ended goal is never copied"
        );
    }

    #[test]
    fn poc_session_end_failed_and_lost_append_releases_nothing_until_replay() {
        for fault in [
            Fault::Fail(1),
            Fault::Fail(2),
            Fault::Fail(3),
            Fault::LandThenFail(3),
        ] {
            let mut s = ready();
            s.fixture_requirements("fixture");
            let entry = Entry {
                machine: "fixture".into(),
                command: b"true".to_vec(),
                provenance: None,
            };
            block_on(s.append(
                &entry,
                &Approval::HarnessPin {
                    machine: "fixture".into(),
                    fingerprint: "SHA256:fixture".into(),
                },
            ))
            .unwrap();
            let calls = s.dispatch.calls.clone();
            let standing = s.dispatch.approved_entries.clone();
            let session = s.sessions[0].clone();
            let before = s.exposure_ledger.clone();
            s.storage.fault(fault);
            assert!(block_on(s.end_session(&session.identity)).is_err());
            assert!(!session.ended.get());
            assert!(session.client_key("fixture").is_some());
            assert!(!s.ended_sessions.contains(&session.identity));
            assert!(
                s.check_session_authority(&session.identity, s.session_pair(&session.identity))
                    .is_err(),
                "uncertain append withholds further sends without releasing the binding"
            );
            assert_eq!(s.exposure_ledger, before);
            assert_eq!(s.dispatch.calls, calls);
            assert_eq!(s.dispatch.approved_entries, standing);
            assert!(
                s.dispatch.check_command("fixture").is_err(),
                "uncertain remote effect keeps its hold"
            );
            assert!(block_on(s.admit_fixture("fixture")).is_err());
            assert!(
                block_on(s.end_session(&session.identity)).is_err(),
                "uncertain writer stays stopped"
            );
            let r = reopen(&s);
            assert_eq!(
                r.sessions[0].ended.get(),
                matches!(fault, Fault::LandThenFail(3))
            );
        }
    }

    #[test]
    fn poc_session_end_is_scoped_and_available_without_runtime_readiness() {
        let mut s = ready();
        let selected = s.sessions[0].clone();
        let other = block_on(s.admit_fixture("fixture-other")).unwrap();
        selected.given.borrow_mut().clear();
        s.authority.suspend();
        let mut local = Local::new(s.storage.clone(), Fixed);
        local.state = State::Unlocked(Box::new(s));
        let report = local.report(None);
        assert_eq!(report["endable_sessions"].as_array().unwrap().len(), 2);
        assert_eq!(report["lifecycle_generation"], "1");
        for field in ["sessions", "goals", "tasks", "given", "delivery"] {
            assert!(report.get(field).is_none(), "suspension exposes no {field}");
        }
        let s = local.store().unwrap();
        let next = s.next;
        block_on(s.end_session(&selected.identity)).unwrap();
        assert_eq!(s.next, next + 1);
        assert!(!s.inference.ended);
        assert_eq!(
            local.report(None)["endable_sessions"],
            json!([{
                "identity":other,"bound_set":["fixture-other"]
            }])
        );
        let s = local.store().unwrap();
        s.authority.revalidated().unwrap();
        assert!(
            s.check_session_authority(&other, s.session_pair(&other))
                .is_ok()
        );
        let r = reopen(s);
        assert!(r.sessions[0].ended.get());
        assert!(!r.sessions[1].ended.get());
        assert!(r.sessions[1].client_key("fixture-other").is_some());
    }

    #[test]
    fn poc_session_approval_append_failure_preserves_pending_and_replay_resolves_commit() {
        for fault in [
            Fault::Fail(1),
            Fault::Fail(2),
            Fault::Fail(3),
            Fault::LandThenFail(3),
        ] {
            let mut s = ready();
            let session = s.sessions[0].identity.clone();
            block_on(s.enter_goal(&session, "install a small service".into(), None)).unwrap();
            block_on(s.accept_mode(&session, Mode::NoBrief)).unwrap();
            let proposal = crate::declaration::Proposal::parse(&json!({"kind":"declaration","machine":"fixture","declaration":crate::declaration::ad_hoc_minimum()})).unwrap();
            s.propose_requirements(
                &session,
                7,
                proposal.clone(),
                &crate::goals::Tool::Done {
                    machine: "fixture".into(),
                },
            )
            .unwrap();
            s.storage.fault(fault);
            assert!(block_on(s.approve_requirements(&session, "fixture", 7)).is_err());
            assert_eq!(s.pending_requirements[&session].candidate, 7);
            assert_eq!(s.pending_requirements[&session].proposal, proposal);
            assert!(
                s.dispatch.approved_entries["fixture"]
                    .requirements
                    .is_empty()
            );
            let before = s.storage.files();
            assert!(block_on(s.approve_requirements(&session, "fixture", 7)).is_err());
            assert_eq!(s.storage.files(), before);
            let r = reopen(&s);
            assert_eq!(r.sessions[0].identity, session);
            assert_eq!(
                !r.dispatch.approved_entries["fixture"]
                    .requirements
                    .is_empty(),
                matches!(fault, Fault::LandThenFail(3))
            );
        }
    }

    #[test]
    fn poc_session_admission_refuses_credential_and_encoded_approval_before_append() {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE};
        let key = b"byo~approval~secret~482700";
        for form in [
            String::from_utf8(key.to_vec()).unwrap(),
            hex::encode(key),
            hex::encode_upper(key),
            STANDARD.encode(key),
            URL_SAFE.encode(key),
        ] {
            let mut s = ready();
            s.remember_poc_credential(key);
            let approval = crate::binding::InferenceApproval {
                approved: true,
                configuration: crate::poc::inference::Configuration::new(
                    format!("https://fixture.invalid/{form}"),
                    "fixture".into(),
                )
                .unwrap(),
            };
            let before = s.storage.files();
            assert!(
                block_on(s.admit("fixture-other", &[], approval)).is_err(),
                "approval must be scanned before append"
            );
            assert_eq!(s.storage.files(), before);
            assert_eq!(s.sessions.len(), 1);
            assert!(s.failed.is_none());
        }
        let s = ready();
        assert!(
            s.poc_configuration_key(s.authority.references()[0].as_bytes())
                .is_err()
        );
        for key in [
            br#""journal_version":2,"event":"#.as_slice(),
            br#""inference_approval":"#,
            br#""end":{"session":"#,
        ] {
            assert!(
                s.poc_configuration_key(key).is_err(),
                "new control envelopes participate in key admission"
            );
        }
    }

    #[derive(Clone)]
    struct Held {
        base: MemoryStorage,
        hold: Rc<Cell<bool>>,
        entered: Rc<Cell<bool>>,
    }
    impl Storage for Held {
        async fn list(&self) -> Result<Vec<String>, String> {
            self.base.list().await
        }
        async fn read(&self, name: &str) -> Result<Vec<u8>, String> {
            self.base.read(name).await
        }
        async fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
            self.base.write(name, bytes).await
        }
        async fn rename(&self, from: &str, to: &str) -> Result<(), String> {
            if self.hold.get() {
                self.entered.set(true);
                std::future::poll_fn(|_| {
                    if self.hold.get() {
                        Poll::Pending
                    } else {
                        Poll::Ready(())
                    }
                })
                .await;
            }
            self.base.rename(from, to).await
        }
    }

    #[test]
    fn poc_session_end_held_append_keeps_binding_and_approval_until_commit() {
        let s = ready();
        let storage = Held {
            base: MemoryStorage::with_files(s.storage.files()),
            hold: Rc::default(),
            entered: Rc::default(),
        };
        let mut r = block_on(unlock(storage.clone(), &Fixed, pass())).unwrap();
        let session = r.sessions[0].clone();
        storage.hold.set(true);
        let mut end = Box::pin(r.end_session(&session.identity));
        assert!(
            end.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert!(storage.entered.get());
        assert!(
            !session.ended.get(),
            "no permanent fence before durable End"
        );
        assert!(session.client_key("fixture").is_some());
        let reopened = reopen(&s);
        assert_eq!(reopened.sessions[0].bound_set, session.bound_set);
        storage.hold.set(false);
        assert!(matches!(
            end.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
        drop(end);
        assert!(session.ended.get());
        assert!(session.client_key("fixture").is_none());
        assert_ne!(
            block_on(r.admit_fixture("fixture")).unwrap(),
            session.identity
        );
    }
}
