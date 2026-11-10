use super::*;

type Snapshot = (BTreeMap<String, Vec<u8>>, u64, Address, Task);

struct ProducerRuntime {
    store: Store<MemoryStorage>,
    before_wait: Option<Snapshot>,
    settle_errors: Vec<String>,
    observations: usize,
}
impl Runtime for ProducerRuntime {
    async fn load(&mut self, id: &str) -> Result<Task, String> {
        self.store.poc_task(id)
    }
    async fn authority(&mut self, id: &str, session: &str) -> Result<(), String> {
        self.store.poc_authority(id, session).map(|_| ())
    }
    async fn change(&mut self, task: &Task, change: Change) -> Result<Task, String> {
        let files = self.store.storage.files();
        let next = self.store.next;
        let previous = self.store.previous.0;
        let before = self.store.poc_task(&task.id)?;
        let tasks = self.store.poc.clone();
        let dispatch = self.store.dispatch.clone();
        let settling = matches!(change, Change::Settle);
        if matches!(change, Change::Wait { .. }) {
            self.before_wait = Some((files.clone(), next, Address(previous), before.clone()));
        }
        let result = self.store.poc_change(&task.id, task.revision, change).await;
        if settling {
            let error = result.as_ref().expect_err("actual checkpoint must refuse");
            assert_eq!(
                error,
                "recorded job output requires protection before checkpoint"
            );
            assert_eq!(self.store.storage.files(), files);
            assert_eq!(self.store.next, next);
            assert_eq!(self.store.previous.0, previous);
            assert_eq!(self.store.poc_task(&task.id)?, before);
            assert_eq!(self.store.poc, tasks);
            assert_eq!(self.store.dispatch.calls, dispatch.calls);
            assert_eq!(self.store.dispatch.jobs, dispatch.jobs);
            assert_eq!(self.store.dispatch.intent_order, dispatch.intent_order);
            assert!(self.store.failed.is_none());
            self.settle_errors.push(error.clone());
        }
        result
    }
    async fn propose(&mut self, _: &Task, _: &str, _: String, _: Tool) -> Result<Task, String> {
        panic!("pending work must be inspected before inference")
    }
    async fn execute(&mut self, _: Binding, _: &Task) -> Result<(), String> {
        panic!("Resume must not launch pending work again")
    }
    async fn observe(&mut self, task: &Task, _: &str) -> Result<Observation, String> {
        self.observations += 1;
        let report = self
            .store
            .poc_committed(task.pending.as_ref().unwrap())
            .unwrap();
        // This is the same terminal classifier used by the worker after reading the journal.
        Ok(run::committed_observation(report).expect("recorded finished terminal"))
    }
}

fn producer_regression(mismatched: bool) {
    // Fix the seed and every subsequent identifier used by configuration and task adoption.
    let _identifiers = FixedIdentifiers::new();
    let probe = if mismatched {
        "remain\",\"running\":false}}}}}"
    } else {
        "checkpoint\",\"running\":false}}}}}"
    };
    assert!((16..=4096).contains(&probe.len()));
    assert!(probe.bytes().all(|byte| (0x21..=0x7e).contains(&byte)));
    let mut unsafe_admissions = 0;
    let mut stranded = 0;
    for unsafe_probe in [true, false] {
        let mut store = ready();
        let task = create_task(&mut store);
        let proposed = proposal(&mut store, &task);
        append(&mut store, &proposed, &task.start_session);
        let pending = store.poc_task(&task.id).unwrap();
        let original_pending = pending.pending.clone();
        let safe_key = b"safe~resume~credential~QZ";
        store.poc_configuration_key(safe_key).unwrap();
        store.remember_poc_credential(safe_key);
        // Admission precedes terminal evidence, while configuration is actually eligible.
        store.poc_configuration_ready().unwrap();
        let files = store.storage.files();
        let next = store.next;
        let previous = store.previous.0;
        let tasks = store.poc.clone();
        let inventory = store.poc_credential_filters.borrow().len();
        let prior_protection = store
            .protect_output(&json!(String::from_utf8_lossy(safe_key)))
            .unwrap();
        assert_ne!(prior_protection, json!(String::from_utf8_lossy(safe_key)));
        let admission = store.poc_configuration_key(probe.as_bytes());
        assert_eq!(store.storage.files(), files);
        assert_eq!(store.next, next);
        assert_eq!(store.previous.0, previous);
        assert_eq!(store.poc, tasks);
        assert_eq!(store.poc_credential_filters.borrow().len(), inventory);
        assert_eq!(
            store
                .protect_output(&json!(String::from_utf8_lossy(safe_key)))
                .unwrap(),
            prior_protection
        );
        assert!(store.failed.is_none());
        if let Err(error) = &admission {
            assert!(!error.contains(probe));
        } else if unsafe_probe {
            unsafe_admissions += 1;
            store.remember_poc_credential(probe.as_bytes());
        }
        let output = "later-sensitive-output-value";
        let mut received = record(&pending, Some(0), output);
        if mismatched && let crate::jobs::Record::Present { command, .. } = &mut received {
            *command = hex::encode("different-command");
        }
        evidence(&mut store, &pending, received);
        let report = store
            .poc_committed(original_pending.as_ref().unwrap())
            .unwrap();
        assert_eq!(report.state, crate::jobs::State::Finished);
        assert_eq!(
            matches!(report.comparison, crate::jobs::Comparison::AdvisoryMatch),
            !mismatched
        );
        assert!(store.poc_configuration_ready().is_err());
        let command_admission = format!("{:?}", store.dispatch.check_command("fixture"));
        if !mismatched {
            // The real Settle projection refuses output that now needs transient protection.
            block_on(store.synthetic_scan_fixture(
                "later-value".into(),
                Zeroizing::new(output.as_bytes().to_vec()),
            ))
            .unwrap();
        }
        let mut runtime = ProducerRuntime {
            store,
            before_wait: None,
            settle_errors: Vec::new(),
            observations: 0,
        };
        let result = block_on(run::resume(
            &mut runtime,
            &mut Script::default(),
            &task.id,
            &task.start_session,
        ));
        let (files, next, previous, before) =
            runtime.before_wait.take().expect("Resume reached Wait");
        assert_eq!(runtime.observations, 1);
        assert_eq!(runtime.settle_errors.len(), usize::from(!mismatched));
        let current = runtime.store.poc_task(&task.id).unwrap();
        assert_eq!(current.pending, original_pending);
        assert!(current.completed.is_empty());
        assert_eq!(runtime.store.dispatch.calls.len(), 1);
        eprintln!(
            "producer mismatched={mismatched} unsafe_probe={unsafe_probe} admitted={} settle_errors={:?} resume_error={:?} wait_writes={}",
            admission.is_ok(),
            runtime.settle_errors,
            result.as_ref().err(),
            runtime.store.next - next
        );
        if let Err(error) = result {
            stranded += 1;
            assert_eq!(error, "task credential boundary");
            assert_eq!(runtime.store.storage.files(), files);
            assert_eq!(runtime.store.next, next);
            assert_eq!(runtime.store.previous.0, previous.0);
            assert_eq!(current, before);
        } else {
            assert_eq!(current.status, Status::Paused);
            let reason = current.pause_reason.as_ref().unwrap();
            if mismatched {
                assert!(reason.starts_with("committed job record differs from its intent"));
                assert!(reason.ends_with("remote effects and command holds remain"));
            } else {
                assert_eq!(
                    reason,
                    "recorded result could not be checkpointed: recorded job output requires protection before checkpoint"
                );
            }
            assert_eq!(runtime.store.next, next + 1);
        }
        assert_eq!(reopen(&runtime.store).poc_task(&task.id).unwrap(), current);
        let abandoned = change(&mut runtime.store, &current, Change::Abandon);
        assert_eq!(abandoned.status, Status::Abandoned);
        assert_eq!(abandoned.pending, original_pending);
        assert!(abandoned.completed.is_empty());
        assert_eq!(runtime.store.dispatch.calls.len(), 1);
        assert_eq!(
            format!("{:?}", runtime.store.dispatch.check_command("fixture")),
            command_admission
        );
        assert!(runtime.store.poc_configuration_ready().is_ok());
        assert_eq!(
            reopen(&runtime.store).poc_task(&task.id).unwrap(),
            abandoned
        );
    }
    assert_eq!(
        unsafe_admissions, 0,
        "unsafe producer envelope admitted; stranded Waits={stranded}"
    );
    assert_eq!(stranded, 0);
}

#[test]
fn poc_wait_producer_checkpoint_admission_and_resume() {
    producer_regression(false);
}

#[test]
fn poc_wait_producer_mismatched_terminal_admission_and_resume() {
    producer_regression(true);
}
