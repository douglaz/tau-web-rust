use super::*;
use crate::poc::wait;

type WaitCheckpoint = (BTreeMap<String, Vec<u8>>, u64, Address, Task);

struct WaitRuntime {
    store: Store<MemoryStorage>,
    reason: String,
    before_wait: Option<WaitCheckpoint>,
}
impl Runtime for WaitRuntime {
    async fn load(&mut self, id: &str) -> Result<Task, String> {
        self.store.poc_task(id)
    }
    async fn authority(&mut self, id: &str, session: &str) -> Result<(), String> {
        self.store.poc_authority(id, session).map(|_| ())
    }
    async fn change(&mut self, task: &Task, change: Change) -> Result<Task, String> {
        if matches!(change, Change::Wait { .. }) {
            self.before_wait = Some((
                self.store.storage.files(),
                self.store.next,
                Address(self.store.previous.0),
                self.store.poc_task(&task.id)?,
            ));
        }
        self.store.poc_change(&task.id, task.revision, change).await
    }
    async fn propose(&mut self, _: &Task, _: &str, _: String, _: Tool) -> Result<Task, String> {
        panic!("Resume must inspect")
    }
    async fn execute(&mut self, _: Binding, _: &Task) -> Result<(), String> {
        panic!("Resume must never launch")
    }
    async fn observe(&mut self, task: &Task, _: &str) -> Result<Observation, String> {
        // Collection's no-outcome reason is produced by the store, including its protection.
        let pending = task.pending.as_ref().unwrap();
        let produced = self.store.poc_collection_reason(pending, &[]);
        if self.reason.starts_with("collection returned no outcome") {
            assert_eq!(self.reason, produced);
            return Ok(Observation::Unknown(produced));
        }
        Ok(Observation::Unknown(self.reason.clone()))
    }
}

fn wait_shapes() -> Vec<String> {
    let mut shapes = Vec::new();
    wait::visit(|s| shapes.push(s));
    shapes
}

fn wait_key(reason: &str) -> String {
    let event = serde_json::to_string(&Event::Poc(Record::Change {
        id: String::new(),
        expected: 0,
        change: Change::Wait {
            why: reason.into(),
            running: false,
        },
    }))
    .unwrap();
    // A complete final word plus the real serializer's closing envelope: no space bytes.
    let start = event
        .rfind(' ')
        .map_or_else(|| event.find("\"why\":\"").unwrap() + 7, |i| i + 1);
    event[start..].to_owned()
}

#[test]
fn poc_wait_admission_prevents_resume_stranding() {
    // Fix all identifiers for the safe-key continuation and adoption assertions.
    let _identifiers = FixedIdentifiers::new();
    let mut rows = Vec::new();
    for pattern in wait_shapes() {
        let reason = pattern
            .replace("{number}", "0")
            .replace("{job}", "")
            .replace("{payload}", "remote-detail");
        let key = if pattern.ends_with("{payload}") || pattern.ends_with("{payload})") {
            format!(
                "{{\"wait\":{{\"why\":\"{}",
                reason.split(' ').next().unwrap()
            )
        } else {
            wait_key(&reason)
        };
        rows.push((key, pattern.replace("{payload}", "remote-detail")));
    }
    rows.extend([
        ("retained\",\"running\":false}}}}}".into(), "collection returned no outcome for pending call {number} job {job}; pending identity retained".into()),
        ("{\"wait\":{\"why\":\"collection".into(), "collection returned no outcome for pending call {number} job {job}; pending identity retained".into()),
        ("remain\",\"running\":false}}}}}".into(), wait::COMMITTED_MISMATCH.into()),
    ]);
    let mut admitted = 0;
    let mut stranded = 0;
    let mut safe_waits = 0;
    for (key, pattern) in &rows {
        assert!(
            (16..=4096).contains(&key.len()) && key.bytes().all(|b| (0x21..=0x7e).contains(&b)),
            "invalid probe {key:?}"
        );
        let mut store = ready();
        let task = create_task(&mut store);
        let proposed = proposal(&mut store, &task);
        append(&mut store, &proposed, &task.start_session);
        let pending = store.poc_task(&task.id).unwrap().pending.unwrap();
        let reason = pattern
            .replace("{number}", &pending.call.to_string())
            .replace("{job}", &pending.job);
        let files = store.storage.files();
        let next = store.next;
        let previous = store.previous.0;
        let tasks = store.poc.clone();
        let filters = store.poc_credential_filters.borrow().len();
        let admission = store.poc_configuration_key(key.as_bytes());
        super::journal_tests::unchanged(&store, &files, next, previous);
        assert_eq!(store.poc, tasks);
        assert_eq!(store.poc_credential_filters.borrow().len(), filters);
        if let Err(error) = &admission {
            assert!(!error.contains(key));
        }
        let mut runtime = WaitRuntime {
            store,
            reason,
            before_wait: None,
        };
        if admission.is_ok() {
            admitted += 1;
            runtime.store.remember_poc_credential(key.as_bytes());
            let result = block_on(run::resume(
                &mut runtime,
                &mut Script::default(),
                &task.id,
                &task.start_session,
            ));
            let (files, next, previous, before) = runtime
                .before_wait
                .take()
                .expect("real runner reached Wait");
            if result.is_err() {
                stranded += 1;
                super::journal_tests::unchanged(&runtime.store, &files, next, previous.0);
                assert_eq!(runtime.store.poc_task(&task.id).unwrap(), before);
            }
            eprintln!(
                "wait probe key={key:?} admitted=true resume_error={:?} wait_writes={}",
                result.err(),
                runtime.store.next - next
            );
        } else {
            // Refusal preserves the old inventory. A seed-independent safe key can still Resume.
            runtime
                .store
                .poc_configuration_key(b"safe~resume~credential~QZ")
                .unwrap();
            runtime
                .store
                .remember_poc_credential(b"safe~resume~credential~QZ");
            let result = block_on(run::resume(
                &mut runtime,
                &mut Script::default(),
                &task.id,
                &task.start_session,
            ))
            .unwrap();
            assert_eq!(
                result.pause_reason.as_deref(),
                Some(runtime.reason.as_str())
            );
            assert!(result.pending.is_some());
            assert_eq!(runtime.store.dispatch.calls.len(), 1);
            assert_eq!(reopen(&runtime.store).poc_task(&task.id).unwrap(), result);
            safe_waits += 1;
        }
        let current = runtime.store.poc_task(&task.id).unwrap();
        assert_eq!(
            change(&mut runtime.store, &current, Change::Abandon).status,
            Status::Abandoned
        );
    }
    eprintln!(
        "wait rows={} admitted={admitted} stranded={stranded} safe_waits={safe_waits}",
        rows.len()
    );
    assert_eq!(
        admitted, 0,
        "fixed Wait envelope keys must be refused at admission"
    );
    assert_eq!(stranded, 0);
    assert_eq!(safe_waits, rows.len());
}

#[test]
fn poc_wait_hex_admission_public_keys_across_fresh_stores() {
    for key in [
        "protectedoutputwithheld".to_owned(),
        format!("sk-{}", "0123456789abcdef".repeat(3)),
    ] {
        for open in [false, true] {
            let mut refused = 0;
            let mut adoption_refused = 0;
            for _ in 0..256 {
                let mut store = ready();
                if open {
                    create_task(&mut store);
                }
                if store.poc_configuration_key(key.as_bytes()).is_err() {
                    refused += 1;
                }
                let mut adopted = ready();
                if adopted.poc_configuration_key(key.as_bytes()).is_ok() {
                    adopted.remember_poc_credential(key.as_bytes());
                    let session = adopted.sessions[0].identity.clone();
                    if block_on(adopted.poc_create(&session, vec!["true".into()])).is_err() {
                        adoption_refused += 1;
                    }
                } else {
                    adoption_refused += 1;
                }
            }
            eprintln!(
                "public key={key:?} open={open} stores=256 refused={refused} adoption_refused={adoption_refused}"
            );
            // Accumulate every scenario before asserting, so the baseline receipt reports each cell.
            PUBLIC_RESULTS.with_borrow_mut(|results| results.push((refused, adoption_refused)));
        }
    }
    let results = PUBLIC_RESULTS.with_borrow_mut(std::mem::take);
    assert_eq!(results, vec![(0, 0); 4]);
}
thread_local! { static PUBLIC_RESULTS: RefCell<Vec<(usize, usize)>> = const { RefCell::new(Vec::new()) }; }

#[test]
fn poc_wait_hex_exact_and_all_digit_forms_still_refuse() {
    // All identities are fixed; only the explicitly retained goal supplies the exact hex form.
    let _identifiers = FixedIdentifiers::new();
    let mut store = crate::store::inference::tests::ready();
    let session = store.sessions[0].identity.clone();
    let key = b"exact~hex~credential~QZ";
    block_on(store.enter_goal(&session, hex::encode(key), None)).unwrap();
    block_on(store.accept_mode(&session, Mode::NoBrief)).unwrap();
    block_on(store.poc_create(&session, vec!["true".into()])).unwrap();
    assert!(store.poc_configuration_key(key).is_err());
    // 'Q' encodes as 51: the hex representation is all digits even though the key is not.
    let digits = b"QQQQQQQQQQQQQQQQ";
    assert!(hex::encode(digits).bytes().all(|b| b.is_ascii_digit()));
    assert!(
        crate::poc::inference::EchoFilter::new(&[digits])
            .symbolic_match(b"arbitrary")
            .unwrap()
    );
    assert!(store.poc_configuration_key(digits).is_err());
}

#[test]
fn poc_wait_real_collection_producers_reach_resume() {
    // Fix seed, task and job identities for every configuration and continuation assertion.
    let _identifiers = FixedIdentifiers::new();
    for case in 0..16 {
        eprintln!("collection producer case={case}");
        let (fixture, task, session) = Fixture::new();
        let proposed = proposal(&mut fixture.store.borrow_mut(), &task);
        append(&mut fixture.store.borrow_mut(), &proposed, &session);
        let pending_task = fixture.task(&task.id);
        let pending = pending_task.pending.as_ref().unwrap();
        let reports = match case {
            0 => vec![],
            1 => vec![json!({"call":pending.call,"job":"other"})],
            2 => vec![json!({"call":pending.call,"not_journaled":true,"why":"remote detail"})],
            3 => vec![json!({"call":pending.call,"not_read":true})],
            4 => vec![json!({"call":pending.call,"failed":true,"why":"remote detail"})],
            5 => vec![json!({"call":pending.call})],
            14 => vec![
                json!({"call":pending.call,"failed":true,"job_record":null,"why":"remote detail"}),
            ],
            15 => vec![json!({"call":pending.call,"not_read":true,"why":"remote detail"})],
            _ => {
                let observed = match case {
                    6 | 7 => crate::jobs::Record::Missing,
                    8 => crate::jobs::Record::Incomplete {
                        machine: Some(hex::encode("fixture")),
                        command: None,
                    },
                    _ => {
                        let mut r = record(
                            &pending_task,
                            if case == 12 { Some(0) } else { None },
                            "ordinary output",
                        );
                        if let crate::jobs::Record::Present {
                            machine,
                            command,
                            alive,
                            ..
                        } = &mut r
                        {
                            if case == 9 {
                                *machine = hex::encode("foreign");
                            }
                            if case == 10 {
                                *command = hex::encode("different");
                                *alive = false;
                            }
                            if case == 11 {
                                *alive = false;
                            }
                        }
                        r
                    }
                };
                if case == 13 {
                    let report = crate::jobs::Evidence {
                        call: pending.call,
                        job: pending.job.clone(),
                        record: observed,
                    }
                    .report(
                        fixture.store.borrow().next,
                        &task.machine,
                        &hex::encode("install-example-service"),
                    );
                    vec![serde_json::to_value(report).unwrap()]
                } else {
                    evidence(&mut fixture.store.borrow_mut(), &pending_task, observed);
                    let mut report = serde_json::to_value(
                        fixture.store.borrow().poc_committed(pending).unwrap(),
                    )
                    .unwrap();
                    if case == 6 {
                        report["number"] = Value::Null;
                    }
                    vec![report]
                }
            }
        };
        let why = fixture
            .store
            .borrow()
            .poc_collection_reason(pending, &reports);
        let templates = wait_shapes();
        assert!(
            templates.iter().any(|t| {
                let rendered = t
                    .replace("{number}", &pending.call.to_string())
                    .replace("{job}", &pending.job);
                let parts: Vec<_> = rendered.split("{payload}").collect();
                if parts.len() == 1 {
                    rendered == why
                } else {
                    why.starts_with(parts[0]) && why.ends_with(parts[1])
                }
            }),
            "producer missing from admission: {why}"
        );
        let mut store = reopen(&fixture.store.borrow());
        // Exercise admission against the retained task and its actual serialized control envelopes.
        store
            .poc_configuration_key(b"safe~resume~credential~QZ")
            .unwrap();
        store.remember_poc_credential(b"safe~resume~credential~QZ");
        // Rebinding is the actual adoption route, with every retained generation checked.
        let fresh = fresh(&mut store);
        store.poc_authority(&task.id, &fresh).map(|_| ()).unwrap();
        let mut runtime = WaitRuntime {
            store,
            reason: why.clone(),
            before_wait: None,
        };
        let waited = block_on(run::resume(
            &mut runtime,
            &mut Script::default(),
            &task.id,
            &fresh,
        ))
        .unwrap();
        assert_eq!(waited.pause_reason.as_deref(), Some(why.as_str()));
        assert_eq!(waited.pending, pending_task.pending);
        assert_eq!(runtime.store.dispatch.calls.len(), 1);
        assert_eq!(reopen(&runtime.store).poc_task(&task.id).unwrap(), waited);
    }
}
