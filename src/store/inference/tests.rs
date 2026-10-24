use super::*;
use crate::inference::{self, Candidate, Transport};
use std::future::Future;
use std::task::{Context, Waker};

pub(crate) struct Fixed;
impl Kdf for Fixed {
    async fn derive(&self, _: LocalPassphrase, _: &Salt) -> Result<WrappingKey, String> {
        Ok(WrappingKey([7; 32]))
    }
}
fn pass() -> LocalPassphrase {
    LocalPassphrase::new(b"inference fixture passphrase".to_vec())
}
pub(crate) fn candidate() -> Candidate {
    Candidate {
        slug: "fixture-model".into(),
        maker: "fixture-maker".into(),
        provider: "fixture-provider".into(),
    }
}
pub(crate) fn request() -> Value {
    json!({"machine":"fixture","messages":[{"role":"user","content":"prompt-only-do-not-journal"}]})
}
pub(crate) fn ready() -> Store<MemoryStorage> {
    let mut s = block_on(create(MemoryStorage::default(), &Fixed, pass())).unwrap();
    block_on(s.seed_backup(allocation::Completion::Skipped)).unwrap();
    block_on(s.approve_setup(crate::dispatch::fixture_setup())).unwrap();
    for m in ["fixture", "fixture-other"] {
        block_on(s.answer_class(m.into(), crate::dispatch::ClassAnswer::No)).unwrap();
    }
    block_on(s.bind("fixture")).unwrap();
    block_on(s.set_inference_account(InferenceAccountCredential::new(
        b"fixture-account-private-value".to_vec(),
    )))
    .unwrap();
    s
}
fn reopen(s: &Store<MemoryStorage>) -> Store<MemoryStorage> {
    block_on(unlock(
        MemoryStorage::with_files(s.storage.files()),
        &Fixed,
        pass(),
    ))
    .unwrap()
}

#[derive(Default)]
pub(crate) struct Fake {
    pub seen: Vec<(String, Value, bool, bool)>,
    pub lose: Option<&'static str>,
    pub suspend: Option<&'static str>,
    pub fail: Option<&'static str>,
    pub top_up: bool,
    pub no_report: bool,
    pub echo: bool,
    pub echo_metadata: bool,
    pub identifier_only: bool,
    pub clock: Option<Rc<std::cell::Cell<u64>>>,
    pub key_id: Option<&'static str>,
    pub key: Option<&'static str>,
    pub on_mint: Option<Box<dyn FnMut()>>,
}
impl Transport for Fake {
    async fn exchange(&mut self, r: &Request) -> Option<Response> {
        let body = serde_json::from_str(&r.body).unwrap_or(Value::Null);
        self.seen.push((
            r.path.into(),
            body,
            r.account.is_some(),
            r.authorization.is_some(),
        ));
        if self.suspend == Some(r.path) {
            std::future::pending::<()>().await;
        }
        if r.path == "/keys"
            && let Some(on_mint) = &mut self.on_mint
        {
            on_mint();
        }
        if self.lose.take_if(|p| *p == r.path).is_some() {
            return None;
        }
        let status = if self.fail.take_if(|p| *p == r.path).is_some() {
            503
        } else {
            200
        };
        if r.path == "/account"
            && let Some(clock) = &self.clock
        {
            clock.set(clock.get() + 300);
        }
        let body = match r.path {
            "/" => "{}".into(),
            "/account" => json!({"automatic_top_up":self.top_up}).to_string(),
            "/keys" if self.identifier_only => json!({"key_id":"fixture-key-id"}).to_string(),
            "/keys" => json!({"key_id":self.key_id.unwrap_or("fixture-key-id"),"key":self.key.unwrap_or("fixture-session-private-value")}).to_string(),
            "/revoke" => "{}".into(),
            _ if self.no_report => "\n \n{\"id\":\"chatcmpl-fixture\",\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":5,\"total_tokens\":8}}".into(),
            _ if self.echo_metadata => json!({"provider":r.authorization.as_deref().and_then(|s|s.strip_prefix("Bearer ")).unwrap(),"id":"fixture-account-private-value"}).to_string(),
            _ if self.echo => "{\"content\":\"fixture-session-private-value fixture-account-private-value\"}".into(),
            _ => "\n \n{\"id\":\"gen-fixture\",\"provider\":\"Fixture Provider\",\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":5,\"total_tokens\":8,\"cost\":0.000000123456789012345678901234567890}}".into(),
        };
        Some(Response {
            status,
            body: Zeroizing::new(body.into_bytes()),
        })
    }
}
pub(crate) fn infer(s: &mut Store<MemoryStorage>, f: &mut Fake) -> Value {
    block_on(inference::infer(
        s,
        f,
        "https://127.0.0.1:1",
        Some(&candidate()),
        &request(),
        || 100,
    ))
}

fn plaintext(s: &Store<MemoryStorage>) -> Vec<Value> {
    let mut reader = Store::new(s.storage.clone(), DataKey(s.key.0), s.id.clone());
    s.records()
        .map(|n| {
            let b = &s.storage.files()[&n.to_string()];
            let event = reader.open(n, b).unwrap();
            reader.previous = Address(Sha256::digest(b).into());
            serde_json::to_value(&event).unwrap()
        })
        .collect()
}

#[test]
fn session_inspection_and_terminal_metadata_and_no_prompt_or_session_inference_key_in_records() {
    let mut s = ready();
    let mut f = Fake::default();
    assert_eq!(
        s.sessions()[0]["given"],
        json!([{"row":3,"machine":"fixture"}])
    );
    let result = infer(&mut s, &mut f);
    assert_eq!(result["finished"], true, "{result}");
    assert_eq!(
        s.sessions()[0]["given"],
        json!([{"row":3,"machine":"fixture"},{"row":2,"machine":null}])
    );
    let terminal = s
        .inference
        .calls
        .values()
        .last()
        .unwrap()
        .terminal
        .as_ref()
        .unwrap();
    assert_eq!(terminal.model.as_deref(), Some("fixture-model"));
    assert_eq!(
        terminal.requested_provider.as_deref(),
        Some("fixture-provider")
    );
    assert_eq!(
        terminal.reported_provider.as_deref(),
        Some("Fixture Provider")
    );
    assert_eq!(
        (
            terminal.prompt_tokens,
            terminal.completion_tokens,
            terminal.total_tokens
        ),
        (Some(3), Some(5), Some(8))
    );
    assert_eq!(
        terminal.spend.as_deref(),
        Some("0.000000123456789012345678901234567890")
    );
    assert_eq!(terminal.request_id.as_deref(), Some("gen-fixture"));
    for mut record in plaintext(&s) {
        if let Some(account) = record.get_mut("inference_account") {
            assert_eq!(account.as_object().unwrap().len(), 1);
            assert_eq!(account["credential"], "fixture-account-private-value");
            account["credential"] = Value::Null;
        }
        let text = record.to_string();
        for needle in [
            "fixture-session-private-value",
            "fixture-account-private-value",
            "prompt-only-do-not-journal",
        ] {
            assert!(!text.contains(needle), "journal contains {needle}");
        }
    }
    f.no_report = true;
    assert_eq!(infer(&mut s, &mut f)["finished"], true);
    let record = serde_json::to_value(
        s.inference
            .calls
            .values()
            .last()
            .unwrap()
            .terminal
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert!(record.get("reported_provider").is_none());
    assert!(record.get("spend").is_none());
    f.no_report = false;
    f.echo = true;
    let result = infer(&mut s, &mut f);
    assert_eq!(result["body"], "{\"content\":\"<redacted> <redacted>\"}");
    assert!(reopen(&s).inference.account.is_some());
}

#[test]
fn every_composition_and_route_and_readable_error() {
    let mut s = ready();
    let mut f = Fake::default();
    assert_eq!(infer(&mut s, &mut f)["finished"], true);
    f.lose = Some("/completion");
    assert_eq!(infer(&mut s, &mut f)["unresolved"], true);
    f.fail = Some("/completion");
    assert_eq!(infer(&mut s, &mut f)["status"], 503);
    assert_eq!(infer(&mut s, &mut f)["finished"], true);
    assert_eq!(f.seen.iter().filter(|r| r.0 == "/").count(), 1);
    assert_eq!(f.seen[0].0, "/");
    for r in f.seen.iter().filter(|r| r.0 == "/completion") {
        assert_eq!(
            r.1["provider"],
            json!({"zdr":true,"only":["fixture-provider"]})
        );
        assert_eq!(r.1["model"], "fixture-model");
        assert!(!r.2 && r.3);
        assert!(!r.1.to_string().contains("fixture-session-private-value"));
    }
    for r in f.seen.iter().filter(|r| r.0 != "/completion" && r.0 != "/") {
        assert!(r.2 && !r.3);
    }
    let bundle: toml::Value =
        toml::from_str(include_str!("../../../spec/bundle/inference.toml")).unwrap();
    for c in bundle["session"]["model"].as_array().unwrap() {
        let c = Candidate {
            slug: c["slug"].as_str().unwrap().into(),
            maker: c["maker"].as_str().unwrap().into(),
            provider: c["provider"].as_str().unwrap().into(),
        };
        assert_eq!(
            inference::compose(&c, &request())["provider"]["only"],
            json!([c.provider])
        );
    }
}

#[test]
fn refused_probe_top_up_and_lost_mint_contact_nothing_further() {
    let mut s = ready();
    let mut f = Fake {
        lose: Some("/"),
        ..Fake::default()
    };
    assert_eq!(
        infer(&mut s, &mut f)["refused"],
        "no route to that origin in this build"
    );
    assert_eq!(f.seen.len(), 1);
    f.top_up = true;
    assert!(
        infer(&mut s, &mut f)["refused"]
            .as_str()
            .unwrap()
            .contains("top-up")
    );
    assert!(!f.seen.iter().any(|r| r.0 == "/keys"));
    f.top_up = false;
    f.lose = Some("/keys");
    assert!(
        infer(&mut s, &mut f)["refused"]
            .as_str()
            .unwrap()
            .contains("mint")
    );
    let before = f.seen.len();
    assert!(
        infer(&mut s, &mut f)["refused"]
            .as_str()
            .unwrap()
            .contains("mint")
    );
    assert_eq!(f.seen.len(), before);
    assert!(
        s.inference_calls()
            .to_string()
            .contains("No revoke can name")
    );
    assert_eq!(s.inference_sweep(), Vec::<String>::new());
    block_on(s.bind("fixture-other")).unwrap();
    let mut r = request();
    r["machine"] = "fixture-other".into();
    assert_eq!(
        block_on(inference::infer(
            &mut s,
            &mut f,
            "https://127.0.0.1:1",
            Some(&candidate()),
            &r,
            || 100
        ))["finished"],
        true
    );
    let mint = f.seen.iter().find(|r| r.0 == "/keys").unwrap();
    assert_eq!(
        mint.1,
        json!({"cap":inference::SESSION_CAP,"expires":100+inference::SESSION_LIFETIME_SECONDS})
    );
}

#[test]
fn unresolved_is_unaccounted_never_resent_and_next_request_dispatches_after_reopen() {
    let mut s = ready();
    let mut f = Fake {
        lose: Some("/completion"),
        ..Fake::default()
    };
    let first = infer(&mut s, &mut f);
    assert_eq!(first["unresolved"], true, "{first}");
    assert!(first.get("failed").is_none());
    let call = first["call"].as_u64().unwrap();
    assert!(
        s.inference_calls()
            .to_string()
            .contains("unaccounted_spend")
    );
    assert_eq!(s.sessions()[0]["unaccounted_spend"]["count"], 1);
    assert_eq!(infer(&mut s, &mut f)["finished"], true);
    let mut reopened = reopen(&s);
    assert!(reopened.inference.calls[&call].terminal.is_none());
    block_on(reopened.bind("fixture")).unwrap();
    assert_eq!(infer(&mut reopened, &mut f)["finished"], true);
    assert_eq!(f.seen.iter().filter(|r| r.0 == "/completion").count(), 3);
    assert!(reopened.inference.calls[&call].terminal.is_none());
}

#[test]
fn request_validation_and_missing_selection_refuse_before_contact() {
    let mut s = ready();
    let mut f = Fake::default();
    let r = block_on(inference::infer(
        &mut s,
        &mut f,
        "https://127.0.0.1:1",
        None,
        &request(),
        || 100,
    ));
    assert_eq!(r["refused"], "missing session-start selection");
    for extra in ["model", "provider", "routing", "zdr"] {
        let mut r = request();
        r[extra] = true.into();
        assert!(!inference::valid_request(&r));
    }
    let mut r = request();
    r["machine"] = "missing".into();
    assert!(
        block_on(inference::infer(
            &mut s,
            &mut f,
            "https://127.0.0.1:1",
            Some(&candidate()),
            &r,
            || 100
        ))
        .get("refused")
        .is_some()
    );
    assert!(f.seen.is_empty());
}

#[test]
fn committed_intents_survive_suspended_send_and_every_storage_kill_boundary() {
    for path in ["/keys", "/completion", "/revoke"] {
        for boundary in 0..=12 {
            let mut s = ready();
            let mut f = Fake::default();
            if path != "/keys" {
                infer(&mut s, &mut f);
            }
            let storage = s.storage.clone();
            let before = s.next;
            f.seen.clear();
            if boundary < 12 {
                storage.fault(Fault::Die(boundary));
            }
            f.suspend = Some(path);
            {
                let mut future = std::pin::pin!(async {
                    if path == "/revoke" {
                        let id = s.end_inference_sessions().remove(0);
                        let (call, r) = s
                            .inference_prepare(
                                "",
                                InferenceIntent::Revoke {
                                    call: 0,
                                    key_id: id,
                                },
                                "https://127.0.0.1:1",
                                Value::Null,
                            )
                            .await?;
                        f.exchange(&r).await;
                        Ok(json!({"call":call}))
                    } else {
                        Ok::<_, String>(
                            inference::infer(
                                &mut s,
                                &mut f,
                                "https://127.0.0.1:1",
                                Some(&candidate()),
                                &request(),
                                || 100,
                            )
                            .await,
                        )
                    }
                });
                let _ = future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()));
            }
            let reopened = block_on(unlock(
                MemoryStorage::with_files(storage.files()),
                &Fixed,
                pass(),
            ))
            .unwrap();
            for sent in &f.seen {
                let kind = match sent.0.as_str() {
                    "/keys" => "mint",
                    "/completion" => "completion",
                    "/revoke" => "revoke",
                    "/account" => "account_read",
                    _ => continue,
                };
                assert!(
                    reopened
                        .inference
                        .calls
                        .values()
                        .any(|c| c.intent.call() >= before && c.intent.kind() == kind),
                    "send has no durable intent: {kind}, boundary {boundary}"
                );
            }
            if boundary == 12 {
                let kind = match path {
                    "/keys" => "mint",
                    "/completion" => "completion",
                    _ => "revoke",
                };
                assert!(
                    reopened
                        .inference
                        .calls
                        .values()
                        .any(|c| c.intent.call() >= before
                            && c.intent.kind() == kind
                            && c.terminal.is_none()),
                    "kill between record and send lost intent: {kind}"
                );
                assert!(
                    f.seen.iter().any(|r| r.0 == path),
                    "suspended request never reached transport"
                );
            }
        }
    }
}

#[test]
fn session_end_sweep_skips_revoke_intents_and_refuses_further_dispatch() {
    let mut s = ready();
    let mut f = Fake::default();
    infer(&mut s, &mut f);
    assert!(s.inference_sweep().is_empty());
    assert_eq!(reopen(&s).inference_sweep(), vec!["fixture-key-id"]);
    let ids = s.end_inference_sessions();
    assert_eq!(ids, vec!["fixture-key-id"]);
    assert!(s.sessions().is_empty());
    assert!(infer(&mut s, &mut f).get("refused").is_some());
    let (call, r) = block_on(s.inference_prepare(
        "",
        InferenceIntent::Revoke {
            call: 0,
            key_id: ids[0].clone(),
        },
        "https://127.0.0.1:1",
        Value::Null,
    ))
    .unwrap();
    assert_eq!(r.path, "/revoke");
    assert_eq!(s.inference.calls[&call].intent.call(), call);
    assert!(s.inference_sweep().is_empty());
    assert!(reopen(&s).inference_sweep().is_empty());
}

#[test]
fn decrypted_records_never_contain_session_inference_key_or_prompt() {
    let mut s = ready();
    let result = infer(&mut s, &mut Fake::default());
    assert_eq!(result["finished"], true);
    for record in plaintext(&s) {
        let text = record.to_string();
        assert!(
            !text.contains("fixture-session-private-value"),
            "decrypted record contains session inference key"
        );
        assert!(
            !text.contains("prompt-only-do-not-journal"),
            "decrypted record contains prompt body"
        );
    }
}

#[test]
fn inference_replay_refuses_bad_references_and_duplicate_terminals_without_plaintext() {
    let mut source = ready();
    infer(&mut source, &mut Fake::default());
    let completion = source
        .inference
        .calls
        .values()
        .last()
        .unwrap()
        .intent
        .clone();
    let terminal = source
        .inference
        .calls
        .values()
        .last()
        .unwrap()
        .terminal
        .clone()
        .unwrap();
    let bad = [
        Event::InferenceAccount {
            credential: "second-private-account".into(),
        },
        Event::InferenceTerminal(terminal),
        Event::InferenceTerminal(InferenceTerminal::new(999, 200)),
        Event::InferenceIntent(InferenceIntent::Completion {
            call: source.next,
            session: "absent-exposure".into(),
            key_id: "fixture-key-id".into(),
            model: "fixture-model".into(),
            requested_provider: "fixture-provider".into(),
            zdr: true,
        }),
        Event::InferenceIntent(completion),
        Event::InferenceIntent(InferenceIntent::Revoke {
            call: 999,
            key_id: "absent-key".into(),
        }),
    ];
    for event in bad {
        let mut s = reopen(&source);
        let n = s.next;
        block_on(s.commit(&event)).unwrap();
        let result = block_on(unlock(
            MemoryStorage::with_files(s.storage.files()),
            &Fixed,
            pass(),
        ));
        let why = match result {
            Ok(_) => panic!("bad record was accepted"),
            Err(why) => why,
        };
        assert!(why.contains(&format!("record {n}")), "{why}");
        for secret in [
            "second-private-account",
            "fixture-account-private-value",
            "fixture-session-private-value",
        ] {
            assert!(!why.contains(secret));
        }
    }
}

#[test]
fn identifier_only_mint_is_recorded_and_revoked_without_installing_a_holding() {
    let mut s = ready();
    let mut f = Fake {
        identifier_only: true,
        ..Fake::default()
    };
    assert!(infer(&mut s, &mut f).get("refused").is_some());
    let mint = s
        .inference
        .calls
        .values()
        .find(|c| c.intent.kind() == "mint")
        .unwrap()
        .terminal
        .as_ref()
        .unwrap();
    assert_eq!(
        (mint.key_id.as_deref(), mint.cap.as_deref(), mint.expires),
        (Some("fixture-key-id"), Some("0.10"), Some(1000))
    );
    assert_eq!(
        s.sessions()[0]["given"],
        json!([{"row":3,"machine":"fixture"}])
    );
    let before = f.seen.len();
    assert!(infer(&mut s, &mut f).get("refused").is_some());
    assert_eq!(
        before,
        f.seen.len(),
        "identifier-only mint must not be attempted again"
    );
    assert_eq!(reopen(&s).inference_sweep(), vec!["fixture-key-id"]);
    let id = s.end_inference_sessions().remove(0);
    assert_eq!(
        block_on(inference::send(
            &mut s,
            &mut f,
            "",
            InferenceIntent::Revoke {
                call: 0,
                key_id: id
            },
            "https://127.0.0.1:1",
            Value::Null
        ))
        .unwrap()["finished"],
        true
    );
    assert_eq!(f.seen.last().unwrap().0, "/revoke");
}

#[test]
fn expiry_reads_the_clock_after_account_read_immediately_before_mint() {
    let clock = Rc::new(std::cell::Cell::new(100));
    let mut s = ready();
    let mut f = Fake {
        clock: Some(clock.clone()),
        ..Fake::default()
    };
    assert_eq!(
        block_on(inference::infer(
            &mut s,
            &mut f,
            "https://127.0.0.1:1",
            Some(&candidate()),
            &request(),
            || clock.get()
        ))["finished"],
        true
    );
    let mint = f.seen.iter().find(|r| r.0 == "/keys").unwrap();
    assert_eq!(
        mint.1["expires"],
        400 + inference::SESSION_LIFETIME_SECONDS,
        "expiry must use the mint clock, after the account read"
    );
}

#[test]
fn readable_completion_after_session_end_commits_terminal_without_handback() {
    let mut s = ready();
    let mut f = Fake::default();
    infer(&mut s, &mut f);
    let session = block_on(s.session("fixture")).unwrap();
    let (call, r) = block_on(s.inference_prepare(
        &session,
        InferenceIntent::Completion {
            call: 0,
            session: session.clone(),
            key_id: String::new(),
            model: "fixture-model".into(),
            requested_provider: "fixture-provider".into(),
            zdr: true,
        },
        "https://127.0.0.1:1",
        inference::compose(&candidate(), &request()),
    ))
    .unwrap();
    let response = block_on(f.exchange(&r)).unwrap();
    s.end_inference_sessions();
    let result = block_on(s.inference_finish(call, &response, &r))
        .unwrap()
        .report;
    assert_eq!(result["refused"], "sessions ended");
    assert!(result.get("body").is_none());
    assert_eq!(
        reopen(&s).inference.calls[&call]
            .terminal
            .as_ref()
            .unwrap()
            .request_id
            .as_deref(),
        Some("gen-fixture"),
        "readable late completion must retain its terminal"
    );
    let req = crate::dispatch::typed_tests::request(crate::dispatch::Operation::Inference);
    assert_eq!(
        s.check_operation(&req),
        Err(crate::dispatch::RequestRefusal::SessionsEnded)
    );
}

#[test]
fn mint_requires_the_latest_account_read_for_its_own_session_live_and_replayed() {
    let mut s = ready();
    infer(&mut s, &mut Fake::default());
    let session = block_on(s.bind("fixture-other")).unwrap();
    // Another session's successful read cannot authorize this session's mint.
    for top_up in [Some(true), None] {
        let (call, sent) = block_on(s.inference_prepare(
            &session,
            InferenceIntent::AccountRead {
                call: 0,
                session: session.clone(),
            },
            "https://127.0.0.1:1",
            Value::Null,
        ))
        .unwrap();
        if let Some(value) = top_up {
            block_on(s.inference_finish(
                call,
                &Response {
                    status: 200,
                    body: Zeroizing::new(
                        json!({"automatic_top_up":value}).to_string().into_bytes(),
                    ),
                },
                &sent,
            ))
            .unwrap();
        }
        let intent = InferenceIntent::Mint {
            call: s.next,
            session: session.clone(),
            cap: "0.10".into(),
            expires: 1000,
        };
        assert_eq!(
            block_on(s.inference_prepare(
                &session,
                intent.clone(),
                "https://127.0.0.1:1",
                json!({"cap":"0.10","expires":1000})
            ))
            .err()
            .as_deref(),
            Some("mint has no top-up-off read")
        );
        let mut crafted = reopen(&s);
        block_on(crafted.commit(&Event::InferenceIntent(intent))).unwrap();
        assert!(
            block_on(unlock(
                MemoryStorage::with_files(crafted.storage.files()),
                &Fixed,
                pass()
            ))
            .is_err(),
            "replay accepted a mint authorized by another session's read"
        );
    }
    // An older off read in the same session cannot override its newer on read.
    for top_up in [false, true] {
        let (call, sent) = block_on(s.inference_prepare(
            &session,
            InferenceIntent::AccountRead {
                call: 0,
                session: session.clone(),
            },
            "https://127.0.0.1:1",
            Value::Null,
        ))
        .unwrap();
        block_on(s.inference_finish(
            call,
            &Response {
                status: 200,
                body: Zeroizing::new(json!({"automatic_top_up":top_up}).to_string().into_bytes()),
            },
            &sent,
        ))
        .unwrap();
    }
    assert!(!s.top_up_off(&session));
}

struct ObservedJournal {
    store: Store<MemoryStorage>,
    end_on_route: bool,
    end_after_append: bool,
    end_before_finish: bool,
    mint_prepares: usize,
}
impl InferenceJournal for ObservedJournal {
    type MintGuard = ();
    async fn mint_guard(&mut self, _: &str) {}
    fn can_send(&self, revoke: bool) -> bool {
        self.store.can_send(revoke)
    }
    async fn session(&mut self, m: &str) -> Result<String, String> {
        self.store.session(m).await
    }
    async fn has_key(&mut self, s: &str) -> Result<bool, String> {
        self.store.has_key(s).await
    }
    async fn prepare(
        &mut self,
        s: &str,
        i: InferenceIntent,
        o: &str,
        b: Value,
    ) -> Result<(u64, Request), String> {
        if matches!(i, InferenceIntent::Mint { .. }) {
            self.mint_prepares += 1;
        }
        let prepared = self.store.inference_prepare(s, i, o, b).await?;
        // The end begins after admission and the append, before the driver regains control.
        if self.end_after_append {
            self.store.end_inference_sessions();
        }
        Ok(prepared)
    }
    async fn finish(&mut self, c: u64, r: &Response, sent: &Request) -> Result<Finished, String> {
        if self.end_before_finish && self.store.inference.calls[&c].intent.kind() == "completion" {
            self.store.end_inference_sessions();
        }
        self.store.inference_finish(c, r, sent).await
    }
    async fn route(&mut self, o: &str, c: bool) -> bool {
        let chosen = self.store.route(o, c).await;
        if !c && self.end_on_route {
            self.store.end_inference_sessions();
        }
        chosen
    }
}
#[test]
fn end_during_intent_append_prevents_send_but_preserves_unresolved_intent() {
    let mut s = ready();
    let mut f = Fake::default();
    infer(&mut s, &mut f);
    let session = block_on(s.session("fixture")).unwrap();
    let mut journal = ObservedJournal {
        store: s,
        end_on_route: false,
        end_after_append: true,
        end_before_finish: false,
        mint_prepares: 0,
    };
    f.seen.clear();
    let result = block_on(inference::send(
        &mut journal,
        &mut f,
        &session,
        InferenceIntent::Completion {
            call: 0,
            session: session.clone(),
            key_id: String::new(),
            model: "fixture-model".into(),
            requested_provider: "fixture-provider".into(),
            zdr: true,
        },
        "https://127.0.0.1:1",
        inference::compose(&candidate(), &request()),
    ))
    .unwrap();
    assert!(
        f.seen.is_empty(),
        "completion sent after end-sessions began during append"
    );
    assert_eq!(result["unresolved"], true);
    let reopened = reopen(&journal.store);
    assert!(
        reopened.inference.calls[&result["call"].as_u64().unwrap()]
            .terminal
            .is_none()
    );
}

#[test]
fn top_up_on_refuses_before_preparing_an_inference_mint() {
    let mut journal = ObservedJournal {
        store: ready(),
        end_on_route: false,
        end_after_append: false,
        end_before_finish: false,
        mint_prepares: 0,
    };
    let mut transport = Fake {
        top_up: true,
        ..Fake::default()
    };
    let reply = block_on(inference::infer(
        &mut journal,
        &mut transport,
        "https://127.0.0.1:1",
        Some(&candidate()),
        &request(),
        || 100,
    ));
    assert_eq!(reply["call"], 7, "{reply}");
    assert_eq!(reply["finished"], true, "{reply}");
    assert_eq!(
        reply["refused"],
        "account read 7: automatic top-up must read off"
    );
    assert_eq!(
        journal.mint_prepares, 0,
        "top-up on must refuse before preparing a mint"
    );
    assert!(!transport.seen.iter().any(|r| r.0 == "/keys"));
}

#[test]
fn infer_preserves_unresolved_account_read_report_after_lost_response() {
    unresolved_account_read(false);
}

#[test]
fn infer_preserves_unresolved_account_read_report_when_sessions_end_after_append() {
    unresolved_account_read(true);
}

fn unresolved_account_read(ended: bool) {
    let mut journal = ObservedJournal {
        store: ready(),
        end_on_route: false,
        end_after_append: ended,
        end_before_finish: false,
        mint_prepares: 0,
    };
    let mut transport = Fake {
        lose: Some("/account"),
        ..Fake::default()
    };
    let report = block_on(inference::infer(
        &mut journal,
        &mut transport,
        "https://127.0.0.1:1",
        Some(&candidate()),
        &request(),
        || 100,
    ));
    assert_eq!(report["call"], 7, "{report}");
    assert_eq!(report["unresolved"], true, "{report}");
    assert_eq!(
        report["refused"], "no mint is sent without a recorded top-up-off read",
        "{report}"
    );
    assert!(report.get("finished").is_none(), "{report}");
    assert!(report.get("automatic_top_up").is_none(), "{report}");
    assert_eq!(journal.mint_prepares, 0);
    assert_eq!(transport.seen.iter().any(|r| r.0 == "/account"), !ended);
    assert!(!transport.seen.iter().any(|r| r.0 == "/keys"));
    let replay = reopen(&journal.store);
    assert_eq!(replay.inference.calls.len(), 1);
    let read = &replay.inference.calls[&7];
    assert_eq!(read.intent.kind(), "account_read");
    assert!(read.terminal.is_none());
}

#[test]
fn late_completion_metadata_redacts_the_request_credential_after_holdings_clear() {
    let mut journal = ObservedJournal {
        store: ready(),
        end_on_route: false,
        end_after_append: false,
        end_before_finish: true,
        mint_prepares: 0,
    };
    let mut transport = Fake {
        echo_metadata: true,
        ..Fake::default()
    };
    let reply = block_on(inference::infer(
        &mut journal,
        &mut transport,
        "https://127.0.0.1:1",
        Some(&candidate()),
        &request(),
        || 100,
    ));
    assert_eq!(reply["refused"], "sessions ended");
    let terminal = journal
        .store
        .inference
        .calls
        .values()
        .last()
        .unwrap()
        .terminal
        .as_ref()
        .unwrap();
    assert_eq!(
        terminal.reported_provider.as_deref(),
        Some("<redacted>"),
        "late metadata must not journal a cleared session inference key"
    );
    assert_eq!(terminal.request_id.as_deref(), Some("<redacted>"));
    assert!(
        plaintext(&journal.store)
            .iter()
            .all(|r| !r.to_string().contains("fixture-session-private-value"))
    );
}

fn prepared_completion(s: &mut Store<MemoryStorage>) -> (u64, Request) {
    let session = block_on(s.session("fixture")).unwrap();
    block_on(s.inference_prepare(
        &session,
        InferenceIntent::Completion {
            call: 0,
            session: session.clone(),
            key_id: String::new(),
            model: "fixture-model".into(),
            requested_provider: "fixture-provider".into(),
            zdr: true,
        },
        "https://127.0.0.1:1",
        inference::compose(&candidate(), &request()),
    ))
    .unwrap()
}

fn escaped_echo(field: &str, secret: &str, ended: bool) {
    let mut s = ready();
    assert_eq!(infer(&mut s, &mut Fake::default())["finished"], true);
    let (call, sent) = prepared_completion(&mut s);
    if ended {
        s.end_inference_sessions();
    }
    // No raw copy appears on the wire; the parser decodes it before metadata is appended.
    let escaped = secret
        .bytes()
        .map(|b| format!("\\u{b:04x}"))
        .collect::<String>();
    let response = Response {
        status: 200,
        body: Zeroizing::new(format!("{{\"{field}\":\"{escaped}\"}}").into_bytes()),
    };
    let finished = block_on(s.inference_finish(call, &response, &sent)).unwrap();
    if ended {
        assert!(finished.report.get("body").is_none());
    }
    let reopened = reopen(&s);
    let t = reopened.inference.calls[&call].terminal.as_ref().unwrap();
    let value = if field == "provider" {
        &t.reported_provider
    } else {
        &t.request_id
    };
    assert_eq!(value.as_deref(), Some(crate::redaction::MARKER));
    assert!(!serde_json::to_string(t).unwrap().contains(secret));
}

#[test]
fn escaped_session_inference_key_in_provider_is_scanned_after_decoding() {
    escaped_echo("provider", "fixture-session-private-value", false);
}

#[test]
fn escaped_account_credential_in_request_id_is_scanned_after_decoding() {
    escaped_echo("id", "fixture-account-private-value", false);
}

#[test]
fn escaped_response_metadata_after_session_end_uses_the_request_credentials() {
    escaped_echo("provider", "fixture-session-private-value", true);
    escaped_echo("id", "fixture-account-private-value", true);
}

#[test]
fn redaction_refusal_still_commits_a_readable_terminal_and_withholds_the_body() {
    let mut s = ready();
    // This is accepted header text, but any replacement marker would still contain it.
    let mut f = Fake {
        key: Some("red"),
        ..Fake::default()
    };
    assert_eq!(infer(&mut s, &mut f)["finished"], true);
    let (call, sent) = prepared_completion(&mut s);
    let response = Response {
        status: 200,
        body: Zeroizing::new(
            br#"{"provider":"red","id":"safe-id","usage":{"prompt_tokens":3}}"#.to_vec(),
        ),
    };
    let result = block_on(s.inference_finish(call, &response, &sent))
        .unwrap()
        .report;
    assert!(
        result["refused"]
            .as_str()
            .unwrap()
            .contains("redaction boundary")
    );
    assert!(result.get("body").is_none());
    let reopened = reopen(&s);
    let t = reopened.inference.calls[&call].terminal.as_ref().unwrap();
    assert_eq!(t.status, 200);
    assert_eq!(t.reported_provider, None);
    assert_eq!(t.request_id.as_deref(), Some("safe-id"));
    assert_eq!(t.prompt_tokens, Some(3));
    f.echo_metadata = true;
    let result = infer(&mut s, &mut f);
    assert!(
        result["refused"]
            .as_str()
            .unwrap()
            .contains("redaction boundary")
    );
    let last = reopen(&s).inference.calls.values().last().unwrap().clone();
    assert_eq!(last.terminal.unwrap().status, 200);
}

#[test]
fn delayed_unlock_sweep_only_revokes_replayed_identifiers() {
    let mut original = ready();
    infer(&mut original, &mut Fake::default());
    let mut s = reopen(&original);
    block_on(s.bind("fixture")).unwrap();
    let mut f = Fake {
        key_id: Some("current-worker-key-id"),
        ..Fake::default()
    };
    assert_eq!(infer(&mut s, &mut f)["finished"], true);
    let ids = s.inference_sweep();
    assert_eq!(ids, vec!["fixture-key-id"]);
    for key_id in ids {
        let result = block_on(inference::send(
            &mut s,
            &mut f,
            "",
            InferenceIntent::Revoke { call: 0, key_id },
            "https://127.0.0.1:1",
            Value::Null,
        ))
        .unwrap();
        assert_eq!(result["finished"], true);
    }
    assert!(s.inference_sweep().is_empty());
    assert_eq!(infer(&mut s, &mut f)["finished"], true);
    assert_eq!(s.end_inference_sessions(), vec!["current-worker-key-id"]);
}

#[test]
fn mint_finishing_during_session_end_records_its_revoke_before_returning() {
    for identifier_only in [false, true] {
        let mut s = ready();
        let mut f = Fake {
            identifier_only,
            ..Fake::default()
        };
        let session = block_on(s.session("fixture")).unwrap();
        block_on(inference::send(
            &mut s,
            &mut f,
            &session,
            InferenceIntent::AccountRead {
                call: 0,
                session: session.clone(),
            },
            "https://127.0.0.1:1",
            Value::Null,
        ))
        .unwrap();
        let (call, sent) = block_on(s.inference_prepare(
            &session,
            InferenceIntent::Mint {
                call: 0,
                session: session.clone(),
                cap: "0.10".into(),
                expires: 1000,
            },
            "https://127.0.0.1:1",
            json!({"cap":"0.10","expires":1000}),
        ))
        .unwrap();
        assert!(s.end_inference_sessions().is_empty());
        let response = block_on(f.exchange(&sent)).unwrap();
        let finished = block_on(s.inference_finish(call, &response, &sent)).unwrap();
        let (revoke_call, revoke) = finished
            .late_revoke
            .expect("late mint owes an immediate revoke");
        assert_eq!(revoke.path, "/revoke");
        assert!(s.sessions.is_empty());
        assert!(matches!(&reopen(&s).inference.calls[&revoke_call].intent,
            InferenceIntent::Revoke { key_id, .. } if key_id == "fixture-key-id"));
    }
}

#[test]
fn post_terminal_failures_report_finished_with_their_own_refusal() {
    for ended in [false, true] {
        let mut s = ready();
        let mut f = Fake::default();
        let session = block_on(s.session("fixture")).unwrap();
        block_on(inference::send(
            &mut s,
            &mut f,
            &session,
            InferenceIntent::AccountRead {
                call: 0,
                session: session.clone(),
            },
            "https://127.0.0.1:1",
            Value::Null,
        ))
        .unwrap();
        let (call, request) = block_on(s.inference_prepare(
            &session,
            InferenceIntent::Mint {
                call: 0,
                session: session.clone(),
                cap: "0.10".into(),
                expires: 1000,
            },
            "https://127.0.0.1:1",
            json!({"cap":"0.10","expires":1000}),
        ))
        .unwrap();
        let response = block_on(f.exchange(&request)).unwrap();
        if ended {
            s.end_inference_sessions();
            // The terminal's create/close/move succeed; the revoke's create fails.
            s.storage.fault(Fault::Fail(4));
        } else {
            s.live(&session)
                .unwrap()
                .given
                .borrow_mut()
                .push(crate::binding::Holding {
                    machine: String::new(),
                    credential: Box::new(SessionInferenceKey(b"already-held-key".to_vec())),
                });
        }
        let result = block_on(s.inference_finish(call, &response, &request)).unwrap();
        assert_eq!(result.report["finished"], true);
        assert!(result.report.get("unresolved").is_none());
        let why = result.report["refused"].as_str().unwrap();
        if ended {
            assert!(why.contains("no revoke was recorded"), "{why}");
            assert!(why.contains("next unlock's sweep or its expiry"), "{why}");
            assert!(
                s.inference
                    .calls
                    .values()
                    .all(|c| c.intent.kind() != "revoke")
            );
            assert_eq!(reopen(&s).inference_sweep(), vec!["fixture-key-id"]);
        } else {
            assert_eq!(why, "second session inference key");
        }
        assert!(result.late_revoke.is_none());
        assert!(reopen(&s).inference.calls[&call].terminal.is_some());
    }
}

struct SharedJournal {
    store: Rc<std::cell::RefCell<Store<MemoryStorage>>>,
    end_after_mint_append: bool,
}
impl InferenceJournal for SharedJournal {
    type MintGuard = ();
    async fn mint_guard(&mut self, _: &str) {}
    fn can_send(&self, revoke: bool) -> bool {
        self.store.borrow().can_send(revoke)
    }
    async fn session(&mut self, machine: &str) -> Result<String, String> {
        block_on(self.store.borrow_mut().session(machine))
    }
    async fn has_key(&mut self, session: &str) -> Result<bool, String> {
        block_on(self.store.borrow_mut().has_key(session))
    }
    async fn prepare(
        &mut self,
        session: &str,
        intent: InferenceIntent,
        origin: &str,
        body: Value,
    ) -> Result<(u64, Request), String> {
        let mint = intent.kind() == "mint";
        let result = block_on(
            self.store
                .borrow_mut()
                .inference_prepare(session, intent, origin, body),
        );
        if mint && result.is_ok() && self.end_after_mint_append {
            assert!(self.store.borrow_mut().end_inference_sessions().is_empty());
        }
        result
    }
    async fn finish(
        &mut self,
        call: u64,
        response: &Response,
        sent: &Request,
    ) -> Result<Finished, String> {
        block_on(
            self.store
                .borrow_mut()
                .inference_finish(call, response, sent),
        )
    }
    async fn route(&mut self, origin: &str, chosen: bool) -> bool {
        block_on(self.store.borrow_mut().route(origin, chosen))
    }
}

#[test]
fn infer_preserves_committed_mint_report_when_sessions_end_in_flight() {
    for fail_revoke in [true, false] {
        let shared = Rc::new(std::cell::RefCell::new(ready()));
        let mut journal = SharedJournal {
            store: shared.clone(),
            end_after_mint_append: false,
        };
        let mut transport = Fake {
            on_mint: Some(Box::new({
                let shared = shared.clone();
                move || {
                    let mut store = shared
                        .try_borrow_mut()
                        .expect("no writer across transport wait");
                    let mint = store.inference.calls.values().last().unwrap();
                    assert_eq!(mint.intent.kind(), "mint");
                    assert!(mint.terminal.is_none(), "mint is still in flight");
                    assert!(store.end_inference_sessions().is_empty());
                    if fail_revoke {
                        // Commit the terminal, then fail the late revoke's create.
                        store.storage.fault(Fault::Fail(4));
                    }
                }
            })),
            ..Fake::default()
        };
        let report = block_on(inference::infer(
            &mut journal,
            &mut transport,
            "https://127.0.0.1:1",
            Some(&candidate()),
            &request(),
            || 100,
        ));
        assert_eq!(report["finished"], true, "{report}");
        let call = report["call"].as_u64().expect("committed mint call id");
        let why = report["refused"].as_str().unwrap();
        if fail_revoke {
            assert!(why.contains("no revoke was recorded"), "{report}");
            assert!(
                why.contains("next unlock's sweep or its expiry"),
                "{report}"
            );
        } else {
            assert_eq!(why, "sessions ended");
        }
        assert!(report.get("unresolved").is_none());
        assert!(!transport.seen.iter().any(|r| r.0 == "/completion"));
        let store = shared.borrow();
        let replay = reopen(&store);
        assert_eq!(replay.inference.calls[&call].intent.kind(), "mint");
        assert!(replay.inference.calls[&call].terminal.is_some());
        if fail_revoke {
            assert_eq!(replay.inference_sweep(), vec!["fixture-key-id"]);
            assert!(!transport.seen.iter().any(|r| r.0 == "/revoke"));
        } else {
            assert!(transport.seen.iter().any(|r| r.0 == "/revoke"));
        }
    }
}

#[test]
fn infer_preserves_unresolved_mint_report_when_sessions_end_after_send() {
    unresolved_mint_at_session_end(false);
}

#[test]
fn infer_preserves_unresolved_mint_report_when_sessions_end_after_append() {
    unresolved_mint_at_session_end(true);
}

fn unresolved_mint_at_session_end(after_append: bool) {
    let shared = Rc::new(std::cell::RefCell::new(ready()));
    let mut journal = SharedJournal {
        store: shared.clone(),
        end_after_mint_append: after_append,
    };
    let mut transport = Fake {
        lose: Some("/keys"),
        on_mint: Some(Box::new({
            let shared = shared.clone();
            move || {
                let mut store = shared
                    .try_borrow_mut()
                    .expect("no writer across transport wait");
                assert!(store.end_inference_sessions().is_empty());
            }
        })),
        ..Fake::default()
    };
    let report = block_on(inference::infer(
        &mut journal,
        &mut transport,
        "https://127.0.0.1:1",
        Some(&candidate()),
        &request(),
        || 100,
    ));
    assert_eq!(
        report["unresolved"], true,
        "after_append={after_append}: {report}"
    );
    assert_eq!(report["call"], 9, "{report}");
    assert_eq!(report["refused"], "sessions ended", "{report}");
    assert!(report.get("finished").is_none());
    assert_eq!(transport.seen.iter().any(|r| r.0 == "/keys"), !after_append);
    assert!(
        !transport
            .seen
            .iter()
            .any(|r| r.0 == "/completion" || r.0 == "/revoke")
    );
    let replay = reopen(&shared.borrow());
    let mint = &replay.inference.calls[&9];
    assert_eq!(mint.intent.kind(), "mint");
    assert!(mint.terminal.is_none());
    assert_eq!(replay.inference.calls.len(), 2);
}

#[test]
fn cold_probe_refuses_when_route_await_ends_sessions() {
    let mut journal = ObservedJournal {
        store: ready(),
        end_on_route: true,
        end_after_append: false,
        end_before_finish: false,
        mint_prepares: 0,
    };
    let mut transport = Fake::default();
    assert_eq!(
        block_on(inference::probe(
            &mut journal,
            &mut transport,
            "https://127.0.0.1:1",
            false
        )),
        Err("sessions ended".into())
    );
    assert!(
        transport.seen.is_empty(),
        "OPTIONS sent after route await ended sessions"
    );
    assert!(!block_on(journal.store.route("https://127.0.0.1:1", false)));
}

#[test]
fn revoke_probe_still_sends_when_route_await_ends_sessions() {
    let mut journal = ObservedJournal {
        store: ready(),
        end_on_route: true,
        end_after_append: false,
        end_before_finish: false,
        mint_prepares: 0,
    };
    let mut transport = Fake::default();
    assert_eq!(
        block_on(inference::probe(
            &mut journal,
            &mut transport,
            "https://127.0.0.1:1",
            true
        )),
        Ok(())
    );
    assert_eq!(transport.seen.len(), 1);
    assert_eq!(transport.seen[0].0, "/");
}

#[test]
fn non_success_account_read_keeps_call_status_and_prepares_no_mint() {
    let mut journal = ObservedJournal {
        store: ready(),
        end_on_route: false,
        end_after_append: false,
        end_before_finish: false,
        mint_prepares: 0,
    };
    let mut transport = Fake {
        fail: Some("/account"),
        ..Fake::default()
    };
    let report = block_on(inference::infer(
        &mut journal,
        &mut transport,
        "https://127.0.0.1:1",
        Some(&candidate()),
        &request(),
        || 100,
    ));
    assert_eq!(report["call"], 7, "{report}");
    assert_eq!(report["status"], 503, "{report}");
    assert_eq!(report["finished"], true, "{report}");
    assert_eq!(
        report["refused"],
        "account read 7: automatic top-up must read off"
    );
    assert_eq!(journal.mint_prepares, 0);
    assert!(!transport.seen.iter().any(|r| r.0 == "/keys"));
}

#[test]
fn non_success_account_read_sends_no_mint_control() {
    let mut store = ready();
    let mut transport = Fake {
        fail: Some("/account"),
        ..Fake::default()
    };
    infer(&mut store, &mut transport);
    assert!(!transport.seen.iter().any(|r| r.0 == "/keys"));
}

#[test]
fn connection_admission_after_end_records_no_refusal_live_or_replayed() {
    let mut store = ready();
    store.end_inference_sessions();
    let before = store.storage.files();
    assert!(
        matches!(block_on(store.connection_session("fixture-other")),
        Err(crate::binding::AdmissionRefusal::Journal(why)) if why == "sessions ended")
    );
    assert_eq!(store.storage.files(), before);
    assert!(store.connection_refusals().is_empty());
    assert!(reopen(&store).connection_refusals().is_empty());
}

#[test]
fn signature_check_after_end_records_no_refusal_live_or_replayed() {
    let mut store = ready();
    block_on(store.bind_with_modes("fixture-other", &[crate::modes::Mode::NoArtifactPin])).unwrap();
    assert!(store.installation_unpinned("fixture-other"));
    // End both sessions before checking the unpinned installation's lowering form.
    store.end_inference_sessions();
    let before = store.storage.files();
    assert!(
        matches!(block_on(store.check_signature("fixture-other", b"echo SigLevel = Never >> /etc/pacman.conf")),
        Err(AppendRefusal::Storage(why)) if why == "sessions ended")
    );
    assert_eq!(store.storage.files(), before);
    assert!(store.signature_refusals().is_empty());
    assert!(reopen(&store).signature_refusals().is_empty());
}
