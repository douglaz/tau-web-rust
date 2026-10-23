//! The attempt itself, on the browser's WebSocket: wasm32 only.

use super::wait;
use super::{AppendRefusal, BoundJournal, Entry, PinSource};
use crate::binding::{AdmissionRefusal, Session};
use crate::dispatch::{Approval, CommandHold, DestructiveDisposition, DispatchRefusal};
use crate::jobs::{self, Evidence, Record};
use futures_util::{SinkExt, StreamExt};
use pharos::{Observable, ObserveConfig};
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, client};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use ws_stream_wasm::{WsEvent, WsMessage, WsMeta, WsStream};

/// A machine as reached through the relay: `wss://<relay>/v1/tcp/<host>/<port>` (`WIR-1`,
/// paid-tcp-relay `844e834`).
pub struct Target {
    pub machine: String,
    /// The relay's URL, `wss://…/`, which the AUTH's `relay` tag names.
    pub relay: String,
    pub host: String,
    pub port: u16,
    pub user: String,
}

/// What a completed command returns, including the journal read-back it was reconciled with.
pub struct Done {
    pub seq: u64,
    pub sent: Vec<u8>,
    pub recorded: Entry,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: u32,
    pub terminal: u64,
    pub host_key: String,
    pub evidence: jobs::Report,
}

/// Why an attempt ended without the command being sent, or without its result.
#[derive(Debug)]
pub enum Refusal {
    /// No pin for the machine: refused before the relay is contacted (`CHN-R4`, `CNF-23`).
    NoPin,
    NoEntry(String),
    Unbound(String),
    Provenance,
    /// No SSH client key or relay key to use: refused before the relay is contacted.
    NoCredentials,
    /// The relay refused the AUTH (`WIR-7`, paid-tcp-relay `844e834`) with this reason and close
    /// code.
    Relay {
        reason: String,
        close_code: Option<u16>,
    },
    /// The presented host key is not the pin: halted in the key exchange (`SEC-11`).
    HostKey {
        pinned: String,
        presented: String,
    },
    /// The journal refused the append, so no `exec` was sent (`STA-3`).
    Journal(String),
    Disposition(DestructiveDisposition),
    Barrier(Vec<crate::dispatch::OperationIntent>),
    Held(Value),
    LaunchTooLong {
        bytes: usize,
    },
    Unresolved {
        call: u64,
        why: String,
        evidence: Option<Box<jobs::Report>>,
    },
    /// Anything else: the transport, the protocol, authentication.
    Failed(String),
}

impl Refusal {
    pub fn to_json(&self) -> Value {
        match self {
            Refusal::Held(answer) => answer.clone(),
            Refusal::Barrier(calls) => json!({"refused":"barrier","calls":calls}),
            Refusal::LaunchTooLong { bytes } => json!({
                "refused": "launch-too-long",
                "why": "command is too long to launch; shorten the command",
                "bytes": bytes,
                "limit": jobs::MAX_LAUNCH_BYTES,
            }),
            Refusal::Unbound(machine) => json!({"refused":"unbound","machine":machine}),
            Refusal::NoEntry(machine) => json!({"refused":"no-entry","machine":machine}),
            Refusal::Provenance => json!({"refused":"provenance"}),
            Refusal::NoPin => json!({ "refused": "no-pin" }),
            Refusal::NoCredentials => json!({ "refused": "no-credentials" }),
            Refusal::Relay { reason, close_code } => {
                json!({ "refused": "relay", "reason": reason, "close_code": close_code })
            }
            Refusal::HostKey { pinned, presented } => {
                json!({ "refused": "host-key", "pinned": pinned, "presented": presented })
            }
            Refusal::Journal(why) => json!({ "refused": "journal", "why": why }),
            Refusal::Disposition(record) => {
                json!({ "refused": "disposition", "disposition": record.disposition, "continuation": record.continuation })
            }
            Refusal::Unresolved {
                call,
                why,
                evidence,
            } => jobs::unresolved(*call, why, evidence.as_deref()),
            Refusal::Failed(why) => json!({ "refused": "failed", "why": why }),
        }
    }
}

/// An attempt's outcome as the worker reports it to the page: output and the reconciled record,
/// or the refusal. Never key material.
pub fn report(outcome: &Result<Done, Refusal>) -> Value {
    match outcome {
        Ok(done) => json!({
            "done": true,
            "seq": done.seq,
            "call": done.seq,
            "terminal": done.terminal,
            "sent": hex::encode(&done.sent),
            "recorded": hex::encode(&done.recorded.command),
            "recorded_machine": done.recorded.machine,
            "stdout": String::from_utf8_lossy(&done.stdout),
            "stderr": String::from_utf8_lossy(&done.stderr),
            "exit_status": done.exit_status,
            "host_key": done.host_key,
            "job_record": done.evidence,
        }),
        Err(refusal) => refusal.to_json(),
    }
}

fn append_refusal(refusal: AppendRefusal) -> Refusal {
    match refusal {
        AppendRefusal::Policy(DispatchRefusal::NoEntry { machine }) => Refusal::NoEntry(machine),
        AppendRefusal::Policy(DispatchRefusal::Provenance) => Refusal::Provenance,
        AppendRefusal::Storage(why) => Refusal::Journal(why),
        AppendRefusal::Policy(DispatchRefusal::Disposition(record)) => Refusal::Disposition(record),
        AppendRefusal::Policy(DispatchRefusal::TypedBarrier { calls }) => Refusal::Barrier(calls),
        AppendRefusal::Policy(DispatchRefusal::Held(_)) => {
            unreachable!("hold collects before reporting")
        }
    }
}

fn failed(context: &str) -> impl Fn(String) -> Refusal + '_ {
    move |e| Refusal::Failed(format!("{context}: {e}"))
}

/// The host-key check, inside the SSH key exchange and before authentication. `false` makes
/// russh abort with `Error::UnknownKey`; the presented fingerprint is kept so the halt can name
/// both keys.
struct PinCheck {
    pinned: String,
    presented: Arc<Mutex<Option<String>>>,
}

impl client::Handler for PinCheck {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let presented = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.fingerprint(HashAlg::Sha256),
            PublicKeyOrCertificate::Certificate(cert) => {
                cert.public_key().fingerprint(HashAlg::Sha256)
            }
        }
        .to_string();
        let matches = presented == self.pinned;
        *self.presented.lock().expect("pin check lock") = Some(presented);
        Ok(matches)
    }
}

/// Runs `command` on `target`, recording it in `journal` first. `tamper_auth` is the tracer's
/// way to send a wrongly signed AUTH; it exists only in the tracer build.
pub async fn run_command(
    pins: &impl PinSource,
    journal: &mut impl BoundJournal,
    target: &Target,
    command: &[u8],
    #[cfg(feature = "tracer")] tamper_auth: bool,
) -> Result<Done, Refusal> {
    let session = resolve(journal, &target.machine).await?;
    if let Err(refusal) = journal.check(&target.machine).await {
        return Err(admission_refusal(
            pins,
            journal,
            &session,
            target,
            refusal,
            #[cfg(feature = "tracer")]
            tamper_auth,
        )
        .await);
    }
    let bytes = jobs::launch_size(&target.machine, command);
    if !jobs::launch_fits(bytes) {
        return Err(Refusal::LaunchTooLong { bytes });
    }
    let (ssh, pinned, host_key) = connect(
        pins,
        journal,
        &session,
        target,
        #[cfg(feature = "tracer")]
        tamper_auth,
    )
    .await?;
    let mut channel = ssh
        .channel_open_session()
        .await
        .map_err(|e| Refusal::Failed(format!("session channel: {e}")))?;

    // ARC-8, STA-4: the record is appended immediately before the bytes leave, and a failed
    // append means they do not (STA-3).
    let entry = Entry {
        provenance: Some(crate::dispatch::CommandProvenance {
            target: crate::dispatch::Target::Entry(target.machine.clone()),
            session: Some(session.identity.clone()),
            requester: crate::dispatch::Requester::Session,
        }),
        machine: target.machine.clone(),
        command: command.to_vec(),
    };
    let approval = Approval::HarnessPin {
        machine: target.machine.clone(),
        fingerprint: pinned,
    };
    let seq = match journal.append(&entry, &approval).await {
        Ok(seq) => seq,
        Err(refusal) => {
            // No exec for this request, even when it already opened a channel.
            drop(channel);
            drop(ssh);
            return Err(admission_refusal(
                pins,
                journal,
                &session,
                target,
                refusal,
                #[cfg(feature = "tracer")]
                tamper_auth,
            )
            .await);
        }
    };
    // No await separates committed intent from registration in this single-threaded worker.
    let own = wait::DispatchResult::new(seq);
    let outcome = async {
        let intent = journal
            .intent(seq)
            .await
            .ok_or_else(|| Refusal::Unresolved {
                call: seq,
                why: "intent read-back missing".into(),
                evidence: None,
            })?;
        let job = intent.job.as_deref().expect("new intent has job identity");
        let sent = jobs::launch(job, &entry.machine, &entry.command).into_bytes();
        let result = exec_record(&mut channel, &sent).await;
        let _ = ssh
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        // CNF-30: the journal determines the wrapper's exact transmitted bytes.
        let recorded = journal.read(seq).await;
        let replayed = journal.intent(seq).await;
        let recorded = match (recorded, replayed) {
            (Some(recorded), Some(replayed))
                if replayed.job.as_deref().is_some_and(|id| {
                    jobs::launch(id, &recorded.machine, &recorded.command).as_bytes() == sent
                }) && recorded.machine == target.machine =>
            {
                recorded
            }
            _ => {
                return Err(Refusal::Unresolved {
                    call: seq,
                    why: "transcript does not reconcile with command bytes".into(),
                    evidence: result.as_ref().ok().map(|record| {
                        Box::new(jobs::uncommitted(
                            &Evidence {
                                call: seq,
                                job: job.into(),
                                record: record.clone(),
                            },
                            &entry.machine,
                            &hex::encode(&entry.command),
                        ))
                    }),
                });
            }
        };
        let record = result.map_err(|why| Refusal::Unresolved {
            call: seq,
            why,
            evidence: None,
        })?;
        let received = Evidence {
            call: seq,
            job: job.into(),
            record,
        };
        let evidence =
            journal
                .job_evidence(&received)
                .await
                .map_err(|why| Refusal::Unresolved {
                    call: seq,
                    why: format!("job evidence append: {why}"),
                    evidence: Some(Box::new(jobs::uncommitted(
                        &received,
                        &entry.machine,
                        &hex::encode(&entry.command),
                    ))),
                })?;
        if evidence.state != jobs::State::Finished {
            return Err(Refusal::Unresolved {
                call: seq,
                why: format!("job record: {:?}", evidence.state),
                evidence: Some(Box::new(evidence)),
            });
        }
        Ok(Done {
            seq,
            sent,
            recorded,
            stdout: evidence.stdout.as_bytes().to_vec(),
            stderr: evidence.stderr.as_bytes().to_vec(),
            exit_status: evidence.exit_status.expect("finished record"),
            terminal: evidence.number.expect("committed evidence"),
            host_key,
            evidence,
        })
    }
    .await;
    own.finish(report(&outcome));
    outcome
}

/// Admission's hold collects only its snapshot of holding calls; it never resumes dispatch.
async fn admission_refusal(
    pins: &impl PinSource,
    journal: &mut impl BoundJournal,
    session: &Session,
    target: &Target,
    refusal: AppendRefusal,
    #[cfg(feature = "tracer")] tamper_auth: bool,
) -> Refusal {
    let AppendRefusal::Policy(DispatchRefusal::Held(hold)) = refusal else {
        return append_refusal(refusal);
    };
    Refusal::Held(
        held(
            pins,
            journal,
            session,
            target,
            hold,
            #[cfg(feature = "tracer")]
            tamper_auth,
        )
        .await,
    )
}

async fn held(
    pins: &impl PinSource,
    journal: &mut impl BoundJournal,
    session: &Session,
    target: &Target,
    hold: CommandHold,
    #[cfg(feature = "tracer")] tamper_auth: bool,
) -> Value {
    let stop = wait::Stop::new(&target.machine);
    let mut reports = Vec::new();
    let mut connection = None;
    let mut unreachable: Option<Value> = None;
    let calls: Vec<_> = hold
        .calls
        .iter()
        .map(|intent| (intent, wait::result(intent.call)))
        .collect();
    for (intent, own) in calls {
        let not_read = |why: Value| json!({"call":intent.call,"not_read":true,"why":why});
        let Some(job) = intent.job.as_deref() else {
            reports.push(not_read(json!(
                "no job identity; only a disposition can release this call"
            )));
            continue;
        };
        if stop.stopped() {
            reports.push(not_read(json!("stopped before record was read")));
            continue;
        }
        if let Some(own) = own {
            let result = stop.until(own.get()).await;
            reports.push(match result {
                Some(result) => json!({"call":intent.call,"dispatch_result":result}),
                None => not_read(json!("stopped while awaiting own dispatch's result")),
            });
            continue;
        }
        if let Some(why) = &unreachable {
            reports.push(not_read(why.clone()));
            continue;
        }
        if connection.is_none() {
            match stop
                .until(connect(
                    pins,
                    journal,
                    session,
                    target,
                    #[cfg(feature = "tracer")]
                    tamper_auth,
                ))
                .await
            {
                Some(Ok((ssh, _, _))) => connection = Some(ssh),
                Some(Err(why)) => {
                    let reason = match why {
                        Refusal::Failed(why) => json!({"connection":"unavailable","why":why}),
                        other => other.to_json(),
                    };
                    let why = json!({"unreachable":reason});
                    reports.push(not_read(why.clone()));
                    unreachable = Some(why);
                    continue;
                }
                None => {
                    reports.push(not_read(json!("stopped before record was read")));
                    continue;
                }
            }
        }
        let ssh = connection.as_ref().expect("connected for collection");
        let read = async {
            let mut channel = ssh
                .channel_open_session()
                .await
                .map_err(|e| format!("session channel: {e}"))?;
            exec_record(&mut channel, jobs::collect(job).as_bytes()).await
        };
        let record = match stop.until(read).await {
            Some(Ok(record)) => record,
            Some(Err(why)) => {
                reports.push(not_read(json!(why)));
                if ssh.is_closed() {
                    unreachable = Some(json!("connection lost"));
                }
                continue;
            }
            None => {
                reports.push(not_read(json!("stopped while reading record")));
                continue;
            }
        };
        let received = Evidence {
            call: intent.call,
            job: job.into(),
            record,
        };
        #[cfg(feature = "tracer")]
        crate::testonly::completed_read();
        match journal.job_evidence_unless_stopped(&received, &stop).await {
            Some(Ok(report)) => {
                reports.push(serde_json::to_value(report).expect("report serialization"))
            }
            result => {
                let why = match result {
                    Some(Err(why)) => format!("job evidence append: {why}"),
                    None => "wait stopped before journaling job evidence".into(),
                    Some(Ok(_)) => unreachable!(),
                };
                reports.push(json!({"call":intent.call,"not_journaled":true,"why":why,
                    "job_record":jobs::uncommitted(&received, &intent.machine, &intent.command)}));
            }
        }
    }
    let mut answer = json!({"held":true,"machine":target.machine,"calls":reports,
        "release":["finished_record","disposition"]});
    if let Some(disposition) = hold.disposition {
        answer["disposition"] = json!(disposition.disposition);
        answer["continuation"] = json!(disposition.continuation);
        answer["dispatch_still_restricted"] = json!(true);
    }
    answer
}

/// Collecting is a read. It neither consults command dispositions nor appends an intent.
/// Calls whose own dispatch awaits its record are reported as not read here.
pub async fn collect_jobs(
    pins: &impl PinSource,
    journal: &mut impl BoundJournal,
    target: &Target,
    #[cfg(feature = "tracer")] tamper_auth: bool,
) -> Result<Vec<Value>, Refusal> {
    let session = resolve(journal, &target.machine).await?;
    let calls = journal
        .collectable(&target.machine)
        .await
        .map_err(Refusal::Journal)?;
    let mut reports = Vec::new();
    let had_calls = !calls.is_empty();
    let calls: Vec<_> = calls
        .into_iter()
        .filter(|intent| {
            if wait::result(intent.call).is_some() {
                reports.push(json!({"call":intent.call,"not_read":true,
                "why":"own dispatch awaits its record"}));
                false
            } else {
                true
            }
        })
        .collect();
    if had_calls && calls.is_empty() {
        return Ok(reports);
    }
    let (ssh, _, _) = connect(
        pins,
        journal,
        &session,
        target,
        #[cfg(feature = "tracer")]
        tamper_auth,
    )
    .await?;
    for intent in calls {
        let job = intent.job.expect("collectable has job identity");
        if ssh.is_closed() {
            reports.push(
                json!({"call":intent.call,"job":job,"not_read":true,"why":"connection lost"}),
            );
            continue;
        }
        let result = match ssh.channel_open_session().await {
            Ok(mut channel) => exec_record(&mut channel, jobs::collect(&job).as_bytes()).await,
            Err(e) => Err(format!("session channel: {e}")),
        };
        let record = match result {
            Ok(record) => record,
            Err(why) => {
                reports.push(json!({"call":intent.call,"job":job,"failed":true,"why":why}));
                continue;
            }
        };
        let received = Evidence {
            call: intent.call,
            job,
            record,
        };
        match journal.job_evidence(&received).await {
            Ok(report) => reports.push(serde_json::to_value(report).expect("report serialization")),
            Err(why) => reports.push(json!({
                "call":intent.call,"job":received.job,"failed":true,
                "why":format!("job evidence append: {why}"),
                "job_record":jobs::uncommitted(&received, &intent.machine, &intent.command)
            })),
        }
    }
    let _ = ssh
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;
    Ok(reports)
}

/// The SSH exit status belongs to the wrapper, never to the command. Only a complete,
/// valid record delivered on a normally ended read can establish the command's outcome.
async fn exec_record(
    channel: &mut russh::Channel<client::Msg>,
    bytes: &[u8],
) -> Result<Record, String> {
    channel
        .exec(true, bytes)
        .await
        .map_err(|e| format!("exec: {e}"))?;
    let mut delivered = jobs::ReadDelivery::default();
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => delivered.stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => delivered.extended_data(&data),
            ChannelMsg::ExitStatus { exit_status } => delivered.status = Some(exit_status),
            ChannelMsg::Close => {
                delivered.closed = true;
                break;
            }
            _ => {}
        }
    }
    delivered.record()
}

async fn connect(
    pins: &impl PinSource,
    journal: &impl BoundJournal,
    session: &Session,
    target: &Target,
    #[cfg(feature = "tracer")] tamper_auth: bool,
) -> Result<(client::Handle<PinCheck>, String, String), Refusal> {
    // CHN-R4: with no pin there is nothing to check a key against, so nothing is contacted.
    let pinned = pins.pin(&target.machine).ok_or(Refusal::NoPin)?.0;
    if !journal.credentials_available() {
        return Err(Refusal::NoCredentials);
    }
    let (Some(ssh_key), Some(relay_key)) = (
        session.client_key(&target.machine),
        journal.relay_key().await,
    ) else {
        return Err(Refusal::NoCredentials);
    };
    // Role 0's child secret is an RFC 8032 Ed25519 seed (credential format v1).
    let ssh_key = PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from_seed(&ssh_key.0)),
        "",
    )
    .map_err(|e| Refusal::Failed(format!("ssh client key: {e}")))?;

    let url = format!("{}v1/tcp/{}/{}", target.relay, target.host, target.port);
    let (mut meta, mut ws) = WsMeta::connect(&url, None)
        .await
        .map_err(|e| Refusal::Failed(format!("relay websocket: {e}")))?;
    let mut events = meta
        .observe(ObserveConfig::default())
        .await
        .map_err(|e| Refusal::Failed(format!("relay events: {e}")))?;

    // WIR-4 (paid-tcp-relay 844e834): the challenge.
    let challenge = text_frame(&mut ws).await.map_err(failed("challenge"))?;
    let challenge = challenge["challenge"]
        .as_str()
        .ok_or_else(|| Refusal::Failed(format!("challenge: {challenge}")))?;

    // WIR-5 (paid-tcp-relay 844e834): the AUTH, signed by the relay key.
    let mut aux = [0u8; 32];
    getrandom::fill(&mut aux).map_err(|e| Refusal::Failed(format!("getrandom: {e}")))?;
    let created_at = (js_sys::Date::now() / 1000.0) as u64;
    #[cfg_attr(not(feature = "tracer"), allow(unused_mut))]
    let mut auth = crate::relay_auth::auth_event(
        &relay_key.0,
        &target.relay,
        challenge,
        &target.host,
        target.port,
        created_at,
        &aux,
    )
    .map_err(Refusal::Failed)?;
    #[cfg(feature = "tracer")]
    if tamper_auth {
        // The signature's first hex digit, so up to four of its bits: the event keeps its shape,
        // so only check 2 of paid-tcp-relay's `WIR-6` (844e834) fails.
        let sig = auth["sig"].as_str().expect("signed").to_string();
        let flipped = if sig.starts_with('0') { "1" } else { "0" };
        auth["sig"] = format!("{flipped}{}", &sig[1..]).into();
    }
    ws.send(WsMessage::Text(auth.to_string()))
        .await
        .map_err(|e| Refusal::Failed(format!("AUTH: {e}")))?;

    // WIR-7 (paid-tcp-relay 844e834): `{"ok": true}` once the relay has dialed; anything else
    // ends the attempt.
    let verdict = text_frame(&mut ws).await.map_err(failed("relay verdict"))?;
    if verdict["ok"] != json!(true) {
        let reason = verdict["reason"].as_str().unwrap_or_default().to_string();
        let mut close_code = None;
        while let Some(event) = events.next().await {
            if let WsEvent::Closed(close) = event {
                close_code = Some(close.code);
                break;
            }
        }
        return Err(Refusal::Relay { reason, close_code });
    }

    // WIR-8 (paid-tcp-relay 844e834): from here on, binary frames carry the TCP bytes; SSH runs
    // over them.
    let presented = Arc::new(Mutex::new(None));
    let handler = PinCheck {
        pinned: pinned.clone(),
        presented: presented.clone(),
    };
    // ADR-0024: no keepalive and no inactivity timeout, which need a tokio timer the browser
    // does not have.
    let config = Arc::new(client::Config::default());
    let mut ssh = match client::connect_stream(config, ws.into_io(), handler).await {
        Ok(ssh) => ssh,
        Err(e) => {
            let presented = presented.lock().expect("pin check lock").clone();
            return Err(match presented {
                Some(presented) if presented != pinned => Refusal::HostKey { pinned, presented },
                _ => Refusal::Failed(format!("ssh: {e}")),
            });
        }
    };
    let host_key = presented
        .lock()
        .expect("pin check lock")
        .clone()
        .unwrap_or_default();

    let auth = ssh
        .authenticate_publickey(
            target.user.clone(),
            PrivateKeyWithHashAlg::new(Arc::new(ssh_key), None),
        )
        .await
        .map_err(|e| Refusal::Failed(format!("authentication: {e}")))?;
    if !auth.success() {
        return Err(Refusal::Failed(format!("authentication refused: {auth:?}")));
    }
    Ok((ssh, pinned, host_key))
}

/// The next frame, which the handshake requires to be a JSON text frame.
async fn text_frame(ws: &mut WsStream) -> Result<Value, String> {
    match ws.next().await {
        Some(WsMessage::Text(text)) => {
            serde_json::from_str(&text).map_err(|e| format!("{e}: {text}"))
        }
        Some(WsMessage::Binary(_)) => Err("a binary frame during the handshake".into()),
        None => Err("the relay closed the connection".into()),
    }
}

async fn resolve(
    journal: &mut impl BoundJournal,
    machine: &str,
) -> Result<std::rc::Rc<Session>, Refusal> {
    journal
        .connection_session(machine)
        .await
        .map_err(|refusal| match refusal {
            AdmissionRefusal::NoEntry => Refusal::NoEntry(machine.into()),
            AdmissionRefusal::Unbound => Refusal::Unbound(machine.into()),
            AdmissionRefusal::Journal(why) => Refusal::Journal(why),
        })
}
