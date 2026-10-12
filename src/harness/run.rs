//! The attempt itself, on the browser's WebSocket: wasm32 only.

use super::{Entry, Journal, PinSource};
use futures_util::{SinkExt, StreamExt};
use pharos::{Observable, ObserveConfig};
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

/// Where the credentials an attempt uses come from: the SSH client key and the relay key. They
/// stay inside the module; nothing here returns them.
pub trait Credentials {
    fn ssh_key(&self) -> Option<PrivateKey>;
    fn relay_key(&self) -> Option<[u8; 32]>;
}

/// What a completed command returns, including the journal read-back it was reconciled with.
pub struct Done {
    pub seq: u64,
    pub sent: Vec<u8>,
    pub recorded: Entry,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: Option<u32>,
    pub host_key: String,
}

/// Why an attempt ended without the command being sent, or without its result.
#[derive(Debug)]
pub enum Refusal {
    /// No pin for the machine: refused before the relay is contacted (`CHN-R4`, `CNF-23`).
    NoPin,
    /// No SSH client key or relay key to use: refused before the relay is contacted.
    NoCredentials,
    /// The relay refused the AUTH (`WIR-7`, paid-tcp-relay `844e834`) with this reason and close
    /// code.
    Relay {
        reason: String,
        close_code: Option<u16>,
    },
    /// The presented host key is not the pin: halted in the key exchange (`SEC-11`).
    HostKey { pinned: String, presented: String },
    /// The journal refused the append, so no `exec` was sent (`STA-3`).
    Journal(String),
    /// The transcript does not reconcile with what was sent (`CNF-30`).
    Unreconciled {
        sent: Vec<u8>,
        recorded: Option<Entry>,
    },
    /// Anything else: the transport, the protocol, authentication.
    Failed(String),
}

impl Refusal {
    pub fn to_json(&self) -> Value {
        match self {
            Refusal::NoPin => json!({ "refused": "no-pin" }),
            Refusal::NoCredentials => json!({ "refused": "no-credentials" }),
            Refusal::Relay { reason, close_code } => {
                json!({ "refused": "relay", "reason": reason, "close_code": close_code })
            }
            Refusal::HostKey { pinned, presented } => {
                json!({ "refused": "host-key", "pinned": pinned, "presented": presented })
            }
            Refusal::Journal(why) => json!({ "refused": "journal", "why": why }),
            Refusal::Unreconciled { sent, recorded } => json!({
                "refused": "unreconciled",
                "sent": hex::encode(sent),
                "recorded": recorded.as_ref().map(|e| hex::encode(&e.command)),
            }),
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
            "sent": hex::encode(&done.sent),
            "recorded": hex::encode(&done.recorded.command),
            "recorded_machine": done.recorded.machine,
            "stdout": String::from_utf8_lossy(&done.stdout),
            "stderr": String::from_utf8_lossy(&done.stderr),
            "exit_status": done.exit_status,
            "host_key": done.host_key,
        }),
        Err(refusal) => refusal.to_json(),
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
    journal: &mut impl Journal,
    credentials: &impl Credentials,
    target: &Target,
    command: &[u8],
    #[cfg(feature = "tracer")] tamper_auth: bool,
) -> Result<Done, Refusal> {
    // CHN-R4: with no pin there is nothing to check a key against, so nothing is contacted.
    let pinned = pins.pin(&target.machine).ok_or(Refusal::NoPin)?;
    let (Some(ssh_key), Some(relay_key)) = (credentials.ssh_key(), credentials.relay_key()) else {
        return Err(Refusal::NoCredentials);
    };

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
        &relay_key,
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
    let mut channel = ssh
        .channel_open_session()
        .await
        .map_err(|e| Refusal::Failed(format!("session channel: {e}")))?;

    // ARC-8, STA-4: the record is appended immediately before the bytes leave, and a failed
    // append means they do not (STA-3).
    let entry = Entry {
        machine: target.machine.clone(),
        command: command.to_vec(),
    };
    let seq = journal.append(&entry).map_err(Refusal::Journal)?;
    channel
        .exec(true, entry.command.clone())
        .await
        .map_err(|e| Refusal::Failed(format!("exec: {e}")))?;
    let sent = entry.command;

    let (mut stdout, mut stderr, mut exit_status) = (Vec::new(), Vec::new(), None);
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus {
                exit_status: status,
            } => exit_status = Some(status),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    let _ = ssh
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;

    // CNF-30: the transcript reconciles against what was sent.
    let recorded = journal.read(seq);
    match recorded {
        Some(recorded) if recorded.command == sent && recorded.machine == target.machine => {
            Ok(Done {
                seq,
                sent,
                recorded,
                stdout,
                stderr,
                exit_status,
                host_key,
            })
        }
        recorded => Err(Refusal::Unreconciled { sent, recorded }),
    }
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
