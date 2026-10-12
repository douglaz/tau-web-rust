//! The tracer's fixtures, on ephemeral loopback ports, each recording what it observed:
//!
//! - **the fixture sshd**: a real SSH server (russh) whose host key the tracer chooses, which
//!   admits the test client key and records every connection, authentication attempt and
//!   channel request, the `exec` command byte for byte. It starts no process: it answers the
//!   tracer's one command with the answer the tracer gives it, and any other with a failure;
//! - **the relay fixture**: the happy path of paid-tcp-relay's handshake at `844e834` over
//!   `wss:` — a fresh challenge (`WIR-4`), `WIR-6` checks 1–4 in order against the test relay
//!   key's pass and a recorded destination set holding the fixture sshd, `{"ok": false, …}` and
//!   close 1008 on a failure (`WIR-7`), and only then the dial, `{"ok": true}` and binary frames
//!   (`WIR-8`). It is not the relay product: no `DST-4` (paid-tcp-relay's, at `844e834`; the
//!   fixture's destination is loopback, which it refuses), no pacing;
//! - **an HTTPS static server** for a built web directory.

use crate::keys::{HOST_KEY_OTHER, HOST_KEY_PINNED, ed25519, ssh_client_public};
use futures_util::{SinkExt, StreamExt};
use russh::keys::{HashAlg, PublicKey};
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId};
use serde_json::{Value, json};
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{self, pki_types::PrivateKeyDer};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

/// What the fixtures observed. The tracer takes it per case, so each case sees only its own.
#[derive(Debug, Default)]
pub struct Seen {
    /// TCP connections the relay fixture accepted, counted at `accept`, before TLS.
    pub relay_accepted: u32,
    /// The paths of the connections that completed the WebSocket upgrade.
    pub relay_connections: Vec<String>,
    /// `(reason, the check of `WIR-6` (paid-tcp-relay `844e834`) that failed, close code)`.
    pub relay_refusals: Vec<(String, String, u16)>,
    pub relay_dials: Vec<String>,
    pub ssh_connections: u32,
    /// `(user, key fingerprint, admitted)` for every publickey attempt; `none` attempts too.
    pub ssh_auth: Vec<(String, String, bool)>,
    pub ssh_exec: Vec<Vec<u8>>,
    pub ssh_exit: Vec<u32>,
    /// Requests a command-at-a-time client never makes: pty, shell, subsystem (`ARC-7`).
    pub ssh_other_requests: Vec<String>,
}

pub type Observed = Arc<Mutex<Seen>>;

fn observe(seen: &Observed, record: impl FnOnce(&mut Seen)) {
    record(&mut seen.lock().expect("observations lock"));
}

pub fn urandom<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .expect("/dev/urandom");
    bytes
}

// ---------------------------------------------------------------------------------------------
// The fixture sshd
// ---------------------------------------------------------------------------------------------

pub struct Sshd {
    pub port: u16,
    /// Present `HOST_KEY_OTHER` instead of the pinned key, for the wrong-key case.
    pub present_other: Arc<AtomicBool>,
    /// Connections accepted and connections ended, over the whole run: never reset, so a
    /// connection from an earlier case that ends late is still counted against its own accept.
    pub accepted: Arc<AtomicU32>,
    pub ended: Arc<AtomicU32>,
}

impl Sshd {
    /// Waits up to 30 s until every connection the sshd accepted has ended, so everything the
    /// client sent before closing has been handled and recorded; whether they all ended.
    pub async fn all_ended(&self) -> bool {
        for _ in 0..600 {
            if self.ended.load(Ordering::SeqCst) == self.accepted.load(Ordering::SeqCst) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
}

/// The one command the fixture sshd answers, and its answer. It runs nothing.
pub struct Answer {
    pub command: &'static str,
    pub stdout: &'static str,
    pub stderr: &'static str,
    pub exit_status: u32,
}

/// What the fixture sshd answers any other command with.
const UNKNOWN_COMMAND: &str = "fixture sshd: not the tracer's command\n";
const UNKNOWN_EXIT_STATUS: u32 = 127;

pub async fn sshd(seen: Observed, answer: Answer) -> Sshd {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("sshd bind");
    let port = listener.local_addr().expect("sshd address").port();
    let present_other = Arc::new(AtomicBool::new(false));
    let (accepted, ended) = (Arc::new(AtomicU32::new(0)), Arc::new(AtomicU32::new(0)));
    let (other, accepts, ends) = (present_other.clone(), accepted.clone(), ended.clone());
    let answer = Arc::new(answer);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            accepts.fetch_add(1, Ordering::SeqCst);
            observe(&seen, |s| s.ssh_connections += 1);
            let seed = if other.load(Ordering::SeqCst) {
                HOST_KEY_OTHER
            } else {
                HOST_KEY_PINNED
            };
            let config = Arc::new(server::Config {
                keys: vec![ed25519(&seed)],
                auth_rejection_time: Duration::from_millis(10),
                auth_rejection_time_initial: Some(Duration::ZERO),
                ..Default::default()
            });
            let handler = SshSession {
                seen: seen.clone(),
                answer: answer.clone(),
            };
            let ends = ends.clone();
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, stream, handler).await {
                    let _ = session.await;
                }
                ends.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    Sshd {
        port,
        present_other,
        accepted,
        ended,
    }
}

struct SshSession {
    seen: Observed,
    answer: Arc<Answer>,
}

impl SshSession {
    fn admit(&self, user: &str, key: &PublicKey) -> Auth {
        let admitted = user == tau_web::testonly::SSH_USER
            && key.key_data().ed25519().map(|k| k.0) == Some(ssh_client_public());
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        observe(&self.seen, |s| {
            s.ssh_auth.push((user.to_string(), fingerprint, admitted))
        });
        if admitted {
            Auth::Accept
        } else {
            Auth::reject()
        }
    }

    fn refuse(
        &self,
        request: &str,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        observe(&self.seen, |s| {
            s.ssh_other_requests.push(request.to_string())
        });
        session.channel_failure(channel)
    }
}

impl server::Handler for SshSession {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        observe(&self.seen, |s| {
            s.ssh_auth.push((user.to_string(), "none".into(), false))
        });
        Ok(Auth::reject())
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(self.admit(user, key))
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(self.admit(user, key))
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse("pty", channel, session)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse("shell", channel, session)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse(&format!("subsystem {name}"), channel, session)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        observe(&self.seen, |s| s.ssh_exec.push(data.to_vec()));
        session.channel_success(channel)?;
        let (stdout, stderr, status) = if data == self.answer.command.as_bytes() {
            (
                self.answer.stdout,
                self.answer.stderr,
                self.answer.exit_status,
            )
        } else {
            ("", UNKNOWN_COMMAND, UNKNOWN_EXIT_STATUS)
        };
        observe(&self.seen, |s| s.ssh_exit.push(status));
        session.data(channel, stdout.as_bytes().to_vec())?;
        session.extended_data(channel, 1, stderr.as_bytes().to_vec())?;
        session.exit_status_request(channel, status)?;
        session.eof(channel)?;
        session.close(channel)
    }
}

// ---------------------------------------------------------------------------------------------
// TLS for the relay fixture and the HTTPS server: one self-signed certificate per run
// ---------------------------------------------------------------------------------------------

pub struct Tls {
    pub acceptor: TlsAcceptor,
    /// base64(SHA-256(SubjectPublicKeyInfo)), what Chrome's `--ignore-certificate-errors-spki-list`
    /// takes: the browser accepts this one test certificate and nothing else unverified.
    pub spki_sha256: String,
}

pub fn tls() -> Tls {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).expect("test certificate");
    let spki_sha256 = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(
        rcgen::PublicKeyData::subject_public_key_info(&signing_key),
    ));
    let key = PrivateKeyDer::Pkcs8(signing_key.serialize_der().into());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert.der().clone()], key)
    .expect("TLS certificate");
    Tls {
        acceptor: TlsAcceptor::from(Arc::new(config)),
        spki_sha256,
    }
}

// ---------------------------------------------------------------------------------------------
// The relay fixture
// ---------------------------------------------------------------------------------------------

pub struct Relay {
    /// `wss://127.0.0.1:<port>/`, the URL the AUTH's `relay` tag must name.
    pub url: String,
}

/// `relay.auth_skew` in paid-tcp-relay's `bundle/timing.toml` at `844e834`: 10 minutes.
const AUTH_SKEW_SECONDS: u64 = 600;

pub async fn relay(seen: Observed, tls: TlsAcceptor, destinations: Vec<(String, u16)>) -> Relay {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("relay bind");
    let url = format!(
        "wss://127.0.0.1:{}/",
        listener.local_addr().expect("relay address").port()
    );
    let this = url.clone();
    let destinations = Arc::new(destinations);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            observe(&seen, |s| s.relay_accepted += 1);
            let (seen, tls, this, destinations) = (
                seen.clone(),
                tls.clone(),
                this.clone(),
                destinations.clone(),
            );
            tokio::spawn(async move {
                let Ok(tls) = tls.accept(tcp).await else {
                    return;
                };
                let path = Arc::new(Mutex::new(String::new()));
                let at = path.clone();
                // The signature is tungstenite's `Callback`, error type included.
                #[allow(clippy::result_large_err)]
                let callback = move |request: &Request, response: Response| {
                    *at.lock().expect("path lock") = request.uri().path().to_string();
                    Ok(response)
                };
                let Ok(ws) = tokio_tungstenite::accept_hdr_async(tls, callback).await else {
                    return;
                };
                let path = path.lock().expect("path lock").clone();
                observe(&seen, |s| s.relay_connections.push(path.clone()));
                relay_connection(ws, &path, &this, &destinations, &seen).await;
            });
        }
    });
    Relay { url }
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>;

/// The path of paid-tcp-relay's `WIR-1` at `844e834`, `/v1/tcp/<host>/<port>`, for the fixture's purposes: the strict grammar and
/// its refusals are twr-ggw.3's.
fn destination(path: &str) -> Option<(String, u16)> {
    let rest = path.strip_prefix("/v1/tcp/")?;
    let (host, port) = rest.split_once('/')?;
    Some((host.to_string(), port.parse().ok()?))
}

/// Checks 1–4 of paid-tcp-relay's `WIR-6` at `844e834`, in order, stopping at the first
/// failure: `(reason, check)`.
fn wir_6(
    auth: &Value,
    this: &str,
    challenge: &str,
    path: &(String, u16),
    destinations: &[(String, u16)],
) -> Result<(), (&'static str, &'static str)> {
    let tags: Vec<Vec<&str>> = auth["tags"]
        .as_array()
        .map(|tags| {
            tags.iter()
                .map(|t| {
                    t.as_array()
                        .map(|t| t.iter().filter_map(Value::as_str).collect())
                        .unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default();
    let tag = |name: &str| -> Vec<&Vec<&str>> {
        tags.iter().filter(|t| t.first() == Some(&name)).collect()
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();

    // 1. shape
    let port = path.1.to_string();
    let shape = auth["kind"] == json!(tau_web::relay_auth::AUTH_KIND)
        && tag("relay").iter().any(|t| t.get(1) == Some(&this))
        && auth["created_at"]
            .as_u64()
            .is_some_and(|t| t.abs_diff(now) <= AUTH_SKEW_SECONDS)
        && matches!(tag("destination").as_slice(),
            [d] if d.len() == 3 && d[1] == path.0 && d[2] == port);
    if !shape {
        return Err(("auth", "1 shape"));
    }
    // 2. signature, and the challenge is this connection's
    if tau_web::relay_auth::verify_signature(auth).is_err()
        || !tag("challenge")
            .iter()
            .any(|t| t.get(1) == Some(&challenge))
    {
        return Err(("auth", "2 signature"));
    }
    // 3. pass: the test relay key holds the one pass
    if auth["pubkey"].as_str() != Some(&hex::encode(crate::keys::relay_public())) {
        return Err(("pass", "3 pass"));
    }
    // 4. destination: in the pass's recorded set
    if !destinations.contains(path) {
        return Err(("destination", "4 destination"));
    }
    Ok(())
}

async fn relay_connection(
    mut ws: Ws,
    path: &str,
    this: &str,
    destinations: &[(String, u16)],
    seen: &Observed,
) {
    use base64::Engine;
    let refuse = |reason: &str, check: &str, code: u16| {
        let (reason, check) = (reason.to_string(), check.to_string());
        observe(seen, |s| s.relay_refusals.push((reason, check, code)));
    };
    let close = |code: u16| {
        Message::Close(Some(CloseFrame {
            code: CloseCode::from(code),
            reason: "".into(),
        }))
    };
    let Some(path) = destination(path) else {
        refuse("path", "paid-tcp-relay 844e834 WIR-2", 1008);
        let _ = ws.send(close(1008)).await;
        return;
    };

    // WIR-4 (paid-tcp-relay 844e834): a fresh challenge per connection.
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(urandom::<32>());
    let frame = json!({ "challenge": challenge, "relay": this }).to_string();
    if ws.send(Message::text(frame)).await.is_err() {
        return;
    }
    let auth = match ws.next().await {
        Some(Ok(Message::Text(text))) => serde_json::from_str(&text).unwrap_or(Value::Null),
        _ => Value::Null,
    };
    if let Err((reason, check)) = wir_6(&auth, this, &challenge, &path, destinations) {
        // WIR-7 (paid-tcp-relay 844e834): one text frame and close 1008, before any dial.
        refuse(reason, check, 1008);
        let _ = ws
            .send(Message::text(
                json!({ "ok": false, "reason": reason }).to_string(),
            ))
            .await;
        let _ = ws.send(close(1008)).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
        return;
    }

    // Every check passed: dial, then `{"ok": true}`, then bytes (WIR-7, WIR-8 and WIR-10 of
    // paid-tcp-relay 844e834).
    let address = format!("{}:{}", path.0, path.1);
    observe(seen, |s| s.relay_dials.push(address.clone()));
    let Ok(tcp) = TcpStream::connect(&address).await else {
        refuse("dial", "dial", 1011);
        let _ = ws
            .send(Message::text(
                json!({ "ok": false, "reason": "dial" }).to_string(),
            ))
            .await;
        let _ = ws.send(close(1011)).await;
        return;
    };
    if ws
        .send(Message::text(json!({ "ok": true }).to_string()))
        .await
        .is_err()
    {
        return;
    }
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let (mut ws_write, mut ws_read) = ws.split();
    let upstream = async {
        while let Some(Ok(message)) = ws_read.next().await {
            match message {
                Message::Binary(bytes) => {
                    if tcp_write.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = tcp_write.shutdown().await;
    };
    let downstream = async {
        let mut buffer = vec![0; 16 * 1024];
        while let Ok(n) = tcp_read.read(&mut buffer).await {
            if n == 0
                || ws_write
                    .send(Message::binary(buffer[..n].to_vec()))
                    .await
                    .is_err()
            {
                break;
            }
        }
        let _ = ws_write.send(Message::Close(None)).await;
    };
    tokio::join!(upstream, downstream);
}

// ---------------------------------------------------------------------------------------------
// The HTTPS static server
// ---------------------------------------------------------------------------------------------

/// Serves `root` over HTTPS on an ephemeral port; its origin, `https://127.0.0.1:<port>`.
/// `worker_policy`, when given, is sent as the worker script's `Content-Security-Policy` header:
/// a dedicated worker takes its policy from its own response, not from the page.
pub async fn https(root: PathBuf, tls: TlsAcceptor, worker_policy: Option<String>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("https bind");
    let origin = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().expect("https address").port()
    );
    let (root, worker_policy) = (Arc::new(root), Arc::new(worker_policy));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let (tls, root, worker_policy) = (tls.clone(), root.clone(), worker_policy.clone());
            tokio::spawn(async move {
                if let Ok(stream) = tls.accept(tcp).await {
                    let _ = serve(stream, &root, worker_policy.as_deref()).await;
                }
            });
        }
    });
    origin
}

async fn serve(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    root: &std::path::Path,
    worker_policy: Option<&str>,
) -> std::io::Result<()> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 16 * 1024 {
        if stream.read(&mut byte).await? == 0 {
            return Ok(());
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    let target = head.split(' ').nth(1).unwrap_or("/");
    let path = target.split(['?', '#']).next().unwrap_or("/");
    let path = if path == "/" { "/index.html" } else { path };
    let file = (!path.split('/').any(|segment| segment == ".."))
        .then(|| root.join(path.trim_start_matches('/')))
        .and_then(|file| std::fs::read(file).ok());
    let response = match file {
        Some(body) => {
            let kind = match path.rsplit('.').next() {
                Some("html") => "text/html; charset=utf-8",
                Some("js") => "text/javascript",
                Some("wasm") => "application/wasm",
                _ => "application/octet-stream",
            };
            let policy = match worker_policy {
                Some(policy) if path == "/worker.js" => {
                    format!("Content-Security-Policy: {policy}\r\n")
                }
                _ => String::new(),
            };
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n{policy}Cache-Control: no-store\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(&body);
            response
        }
        None => {
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
        }
    };
    stream.write_all(&response).await?;
    stream.shutdown().await
}
