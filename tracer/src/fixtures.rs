//! The tracer's fixtures, on ephemeral loopback ports, each recording what it observed:
//!
//! - **the fixture sshd**: a real SSH server (russh) whose host key the tracer chooses, which
//!   admits the test client key and records every connection, authentication attempt and
//!   channel request, the `exec` command byte for byte. It starts no process: it answers the
//!   tracer's one command with the answer the tracer gives it, and any other with a failure;
//! - **the relay fixture**: paid-tcp-relay's handshake at `844e834` over `wss:`, `WIR-4`–`WIR-10`
//!   — a fresh challenge (`WIR-4`); `WIR-6` checks 1–4 and 6 in order against hand-recorded
//!   passes (`PAS-6`), each a key, its destination hosts and an expiry, with the limits of that
//!   repository's `bundle/timing.toml` (vendored under `tests/vectors/`); `{"ok": false, …}` and
//!   close 1008 on a failure, before any dial (`WIR-7`); then the dial, `{"ok": true}` and binary
//!   frames, with a binary frame before OK or a text frame after it closing with 1002 (`WIR-8`);
//!   and an ordered log per connection, which shows no dial before the AUTH is accepted and no
//!   byte forwarded before OK (`WIR-10`). It is not the relay product. It does not implement
//!   check 5, address (`DST-4`), since its destinations are loopback, which `DST-4` refuses; nor
//!   the strict path grammar of `WIR-1`–`WIR-3`, which is not among `CNF-87`'s items;
//! - **an HTTPS static server** for a built web directory.

use crate::keys::{HOST_KEY_OTHER, HOST_KEY_PINNED, ed25519, ssh_client_public};
use futures_util::{SinkExt, Stream, StreamExt};
use russh::keys::{HashAlg, PublicKey};
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer},
};
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
    /// `(reason, the check of WIR-6 (paid-tcp-relay 844e834) that failed, close code)`.
    pub relay_refusals: Vec<(String, String, u16)>,
    pub relay_dials: Vec<String>,
    /// Every relay connection's events, in order, by connection (`Seen::relay_logs`).
    pub relay_log: Vec<(u32, Event)>,
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
    /// The certificate, for a client that trusts exactly it: the relay matrix's.
    #[cfg_attr(not(test), allow(dead_code))]
    pub cert: CertificateDer<'static>,
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
        cert: cert.der().clone(),
    }
}

// ---------------------------------------------------------------------------------------------
// The relay fixture
// ---------------------------------------------------------------------------------------------

/// paid-tcp-relay's `bundle/timing.toml` at `844e834`, byte for byte (`tests/vectors/`).
const TIMING: &str = include_str!("../../tests/vectors/paid-tcp-relay-844e834-timing.toml");

/// The relay's limits, `[relay]` in paid-tcp-relay's `bundle/timing.toml` at `844e834`, where
/// they live by name (its `OPR-7`). The fixture reads them from the vendored file and keeps no
/// copy of its own, so the two cannot diverge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// How far an AUTH's `created_at` may be from the fixture's clock, either way (`WIR-5`,
    /// paid-tcp-relay `844e834`).
    pub auth_skew: Duration,
    /// The least time between two dials to one host (`DST-3`, paid-tcp-relay `844e834`).
    pub min_spacing: Duration,
    /// The span `window_cap` counts dials over, sliding (`DST-3`, paid-tcp-relay `844e834`).
    pub window: Duration,
    /// The most dials to one host within any `window` (`DST-3`, paid-tcp-relay `844e834`).
    pub window_cap: usize,
}

impl Limits {
    pub fn bundle() -> Limits {
        let table: toml::Table = TIMING.parse().expect("the vendored timing.toml parses");
        let relay = table.get("relay").expect("timing.toml has [relay]");
        let duration = |name: &str| {
            relay
                .get(name)
                .and_then(toml::Value::as_str)
                .and_then(duration)
                .unwrap_or_else(|| panic!("timing.toml: relay.{name} is not a duration"))
        };
        Limits {
            auth_skew: duration("auth_skew"),
            min_spacing: duration("min_spacing"),
            window: duration("window"),
            window_cap: relay
                .get("window_cap")
                .and_then(toml::Value::as_integer)
                .and_then(|cap| usize::try_from(cap).ok())
                .expect("timing.toml: relay.window_cap is a count"),
        }
    }
}

/// `"<n>s"`, `"<n>m"` or `"<n>h"`, the forms the bundle writes; anything else is `None`.
fn duration(text: &str) -> Option<Duration> {
    let unit = match text.chars().last()? {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        _ => return None,
    };
    let count = &text[..text.len() - 1];
    if count.is_empty() || !count.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(Duration::from_secs(
        count.parse::<u64>().ok()?.checked_mul(unit)?,
    ))
}

/// A pass recorded by hand (paid-tcp-relay's `PAS-6` at `844e834`): a relay key's public half,
/// the destination hosts it may reach, on any port (`PAS-4`, `DST-2`), and an expiry, which a
/// hand-recorded pass must have. Revocation (`PAS-5`) has no wire in v1 (`F2`), so none here.
#[derive(Clone, Debug)]
pub struct Pass {
    /// The x-only public key an AUTH's `pubkey` carries.
    pub key: [u8; 32],
    pub hosts: Vec<String>,
    pub expires: SystemTime,
}

/// Check 6, pace (`DST-3`, paid-tcp-relay `844e834`), per recorded destination host across all
/// its ports, since pacing is what makes a wide port range useless: at least `min_spacing`
/// between dials, and at most `window_cap` dials in any `window`, a sliding window over the
/// last `window` of dials. Only an admitted dial is recorded; a refused attempt is not a dial.
#[derive(Debug)]
pub struct Pace {
    limits: Limits,
    dials: HashMap<String, VecDeque<Instant>>,
    /// A clock the test sets and moves; `None` is the real one.
    pub clock: Option<Instant>,
}

impl Pace {
    pub fn new(limits: Limits) -> Pace {
        Pace {
            limits,
            dials: HashMap::new(),
            clock: None,
        }
    }

    pub fn now(&self) -> Instant {
        self.clock.unwrap_or_else(Instant::now)
    }

    /// Whether a dial to `host` is allowed at `now`, recording it as a dial when it is.
    pub fn admit(&mut self, host: &str, now: Instant) -> bool {
        let Limits {
            min_spacing,
            window,
            window_cap,
            ..
        } = self.limits;
        let dials = self.dials.entry(host.to_string()).or_default();
        while dials
            .front()
            .is_some_and(|dial| now.duration_since(*dial) >= window)
        {
            dials.pop_front();
        }
        let allowed = dials
            .back()
            .is_none_or(|last| now.duration_since(*last) >= min_spacing)
            && dials.len() < window_cap;
        if allowed {
            dials.push_back(now);
        }
        allowed
    }

    /// Puts `host` at its window cap now, as though `window_cap` dials had just been made: the
    /// tracer's deterministic pace refusal, which holds for a whole window.
    pub fn arm(&mut self, host: &str) {
        let now = self.now();
        self.dials
            .insert(host.to_string(), vec![now; self.limits.window_cap].into());
    }

    /// Forgets every dial, so the next case starts from fresh pace state.
    pub fn clear(&mut self) {
        self.dials.clear();
    }
}

/// One event in a relay connection's log, in the order the fixture saw it. The log is what lets
/// a test read the order of `WIR-10`'s two invariants (paid-tcp-relay `844e834`), not counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    ChallengeSent,
    AuthReceived,
    Accepted,
    /// `(reason, the check that failed)`.
    Refused(&'static str, &'static str),
    /// The `host:port` dialed.
    Dial(String),
    OkSent,
    /// Application bytes forwarded, toward the destination or toward the client.
    Forwarded(Toward, usize),
    /// A frame the client sent other than the AUTH and forwarded bytes: `text`, `binary`,
    /// `close`, `ping` or `pong`.
    Frame(&'static str),
    CloseSent(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Toward {
    Destination,
    Client,
}

impl Seen {
    /// The ordered log of each relay connection whose challenge was sent within these
    /// observations, in the order of their challenges.
    pub fn relay_logs(&self) -> Vec<Vec<Event>> {
        self.relay_log
            .iter()
            .filter(|(_, event)| *event == Event::ChallengeSent)
            .map(|(id, _)| {
                self.relay_log
                    .iter()
                    .filter(|(of, _)| of == id)
                    .map(|(_, event)| event.clone())
                    .collect()
            })
            .collect()
    }
}

pub struct Relay {
    /// `wss://127.0.0.1:<port>/`, the URL the AUTH's `relay` tag must name.
    pub url: String,
    /// Check 6's state, shared by every connection.
    pub pace: Arc<Mutex<Pace>>,
    /// With `hold`, the fixture waits here between the dial and OK until the test adds a permit,
    /// so a test can put a frame into that interval deterministically. Each permit releases one
    /// connection: the fixture spends it rather than returning it. The relay matrix's.
    #[cfg_attr(not(test), allow(dead_code))]
    pub release: Arc<Semaphore>,
}

struct RelayState {
    url: String,
    passes: Vec<Pass>,
    limits: Limits,
    pace: Arc<Mutex<Pace>>,
    release: Arc<Semaphore>,
    connections: AtomicU32,
}

/// The relay fixture on an ephemeral loopback port, holding `passes`, with the bundle's limits.
/// `hold` keeps every connection between its dial and OK until the test releases it, one
/// permit of `Relay::release` per connection.
pub async fn relay(seen: Observed, tls: TlsAcceptor, passes: Vec<Pass>, hold: bool) -> Relay {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("relay bind");
    let url = format!(
        "wss://127.0.0.1:{}/",
        listener.local_addr().expect("relay address").port()
    );
    let limits = Limits::bundle();
    let pace = Arc::new(Mutex::new(Pace::new(limits)));
    let release = Arc::new(Semaphore::new(if hold {
        0
    } else {
        Semaphore::MAX_PERMITS
    }));
    let state = Arc::new(RelayState {
        url: url.clone(),
        passes,
        limits,
        pace: pace.clone(),
        release: release.clone(),
        connections: AtomicU32::new(0),
    });
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            observe(&seen, |s| s.relay_accepted += 1);
            let (seen, tls, state) = (seen.clone(), tls.clone(), state.clone());
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
                let log = Log {
                    seen,
                    id: state.connections.fetch_add(1, Ordering::SeqCst),
                };
                relay_connection(ws, &path, &state, &log).await;
            });
        }
    });
    Relay { url, pace, release }
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>;

/// One connection's log, in `Seen`.
struct Log {
    seen: Observed,
    id: u32,
}

impl Log {
    fn event(&self, event: Event) {
        observe(&self.seen, |s| {
            if let Event::Dial(address) = &event {
                s.relay_dials.push(address.clone());
            }
            s.relay_log.push((self.id, event));
        });
    }

    fn refused(&self, reason: &'static str, check: &'static str, code: u16) {
        observe(&self.seen, |s| {
            s.relay_refusals.push((reason.into(), check.into(), code))
        });
        self.event(Event::Refused(reason, check));
    }
}

/// The path of paid-tcp-relay's `WIR-1` at `844e834`, `/v1/tcp/<host>/<port>`, parsed loosely.
/// The fixture is that repository's `WIR-4`–`WIR-10`, with `WIR-6` checks 1–4 and 6. It does not
/// implement the strict grammar of `WIR-1`–`WIR-3` and its refusals, which are not among
/// `CNF-87`'s items (`WIR-4`–`WIR-10`), nor check 5, address (`DST-4`).
fn destination(path: &str) -> Option<(String, u16)> {
    let rest = path.strip_prefix("/v1/tcp/")?;
    let (host, port) = rest.split_once('/')?;
    Some((host.to_string(), port.parse().ok()?))
}

/// The checks of paid-tcp-relay's `WIR-6` at `844e834`, in order, stopping at the first failure:
/// `(reason, check)`. Checks 1–4 and 6; check 5, address (`DST-4`), is not implemented, since
/// the fixture's destinations are loopback, which `DST-4` refuses. Check 6 records the dial it
/// admits, so it runs only once checks 1–4 have passed.
fn wir_6(
    auth: &Value,
    state: &RelayState,
    challenge: &str,
    path: &(String, u16),
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
    let now = SystemTime::now();
    let unix = now.duration_since(UNIX_EPOCH).expect("clock").as_secs();

    // 1. shape, `created_at` within `relay.auth_skew` either way
    let port = path.1.to_string();
    let shape = auth["kind"] == json!(tau_web::relay_auth::AUTH_KIND)
        && tag("relay")
            .iter()
            .any(|t| t.get(1) == Some(&state.url.as_str()))
        && auth["created_at"]
            .as_u64()
            .is_some_and(|t| t.abs_diff(unix) <= state.limits.auth_skew.as_secs())
        && matches!(tag("destination").as_slice(),
            [d] if d.len() == 3 && d[1] == path.0 && d[2] == port);
    if !shape {
        return Err(("auth", "1 shape"));
    }
    // 2. signature, and the challenge is this connection's: a replayed AUTH fails here (WIR-9,
    // paid-tcp-relay 844e834)
    if tau_web::relay_auth::verify_signature(auth).is_err()
        || !tag("challenge")
            .iter()
            .any(|t| t.get(1) == Some(&challenge))
    {
        return Err(("auth", "2 signature"));
    }
    // 3. pass: the key holds one, and it has not expired (PAS-3, paid-tcp-relay 844e834)
    let pass = state
        .passes
        .iter()
        .find(|pass| auth["pubkey"].as_str() == Some(&hex::encode(pass.key)))
        .filter(|pass| pass.expires > now);
    let Some(pass) = pass else {
        return Err(("pass", "3 pass"));
    };
    // 4. destination: the host is in the pass's record, on any port (PAS-4, DST-2,
    // paid-tcp-relay 844e834)
    if !pass.hosts.contains(&path.0) {
        return Err(("destination", "4 destination"));
    }
    // 5. address (DST-4, paid-tcp-relay 844e834): not implemented, see above.
    // 6. pace (DST-3, paid-tcp-relay 844e834)
    let mut pace = state.pace.lock().expect("pace lock");
    let now = pace.now();
    if !pace.admit(&path.0, now) {
        return Err(("pace", "6 pace"));
    }
    Ok(())
}

fn kind(frame: &Message) -> &'static str {
    match frame {
        Message::Text(_) => "text",
        Message::Binary(_) => "binary",
        Message::Ping(_) => "ping",
        Message::Pong(_) => "pong",
        Message::Close(_) => "close",
        Message::Frame(_) => "frame",
    }
}

/// Sends close `code`, then reads until the client's close or the end, for 5 s at most, logging
/// every frame the client sends meanwhile.
async fn close(ws: &mut Ws, code: u16, log: &Log) {
    let frame = CloseFrame {
        code: CloseCode::from(code),
        reason: "".into(),
    };
    if ws.send(Message::Close(Some(frame))).await.is_ok() {
        log.event(Event::CloseSent(code));
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(frame)) = ws.next().await {
            log.event(Event::Frame(kind(&frame)));
        }
    })
    .await;
}

/// What came first between an accepted AUTH and OK.
pub enum PreOk<F, D> {
    /// The client's next frame, or the end of its stream.
    Frame(Option<F>),
    /// The dial's outcome.
    Dialed(D),
}

/// Waits for the client's next frame or the dial, whichever comes first. A frame that can be read
/// when the dial completes comes first: the select is biased toward the socket. Unbiased, it
/// would pick at random when both are ready, and in half of those the fixture would send OK and
/// then forward a binary frame it already had before OK, against `WIR-8` and `WIR-10`
/// (paid-tcp-relay `844e834`).
pub async fn pre_ok<S, D>(frames: &mut S, dial: &mut D) -> PreOk<S::Item, D::Output>
where
    S: Stream + Unpin,
    D: Future + Unpin,
{
    tokio::select! {
        biased;
        frame = frames.next() => PreOk::Frame(frame),
        dialed = dial => PreOk::Dialed(dialed),
    }
}

async fn relay_connection(mut ws: Ws, path: &str, state: &RelayState, log: &Log) {
    use base64::Engine;
    let Some(path) = destination(path) else {
        log.refused("path", "paid-tcp-relay 844e834 WIR-2", 1008);
        close(&mut ws, 1008, log).await;
        return;
    };

    // WIR-4 (paid-tcp-relay 844e834): a fresh challenge per connection.
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(urandom::<32>());
    let frame = json!({ "challenge": challenge, "relay": state.url }).to_string();
    if ws.send(Message::text(frame)).await.is_err() {
        return;
    }
    log.event(Event::ChallengeSent);
    let auth = match ws.next().await {
        Some(Ok(Message::Text(text))) => {
            log.event(Event::AuthReceived);
            serde_json::from_str(&text).unwrap_or(Value::Null)
        }
        // WIR-8 (paid-tcp-relay 844e834): a binary frame before OK, here in place of the AUTH,
        // closes with 1002, with no verdict.
        Some(Ok(Message::Binary(_))) => {
            log.event(Event::Frame("binary"));
            close(&mut ws, 1002, log).await;
            return;
        }
        _ => return,
    };
    if let Err((reason, check)) = wir_6(&auth, state, &challenge, &path) {
        // WIR-7 (paid-tcp-relay 844e834): one text frame and close 1008, before any dial.
        log.refused(reason, check, 1008);
        let _ = ws
            .send(Message::text(
                json!({ "ok": false, "reason": reason }).to_string(),
            ))
            .await;
        close(&mut ws, 1008, log).await;
        return;
    }
    log.event(Event::Accepted);

    // Every check passed: the dial, then `{"ok": true}` once it is up (WIR-7, paid-tcp-relay
    // 844e834). Until OK the socket is still read, and a binary frame closes it with 1002 and is
    // not forwarded (WIR-8), even one that is ready when the dial completes (`pre_ok`). WIR-8
    // says nothing of a text frame here, so it is logged and otherwise ignored.
    let address = format!("{}:{}", path.0, path.1);
    log.event(Event::Dial(address.clone()));
    let dial = async {
        let tcp = TcpStream::connect(&address).await?;
        // One permit releases one connection: it is spent, not returned to the semaphore.
        if let Ok(permit) = state.release.acquire().await {
            permit.forget();
        }
        Ok::<_, std::io::Error>(tcp)
    };
    tokio::pin!(dial);
    let tcp = loop {
        match pre_ok(&mut ws, &mut dial).await {
            PreOk::Dialed(tcp) => break tcp,
            PreOk::Frame(frame) => {
                let Some(Ok(frame)) = frame else { return };
                log.event(Event::Frame(kind(&frame)));
                match frame {
                    Message::Binary(_) => {
                        close(&mut ws, 1002, log).await;
                        return;
                    }
                    Message::Close(_) => return,
                    _ => {}
                }
            }
        }
    };
    let Ok(mut tcp) = tcp else {
        log.refused("dial", "dial", 1011);
        let _ = ws
            .send(Message::text(
                json!({ "ok": false, "reason": "dial" }).to_string(),
            ))
            .await;
        close(&mut ws, 1011, log).await;
        return;
    };
    if ws
        .send(Message::text(json!({ "ok": true }).to_string()))
        .await
        .is_err()
    {
        return;
    }
    log.event(Event::OkSent);

    // WIR-8 and WIR-10 (paid-tcp-relay 844e834): only now are bytes forwarded, binary frames
    // both ways. The destination is first read here, so bytes it sent at the dial (an sshd's
    // banner) follow OK. A text frame closes with 1002, none of its bytes forwarded, and the TCP
    // connection with it.
    let mut buffer = vec![0; 16 * 1024];
    let code = loop {
        tokio::select! {
            frame = ws.next() => match frame {
                Some(Ok(Message::Binary(bytes))) => {
                    if tcp.write_all(&bytes).await.is_err() {
                        break Some(1000);
                    }
                    log.event(Event::Forwarded(Toward::Destination, bytes.len()));
                }
                Some(Ok(Message::Text(_))) => {
                    log.event(Event::Frame("text"));
                    break Some(1002);
                }
                Some(Ok(Message::Close(_))) => {
                    log.event(Event::Frame("close"));
                    break None;
                }
                Some(Ok(_)) => {}
                _ => break None,
            },
            read = tcp.read(&mut buffer) => match read {
                Ok(n) if n > 0 => {
                    if ws.send(Message::binary(buffer[..n].to_vec())).await.is_err() {
                        break None;
                    }
                    log.event(Event::Forwarded(Toward::Client, n));
                }
                _ => break Some(1000),
            },
        }
    };
    drop(tcp);
    match code {
        Some(code) => close(&mut ws, code, log).await,
        None => {
            let _ = ws.close(None).await;
        }
    }
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
