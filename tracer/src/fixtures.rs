//! The tracer's fixtures, on ephemeral loopback ports, each recording what it observed:
//!
//! - **the fixture sshd**: a real SSH server (russh) whose host key the tracer chooses, which
//!   reads its own authorized_keys and records every connection, authentication attempt and
//!   channel request, the `exec` command byte for byte. It runs real POSIX shells with fixed
//!   machine paths mapped into its own persistent scratch directory;
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

use crate::keys::{HOST_KEY_OTHER, HOST_KEY_PINNED, ed25519};
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
    pub ssh_channels: u32,
    pub ssh_authentication_banners: u32,
    /// `(user, key fingerprint, admitted)` for every publickey attempt; `none` attempts too.
    pub ssh_auth: Vec<(String, String, bool)>,
    pub ssh_exec: Vec<Vec<u8>>,
    pub ssh_exit: Vec<u32>,
    pub ssh_ends: Vec<String>,
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
    pub auth_banner: Arc<AtomicBool>,
    pub port: u16,
    /// Present `HOST_KEY_OTHER` instead of the pinned key, for the wrong-key case.
    pub present_other: Arc<AtomicBool>,
    /// Disconnect the next job-record read after its exec arrives.
    pub disconnect_read: Arc<AtomicBool>,
    /// Connections accepted and connections ended, over the whole run: never reset, so a
    /// connection from an earlier case that ends late is still counted against its own accept.
    pub accepted: Arc<AtomicU32>,
    pub ended: Arc<AtomicU32>,
    pub machine: Arc<crate::machine::Machine>,
    listener: tokio::task::JoinHandle<()>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Sshd {
    /// Waits up to 30 s until every connection the sshd accepted has ended, so everything the
    /// client sent before closing has been handled and recorded; whether they all ended.
    pub async fn cleanup(&self) {
        self.listener.abort();
        self.machine.reboot();
        self.all_ended().await;
        let tasks = std::mem::take(&mut *self.tasks.lock().expect("exec tasks"));
        for task in tasks {
            let _ = task.await;
        }
        self.machine.cleanup();
    }

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

pub async fn sshd(seen: Observed) -> Sshd {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("sshd bind");
    let port = listener.local_addr().expect("sshd address").port();
    let present_other = Arc::new(AtomicBool::new(false));
    let auth_banner = Arc::new(AtomicBool::new(false));
    let authentication_banner = auth_banner.clone();
    let disconnect_read = Arc::new(AtomicBool::new(false));
    let read_disconnect = disconnect_read.clone();
    let (accepted, ended) = (Arc::new(AtomicU32::new(0)), Arc::new(AtomicU32::new(0)));
    let (other, accepts, ends) = (present_other.clone(), accepted.clone(), ended.clone());
    let machine = Arc::new(crate::machine::Machine::new());
    let fixture = machine.clone();
    let tasks = Arc::new(Mutex::new(Vec::new()));
    let exec_tasks = tasks.clone();
    let listener = tokio::spawn(async move {
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
                machine: fixture.clone(),
                execs: Arc::default(),
                tasks: exec_tasks.clone(),
                disconnect_read: read_disconnect.clone(),
                auth_banner: authentication_banner.clone(),
            };
            let ends = ends.clone();
            let observations = seen.clone();
            tokio::spawn(async move {
                let result = match server::run_stream(config, stream, handler).await {
                    Ok(session) => session.await,
                    Err(error) => Err(error),
                };
                observe(&observations, |seen| {
                    seen.ssh_ends.push(format!("{result:?}"))
                });
                ends.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    Sshd {
        auth_banner,
        port,
        present_other,
        disconnect_read,
        accepted,
        ended,
        machine,
        listener,
        tasks,
    }
}

struct SshSession {
    auth_banner: Arc<AtomicBool>,
    seen: Observed,
    disconnect_read: Arc<AtomicBool>,
    machine: Arc<crate::machine::Machine>,
    execs: Arc<Mutex<Vec<crate::machine::ExecGroup>>>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl SshSession {
    fn admit(&self, user: &str, key: &PublicKey) -> Auth {
        let admitted = user == tau_web::testonly::SSH_USER
            && std::fs::read_to_string(self.machine.root.join("authorized_keys"))
                .ok()
                .is_some_and(|file| {
                    file.lines()
                        .filter_map(|line| PublicKey::from_openssh(line).ok())
                        .any(|installed| installed == *key)
                });
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

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(if self.auth_banner.swap(false, Ordering::SeqCst) {
            observe(&self.seen, |seen| seen.ssh_authentication_banners += 1);
            Some("fixture authentication stage".into())
        } else {
            None
        })
    }

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
        observe(&self.seen, |seen| seen.ssh_channels += 1);
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
        if data.starts_with(b"# tau-web job read ")
            && self.disconnect_read.swap(false, Ordering::SeqCst)
        {
            session.disconnect(
                russh::Disconnect::ByApplication,
                "fixture collection disconnect",
                "en",
            )?;
            return Ok(());
        }
        let mapped = self.machine.map(data);
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", &mapped])
            .process_group(0)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("fixture exec");
        self.execs
            .lock()
            .expect("exec groups")
            .push(crate::machine::ExecGroup::new(
                child.id().expect("exec pid"),
            ));
        let close_without_status = closes_without_status(data);
        let handle = session.handle();
        let seen = self.seen.clone();
        let machine = self.machine.clone();
        let task = tokio::spawn(async move {
            // Observe launches while the exec is waiting, not from the harness's report.
            let mut stdout = child.stdout.take().expect("stdout");
            let mut stderr = child.stderr.take().expect("stderr");
            let mut out = Vec::new();
            let mut err = Vec::new();
            {
                let output = async {
                    tokio::try_join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err))
                };
                tokio::pin!(output);
                loop {
                    tokio::select! {
                        _ = &mut output => break,
                        _ = tokio::time::sleep(Duration::from_millis(10)) => { machine.observe(); }
                    }
                }
            }
            let status = child.wait().await.expect("exec wait");
            machine.observe();
            if !close_without_status {
                let status = status.code().unwrap_or(255) as u32;
                observe(&seen, |s| s.ssh_exit.push(status));
                let _ = handle.data(channel, out).await;
                let _ = handle.extended_data(channel, 1, err).await;
                let _ = handle.exit_status_request(channel, status).await;
            }
            if close_without_status {
                // Keep this dispatch awaiting its record while concurrent requests reach admission.
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
        self.tasks.lock().expect("exec tasks").push(task);
        Ok(())
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

    /// Let a concurrency fixture admit simultaneous dials; return the prior spacing.
    pub fn set_spacing(&mut self, spacing: Duration) -> Duration {
        std::mem::replace(&mut self.limits.min_spacing, spacing)
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
    Held(String),
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
    /// The client's connection ended with no close frame, after OK.
    Ended,
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

/// One protocol stage held while still polling the browser socket for its close.
#[derive(Default)]
pub struct SessionGate {
    stage: Mutex<String>,
    pub reached: AtomicBool,
}
impl SessionGate {
    pub fn arm(&self, stage: &str) {
        let mut current = self.stage.lock().unwrap();
        self.reached.store(false, Ordering::SeqCst);
        *current = stage.into();
    }
    pub fn clear(&self) {
        self.stage.lock().unwrap().clear();
    }
    fn is(&self, stage: &str) -> bool {
        *self.stage.lock().unwrap() == stage
    }
    async fn hold(&self, stage: &str, ws: &mut Ws, log: &Log) -> bool {
        if !self.is(stage) {
            return true;
        }
        self.reached.store(true, Ordering::SeqCst);
        log.event(Event::Held(stage.into()));
        while self.is(stage) {
            tokio::select! {
                frame = ws.next() => match frame {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
                        log.event(Event::Ended);
                        let _ = ws.close(None).await;
                        return false;
                    }
                    Some(Ok(frame)) => log.event(Event::Frame(kind(&frame))),
                },
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
        true
    }
}

pub struct Relay {
    pub session_gate: Arc<SessionGate>,
    /// `wss://127.0.0.1:<port>/`, the URL the AUTH's `relay` tag must name.
    pub url: String,
    /// Check 6's state, shared by every connection.
    pub pace: Arc<Mutex<Pace>>,
    pub passes: Arc<Mutex<Vec<Pass>>>,
    /// With `hold`, the fixture waits here between the dial and OK until the test adds a permit,
    /// so a test can put a frame into that interval deterministically. Each permit releases one
    /// connection: the fixture spends it rather than returning it. The relay matrix's.
    #[cfg_attr(not(test), allow(dead_code))]
    pub release: Arc<Semaphore>,
}

struct RelayState {
    session_gate: Arc<SessionGate>,
    url: String,
    passes: Arc<Mutex<Vec<Pass>>>,
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
    let session_gate = Arc::new(SessionGate::default());
    let state = Arc::new(RelayState {
        session_gate: session_gate.clone(),
        url: url.clone(),
        passes: Arc::new(Mutex::new(passes)),
        limits,
        pace: pace.clone(),
        release: release.clone(),
        connections: AtomicU32::new(0),
    });
    let recorded_passes = state.passes.clone();
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
    Relay {
        session_gate,
        url,
        pace,
        release,
        passes: recorded_passes,
    }
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
    let passes = state.passes.lock().expect("passes lock");
    let pass = passes
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
    if !state.session_gate.hold("challenge", &mut ws, log).await {
        return;
    }
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
        _ => {
            log.event(Event::Ended);
            return;
        }
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
                let Some(Ok(frame)) = frame else {
                    log.event(Event::Ended);
                    return;
                };
                log.event(Event::Frame(kind(&frame)));
                match frame {
                    Message::Binary(_) => {
                        close(&mut ws, 1002, log).await;
                        return;
                    }
                    Message::Close(_) => {
                        log.event(Event::Ended);
                        return;
                    }
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
    if !state.session_gate.hold("verdict", &mut ws, log).await {
        return;
    }
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
    let auth_before = log.seen.lock().unwrap().ssh_auth.len();
    let mut banner_sent = false;
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
                _ => {
                    log.event(Event::Ended);
                    break None;
                }
            },
            read = tcp.read(&mut buffer) => match read {
                Ok(n) if n > 0 => {
                    if !banner_sent {
                        if !state.session_gate.hold("identification", &mut ws, log).await { break None; }
                        if let Some(end) = buffer[..n].iter().position(|b| *b == b'\n') {
                            let end = end + 1;
                            if ws.send(Message::binary(buffer[..end].to_vec())).await.is_err() { break None; }
                            log.event(Event::Forwarded(Toward::Client, end));
                            banner_sent = true;
                            if end == n { continue; }
                            buffer.copy_within(end..n, 0);
                            let bytes = buffer[..n-end].to_vec();
                            if !state.session_gate.hold("kex", &mut ws, log).await { break None; }
                            if ws.send(Message::binary(bytes)).await.is_err() { break None; }
                            log.event(Event::Forwarded(Toward::Client, n-end));
                            continue;
                        }
                    }
                    if !state.session_gate.hold("kex", &mut ws, log).await { break None; }
                    let authenticating = log.seen.lock().unwrap().ssh_auth.len() > auth_before;
                    if authenticating && !state.session_gate.hold("auth", &mut ws, log).await { break None; }
                    if !state.session_gate.hold("rekey", &mut ws, log).await { break None; }
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

/// Every request an HTTPS server received, its request line, headers and body, byte for byte.
pub type Requests = Arc<Mutex<Vec<Vec<u8>>>>;

/// Serves `root` over HTTPS on an ephemeral port; its origin, `https://127.0.0.1:<port>`, and
/// its log of requests. `worker_policy`, when given, is sent as the worker script's
/// `Content-Security-Policy` header: a dedicated worker takes its policy from its own response,
/// not from the page.
pub async fn https(
    root: PathBuf,
    tls: TlsAcceptor,
    worker_policy: Option<String>,
) -> (String, Requests) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("https bind");
    let origin = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().expect("https address").port()
    );
    let (root, worker_policy) = (Arc::new(root), Arc::new(worker_policy));
    let requests = Requests::default();
    let log = requests.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let (tls, root, worker_policy) = (tls.clone(), root.clone(), worker_policy.clone());
            let log = log.clone();
            tokio::spawn(async move {
                if let Ok(stream) = tls.accept(tcp).await {
                    let _ = serve(stream, &root, worker_policy.as_deref(), &log).await;
                }
            });
        }
    });
    (origin, requests)
}

async fn serve(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    root: &std::path::Path,
    worker_policy: Option<&str>,
    log: &Requests,
) -> std::io::Result<()> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 16 * 1024 {
        if stream.read(&mut byte).await? == 0 {
            log.lock().expect("requests lock").push(head);
            return Ok(());
        }
        head.push(byte[0]);
    }
    // The body too, if the request declares one: what the no-plaintext case reads.
    let length = String::from_utf8_lossy(&head)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut request = head.clone();
    let mut body = vec![0; length.min(1 << 20)];
    stream.read_exact(&mut body).await?;
    request.extend_from_slice(&body);
    log.lock().expect("requests lock").push(request);
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

fn closes_without_status(data: &[u8]) -> bool {
    let sentinel = tau_web::jobs::launch(&"0".repeat(48), "", b"close-without-status");
    let command_line = sentinel
        .lines()
        .find(|line| line.ends_with("> \"$d/command\" || exit 1"))
        .expect("command operand");
    data.starts_with(b"# tau-web job launch ")
        && std::str::from_utf8(data).is_ok_and(|text| text.lines().any(|line| line == command_line))
}

#[cfg(test)]
mod job_trigger_tests {
    use super::*;

    #[test]
    fn close_without_status_requires_exact_command_operand() {
        let id = "a".repeat(48);
        assert!(closes_without_status(
            tau_web::jobs::launch(&id, "fixture", b"close-without-status").as_bytes()
        ));
        for (machine, command) in [
            ("close", "exit 0"),
            ("close-without-status", "exit 0"),
            ("fixture", "echo close-without-status"),
            ("fixture", "close-without-status; exit 0"),
        ] {
            assert!(
                !closes_without_status(
                    tau_web::jobs::launch(&id, machine, command.as_bytes()).as_bytes()
                ),
                "{machine}: {command}"
            );
        }
    }
}

#[cfg(test)]
mod binding_tests {
    use super::*;
    use russh::client;
    use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
    struct Pin;
    impl client::Handler for Pin {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            key: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(
                matches!(key, PublicKeyOrCertificate::PublicKey { key, .. } if *key == *ed25519(&HOST_KEY_PINNED).public_key()),
            )
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn sshd_refuses_uninstalled_and_other_machine_keys_without_harness() {
        let seen = Observed::default();
        let fixture = sshd(seen.clone()).await;
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let own = crate::reader::role_key(mnemonic, 0, 0).unwrap();
        let other = crate::reader::role_key(mnemonic, 0, 1).unwrap();
        std::fs::write(
            fixture.machine.root.join("authorized_keys"),
            ed25519(&own).public_key().to_openssh().unwrap() + "\n",
        )
        .unwrap();
        for (seed, expected) in [(urandom::<32>(), false), (other, false), (own, true)] {
            let result = tokio::time::timeout(Duration::from_secs(10), async {
                let mut connection = client::connect(
                    Arc::new(client::Config::default()),
                    ("127.0.0.1", fixture.port),
                    Pin,
                )
                .await
                .unwrap();
                let result = connection
                    .authenticate_publickey(
                        tau_web::testonly::SSH_USER,
                        PrivateKeyWithHashAlg::new(Arc::new(ed25519(&seed)), None),
                    )
                    .await
                    .unwrap();
                connection
                    .disconnect(russh::Disconnect::ByApplication, "", "en")
                    .await
                    .unwrap();
                result.success()
            })
            .await
            .unwrap();
            assert_eq!(
                result, expected,
                "fixture sshd must refuse an uninstalled or another machine's key"
            );
        }
        // The file is read at each attempt; removing the key immediately revokes admission.
        std::fs::write(fixture.machine.root.join("authorized_keys"), "").unwrap();
        let mut connection = client::connect(
            Arc::new(client::Config::default()),
            ("127.0.0.1", fixture.port),
            Pin,
        )
        .await
        .unwrap();
        assert!(
            !connection
                .authenticate_publickey(
                    tau_web::testonly::SSH_USER,
                    PrivateKeyWithHashAlg::new(Arc::new(ed25519(&own)), None)
                )
                .await
                .unwrap()
                .success()
        );
        connection
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await
            .unwrap();
        drop(connection);
        fixture.cleanup().await;
    }
}
