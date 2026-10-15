//! The relay matrix (twr-ggw.3): the fixture half of `CNF-87`, paid-tcp-relay's handshake items
//! at `844e834` (`WIR-4`–`WIR-10`), driven by a host-side client that can misbehave as no correct
//! client does. It runs under `cargo test`. Each case starts its own relay fixture, so it starts
//! from fresh observations and pace state, and asserts first on what is visible outside the
//! relay: the frames, the reason, the close code, and what the test's own destination listeners
//! accepted and received. Then it asserts on the fixture's log (`WIR-10`). The cases are written
//! against `UnderTest`, a description of the relay, so the same set can run against another
//! relay (twr-ggw.26).

use crate::fixtures::{self, Event, Limits, Observed, Pace, Pass, PreOk, Relay, Toward, urandom};
use crate::keys::relay_public;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

/// How long any wait lasts before a case fails rather than hangs.
const WAIT: Duration = Duration::from_secs(10);
/// How long a case gives an absence (no connection, no byte) to be contradicted.
const SETTLE: Duration = Duration::from_millis(300);

/// A destination listener the test owns. It writes its banner as soon as it accepts, then echoes
/// what it receives, and records what it accepted and received, and when a connection closed.
struct Listener {
    host: String,
    port: u16,
    accepted: Arc<AtomicU32>,
    received: Arc<Mutex<Vec<u8>>>,
    closed: Arc<AtomicU32>,
    /// Set once the banner has been written.
    spoke: Arc<AtomicBool>,
}

async fn listener(host: &str, banner: &'static [u8]) -> Listener {
    let socket = TcpListener::bind((host, 0)).await.expect("listener bind");
    let port = socket.local_addr().expect("listener address").port();
    let (accepted, received, closed, spoke) = (
        Arc::new(AtomicU32::new(0)),
        Arc::new(Mutex::new(Vec::new())),
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicBool::new(false)),
    );
    let at = (
        accepted.clone(),
        received.clone(),
        closed.clone(),
        spoke.clone(),
    );
    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, _)) = socket.accept().await else {
                continue;
            };
            at.0.fetch_add(1, Ordering::SeqCst);
            let (received, closed, spoke) = (at.1.clone(), at.2.clone(), at.3.clone());
            tokio::spawn(async move {
                if !banner.is_empty() {
                    let _ = tcp.write_all(banner).await;
                    spoke.store(true, Ordering::SeqCst);
                }
                let mut buffer = [0; 4096];
                while let Ok(n @ 1..) = tcp.read(&mut buffer).await {
                    received.lock().expect("received lock").extend(&buffer[..n]);
                    if tcp.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
                closed.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    Listener {
        host: host.to_string(),
        port,
        accepted,
        received,
        closed,
        spoke,
    }
}

impl Listener {
    fn accepted(&self) -> u32 {
        self.accepted.load(Ordering::SeqCst)
    }

    fn received(&self) -> Vec<u8> {
        self.received.lock().expect("received lock").clone()
    }

    /// Waits until the listener has accepted `n` connections; whether it has. It counts an
    /// accept in its own task, which a completed connect does not wait for.
    async fn accepts(&self, n: u32) -> bool {
        let deadline = Instant::now() + WAIT;
        while self.accepted() < n && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.accepted() == n
    }
}

/// The relay under test: its URL and the certificate to trust for it, a relay key that holds a
/// pass, a recorded destination host with two listeners the test owns on it (`sshd`, standing
/// for the machine's sshd, and `other`), and an unrecorded host with a listener of its own.
struct UnderTest {
    url: String,
    cert: CertificateDer<'static>,
    key: [u8; 32],
    sshd: Listener,
    other: Listener,
    unrecorded: Listener,
}

/// The relay fixture behind an `UnderTest`, and what it observed.
struct Fixture {
    relay: UnderTest,
    seen: Observed,
    handle: Relay,
}

/// A relay fixture of its own, holding a pass for a relay key the test generates, for the host
/// `127.0.0.1` until an hour from now, plus `passes`. `hold` holds OK after each dial until the
/// test releases it.
async fn fixture(hold: bool, passes: Vec<Pass>) -> Fixture {
    let seen = Observed::default();
    let tls = fixtures::tls();
    let key = urandom::<32>();
    let mut all = vec![Pass {
        key: relay_public(&key),
        hosts: vec!["127.0.0.1".into()],
        expires: SystemTime::now() + Duration::from_secs(3600),
    }];
    all.extend(passes);
    let handle = fixtures::relay(seen.clone(), tls.acceptor, all, hold).await;
    Fixture {
        relay: UnderTest {
            url: handle.url.clone(),
            cert: tls.cert,
            key,
            sshd: listener("127.0.0.1", b"").await,
            other: listener("127.0.0.1", b"").await,
            unrecorded: listener("127.0.0.2", b"").await,
        },
        seen,
        handle,
    }
}

impl Fixture {
    /// The log of the `n`th connection, in the order the challenges were sent.
    fn log(&self, n: usize) -> Vec<Event> {
        let logs = self.seen.lock().expect("observations lock").relay_logs();
        logs.get(n).cloned().unwrap_or_default()
    }

    /// Waits until the `n`th connection's log holds `event`.
    async fn logged(&self, n: usize, event: impl Fn(&Event) -> bool) -> bool {
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if self.log(n).iter().any(&event) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }
}

type Client = WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// A frame as the client got it.
#[derive(Debug, PartialEq)]
enum Got {
    Text(Value),
    Binary(Vec<u8>),
    Close(Option<u16>),
    /// Nothing within `WAIT`.
    Nothing,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

impl UnderTest {
    /// Opens a connection for `host:port`, trusting exactly the relay's certificate; the socket
    /// and the challenge it got.
    async fn open(&self, host: &str, port: u16) -> (Client, Value) {
        let mut roots = RootCertStore::empty();
        roots
            .add(self.cert.clone())
            .expect("the relay's certificate");
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
        let authority = self
            .url
            .strip_prefix("wss://")
            .and_then(|rest| rest.strip_suffix('/'))
            .expect("wss://<host>:<port>/");
        let name = authority.rsplit_once(':').expect("<host>:<port>").0;
        let tcp = TcpStream::connect(authority).await.expect("relay connect");
        let tls = TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(name.to_string()).expect("name"), tcp)
            .await
            .expect("TLS to the relay");
        let url = format!("{}v1/tcp/{host}/{port}", self.url);
        let (mut ws, _) = tokio_tungstenite::client_async(url, tls)
            .await
            .expect("WebSocket upgrade");
        let challenge = match next(&mut ws).await {
            Got::Text(challenge) => challenge,
            other => panic!("the first frame is not a text frame: {other:?}"),
        };
        (ws, challenge)
    }

    /// An AUTH for `host:port` over `challenge`, signed by `key`, created at `created_at`.
    fn auth(&self, key: &[u8; 32], challenge: &Value, to: &Listener, created_at: u64) -> String {
        tau_web::relay_auth::auth_event(
            key,
            &self.url,
            challenge["challenge"].as_str().expect("a challenge"),
            &to.host,
            to.port,
            created_at,
            &urandom::<32>(),
        )
        .expect("signed")
        .to_string()
    }

    /// Opens a connection to `to` and answers its challenge with a correct AUTH by the key
    /// holding the pass; the socket, and the AUTH it sent.
    async fn authenticate(&self, to: &Listener) -> (Client, String) {
        let (mut ws, challenge) = self.open(&to.host, to.port).await;
        let auth = self.auth(&self.key, &challenge, to, now());
        send(&mut ws, Message::text(auth.clone())).await;
        (ws, auth)
    }

    fn listeners(&self) -> [&Listener; 3] {
        [&self.sshd, &self.other, &self.unrecorded]
    }

    /// What each listener has accepted and received so far.
    fn touched(&self) -> Vec<(u32, Vec<u8>)> {
        self.listeners()
            .iter()
            .map(|l| (l.accepted(), l.received()))
            .collect()
    }

    /// Whether, `SETTLE` from now, no listener has accepted a connection or received a byte
    /// since `before`.
    async fn untouched_since(&self, before: &[(u32, Vec<u8>)]) -> bool {
        tokio::time::sleep(SETTLE).await;
        self.touched() == before
    }

    /// Whether, `SETTLE` from now, no listener has accepted a connection or received a byte.
    async fn untouched(&self) -> bool {
        self.untouched_since(&[(0, Vec::new()), (0, Vec::new()), (0, Vec::new())])
            .await
    }
}

async fn send(ws: &mut Client, message: Message) {
    ws.send(message).await.expect("send");
}

/// The next frame, pings and pongs aside.
async fn next(ws: &mut Client) -> Got {
    loop {
        return match tokio::time::timeout(WAIT, ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                Got::Text(serde_json::from_str(&text).unwrap_or(Value::Null))
            }
            Ok(Some(Ok(Message::Binary(bytes)))) => Got::Binary(bytes.to_vec()),
            Ok(Some(Ok(Message::Close(frame)))) => Got::Close(frame.map(|f| f.code.into())),
            Ok(Some(Ok(_))) => continue,
            Ok(_) => Got::Close(None),
            Err(_) => Got::Nothing,
        };
    }
}

/// Every frame up to and including the close, or up to a wait that ends with nothing.
async fn until_close(ws: &mut Client) -> Vec<Got> {
    let mut frames = Vec::new();
    loop {
        let frame = next(ws).await;
        let last = matches!(frame, Got::Close(_) | Got::Nothing);
        frames.push(frame);
        if last {
            return frames;
        }
    }
}

/// `WIR-7`'s refusal (paid-tcp-relay `844e834`): one text frame naming `reason`, then close 1008.
fn refusal(reason: &str) -> Vec<Got> {
    vec![
        Got::Text(json!({ "ok": false, "reason": reason })),
        Got::Close(Some(1008)),
    ]
}

/// The log shows the refusal at `check`, and no dial.
fn refused_without_dial(log: &[Event], reason: &str, check: &str) -> bool {
    log.iter()
        .any(|e| matches!(e, Event::Refused(r, c) if *r == reason && *c == check))
        && !log.iter().any(|e| matches!(e, Event::Dial(_)))
}

fn ok() -> Got {
    Got::Text(json!({ "ok": true }))
}

/// Case 1, `WIR-4` (paid-tcp-relay `844e834`): each connection gets a fresh challenge, 32 bytes
/// as base64url with no padding, naming the relay.
#[tokio::test]
async fn case_01_fresh_challenge() {
    let f = fixture(false, vec![]).await;
    let mut challenges = Vec::new();
    for _ in 0..4 {
        let (ws, challenge) = f.relay.open("127.0.0.1", f.relay.sshd.port).await;
        assert_eq!(challenge["relay"], f.relay.url.as_str(), "{challenge}");
        let text = challenge["challenge"]
            .as_str()
            .expect("a challenge")
            .to_string();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&text)
            .expect("base64url with no padding");
        assert_eq!(bytes.len(), 32, "{text}");
        assert_eq!(
            challenge.as_object().map(|o| o.len()),
            Some(2),
            "{challenge}"
        );
        challenges.push(text);
        drop(ws);
    }
    let mut distinct = challenges.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), challenges.len(), "{challenges:?}");
    assert!(f.relay.untouched().await);
}

/// Case 2, `WIR-6` check 2 (paid-tcp-relay `844e834`): an AUTH signed now by the key holding the
/// pass, within the skew, for a recorded destination, but over an earlier connection's
/// challenge, is refused for `auth`. Every other check passes, so a relay that skips the
/// comparison answers OK.
#[tokio::test]
async fn case_02_stale_challenge() {
    let f = fixture(false, vec![]).await;
    let r = &f.relay;
    let (_earlier, stale) = r.open(&r.sshd.host, r.sshd.port).await;
    let (mut ws, _) = r.open(&r.sshd.host, r.sshd.port).await;
    send(
        &mut ws,
        Message::text(r.auth(&r.key, &stale, &r.sshd, now())),
    )
    .await;
    assert_eq!(until_close(&mut ws).await, refusal("auth"));
    assert!(r.untouched().await);
    assert!(
        refused_without_dial(&f.log(1), "auth", "2 signature"),
        "{:?}",
        f.log(1)
    );
}

/// Case 3, `WIR-9` (paid-tcp-relay `844e834`): an AUTH an earlier connection had accepted,
/// resent verbatim on a new connection within the skew, is refused for `auth` at check 2.
#[tokio::test]
async fn case_03_replayed_signature() {
    let f = fixture(false, vec![]).await;
    let r = &f.relay;
    let (mut first, auth) = r.authenticate(&r.sshd).await;
    assert_eq!(next(&mut first).await, ok());
    let _ = first.close(None).await;
    assert!(
        r.sshd.accepts(1).await,
        "the sshd accepted {}",
        r.sshd.accepted()
    );
    tokio::time::sleep(SETTLE).await;
    let before = r.touched();

    let (mut ws, _) = r.open(&r.sshd.host, r.sshd.port).await;
    send(&mut ws, Message::text(auth)).await;
    assert_eq!(until_close(&mut ws).await, refusal("auth"));
    assert!(r.untouched_since(&before).await, "the replay dialed");
    assert!(
        refused_without_dial(&f.log(1), "auth", "2 signature"),
        "{:?}",
        f.log(1)
    );
}

/// Case 4, `WIR-5`/`WIR-6` check 1 (paid-tcp-relay `844e834`): `created_at` beyond
/// `relay.auth_skew` in the past or the future is refused for `auth`; a minute inside it is
/// accepted.
#[tokio::test]
async fn case_04_skew() {
    let f = fixture(false, vec![]).await;
    let r = &f.relay;
    let skew = Limits::bundle().auth_skew.as_secs();
    for (n, created_at) in [now() - skew - 60, now() + skew + 60]
        .into_iter()
        .enumerate()
    {
        let (mut ws, challenge) = r.open(&r.sshd.host, r.sshd.port).await;
        send(
            &mut ws,
            Message::text(r.auth(&r.key, &challenge, &r.sshd, created_at)),
        )
        .await;
        assert_eq!(until_close(&mut ws).await, refusal("auth"), "{created_at}");
        assert!(refused_without_dial(&f.log(n), "auth", "1 shape"));
    }
    assert!(r.untouched().await);

    let (mut ws, challenge) = r.open(&r.sshd.host, r.sshd.port).await;
    let inside = now() - skew + 60;
    send(
        &mut ws,
        Message::text(r.auth(&r.key, &challenge, &r.sshd, inside)),
    )
    .await;
    assert_eq!(next(&mut ws).await, ok());
}

/// Case 5, `PAS-3` and `WIR-6` check 3 (paid-tcp-relay `844e834`): a correct AUTH by a key with
/// no pass, and one by a key whose pass has expired, are each refused for `pass`.
#[tokio::test]
async fn case_05_unknown_key_and_expired_pass() {
    let expired = urandom::<32>();
    let f = fixture(
        false,
        vec![Pass {
            key: relay_public(&expired),
            hosts: vec!["127.0.0.1".into()],
            expires: SystemTime::now() - Duration::from_secs(1),
        }],
    )
    .await;
    let r = &f.relay;
    for (n, key) in [urandom::<32>(), expired].iter().enumerate() {
        let (mut ws, challenge) = r.open(&r.sshd.host, r.sshd.port).await;
        send(
            &mut ws,
            Message::text(r.auth(key, &challenge, &r.sshd, now())),
        )
        .await;
        assert_eq!(until_close(&mut ws).await, refusal("pass"));
        assert!(refused_without_dial(&f.log(n), "pass", "3 pass"));
    }
    assert!(r.untouched().await);
}

/// Case 6, `PAS-4`, `DST-1`, `DST-2` (paid-tcp-relay `844e834`): a recorded host is reached on a
/// port other than the sshd's; an unrecorded host is refused for `destination`, and its listener
/// sees nothing.
#[tokio::test]
async fn case_06_recorded_destinations_only() {
    let f = fixture(false, vec![]).await;
    let r = &f.relay;
    let (mut ws, _) = r.authenticate(&r.unrecorded).await;
    assert_eq!(until_close(&mut ws).await, refusal("destination"));
    assert!(r.untouched().await);
    assert!(refused_without_dial(
        &f.log(0),
        "destination",
        "4 destination"
    ));

    let (mut ws, _) = r.authenticate(&r.other).await;
    assert_eq!(next(&mut ws).await, ok());
    send(&mut ws, Message::binary(b"other port".to_vec())).await;
    assert_eq!(next(&mut ws).await, Got::Binary(b"other port".to_vec()));
    assert_eq!(r.other.received(), b"other port");
    assert_eq!(r.other.accepted(), 1);
    assert_eq!((r.sshd.accepted(), r.unrecorded.accepted()), (0, 0));
}

/// Case 7, `DST-3` (paid-tcp-relay `844e834`) at the bundle's values, end to end on the
/// fixture's clock, frozen: a second dial to one host within `min_spacing`, on another port, is
/// refused for `pace` with no dial; once `min_spacing` has passed, a dial is accepted.
#[tokio::test]
async fn case_07_pace_min_spacing() {
    let f = fixture(false, vec![]).await;
    let r = &f.relay;
    let start = Instant::now();
    f.handle.pace.lock().expect("pace lock").clock = Some(start);
    let (mut ws, _) = r.authenticate(&r.sshd).await;
    assert_eq!(next(&mut ws).await, ok());
    tokio::time::sleep(SETTLE).await;
    let before = r.touched();

    let (mut ws, _) = r.authenticate(&r.other).await;
    assert_eq!(until_close(&mut ws).await, refusal("pace"));
    assert!(r.untouched_since(&before).await);
    assert!(refused_without_dial(&f.log(1), "pace", "6 pace"));

    f.handle.pace.lock().expect("pace lock").clock = Some(start + Limits::bundle().min_spacing);
    let (mut ws, _) = r.authenticate(&r.other).await;
    assert_eq!(next(&mut ws).await, ok());
    assert!(f.logged(2, |e| matches!(e, Event::Dial(_))).await);
}

/// Case 7, `DST-3`'s window (paid-tcp-relay `844e834`), on an injected clock at the bundle's
/// values: inside one window the (`window_cap`+1)th dial is refused, spaced as it is; once the
/// window has passed, a dial is accepted.
#[test]
fn case_07_pace_window_cap() {
    let limits = Limits::bundle();
    let mut pace = Pace::new(limits);
    let start = Instant::now();
    let cap = u32::try_from(limits.window_cap).expect("a small cap");
    assert!(limits.min_spacing * cap < limits.window, "{limits:?}");
    for n in 0..cap {
        assert!(
            pace.admit("host", start + limits.min_spacing * n),
            "dial {n}"
        );
    }
    assert!(!pace.admit("host", start + limits.min_spacing * cap));
    assert!(pace.admit("other host", start + limits.min_spacing * cap));
    assert!(pace.admit("host", start + limits.window));
}

/// Case 8, `WIR-7` and `WIR-10` (paid-tcp-relay `844e834`): challenge, then OK after the AUTH,
/// then binary; the log reads challenge sent, AUTH received, accepted, dial, OK sent, first
/// forwarded byte.
#[tokio::test]
async fn case_08_order() {
    let f = fixture(false, vec![]).await;
    let r = &f.relay;
    let (mut ws, _) = r.authenticate(&r.sshd).await;
    assert_eq!(next(&mut ws).await, ok());
    send(&mut ws, Message::binary(b"after OK".to_vec())).await;
    assert_eq!(next(&mut ws).await, Got::Binary(b"after OK".to_vec()));
    assert_eq!(r.sshd.received(), b"after OK");
    let log = f.log(0);
    assert_eq!(
        log.get(..6),
        Some(
            &[
                Event::ChallengeSent,
                Event::AuthReceived,
                Event::Accepted,
                Event::Dial(format!("127.0.0.1:{}", r.sshd.port)),
                Event::OkSent,
                Event::Forwarded(Toward::Destination, 8),
            ][..]
        ),
        "{log:?}"
    );
}

/// Case 9(a), `WIR-8` (paid-tcp-relay `844e834`): a binary frame in place of the AUTH closes
/// with 1002: no verdict, no dial, no connection at any listener.
#[tokio::test]
async fn case_09a_binary_in_place_of_the_auth() {
    let f = fixture(false, vec![]).await;
    let r = &f.relay;
    let (mut ws, _) = r.open(&r.sshd.host, r.sshd.port).await;
    send(&mut ws, Message::binary(b"not an AUTH".to_vec())).await;
    assert_eq!(until_close(&mut ws).await, [Got::Close(Some(1002))]);
    assert!(r.untouched().await);
    let log = f.log(0);
    assert!(!log.iter().any(|e| matches!(e, Event::Dial(_))), "{log:?}");
}

/// Case 9(b), `WIR-8` and `WIR-10` (paid-tcp-relay `844e834`): a binary frame after an accepted
/// AUTH and before OK closes with 1002 and no OK; the destination may have been dialed, and
/// receives no byte. The fixture holds OK until the frame has been read, so the frame comes
/// before OK every time.
#[tokio::test]
async fn case_09b_binary_after_the_auth_before_ok() {
    let f = fixture(true, vec![]).await;
    let r = &f.relay;
    let (mut ws, _) = r.authenticate(&r.sshd).await;
    assert!(f.logged(0, |e| matches!(e, Event::Dial(_))).await);
    send(&mut ws, Message::binary(b"before OK".to_vec())).await;
    assert!(f.logged(0, |e| *e == Event::Frame("binary")).await);
    f.handle.release.add_permits(1);
    assert_eq!(until_close(&mut ws).await, [Got::Close(Some(1002))]);
    tokio::time::sleep(SETTLE).await;
    assert_eq!(r.sshd.received(), b"");
    let log = f.log(0);
    assert!(
        !log.iter()
            .any(|e| matches!(e, Event::OkSent | Event::Forwarded(..))),
        "{log:?}"
    );
}

/// Case 10, `WIR-8` (paid-tcp-relay `844e834`): a text frame after OK closes with 1002; the
/// destination receives none of its bytes, and its TCP connection closes.
#[tokio::test]
async fn case_10_text_after_ok() {
    let f = fixture(false, vec![]).await;
    let r = &f.relay;
    let (mut ws, _) = r.authenticate(&r.sshd).await;
    assert_eq!(next(&mut ws).await, ok());
    send(&mut ws, Message::text("after OK")).await;
    assert_eq!(until_close(&mut ws).await, [Got::Close(Some(1002))]);
    let deadline = Instant::now() + WAIT;
    while r.sshd.closed.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        r.sshd.closed.load(Ordering::SeqCst),
        1,
        "the TCP connection is open"
    );
    assert_eq!(r.sshd.received(), b"");
}

/// Case 11, `WIR-10` (paid-tcp-relay `844e834`): a destination that speaks as soon as it
/// accepts. Its bytes reach the client only after `{"ok": true}`, and the log shows them
/// forwarded after OK sent. The fixture holds OK until the destination has spoken.
#[tokio::test]
async fn case_11_a_destination_that_speaks_first() {
    let f = fixture(true, vec![]).await;
    let r = &f.relay;
    let banner = listener("127.0.0.1", b"SSH-2.0-banner\r\n").await;
    let (mut ws, _) = r.authenticate(&banner).await;
    let deadline = Instant::now() + WAIT;
    while !banner.spoke.load(Ordering::SeqCst) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(banner.spoke.load(Ordering::SeqCst));
    tokio::time::sleep(SETTLE).await;
    f.handle.release.add_permits(1);
    assert_eq!(next(&mut ws).await, ok());
    assert_eq!(
        next(&mut ws).await,
        Got::Binary(b"SSH-2.0-banner\r\n".to_vec())
    );
    // The fixture logs a forwarded frame once it has sent it, so wait for the log.
    let forwarded = |e: &Event| matches!(e, Event::Forwarded(Toward::Client, _));
    assert!(f.logged(0, forwarded).await, "{:?}", f.log(0));
    let log = f.log(0);
    let ok_sent = log.iter().position(|e| *e == Event::OkSent);
    let first_byte = log.iter().position(forwarded);
    assert!(
        ok_sent.is_some() && first_byte.is_some() && ok_sent < first_byte,
        "{log:?}"
    );
}

/// `WIR-8` and `WIR-10` (paid-tcp-relay `844e834`), the fixture's step between an accepted AUTH
/// and OK, the one `relay_connection` runs: a binary frame that is ready when the dial completes
/// is read first, so the fixture closes with 1002 rather than sending OK and forwarding it. The
/// matrix cannot make both ready at one poll on a socket, so this drives the step with both
/// ready at the first poll, 64 times: an unbiased select would pick the dial in about half.
#[tokio::test]
async fn the_pre_ok_step_reads_a_ready_frame_first() {
    for n in 0..64 {
        let mut frames = futures_util::stream::iter([Message::binary(b"before OK".to_vec())]);
        let mut dial = std::future::ready(());
        let first = fixtures::pre_ok(&mut frames, &mut dial).await;
        assert!(
            matches!(first, PreOk::Frame(Some(Message::Binary(_)))),
            "poll {n}: the dial came first"
        );
    }
}

/// The limits are the bundle's, read from the vendored file.
#[test]
fn the_limits_are_the_bundles() {
    assert_eq!(
        Limits::bundle(),
        Limits {
            auth_skew: Duration::from_secs(600),
            min_spacing: Duration::from_secs(1),
            window: Duration::from_secs(900),
            window_cap: 200,
        }
    );
}
