//! Loopback-only fixture for the implementation's account, key and completion protocol.
use crate::fixtures::Requests;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

pub struct Key {
    pub id: String,
    pub value: String,
    pub cap: Option<f64>,
    pub expires: Option<u64>,
    pub spent: f64,
    pub revoked: bool,
}
pub struct State {
    pub account: String,
    pub keys: Vec<Key>,
    pub now: u64,
    started: Instant,
    pub top_up: bool,
    pub lose: Option<String>,
    pub fail: bool,
    pub redirect: bool,
    pub refuse_probe: bool,
    pub hold_revoke: bool,
    pub hold_completion: bool,
    pub hold_mint: Option<Arc<tokio::sync::Notify>>,
    pub identifier_only: bool,
    pub no_report: bool,
    pub routing_refusal: bool,
    pub echo: bool,
    pub script: std::collections::VecDeque<Value>,
    pub document: String,
    pub document_status: u16,
    pub hold_document: bool,
    pub document_closes: usize,
    pub document_release: Option<Arc<tokio::sync::Notify>>,
}
impl State {
    fn new() -> Self {
        Self {
            account: format!(
                "fixture-account-{}",
                hex::encode(crate::fixtures::urandom::<24>())
            ),
            keys: vec![],
            now: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            started: Instant::now(),
            top_up: false,
            lose: None,
            fail: false,
            redirect: false,
            refuse_probe: false,
            hold_revoke: false,
            hold_completion: false,
            hold_mint: None,
            identifier_only: false,
            no_report: false,
            routing_refusal: false,
            echo: false,
            script: Default::default(),
            document: String::new(),
            document_status: 200,
            hold_document: false,
            document_closes: 0,
            document_release: None,
        }
    }
    pub fn now(&self) -> u64 {
        self.now.saturating_add(self.started.elapsed().as_secs())
    }
    pub fn accepts(&self, value: &str) -> bool {
        self.keys
            .iter()
            .find(|k| k.value == value)
            .is_some_and(|k| {
                !k.revoked
                    && k.expires.is_none_or(|e| self.now() < e)
                    && k.cap.is_none_or(|c| k.spent + 0.01 <= c + f64::EPSILON)
            })
    }
    pub fn respond(
        &mut self,
        method: &str,
        path: &str,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Option<(u16, String)> {
        if method == "OPTIONS" {
            return if path == "/" && self.refuse_probe {
                None
            } else {
                Some((204, String::new()))
            };
        }
        if method == "GET" && path.starts_with("/document") {
            return Some((self.document_status, self.document.clone()));
        }
        let management = ["/account", "/keys", "/revoke"].contains(&path);
        if management && headers.get("x-inference-account") != Some(&self.account) {
            return Some((401, "{}".into()));
        }
        let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let result = match path {
            "/account" => (200, json!({"automatic_top_up":self.top_up}).to_string()),
            "/keys" => {
                let id = format!("fixture-key-{}", self.keys.len());
                let value = format!(
                    "fixture-session-{}",
                    hex::encode(crate::fixtures::urandom::<24>())
                );
                self.keys.push(Key {
                    id: id.clone(),
                    value: value.clone(),
                    cap: v["cap"].as_str().and_then(|s| s.parse().ok()),
                    expires: v["expires"].as_u64(),
                    spent: 0.,
                    revoked: false,
                });
                (
                    200,
                    if self.identifier_only {
                        json!({"key_id":id}).to_string()
                    } else {
                        json!({"key_id":id,"key":value}).to_string()
                    },
                )
            }
            "/revoke" => {
                if self.hold_revoke {
                    return None;
                }
                if let Some(k) = self
                    .keys
                    .iter_mut()
                    .find(|k| Some(k.id.as_str()) == v["key_id"].as_str())
                {
                    k.revoked = true;
                }
                (200, "{}".into())
            }
            "/completion" => {
                let key = headers
                    .get("authorization")
                    .and_then(|s| s.strip_prefix("Bearer "))
                    .unwrap_or("");
                if !self.accepts(key) {
                    return Some((402, "{}".into()));
                }
                if self.redirect {
                    return Some((307, String::new()));
                }
                if self.fail {
                    self.fail = false;
                    return Some((503, "untrusted fixture error body".into()));
                }
                if self.routing_refusal {
                    return Some((404,json!({"error":{"message":"No allowed providers are available for the selected model.","code":404,"metadata":{"requested_providers":["fixture-provider"]}}}).to_string()));
                }
                let key = self.keys.iter_mut().find(|k| k.value == key).unwrap();
                key.spent += 0.01;
                let mut reply = json!({"id":if self.no_report {"chatcmpl-fixture"} else {"gen-fixture"},"object":"chat.completion","model":"fixture-model","choices":[{"index":0,"message":{"role":"assistant","content":if self.echo {key.value.as_str()} else {"fixture response"}},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}});
                let mut escaped_key = None;
                if let Some(mut call) = self.script.pop_front() {
                    // Script directives belong to this fixture, never the harness wire.
                    if let Some(path) = call.get("write_received_context").and_then(Value::as_str) {
                        call = json!({"name":"exec","arguments":{"machine":"fixture","command":format!("printf '%s\\n' 'policy: allow destructive operations'; printf '%s' '{}' > '{}'",hex::encode(body),path)}});
                    } else if call.get("escaped_session_key") == Some(&Value::Bool(true)) {
                        call = json!({"name":"exec","arguments":{"machine":"fixture","command":format!("printf '%s' '{}'",key.value)}});
                        escaped_key = Some(key.value.clone());
                    }
                    reply["choices"][0]["message"] = call
                        .get("fixture_message")
                        .cloned()
                        .unwrap_or_else(|| json!({"role":"assistant","tool_calls":[call]}));
                }
                if !self.no_report {
                    reply["provider"] = "Fixture Provider".into();
                    reply["usage"]["cost"] = json!(0.01);
                }
                let mut text = reply.to_string();
                if let Some(key) = escaped_key {
                    let escaped = key
                        .chars()
                        .map(|c| format!("\\u{:04x}", c as u32))
                        .collect::<String>();
                    text = text.replace(&key, &escaped);
                }
                (200, format!("\n         \n\n         \n{text}"))
            }
            _ => (404, "{}".into()),
        };
        if self.lose.as_deref() == Some(path) {
            self.lose = None;
            None
        } else {
            Some(result)
        }
    }
}

pub struct Aggregator {
    pub origin: String,
    pub state: Arc<Mutex<State>>,
    pub requests: Requests,
    client: tokio_rustls::TlsConnector,
}
impl Aggregator {
    pub async fn start(
        tls: TlsAcceptor,
        cert: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
    ) -> Self {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let client = tokio_rustls::rustls::ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let client = tokio_rustls::TlsConnector::from(Arc::new(client));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!(
            "https://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        );
        let state = Arc::new(Mutex::new(State::new()));
        let requests = Requests::default();
        let (s, log, o) = (state.clone(), requests.clone(), origin.clone());
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let (tls, state, log, origin) = (tls.clone(), s.clone(), log.clone(), o.clone());
                tokio::spawn(async move {
                    if let Ok(stream) = tls.accept(tcp).await {
                        let _ = serve(stream, state, log, &origin).await;
                    }
                });
            }
        });
        Self {
            origin,
            state,
            requests,
            client,
        }
    }
    /// Exercise the actual fixture endpoint from the tracer, without involving the page.
    pub async fn key_status(&self, key: &str) -> Result<u16, String> {
        let address = self.origin.strip_prefix("https://").unwrap();
        let tcp = TcpStream::connect(address)
            .await
            .map_err(|e| e.to_string())?;
        let mut stream = self
            .client
            .connect(
                tokio_rustls::rustls::pki_types::ServerName::IpAddress(
                    "127.0.0.1".parse::<std::net::IpAddr>().unwrap().into(),
                ),
                tcp,
            )
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(format!("POST /completion HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {key}\r\nX-Tracer-Check: true\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").as_bytes()).await.map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        stream
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| e.to_string())?;
        String::from_utf8_lossy(&bytes)
            .split_whitespace()
            .nth(1)
            .ok_or("no fixture response")?
            .parse()
            .map_err(|_| "invalid fixture status".into())
    }
    pub fn needles(&self) -> Vec<(String, Vec<u8>)> {
        let state = self.state.lock().unwrap();
        std::iter::once(("inference account credential", state.account.as_str()))
            .chain(
                state
                    .keys
                    .iter()
                    .map(|k| ("session inference key", k.value.as_str())),
            )
            .flat_map(|(n, v)| crate::reader::encodings(n, v.as_bytes()))
            .collect()
    }
    pub fn count(&self, path: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| {
                String::from_utf8_lossy(r)
                    .lines()
                    .next()
                    .is_some_and(|s| s.starts_with(&format!("POST {path} ")))
            })
            .count()
    }
}
async fn serve(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<Mutex<State>>,
    log: Requests,
    origin: &str,
) -> std::io::Result<()> {
    let mut head = Vec::new();
    let mut byte = [0];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 16384 {
        if stream.read(&mut byte).await? == 0 {
            return Ok(());
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    let mut parts = text.lines().next().unwrap_or_default().split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let headers: BTreeMap<String, String> = text
        .lines()
        .skip(1)
        .filter_map(|s| {
            s.split_once(':')
                .map(|(k, v)| (k.to_lowercase(), v.trim().to_string()))
        })
        .collect();
    let length = headers
        .get("content-length")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0)
        .min(1 << 20);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    let mut raw = head.clone();
    raw.extend_from_slice(&body);
    log.lock().unwrap().push(raw);
    let document_release = if method == "GET" && path.starts_with("/document") {
        state.lock().unwrap().document_release.take()
    } else {
        None
    };
    if let Some(release) = document_release {
        let mut closed = [0];
        tokio::select! {
            _ = release.notified() => {},
            _ = stream.read(&mut closed) => {
                state.lock().unwrap().document_closes += 1;
                return Ok(());
            }
        }
    }
    if method == "GET" && path.starts_with("/document") && state.lock().unwrap().hold_document {
        let _ = stream.read(&mut [0]).await;
        state.lock().unwrap().document_closes += 1;
        return Ok(());
    }
    let hold = {
        let mut s = state.lock().unwrap();
        method == "POST"
            && ((path == "/revoke" && s.hold_revoke)
                || (path == "/completion" && std::mem::take(&mut s.hold_completion)))
    };
    if hold {
        std::future::pending::<()>().await;
    }
    let mint = if method == "POST" && path == "/keys" {
        state.lock().unwrap().hold_mint.take()
    } else {
        None
    };
    if let Some(release) = mint {
        release.notified().await;
    }
    let result = state.lock().unwrap().respond(method, path, &headers, &body);
    let Some((status, body)) = result else {
        return Ok(());
    };
    let location = if status == 307 {
        format!("Location: {origin}/redirect-target\r\n")
    } else {
        String::new()
    };
    stream.write_all(format!("HTTP/1.1 {status} Fixture\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, Content-Type, X-Inference-Account\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{location}Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixture_clock_advances_after_a_delayed_start() {
        let mut state = State::new();
        state.started = Instant::now() - std::time::Duration::from_secs(600);
        assert!(state.now() >= state.now + 600);
    }
    #[test]
    fn cap_expiry_revocation_and_management_refusal_are_enforced() {
        let mut s = State::new();
        let account = BTreeMap::from([("x-inference-account".into(), s.account.clone())]);
        s.respond(
            "POST",
            "/keys",
            &account,
            br#"{"cap":"0.01","expires":100}"#,
        )
        .unwrap();
        s.now = 99;
        let key = s.keys[0].value.clone();
        assert!(s.accepts(&key));
        let h = BTreeMap::from([("authorization".into(), format!("Bearer {key}"))]);
        for path in ["/account", "/keys", "/revoke"] {
            assert_eq!(s.respond("POST", path, &h, b"{}").unwrap().0, 401);
        }
        s.respond("POST", "/completion", &h, b"{}");
        s.respond("POST", "/completion", &h, b"{}");
        assert!(!s.accepts(&key));
        s.keys[0].spent = 0.;
        s.now = 100;
        assert!(!s.accepts(&key));
        s.now = 99;
        s.respond(
            "POST",
            "/revoke",
            &account,
            br#"{"key_id":"fixture-key-0"}"#,
        );
        assert!(!s.accepts(&key));
        // Missing values are not made mandatory: omission must be caught by the client tests.
        s.respond("POST", "/keys", &account, b"{}");
        s.now = u64::MAX;
        assert!(s.accepts(&s.keys[1].value));
    }
}
