//! Procured inference: durable intents, metadata terminals and memory-only session holdings.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest;
use zeroize::Zeroizing;

pub const SESSION_CAP: &str = "0.10";
pub const SESSION_LIFETIME_SECONDS: u64 = 900;

#[derive(Clone, Debug)]
pub struct Candidate {
    pub slug: String,
    pub maker: String,
    pub provider: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Intent {
    ClockRead {
        call: u64,
        session: String,
        sent: crate::clock::Pair,
    },
    AccountRead {
        call: u64,
        session: String,
    },
    Mint {
        call: u64,
        session: String,
        cap: String,
        expires: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evidence: Option<crate::inference_limits::OriginEvidence>,
    },
    Completion {
        call: u64,
        session: String,
        key_id: String,
        model: String,
        requested_provider: String,
        zdr: bool,
    },
    Revoke {
        call: u64,
        key_id: String,
    },
}

impl Intent {
    pub fn call(&self) -> u64 {
        match self {
            Self::ClockRead { call, .. } => *call,
            Self::AccountRead { call, .. }
            | Self::Mint { call, .. }
            | Self::Completion { call, .. }
            | Self::Revoke { call, .. } => *call,
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ClockRead { .. } => "clock_read",
            Self::AccountRead { .. } => "account_read",
            Self::Mint { .. } => "mint",
            Self::Completion { .. } => "completion",
            Self::Revoke { .. } => "revoke",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terminal {
    pub call: u64,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clock_received: Option<crate::clock::Pair>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clock_sent: Option<crate::clock::Pair>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charge_refusal: Option<ChargeRefusal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automatic_top_up: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl Terminal {
    pub fn new(call: u64, status: u16) -> Self {
        Self {
            call,
            status,
            issuer_time: None,
            clock_received: None,
            clock_sent: None,
            charge_refusal: None,
            automatic_top_up: None,
            key_id: None,
            cap: None,
            expires: None,
            unit: None,
            model: None,
            requested_provider: None,
            reported_provider: None,
            prompt_tokens: None,
            completion_tokens: None,
            total_tokens: None,
            spend: None,
            request_id: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChargeRefusal {
    AccountBalance,
    KeyCapExhausted,
    KeyExpired,
}

#[derive(Clone, Debug, Serialize)]
pub struct Call {
    pub intent: Intent,
    pub terminal: Option<Terminal>,
}

/// A transport request is transient and never serializable or printable.
pub struct Request {
    pub(crate) runtime: Option<std::rc::Rc<crate::binding::Session>>,
    pub(crate) clock_sent: std::cell::Cell<Option<crate::clock::Pair>>,
    pub(crate) clock_received: std::cell::Cell<Option<crate::clock::Pair>>,
    pub(crate) approved_body: crate::store::Address,
    pub(crate) call: u64,
    pub(crate) session: String,
    pub(crate) continuation: Option<crate::lifecycle::Continuation>,
    pub(crate) scan_revision: u64,
    pub method: &'static str,
    pub origin: String,
    pub path: &'static str,
    pub account: Option<Zeroizing<String>>,
    pub authorization: Option<Zeroizing<String>>,
    pub body: Zeroizing<String>,
}

impl Request {
    fn commitment(&self, body: &str) -> [u8; 32] {
        let mut hash = sha2::Sha256::new();
        for field in [
            self.method,
            &self.origin,
            self.path,
            self.account.as_deref().map_or("", |s| s.as_str()),
            self.authorization.as_deref().map_or("", |s| s.as_str()),
            body,
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        hash.finalize().into()
    }
    pub(crate) fn bind_bytes(&mut self) {
        self.approved_body = crate::store::Address(self.commitment(&self.body));
    }
    pub(crate) fn unchanged(&self) -> bool {
        self.unchanged_body(&self.body)
    }
    pub(crate) fn unchanged_body(&self, body: &str) -> bool {
        self.approved_body.0 == self.commitment(body)
    }
    pub(crate) fn retained_unsent(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
            clock_sent: std::cell::Cell::new(self.clock_sent.get()),
            clock_received: std::cell::Cell::new(self.clock_received.get()),
            approved_body: crate::store::Address(self.approved_body.0),
            call: self.call,
            session: self.session.clone(),
            continuation: self.continuation.clone(),
            scan_revision: self.scan_revision,
            method: self.method,
            origin: self.origin.clone(),
            path: self.path,
            account: self.account.as_ref().map(|s| Zeroizing::new(s.to_string())),
            authorization: self
                .authorization
                .as_ref()
                .map(|s| Zeroizing::new(s.to_string())),
            body: Zeroizing::new(self.body.to_string()),
        }
    }
}

pub struct Finished {
    pub report: Value,
    pub late_revoke: Option<(u64, Request)>,
}

pub struct Response {
    pub status: u16,
    pub body: Zeroizing<Vec<u8>>,
}

#[allow(async_fn_in_trait, reason = "single worker or recording host fixture")]
pub trait Transport {
    /// Redirects and opaque responses return None, as does a lost response.
    async fn exchange(&mut self, request: &Request) -> Option<Response>;
}

/// The driver never holds the store writer across a network wait.
#[allow(async_fn_in_trait, reason = "single worker")]
pub trait Journal {
    async fn probe_authority(
        &mut self,
        session: &str,
    ) -> Result<
        (
            crate::lifecycle::Continuation,
            std::rc::Rc<crate::binding::Session>,
        ),
        String,
    >;
    type MintGuard;
    async fn mint_guard(&mut self, session: &str) -> Self::MintGuard;
    fn can_send(&self, revoke: bool) -> bool;
    async fn mint_bounds(&mut self, session: &str, now: u64) -> Result<(String, u64), String>;
    async fn authorize(&mut self, request: &Request, now: u64) -> bool;
    async fn actionable(&mut self, request: &Request, now: u64) -> bool;
    async fn current_at(&mut self, session: &str, now: u64) -> Result<(), String>;
    async fn session(&mut self, machine: &str) -> Result<String, String>;
    async fn has_key(&mut self, session: &str) -> Result<bool, String>;
    async fn prepare(
        &mut self,
        session: &str,
        intent: Intent,
        origin: &str,
        body: Value,
    ) -> Result<(u64, Request), String>;
    async fn finish(
        &mut self,
        call: u64,
        response: &Response,
        request: &Request,
    ) -> Result<Finished, String>;
    async fn route(&mut self, origin: &str, chosen: bool) -> bool;
}

pub fn valid_request(value: &Value) -> bool {
    let Some(o) = value.as_object() else {
        return false;
    };
    o.get("machine").is_some_and(Value::is_string)
        && o.get("messages").is_some_and(|v| {
            v.as_array().is_some_and(|a| {
                !a.is_empty()
                    && a.iter().all(|m| {
                        m.as_object().is_some_and(|m| {
                            m.len() == 2
                                && m.get("role").is_some_and(|r| {
                                    matches!(r.as_str(), Some("user" | "system" | "assistant"))
                                })
                                && m.get("content").is_some_and(Value::is_string)
                        })
                    })
            })
        })
        && o.iter().all(|(k, v)| match k.as_str() {
            "machine" | "messages" => true,
            "max_tokens" => v.as_u64().is_some_and(|n| n > 0),
            _ => false,
        })
}

pub fn compose(candidate: &Candidate, request: &Value) -> Value {
    let mut body = json!({"model":candidate.slug,"messages":request["messages"],"provider":{"zdr":true,"only":[candidate.provider]}});
    if let Some(n) = request.get("max_tokens") {
        body["max_tokens"] = n.clone();
    }
    body
}

pub async fn probe(
    journal: &mut impl Journal,
    transport: &mut impl Transport,
    origin: &str,
    revoke: bool,
) -> Result<(), String> {
    probe_with(journal, transport, origin, revoke, None).await
}

pub(crate) async fn probe_with(
    journal: &mut impl Journal,
    transport: &mut impl Transport,
    origin: &str,
    revoke: bool,
    subject: Option<(
        crate::lifecycle::Continuation,
        std::rc::Rc<crate::binding::Session>,
    )>,
) -> Result<(), String> {
    if journal.route(origin, false).await {
        return Ok(());
    }
    if !journal.can_send(revoke) {
        return Err("sessions ended".into());
    }
    let mut request = Request {
        runtime: subject.as_ref().map(|(_, s)| s.clone()),
        clock_sent: std::cell::Cell::new(None),
        clock_received: std::cell::Cell::new(None),
        approved_body: crate::store::Address([0; 32]),
        call: 0,
        session: String::new(),
        continuation: subject.map(|(c, _)| c),
        scan_revision: 0,
        method: "OPTIONS",
        origin: origin.into(),
        path: "/",
        account: Some(Zeroizing::new("probe-placeholder".into())),
        authorization: Some(Zeroizing::new("probe-placeholder".into())),
        body: Zeroizing::new(String::new()),
    };
    request.bind_bytes();
    if transport.exchange(&request).await.is_none() {
        return Err("no route to that origin in this build".into());
    }
    journal.route(origin, true).await;
    Ok(())
}

pub(crate) async fn send_at(
    journal: &mut impl Journal,
    transport: &mut impl Transport,
    session: &str,
    intent: Intent,
    origin: &str,
    body: Value,
    now: &impl Fn() -> u64,
) -> Result<Value, String> {
    let revoke = matches!(intent, Intent::Revoke { .. });
    if !revoke {
        journal.current_at(session, now()).await?;
    }
    let (call, request) = journal.prepare(session, intent, origin, body).await?;
    // Session end may have begun while the durable append was suspended.
    if !journal.can_send(revoke) || !journal.authorize(&request, now()).await {
        return Ok(json!({"unresolved":true,"call":call}));
    }
    match transport.exchange(&request).await {
        Some(response) => {
            let actionable = revoke || journal.actionable(&request, now()).await;
            match journal.finish(call, &response, &request).await {
                Ok(finished) => {
                    // A mint can supply its identifier after the end step's first snapshot.
                    // Its revoke intent has already committed; finish it before releasing the
                    // mint guard that the end step awaits.
                    if let Some((revoke_call, revoke_request)) = finished.late_revoke
                        && let Some(response) = transport.exchange(&revoke_request).await
                    {
                        let _ = journal
                            .finish(revoke_call, &response, &revoke_request)
                            .await;
                    }
                    let mut report = finished.report;
                    if !actionable || (!revoke && !journal.actionable(&request, now()).await) {
                        report.as_object_mut().map(|v| v.remove("body"));
                        report
                            .as_object_mut()
                            .expect("report object")
                            .entry("refused")
                            .or_insert(json!("ordinary authority withheld"));
                    }
                    Ok(report)
                }
                Err(_) => Ok(
                    json!({"unresolved":true,"call":call,"why":"the response terminal could not be committed"}),
                ),
            }
        }
        None => Ok(json!({"unresolved":true,"call":call})),
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) async fn send(
    journal: &mut impl Journal,
    transport: &mut impl Transport,
    session: &str,
    intent: Intent,
    origin: &str,
    body: Value,
) -> Result<Value, String> {
    send_at(journal, transport, session, intent, origin, body, &|| 100).await
}

pub async fn infer(
    journal: &mut impl Journal,
    transport: &mut impl Transport,
    origin: &str,
    candidate: Option<&Candidate>,
    request: &Value,
    now: impl Fn() -> u64,
) -> Value {
    match run(journal, transport, origin, candidate, request, None, now).await {
        Ok(v) => v,
        Err(why) => json!({"refused":why}),
    }
}

/// Harness-owned tools share the same mint, route, redaction and journal driver.
pub async fn infer_tools(
    journal: &mut impl Journal,
    transport: &mut impl Transport,
    origin: &str,
    candidate: Option<&Candidate>,
    request: &Value,
    now: impl Fn() -> u64,
) -> Value {
    match run(
        journal,
        transport,
        origin,
        candidate,
        request,
        Some(crate::goals::definitions()),
        now,
    )
    .await
    {
        Ok(v) => v,
        Err(why) => json!({"refused":why}),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "shared inference admission and send driver"
)]
async fn run(
    journal: &mut impl Journal,
    transport: &mut impl Transport,
    origin: &str,
    candidate: Option<&Candidate>,
    request: &Value,
    tools: Option<Value>,
    now: impl Fn() -> u64,
) -> Result<Value, String> {
    if !valid_request(request) {
        return Err("request".into());
    }
    let candidate = candidate.ok_or("missing session-start selection")?;
    if candidate.slug.is_empty() || candidate.provider.is_empty() || candidate.maker.is_empty() {
        return Err("incomplete selection".into());
    }
    let session = journal
        .session(request["machine"].as_str().expect("validated"))
        .await?;
    let mint_guard = journal.mint_guard(&session).await;
    journal.current_at(&session, now()).await?;
    // A recorded mint attempt is checked before even a probe on subsequent requests.
    if !journal.has_key(&session).await? {
        let subject = journal.probe_authority(&session).await?;
        probe_with(journal, transport, origin, false, Some(subject)).await?;
        let mut read = send_at(
            journal,
            transport,
            &session,
            Intent::AccountRead {
                call: 0,
                session: session.clone(),
            },
            origin,
            Value::Null,
            &now,
        )
        .await?;
        if !read["status"]
            .as_u64()
            .is_some_and(|s| (200..300).contains(&s))
            || read.get("automatic_top_up") != Some(&Value::Bool(false))
        {
            read["refused"] = if read["unresolved"] == true {
                json!("no mint is sent without a recorded top-up-off read")
            } else {
                json!(format!(
                    "account read {}: automatic top-up must read off",
                    read["call"]
                ))
            };
            return Ok(read);
        }
        let (cap, expires) = journal.mint_bounds(&session, now()).await?;
        let mut minted = send_at(
            journal,
            transport,
            &session,
            Intent::Mint {
                call: 0,
                session: session.clone(),
                cap: cap.clone(),
                expires,
                evidence: None,
            },
            origin,
            json!({"cap":cap,"expires":expires}),
            &now,
        )
        .await?;
        if minted["finished"] == true && minted.get("refused").is_some() {
            return Ok(minted);
        }
        let has_key = match journal.has_key(&session).await {
            Ok(has_key) => has_key,
            Err(why) if minted.get("call").is_some() => {
                minted["refused"] = json!(why);
                return Ok(minted);
            }
            Err(why) => return Err(why),
        };
        if !has_key {
            return Err(format!(
                "mint {} supplied no session inference key",
                minted["call"]
            ));
        }
    }
    drop(mint_guard);
    let subject = journal.probe_authority(&session).await?;
    probe_with(journal, transport, origin, false, Some(subject)).await?;
    let mut body = compose(candidate, request);
    if let Some(tools) = tools {
        body["tools"] = tools;
    }
    send_at(
        journal,
        transport,
        &session,
        Intent::Completion {
            call: 0,
            session: session.clone(),
            key_id: String::new(),
            model: candidate.slug.clone(),
            requested_provider: candidate.provider.clone(),
            zdr: true,
        },
        origin,
        body,
        &now,
    )
    .await
}

/// Parse provider responses while preserving JSON number lexemes for spend. The scanner walks
/// the original JSON tokens rather than converting the amount through a floating-point value.
pub fn completion_terminal(call: u64, status: u16, intent: &Intent, body: &[u8]) -> Terminal {
    let mut t = Terminal::new(call, status);
    if let Intent::Completion {
        model,
        requested_provider,
        ..
    } = intent
    {
        t.model = Some(model.clone());
        t.requested_provider = Some(requested_provider.clone());
    }
    if let Ok(v) = serde_json::from_slice::<Value>(body) {
        t.reported_provider = v["provider"].as_str().map(str::to_owned);
        t.request_id = v["id"].as_str().map(str::to_owned);
        t.prompt_tokens = v["usage"]["prompt_tokens"].as_u64();
        t.completion_tokens = v["usage"]["completion_tokens"].as_u64();
        t.total_tokens = v["usage"]["total_tokens"].as_u64();
        t.spend = number_at(body, &["usage", "cost"]);
    }
    t
}

fn number_at(bytes: &[u8], path: &[&str]) -> Option<String> {
    fn ws(b: &[u8], i: &mut usize) {
        while b.get(*i).is_some_and(u8::is_ascii_whitespace) {
            *i += 1;
        }
    }
    fn string(b: &[u8], i: &mut usize) -> Option<String> {
        let start = *i;
        *i += 1;
        loop {
            match *b.get(*i)? {
                b'\\' => *i += 2,
                b'"' => {
                    *i += 1;
                    return serde_json::from_slice(&b[start..*i]).ok();
                }
                _ => *i += 1,
            }
        }
    }
    fn value(b: &[u8], i: &mut usize, path: &[&str]) -> Option<String> {
        ws(b, i);
        if b.get(*i) == Some(&b'{') {
            *i += 1;
            ws(b, i);
            while b.get(*i) != Some(&b'}') {
                let key = string(b, i)?;
                ws(b, i);
                if b.get(*i) != Some(&b':') {
                    return None;
                }
                *i += 1;
                let found = value(
                    b,
                    i,
                    if path.first() == Some(&key.as_str()) {
                        &path[1..]
                    } else {
                        &["\0"]
                    },
                );
                if found.is_some() {
                    return found;
                }
                ws(b, i);
                if b.get(*i) != Some(&b',') {
                    break;
                }
                *i += 1;
                ws(b, i);
            }
            *i += 1;
            None
        } else if b.get(*i) == Some(&b'[') {
            *i += 1;
            ws(b, i);
            while b.get(*i) != Some(&b']') {
                value(b, i, &["\0"]);
                ws(b, i);
                if b.get(*i) != Some(&b',') {
                    break;
                }
                *i += 1;
            }
            *i += 1;
            None
        } else if b.get(*i) == Some(&b'"') {
            string(b, i)?;
            None
        } else {
            let start = *i;
            while b.get(*i).is_some_and(|c| !b",]} \t\r\n".contains(c)) {
                *i += 1;
            }
            let raw = std::str::from_utf8(&b[start..*i]).ok()?;
            (path.is_empty() && serde_json::from_str::<Value>(raw).ok()?.is_number())
                .then(|| raw.into())
        }
    }
    value(bytes, &mut 0, path)
}
