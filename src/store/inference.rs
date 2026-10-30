//! The inference projection and its append boundary. Network waits never enter this module.

use super::*;
use crate::credential::{InferenceAccountCredential, SessionInferenceKey};
use crate::inference::{
    Call, Finished, Intent as InferenceIntent, Journal as InferenceJournal, Request, Response,
    Terminal as InferenceTerminal,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(super) struct State {
    pub account: Option<InferenceAccountCredential>,
    calls: BTreeMap<u64, Call>,
    routes: BTreeSet<String>,
    pub(super) ended: bool,
    pub(super) recovered: BTreeSet<String>,
    pub(super) limits: std::cell::RefCell<BTreeMap<String, crate::inference_limits::Limits>>,
    pub(super) account_record: Option<u64>,
    transmitted: BTreeSet<u64>,
    unsent: BTreeMap<u64, Request>,
}

fn text_credential(bytes: &[u8]) -> Result<&str, String> {
    let s = std::str::from_utf8(bytes).map_err(|_| "credential is not header text")?;
    if s.is_empty() || !s.bytes().all(|c| (33..=126).contains(&c)) {
        return Err("credential is not header text".into());
    }
    Ok(s)
}

impl<S: Storage> Store<S> {
    /// A second credential is refused. The input's secret type clears it on every exit.
    pub async fn set_inference_account(
        &mut self,
        credential: InferenceAccountCredential,
    ) -> Result<(), String> {
        if self.inference.account.is_some() {
            return Err("inference account credential already stored".into());
        }
        if self.inference.ended {
            return Err("sessions ended".into());
        }
        let text = text_credential(&credential.0)?;
        let event = Event::InferenceAccount {
            credential: text.into(),
        };
        let number = self.commit(&event).await?;
        self.apply_inference(number, &event)
    }

    pub(super) fn apply_inference(&mut self, number: u64, event: &Event) -> Result<(), String> {
        match event {
            Event::InferenceAccount { credential } => {
                if self.inference.account.is_some() {
                    return Err("second inference account credential".into());
                }
                text_credential(credential.as_bytes())?;
                self.inference.account =
                    Some(InferenceAccountCredential(credential.as_bytes().to_vec()));
                self.inference.account_record = Some(number);
            }
            Event::InferenceIntent(intent) => {
                if intent.call() != number {
                    return Err("inference call differs from record number".into());
                }
                if self.inference.account.is_none() {
                    return Err("inference call has no account credential".into());
                }
                match intent {
                    InferenceIntent::ClockRead { session, .. } => {
                        self.exposure(session)?;
                    }
                    InferenceIntent::AccountRead { session, .. } => {
                        self.exposure(session)?;
                    }
                    InferenceIntent::Mint {
                        session,
                        cap,
                        expires,
                        evidence,
                        ..
                    } => {
                        self.exposure(session)?;
                        if !crate::inference_limits::Decimal::parse(cap).is_ok_and(|n| !n.is_zero())
                            || *expires == 0
                        {
                            return Err("invalid mint bounds".into());
                        }
                        if self.mint(session).is_some() {
                            return Err("second mint for session".into());
                        }
                        if !self.top_up_off(session) {
                            return Err("mint has no top-up-off read".into());
                        }
                        if let Some(evidence) = evidence {
                            evidence.validate(
                                session,
                                self.inference.account_record.ok_or("no account identity")?,
                                cap,
                                *expires,
                            )?;
                        }
                    }
                    InferenceIntent::Completion {
                        session,
                        key_id,
                        model,
                        requested_provider,
                        zdr,
                        ..
                    } => {
                        self.exposure(session)?;
                        if model.is_empty()
                            || requested_provider.is_empty()
                            || !zdr
                            || !self.mint(session).is_some_and(|c| {
                                c.terminal
                                    .as_ref()
                                    .is_some_and(|t| t.key_id.as_ref() == Some(key_id))
                            })
                        {
                            return Err("completion has no matching minted key or selection".into());
                        }
                    }
                    InferenceIntent::Revoke { key_id, .. } => {
                        if !self.inference.calls.values().any(|c| {
                            c.terminal
                                .as_ref()
                                .is_some_and(|t| t.key_id.as_ref() == Some(key_id))
                        }) || self.revoked(key_id)
                        {
                            return Err("revoke has no minted key or already has intent".into());
                        }
                    }
                }
                self.inference.calls.insert(
                    number,
                    Call {
                        intent: intent.clone(),
                        terminal: None,
                    },
                );
            }
            Event::InferenceTerminal(t) => {
                let c = self
                    .inference
                    .calls
                    .get(&t.call)
                    .ok_or("terminal has no earlier inference intent")?;
                if c.terminal.is_some() {
                    return Err("second inference terminal".into());
                }
                if !(100..=599).contains(&t.status) {
                    return Err("invalid inference status".into());
                }
                let mut permitted = InferenceTerminal::new(t.call, t.status);
                match &c.intent {
                    InferenceIntent::ClockRead { .. } => {
                        permitted.issuer_time = t.issuer_time;
                        permitted.clock_received = t.clock_received;
                        permitted.clock_sent = t.clock_sent;
                    }
                    InferenceIntent::AccountRead { .. } => {
                        permitted.automatic_top_up = t.automatic_top_up
                    }
                    InferenceIntent::Mint { cap, expires, .. } => {
                        if t.key_id.as_ref().is_some_and(String::is_empty) {
                            return Err("empty minted identifier".into());
                        }
                        // An incompatible issuer report is evidence, never usable authority.
                        let _ = (cap, expires);
                        permitted.key_id = t.key_id.clone();
                        permitted.cap = t.cap.clone();
                        permitted.expires = t.expires;
                        permitted.unit = t.unit.clone();
                    }
                    InferenceIntent::Completion {
                        model,
                        requested_provider,
                        ..
                    } => {
                        if t.model.as_ref() != Some(model)
                            || t.requested_provider.as_ref() != Some(requested_provider)
                        {
                            return Err("completion terminal differs from selection".into());
                        }
                        permitted = t.clone();
                        permitted.automatic_top_up = None;
                        permitted.key_id = None;
                        permitted.cap = None;
                        permitted.expires = None;
                        permitted.unit = None;
                        if t.spend.as_ref().is_some_and(|s| {
                            serde_json::from_str::<Value>(s)
                                .ok()
                                .is_none_or(|v| !v.is_number())
                        }) {
                            return Err("invalid spend number text".into());
                        }
                    }
                    InferenceIntent::Revoke { .. } => {}
                }
                if &permitted != t {
                    return Err("terminal has fields for another inference kind".into());
                }
                let intent = c.intent.clone();
                self.inference
                    .calls
                    .get_mut(&t.call)
                    .expect("checked")
                    .terminal = Some(t.clone());
                if let InferenceIntent::Completion { session, .. } = &intent
                    && let Some(limits) = self.inference.limits.borrow_mut().get_mut(session)
                {
                    if let Some(spend) = &t.spend {
                        match crate::inference_limits::Decimal::parse(spend) {
                            Ok(spend) => limits.spent.add(&spend),
                            Err(_) => limits.ended = Some("incompatible issuer usage".into()),
                        }
                    }
                    use crate::inference::ChargeRefusal;
                    match t.charge_refusal {
                        Some(ChargeRefusal::KeyCapExhausted) => {
                            limits.ended = Some("session cap exhausted".into())
                        }
                        Some(ChargeRefusal::KeyExpired) => {
                            limits.ended = Some("session expired".into())
                        }
                        _ => {}
                    }
                }
            }
            _ => return Err("not an inference record".into()),
        }
        Ok(())
    }

    fn exposure(&self, session: &str) -> Result<(), String> {
        if self.exposure_ledger.iter().any(|e| e.session == session) {
            Ok(())
        } else {
            Err("inference intent names no earlier exposure".into())
        }
    }
    #[cfg(all(feature = "tracer", target_arch = "wasm32"))]
    pub(crate) fn test_cold_inference_route(&mut self) {
        self.inference.routes.clear();
    }

    fn top_up_off(&self, session: &str) -> bool {
        self.inference.calls.values().rev()
            .find(|c| matches!(&c.intent, InferenceIntent::AccountRead { session: s, .. } if s == session))
            .and_then(|c| c.terminal.as_ref())
            .is_some_and(|t| (200..300).contains(&t.status) && t.automatic_top_up == Some(false))
    }
    fn mint(&self, session: &str) -> Option<&Call> {
        self.inference
            .calls
            .values()
            .find(|c| matches!(&c.intent, InferenceIntent::Mint { session:s, .. } if s == session))
    }
    pub(super) fn mint_attempted(&self, session: &str) -> bool {
        self.mint(session).is_some()
    }
    #[cfg(target_arch = "wasm32")]
    pub(super) fn session_revocation(&self, session: &str) -> Option<String> {
        let id = self.mint(session)?.terminal.as_ref()?.key_id.as_ref()?;
        (!self.revoked(id)).then(|| id.clone())
    }
    fn revoked(&self, key_id: &str) -> bool {
        self.inference
            .calls
            .values()
            .any(|c| matches!(&c.intent, InferenceIntent::Revoke { key_id:k, .. } if k == key_id))
    }
    fn live(&self, session: &str) -> Result<&Rc<Session>, String> {
        if self.inference.ended {
            return Err("sessions ended".into());
        }
        self.sessions
            .iter()
            .find(|s| s.identity == session && !s.ended.get())
            .ok_or("no live session".into())
    }

    pub(super) fn inference_choice_used(&self, choice: &str) -> bool {
        self.inference.calls.values().any(|c| matches!(&c.intent,
            InferenceIntent::Mint { evidence: Some(e), .. } if e.confirmed.choice_generation == choice))
    }

    pub fn inference_calls(&self) -> Value {
        self.inference.calls.iter().map(|(id,c)| {
            let mut v = json!({"call":id,"kind":c.intent.kind(),"intent":c.intent,"state":if c.terminal.is_some() {"finished"} else {"unresolved"},"terminal":c.terminal});
            if let InferenceIntent::Completion { session, key_id, .. } = &c.intent {
                if c.terminal.is_none() { v["unaccounted_spend"] = json!({"key_id":key_id,"cap":self.mint(session).and_then(|m| m.terminal.as_ref()).and_then(|t| t.cap.as_ref())}); }
            } else if matches!(c.intent, InferenceIntent::Mint { .. }) && c.terminal.is_none() {
                v["notice"] = "No revoke can name that key; only its expiry bounds it.".into();
            }
            v
        }).collect::<Vec<_>>().into()
    }
    pub fn unaccounted_spend(&self, session: &str) -> Value {
        let count = self.inference.calls.values().filter(|c| c.terminal.is_none() && matches!(&c.intent, InferenceIntent::Completion { session:s, .. } if s == session)).count();
        json!({"count":count,"cap":self.mint(session).and_then(|c| c.terminal.as_ref()).and_then(|t| t.cap.as_ref())})
    }

    pub fn check_inference_release(&self, call: u64) -> Result<(), String> {
        let call = self
            .inference
            .calls
            .get(&call)
            .ok_or("no original inference call")?;
        let session = match &call.intent {
            InferenceIntent::AccountRead { session, .. }
            | InferenceIntent::Mint { session, .. }
            | InferenceIntent::Completion { session, .. }
            | InferenceIntent::ClockRead { session, .. } => session,
            InferenceIntent::Revoke { .. } => {
                return Err("cleanup evidence supplies no ordinary authority".into());
            }
        };
        self.check_session_authority(session, self.session_pair(session))
    }
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn cleanup_transport_allowed(&self, call: u64) -> bool {
        self.inference.calls.get(&call).is_some_and(|c| {
            matches!(c.intent, InferenceIntent::Revoke { .. }) && c.terminal.is_none()
        })
    }

    /// Stops dispatch before any await. Dropping the row-2 holdings zeroizes their buffers.
    pub fn end_inference_sessions(&mut self) -> Vec<String> {
        self.inference.ended = true;
        self.clear_scan_working_copies();
        self.inference.unsent.clear();
        self.pending_requirements.clear();
        for s in &self.sessions {
            s.ended.set(true);
            s.given.borrow_mut().clear();
        }
        self.sessions.clear();
        self.inference_revocations()
    }

    /// Replay supplies identifiers, never session inference keys. Existing revoke intents are
    /// deliberately skipped even if their response never arrived.
    pub fn inference_sweep(&self) -> Vec<String> {
        self.inference_revocations()
            .into_iter()
            .filter(|id| self.inference.recovered.contains(id))
            .collect()
    }

    pub(super) fn inference_revocations(&self) -> Vec<String> {
        self.inference
            .calls
            .values()
            .filter_map(|c| {
                let id = c.terminal.as_ref()?.key_id.as_ref()?;
                (!self.revoked(id)).then(|| id.clone())
            })
            .collect()
    }

    pub async fn inference_prepare(
        &mut self,
        session: &str,
        mut intent: InferenceIntent,
        origin: &str,
        body: Value,
    ) -> Result<(u64, Request), String> {
        let call = self.next;
        let is_revoke = matches!(intent, InferenceIntent::Revoke { .. });
        let verification = matches!(intent, InferenceIntent::ClockRead { .. });
        if verification {
            if !self.authority.verification() {
                return Err("sessions ended".into());
            }
            self.live(session)?;
            if !self.inference.limits.borrow().contains_key(session) {
                return Err("no clock profile".into());
            }
        } else if !is_revoke {
            self.check_session_authority(session, self.session_pair(session))?;
            self.live(session)?;
            if self.pending_requirements.contains_key(session) {
                return Err("proposal approval pending".into());
            }
        }
        let account = self
            .inference
            .account
            .as_ref()
            .ok_or("no inference account credential")?;
        let mut request = Request {
            runtime: if is_revoke {
                None
            } else {
                Some(self.live(session)?.clone())
            },
            clock_sent: std::cell::Cell::new(None),
            clock_received: std::cell::Cell::new(None),
            approved_body: Address([0; 32]),
            call,
            session: session.into(),
            continuation: if is_revoke {
                None
            } else if verification {
                Some(self.authority.clock_continuation()?)
            } else {
                Some(self.authority.continuation()?)
            },
            scan_revision: self.scan_revision(),
            method: "POST",
            origin: origin.into(),
            path: "/completion",
            account: None,
            authorization: None,
            body: Zeroizing::new(if body.is_null() {
                String::new()
            } else {
                body.to_string()
            }),
        };
        match &mut intent {
            InferenceIntent::ClockRead {
                call: n,
                session: s,
                sent,
            } => {
                if s != session {
                    return Err("wrong clock session".into());
                }
                *n = call;
                *sent = self.session_pair(session);
                request.method = "GET";
                request.path = "/time";
            }
            InferenceIntent::Completion {
                call: n,
                session: s,
                key_id,
                model,
                requested_provider,
                zdr,
            } => {
                *n = call;
                if model.is_empty() || requested_provider.is_empty() || !*zdr {
                    return Err("incomplete inference selection".into());
                }
                if s != session {
                    return Err("wrong inference session".into());
                }
                self.dispatch
                    .check_operation(
                        &crate::dispatch::Resource::Inference,
                        crate::dispatch::Operation::Inference,
                        crate::dispatch::Requester::Session,
                    )
                    .map_err(|_| "inference admission refused")?;
                *key_id = self
                    .mint(session)
                    .and_then(|c| c.terminal.as_ref())
                    .and_then(|t| t.key_id.clone())
                    .ok_or("no minted identifier")?;
                let holdings = self.live(session)?.given.borrow();
                let key = holdings
                    .iter()
                    .find_map(|h| h.credential.value().downcast_ref::<SessionInferenceKey>())
                    .ok_or("no session inference key")?;
                request.authorization = Some(Zeroizing::new(format!(
                    "Bearer {}",
                    text_credential(&key.0)?
                )));
            }
            InferenceIntent::AccountRead {
                call: n,
                session: s,
            } => {
                if s != session {
                    return Err("wrong inference session".into());
                }
                *n = call;
                request.method = "GET";
                request.path = "/account";
            }
            InferenceIntent::Mint {
                call: n,
                session: s,
                cap,
                expires,
                evidence,
            } => {
                if s != session
                    || *expires == 0
                    || !crate::inference_limits::Decimal::parse(cap).is_ok_and(|n| !n.is_zero())
                {
                    return Err("invalid mint request".into());
                }
                if !self.top_up_off(session) {
                    return Err("mint has no top-up-off read".into());
                }
                let pair = self.session_pair(session);
                let mut limits = self.inference.limits.borrow_mut();
                let limits = limits.get_mut(session).ok_or("missing confirmed limits")?;
                // A direct caller of the shared seam fixes the same origin once, after the
                // recorded top-up-off read, just as the driver does.
                if limits.origin.is_none() {
                    limits.authorize_mint(pair)?;
                }
                if limits.cap() != *cap || limits.expires != Some(*expires) {
                    return Err("mint differs from original confirmed limits".into());
                }
                *evidence = limits.evidence.clone();
                request.body = Zeroizing::new(
                    json!({"cap":cap,"expires":expires,"unit":limits.confirmed.unit}).to_string(),
                );
                *n = call;
                request.path = "/keys";
                if self.mint(session).is_some() {
                    return Err("one mint attempt per session".into());
                }
            }
            InferenceIntent::Revoke { call: n, key_id } => {
                *n = call;
                request.path = "/revoke";
                request.body = Zeroizing::new(json!({"key_id":key_id}).to_string());
            }
        }
        if !matches!(
            intent,
            InferenceIntent::Completion { .. } | InferenceIntent::ClockRead { .. }
        ) {
            request.account = Some(Zeroizing::new(text_credential(&account.0)?.into()));
        }
        if matches!(intent, InferenceIntent::Completion { .. }) {
            let safe = crate::redaction::Redacted::for_store(self, request.body.as_bytes(), &[])?;
            request.body = Zeroizing::new(
                String::from_utf8(safe.as_bytes().to_vec())
                    .map_err(|_| "request boundary returned non-text")?,
            );
        }
        let event = Event::InferenceIntent(intent);
        request.bind_bytes();
        // Validate without changing state; apply only after commit. The projection is cheap and
        // contains metadata only, except for the independently held account credential.
        self.validate_new_inference(&event)?;
        self.commit(&event).await?;
        self.apply_inference(call, &event)?;
        if matches!(event, Event::InferenceIntent(InferenceIntent::Mint { .. })) {
            self.inference
                .unsent
                .insert(call, request.retained_unsent());
            #[cfg(all(feature = "tracer", target_arch = "wasm32"))]
            crate::testonly::session_point("mint_intent").await;
        }
        Ok((call, request))
    }

    /// Only the same retained worker may release this demonstrably never-transmitted intent.
    /// Taking it neither appends a new intent nor resets the consumed mint slot.
    pub fn take_unsent_mint(&mut self, call: u64) -> Result<Request, String> {
        let recorded = self
            .inference
            .calls
            .get(&call)
            .ok_or("no original intent")?;
        let InferenceIntent::Mint {
            session,
            cap,
            expires,
            ..
        } = &recorded.intent
        else {
            return Err("not a retained mint".into());
        };
        if recorded.terminal.is_some() || self.inference.transmitted.contains(&call) {
            return Err("mint may already have been transmitted".into());
        }
        self.check_session_authority(session, self.session_pair(session))?;
        if !self
            .inference
            .limits
            .borrow()
            .get(session)
            .is_some_and(|l| l.expires == Some(*expires) && l.cap() == *cap)
        {
            return Err("original mint limits differ".into());
        }
        let mut request = self
            .inference
            .unsent
            .remove(&call)
            .ok_or("no identifiable safe unsent continuation")?;
        request.continuation = Some(self.authority.continuation()?);
        request.scan_revision = self.scan_revision();
        Ok(request)
    }

    fn validate_new_inference(&self, event: &Event) -> Result<(), String> {
        if let Event::InferenceIntent(InferenceIntent::Revoke { key_id, .. }) = event
            && (self.revoked(key_id) || !self.inference_revocations().contains(key_id))
        {
            return Err("key has no revocation owed".into());
        }
        Ok(())
    }

    pub async fn inference_finish(
        &mut self,
        call: u64,
        response: &Response,
        request: &Request,
    ) -> Result<Finished, String> {
        // Terminal/accounting cleanup remains entitled after ordinary session end. Reload only
        // the prescribed material, and clear these temporary copies when no session owns them.
        let _ = self.ensure_scan_references().await;
        let result = self
            .inference_finish_protected(call, response, request)
            .await;
        if self.sessions.iter().all(|s| s.ended.get()) {
            self.clear_scan_working_copies();
        }
        result
    }

    async fn inference_finish_protected(
        &mut self,
        call: u64,
        response: &Response,
        request: &Request,
    ) -> Result<Finished, String> {
        if !(100..=599).contains(&response.status) {
            return Err("unreadable inference status".into());
        }
        let intent = self
            .inference
            .calls
            .get(&call)
            .ok_or("no inference call")?
            .intent
            .clone();
        if self.inference.calls[&call].terminal.is_some() {
            return Err("second inference terminal".into());
        }
        let mut v: Value = if matches!(intent, InferenceIntent::Completion { .. }) {
            // Scan the original values the loop's lossy text decoder can recover, before
            // the byte boundary replaces any credential with executable marker text.
            serde_json::from_str(&String::from_utf8_lossy(&response.body)).unwrap_or(Value::Null)
        } else {
            serde_json::from_slice(&response.body).unwrap_or(Value::Null)
        };
        let mut credentials: Vec<&[u8]> = request
            .account
            .as_deref()
            .map(|s| s.as_bytes())
            .into_iter()
            .chain(
                request
                    .authorization
                    .as_deref()
                    .and_then(|s| s.strip_prefix("Bearer "))
                    .map(str::as_bytes),
            )
            .collect();
        if matches!(intent, InferenceIntent::Mint { .. })
            && let Some(key) = v["key"].as_str()
        {
            credentials.push(key.as_bytes());
        }
        let boundary =
            |bytes: &[u8]| crate::redaction::Redacted::for_inference(self, bytes, &credentials);
        let redacted = boundary(&response.body);
        // Inspect decoded action values with the same holdings and transient request keys.
        // Refuse the whole call rather than turn a redacted command into executable text.
        let tool_refused = matches!(intent, InferenceIntent::Completion { .. })
            && [
                "/choices/0/message/tool_calls",
                "/choices/0/message/proposal",
            ]
            .iter()
            .any(|path| {
                v.pointer(path).is_some_and(|value| {
                    !crate::redaction::Redacted::inference_value_is_safe(self, value, &credentials)
                }) || redacted.as_ref().is_ok_and(|safe| {
                    serde_json::from_str::<Value>(&String::from_utf8_lossy(safe.as_bytes()))
                        .ok()
                        .and_then(|body| body.pointer(path).cloned())
                        .as_ref()
                        != v.pointer(path)
                })
            });
        let mut t = InferenceTerminal::new(call, response.status);
        let mut key = None;
        match &intent {
            InferenceIntent::ClockRead { .. } => {
                if (200..300).contains(&response.status) {
                    t.issuer_time = v["issuer_time"]
                        .as_u64()
                        .filter(|n| (1..=crate::clock::MAX_UTC).contains(n));
                    t.clock_received = request.clock_received.get();
                    t.clock_sent = request.clock_sent.get();
                }
            }
            InferenceIntent::AccountRead { .. } => {
                t.automatic_top_up = v["automatic_top_up"].as_bool()
            }
            InferenceIntent::Mint {
                cap,
                expires,
                session,
                ..
            } => {
                if (200..300).contains(&response.status)
                    && v["key_id"].as_str().is_some_and(|s| !s.is_empty())
                    && v["key"].as_str().is_none_or(|key| {
                        key.is_empty() || !v["key_id"].as_str().expect("checked").contains(key)
                    })
                    && self.inference.account.as_ref().is_none_or(|a| {
                        !v["key_id"]
                            .as_str()
                            .expect("checked")
                            .as_bytes()
                            .windows(a.0.len())
                            .any(|w| w == a.0)
                    })
                {
                    t.key_id = v["key_id"].as_str().map(str::to_owned);
                    t.cap = v["cap"].as_str().map(str::to_owned);
                    t.expires = v["expires"].as_u64();
                    t.unit = v["unit"].as_str().map(str::to_owned);
                    if self.live(session).is_ok()
                        && t.cap.as_ref() == Some(cap)
                        && t.expires == Some(*expires)
                        && t.unit.as_deref() == Some("account units")
                        && v["key"]
                            .as_str()
                            .is_some_and(|s| text_credential(s.as_bytes()).is_ok())
                    {
                        key = Some(SessionInferenceKey(
                            v["key"].as_str().expect("checked").as_bytes().to_vec(),
                        ));
                    }
                }
            }
            InferenceIntent::Completion { .. } => {
                t = crate::inference::completion_terminal(
                    call,
                    response.status,
                    &intent,
                    &response.body,
                );
                t.charge_refusal = match v["error"]["code"].as_str() {
                    Some("account_balance") => {
                        Some(crate::inference::ChargeRefusal::AccountBalance)
                    }
                    Some("key_cap_exhausted") => {
                        Some(crate::inference::ChargeRefusal::KeyCapExhausted)
                    }
                    Some("key_expired") => Some(crate::inference::ChargeRefusal::KeyExpired),
                    _ => None,
                };
            }
            InferenceIntent::Revoke { .. } => {}
        }
        // Scan decoded response values too: a JSON escape may hide an exact credential
        // from the raw-byte boundary. Withhold values the marker cannot safely replace.
        let safe_value = |value: &Value| -> Option<Value> {
            let text = value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string());
            let safe = boundary(text.as_bytes()).ok()?;
            if value.is_string() {
                Some(String::from_utf8(safe.as_bytes().to_vec()).ok()?.into())
            } else {
                serde_json::from_slice(safe.as_bytes()).ok()
            }
        };
        let mut metadata = serde_json::to_value(&t).expect("terminal is serializable");
        // Empty decoded text conveys no metadata, for every terminal kind.
        metadata
            .as_object_mut()
            .expect("terminal object")
            .retain(|_, value| value.as_str() != Some(""));
        for field in [
            "automatic_top_up",
            "key_id",
            "cap",
            "unit",
            "expires",
            "issuer_time",
            "reported_provider",
            "request_id",
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "spend",
        ] {
            if let Some(value) = metadata.get(field) {
                let safe = safe_value(value);
                // A substituted identifier cannot name the key to revoke.
                if safe
                    .as_ref()
                    .is_none_or(|safe| field == "key_id" && safe != value)
                {
                    metadata
                        .as_object_mut()
                        .expect("terminal object")
                        .remove(field);
                } else {
                    metadata[field] = safe.expect("checked");
                }
            }
        }
        t = serde_json::from_value(metadata).expect("scanned terminal types");
        if t.spend.as_ref().is_some_and(|s| {
            serde_json::from_str::<Value>(s)
                .ok()
                .is_none_or(|v| !v.is_number())
        }) {
            t.spend = None;
        }
        if let InferenceIntent::Mint { cap, expires, .. } = &intent {
            if t.key_id.is_none() {
                t.cap = None;
                t.expires = None;
            }
            if t.key_id.is_none()
                || t.cap.as_ref() != Some(cap)
                || t.expires != Some(*expires)
                || t.unit.as_deref() != Some("account units")
            {
                key = None;
            }
        }
        fn clear(value: &mut Value) {
            match value {
                Value::String(s) => s.zeroize(),
                Value::Array(a) => a.iter_mut().for_each(clear),
                Value::Object(o) => o.values_mut().for_each(clear),
                _ => {}
            }
        }
        clear(&mut v);
        let event = Event::InferenceTerminal(t.clone());
        let number = self.commit(&event).await?;
        let mut report = json!({"call":call,"status":response.status,"finished":true});
        if self.inference.ended && !matches!(intent, InferenceIntent::Revoke { .. }) {
            report["refused"] = "sessions ended".into();
        }
        match redacted {
            Err(why) => report["refused"] = format!("response redaction boundary: {why}").into(),
            Ok(safe) if matches!(intent, InferenceIntent::Completion { .. }) => {
                if self.inference.ended {
                    report["refused"] = "sessions ended".into();
                } else if tool_refused {
                    report["tool_refusal"] = "tool credential boundary".into();
                } else {
                    report["body"] = String::from_utf8_lossy(safe.as_bytes()).into_owned().into();
                }
            }
            Ok(_) => {}
        }
        if let Some(top_up) = t.automatic_top_up {
            report["automatic_top_up"] = top_up.into();
        }
        // The terminal is durable. Later failures are refusals of follow-up work.
        let follow_up: Result<_, String> = async {
            self.apply_inference(number, &event)?;
            if let InferenceIntent::Mint { session, cap, expires, .. } = &intent
                && (t.cap.as_ref() != Some(cap) || t.expires != Some(*expires) || t.unit.as_deref() != Some("account units"))
                && let Some(limits) = self.inference.limits.borrow_mut().get_mut(session) {
                limits.ended = Some("incompatible or missing issuer acceptance".into());
            }
            if let InferenceIntent::Mint { session, .. } | InferenceIntent::Completion { session, .. } = &intent
                && let Err(why) = self.check_session_authority(session, self.session_pair(session)) {
                report.as_object_mut().expect("report").remove("body");
                report["refused"] = why.into();
            }
            if let InferenceIntent::ClockRead { session, .. } = &intent {
                request.continuation.as_ref().ok_or("missing verification continuation")?.check()?;
                if !self.authority.verification() || self.live(session).is_err() { return Err("sessions ended".into()); }
                let timestamp = t.issuer_time.ok_or("missing authenticated issuer time")?;
                let received = t.clock_received.ok_or("missing measured time response")?;
                let sent = t.clock_sent.ok_or("missing measured time request")?;
                let mut limits = self.inference.limits.borrow_mut();
                let limits = limits.get_mut(session).ok_or("no clock profile")?;
                if limits.confirmed.profile != "inference-profile-fixture-v1" { return Err("unsupported clock profile".into()); }
                let rate = crate::clock::Rate { numerator: 1, denominator: 1 };
                limits.clock.repair(crate::clock::Observation { sent, received,
                    earliest: timestamp, latest: timestamp, minimum: rate, maximum: rate })?;
                limits.check(received)?;
            }
            if let (Some(key), InferenceIntent::Mint { session, .. }) = (key, &intent)
                && self.authority.verification()
                && self.live(session).is_ok_and(|live| request.runtime.as_ref().is_some_and(|original| Rc::ptr_eq(live, original))) {
                // Custody of this original lower-tier key survives suspension. Every use and
                // result release still needs fresh authority; actual end forbids retention.
                let session = self.live(session)?;
                if session.given.borrow().iter().any(|h| h.credential.row() == 2) {
                    return Err("second session inference key".into());
                }
                session.given.borrow_mut().push(crate::binding::Holding {
                    machine: String::new(),
                    credential: Box::new(key),
                });
            }
            if let InferenceIntent::Mint { session, .. } = &intent
                && (self.inference.ended || self.live(session).is_err())
                && let Some(key_id) = t.key_id
            {
                let revoke = self
                    .inference_prepare(
                        "",
                        InferenceIntent::Revoke { call: 0, key_id },
                        &request.origin,
                        Value::Null,
                    )
                    .await
                    .map_err(|why| format!(
                        "no revoke was recorded; the key is left to the next unlock's sweep or its expiry: {why}"
                    ))?;
                Ok(Some(revoke))
            } else {
                Ok(None)
            }
        }
        .await;
        let late_revoke = match follow_up {
            Ok(revoke) => revoke,
            Err(why) => {
                report["refused"] = why.into();
                None
            }
        };
        Ok(Finished {
            report,
            late_revoke,
        })
    }
}

impl<S: Storage> InferenceJournal for Store<S> {
    async fn probe_authority(
        &mut self,
        session: &str,
    ) -> Result<(crate::lifecycle::Continuation, Rc<Session>), String> {
        self.check_session_authority(session, self.session_pair(session))?;
        Ok((self.authority.continuation()?, self.live(session)?.clone()))
    }
    async fn current_at(&mut self, session: &str, now: u64) -> Result<(), String> {
        self.check_session_authority(session, super::authority::current_pair(now))
    }
    type MintGuard = ();
    async fn mint_guard(&mut self, _: &str) {}
    fn can_send(&self, revoke: bool) -> bool {
        revoke || (!self.inference.ended && self.authority.ordinary().is_ok())
    }
    async fn mint_bounds(&mut self, session: &str, now: u64) -> Result<(String, u64), String> {
        self.check_session_authority(session, super::authority::current_pair(now))?;
        if !self.top_up_off(session) {
            return Err("mint has no top-up-off read".into());
        }
        self.inference
            .limits
            .borrow_mut()
            .get_mut(session)
            .ok_or("missing confirmed limits")?
            .authorize_mint(super::authority::current_pair(now))
    }
    async fn authorize(&mut self, request: &Request, now: u64) -> bool {
        let Some(call) = self.inference.calls.get(&request.call) else {
            return false;
        };
        if matches!(call.intent, InferenceIntent::Revoke { .. }) {
            return self.inference.transmitted.insert(request.call);
        }
        if !self.actionable(request, now).await {
            return false;
        }
        let first = self.inference.transmitted.insert(request.call);
        if first {
            self.inference.unsent.remove(&request.call);
        }
        first
    }
    async fn actionable(&mut self, request: &Request, now: u64) -> bool {
        if !request.unchanged()
            || request
                .continuation
                .as_ref()
                .is_none_or(|c| c.check().is_err())
            || request.scan_revision != self.scan_revision()
            || self
                .check_session_authority(&request.session, super::authority::current_pair(now))
                .is_err()
        {
            return false;
        }
        true
    }

    async fn session(&mut self, machine: &str) -> Result<String, String> {
        if self.inference.ended {
            return Err("sessions ended".into());
        }
        self.sessions
            .iter()
            .find(|s| !s.ended.get() && s.bound_set.iter().any(|m| m == machine))
            .map(|s| s.identity.clone())
            .ok_or("no live bound session".into())
    }
    async fn has_key(&mut self, session: &str) -> Result<bool, String> {
        self.check_session_authority(session, self.session_pair(session))?;
        let live = self.live(session)?;
        if live.given.borrow().iter().any(|h| h.credential.row() == 2) {
            return Ok(true);
        }
        if let Some(mint) = self.mint(session) {
            return Err(format!(
                "mint {}: no further mint attempt for this session",
                mint.intent.call()
            ));
        }
        Ok(false)
    }
    async fn prepare(
        &mut self,
        session: &str,
        intent: InferenceIntent,
        origin: &str,
        body: Value,
    ) -> Result<(u64, Request), String> {
        self.inference_prepare(session, intent, origin, body).await
    }
    async fn finish(
        &mut self,
        call: u64,
        response: &Response,
        request: &Request,
    ) -> Result<Finished, String> {
        self.inference_finish(call, response, request).await
    }
    async fn route(&mut self, origin: &str, chosen: bool) -> bool {
        if chosen {
            self.inference.routes.insert(origin.into());
        }
        self.inference.routes.contains(origin)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod tests;
