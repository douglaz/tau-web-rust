//! Browser transport and the short writer acquisitions around the shared inference driver.
use crate::inference::{self, Candidate, Finished, Intent, Journal, Request, Response, Transport};
use crate::store::Local;
use crate::store::opfs::{Opfs, WebCrypto};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;
use tokio::sync::Mutex;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroizing;

type LocalStore = Rc<Mutex<Local<Opfs, WebCrypto>>>;
thread_local! {
    static ENDING: Cell<bool> = const { Cell::new(false) };
    static LOCKS: RefCell<BTreeMap<String, Arc<Mutex<()>>>> = const { RefCell::new(BTreeMap::new()) };
    static FETCHES: RefCell<Vec<web_sys::AbortController>> = const { RefCell::new(Vec::new()) };
    static AUTHORITY_CHANGED: Arc<tokio::sync::Notify> = Arc::default();
    #[cfg(feature = "tracer")]
    static ORIGIN: RefCell<Option<String>> = const { RefCell::new(None) };
}
pub(super) fn authority_notification() -> Arc<tokio::sync::Notify> {
    AUTHORITY_CHANGED.with(Arc::clone)
}
pub(crate) fn authority_changed() {
    AUTHORITY_CHANGED.with(|ready| ready.notify_waiters());
}
pub(crate) fn ending() -> bool {
    ENDING.get()
}

#[wasm_bindgen]
pub fn publication_generation() -> u64 {
    crate::lifecycle::owner().generation()
}

#[wasm_bindgen]
pub async fn protect_publication(generation: u64, session: String, report: String) -> String {
    publication(generation, session, report, false).await
}

#[wasm_bindgen]
pub async fn publish_report(generation: u64, session: String, report: String) {
    publication(generation, session, report, true).await;
}

async fn publication(generation: u64, session: String, report: String, post: bool) -> String {
    #[cfg(feature = "tracer")]
    crate::testonly::session_point("publication_writer").await;
    let local = crate::worker::local();
    let mut local = local.lock().await;
    if let Some(store) = local.store() {
        let _ = store.sessions();
        let _ = store.ensure_scan_references().await;
    }
    // A settled stopped loop can still report safe metadata after ordinary authority ends.
    // This separate channel carries no body, proposal, controls or actionable done.
    let history = (|| {
        let value = serde_json::from_str::<Value>(&report).ok()?;
        let outcome = &value["goal_outcome"];
        if session.is_empty() || outcome["session"] != session {
            return None;
        }
        let mut metadata = serde_json::Map::new();
        for field in ["call", "status", "finished", "refused", "unresolved"] {
            if let Some(value) = outcome["outcome"].get(field)
                && match field {
                    "call" | "status" => value.is_u64(),
                    "finished" | "unresolved" => value.is_boolean(),
                    "refused" => value.is_string(),
                    _ => false,
                }
            {
                metadata.insert(field.into(), value.clone());
            }
        }
        if metadata.is_empty() {
            return None;
        }
        metadata.insert("historical".into(), true.into());
        metadata.insert("actionable".into(), false.into());
        local
            .store()?
            .protect_output(&json!({"session":session,"outcome":metadata}))
            .ok()
    })();
    let result = (|| {
        let owner = crate::lifecycle::owner();
        owner.ordinary()?;
        if generation != owner.generation() {
            return Err("stale publication; reconciliation required".to_string());
        }
        let value = serde_json::from_str::<Value>(&report).map_err(|_| "publication JSON")?;
        if let Some(store) = local.store() {
            if !session.is_empty() {
                store
                    .check_session_authority(&session, crate::store::authority::current_pair(0))?;
            } else if value.get("goal_outcome").is_some() {
                return Err("publication has no affected session".into());
            }
            let safe = store.protect_output(&value)?;
            let mut current = local.report(None);
            if let Some(outcome) = safe.get("goal_outcome") {
                if outcome["session"] != session {
                    return Err("publication session differs".into());
                }
                current["goal_outcome"] = outcome.clone();
            }
            if let Some(error) = safe.get("error") {
                current["error"] = error.clone();
            }
            Ok(current)
        } else {
            Ok(local.report(value.get("error").and_then(Value::as_str)))
        }
    })();
    let mut carries_result = result.is_ok() && !session.is_empty();
    let mut value = result.unwrap_or_else(|why| local.report(Some(&why)));
    #[cfg(feature = "tracer")]
    crate::testonly::session_point("publication_prepared").await;
    let mut last_refusal = None;
    loop {
        if !carries_result && let Some(history) = &history {
            value["goal_history"] = history.clone();
        }
        let encoded = value.to_string();
        let message = if post {
            let mut message = value.clone();
            if let Some(object) = message.as_object_mut() {
                for (from, to) in [
                    ("state", "store_state"),
                    ("error", "store_error"),
                    ("reason", "store_reason"),
                ] {
                    if let Some(value) = object.remove(from) {
                        object.insert(to.into(), value);
                    }
                }
            }
            js_sys::JSON::parse(&json!({"store":message}).to_string()).ok()
        } else {
            None
        };
        // Encoding and scanning can consume lifetime too. Validate after all preparation,
        // under the same writer, immediately before the actual release.
        let final_check = (|| {
            if carries_result {
                let owner = crate::lifecycle::owner();
                owner.ordinary()?;
                if generation != owner.generation() {
                    return Err("stale publication".into());
                }
                local
                    .store()
                    .ok_or("locked")?
                    .check_session_authority(&session, crate::store::authority::current_pair(0))?;
            }
            if let Some(store) = local.store() {
                store.check_report_sessions(&value)?;
                if !store.has_live_sessions() {
                    store.clear_scan_working_copies();
                }
            }
            Ok::<_, String>(())
        })();
        if let Err(why) = final_check {
            carries_result = false;
            value = if last_refusal.as_ref() == Some(&why) {
                json!({"state":"unlocked","lifecycle_state":"reconciling","seed_backup_stage":"inactive","error":"Protected report authority unavailable."})
            } else {
                local.report(Some(&why))
            };
            last_refusal = Some(why);
            continue;
        }
        if let Some(message) = message {
            let worker: web_sys::DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
            let _ = worker.post_message(&message);
        }
        return encoded;
    }
}

#[wasm_bindgen]
pub async fn lifecycle_transition(event: String) -> String {
    let owner = crate::lifecycle::owner();
    match event.as_str() {
        "hidden" | "visible" => {}
        "freeze" => {
            owner.suspend();
            super::wait::stop_all();
            super::goals::suspend();
            FETCHES.with_borrow(|fetches| {
                for fetch in fetches {
                    fetch.abort();
                }
            });
        }
        "resume" => {}
        _ => return json!({"refused":"lifecycle event"}).to_string(),
    }
    let local = crate::worker::local();
    let mut local = local.lock().await;
    if let Some(store) = local.store() {
        if event == "freeze" {
            store.suspend_clocks();
        }
        if event == "resume"
            && let Err(why) = store.reload_scan_references().await
        {
            return local.report(Some(&why)).to_string();
        }
    }
    if event == "resume"
        && let Err(why) = owner.revalidated()
    {
        return local.report(Some(&why)).to_string();
    }
    authority_changed();
    local.report(None).to_string()
}
pub(super) fn origin() -> String {
    #[cfg(feature = "tracer")]
    {
        ORIGIN.with_borrow(|o| o.clone()).unwrap_or_default()
    }
    #[cfg(not(feature = "tracer"))]
    {
        env!("TAU_INFERENCE_ORIGIN").to_string()
    } // No selection exists, so this build refuses before any contact.
}
pub(super) fn candidate() -> Option<Candidate> {
    #[cfg(feature = "tracer")]
    {
        Some(crate::testonly::inference_candidate())
    }
    #[cfg(not(feature = "tracer"))]
    {
        None
    }
}

async fn transport_authorized(request: &Request, body: &str) -> bool {
    if !request.unchanged_body(body)
        || request
            .continuation
            .as_ref()
            .is_some_and(|c| c.check().is_err())
    {
        return false;
    }
    let local = crate::worker::local();
    let mut local = local.lock().await;
    let Some(store) = local.store() else {
        return false;
    };
    // Recheck after the queued writer acquisition, immediately before the actual fetch.
    if request
        .continuation
        .as_ref()
        .is_some_and(|c| c.check().is_err())
    {
        return false;
    }
    if let Some(session) = &request.runtime {
        if request
            .continuation
            .as_ref()
            .is_some_and(|c| c.is_clock_verification())
        {
            return matches!(
                (request.method, request.path),
                ("OPTIONS", "/") | ("GET", "/time")
            ) && store
                .clock_verification_authority(&session.identity)
                .is_ok_and(|(_, current)| Rc::ptr_eq(&current, session));
        }
        ((request.method == "OPTIONS" && request.path == "/" && request.body.is_empty())
            || request.scan_revision == store.scan_revision())
            && store.check_current_session(session).is_ok()
    } else {
        // Only the existing revocation path can send without ordinary session authority.
        (request.method == "OPTIONS" && request.path == "/" && request.body.is_empty())
            || (request.method == "POST"
                && request.path == "/revoke"
                && store.cleanup_transport_allowed(request.call))
    }
}

pub struct Fetch;
impl Transport for Fetch {
    async fn exchange(&mut self, r: &Request) -> Option<Response> {
        if r.origin.is_empty() {
            return None;
        }
        use web_sys::{
            RequestCache, RequestCredentials, RequestInit, RequestMode, RequestRedirect,
            ResponseType,
        };
        let init = RequestInit::new();
        let controller = web_sys::AbortController::new().ok()?;
        if r.path != "/revoke" {
            init.set_signal(Some(&controller.signal()));
        }
        init.set_method(r.method);
        init.set_redirect(RequestRedirect::Manual);
        init.set_credentials(RequestCredentials::Omit);
        init.set_cache(RequestCache::NoStore);
        init.set_mode(RequestMode::Cors);
        let headers = web_sys::Headers::new().ok()?;
        headers.set("Content-Type", "application/json").ok()?;
        if let Some(value) = &r.account {
            headers.set("X-Inference-Account", value).ok()?;
        }
        if let Some(value) = &r.authorization {
            headers.set("Authorization", value).ok()?;
        }
        init.set_headers(&headers);
        #[cfg_attr(not(feature = "tracer"), allow(unused_mut))]
        let mut body = Zeroizing::new(r.body.to_string());
        #[cfg(feature = "tracer")]
        if r.method == "POST"
            && r.path == "/completion"
            && let Some(append) = crate::testonly::transport_append()
        {
            body.push_str(&append);
        }
        if !body.is_empty() {
            init.set_body(&JsValue::from_str(&body));
        }
        let request =
            web_sys::Request::new_with_str_and_init(&format!("{}{}", r.origin, r.path), &init)
                .ok()?;
        let worker: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
        #[cfg(feature = "tracer")]
        if r.method == "POST" && r.path == "/completion" {
            crate::testonly::session_point("transport_send").await;
        }
        if !transport_authorized(r, &body).await {
            return None;
        }
        FETCHES.with_borrow_mut(|fetches| fetches.push(controller.clone()));
        let result = async {
            r.clock_sent
                .set(Some(crate::store::authority::current_pair(0)));
            let response: web_sys::Response = JsFuture::from(worker.fetch_with_request(&request))
                .await
                .ok()?
                .dyn_into()
                .ok()?;
            if matches!(
                response.type_(),
                ResponseType::Opaque | ResponseType::Opaqueredirect | ResponseType::Error
            ) || response.status() == 0
            {
                return None;
            }
            let body = JsFuture::from(response.array_buffer().ok()?).await.ok()?;
            r.clock_received
                .set(Some(crate::store::authority::current_pair(0)));
            Some(Response {
                status: response.status(),
                body: Zeroizing::new(js_sys::Uint8Array::new(&body).to_vec()),
            })
        }
        .await;
        FETCHES.with_borrow_mut(|fetches| fetches.retain(|f| f != &controller));
        result
    }
}

/// A narrow, journaled read: it cannot mint, complete or renew a session.
#[wasm_bindgen]
pub async fn verify_inference_clock(session: String) -> String {
    if ending() || !crate::lifecycle::owner().verification() || candidate().is_none() {
        return json!({"refused":"clock verification unavailable"}).to_string();
    }
    let mut journal = Writer(crate::worker::local());
    let result = async {
        let subject = crate::worker::local()
            .lock()
            .await
            .store()
            .ok_or("locked")?
            .clock_verification_authority(&session)?;
        inference::probe_with(&mut journal, &mut Fetch, &origin(), true, Some(subject)).await?;
        let (call, request) = journal
            .prepare(
                &session,
                Intent::ClockRead {
                    call: 0,
                    session: session.clone(),
                    sent: crate::store::authority::current_pair(0),
                },
                &origin(),
                Value::Null,
            )
            .await?;
        if ending() || !crate::lifecycle::owner().verification() {
            return Err("sessions ended".to_string());
        }
        let response = Fetch
            .exchange(&request)
            .await
            .ok_or("clock verification unresolved")?;
        Ok::<_, String>(journal.finish(call, &response, &request).await?.report)
    }
    .await;
    authority_changed();
    result
        .unwrap_or_else(|why| json!({"refused":why}))
        .to_string()
}

#[wasm_bindgen]
pub async fn continue_inference(call: u64) -> String {
    let local = crate::worker::local();
    let request = {
        let mut local = local.lock().await;
        let Some(store) = local.store() else {
            return json!({"refused":"locked"}).to_string();
        };
        match store.take_unsent_mint(call) {
            Ok(request) => request,
            Err(why) => return json!({"refused":why}).to_string(),
        }
    };
    let mut journal = Writer(local);
    if !journal.authorize(&request, 0).await {
        return json!({"unresolved":true,"call":call}).to_string();
    }
    let Some(response) = Fetch.exchange(&request).await else {
        return json!({"unresolved":true,"call":call}).to_string();
    };
    let actionable = journal.actionable(&request, 0).await;
    match journal.finish(call, &response, &request).await {
        Ok(mut finished) => {
            if let Some((revoke_call, revoke)) = finished.late_revoke
                && let Some(response) = Fetch.exchange(&revoke).await
            {
                let _ = journal.finish(revoke_call, &response, &revoke).await;
            }
            if !actionable {
                finished.report["refused"] = "ordinary authority withheld".into();
            }
            finished.report.to_string()
        }
        Err(why) => json!({"unresolved":true,"call":call,"why":why}).to_string(),
    }
}

pub(super) struct Writer(pub(super) LocalStore);
impl Journal for Writer {
    async fn probe_authority(
        &mut self,
        s: &str,
    ) -> Result<(crate::lifecycle::Continuation, Rc<crate::binding::Session>), String> {
        self.0
            .lock()
            .await
            .store()
            .ok_or("locked")?
            .probe_authority(s)
            .await
    }
    async fn current_at(&mut self, session: &str, now: u64) -> Result<(), String> {
        self.0
            .lock()
            .await
            .store()
            .ok_or("locked")?
            .current_at(session, now)
            .await
    }
    type MintGuard = tokio::sync::OwnedMutexGuard<()>;
    async fn mint_guard(&mut self, session: &str) -> Self::MintGuard {
        let lock = LOCKS.with_borrow_mut(|locks| locks.entry(session.into()).or_default().clone());
        lock.lock_owned().await
    }
    fn can_send(&self, revoke: bool) -> bool {
        revoke || (!ending() && crate::lifecycle::owner().ordinary().is_ok())
    }
    async fn mint_bounds(&mut self, session: &str, now: u64) -> Result<(String, u64), String> {
        self.0
            .lock()
            .await
            .store()
            .ok_or("locked")?
            .mint_bounds(session, now)
            .await
    }
    async fn authorize(&mut self, request: &Request, now: u64) -> bool {
        match self.0.lock().await.store() {
            Some(store) => store.authorize(request, now).await,
            None => false,
        }
    }
    async fn actionable(&mut self, request: &Request, now: u64) -> bool {
        match self.0.lock().await.store() {
            Some(store) => store.actionable(request, now).await,
            None => false,
        }
    }
    async fn session(&mut self, machine: &str) -> Result<String, String> {
        if ending() {
            return Err("sessions ended".into());
        }
        let mut local = self.0.lock().await;
        if let Some(why) = local.dispatch_refusal() {
            return Err(why.into());
        }
        local.store().ok_or("locked")?.session(machine).await
    }
    async fn has_key(&mut self, session: &str) -> Result<bool, String> {
        if ending() {
            return Err("sessions ended".into());
        }
        self.0
            .lock()
            .await
            .store()
            .ok_or("locked")?
            .has_key(session)
            .await
    }
    async fn prepare(
        &mut self,
        session: &str,
        intent: Intent,
        origin: &str,
        body: Value,
    ) -> Result<(u64, Request), String> {
        let revoke = matches!(intent, Intent::Revoke { .. });
        let mut local = self.0.lock().await;
        if ending() && !revoke {
            return Err("sessions ended".into());
        }
        local
            .store()
            .ok_or("locked")?
            .inference_prepare(session, intent, origin, body)
            .await
    }
    async fn finish(
        &mut self,
        call: u64,
        response: &Response,
        request: &Request,
    ) -> Result<Finished, String> {
        #[cfg(feature = "tracer")]
        if request.path == "/keys" {
            crate::testonly::session_point("mint_finish_writer").await;
        }
        #[cfg(feature = "tracer")]
        crate::testonly::session_point("finish_writer").await;
        self.0
            .lock()
            .await
            .store()
            .ok_or("locked")?
            .inference_finish(call, response, request)
            .await
    }
    async fn route(&mut self, origin: &str, chosen: bool) -> bool {
        #[cfg(feature = "tracer")]
        if !chosen {
            crate::testonly::session_point("route_writer").await;
        }
        match self.0.lock().await.store() {
            Some(s) => s.route(origin, chosen).await,
            None => false,
        }
    }
}

#[wasm_bindgen]
pub async fn inference_request(request: String) -> String {
    let continuation = crate::lifecycle::owner().continuation();
    let Ok(request) = serde_json::from_str::<Value>(&request) else {
        return json!({"refused":"request"}).to_string();
    };
    let mut result = inference::infer(
        &mut Writer(crate::worker::local()),
        &mut Fetch,
        &origin(),
        candidate().as_ref(),
        &request,
        || (js_sys::Date::now() / 1000.) as u64,
    )
    .await;
    #[cfg(feature = "tracer")]
    crate::testonly::session_point("response_writer").await;
    let local = crate::worker::local();
    let mut guard = local.lock().await;
    if let Some(store) = guard.store() {
        let _ = store.ensure_scan_references().await;
        result = store
            .protect_output(&result)
            .unwrap_or_else(|why| json!({"refused":why}));
    }
    let mut last_status_refusal = None;
    let mut status_fallback = false;
    loop {
        let mut status = guard.report(None);
        if status_fallback {
            status = json!({"state":"unlocked","lifecycle_state":"reconciling","seed_backup_stage":"inactive","error":"Protected report authority unavailable."});
        }
        let status_for_check = status.clone();
        if let Some(fields) = status.as_object_mut()
            && let Some(state) = fields.remove("state")
        {
            fields.insert("store_state".into(), state);
        }
        let message = js_sys::JSON::parse(&json!({"store":status}).to_string()).ok();
        let encoded = result.to_string();
        let current = continuation.as_ref().is_ok_and(|c| c.check().is_ok())
            && guard.store().is_some_and(|store| {
                result["call"]
                    .as_u64()
                    .is_none_or(|call| store.check_inference_release(call).is_ok())
            });
        if !current && (result.get("body").is_some() || result["historical"] != true) {
            if let Some(fields) = result.as_object_mut() {
                fields.remove("body");
                fields.insert("historical".into(), true.into());
                fields.insert("actionable".into(), false.into());
                fields.entry("refused").or_insert(json!(if ending() {
                    "sessions ended"
                } else {
                    "ordinary authority withheld"
                }));
            }
            continue;
        }
        if let Some(store) = guard.store() {
            if let Err(why) = store.check_report_sessions(&status_for_check) {
                status_fallback = last_status_refusal.as_ref() == Some(&why);
                last_status_refusal = Some(why);
                continue;
            }
            if !store.has_live_sessions() {
                store.clear_scan_working_copies();
            }
        }
        if let Some(message) = message {
            let worker: web_sys::DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
            let _ = worker.post_message(&message);
        }
        return encoded;
    }
}

async fn revoke(local: LocalStore, origin: String, key_id: String) {
    let mut journal = Writer(local);
    if inference::probe(&mut journal, &mut Fetch, &origin, true)
        .await
        .is_err()
    {
        return;
    }
    if let Ok((call, r)) = journal
        .prepare("", Intent::Revoke { call: 0, key_id }, &origin, Value::Null)
        .await
        && let Some(response) = Fetch.exchange(&r).await
    {
        let _ = journal.finish(call, &response, &r).await;
    }
}

pub(crate) fn schedule_revocation(key_id: String) {
    if candidate().is_some() {
        wasm_bindgen_futures::spawn_local(revoke(crate::worker::local(), origin(), key_id));
    }
}

/// A separate worker step, scheduled after the unlock or re-display report.
#[wasm_bindgen]
pub async fn sweep_inference() {
    let local = crate::worker::local();
    if candidate().is_none() {
        return;
    }
    let ids = local
        .lock()
        .await
        .store()
        .map(|s| s.inference_sweep())
        .unwrap_or_default();
    futures_util::future::join_all(
        ids.into_iter()
            .map(|id| revoke(local.clone(), origin(), id)),
    )
    .await;
}

#[wasm_bindgen]
pub async fn end_sessions() {
    ENDING.set(true);
    crate::lifecycle::owner().end();
    authority_changed();
    super::goals::end();
    super::wait::stop_all();
    let local = crate::worker::local();
    let ids = {
        let mut local = local.lock().await;
        if let Some(store) = local.store() {
            store.end_inference_sessions()
        } else {
            Vec::new()
        }
    };
    if candidate().is_none() {
        return;
    }
    let locks = LOCKS.with_borrow(|locks| locks.values().cloned().collect::<Vec<_>>());
    futures_util::future::join(
        futures_util::future::join_all(
            ids.into_iter()
                .map(|id| revoke(local.clone(), origin(), id)),
        ),
        futures_util::future::join_all(locks.into_iter().map(|lock| async move {
            // A mint finishing after the snapshot sends its own recorded revoke.
            drop(lock.lock_owned().await);
        })),
    )
    .await;
}

#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub async fn test_inference_origin(value: String) -> bool {
    let valid = value
        .strip_prefix("https://127.0.0.1:")
        .is_some_and(|p| p.parse::<u16>().is_ok_and(|p| p > 0));
    if !valid || crate::worker::local().lock().await.store().is_some() {
        return false;
    }
    ORIGIN.with_borrow_mut(|o| *o = Some(value));
    true
}

#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub async fn test_inference_account(input: js_sys::Uint8Array) -> bool {
    let credential = crate::credential::InferenceAccountCredential::new(input.to_vec());
    input.fill(0, 0, input.length());
    let local = crate::worker::local();
    let mut local = local.lock().await;
    if local.dispatch_refusal().is_some() {
        return false;
    }
    match local.store() {
        Some(s) => {
            s.set_inference_account(credential).await.is_ok()
                && s.synthetic_confirm_limits((js_sys::Date::now() / 1000.) as u64)
                    .is_ok()
        }
        None => false,
    }
}

#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub async fn test_cold_inference_route() {
    if let Some(store) = crate::worker::local().lock().await.store() {
        store.test_cold_inference_route();
    }
}

#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub async fn test_scan_fixture(name: String, value: js_sys::Uint8Array) -> Result<String, JsValue> {
    let secret = Zeroizing::new(value.to_vec());
    value.fill(0, 0, value.length());
    crate::worker::local()
        .lock()
        .await
        .store()
        .ok_or("locked")?
        .synthetic_scan_fixture(name, secret)
        .await
        .map_err(JsValue::from)
}

#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub async fn test_scan_reload(clear: bool) -> bool {
    let local = crate::worker::local();
    let mut local = local.lock().await;
    let Some(store) = local.store() else {
        return false;
    };
    if clear {
        store.clear_scan_working_copies();
        return true;
    }
    store.reload_scan_references().await.is_ok()
}

#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub async fn test_confirm_inference() -> bool {
    match crate::worker::local().lock().await.store() {
        Some(store) => store
            .synthetic_confirm_limits((js_sys::Date::now() / 1000.) as u64)
            .is_ok(),
        None => false,
    }
}

#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub fn test_clock_sample(monotonic: String, wall: String) -> bool {
    let pair = if monotonic.is_empty() && wall.is_empty() {
        None
    } else {
        let (Ok(monotonic), Ok(wall)) = (monotonic.parse(), wall.parse()) else {
            return false;
        };
        Some(crate::clock::Pair { monotonic, wall })
    };
    crate::store::authority::synthetic_clock_pair(pair);
    true
}

#[wasm_bindgen]
pub async fn withdraw_reinstall(
    approval: String,
    reset: String,
    entry: String,
) -> Result<(), JsValue> {
    let approval = approval
        .parse::<u64>()
        .map_err(|_| JsValue::from_str("invalid approval identity"))?;
    crate::worker::local()
        .lock()
        .await
        .store()
        .ok_or("locked")?
        .withdraw_reinstall(approval, &reset, &entry)
        .await
        .map_err(JsValue::from)
}

/// Synthetic dedicated adapter facts; consumer and dispatch boundary are the Store's.
#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub async fn test_reinstall(action: String, input: String) -> Result<String, JsValue> {
    use crate::store::reinstall::Approval;
    let value: Value =
        serde_json::from_str(&input).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let local = crate::worker::local();
    let mut local = local.lock().await;
    let store = local.store().ok_or("locked")?;
    let result: Result<Value,String> = async {
        let entry="fixture";
        let session=store.sessions().into_iter().find(|s| s["bound_set"]==json!([entry]))
            .and_then(|s|s["identity"].as_str().map(str::to_owned)).ok_or("fixture binding")?;
        let id=value["approval"].as_u64().unwrap_or(0);
        let reset=value["reset"].as_str().unwrap_or("synthetic-reset");
        match action.as_str() {
            "approve" => {
                store.synthetic_dedicated_path(entry)?;
                let modes=store.standing_modes(entry);
                let approval=Approval { reset: reset.into(), entry: entry.into(), session,
                    facts: crate::dispatch::Facts { arguments: std::collections::BTreeMap::from([("disks".into(),"synthetic-disk".into())]), cost_bound:0,bundle_commit:crate::SPEC_COMMIT.into() },modes };
                Ok(json!({"approval":store.approve_reinstall(approval).await?}))
            }
            "activate" => Ok(json!({"activation":store.dedicated_activation(&session,entry).await?})),
            "read" => Ok(json!({"read":store.dedicated_activation_read(&session,entry,value["activation"].as_u64().ok_or("activation")?,value["confirmed"]==true).await?})),
            "dispatch" => {
                let pending=store.dispatch_reinstall(id,reset,entry,value["read"].as_u64().ok_or("read")?).await?;
                store.dedicated_reset_current(&pending)?;
                Ok(json!({"dispatched":true,"call":pending.intent.call}))
            }
            _ => Err("unknown dedicated fixture action".into()),
        }
    }.await;
    Ok(result
        .unwrap_or_else(|why| json!({"refused":why}))
        .to_string())
}

/// Synthetic affected-session transitions for deterministic consumer races; no global end or
/// worker generation change. The ordinary evaluator applies the resulting terminal condition.
#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub async fn test_session_transition(session: String, transition: String) -> Result<(), JsValue> {
    let local = crate::worker::local();
    let mut local = local.lock().await;
    let store = local.store().ok_or("locked")?;
    store
        .synthetic_session_transition(&session, &transition)
        .map_err(JsValue::from)
}
