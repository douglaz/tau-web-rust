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
    #[cfg(feature = "tracer")]
    static ORIGIN: RefCell<Option<String>> = const { RefCell::new(None) };
}
pub(crate) fn ending() -> bool {
    ENDING.get()
}
fn origin() -> String {
    #[cfg(feature = "tracer")]
    {
        ORIGIN.with_borrow(|o| o.clone()).unwrap_or_default()
    }
    #[cfg(not(feature = "tracer"))]
    {
        env!("TAU_INFERENCE_ORIGIN").to_string()
    } // No selection exists, so this build refuses before any contact.
}
fn candidate() -> Option<Candidate> {
    #[cfg(feature = "tracer")]
    {
        Some(crate::testonly::inference_candidate())
    }
    #[cfg(not(feature = "tracer"))]
    {
        None
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
        if !r.body.is_empty() {
            init.set_body(&JsValue::from_str(&r.body));
        }
        let request =
            web_sys::Request::new_with_str_and_init(&format!("{}{}", r.origin, r.path), &init)
                .ok()?;
        let worker: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
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
        Some(Response {
            status: response.status(),
            body: Zeroizing::new(js_sys::Uint8Array::new(&body).to_vec()),
        })
    }
}

struct Writer(LocalStore);
impl Journal for Writer {
    type MintGuard = tokio::sync::OwnedMutexGuard<()>;
    async fn mint_guard(&mut self, session: &str) -> Self::MintGuard {
        let lock = LOCKS.with_borrow_mut(|locks| locks.entry(session.into()).or_default().clone());
        lock.lock_owned().await
    }
    fn can_send(&self, revoke: bool) -> bool {
        revoke || !ending()
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
        self.0
            .lock()
            .await
            .store()
            .ok_or("locked")?
            .inference_finish(call, response, request)
            .await
    }
    async fn route(&mut self, origin: &str, chosen: bool) -> bool {
        match self.0.lock().await.store() {
            Some(s) => s.route(origin, chosen).await,
            None => false,
        }
    }
}

#[wasm_bindgen]
pub async fn inference_request(request: String) -> String {
    let Ok(request) = serde_json::from_str::<Value>(&request) else {
        return json!({"refused":"request"}).to_string();
    };
    let result = inference::infer(
        &mut Writer(crate::worker::local()),
        &mut Fetch,
        &origin(),
        candidate().as_ref(),
        &request,
        || (js_sys::Date::now() / 1000.) as u64,
    )
    .await;
    let mut report = crate::worker::local().lock().await.report(None);
    if let Some(fields) = report.as_object_mut()
        && let Some(state) = fields.remove("state")
    {
        fields.insert("store_state".into(), state);
    }
    if let Ok(message) = js_sys::JSON::parse(&json!({"store":report}).to_string()) {
        let worker: web_sys::DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
        let _ = worker.post_message(&message);
    }
    result.to_string()
}

async fn revoke(local: LocalStore, origin: String, key_id: String) {
    let mut journal = Writer(local);
    if inference::probe(&mut journal, &mut Fetch, &origin)
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
        Some(s) => s.set_inference_account(credential).await.is_ok(),
        None => false,
    }
}
