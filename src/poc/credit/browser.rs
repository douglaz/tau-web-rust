//! Worker-only credit exchanges. A writer is held only for a dispatch or one append.
use super::*;
use crate::credential::SessionInferenceKey;
use crate::poc::inference::Configuration;
use crate::store::credit::Record;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use tokio::sync::{Mutex, Notify, OwnedMutexGuard};
use wasm_bindgen::{JsCast, JsValue, closure::Closure, prelude::wasm_bindgen};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, Response, WorkerGlobalScope};

thread_local! {
    static ACTIVE: std::sync::Arc<Mutex<()>> = std::sync::Arc::new(Mutex::new(()));
    static MINT_FAILURE: RefCell<std::collections::BTreeMap<String, String>> = const { RefCell::new(std::collections::BTreeMap::new()) };
    static REVISION: Cell<u64> = const { Cell::new(0) };
    static SELECTED: Cell<bool> = const { Cell::new(false) };
    static SESSION_KEY: RefCell<Option<(String, SessionInferenceKey)>> = const { RefCell::new(None) };
    static PENDING: RefCell<Vec<std::rc::Weak<Pending>>> = const { RefCell::new(Vec::new()) };
    #[cfg(feature = "tracer")]
    static ORIGIN: RefCell<Option<String>> = const { RefCell::new(None) };
}
struct Active;
impl Active {
    fn acquire() -> Result<OwnedMutexGuard<()>, String> {
        ACTIVE
            .with(Clone::clone)
            .try_lock_owned()
            .map_err(|_| "The current credit operation is still in progress.".into())
    }
    async fn wait() -> OwnedMutexGuard<()> {
        ACTIVE.with(Clone::clone).lock_owned().await
    }
}
pub(crate) fn selected() -> bool {
    SELECTED.get()
}
pub(crate) fn select_byo() {
    SELECTED.set(false);
    SESSION_KEY.with_borrow_mut(|key| *key = None);
}
pub(crate) fn has_key(session: &str) -> bool {
    SESSION_KEY.with_borrow(|key| key.as_ref().is_some_and(|(owner, _)| owner == session))
}
pub(crate) fn key_present() -> bool {
    SESSION_KEY.with_borrow(Option::is_some)
}
pub(crate) fn retry_mint(session: &str) {
    MINT_FAILURE.with_borrow_mut(|failures| failures.remove(session));
}
pub(crate) fn with_key<T>(
    session: &str,
    use_key: impl FnOnce(&[u8]) -> Result<T, String>,
) -> Result<T, String> {
    SESSION_KEY.with_borrow(|key| {
        let (owner, key) = key.as_ref().ok_or(MINT_FAILED)?;
        if owner != session {
            return Err(MINT_FAILED.into());
        }
        use_key(&key.0)
    })
}
pub(crate) fn freeze() {
    REVISION.set(REVISION.get().wrapping_add(1));
    PENDING.with_borrow(|pending| {
        for p in pending.iter().filter_map(std::rc::Weak::upgrade) {
            p.stop();
        }
    });
}
pub(crate) fn retire() {
    freeze();
    SELECTED.set(false);
    SESSION_KEY.with_borrow_mut(|key| *key = None);
    MINT_FAILURE.with_borrow_mut(|failures| failures.clear());
}
pub(crate) fn stop_session(session: &str) {
    freeze();
    MINT_FAILURE.with_borrow_mut(|failures| failures.remove(session));
    SESSION_KEY.with_borrow_mut(|key| {
        if key.as_ref().is_some_and(|(owner, _)| owner == session) {
            *key = None;
        }
    });
    let session = session.to_owned();
    wasm_bindgen_futures::spawn_local(async move {
        let _ = cleanup(&session, true).await;
    });
}

#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub fn test_credit_origin(origin: String) -> Result<(), JsValue> {
    let url =
        js_sys::Reflect::get(&js_sys::global(), &"URL".into())?.dyn_into::<js_sys::Function>()?;
    let args = js_sys::Array::of1(&origin.clone().into());
    let parsed = js_sys::Reflect::construct(&url, &args)?;
    let host = js_sys::Reflect::get(&parsed, &"hostname".into())?
        .as_string()
        .unwrap_or_default();
    if !matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]")
        || !origin.starts_with("https://")
        || origin.ends_with('/')
    {
        return Err(JsValue::from_str("loopback credit origin required"));
    }
    ORIGIN.with_borrow_mut(|current| *current = Some(origin));
    Ok(())
}
fn origin() -> Result<String, String> {
    #[cfg(feature = "tracer")]
    {
        ORIGIN
            .with_borrow(Clone::clone)
            .ok_or_else(|| "Credit fixture origin missing.".into())
    }
    #[cfg(not(feature = "tracer"))]
    {
        Ok(env!("TAU_INFERENCE_ORIGIN").trim_end_matches('/').into())
    }
}

#[derive(Clone)]
struct Fence {
    continuation: crate::lifecycle::Continuation,
    revision: u64,
    session: Option<String>,
}
impl Fence {
    fn new(session: Option<&str>) -> Result<Self, String> {
        Ok(Self {
            continuation: crate::lifecycle::owner().continuation()?,
            revision: REVISION.get(),
            session: session.map(str::to_owned),
        })
    }
    fn scoped(&self, session: &str) -> Self {
        Self {
            continuation: self.continuation.clone(),
            revision: self.revision,
            session: Some(session.into()),
        }
    }
    fn check(&self) -> Result<(), String> {
        self.continuation.check()?;
        if self.revision != REVISION.get() {
            return Err("Credit operation interrupted.".into());
        }
        Ok(())
    }
    fn store<'a>(
        &self,
        local: &'a mut crate::store::Local<crate::store::opfs::Opfs, crate::store::opfs::WebCrypto>,
    ) -> Result<&'a mut crate::store::Store<crate::store::opfs::Opfs>, String> {
        self.check()?;
        if local.dispatch_refusal().is_some() {
            return Err("Unlock before using inference credit.".into());
        }
        let store = local
            .store()
            .ok_or("Unlock before using inference credit.")?;
        store.credit_ready()?;
        if let Some(session) = &self.session {
            store.credit_authority(session)?;
        }
        Ok(store)
    }
}
struct Pending {
    controller: web_sys::AbortController,
    stopped: Cell<bool>,
    notify: Notify,
}
impl Pending {
    fn stop(&self) {
        self.stopped.set(true);
        self.controller.abort();
        self.notify.notify_waiters();
    }
}
struct Exchange {
    pending: Rc<Pending>,
    worker: WorkerGlobalScope,
    timer: i32,
    _callback: Closure<dyn FnMut()>,
}
impl Exchange {
    fn new() -> Result<Self, String> {
        let pending = Rc::new(Pending {
            controller: web_sys::AbortController::new().map_err(|_| REFUSED)?,
            stopped: Cell::new(false),
            notify: Notify::new(),
        });
        let worker: WorkerGlobalScope = js_sys::global().unchecked_into();
        let weak = Rc::downgrade(&pending);
        let callback = Closure::<dyn FnMut()>::new(move || {
            if let Some(p) = weak.upgrade() {
                p.stop();
            }
        });
        let timer = worker
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                callback.as_ref().unchecked_ref(),
                15_000,
            )
            .map_err(|_| REFUSED)?;
        PENDING.with_borrow_mut(|list| list.push(Rc::downgrade(&pending)));
        Ok(Self {
            pending,
            worker,
            timer,
            _callback: callback,
        })
    }
    async fn finish(&self, request: &Request) -> Result<(u16, ClearedValue), String> {
        let stopped = self.pending.notify.notified();
        let work = async {
            let response: Response = JsFuture::from(self.worker.fetch_with_request(request))
                .await
                .map_err(|_| REFUSED)?
                .dyn_into()
                .map_err(|_| REFUSED)?;
            let stream = js_sys::Reflect::get(&response, &"body".into()).map_err(|_| REFUSED)?;
            let reader = function(&stream, "getReader")?
                .call0(&stream)
                .map_err(|_| REFUSED)?;
            let read = function(&reader, "read")?;
            let mut bytes = Zeroizing::new(Vec::new());
            loop {
                let chunk = JsFuture::from(
                    read.call0(&reader)
                        .map_err(|_| REFUSED)?
                        .dyn_into::<js_sys::Promise>()
                        .map_err(|_| REFUSED)?,
                )
                .await
                .map_err(|_| REFUSED)?;
                if self.pending.stopped.get() {
                    return Err(REFUSED.into());
                }
                if js_sys::Reflect::get(&chunk, &"done".into())
                    .map_err(|_| REFUSED)?
                    .as_bool()
                    == Some(true)
                {
                    break;
                }
                let array = js_sys::Uint8Array::new(
                    &js_sys::Reflect::get(&chunk, &"value".into()).map_err(|_| REFUSED)?,
                );
                if bytes.len().saturating_add(array.length() as usize) > 256 * 1024 {
                    array.fill(0, 0, array.length());
                    return Err(REFUSED.into());
                }
                let offset = bytes.len();
                bytes.resize(offset + array.length() as usize, 0);
                array.copy_to(&mut bytes[offset..]);
                array.fill(0, 0, array.length());
            }
            let value = super::decode(&bytes)?;
            Ok((response.status(), value))
        };
        match futures_util::future::select(Box::pin(work), Box::pin(stopped)).await {
            futures_util::future::Either::Left((value, _)) if !self.pending.stopped.get() => value,
            _ => Err(REFUSED.into()),
        }
    }
}
impl Drop for Exchange {
    fn drop(&mut self) {
        self.pending.stop();
        self.worker.clear_timeout_with_handle(self.timer);
        PENDING.with_borrow_mut(|list| {
            list.retain(|p| p.upgrade().is_some_and(|p| !Rc::ptr_eq(&p, &self.pending)))
        });
    }
}
fn function(object: &JsValue, name: &str) -> Result<js_sys::Function, String> {
    js_sys::Reflect::get(object, &name.into())
        .map_err(|_| REFUSED)?
        .dyn_into()
        .map_err(|_| REFUSED.into())
}
#[derive(Clone, Copy)]
enum Auth {
    None,
    Default,
    Account,
    Balance,
}
fn prepare(
    store: &crate::store::Store<crate::store::opfs::Opfs>,
    exchange: &Exchange,
    method: &str,
    path: &str,
    auth: Auth,
    body: Option<Value>,
) -> Result<Request, String> {
    let url = format!("{}{path}", origin()?);
    let init = RequestInit::new();
    init.set_method(method);
    init.set_mode(web_sys::RequestMode::Cors);
    init.set_credentials(web_sys::RequestCredentials::Omit);
    init.set_cache(web_sys::RequestCache::NoStore);
    init.set_redirect(web_sys::RequestRedirect::Error);
    init.set_signal(Some(&exchange.pending.controller.signal()));
    let headers = web_sys::Headers::new().map_err(|_| REFUSED)?;
    let mut body = ClearedValue(body.unwrap_or(Value::Null));
    if !matches!(auth, Auth::None) {
        let account = store.credit_account().ok_or(ACCOUNT_FAILED)?;
        let id = std::str::from_utf8(&account.credit_id.0).map_err(|_| REFUSED)?;
        match auth {
            Auth::Default => {
                let key = std::str::from_utf8(&account.default_key.0).map_err(|_| REFUSED)?;
                let value = Zeroizing::new(format!("Bearer {key}"));
                headers.set("Authorization", &value).map_err(|_| REFUSED)?;
            }
            Auth::Account => headers.set("x-credit-id", id).map_err(|_| REFUSED)?,
            Auth::Balance => body.0 = serde_json::json!({"credit_id":id}),
            Auth::None => (),
        }
    }
    if !body.0.is_null() {
        headers
            .set("Content-Type", "application/json")
            .map_err(|_| REFUSED)?;
        let bytes = Zeroizing::new(serde_json::to_vec(&body.0).map_err(|_| REFUSED)?);
        let array = js_sys::Uint8Array::from(bytes.as_slice());
        init.set_body(&array);
        init.set_headers(&headers);
        let request = Request::new_with_str_and_init(&url, &init);
        array.fill(0, 0, array.length());
        let _ = headers.delete("Authorization");
        let _ = headers.delete("x-credit-id");
        request.map_err(|_| REFUSED.into())
    } else {
        init.set_headers(&headers);
        let request = Request::new_with_str_and_init(&url, &init);
        let _ = headers.delete("Authorization");
        let _ = headers.delete("x-credit-id");
        request.map_err(|_| REFUSED.into())
    }
}
async fn exchange(
    fence: &Fence,
    method: &str,
    path: &str,
    auth: Auth,
    body: Option<Value>,
) -> Result<(u16, ClearedValue), String> {
    let exchange = Exchange::new()?;
    let request = {
        let local = crate::worker::local();
        let mut local = local.lock().await;
        let store = fence.store(&mut local)?;
        prepare(store, &exchange, method, path, auth, body)?
    };
    fence.check()?;
    exchange.finish(&request).await
}
async fn read_balance(fence: &Fence) -> Result<f64, String> {
    let response = exchange(fence, "POST", "/credits/balance", Auth::Balance, None).await;
    let local = crate::worker::local();
    let mut local = local.lock().await;
    let store = fence.store(&mut local)?;
    let amount = response.as_ref().ok().and_then(|(status, value)| {
        (200..300)
            .contains(status)
            .then(|| balance(&value.0))
            .flatten()
    });
    store.credit_balance(amount);
    amount.ok_or_else(|| "Couldn't read inference credit balance.".into())
}
async fn append(fence: &Fence, record: Record) -> Result<(), String> {
    let local = crate::worker::local();
    let mut local = local.lock().await;
    fence
        .store(&mut local)?
        .credit_commit(record)
        .await
        .map_err(|_| "Credit store write failed; unlock again before continuing.".to_string())?;
    fence.check()
}
async fn fund(fence: &Fence, amount: u64) -> Result<(), String> {
    if !(100..=5000).contains(&amount) {
        return Err("Choose 100 through 5,000 sat.".into());
    }
    {
        let local = crate::worker::local();
        let mut local = local.lock().await;
        if fence.store(&mut local)?.credit_invoice().is_some_and(|i| {
            !matches!(
                i.outcome,
                Payment::Paid | Payment::ExpiredUnpaid | Payment::Abandoned
            )
        }) {
            return Err("Check the saved invoice; its payment outcome is unresolved.".into());
        }
    }
    let needs_account = {
        let local = crate::worker::local();
        let mut local = local.lock().await;
        fence.store(&mut local)?.credit_account().is_none()
    };
    if needs_account {
        let (status, value) = exchange(fence, "POST", "/accounts/create", Auth::None, None)
            .await
            .map_err(|_| ACCOUNT_FAILED)?;
        let account = AccountRecord::from_response(status, &value.0)?;
        let local = crate::worker::local();
        let mut local = local.lock().await;
        fence
            .store(&mut local)?
            .credit_install(&account)
            .await
            .map_err(|_| "Credit store write failed; no invoice requested.")?;
        fence.check()?;
    }
    let baseline = read_balance(fence).await?;
    let (status, value) = exchange(
        fence,
        "POST",
        "/topup/create/btc-lightning",
        Auth::Default,
        Some(serde_json::json!({"amount":amount,"currency":"SATS"})),
    )
    .await
    .map_err(|_| INVOICE_FAILED)?;
    fence.check()?;
    if status != 201 {
        return Err(INVOICE_FAILED.into());
    }
    {
        let candidate = ClearedValue(
            serde_json::json!({"id":value.0["invoice_id"],"invoice":value.0["lightning_invoice"]}),
        );
        let local = crate::worker::local();
        let mut local = local.lock().await;
        if !crate::poc::inference::safe(fence.store(&mut local)?, &candidate.0, &[]) {
            return Err(INVOICE_INVALID.into());
        }
    }
    let invoice = Invoice::from_response(status, &value.0, amount, baseline)?;
    append(fence, Record::Invoice(invoice)).await
}
async fn check_invoice(fence: &Fence, automatic: bool) -> Result<(), String> {
    let invoice = {
        let local = crate::worker::local();
        let mut local = local.lock().await;
        let store = fence.store(&mut local)?;
        store.credit_invoice().cloned()
    };
    let Some(invoice) = invoice else {
        return read_balance(fence).await.map(|_| ());
    };
    if invoice.outcome == Payment::Abandoned {
        return read_balance(fence).await.map(|_| ());
    }
    if automatic && !invoice.may_poll(now()) {
        return Ok(());
    }
    let status = exchange(
        fence,
        "GET",
        &format!("/topup/status/{}", invoice.id),
        Auth::Default,
        None,
    )
    .await;
    fence.check()?;
    let status_value = status
        .as_ref()
        .ok()
        .filter(|(s, _)| (200..300).contains(s))
        .map(|(_, v)| &v.0);
    let balance = read_balance(fence).await.ok();
    fence.check()?;
    let outcome = invoice.observe(status_value, balance, now());
    let raw = status_value
        .and_then(|s| s["status"].as_str())
        .filter(|s| s.len() <= 128)
        .unwrap_or("unreadable");
    let raw = {
        let local = crate::worker::local();
        let mut local = local.lock().await;
        let store = fence.store(&mut local)?;
        let safe = store.protect_output(&Value::String(raw.into()))?;
        safe.as_str().unwrap_or("unavailable").to_owned()
    };
    append(
        fence,
        Record::Status {
            id: invoice.id,
            status: raw,
            outcome,
            balance,
        },
    )
    .await
}
fn now() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Start {
        machine: String,
        goal: String,
        endpoint: String,
        model: String,
    },
    Invoice {
        amount: u64,
    },
    Check,
    Refresh,
    Poll,
    NewKey {
        session: String,
    },
    Configure {
        endpoint: String,
        model: String,
    },
}
#[wasm_bindgen]
pub async fn credit_request(request: String) -> String {
    let result = async {
        let action: Action =
            serde_json::from_str(&request).map_err(|_| "Invalid credit request.")?;
        let fence = Fence::new(None)?;
        // Mandatory reads wait for the current mutation rather than dropping the refresh.
        let _active = if matches!(action, Action::Check | Action::Refresh | Action::Poll) {
            Active::wait().await
        } else {
            Active::acquire()?
        };
        fence.check()?;
        match action {
            Action::Start { machine, goal, endpoint, model } => {
                let config = Configuration::new(endpoint,model)?;
                let session = {
                    let local = crate::worker::local(); let mut local = local.lock().await;
                    let store = fence.store(&mut local)?;
                    if goal.trim().is_empty() { return Err("Enter a goal before Start session.".into()); }
                    if !store.credit_can_start() { return Err("Read a positive inference credit balance before Start.".into()); }
                    if !crate::poc::inference::safe(store,&serde_json::json!({"goal":goal,"endpoint":config.endpoint,"model":config.model}),&[]) { return Err("Start contains protected material.".into()); }
                    if store.sessions().iter().any(|s| s["session_state"] != "ended" && s["bound_set"].as_array().is_some_and(|b| b.iter().any(|m| m == &machine))) {
                        return Err("Use the existing session controls; End it before starting another.".into());
                    }
                    crate::poc::targets::resolve(store,&machine)?;
                    let session = store.admit_with_credit(&machine,&[],crate::binding::InferenceApproval {approved:true,configuration:config},true).await?;
                    fence.check()?;
                    store.enter_goal(&session,goal,None).await?;
                    session
                };
                mint(&session,false,&fence).await
            }
            Action::Invoice { amount } => fund(&fence, amount).await,
            Action::Check | Action::Refresh => check_invoice(&fence, false).await,
            Action::Poll => check_invoice(&fence, true).await,
            Action::NewKey { session } => mint(&session, true, &fence).await,
            Action::Configure { endpoint, model } => {
                let config = Configuration::new(endpoint, model)?;
                let local = crate::worker::local();
                let mut local = local.lock().await;
                let store = fence.store(&mut local)?;
                if !store.credit_can_start() {
                    return Err("Read a positive inference credit balance before Start.".into());
                }
                if !crate::poc::inference::safe(
                    store,
                    &serde_json::json!({"endpoint":config.endpoint,"model":config.model}),
                    &[],
                ) {
                    return Err(REFUSED.into());
                }
                if crate::poc::inference::response_pending() { return Err("Credit configuration refused: command response pending; retry after it completes.".into()); }
                for session in store.sessions().iter().filter(|s| s["session_state"] != "ended") {
                    let id = session["identity"].as_str().ok_or("session identity")?;
                    if !store.credit_session(id) || store.session_configuration(id)?.model != config.model {
                        return Err("Use the admitted inference configuration for the existing session.".into());
                    }
                }
                crate::poc::inference::restore_credit(config);
                SELECTED.set(true);
                Ok(())
            }
        }
    }
    .await;
    let local = crate::worker::local();
    let local = local.lock().await;
    let mut report = local.report(None);
    if let Err(why) = result {
        report["credit_error"] = why.into();
    }
    report.to_string()
}

// This narrow capability permits only best-effort deletion of a returned key after retirement.
struct Cleanup {
    headers: web_sys::Headers,
    origin: String,
    filters: Rc<RefCell<Vec<crate::poc::inference::EchoFilter>>>,
}
impl Cleanup {
    fn new(store: &crate::store::Store<crate::store::opfs::Opfs>) -> Result<Self, String> {
        let origin = origin()?;
        let account = store.credit_account().ok_or(MINT_FAILED)?;
        let headers = web_sys::Headers::new().map_err(|_| MINT_FAILED)?;
        headers
            .set(
                "x-credit-id",
                std::str::from_utf8(&account.credit_id.0).map_err(|_| MINT_FAILED)?,
            )
            .map_err(|_| MINT_FAILED)?;
        Ok(Self {
            headers,
            origin,
            filters: store.credit_filter_handle(),
        })
    }
    fn safe_id(&self, id: &str) -> bool {
        identifier(id)
            && self.filters.borrow().iter().all(|filter| {
                filter
                    .protect_bytes(id.as_bytes())
                    .is_ok_and(|safe| safe.as_slice() == id.as_bytes())
            })
    }
    async fn revoke(&self, id: &str) {
        if !self.safe_id(id) {
            return;
        }
        let Ok(exchange) = Exchange::new() else {
            return;
        };
        let init = RequestInit::new();
        init.set_method("DELETE");
        init.set_headers(&self.headers);
        init.set_mode(web_sys::RequestMode::Cors);
        init.set_credentials(web_sys::RequestCredentials::Omit);
        init.set_cache(web_sys::RequestCache::NoStore);
        init.set_redirect(web_sys::RequestRedirect::Error);
        init.set_signal(Some(&exchange.pending.controller.signal()));
        if let Ok(request) =
            Request::new_with_str_and_init(&format!("{}/keys/{id}", self.origin), &init)
        {
            let _ = exchange.finish(&request).await;
        }
    }
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.headers.delete("x-credit-id");
    }
}

async fn cleanup(session: &str, ended: bool) -> Result<(), String> {
    let fence = Fence::new(if ended { None } else { Some(session) })?;
    let mints = {
        let local = crate::worker::local();
        let mut local = local.lock().await;
        fence.store(&mut local)?.credit_mints(session)
    };
    if mints.is_empty() {
        return Ok(());
    }
    let cleanup = {
        let local = crate::worker::local();
        let mut local = local.lock().await;
        Cleanup::new(fence.store(&mut local)?)?
    };
    let mut ids: std::collections::BTreeSet<String> =
        mints.iter().filter_map(|m| m.issuer_id.clone()).collect();
    if let Ok((200, value)) = exchange(
        &fence,
        "GET",
        "/keys?include_disabled=true",
        Auth::Account,
        None,
    )
    .await
        && let Some(keys) = value.0["data"].as_array().filter(|a| a.len() <= 128)
    {
        for key in keys {
            if mints.iter().any(|m| key["name"] == m.name)
                && let Some(id) = key["_id"].as_str().filter(|s| cleanup.safe_id(s))
            {
                ids.insert(id.into());
            }
        }
    }
    for id in ids {
        cleanup.revoke(&id).await;
    }
    Ok(())
}
pub(crate) async fn ensure(
    session: &str,
    continuation: &crate::lifecycle::Continuation,
) -> Result<(), String> {
    let fence = Fence {
        continuation: continuation.clone(),
        revision: REVISION.get(),
        session: Some(session.into()),
    };
    let local = crate::worker::local();
    let is_credit = {
        let mut local = local.lock().await;
        continuation.check()?;
        let store = local.store().ok_or("locked")?;
        store.credit_session(session)
    };
    if !is_credit || has_key(session) {
        return Ok(());
    }
    let _active = Active::wait().await;
    fence.check()?;
    if has_key(session) {
        return Ok(());
    }
    if let Some(why) = MINT_FAILURE.with_borrow(|failures| failures.get(session).cloned()) {
        pause_mint_failure(session, &why, &fence).await;
        return Err(why);
    }
    mint(session, false, &fence).await
}
async fn pause_mint_failure(session: &str, why: &str, parent: &Fence) {
    let fence = parent.scoped(session);
    let local = crate::worker::local();
    let mut local = local.lock().await;
    if let Ok(store) = fence.store(&mut local)
        && store.credit_session(session)
    {
        let _ = store.credit_pause_mint_failure(session, why).await;
    }
}
async fn mint(session: &str, replace: bool, parent: &Fence) -> Result<(), String> {
    let result = mint_inner(session, replace, parent).await;
    if result.is_ok() {
        MINT_FAILURE.with_borrow_mut(|failures| failures.remove(session));
    }
    if let Err(why) = &result
        && matches!(
            why.as_str(),
            MINT_FAILED | "Couldn't read inference credit balance." | "Inference credit used up."
        )
        && parent.check().is_ok()
    {
        MINT_FAILURE.with_borrow_mut(|failures| failures.insert(session.into(), why.clone()));
        // Collection and verification proceed; pause only at the next inference boundary.
        pause_mint_failure(session, why, parent).await;
    }
    result
}
async fn mint_inner(session: &str, replace: bool, parent: &Fence) -> Result<(), String> {
    if !replace && has_key(session) {
        return Ok(());
    }
    let fence = parent.scoped(session);
    fence.check()?;
    if crate::poc::inference::response_pending() {
        return Err(
            "Credit configuration refused: command response pending; retry after it completes."
                .into(),
        );
    }
    #[cfg(feature = "tracer")]
    crate::testonly::session_point("credit_mint_writer").await;
    {
        let local = crate::worker::local();
        let mut local = local.lock().await;
        let store = fence.store(&mut local)?;
        if !store.credit_session(session) {
            return Err(MINT_FAILED.into());
        }
        let config = store.session_configuration(session)?;
        crate::poc::inference::restore_credit(config);
        SELECTED.set(true);
    }
    SESSION_KEY.with_borrow_mut(|key| *key = None);
    cleanup(session, false).await?;
    if read_balance(&fence).await? <= 0.0 {
        return Err("Inference credit used up.".into());
    }
    let mint = Mint {
        session: session.into(),
        name: mint_name()?,
        requested_cap: CAP,
        requested_expiry: now().checked_add(LIFETIME).ok_or(MINT_FAILED)?,
        issuer_id: None,
        returned_cap: None,
        returned_expiry: None,
    };
    append(&fence, Record::MintName(mint.clone())).await?;
    let expiry = js_sys::Date::new(&JsValue::from_f64(mint.requested_expiry as f64 * 1000.0))
        .to_iso_string()
        .as_string()
        .ok_or(MINT_FAILED)?;
    let (registration, cleanup) = {
        let local = crate::worker::local();
        let mut local = local.lock().await;
        let store = fence.store(&mut local)?;
        (store.credit_filter_handle(), Cleanup::new(store)?)
    };
    let (status, mut value) = exchange(
        &fence,
        "POST",
        "/keys",
        Auth::Account,
        Some(serde_json::json!({"name":mint.name,"usage_limit_usd":CAP,"expire_at":expiry})),
    )
    .await
    .map_err(|_| MINT_FAILED)?;
    let id = value.0["data"]["_id"]
        .as_str()
        .filter(|id| identifier(id))
        .map(|id| Zeroizing::new(id.to_owned()));
    let raw_key = value.0["data"]["api_key"].take();
    let raw_key = ClearedValue(raw_key);
    let key = raw_key
        .0
        .as_str()
        .map(|s| Zeroizing::new(s.as_bytes().to_vec()));
    if let Some(key) = &key {
        let next = crate::poc::inference::EchoFilter::new(&[key]);
        let mut filters = registration.borrow_mut();
        if let Some(combined) = filters.first_mut() {
            combined.merge(next);
        } else {
            filters.push(next);
        }
    }
    #[cfg(feature = "tracer")]
    crate::testonly::session_point("credit_mint_return").await;
    let accepted: Result<(), String> = async {
        let local = crate::worker::local();
        let mut local = local.lock().await;
        let store = fence.store(&mut local)?;
        if status != 201 {
            return Err(MINT_FAILED.into());
        }
        let key = key.as_ref().ok_or(MINT_FAILED)?;
        crate::poc::inference::valid_key(key).map_err(|_| MINT_FAILED)?;
        let account = store.credit_account().ok_or(MINT_FAILED)?;
        if key.as_slice() == account.credit_id.0 || key.as_slice() == account.default_key.0 {
            return Err(MINT_FAILED.into());
        }
        store.poc_configuration_key(key).map_err(|_| MINT_FAILED)?;
        let metadata = ClearedValue(serde_json::json!({"id":value.0["data"]["_id"],"name":value.0["data"]["name"],"cap":value.0["data"]["usage_limit_usd"],"expiry":value.0["data"]["expire_at"]}));
        if !crate::poc::inference::safe(store, &metadata.0, &[]) { return Err(MINT_FAILED.into()); }
        let (id, expiry) = returned_mint(&value.0, &mint)?;
        store
            .credit_commit(Record::MintId {
                name: mint.name.clone(),
                issuer_id: id,
                returned_cap: CAP,
                returned_expiry: expiry,
            })
            .await?;
        fence.check()?;
        store.credit_authority(session)?;
        SESSION_KEY.with_borrow_mut(|held| {
            *held = Some((session.into(), SessionInferenceKey(key.to_vec())))
        });
        Ok(())
    }
    .await;
    drop(key);
    drop(raw_key);
    drop(value);
    if accepted.is_err()
        && let Some(id) = id
    {
        cleanup.revoke(&id).await;
    }
    accepted.map_err(|_| MINT_FAILED.into())
}

pub(crate) async fn refusal(status: u16, bytes: &[u8], session: &str) -> String {
    match inference_failure(status, bytes) {
        InferenceFailure::Expired => "This session's inference key expired.".into(),
        InferenceFailure::Exhaustion(minimum) => {
            if let Ok(fence) = Fence::new(Some(session))
                && let Ok(balance) = read_balance(&fence).await
                && (minimum.is_some_and(|minimum| balance < minimum) || balance == 0.0)
            {
                return "Inference credit used up.".into();
            }
            REFUSED.into()
        }
        InferenceFailure::Refused => REFUSED.into(),
    }
}
