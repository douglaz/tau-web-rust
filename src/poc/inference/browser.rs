use super::*;
use crate::credential::InferenceAccountCredential;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use tokio::sync::Notify;
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::JsFuture;

thread_local! {
    static CONFIG: RefCell<Option<Configuration>> = const { RefCell::new(None) };
    static KEY: RefCell<Option<InferenceAccountCredential>> = const { RefCell::new(None) };
    static REQUESTS: RefCell<Vec<std::rc::Weak<Pending>>> = const { RefCell::new(Vec::new()) };
    static COMMAND_RESPONSES: Cell<usize> = const { Cell::new(0) };
    static REVISION: Cell<u64> = const { Cell::new(0) };
}

/// Reserve the current protection inventory until a command response leaves the worker.
/// This holds no writer across transport waits. Configuration refuses promptly while any
/// response is pending, so a terminal's capacity preflight remains valid through release.
/// Each caller (including a held request) owns its own reservation; drop covers all exits.
pub(crate) struct CommandResponse;
impl CommandResponse {
    pub(crate) fn reserve() -> Self {
        COMMAND_RESPONSES.set(
            COMMAND_RESPONSES
                .get()
                .checked_add(1)
                .expect("command response count"),
        );
        Self
    }
}
impl Drop for CommandResponse {
    fn drop(&mut self) {
        COMMAND_RESPONSES.set(COMMAND_RESPONSES.get() - 1);
    }
}

struct Pending {
    controller: web_sys::AbortController,
    stopped: Cell<bool>,
    ready: Notify,
}
impl Pending {
    fn stop(&self) {
        self.stopped.set(true);
        self.controller.abort();
        self.ready.notify_waiters();
    }

    async fn until<T>(&self, work: impl std::future::Future<Output = T>) -> Result<T, String> {
        let ready = self.ready.notified();
        if self.stopped.get() {
            return Err(INCOMPLETE.into());
        }
        match futures_util::future::select(Box::pin(work), Box::pin(ready)).await {
            futures_util::future::Either::Left((result, _)) if !self.stopped.get() => Ok(result),
            _ => Err(INCOMPLETE.into()),
        }
    }
}

pub(crate) fn freeze() {
    REQUESTS.with_borrow_mut(|requests| {
        requests.retain(|pending| {
            if let Some(pending) = pending.upgrade() {
                pending.stop();
                true
            } else {
                false
            }
        });
    });
}
pub(crate) fn end() {
    freeze();
    KEY.with_borrow_mut(|key| *key = None);
    REVISION.set(REVISION.get().wrapping_add(1));
}
pub(crate) fn key_is_set() -> bool {
    KEY.with_borrow(Option::is_some)
}

pub(crate) async fn configure(
    endpoint: String,
    model: String,
    key: Zeroizing<Vec<u8>>,
) -> Result<(), String> {
    let continuation = crate::lifecycle::owner().continuation()?;
    let local = crate::worker::local();
    let mut local = local.lock().await;
    continuation.check()?;
    if let Some(why) = local.dispatch_refusal() {
        return Err(why.into());
    }
    if COMMAND_RESPONSES.get() != 0 {
        return Err(
            "inference configuration refused: command response pending; retry after it completes"
                .into(),
        );
    }
    let config = Configuration::new(endpoint, model)?;
    valid_key(&key)?;
    let store = local.store().ok_or("locked")?;
    store.poc_configuration_ready()?;
    store.poc_configuration_key(&key)?;
    if !safe(
        store,
        &json!({"endpoint":config.endpoint,"model":config.model}),
        &[&key],
    ) {
        return Err("inference configuration contains protected material".into());
    }
    store.remember_poc_credential(&key);
    freeze();
    REVISION.set(REVISION.get().wrapping_add(1));
    KEY.with_borrow_mut(|held| *held = Some(InferenceAccountCredential::new(key.to_vec())));
    CONFIG.with_borrow_mut(|held| *held = Some(config));
    Ok(())
}

struct Registration {
    pending: Rc<Pending>,
    worker: web_sys::WorkerGlobalScope,
    timer: i32,
    _callback: Closure<dyn FnMut()>,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.pending.stop();
        self.worker.clear_timeout_with_handle(self.timer);
        REQUESTS.with_borrow_mut(|requests| {
            requests.retain(|r| r.upgrade().is_some_and(|r| !Rc::ptr_eq(&r, &self.pending)))
        });
    }
}

fn method(object: &JsValue, name: &str) -> Result<js_sys::Function, String> {
    js_sys::Reflect::get(object, &name.into())
        .ok()
        .and_then(|v| v.dyn_into().ok())
        .ok_or_else(|| INCOMPLETE.into())
}

async fn body(
    response: &web_sys::Response,
    pending: &Pending,
) -> Result<Zeroizing<Vec<u8>>, String> {
    // Read incrementally: response.array_buffer() would allocate an unbounded response first.
    let stream = js_sys::Reflect::get(response, &"body".into()).map_err(|_| INCOMPLETE)?;
    if stream.is_null() {
        return Ok(Zeroizing::new(Vec::new()));
    }
    let reader = method(&stream, "getReader")?
        .call0(&stream)
        .map_err(|_| INCOMPLETE)?;
    let read = method(&reader, "read")?;
    let mut output = Zeroizing::new(Vec::new());
    loop {
        if pending.stopped.get() {
            return Err(INCOMPLETE.into());
        }
        let promise: js_sys::Promise = read
            .call0(&reader)
            .map_err(|_| INCOMPLETE)?
            .dyn_into()
            .map_err(|_| INCOMPLETE)?;
        let chunk = JsFuture::from(promise).await.map_err(|_| INCOMPLETE)?;
        if pending.stopped.get() {
            return Err(INCOMPLETE.into());
        }
        if js_sys::Reflect::get(&chunk, &"done".into())
            .map_err(|_| INCOMPLETE)?
            .as_bool()
            == Some(true)
        {
            break;
        }
        let bytes = js_sys::Uint8Array::new(
            &js_sys::Reflect::get(&chunk, &"value".into()).map_err(|_| INCOMPLETE)?,
        );
        if output.len().saturating_add(bytes.length() as usize) > RESPONSE_BYTES {
            pending.controller.abort();
            return Err(RESPONSE_TOO_LARGE.into());
        }
        output.extend_from_slice(&bytes.to_vec());
        bytes.fill(0, 0, bytes.length());
    }
    Ok(output)
}

/// One request, never retried here. Completed steps remain owned by the durable caller.
pub(crate) async fn next(
    goal: &str,
    machine: &str,
    steps: &[(String, crate::goals::Tool, serde_json::Value)],
) -> Result<(String, crate::goals::Tool), String> {
    let continuation = crate::lifecycle::owner().continuation()?;
    let revision = REVISION.get();
    let config = CONFIG
        .with_borrow(Clone::clone)
        .ok_or("inference endpoint missing")?;
    let local = crate::worker::local();
    let pending = Rc::new(Pending {
        controller: web_sys::AbortController::new().map_err(|_| INCOMPLETE)?,
        stopped: Cell::new(false),
        ready: Notify::new(),
    });
    let worker: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let weak = Rc::downgrade(&pending);
    let callback = Closure::<dyn FnMut()>::new(move || {
        if let Some(pending) = weak.upgrade() {
            pending.stop();
        }
    });
    let timer = worker
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            callback.as_ref().unchecked_ref(),
            60_000,
        )
        .map_err(|_| INCOMPLETE)?;
    let registration = Registration {
        pending: pending.clone(),
        worker: worker.clone(),
        timer,
        _callback: callback,
    };
    REQUESTS.with_borrow_mut(|requests| requests.push(Rc::downgrade(&pending)));

    let (promise, filter) = {
        let mut local = pending.until(local.lock()).await?;
        continuation.check()?;
        if revision != REVISION.get() {
            return Err(INCOMPLETE.into());
        }
        if let Some(why) = local.dispatch_refusal() {
            return Err(why.into());
        }
        let store = local.store().ok_or("locked")?;
        store.ensure_scan_references().await?;
        continuation.check()?;
        if revision != REVISION.get() || pending.stopped.get() {
            return Err(INCOMPLETE.into());
        }
        KEY.with_borrow(|key| {
            let key = key.as_ref().ok_or("inference key missing")?;
            let body = request(store, &config, goal, machine, steps, &[&key.0])?;
            let filter = EchoFilter::new(&[&key.0]);
            let init = web_sys::RequestInit::new();
            init.set_method("POST");
            init.set_signal(Some(&pending.controller.signal()));
            init.set_mode(web_sys::RequestMode::Cors);
            init.set_credentials(web_sys::RequestCredentials::Omit);
            init.set_cache(web_sys::RequestCache::NoStore);
            init.set_redirect(web_sys::RequestRedirect::Error);
            let headers = web_sys::Headers::new().map_err(|_| INCOMPLETE)?;
            headers
                .set("Content-Type", "application/json")
                .map_err(|_| INCOMPLETE)?;
            let authorization = Zeroizing::new(format!(
                "Bearer {}",
                std::str::from_utf8(&key.0).map_err(|_| "inference key invalid")?
            ));
            headers
                .set("Authorization", &authorization)
                .map_err(|_| INCOMPLETE)?;
            init.set_headers(&headers);
            let body = js_sys::Uint8Array::from(body.as_slice());
            init.set_body(&body);
            let request = web_sys::Request::new_with_str_and_init(&config.endpoint, &init)
                .map_err(|_| INCOMPLETE)?;
            body.fill(0, 0, body.length());
            let _ = headers.delete("Authorization");
            continuation.check()?;
            Ok::<_, String>((worker.fetch_with_request(&request), filter))
        })?
    };

    let ready = pending.ready.notified();
    let received_status = Cell::new(None);
    let exchange = async {
        let response: web_sys::Response = JsFuture::from(promise)
            .await
            .map_err(|_| INCOMPLETE)?
            .dyn_into()
            .map_err(|_| INCOMPLETE)?;
        continuation.check().map_err(|_| INCOMPLETE)?;
        if revision != REVISION.get() || pending.stopped.get() {
            return Err(INCOMPLETE.into());
        }
        let status = response.status();
        received_status.set(Some(status));
        if status == 0 {
            return Err(INCOMPLETE.into());
        }
        // Authentication refusal is established by the status, even if its body never ends.
        let bytes = if matches!(status, 401 | 403) {
            Zeroizing::new(Vec::new())
        } else {
            match body(&response, &pending).await {
                Ok(body) => body,
                Err(_) if !(200..300).contains(&status) => return Err(http_failure(status)),
                Err(why) => return Err(why),
            }
        };
        // Only these envelopes can reach normalization/release. Unused provider metadata
        // has no durable or publication sink; discard it before repeated protection. The
        // full response read remains bounded, and model values are still refused, not repaired.
        let bytes = if let Ok(mut value) = serde_json::from_slice::<Value>(&bytes) {
            if let Some(object) = value.as_object_mut() {
                object.retain(|name, _| {
                    if (200..300).contains(&status) {
                        name == "choices"
                    } else {
                        name == "error"
                    }
                });
            }
            Zeroizing::new(serde_json::to_vec(&value).map_err(|_| "inference response encoding")?)
        } else if (200..300).contains(&status) {
            return Err("inference response malformed JSON".into());
        } else {
            Zeroizing::new(Vec::new())
        };
        // Apply the request's non-reversible echo filter before any lock wait or late disposal.
        let filtered = match filter.protect_bytes(&bytes) {
            Ok(filtered) => filtered,
            Err(_) if !(200..300).contains(&status) => Zeroizing::new(Vec::new()),
            Err(why) => return Err(why),
        };
        if (200..300).contains(&status) && *filtered != *bytes {
            return Err("inference proposal contains protected material".into());
        }
        let bytes = filtered;
        continuation.check().map_err(|_| INCOMPLETE)?;
        if revision != REVISION.get() || pending.stopped.get() {
            return Err(INCOMPLETE.into());
        }
        let mut local = pending.until(local.lock()).await?;
        continuation.check().map_err(|_| INCOMPLETE)?;
        if revision != REVISION.get() || pending.stopped.get() {
            return Err(INCOMPLETE.into());
        }
        if local.dispatch_refusal().is_some() {
            return Err(INCOMPLETE.into());
        }
        let store = local.store().ok_or(INCOMPLETE)?;
        KEY.with_borrow(|key| {
            let key = key.as_ref().ok_or("inference key missing")?;
            // The shared completion boundary classifies HTTP failures before JSON decoding.
            complete_response(store, status, &bytes, machine, steps, &[&key.0], &filter)
        })
    };
    let result = match futures_util::future::select(Box::pin(exchange), Box::pin(ready)).await {
        futures_util::future::Either::Left((result, _)) => result,
        futures_util::future::Either::Right(_) => Err(INCOMPLETE.into()),
    };
    drop(registration);
    match result {
        Err(why)
            if why == INCOMPLETE
                && received_status
                    .get()
                    .is_some_and(|status| status != 0 && !(200..300).contains(&status)) =>
        {
            Err(http_failure(received_status.get().expect("known status")))
        }
        result => result,
    }
}
