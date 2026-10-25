use crate::goals::{self, Driver, Tool};
use crate::harness::{BoundJournal, Target};
use crate::worker::{StoreJournal, local};
use serde::Deserialize;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use wasm_bindgen::{JsCast, prelude::*};
use wasm_bindgen_futures::JsFuture;

thread_local! {
    static DOCUMENTS: RefCell<BTreeMap<String, String>> = const { RefCell::new(BTreeMap::new()) };
    static PENDING: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
    static STARTED: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
    static FETCHES: RefCell<Vec<web_sys::AbortController>> = const { RefCell::new(Vec::new()) };
    #[cfg(feature = "tracer")]
    static TARGETS: RefCell<BTreeMap<String, Value>> = const { RefCell::new(BTreeMap::new()) };
}
pub(super) fn end() {
    FETCHES.with_borrow_mut(|fetches| {
        for f in fetches.drain(..) {
            f.abort();
        }
    });
    DOCUMENTS.with_borrow_mut(BTreeMap::clear);
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    session: String,
    text: String,
    document_source: Option<String>,
}

#[wasm_bindgen]
pub async fn goal_request(request: String) -> String {
    let result = enter(&request).await;
    local()
        .lock()
        .await
        .report(result.as_ref().err().map(String::as_str))
        .to_string()
}
async fn enter(request: &str) -> Result<(), String> {
    if !serde_json::from_str::<Value>(request).is_ok_and(|v| v.is_object()) {
        return Err("goal request".into());
    }
    let entry: Entry = serde_json::from_str(request).map_err(|_| "goal request")?;
    if super::inference::ending() {
        return Err("sessions ended".into());
    }
    if let Some(source) = &entry.document_source
        && (!goals::document_url(source) || web_sys::Request::new_with_str(source).is_err())
    {
        return Err("document source".into());
    }
    let source = entry.document_source.clone();
    {
        let local = local();
        let mut local = local.lock().await;
        if super::inference::ending() {
            return Err("sessions ended".into());
        }
        if let Some(why) = local.dispatch_refusal() {
            return Err(why.into());
        }
        local
            .store()
            .ok_or("locked")?
            .enter_goal(&entry.session, entry.text, entry.document_source)
            .await?;
        if source.is_some() {
            PENDING.with_borrow_mut(|p| p.insert(entry.session.clone()));
        }
    }
    // The goal's source has committed. End may have begun while that append waited.
    if super::inference::ending() {
        PENDING.with_borrow_mut(|p| p.remove(&entry.session));
        return Err("sessions ended".into());
    }
    if let Some(source) = source
        && let Some(text) = fetch_document(&source).await
        && !super::inference::ending()
    {
        DOCUMENTS.with_borrow_mut(|docs| docs.insert(entry.session.clone(), text));
    }
    PENDING.with_borrow_mut(|p| p.remove(&entry.session));
    Ok(())
}

async fn fetch_document(source: &str) -> Option<String> {
    use web_sys::{
        RequestCache, RequestCredentials, RequestInit, RequestMode, RequestRedirect, ResponseType,
    };
    let init = RequestInit::new();
    init.set_method("GET");
    init.set_redirect(RequestRedirect::Manual);
    init.set_mode(RequestMode::Cors);
    init.set_cache(RequestCache::NoStore);
    init.set_credentials(RequestCredentials::Omit);
    let controller = web_sys::AbortController::new().ok()?;
    init.set_signal(Some(&controller.signal()));
    let request = web_sys::Request::new_with_str_and_init(source, &init).ok()?;
    let worker: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    if super::inference::ending() {
        return None;
    }
    FETCHES.with_borrow_mut(|fs| fs.push(controller.clone()));
    let result = async {
        let response: web_sys::Response = JsFuture::from(worker.fetch_with_request(&request))
            .await
            .ok()?
            .dyn_into()
            .ok()?;
        if !(200..300).contains(&response.status())
            || matches!(
                response.type_(),
                ResponseType::Opaque | ResponseType::Opaqueredirect | ResponseType::Error
            )
        {
            return None;
        }
        JsFuture::from(response.text().ok()?)
            .await
            .ok()?
            .as_string()
    }
    .await;
    FETCHES.with_borrow_mut(|fs| fs.retain(|f| f != &controller));
    result
}

#[wasm_bindgen]
pub async fn goal_accept(request: String) -> String {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Acceptance {
        session: String,
    }
    let result = async {
        if !serde_json::from_str::<Value>(&request).is_ok_and(|v| v.is_object()) {
            return Err("acceptance request".into());
        }
        let a: Acceptance = serde_json::from_str(&request).map_err(|_| "acceptance request")?;
        let local = local();
        let mut local = local.lock().await;
        if super::inference::ending() {
            return Err("sessions ended".into());
        }
        if let Some(why) = local.dispatch_refusal() {
            return Err(why.into());
        }
        let store = local.store().ok_or("locked")?;
        store.goal(&a.session).ok_or("missing goal")?;
        if PENDING.with_borrow(|p| p.contains(&a.session)) {
            return Err("document fetch pending".into());
        }
        store
            .accept_mode(&a.session, crate::modes::Mode::NoBrief)
            .await
    }
    .await;
    local()
        .lock()
        .await
        .report(result.as_ref().err().map(String::as_str))
        .to_string()
}

struct SessionDriver {
    session: String,
}
impl Driver for SessionDriver {
    fn ending(&self) -> bool {
        super::inference::ending()
    }
    async fn turn(&mut self, request: &Value) -> Value {
        crate::inference::infer_tools(
            &mut super::inference::Writer(local()),
            &mut super::inference::Fetch,
            &super::inference::origin(),
            super::inference::candidate().as_ref(),
            request,
            || (js_sys::Date::now() / 1000.) as u64,
        )
        .await
    }
    async fn tool(&mut self, tool: &Tool) -> Value {
        dispatch(&self.session, tool).await
    }
}

#[wasm_bindgen]
pub async fn run_goal(session: String) -> String {
    let prepared = async {
        let local = local();
        let mut local = local.lock().await;
        if super::inference::ending() {
            return Err("sessions ended".to_string());
        }
        if let Some(why) = local.dispatch_refusal() {
            return Err(why.to_string());
        }
        let store = local.store().ok_or("locked")?;
        let live = store
            .live_goal_session(&session)
            .map_err(|_| "not a live session")?;
        let goal = store.goal(&session).cloned().ok_or("missing goal")?;
        store.check_tool(
            &session,
            &Tool::Exec {
                machine: live.bound_set[0].clone(),
                command: String::new(),
            },
        )?;
        if PENDING.with_borrow(|p| p.contains(&session)) {
            return Err("document fetch pending".into());
        }
        if !STARTED.with_borrow_mut(|s| s.insert(session.clone())) {
            return Err("goal already started".into());
        }
        Ok((goal, live.bound_set[0].clone()))
    }
    .await;
    let (goal, machine) = match prepared {
        Ok(v) => v,
        Err(why) => return json!({"refused":why}).to_string(),
    };
    let document = DOCUMENTS.with_borrow_mut(|d| d.remove(&session));
    #[cfg(feature = "tracer")]
    crate::testonly::session_point("goal_turn").await;
    goals::run(&mut SessionDriver { session }, &goal, &machine, document)
        .await
        .to_string()
}

async fn dispatch(session: &str, tool: &Tool) -> Value {
    {
        let local = local();
        let mut local = local.lock().await;
        if super::inference::ending() {
            return json!({"refused":"sessions ended"});
        }
        if let Some(why) = local.dispatch_refusal() {
            return json!({"refused":why});
        }
        let Some(store) = local.store() else {
            return json!({"refused":"locked"});
        };
        if let Err(why) = store.check_tool(session, tool) {
            return json!({"refused":why});
        }
        if matches!(tool, Tool::Typed { .. }) {
            return match store.model_typed_request(session, tool) {
                Ok(_) => json!({"refused":"awaiting operator approval"}),
                Err(why) => json!({"refused":why}),
            };
        }
    }
    if matches!(tool, Tool::Done { .. }) {
        return json!({"done":true});
    }
    let target = target(tool.machine());
    let mut journal = StoreJournal {
        local: local(),
        unavailable: false,
    };
    #[cfg(feature = "tracer")]
    let pins = crate::testonly::TestPins;
    #[cfg(not(feature = "tracer"))]
    let pins = crate::worker::NoPins;
    match tool {
        Tool::Exec { command, .. } => {
            let result = crate::harness::run_command(
                &pins,
                &mut journal,
                &target,
                command.as_bytes(),
                #[cfg(feature = "tracer")]
                false,
            )
            .await;
            match result {
                Ok(done) => {
                    json!({"stdout":String::from_utf8_lossy(&done.stdout),"stderr":String::from_utf8_lossy(&done.stderr),"exit_status":done.exit_status})
                }
                Err(why) => why.to_json(),
            }
        }
        Tool::Job { job, .. } => {
            let live = match journal.connection_session(tool.machine()).await {
                Ok(s) => s,
                Err(_) => return json!({"refused":"session unavailable"}),
            };
            match goals::check_job(&journal, tool.machine(), *job).await {
                goals::BoxAdmission::Held(why) | goals::BoxAdmission::Refused(why) => {
                    super::run::admission_refusal(
                        &pins,
                        &mut journal,
                        &live,
                        &target,
                        why,
                        #[cfg(feature = "tracer")]
                        false,
                    )
                    .await
                    .to_json()
                }
                goals::BoxAdmission::JobUnavailable(owner) => {
                    json!({"refused":"job unavailable","owner":owner})
                }
            }
        }
        _ => unreachable!("typed and done returned above"),
    }
}
fn target(machine: &str) -> Target {
    #[cfg(feature = "tracer")]
    let value = TARGETS
        .with_borrow(|t| t.get(machine).cloned())
        .unwrap_or(Value::Null);
    #[cfg(not(feature = "tracer"))]
    let value = Value::Null;
    Target {
        machine: machine.into(),
        relay: value["relay"].as_str().unwrap_or_default().into(),
        host: value["host"].as_str().unwrap_or_default().into(),
        port: value["port"].as_u64().unwrap_or(0) as u16,
        user: value["user"].as_str().unwrap_or_default().into(),
    }
}

#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub fn test_model_target(request: String) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(&request) else {
        return false;
    };
    if !v.as_object().is_some_and(|o| {
        o.len() == 5
            && ["machine", "relay", "host", "port", "user"]
                .iter()
                .all(|k| o.contains_key(*k))
    }) || !crate::harness::valid_request(&v)
        || !v["relay"]
            .as_str()
            .and_then(|s| s.strip_prefix("wss://127.0.0.1:"))
            .and_then(|s| s.strip_suffix('/'))
            .is_some_and(|p| p.parse::<u16>().is_ok_and(|p| p > 0))
        || v["host"] != "127.0.0.1"
    {
        return false;
    }
    TARGETS.with_borrow_mut(|t| t.insert(v["machine"].as_str().unwrap_or_default().into(), v));
    true
}

#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub async fn test_model_tool(session: String, call: String) -> String {
    match serde_json::from_str::<Value>(&call)
        .ok()
        .as_ref()
        .and_then(|v| Tool::parse(v).ok())
    {
        Some(tool) => dispatch(&session, &tool).await.to_string(),
        None => json!({"refused":"tool schema"}).to_string(),
    }
}
