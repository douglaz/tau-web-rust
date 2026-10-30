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
    static APPROVALS: RefCell<BTreeMap<String, tokio::sync::oneshot::Sender<Result<(), String>>>> = const { RefCell::new(BTreeMap::new()) };
    static DOCUMENTS: RefCell<BTreeMap<String, String>> = const { RefCell::new(BTreeMap::new()) };
    static PENDING: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
    static STARTED: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
    static FETCHES: RefCell<Vec<web_sys::AbortController>> = const { RefCell::new(Vec::new()) };
    #[cfg(feature = "tracer")]
    static TARGETS: RefCell<BTreeMap<String, Value>> = const { RefCell::new(BTreeMap::new()) };
}
pub(super) fn end() {
    APPROVALS.with_borrow_mut(|pending| {
        for (_, sender) in std::mem::take(pending) {
            let _ = sender.send(Err("sessions ended".into()));
        }
    });
    suspend();
    DOCUMENTS.with_borrow_mut(BTreeMap::clear);
}
pub(crate) fn end_session(session: &str) {
    super::inference::authority_changed();
    if let Some(sender) = APPROVALS.with_borrow_mut(|pending| pending.remove(session)) {
        let _ = sender.send(Err("session ended".into()));
    }
    DOCUMENTS.with_borrow_mut(|docs| docs.remove(session));
    PENDING.with_borrow_mut(|pending| pending.remove(session));
}
pub(super) fn suspend() {
    FETCHES.with_borrow_mut(|fetches| {
        for f in fetches.drain(..) {
            f.abort();
        }
    });
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
    let continuation = crate::lifecycle::owner().continuation()?;
    if !serde_json::from_str::<Value>(request).is_ok_and(|v| v.is_object()) {
        return Err("goal request".into());
    }
    let entry: Entry = serde_json::from_str(request).map_err(|_| "goal request")?;
    if super::inference::ending() {
        return Err("sessions ended".into());
    }
    continuation.check()?;
    if let Some(source) = &entry.document_source
        && (!goals::document_url(source) || web_sys::Request::new_with_str(source).is_err())
    {
        return Err("document source".into());
    }
    let source = entry.document_source.clone();
    let runtime = {
        let local = local();
        let mut local = local.lock().await;
        continuation.check()?;
        if super::inference::ending() {
            return Err("sessions ended".into());
        }
        if let Some(why) = local.dispatch_refusal() {
            return Err(why.into());
        }
        let runtime = local
            .store()
            .ok_or("locked")?
            .live_goal_session(&entry.session)?;
        local
            .store()
            .ok_or("locked")?
            .enter_goal(&entry.session, entry.text, entry.document_source)
            .await?;
        if source.is_some() {
            PENDING.with_borrow_mut(|p| p.insert(entry.session.clone()));
        }
        runtime
    };
    let result = async {
        #[cfg(feature = "tracer")]
        crate::testonly::session_point("document_send").await;
        current_document(&runtime, &continuation).await?;
        if let Some(source) = source
            && let Some(text) = fetch_document(&source, &runtime, &continuation).await?
        {
            let local = local();
            let mut local = local.lock().await;
            continuation.check()?;
            let store = local.store().ok_or("locked")?;
            store.check_current_session(&runtime)?;
            let safe = store.protect_output(&Value::String(text))?;
            DOCUMENTS.with_borrow_mut(|docs| {
                docs.insert(
                    entry.session.clone(),
                    safe.as_str().expect("protected text").into(),
                )
            });
        }
        Ok(())
    }
    .await;
    PENDING.with_borrow_mut(|p| p.remove(&entry.session));
    result
}

async fn current_document(
    session: &crate::binding::Session,
    continuation: &crate::lifecycle::Continuation,
) -> Result<(), String> {
    let local = local();
    let mut local = local.lock().await;
    continuation.check()?;
    if super::inference::ending() {
        return Err("sessions ended".into());
    }
    local
        .store()
        .ok_or("locked")?
        .check_current_session(session)
}

async fn fetch_document(
    source: &str,
    session: &crate::binding::Session,
    continuation: &crate::lifecycle::Continuation,
) -> Result<Option<String>, String> {
    use web_sys::{
        RequestCache, RequestCredentials, RequestInit, RequestMode, RequestRedirect, ResponseType,
    };
    let init = RequestInit::new();
    init.set_method("GET");
    init.set_redirect(RequestRedirect::Manual);
    init.set_mode(RequestMode::Cors);
    init.set_cache(RequestCache::NoStore);
    init.set_credentials(RequestCredentials::Omit);
    let controller = web_sys::AbortController::new().map_err(|_| "document abort controller")?;
    init.set_signal(Some(&controller.signal()));
    let request =
        web_sys::Request::new_with_str_and_init(source, &init).map_err(|_| "document request")?;
    let worker: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    current_document(session, continuation).await?;
    FETCHES.with_borrow_mut(|fs| fs.push(controller.clone()));
    let result = async {
        let response: web_sys::Response = JsFuture::from(worker.fetch_with_request(&request))
            .await
            .ok()?
            .dyn_into()
            .ok()?;
        if current_document(session, continuation).await.is_err() {
            return None;
        }
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
    #[cfg(feature = "tracer")]
    crate::testonly::session_point("document_release").await;
    current_document(session, continuation).await?;
    Ok(result)
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

#[wasm_bindgen]
pub async fn requirements_answer(request: String) -> String {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Answer {
        session: String,
        machine: String,
        candidate: u64,
        decision: Decision,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Decision {
        Approve,
        Reject,
    }
    let result = async {
        if !serde_json::from_str::<Value>(&request).is_ok_and(|v| v.is_object()) {
            return Err("proposal answer schema".into());
        }
        let a: Answer = serde_json::from_str(&request).map_err(|_| "proposal answer schema")?;
        #[cfg(feature = "tracer")]
        crate::testonly::session_point("requirements_writer").await;
        let local = local();
        let mut local = local.lock().await;
        if super::inference::ending() {
            return Err("sessions ended".into());
        }
        if let Some(why) = local.dispatch_refusal() {
            return Err(why.into());
        }
        let store = local.store().ok_or("locked")?;
        // A stale/malformed act must not consume a different candidate's waiter.
        if !store.pending_requirements_matches(&a.session, &a.machine, a.candidate) {
            return Err("stale proposal approval".into());
        }
        let result = match a.decision {
            Decision::Approve => {
                store
                    .approve_requirements(&a.session, &a.machine, a.candidate)
                    .await
            }
            Decision::Reject => store
                .reject_requirements(&a.session, &a.machine, a.candidate)
                .and(Err("proposal rejected".into())),
        };
        #[cfg(feature = "tracer")]
        crate::testonly::session_point("requirements_committed").await;
        let result = if super::inference::ending() {
            Err("sessions ended".into())
        } else {
            result
        };
        if let Some(sender) = APPROVALS.with_borrow_mut(|pending| pending.remove(&a.session)) {
            let _ = sender.send(result.clone());
        }
        result
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
    live: std::rc::Rc<crate::binding::Session>,
}
impl SessionDriver {
    // Preserve the context and an identifiable unsent step while current authority is withheld.
    async fn wait_current(&self) -> Result<(), String> {
        loop {
            let changed = super::inference::authority_notification();
            let mut notified = std::pin::pin!(changed.notified());
            notified.as_mut().enable();
            if self.ending() {
                return Err("sessions ended".into());
            }
            let ready = {
                let local = local();
                let mut local = local.lock().await;
                local
                    .store()
                    .ok_or("locked")?
                    .check_current_session(&self.live)
                    .is_ok()
            };
            if ready {
                return Ok(());
            }
            if self.ending() {
                return Err("session ended".into());
            }
            notified.await;
        }
    }
}
impl Driver for SessionDriver {
    fn ending(&self) -> bool {
        super::inference::ending() || self.live.ended.get()
    }
    async fn turn(&mut self, request: &Value) -> Value {
        if let Err(why) = self.wait_current().await {
            return json!({"refused":why});
        }
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
    async fn proposal(
        &mut self,
        candidate: u64,
        proposal: crate::declaration::Proposal,
        tool: &Tool,
    ) -> Result<(), String> {
        self.wait_current().await?;
        let continuation = crate::lifecycle::owner().continuation()?;
        let generation = super::inference::publication_generation();
        #[cfg(feature = "tracer")]
        crate::testonly::session_point("proposal_writer").await;
        let (receiver, report) = {
            let local = local();
            let mut local = local.lock().await;
            continuation.check()?;
            if super::inference::ending() {
                return Err("sessions ended".into());
            }
            if let Some(why) = local.dispatch_refusal() {
                return Err(why.into());
            }
            local.store().ok_or("locked")?.propose_requirements(
                &self.session,
                candidate,
                proposal,
                tool,
            )?;
            let (sender, receiver) = tokio::sync::oneshot::channel();
            APPROVALS.with_borrow_mut(|pending| pending.insert(self.session.clone(), sender));
            (receiver, local.report(None).to_string())
        };
        super::inference::publish_report(generation, self.session.clone(), report).await;
        let result = receiver
            .await
            .map_err(|_| "proposal approval cancelled".to_string())?;
        self.wait_current().await?;
        result
    }
    async fn tool(&mut self, tool: &Tool) -> Value {
        if let Err(why) = self.wait_current().await {
            return json!({"refused":why});
        }
        let continuation = crate::lifecycle::owner().continuation();
        let mut result = dispatch(&self.live, tool).await;
        if !continuation.as_ref().is_ok_and(|c| c.check().is_ok()) {
            if let Some(o) = result.as_object_mut() {
                o.remove("done");
            }
            result["historical"] = true.into();
            result["refused"] = "stale goal result; reconciliation required".into();
        }
        let current = local();
        let mut current = current.lock().await;
        let Some(store) = current.store() else {
            return json!({"refused":"locked"});
        };
        if let Err(why) = store.check_current_session(&self.live) {
            if let Some(o) = result.as_object_mut() {
                o.remove("done");
            }
            result["historical"] = true.into();
            result["refused"] = why.into();
        }
        let mut safe = store
            .protect_output(&result)
            .unwrap_or_else(|why| json!({"refused":why}));
        if let Err(why) = store.check_current_session(&self.live) {
            crate::jobs::historical(&mut safe, &why);
            if let Some(fields) = safe.as_object_mut() {
                fields.remove("done");
            }
            safe["historical"] = true.into();
            safe["refused"] = why.into();
        }
        safe
    }
}

#[wasm_bindgen]
pub async fn run_goal(session: String) -> String {
    let _continuation = match crate::lifecycle::owner().continuation() {
        Ok(c) => c,
        Err(why) => return json!({"refused":why}).to_string(),
    };
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
        store.check_goal_start(&session)?;
        if PENDING.with_borrow(|p| p.contains(&session)) {
            return Err("document fetch pending".into());
        }
        if !STARTED.with_borrow_mut(|s| s.insert(session.clone())) {
            return Err("goal already started".into());
        }
        Ok((goal, live))
    }
    .await;
    let (goal, live) = match prepared {
        Ok(v) => v,
        Err(why) => return json!({"refused":why}).to_string(),
    };
    let machine = live.bound_set[0].clone();
    let document = DOCUMENTS.with_borrow_mut(|d| d.remove(&session));
    #[cfg(feature = "tracer")]
    crate::testonly::session_point("goal_turn").await;
    goals::run(
        &mut SessionDriver { session, live },
        &goal,
        &machine,
        document,
    )
    .await
    .to_string()
}

async fn dispatch(live: &std::rc::Rc<crate::binding::Session>, tool: &Tool) -> Value {
    let session = &live.identity;
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
        if let Err(why) = store.check_current_session(live) {
            return json!({"refused":why});
        }
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
                Some(live),
                #[cfg(feature = "tracer")]
                false,
            )
            .await;
            let result = match result {
                Ok(done) => {
                    json!({"stdout":String::from_utf8_lossy(&done.stdout),"stderr":String::from_utf8_lossy(&done.stderr),"exit_status":done.exit_status})
                }
                Err(why) => why.to_json(),
            };
            journal
                .release(result)
                .await
                .unwrap_or_else(|why| json!({"refused":why}))
        }
        Tool::Job { job, .. } => {
            let live = match journal.connection_session(tool.machine(), Some(live)).await {
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
        Some(tool) => {
            let live = {
                let local = local();
                let mut local = local.lock().await;
                local
                    .store()
                    .ok_or_else(|| "locked".to_string())
                    .and_then(|s| s.live_goal_session(&session))
            };
            match live {
                Ok(live) => dispatch(&live, &tool).await.to_string(),
                Err(why) => json!({"refused":why}).to_string(),
            }
        }
        None => json!({"refused":"tool schema"}).to_string(),
    }
}

#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub fn test_document_state(session: String) -> String {
    json!({"retained":DOCUMENTS.with_borrow(|docs| docs.contains_key(&session)),
        "pending":PENDING.with_borrow(|pending| pending.contains(&session))})
    .to_string()
}
