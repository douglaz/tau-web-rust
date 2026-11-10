//! Private immutable worker query results and the fields consumed by original comparisons.
use crate::logical_checks::Observe;
use crate::{completion, history, reader_checks};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};
pub const EXPRESSION: &str = "(async () => {\n                    const module = await import(new URL('./pkg/tau_web.js', self.location.href).href);\n                    return JSON.parse(await module.store_state());\n                })()";
static CAPTURES: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static USES: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static OPERATIONS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
const ERROR: &str = "original worker query/field/operation correspondence mismatch";
/// A computed assertion result whose original comparison receipts move into the check.
/// Dropping the result leaves its receipts unconsumed.
#[must_use]
pub struct Predicate {
    holds: bool,
    reboot: Option<crate::reboot_evidence::Reboot>,
    comparisons: Vec<usize>,
    views: Vec<crate::view_inputs::Predicate>,
    files: Vec<crate::file_inputs::Predicate>,
    displayed: Vec<crate::observer::DisplayedComparison>,
}
impl From<bool> for Predicate {
    fn from(holds: bool) -> Self {
        Self {
            holds,
            reboot: None,
            comparisons: Vec::new(),
            views: Vec::new(),
            files: Vec::new(),
            displayed: Vec::new(),
        }
    }
}
impl std::ops::Not for Predicate {
    type Output = Self;
    fn not(mut self) -> Self {
        self.holds = !self.holds;
        self
    }
}
impl From<crate::view_inputs::Predicate> for Predicate {
    fn from(value: crate::view_inputs::Predicate) -> Self {
        Self {
            holds: value.continues(),
            reboot: None,
            comparisons: Vec::new(),
            views: vec![value],
            files: Vec::new(),
            displayed: Vec::new(),
        }
    }
}
impl From<crate::file_inputs::Predicate> for Predicate {
    fn from(value: crate::file_inputs::Predicate) -> Self {
        Self {
            holds: value.continues(),
            reboot: None,
            comparisons: Vec::new(),
            views: Vec::new(),
            files: vec![value],
            displayed: Vec::new(),
        }
    }
}
impl From<crate::observer::DisplayedComparison> for Predicate {
    fn from(value: crate::observer::DisplayedComparison) -> Self {
        Self {
            holds: value.continues(),
            reboot: None,
            comparisons: Vec::new(),
            views: Vec::new(),
            files: Vec::new(),
            displayed: vec![value],
        }
    }
}
impl From<crate::reboot_evidence::Reboot> for Predicate {
    fn from(reboot: crate::reboot_evidence::Reboot) -> Self {
        let holds = reboot.holds();
        Self {
            reboot: Some(reboot),
            ..Self::from(holds)
        }
    }
}
impl Predicate {
    pub fn take_reboot(&mut self) -> Option<crate::reboot_evidence::Reboot> {
        self.reboot.take()
    }
    pub fn continues(&self) -> bool {
        self.holds
    }
    pub fn and(self, other: Self) -> Self {
        let mut comparisons = self.comparisons;
        comparisons.extend(other.comparisons);
        let mut views = self.views;
        views.extend(other.views);
        let mut files = self.files;
        files.extend(other.files);
        let mut displayed = self.displayed;
        displayed.extend(other.displayed);
        assert!(self.reboot.is_none() || other.reboot.is_none());
        Self {
            reboot: self.reboot.or(other.reboot),
            holds: self.holds && other.holds,
            comparisons,
            views,
            files,
            displayed,
        }
    }
    pub fn checked(self, binding: &crate::predicate_inputs::Primary) -> bool {
        let (predicate, instance, at, cursor) = binding.coordinates();
        let case = history::active_case_id();
        let mut holds = self.holds;
        let mut rows = USES.lock().unwrap();
        for index in self.comparisons {
            let row = &mut rows[index];
            if row["predicate"] != predicate
                || row["case"] != json!(case)
                || !row["check_ns"].is_null()
            {
                holds = false;
                continue;
            }
            row["check_ns"] = json!(at);
            row["check_cursor"] = json!(cursor);
            row["instance"] = json!(instance);
        }
        for view in self.views {
            holds &= view.checked(binding);
        }
        for file in self.files {
            holds &= file.checked(binding);
        }
        for displayed in self.displayed {
            holds &= displayed.checked(binding);
        }
        holds
    }
}
// Each expression retains its original short-circuit position, including awaited queries.
macro_rules! all {
    ($first:expr $(, $rest:expr)* $(,)?) => {{
        let mut result = $crate::state_inputs::Predicate::from($first);
        $(if result.continues() { result = result.and($crate::state_inputs::Predicate::from($rest)); })*
        result
    }};
}
pub(crate) use all;
struct Original {
    value: crate::cdp::OriginalEvaluation,
    source: usize,
}
#[derive(Clone)]
pub struct State {
    original: Arc<Original>,
    path: String,
}
impl std::ops::Deref for State {
    type Target = Value;
    fn deref(&self) -> &Value {
        self.original
            .value
            .pointer(&self.path)
            .unwrap_or(&Value::Null)
    }
}
impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&**self, f)
    }
}
impl State {
    pub fn project(&self, path: &str) -> Self {
        Self {
            original: self.original.clone(),
            path: format!("{}{path}", self.path),
        }
    }
    pub fn same_at(&self, predicate: &'static str, other: &Self, fields: &[&str]) -> Predicate {
        self.compare_value(predicate, other, fields, "identity", other)
    }
    pub fn replayed_at(&self, predicate: &'static str, other: &Self) -> Predicate {
        self.same_at(predicate, other, &[""])
    }
    fn compare_value(
        &self,
        predicate: &'static str,
        other: &Self,
        fields: &[&str],
        transform: &str,
        right: &Value,
    ) -> Predicate {
        let mut comparisons = Vec::new();
        let result = fields
            .iter()
            .all(|p| self.compare_field(other, p, right, transform, &mut comparisons));
        let paths = |s: &Self| {
            fields
                .iter()
                .map(|p| format!("{}{p}", s.path))
                .collect::<Vec<_>>()
        };
        let mut uses = USES.lock().unwrap();
        let index = uses.len();
        uses.push(json!({"predicate":predicate,"sources":[self.original.source,other.original.source],"paths":[paths(self),paths(other)],"transform":transform,"comparisons":comparisons,"result":result,"case":history::active_case_id(),"at_ns":completion::now(),"history_cursor":history::cursor(),"check_ns":null,"check_cursor":null,"instance":null}));
        Predicate {
            holds: result,
            reboot: None,
            comparisons: vec![index],
            views: Vec::new(),
            files: Vec::new(),
            displayed: Vec::new(),
        }
    }
    fn compare_field(
        &self,
        other: &Self,
        field: &str,
        right: &Value,
        transform: &str,
        comparisons: &mut Vec<Value>,
    ) -> bool {
        let result = self.pointer(field).unwrap_or(&Value::Null)
            == right.pointer(field).unwrap_or(&Value::Null);
        comparisons.push(json!({"sources":[self.original.source,other.original.source],"paths":[format!("{}{field}",self.path),format!("{}{field}",other.path)],"transform":transform,"result":result}));
        result
    }
    pub fn failed_append_at(
        &self,
        predicate: &'static str,
        before: &Self,
        replayed: &Self,
    ) -> Predicate {
        let mut comparisons = Vec::new();
        let mut expected = (**before).clone();
        for session in expected["sessions"].as_array_mut().expect("sessions") {
            session["session_state"] = json!("waiting");
            session["readiness_reason"] =
                json!("journal append outcome uncertain; reopen to validate before further work");
        }
        let result =
            self.compare_field(before, "", &expected, "append_fail_stop", &mut comparisons)
                && self.compare_field(replayed, "/records", replayed, "identity", &mut comparisons);
        let mut uses = USES.lock().unwrap();
        let index = uses.len();
        uses.push(json!({"predicate":predicate,"sources":[self.original.source,before.original.source,replayed.original.source],"paths":[[self.path.clone()],[before.path.clone()],[format!("{}/records",replayed.path)]],"transform":"failed_append","comparisons":comparisons,"result":result,"case":history::active_case_id(),"at_ns":completion::now(),"history_cursor":history::cursor(),"check_ns":null,"check_cursor":null,"instance":null}));
        Predicate {
            holds: result,
            reboot: None,
            comparisons: vec![index],
            views: Vec::new(),
            files: Vec::new(),
            displayed: Vec::new(),
        }
    }
    pub fn goal_usage_at(
        &self,
        predicate: &'static str,
        before: &Self,
        session: &crate::observer::GoalSession,
    ) -> Result<Predicate, String> {
        let mut expected = (**before).clone();
        for view in expected["sessions"].as_array_mut().expect("sessions") {
            if view["identity"] == **session {
                let mut spent = tau_web::inference_limits::Decimal::parse(
                    view["inference_limits"]["observed_spend"]
                        .as_str()
                        .ok_or("original observed usage")
                        .checked("goal.usage.text")?,
                )
                .checked("goal.usage.decimal")?;
                spent.add(&tau_web::inference_limits::Decimal::parse("0.02")?);
                view["inference_limits"]["observed_spend"] = spent.text().into();
            }
        }
        Ok(self.compare_value(predicate, before, &["/sessions"], "goal_usage", &expected))
    }
}
pub async fn inspect(
    site: &'static str,
    run: &crate::Run<'_>,
    worker: &crate::Worker,
) -> Result<State, String> {
    let start = completion::now();
    let cursor = history::cursor();
    crate::seed_operations::operation("inspect", worker, None);
    let value = run
        .browser
        .evaluate_original(&worker.session, EXPRESSION)
        .await?;
    let query_ok = value.within(start, cursor)
        && value.matches_hash(
            &worker.session,
            completion::inventory()["state_query_sha256"]
                .as_str()
                .unwrap_or(""),
        );
    let (identity, page) = history::worker_identity(&worker.session);
    let mut rows = CAPTURES.lock().unwrap();
    let source = rows.len() + 1;
    rows.push(json!({"site":site,"source":source,"page":page,"worker":identity,"case":history::active_case_id(),"start_ns":start,"end_ns":completion::now(),"start_cursor":cursor,"end_cursor":history::cursor(),"receiver_ok":history::selected_worker_matches(page,worker),"query_ok":query_ok}));
    Ok(State {
        original: Arc::new(Original { value, source }),
        path: String::new(),
    })
}
struct OperationPrivate {
    worker: crate::Worker,
    expected: Option<(Option<String>, String, Value)>,
    active: bool,
    dispatches: usize,
    script: Vec<Value>,
    script_items: usize,
}
static OPERATION_PRIVATE: Mutex<Vec<OperationPrivate>> = Mutex::new(Vec::new());
pub struct Operation(usize);
impl Operation {
    pub fn begin(site: &str, kind: &'static str, worker: &crate::Worker) -> Self {
        let (identity, page) = history::worker_identity(&worker.session);
        let mut private = OPERATION_PRIVATE.lock().unwrap();
        let mut rows = OPERATIONS.lock().unwrap();
        let index = rows.len();
        private.push(OperationPrivate {
            worker: worker.clone(),
            expected: None,
            active: true,
            dispatches: 0,
            script: Vec::new(),
            script_items: 0,
        });
        rows.push(json!({"source":index+1,"site":site,"kind":kind,"page":page,"worker":identity,"case":history::active_case_id(),"start_ns":completion::now(),"end_ns":null,"start_cursor":history::cursor(),"end_cursor":null,"receiver_ok":history::selected_worker_matches(page,worker),"input_ok":true,"completed":false,"dispatches":0,"successor":null,"session":null,"script_items":0}));
        Self(index)
    }
    fn coordinates(&self) -> (String, String, usize) {
        let rows = OPERATIONS.lock().unwrap();
        let row = &rows[self.0];
        let site = row["site"].as_str().unwrap().to_owned();
        let case = row["case"].as_str().unwrap_or("").to_owned();
        let ordinal = rows[..self.0]
            .iter()
            .filter(|r| r["site"] == site && r["case"] == row["case"])
            .count();
        (site, case, ordinal)
    }
    fn input(&self, ok: bool) {
        let mut rows = OPERATIONS.lock().unwrap();
        rows[self.0]["input_ok"] = json!(rows[self.0]["input_ok"] == true && ok);
    }
    fn expect(&self, session: Option<&str>, method: &str, params: Value) {
        OPERATION_PRIVATE.lock().unwrap()[self.0].expected =
            Some((session.map(str::to_owned), method.into(), params));
    }
    pub fn evaluate(&self, worker: &crate::Worker, expression: &str) {
        self.expect(
            Some(&worker.session),
            "Runtime.evaluate",
            json!({"expression":expression,"awaitPromise":true,"returnByValue":true}),
        );
    }
    fn module(&self, worker: &crate::Worker, body: &str) {
        self.evaluate(worker,&format!("(async()=>{{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);{body}}})()"));
    }
    pub fn request(&self, run: &crate::Run<'_>, worker: &crate::Worker, args: &Value) {
        let (site, case, ordinal) = self.coordinates();
        self.input(crate::state_operation_recipes::request(
            &site, run, args, &case, ordinal,
        ));
        let mut expression = crate::operation_windows::original_run_expression(args);
        if OPERATIONS.lock().unwrap()[self.0]["kind"] == "collect" {
            expression = expression.replace("module.run_command(", "module.collect_jobs(");
        }
        self.evaluate(worker, &expression);
    }
    pub fn reload(&self, tab: &crate::Tab) {
        let page_ok = OPERATIONS.lock().unwrap()[self.0]["page"] == history::page_id(&tab.session);
        self.input(page_ok);
        self.expect(Some(&tab.session), "Page.reload", json!({}));
    }
    fn bind_goal(
        &self,
        worker: &crate::Worker,
        session: &crate::observer::GoalSession,
        calls: &[Value],
        expected: &[Value],
    ) {
        self.input(session.matches_receiver(worker) && calls == expected);
        OPERATION_PRIVATE.lock().unwrap()[self.0].script = expected.to_vec();
        OPERATIONS.lock().unwrap()[self.0]["session"] = session.operand();
    }
    pub fn goal_input(
        &self,
        run: &crate::Run<'_>,
        worker: &crate::Worker,
        session: &crate::observer::GoalSession,
        calls: &[Value],
    ) {
        let (site, case, ordinal) = self.coordinates();
        let expected = crate::state_operation_recipes::goal_script(&site, run, &case, ordinal);
        self.bind_goal(worker, session, calls, expected.as_deref().unwrap_or(&[]));
        self.input(expected.is_some());
        self.module(
            worker,
            &format!("return JSON.parse(await m.run_goal({}));", json!(session)),
        );
    }
    pub fn goal_turn(
        &self,
        run: &crate::Run<'_>,
        worker: &crate::Worker,
        session: &crate::observer::GoalSession,
    ) {
        let (site, case, ordinal) = self.coordinates();
        let expected = crate::state_operation_recipes::goal_script(&site, run, &case, ordinal);
        let calls = run
            .aggregator
            .state
            .lock()
            .unwrap()
            .script
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        self.bind_goal(worker, session, &calls, expected.as_deref().unwrap_or(&[]));
        self.input(expected.is_some());
        self.module(worker, "self.releaseGoalTurn();return true;");
    }
    pub fn finish(self) {
        self.finish_when(true);
    }
    pub fn finish_when(self, finished: bool) {
        let private = OPERATION_PRIVATE.lock().unwrap();
        let p = &private[self.0];
        OPERATIONS.lock().unwrap()[self.0]["completed"] =
            json!(finished && p.dispatches == 1 && p.script_items == p.script.len());
    }
    pub fn successor(self, worker: &crate::Worker) {
        let (identity, page) = history::worker_identity(&worker.session);
        let original = OPERATION_PRIVATE.lock().unwrap()[self.0].worker.clone();
        let page_ok = OPERATIONS.lock().unwrap()[self.0]["page"] == page;
        self.input(
            original != *worker && history::selected_worker_matches(page, worker) && page_ok,
        );
        OPERATIONS.lock().unwrap()[self.0]["successor"] = json!(identity);
        self.finish();
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        OPERATION_PRIVATE.lock().unwrap()[self.0].active = false;
        let mut rows = OPERATIONS.lock().unwrap();
        rows[self.0]["end_ns"] = json!(completion::now());
        rows[self.0]["end_cursor"] = json!(history::cursor());
    }
}
pub fn dispatch(session: Option<&str>, method: &str, params: &Value) {
    let mut private = OPERATION_PRIVATE.lock().unwrap();
    let mut rows = OPERATIONS.lock().unwrap();
    for (index, p) in private.iter_mut().enumerate().filter(|(_, p)| p.active) {
        if p.expected
            .as_ref()
            .is_some_and(|(s, m, v)| s.as_deref() == session && m == method && v == params)
        {
            if p.dispatches == 0 {
                rows[index]["start_ns"] = json!(completion::now());
                rows[index]["start_cursor"] = json!(history::cursor());
            }
            p.dispatches += 1;
            rows[index]["dispatches"] = json!(p.dispatches);
        }
    }
}
pub fn script_item(value: &Value) {
    let mut private = OPERATION_PRIVATE.lock().unwrap();
    let mut rows = OPERATIONS.lock().unwrap();
    for (index, p) in private
        .iter_mut()
        .enumerate()
        .filter(|(_, p)| p.active && !p.script.is_empty())
    {
        let ok = p.script.get(p.script_items) == Some(value);
        p.script_items += 1;
        rows[index]["script_items"] = json!(p.script_items);
        rows[index]["input_ok"] = json!(rows[index]["input_ok"] == true && ok);
    }
}

pub fn snapshot() -> Value {
    json!({"captures":*CAPTURES.lock().unwrap(),"uses":*USES.lock().unwrap(),"operations":*OPERATIONS.lock().unwrap()})
}
pub fn validate(report: &Value) -> Result<(), String> {
    validate_with(report, completion::inventory())
}
fn validate_with(report: &Value, key: &Value) -> Result<(), String> {
    let value = &report["state_inputs"];
    if value.as_object().is_none_or(|o| o.len() != 3) {
        return Err(ERROR.into());
    }
    let captures = value["captures"].as_array().ok_or(ERROR)?;
    let uses = value["uses"].as_array().ok_or(ERROR)?;
    let operations = value["operations"].as_array().ok_or(ERROR)?;
    let rules = key["state_comparison_sources"].as_object().ok_or(ERROR)?;
    for rule in rules.values() {
        if rule.as_object().is_none_or(|o| o.len() != 7)
            || rule["sources"]
                .as_array()
                .is_none_or(|s| !(2..=3).contains(&s.len()))
            || !valid_paths(&rule["paths"])
            || !rule["result"].is_boolean()
            || !matches!(
                rule["transform"].as_str(),
                Some("identity" | "goal_usage" | "failed_append")
            )
            || !matches!(
                rule["page_role"].as_str(),
                Some("tracer" | "served" | "invocation")
            )
            || !rule["operation"]
                .as_str()
                .is_some_and(|s| operation_kind(s, true))
        {
            return Err(ERROR.into());
        }
        for source in rule["sources"].as_array().ok_or(ERROR)? {
            if source
                .as_array()
                .is_none_or(|s| !(3..=4).contains(&s.len()))
                || !source[0].is_string()
                || !matches!(source[1].as_str(), Some("once" | "each" | "saved"))
                || !valid_phase(source[2].as_str(), key)
                || source.get(3).is_some_and(|anchor| !anchor.is_string())
            {
                return Err(ERROR.into());
            }
        }
    }
    let states = reader_checks::caller_states(report);
    let workers = history::worker_states(report);
    let pages = history::source_page_states(report)?;
    let events = report["helper_history"].as_array().ok_or(ERROR)?;
    let duration = report["duration_ns"].as_u64().ok_or(ERROR)?;
    let mut previous = 0;
    for (index, row) in captures.iter().enumerate() {
        validate_interval(row, &workers, events, duration)?;
        let cursor = row["start_cursor"].as_u64().ok_or(ERROR)? as usize;
        let owner = states
            .get(cursor)
            .and_then(|s| s.owner.as_ref())
            .ok_or(ERROR)?;
        if row.as_object().is_none_or(|o| o.len() != 11)
            || row["source"] != index + 1
            || !row["site"].is_string()
            || row["query_ok"] != true
            || row["case"]
                != json!(if owner.1 == "inside" {
                    Some(owner.2.as_str())
                } else {
                    None
                })
            || row["start_cursor"] != row["end_cursor"]
            || row["start_ns"].as_u64().ok_or(ERROR)? < previous
        {
            return Err(ERROR.into());
        }
        previous = row["end_ns"].as_u64().ok_or(ERROR)?;
    }
    let mut previous_operation_end = 0;
    let reload_sites = key["state_reload_sites"].as_array().ok_or(ERROR)?;
    for (index, row) in operations.iter().enumerate() {
        if row.as_object().is_none_or(|o| o.len() != 17)
            || row["source"] != index + 1
            || !row["site"].is_string()
            || !row["kind"]
                .as_str()
                .is_some_and(|s| operation_kind(s, false))
            || row["completed"] != true
            || row["input_ok"] != true
            || row["dispatches"] != 1
            || row["start_ns"]
                .as_u64()
                .is_none_or(|t| t < previous_operation_end)
        {
            return Err(ERROR.into());
        }
        validate_interval(row, &workers, events, duration)?;
        let cursor = row["start_cursor"].as_u64().ok_or(ERROR)? as usize;
        let until = row["end_cursor"].as_u64().ok_or(ERROR)? as usize;
        let owner = states
            .get(cursor)
            .and_then(|s| s.owner.as_ref())
            .ok_or(ERROR)?;
        if row["case"]
            != json!(if owner.1 == "inside" {
                Some(owner.2.as_str())
            } else {
                None
            })
            || states.get(until).is_none_or(|s| {
                s.owner != states[cursor].owner || s.invocation != states[cursor].invocation
            })
        {
            return Err(ERROR.into());
        }
        if row["kind"] == "reload" {
            let page = row["page"].as_u64().ok_or(ERROR)?;
            if !reload_sites.contains(&row["site"])
                || row["successor"].as_u64().is_none_or(|w| w == 0)
                || row["successor"] == row["worker"]
                || row["successor"] != json!(workers.get(until).and_then(|w| w.get(&page)))
                || row["script_items"] != 0
                || !row["session"].is_null()
            {
                return Err(ERROR.into());
            }
        } else if !row["successor"].is_null() {
            return Err(ERROR.into());
        }
        previous_operation_end = row["end_ns"].as_u64().ok_or(ERROR)?;
    }
    crate::state_reload_domains::validate(report, key)?;
    let resolved_operations = crate::state_operation_domains::validate(report, key)?;
    let primary = report["primary_history"].as_array().ok_or(ERROR)?;
    let expected: Vec<_> = primary
        .iter()
        .filter_map(|p| {
            p["id"]
                .as_str()
                .and_then(|s| s.rsplit_once(".i"))
                .and_then(|(s, _)| rules.get(s).map(|r| (p, s, r)))
        })
        .collect();
    if uses.len() != expected.len() {
        return Err(ERROR.into());
    }
    let mut consumed = BTreeSet::new();
    previous = 0;
    for (row, (check, predicate, rule)) in uses.iter().zip(expected) {
        let instance = row["instance"].as_u64().ok_or(ERROR)? as usize;
        if row["sources"]
            .as_array()
            .is_none_or(|s| s.len() != rule["sources"].as_array().unwrap().len())
        {
            return Err(ERROR.into());
        }
        if instance == 0
            || row.as_object().is_none_or(|o| o.len() != 12)
            || row["predicate"] != predicate
            || row["case"] != check["case"]
            || check["id"] != format!("{predicate}.i{instance:03}")
            || row["check_ns"] != check["at_ns"]
            || row["check_cursor"] != check["history_cursor"]
            || row["paths"] != *paths_at(&rule["paths"], instance)?
            || row["transform"] != rule["transform"]
            || row["result"] != rule["result"]
            || !matches!(
                rule["transform"].as_str(),
                Some("identity" | "goal_usage" | "failed_append")
            )
        {
            return Err(ERROR.into());
        }
        let at = row["at_ns"].as_u64().ok_or(ERROR)?;
        let cursor = row["history_cursor"].as_u64().ok_or(ERROR)? as usize;
        if at < previous
            || at > check["at_ns"].as_u64().ok_or(ERROR)?
            || row["history_cursor"] != row["check_cursor"]
        {
            return Err(ERROR.into());
        }
        let owner = states
            .get(cursor)
            .and_then(|s| s.owner.as_ref())
            .ok_or(ERROR)?;
        let invocation = states[cursor].invocation;
        let mut inputs = Vec::new();
        for (side, descriptor) in rule["sources"].as_array().ok_or(ERROR)?.iter().enumerate() {
            let site = descriptor[0].as_str().ok_or(ERROR)?;
            let mode = descriptor[1].as_str().ok_or(ERROR)?;
            let phase = descriptor[2].as_str().ok_or(ERROR)?;
            if !matches!(mode, "once" | "each" | "saved") || !valid_phase(Some(phase), key) {
                return Err(ERROR.into());
            }
            let candidates: Vec<_> = captures
                .iter()
                .filter(|c| c["site"] == site)
                .filter(|c| {
                    c["start_cursor"]
                        .as_u64()
                        .and_then(|n| states.get(n as usize))
                        .is_some_and(|s| {
                            s.invocation == invocation
                                && s.owner.as_ref().is_some_and(|o| {
                                    o.0 == owner.0
                                        && if phase == "inside" {
                                            o.1 == "inside" && o.2 == owner.2
                                        } else if phase == "outside" {
                                            o.1 == "after"
                                        } else {
                                            o.1 == "inside"
                                                && phase.strip_prefix("case:") == Some(o.2.as_str())
                                        }
                                })
                        })
                })
                .collect();
            let capture = *candidates
                .get(if mode == "each" { instance - 1 } else { 0 })
                .ok_or(ERROR)?;
            if row["sources"][side] != capture["source"]
                || capture["end_ns"].as_u64().ok_or(ERROR)? > at
            {
                return Err(ERROR.into());
            }
            if let Some(anchor) = descriptor.get(3).and_then(Value::as_str) {
                crate::file_domains::checkpoint(
                    report,
                    &json!({"at_ns":capture["end_ns"],"history_cursor":capture["end_cursor"]}),
                    capture["case"].as_str().ok_or(ERROR)?,
                    anchor,
                    if mode == "each" { instance } else { 1 },
                )?;
            }
            consumed.insert(capture["source"].as_u64().ok_or(ERROR)?);
            inputs.push(capture);
        }
        if inputs
            .iter()
            .map(|i| i["source"].as_u64().ok_or(ERROR))
            .collect::<Result<BTreeSet<_>, _>>()?
            .len()
            != inputs.len()
        {
            return Err(ERROR.into());
        }
        let role = if rule["page_role"] == "invocation" {
            if invocation == 2 { "served" } else { "tracer" }
        } else {
            rule["page_role"].as_str().ok_or(ERROR)?
        };
        if !matches!(role, "tracer" | "served") {
            return Err(ERROR.into());
        }
        for input in &inputs {
            let c = input["start_cursor"].as_u64().ok_or(ERROR)? as usize;
            if input["page"].as_u64() != pages.get(c).and_then(|p| p.get(role)).copied() {
                return Err(ERROR.into());
            }
        }
        if row["comparisons"] != expected_comparisons(rule, row)? {
            return Err(format!("{ERROR}: original inner comparison {predicate}"));
        }
        if rule["sources"][0][2] == "inside" && rule["sources"][0].get(3).is_none() {
            let (anchor, ordinal) = if rule["sources"][0][1] == "saved" {
                primary
                    .iter()
                    .filter(|p| p["case"] == check["case"])
                    .find_map(|p| {
                        let (id, n) = p["id"].as_str()?.rsplit_once(".i")?;
                        (rules.get(id)?["sources"][0][0] == rule["sources"][0][0])
                            .then(|| n.parse::<usize>().ok().map(|n| (id, n)))
                            .flatten()
                    })
                    .ok_or(ERROR)?
            } else {
                (
                    rule["sources"][0]
                        .get(3)
                        .and_then(Value::as_str)
                        .unwrap_or(predicate),
                    instance,
                )
            };
            crate::file_domains::checkpoint(
                report,
                &json!({"at_ns":inputs[0]["end_ns"],"history_cursor":inputs[0]["end_cursor"]}),
                check["case"].as_str().ok_or(ERROR)?,
                anchor,
                ordinal,
            )?;
        }
        let before = inputs[1]["end_ns"].as_u64().ok_or(ERROR)?;
        let after = inputs[0]["start_ns"].as_u64().ok_or(ERROR)?;
        if before > after {
            return Err(ERROR.into());
        }
        let operation = rule["operation"].as_str().ok_or(ERROR)?;
        if !operation_kind(operation, true) {
            return Err(ERROR.into());
        }
        let bracketed = if operation == "binding.prepare" {
            let matching = events
                .iter()
                .enumerate()
                .filter(|(n, event)| {
                    if event["event"] != "call_start"
                        || event["kind"] != "binding.prepare"
                        || event["page"] != inputs[1]["page"]
                        || event["at_ns"].as_u64().is_none_or(|t| t < before)
                        || states[*n].invocation != invocation
                        || states[*n].owner.as_ref() != Some(owner)
                    {
                        return false;
                    }
                    let end = events
                        .iter()
                        .enumerate()
                        .skip(*n + 1)
                        .find(|(_, e)| e["event"] == "call_end" && e["call"] == event["call"]);
                    end.is_some_and(|(n, e)| {
                        e["at_ns"].as_u64().is_some_and(|t| t <= after)
                            && inputs[0]["worker"]
                                == json!(workers.get(n + 1).and_then(|w| {
                                    w.get(&inputs[0]["page"].as_u64().unwrap_or(0))
                                }))
                    })
                })
                .count();
            matching == 1
        } else if operation == "declaration.outcome" {
            report["observer_calls"]
                .as_array()
                .ok_or(ERROR)?
                .iter()
                .any(|op| {
                    op["kind"] == operation
                        && op["page"] == inputs[1]["page"]
                        && op["start_ns"].as_u64().is_some_and(|t| t >= before)
                        && op["end_ns"].as_u64().is_some_and(|t| t <= after)
                })
        } else if matches!(
            operation,
            "file:setup.request"
                | "file:setup.message"
                | "window:hold.evidence"
                | "window:main.hidden"
        ) {
            let source = if operation.starts_with("window:") {
                "operation_windows"
            } else {
                "file_requests"
            };
            let candidates: Vec<_> = report[source]
                .as_array()
                .ok_or(ERROR)?
                .iter()
                .filter(|op| {
                    op["case"] == check["case"]
                        && match operation {
                            "file:setup.request" => {
                                matches!(op["kind"].as_str(), Some("setup.run" | "setup.collect"))
                            }
                            "file:setup.message" => op["kind"] == "setup.message",
                            "window:hold.evidence" | "window:main.hidden" => {
                                op["site"] == operation.strip_prefix("window:").unwrap()
                            }
                            _ => false,
                        }
                })
                .collect();
            candidates.get(instance - 1).is_some_and(|op| {
                op["page"] == inputs[1]["page"]
                    && op["worker"] == inputs[1]["worker"]
                    && op["start_ns"].as_u64().is_some_and(|t| t >= before)
                    && op["end_ns"].as_u64().is_some_and(|t| t <= after)
            })
        } else {
            let references = rule["operations"]
                .as_array()
                .filter(|a| !a.is_empty())
                .ok_or(ERROR)?;
            let mut indices = BTreeSet::new();
            let mut previous = before;
            let mut valid = true;
            for reference in references {
                if reference
                    .as_array()
                    .is_none_or(|a| !(2..=3).contains(&a.len()))
                {
                    return Err(ERROR.into());
                }
                let source = reference[0].as_str().ok_or(ERROR)?;
                let n = match reference[1].as_str() {
                    Some("once") => 1,
                    Some("each") => instance,
                    Some("first_of_pair") => instance
                        .checked_mul(2)
                        .and_then(|n| n.checked_sub(1))
                        .ok_or(ERROR)?,
                    Some("second_of_pair") => instance.checked_mul(2).ok_or(ERROR)?,
                    _ => return Err(ERROR.into()),
                };
                let case = reference
                    .get(2)
                    .and_then(Value::as_str)
                    .unwrap_or(check["case"].as_str().ok_or(ERROR)?);
                let index = if let Some(site) = source.strip_prefix("reload_site:") {
                    let matching: Vec<_> = operations
                        .iter()
                        .enumerate()
                        .filter(|(_, op)| {
                            op["kind"] == "reload" && op["site"] == site && op["case"] == case
                        })
                        .collect();
                    if matching.len() != 1 || n != 1 {
                        return Err(ERROR.into());
                    }
                    matching[0].0
                } else {
                    resolved_operations
                        .iter()
                        .find(|r| r.source == source && r.case == case && r.instance == n)
                        .ok_or(ERROR)?
                        .index
                };
                let op = &operations[index];
                let start = op["start_ns"].as_u64().ok_or(ERROR)?;
                let end = op["end_ns"].as_u64().ok_or(ERROR)?;
                valid &= indices.insert(index)
                    && op["page"] == inputs[1]["page"]
                    && op["worker"] == inputs[1]["worker"]
                    && start >= previous
                    && end <= after;
                previous = end;
            }
            valid
        };
        if !bracketed {
            return Err(format!("{ERROR}: {predicate}"));
        }
        previous = at;
    }
    if consumed.len() != captures.len() {
        return Err(ERROR.into());
    }
    Ok(())
}
fn operation_kind(kind: &str, helper: bool) -> bool {
    matches!(
        kind,
        "run" | "collect" | "reload" | "goal.drive" | "goal.turn"
    ) || helper
        && matches!(
            kind,
            "declaration.outcome"
                | "binding.prepare"
                | "file:setup.request"
                | "file:setup.message"
                | "window:hold.evidence"
                | "window:main.hidden"
        )
}
fn expected_comparisons(rule: &Value, row: &Value) -> Result<Value, String> {
    let sources = row["sources"].as_array().ok_or(ERROR)?;
    let paths = row["paths"].as_array().ok_or(ERROR)?;
    let component = |a: usize, b: usize, left: &str, right: &str, transform: &str, result: bool| json!({"sources":[sources[a],sources[b]],"paths":[left,right],"transform":transform,"result":result});
    if rule["transform"] == "failed_append" {
        if sources.len() != 3
            || paths.len() != 3
            || paths
                .iter()
                .any(|p| p.as_array().is_none_or(|a| a.len() != 1))
            || rule["result"] != true
        {
            return Err(ERROR.into());
        }
        return Ok(json!([
            component(
                0,
                1,
                paths[0][0].as_str().ok_or(ERROR)?,
                paths[1][0].as_str().ok_or(ERROR)?,
                "append_fail_stop",
                true
            ),
            component(
                0,
                2,
                &format!("{}/records", paths[0][0].as_str().ok_or(ERROR)?),
                paths[2][0].as_str().ok_or(ERROR)?,
                "identity",
                true
            )
        ]));
    }
    if sources.len() != 2 || paths.len() != 2 {
        return Err(ERROR.into());
    }
    let left = paths[0].as_array().ok_or(ERROR)?;
    let right = paths[1].as_array().ok_or(ERROR)?;
    let result = rule["result"].as_bool().ok_or(ERROR)?;
    if left.is_empty() || left.len() != right.len() || !result && left.len() != 1 {
        return Err(ERROR.into());
    }
    Ok(json!(
        left.iter()
            .zip(right)
            .map(|(l, r)| Ok(component(
                0,
                1,
                l.as_str().ok_or(ERROR)?,
                r.as_str().ok_or(ERROR)?,
                rule["transform"].as_str().ok_or(ERROR)?,
                result
            )))
            .collect::<Result<Vec<_>, String>>()?
    ))
}
fn valid_phase(phase: Option<&str>, key: &Value) -> bool {
    matches!(phase, Some("inside" | "outside"))
        || phase
            .and_then(|p| p.strip_prefix("case:"))
            .is_some_and(|id| {
                key["cases"]
                    .as_array()
                    .is_some_and(|cases| cases.iter().any(|c| c["id"] == id))
            })
}
fn valid_paths(paths: &Value) -> bool {
    fn pair(v: &Value) -> bool {
        v.as_array().is_some_and(|a| {
            (2..=3).contains(&a.len())
                && a.iter().all(|side| {
                    side.as_array()
                        .is_some_and(|p| p.iter().all(Value::is_string))
                })
        })
    }
    pair(paths)
        || paths.as_object().is_some_and(|o| {
            o.len() == 1
                && o.get("by_instance")
                    .and_then(Value::as_array)
                    .is_some_and(|a| !a.is_empty() && a.iter().all(pair))
        })
}
fn paths_at(paths: &Value, instance: usize) -> Result<&Value, String> {
    if paths.is_array() {
        return Ok(paths);
    }
    paths["by_instance"]
        .as_array()
        .and_then(|a| instance.checked_sub(1).and_then(|n| a.get(n)))
        .ok_or_else(|| ERROR.into())
}
fn validate_interval(
    row: &Value,
    workers: &[std::collections::BTreeMap<u64, u64>],
    events: &[Value],
    duration: u64,
) -> Result<(), String> {
    let cursor = row["start_cursor"].as_u64().ok_or(ERROR)? as usize;
    let end_cursor = row["end_cursor"].as_u64().ok_or(ERROR)? as usize;
    let start = row["start_ns"].as_u64().ok_or(ERROR)?;
    let end = row["end_ns"].as_u64().ok_or(ERROR)?;
    let page = row["page"].as_u64().ok_or(ERROR)?;
    if page == 0
        || end < start
        || end > duration
        || end_cursor < cursor
        || end_cursor > events.len()
        || row["receiver_ok"] != true
        || row["worker"].as_u64().is_none_or(|w| w == 0)
        || row["worker"] != json!(workers.get(cursor).and_then(|w| w.get(&page)))
        || cursor > 0 && events[cursor - 1]["at_ns"].as_u64().ok_or(ERROR)? > start
        || end_cursor < events.len() && events[end_cursor]["at_ns"].as_u64().ok_or(ERROR)? < end
    {
        return Err(ERROR.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn comparison_result_must_move_into_the_original_check() {
        let state = |source| State {
            original: Arc::new(Original {
                value: crate::cdp::test_original(json!({"records":[0]})),
                source,
            }),
            path: String::new(),
        };
        let mut case = crate::Case {
            id: "fixture.case".into(),
            site: "fixture",
            name: "fixture".into(),
            failures: Vec::new(),
            assertions: Vec::new(),
            branches: Default::default(),
            start: 0,
            end: 0,
        };
        let before = state(1);
        let after = state(2);
        let dropped = after.same_at("fixture.original", &before, &["/records"]);
        let index = dropped.comparisons[0];
        drop(dropped);
        case.check("fixture.original", "substituted result", true);
        assert!(USES.lock().unwrap()[index]["check_ns"].is_null());
        let result = after.same_at("fixture.original", &before, &["/records"]);
        let index = result.comparisons[0];
        case.check("fixture.original", "original result", result);
        assert!(!USES.lock().unwrap()[index]["check_ns"].is_null());
        let entered = std::cell::Cell::new(false);
        let result = all!(false, {
            entered.set(true);
            after.same_at("fixture.skipped", &before, &["/records"])
        });
        case.check("fixture.skipped", "short circuit", result);
        assert_eq!(case.failures.len(), 1);
        assert!(!entered.get());
    }
    #[test]
    fn every_original_operation_including_noncomparison_work_is_required_once() {
        let mut f: Value =
            serde_json::from_str(include_str!("../testdata/state-inputs.json")).unwrap();
        f["inventory"]["cases"][1]["assertions"]
            .as_array_mut()
            .unwrap()
            .push(json!("goal_cases.a009"));
        f["inventory"]["state_operation_rules"]
            .as_array_mut()
            .unwrap()
            .push(json!([
                "fixture.second",
                "fixture.second",
                "collect",
                "goal_cases.run",
                ["goal_cases.c004.p001"],
                "inside",
                "goal_cases.a009",
                "all",
                0,
                "tracer",
                0
            ]));
        let mut check = f["report"]["primary_history"][0].clone();
        check["id"] = json!("goal_cases.a009.i001");
        check["at_ns"] = json!(35);
        f["report"]["primary_history"]
            .as_array_mut()
            .unwrap()
            .push(check);
        let mut second = f["report"]["state_inputs"]["operations"][0].clone();
        second["site"] = json!("fixture.second");
        second["source"] = json!(2);
        second["start_ns"] = json!(30);
        second["end_ns"] = json!(31);
        f["report"]["state_inputs"]["operations"]
            .as_array_mut()
            .unwrap()
            .push(second);
        let report = &f["report"];
        let key = &f["inventory"];
        validate_with(report, key).unwrap();
        for action in [
            "missing",
            "duplicate",
            "extra_after",
            "same_total",
            "cancelled",
        ] {
            let mut bad = report.clone();
            let rows = bad["state_inputs"]["operations"].as_array_mut().unwrap();
            match action {
                "missing" => {
                    rows.pop();
                }
                "duplicate" => {
                    let mut row = rows[0].clone();
                    row["source"] = json!(2);
                    rows[1] = row;
                }
                "extra_after" => {
                    let mut row = rows[1].clone();
                    row["source"] = json!(3);
                    row["start_ns"] = json!(40);
                    row["end_ns"] = json!(41);
                    rows.push(row);
                }
                "same_total" => rows[1]["site"] = json!("fixture.collect"),
                _ => rows[1]["completed"] = json!(false),
            }
            assert!(validate_with(&bad, key).is_err(), "{action}");
            validate_with(report, key).unwrap();
        }
    }
    #[test]
    fn failed_append_consumes_all_three_original_queries_across_the_original_cases() {
        let f: Value =
            serde_json::from_str(include_str!("../testdata/state-failed-append-inputs.json"))
                .unwrap();
        let report = &f["report"];
        let key = &f["inventory"];
        validate_with(report, key).unwrap();
        for (path, value) in [
            (
                "/state_inputs/uses/0/comparisons/0/transform",
                json!("identity"),
            ),
            ("/state_inputs/uses/0/sources", json!([2, 2, 1])),
            ("/state_inputs/uses/0/sources", json!([3, 1, 2])),
            (
                "/state_inputs/uses/0/paths",
                json!([[""], [""], ["/standing"]]),
            ),
            (
                "/state_inputs/captures/0/case",
                json!("goal_cases.c004.p001"),
            ),
            (
                "/state_inputs/captures/1/site",
                json!("state.fixture.completed"),
            ),
        ] {
            let mut bad = report.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(validate_with(&bad, key).is_err(), "{path}");
        }
        let mut removed = report.clone();
        removed["state_inputs"]["uses"][0]["comparisons"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(
            validate_with(&removed, key)
                .unwrap_err()
                .contains("inner comparison")
        );
        let mut moved = report.clone();
        moved["state_inputs"]["captures"][0]["start_ns"] = json!(817);
        moved["state_inputs"]["captures"][0]["end_ns"] = json!(818);
        assert!(validate_with(&moved, key).is_err());
        validate_with(report, key).unwrap();
    }
    #[test]
    fn real_comparison_rules_validate_even_without_selected_state_comparisons() {
        let mut fixture: Value =
            serde_json::from_str(include_str!("../testdata/state-inputs.json")).unwrap();
        fixture["report"]["state_inputs"] = json!({"captures":[],"uses":[],"operations":[]});
        fixture["report"]["cases"] = json!([]);
        fixture["report"]["plan"]["expected_execution"] = json!([]);
        fixture["report"]["helper_history"] = json!([]);
        fixture["report"]["primary_history"] = json!([]);
        fixture["report"]["plan"]["invocation_root_sequences"] = json!([]);
        validate_with(&fixture["report"], completion::inventory()).unwrap();
    }
    #[test]
    fn saved_query_keeps_its_original_checkpoint_across_parameterized_uses() {
        let mut fixture: Value =
            serde_json::from_str(include_str!("../testdata/state-inputs.json")).unwrap();
        let rule = &mut fixture["inventory"]["state_comparison_sources"]["goal_cases.a008"];
        rule["sources"][0][1] = json!("saved");
        rule["paths"] =
            json!({"by_instance":[[["/records"],["/records"]],[["/standing"],["/standing"]]]});
        let report = &mut fixture["report"];
        report["state_inputs"]["uses"][0]["paths"] = json!([["/records"], ["/records"]]);
        report["state_inputs"]["uses"][0]["comparisons"] = json!([{"sources":[2,1],"paths":["/records","/records"],"transform":"identity","result":true}]);
        let mut used = report["state_inputs"]["uses"][0].clone();
        used["paths"] = json!([["/standing"], ["/standing"]]);
        used["comparisons"] = json!([{"sources":[2,1],"paths":["/standing","/standing"],"transform":"identity","result":true}]);
        used["at_ns"] = json!(26);
        used["check_ns"] = json!(27);
        used["instance"] = json!(2);
        report["state_inputs"]["uses"]
            .as_array_mut()
            .unwrap()
            .push(used);
        let mut check = report["primary_history"][0].clone();
        check["at_ns"] = json!(27);
        check["id"] = json!("goal_cases.a008.i002");
        report["primary_history"]
            .as_array_mut()
            .unwrap()
            .push(check);
        let report = &fixture["report"];
        let key = &fixture["inventory"];
        validate_with(report, key).unwrap();
        for (path, value) in [
            ("/state_inputs/uses/1/sources", json!([1, 1])),
            (
                "/state_inputs/uses/1/paths",
                json!([["/records"], ["/records"]]),
            ),
            ("/state_inputs/captures/1/start_ns", json!(26)),
        ] {
            let mut bad = report.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(validate_with(&bad, key).is_err(), "{path}");
        }
        validate_with(report, key).unwrap();
    }
    #[test]
    fn query_fields_and_actual_operation_bracket_are_required() {
        let fixture: Value =
            serde_json::from_str(include_str!("../testdata/state-inputs.json")).unwrap();
        let report = &fixture["report"];
        let key = &fixture["inventory"];
        validate_with(report, key).unwrap();
        for (pointer, value) in [
            ("/state_inputs/uses/0/sources", json!([1, 1])),
            ("/state_inputs/uses/0/sources", json!([2, 1, 3])),
            ("/state_inputs/captures/1/query_ok", json!(false)),
            ("/state_inputs/uses/0/sources", json!([1, 2])),
            (
                "/state_inputs/uses/0/paths",
                json!([["/standing"], ["/standing"]]),
            ),
            ("/state_inputs/uses/0/transform", json!("clear_sessions")),
            ("/state_inputs/captures/0/end_ns", json!(21)),
            ("/state_inputs/captures/1/start_ns", json!(20)),
            ("/state_inputs/captures/1/page", json!(8)),
            ("/state_inputs/operations/0/worker", json!(4)),
            ("/state_inputs/operations/0/end_ns", json!(23)),
        ] {
            let mut bad = report.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(validate_with(&bad, key).is_err(), "{pointer}");
        }
        for field in ["captures", "uses", "operations"] {
            let mut bad = report.clone();
            bad["state_inputs"][field].as_array_mut().unwrap().pop();
            assert!(validate_with(&bad, key).is_err(), "{field}");
        }
        validate_with(report, key).unwrap();
    }
}
