//! Completion is checked against the source-reviewed inventory, never learned from a run.
use super::{Case, json};
#[path = "../identity.rs"]
pub mod identity;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

static CLOCK: OnceLock<Instant> = OnceLock::new();
static DOMAINS: Mutex<BTreeMap<String, (usize, usize)>> = Mutex::new(BTreeMap::new());
static PREREQUISITES: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static PREREQUISITE_COUNTS: Mutex<BTreeMap<&'static str, u64>> = Mutex::new(BTreeMap::new());
static PREREQUISITE_REQUESTS: Mutex<BTreeMap<&'static str, u64>> = Mutex::new(BTreeMap::new());
static SCOPES: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static SCENARIO_INVOCATIONS: Mutex<BTreeMap<&'static str, u64>> = Mutex::new(BTreeMap::new());

pub struct ScenarioSpan {
    identity: &'static str,
    invocation: u64,
    start: u64,
}

pub fn scenario(identity: &'static str) -> ScenarioSpan {
    let invocation = {
        let mut counts = SCENARIO_INVOCATIONS.lock().unwrap();
        let n = counts.entry(identity).or_default();
        *n += 1;
        *n
    };
    ScenarioSpan {
        identity,
        invocation,
        start: super::history::event(
            json!({"event":"scenario_start","id":identity,"invocation":invocation}),
        ),
    }
}

impl Drop for ScenarioSpan {
    fn drop(&mut self) {
        let end = super::history::event(
            json!({"event":"scenario_end","id":self.identity,"invocation":self.invocation}),
        );
        let value = json!({"id":self.identity,"invocation":self.invocation,"start_ns":self.start,"end_ns":end});
        SCOPES.lock().unwrap().push(value.clone());
        println!("TRACER_GROUP_TIMING {value}");
    }
}
pub fn prerequisite_request(id: &'static str) {
    *PREREQUISITE_REQUESTS.lock().unwrap().entry(id).or_default() += 1;
}

#[derive(Default)]
struct FixtureCensus {
    requests: u64,
    mints: u64,
    snapshots: BTreeMap<String, Value>,
    helpers: Option<Value>,
}

impl FixtureCensus {
    fn observe(&mut self, line: &str) -> Result<(), String> {
        if let Some(raw) = line.strip_prefix("TRACER_HELPER_REQUESTS ") {
            let value =
                super::strict_json::parse(raw).map_err(|_| "malformed helper observations")?;
            if self.helpers.replace(value).is_some() {
                return Err("duplicate helper observations".into());
            }
            return Ok(());
        }
        let Some(raw) = line.strip_prefix("TRACER_FIXTURE ") else {
            return Ok(());
        };
        let event: Value =
            super::strict_json::parse(raw).map_err(|_| "malformed fixture observation")?;
        match event["kind"].as_str() {
            Some("request") => self.requests += 1,
            Some("mint") => {
                self.mints += 1;
                if event["ordinal"] != self.mints || self.mints > self.requests {
                    return Err("fixture mint order/count mismatch".into());
                }
            }
            Some("census") if event["id"] == "inference-credentials" => {
                if self
                    .snapshots
                    .insert(
                        "inference-credentials".into(),
                        json!({"count":self.mints+1,"bound":self.requests+1}),
                    )
                    .is_some()
                {
                    return Err("duplicate fixture census".into());
                }
            }
            _ => return Err("unknown fixture observation".into()),
        }
        Ok(())
    }

    fn value(&self) -> Value {
        json!(self.snapshots)
    }
}

fn validate_observed(
    report: &Value,
    actual_exit: Option<i32>,
    actual: &Value,
    full: bool,
    census: &Value,
) -> Result<(), String> {
    if report["domains"] != *census {
        return Err(
            "fixture credential census differs from independently observed mint history".into(),
        );
    }
    validate(report, actual_exit, actual, full)
}

pub fn prerequisite(id: &'static str, holds: bool) -> bool {
    let mut checks = PREREQUISITES.lock().unwrap();
    let mut counts = PREREQUISITE_COUNTS.lock().unwrap();
    let n = counts.entry(id).or_default();
    *n += 1;
    let instance = format!("{id}.i{n:03}");
    super::history::event(
        json!({"event":"check","id":id,"instance":instance,"ordinal":checks.len()+1}),
    );
    if !holds {
        super::diagnostics::prerequisite(&instance);
    }
    checks.push(json!({"id":id,"instance":instance,"ok":holds}));
    holds
}

pub fn rejects(id: &'static str, fails: bool) -> bool {
    prerequisite(id, !fails);
    fails
}

pub fn now() -> u64 {
    CLOCK
        .get_or_init(Instant::now)
        .elapsed()
        .as_nanos()
        .try_into()
        .expect("tracer duration fits u64")
}

pub struct Span {
    phase: &'static str,
    start: u64,
    finished: bool,
}

impl Span {
    pub fn start(phase: &'static str) -> Self {
        super::diagnostics::phase(phase);
        Self {
            phase,
            start: now(),
            finished: false,
        }
    }
    pub fn finish(mut self) -> Value {
        self.finished = true;
        let value = timing(self.phase, self.start);
        println!("TRACER_TIMING {value}");
        value
    }
    pub fn fail(mut self) {
        self.finished = true;
        println!(
            "TRACER_TIMING {}",
            json!({"phase":self.phase,"start_ns":self.start,"end_ns":now(),"status":"failed"})
        );
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        if !self.finished {
            println!(
                "TRACER_TIMING {}",
                json!({"phase":self.phase,"start_ns":self.start,"end_ns":now(),"status":"incomplete"})
            );
        }
    }
}

pub fn inventory() -> &'static Value {
    static INVENTORY: OnceLock<Value> = OnceLock::new();
    INVENTORY.get_or_init(super::inventory::read)
}

pub fn inventory_hash() -> String {
    identity::digest(include_bytes!("../inventory.json"))
}

fn success_verdict(coverage: &Value, full: bool) -> Result<&'static str, String> {
    if !full {
        return Ok("TARGETED PASS");
    }
    match coverage["complete"].as_bool() {
        Some(true) => Ok("TRACER PASS"),
        Some(false) => Ok("TRACER PARTIAL PASS (coverage.complete=false)"),
        None => Err("missing or invalid inventory coverage status".into()),
    }
}

fn is_success_verdict(line: &str) -> bool {
    ["TRACER PASS", "TRACER PARTIAL PASS", "TARGETED PASS"]
        .iter()
        .any(|prefix| line.starts_with(prefix))
}

pub fn domain(name: &str, count: usize, bound: usize) {
    DOMAINS.lock().unwrap().insert(name.into(), (count, bound));
}

pub fn provenance(served: &Path, tracer: &Path) -> Result<Value, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let (source, paths) = identity::source(root)?;
    if source != env!("TRACER_SOURCE_SHA256") {
        return Err("source differs from the compiled tracer; rebuild before execution".into());
    }
    let chrome = std::env::var_os("CHROME").ok_or("CHROME is not set")?;
    let chrome = executable(Path::new(&chrome))?;
    let version = std::process::Command::new(&chrome)
        .arg("--version")
        .output()
        .map_err(|e| e.to_string())?;
    if !version.status.success() {
        return Err("cannot identify Chrome".into());
    }
    Ok(json!({
        "source":source,
        "validation_contracts":identity::validation_contracts(root, &paths)?,
        "spec":tau_web::SPEC_COMMIT,
        "binary":identity::file(&std::env::current_exe().map_err(|e| e.to_string())?)?,
        "served":identity::directory(served)?,
        "tracer":identity::directory(tracer)?,
        "preconditions":{
            "chrome":identity::file(&chrome)?,
            "chrome_version":identity::digest(&version.stdout),
            "fresh_profile":true,
            "local_fixtures":true,
            "serial":true,
            "declaration_witnesses":std::env::var_os("TAU_DECLARATION_WITNESSES").is_none()
        }
    }))
}

fn executable(path: &Path) -> Result<PathBuf, String> {
    if path.components().count() > 1 {
        return path.canonicalize().map_err(|e| e.to_string());
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|p| p.join(path))
        .find(|p| p.is_file())
        .ok_or("Chrome executable unavailable".into())
}

pub fn report(
    mode: &str,
    provenance: &Value,
    cases: &[Case],
    timings: Vec<Value>,
    outcome: bool,
    mandatory: bool,
    cleanup: bool,
) -> Result<Value, String> {
    let plan = if mode == "targeted" {
        super::selection::plan(&super::selection::current())?
    } else {
        Value::Null
    };
    println!(
        "TRACER_HELPER_REQUESTS {}",
        json!(*PREREQUISITE_REQUESTS.lock().unwrap())
    );
    let domains: BTreeMap<_, _> = DOMAINS
        .lock()
        .unwrap()
        .iter()
        .map(|(name, (count, bound))| (name.clone(), json!({"count":count,"bound":bound})))
        .collect();
    let completed: Vec<_> = cases
        .iter()
        .map(|case| {
            json!({
            "id":case.id,"site_id":case.site,"assertions":case.assertions,"branches":case.branches,
                    "start_ns":case.start,"end_ns":case.end,
                    "ok":case.failures.is_empty(),
                })
        })
        .collect();
    let mut groups: Vec<Value> = Vec::new();
    for case in cases {
        let scenario = json!(super::catalogue::scenario(case.site));
        if let Some(last) = groups.last_mut().filter(|g| g["id"] == scenario) {
            last["end_ns"] = json!(case.end);
        } else {
            groups.push(json!({"id":scenario,"start_ns":case.start,"end_ns":case.end}));
        }
    }
    let mut report = json!({"schema":1,"mode":mode,"inventory":inventory_hash(),"provenance":provenance,
        "cases":completed,"domains":domains,"timings":timings,"group_spans":groups,"scenario_spans":*SCOPES.lock().unwrap(),"duration_ns":now(),
        "prerequisites":*PREREQUISITES.lock().unwrap(),"prerequisite_requests":*PREREQUISITE_REQUESTS.lock().unwrap(),"helper_history":super::history::snapshot(),"reader_roots":super::reader_checks::snapshot(),"auxiliary_calls":super::auxiliary::snapshot(),"observer_calls":super::observer::snapshot(),"displayed_word_captures":super::observer::displayed_word_captures(),"observer_prior_inputs":super::observer::prior_snapshot(),"observer_unbound_arguments":super::observer::unbound_arguments(),"causal_unbound_jobs":super::causal::unbound_jobs(),"causal_use_calls":super::causal::use_calls(),"class_inputs":super::observer::class_snapshot(),"goal_end_inputs":super::observer::goal_end_snapshot(),"original_input_history":super::inputs::snapshot(),"original_unbound_inputs":super::inputs::unbound(),"counter_inputs":super::counter_inputs::snapshot(),"counter_unbound_inputs":super::counter_inputs::unbound(),"session_operands":super::session_operands::snapshot(),"session_operand_unbound":super::session_operands::unbound(),"key_inputs":super::key_inputs::snapshot(),"key_unbound_inputs":super::key_inputs::unbound(),"fixture_inputs":super::fixture_inputs::snapshot(),"aggregator_inputs":super::aggregator::input_snapshot(),"submissions":super::observer::submission_snapshot(),"runtime_inputs":super::observer::runtime_snapshot(),"binding_inputs":super::observer::binding_snapshot(),
        "mandatory":{"same_browser_policy_command":mandatory,"cleanup":cleanup},
        "selected":if mode=="targeted" {plan["selected"].clone()} else {json!([])},
        "support":if mode=="targeted" {plan["support"].clone()} else {json!([])}, "plan":plan, "execution_ok":outcome});
    report["seed_operations"] = super::seed_operations::snapshot();
    report["file_captures"] = super::file_inputs::snapshot();
    report["file_comparisons"] = super::file_inputs::comparisons();
    report["file_controls"] = super::file_inputs::controls();
    report["file_uses"] = super::file_uses::snapshot();
    report["file_dump_queries"] = super::operation_windows::dump_queries();
    report["operation_windows"] = super::operation_windows::snapshot();
    report["state_inputs"] = super::state_inputs::snapshot();
    report["file_pending_inputs"] = super::file_windows::pending_snapshot();
    report["file_requests"] = super::file_windows::snapshot();
    report["blob_sources"] = super::file_inputs::blob_sources();
    report["primary_history"] = super::file_inputs::primary_history();
    report["page_query_inputs"] = super::page_queries::snapshot();
    report["view_inputs"] = super::view_inputs::snapshot();
    report["settle_inputs"] = super::settle_inputs::snapshot();
    report["catalogue"] = super::catalogue::cases();
    report["worker_exclusions"] = super::observer::worker_exclusions();
    report["displayed_word_uses"] = super::observer::displayed_word_uses();
    report["second_worker_inputs"] = super::observer::second_worker_inputs();
    report["goal_rebind_inputs"] = super::observer::rebind_inputs();
    report["goal_session_inputs"] = super::observer::goal_session_inputs();
    report["leakage_input_captures"] = super::auxiliary::leakage_input_captures();
    report["leakage_input_uses"] = super::auxiliary::leakage_input_uses();
    Ok(report)
}

/// The supervisor supplies the actual process exit and independently recomputed inputs.
/// A printed verdict or an identity copied from the evidence is never an input authority.
pub fn validate(
    report: &Value,
    actual_exit: Option<i32>,
    actual: &Value,
    full: bool,
) -> Result<(), String> {
    validate_inventory(report, actual_exit, actual, full)?;
    super::history::validate(report)?;
    super::settle_inputs::validate(report)?;
    super::file_inputs::validate(report)?;
    super::file_uses::validate(report)?;
    super::file_windows::validate(report)?;
    super::operation_windows::validate(report)?;
    super::state_inputs::validate(report)?;
    super::seed_operations::validate(report)?;
    super::reader_checks::validate(report)?;
    super::auxiliary::validate(report)?;
    super::observer::validate(report)?;
    super::page_queries::validate(report)?;
    super::view_domains::validate(report)
}

fn validate_inventory(
    report: &Value,
    actual_exit: Option<i32>,
    actual: &Value,
    full: bool,
) -> Result<(), String> {
    if actual_exit != Some(0) {
        return Err("execution did not exit successfully".into());
    }
    if report["schema"] != 1 || report["inventory"] != inventory_hash() {
        return Err("missing or stale expected inventory".into());
    }
    if report["provenance"] != *actual {
        return Err("source/artifact/precondition provenance mismatch".into());
    }
    if report["execution_ok"] != true || report["mandatory"]["cleanup"] != true {
        return Err("incomplete execution or cleanup".into());
    }
    if full
        && (report["mode"] != "full"
            || report["mandatory"]["same_browser_policy_command"] != true
            || report["selected"] != json!([])
            || report["support"] != json!([])
            || !report["plan"].is_null())
    {
        return Err("targeted/incomplete evidence cannot qualify as full".into());
    }
    if full
        && [
            "fresh_profile",
            "local_fixtures",
            "serial",
            "declaration_witnesses",
        ]
        .iter()
        .any(|key| actual["preconditions"][key] != true)
    {
        return Err("ineligible full-run preconditions".into());
    }
    if !full && report["mode"] != "targeted" {
        return Err("targeted mode mismatch".into());
    }
    let independent_catalogue = json!(inventory()["cases"].as_array().unwrap().iter().map(|c|json!({"id":c["id"],"site_id":c["site_id"],"label":c["label"],"scenario_id":c["scenario_id"]})).collect::<Vec<_>>());
    if report["catalogue"] != independent_catalogue {
        return Err("executable catalogue differs from independent case key".into());
    }
    if !full {
        let selection: BTreeMap<String, String> =
            serde_json::from_value(report["plan"]["selection"].clone())
                .map_err(|_| "missing targeted selection inputs")?;
        let entries = selection
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>();
        super::selection::validate("targeted", &entries)?;
        let expected = super::requirements::plan(&selection)?;
        if report["plan"] != expected
            || report["selected"] != expected["selected"]
            || report["support"] != expected["support"]
        {
            return Err("targeted plan differs from independently required projection".into());
        }
    }
    let cases = report["cases"]
        .as_array()
        .ok_or("missing case completion")?;
    let expected = inventory()["cases"].as_array().unwrap();
    let execution: Vec<Value> = if full {
        expected.iter().map(|c| c["id"].clone()).collect()
    } else {
        report["plan"]["expected_execution"]
            .as_array()
            .ok_or("missing targeted execution plan")?
            .clone()
    };
    if cases.is_empty() || cases.len() != execution.len() {
        return Err("missing or extra primary completion".into());
    }
    let mut ids = BTreeSet::new();
    let mut previous = 0;
    for (position, case) in cases.iter().enumerate() {
        let id = case["id"].as_str().ok_or("case identity missing")?;
        if !ids.insert(id) {
            return Err(format!("duplicate primary completion: {id}"));
        }
        let spec = expected
            .iter()
            .find(|s| s["id"] == id)
            .ok_or_else(|| format!("extra primary completion: {id}"))?;
        if spec["id"] != execution[position] {
            return Err(format!("serial order/history mismatch: {id}"));
        }
        if case["site_id"] != spec["site_id"] || case["ok"] != true {
            return Err(format!("failed primary completion: {id}"));
        }
        let start = case["start_ns"].as_u64().ok_or("missing case start")?;
        let end = case["end_ns"].as_u64().ok_or("missing case end")?;
        if start < previous
            || end < start
            || end > report["duration_ns"].as_u64().ok_or("missing duration")?
        {
            return Err("invalid monotonic case timing/order".into());
        }
        previous = end;
        let checks = case["assertions"]
            .as_array()
            .ok_or("missing assertion completion")?;
        let want = expected_assertions(spec, case, report)?;
        if checks.len() != want.len() {
            return Err(format!("missing or extra assertion completion: {id}"));
        }
        for (got, want) in checks.iter().zip(&want) {
            if got["id"] != *want || got["ok"] != true {
                return Err(format!(
                    "missing/extra/duplicate assertion or order mismatch: {id}/{want}"
                ));
            }
        }
    }
    validate_timings(report)?;
    validate_prerequisites(report, full)?;
    Ok(())
}

fn validate_prerequisites(report: &Value, full: bool) -> Result<(), String> {
    let checks = report["prerequisites"]
        .as_array()
        .ok_or("missing prerequisite completions")?;
    let requests = report["prerequisite_requests"]
        .as_object()
        .ok_or("missing prerequisite request domains")?;
    let requirements = if full { inventory() } else { &report["plan"] };
    let mut counts = super::history::expected_prerequisites(requirements);
    let worker = requests
        .get("runtime.worker.ready")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let ready = requests
        .get("runtime.store.ready_nontransient")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let polls = requests
        .get("runtime.store.not_failed")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let classes = requests
        .get("binding.fixture_class.ready")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let bindings = requests
        .get("binding.page.bound")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if worker < if full { 2 } else { 1 }
        || ready < worker
        || polls < ready
        || polls > ready.saturating_mul(300)
        || (full
            || report["plan"]["expected_execution"]
                .as_array()
                .is_some_and(|a| a.iter().any(|id| id == "main.c001.p001")))
            && (classes < 2 || bindings < 2)
    {
        return Err("invalid prerequisite request applicability/poll bounds".into());
    }
    for (id, count) in requests {
        if !inventory()["dynamic_prerequisites"]
            .as_object()
            .unwrap()
            .contains_key(id)
        {
            return Err("unknown prerequisite request domain".into());
        }
        let n = count
            .as_u64()
            .ok_or("invalid prerequisite request cardinality")?;
        if counts.get(id).is_some_and(|expected| *expected != n) {
            return Err(format!(
                "helper request differs from source-derived cardinality: {id}"
            ));
        }
        counts.insert(id.clone(), n);
    }
    let mut observed: BTreeMap<String, u64> = BTreeMap::new();
    for check in checks {
        let id = check["id"]
            .as_str()
            .ok_or("missing prerequisite identity")?;
        let n = observed.entry(id.into()).or_default();
        *n += 1;
        if check["ok"] != true || check["instance"] != format!("{id}.i{n:03}") {
            return Err(format!("failed/duplicate prerequisite: {id}"));
        }
    }
    if observed.iter().any(|(id, n)| counts.get(id) != Some(n))
        || counts
            .iter()
            .any(|(id, n)| *n != observed.get(id).copied().unwrap_or(0))
    {
        return Err("missing/extra/duplicate prerequisite completion".into());
    }
    Ok(())
}

pub(super) fn expected_assertions(
    spec: &Value,
    case: &Value,
    report: &Value,
) -> Result<Vec<String>, String> {
    let id = spec["id"].as_str().unwrap();
    let mut want = Vec::new();
    let mut occurrences: BTreeMap<&str, usize> = BTreeMap::new();
    let mut sites = spec["assertions"].as_array().unwrap().clone();
    if id.starts_with("seed_cases.c001.")
        && report["mode"] == "targeted"
        && report["plan"]["name"]
            .as_str()
            .is_some_and(|name| name.starts_with("seed.") && name != "seed.all")
    {
        sites.retain(|site| site != "seed_cases.a005");
    }
    if let Some(variants) = spec.get("variants") {
        let branch = variants["branch"]
            .as_str()
            .ok_or("invalid variant branch")?;
        let selected = case["branches"][branch]
            .as_str()
            .ok_or("missing observed scenario branch")?;
        sites = variants["sequences"][selected]
            .as_array()
            .ok_or("unknown scenario branch")?
            .clone();
    }
    if let Some(optional) = spec.get("optional") {
        let branch = optional["branch"]
            .as_str()
            .ok_or("invalid optional branch")?;
        match case["branches"][branch].as_str() {
            Some("locked") => {
                let at = sites
                    .iter()
                    .position(|s| *s == optional["after"])
                    .ok_or("invalid optional placement")?;
                sites.insert(at + 1, optional["site"].clone());
            }
            Some("unopened") => {}
            _ => return Err("missing/unknown second-worker observation".into()),
        }
    }
    for site in &sites {
        let site = site.as_str().unwrap();
        let n = occurrences.entry(site).or_default();
        *n += 1;
        want.push(format!("{site}.i{n:03}"));
    }
    // This one domain is truly data dependent: account plus every fixture-minted key.
    if id.starts_with("inference_cases.c014.") {
        let domain = &report["domains"]["inference-credentials"];
        let count = domain["count"]
            .as_u64()
            .ok_or("missing independent fixture credential census")? as usize;
        let bound = domain["bound"]
            .as_u64()
            .ok_or("missing fixture mint bound")? as usize;
        if count < 2 || count > bound {
            return Err("invalid credential census bounds".into());
        }
        let at = want
            .iter()
            .position(|s| s.starts_with("inference_cases.a068."))
            .ok_or("missing credential domain")?;
        want.retain(|s| !s.starts_with("inference_cases.a068."));
        want.splice(
            at..at,
            (1..=count).map(|i| format!("inference_cases.a068.i{i:03}")),
        );
    }
    Ok(want)
}

fn validate_timings(report: &Value) -> Result<(), String> {
    let duration = report["duration_ns"]
        .as_u64()
        .ok_or("missing total timing")?;
    let timings = report["timings"].as_array().ok_or("missing timings")?;
    let mut previous = 0;
    for phase in ["fixtures", "browser", "groups", "cleanup"] {
        let entries: Vec<_> = timings.iter().filter(|t| t["phase"] == phase).collect();
        if entries.len() != 1 {
            return Err(format!("missing or duplicate phase timing: {phase}"));
        }
        for entry in entries {
            let start = entry["start_ns"].as_u64().ok_or("invalid phase start")?;
            let end = entry["end_ns"].as_u64().ok_or("invalid phase end")?;
            if start < previous || end < start || end > duration {
                return Err("invalid phase timing bounds".into());
            }
            previous = end;
        }
    }
    if timings.len() != 4
        || timings
            .iter()
            .any(|t| t.as_object().is_none_or(|o| o.len() != 3))
    {
        return Err("unknown timing field or phase".into());
    }
    let groups = timings.iter().find(|t| t["phase"] == "groups").unwrap();
    for case in report["cases"].as_array().unwrap() {
        if case["start_ns"].as_u64() < groups["start_ns"].as_u64()
            || case["end_ns"].as_u64() > groups["end_ns"].as_u64()
        {
            return Err("case lies outside group timing".into());
        }
    }
    let spans = report["group_spans"]
        .as_array()
        .ok_or("missing group timings")?;
    let mut expected: Vec<Value> = Vec::new();
    for case in report["cases"].as_array().unwrap() {
        let scenario = &inventory()["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == case["id"])
            .unwrap()["scenario_id"];
        if let Some(last) = expected.last_mut().filter(|s| s["id"] == *scenario) {
            last["end_ns"] = case["end_ns"].clone();
        } else {
            expected
                .push(json!({"id":scenario,"start_ns":case["start_ns"],"end_ns":case["end_ns"]}));
        }
    }
    if spans != &expected {
        return Err("group timing identity/order/case bounds mismatch".into());
    }
    let expected_scopes = if report["mode"] == "full" {
        &inventory()["scenario_scopes"]
    } else {
        &report["plan"]["scenario_scopes"]
    };
    let scopes = report["scenario_spans"]
        .as_array()
        .ok_or("missing scenario scope timings")?;
    let expected_order = inventory()["scope_order"]
        .as_array()
        .ok_or("missing scenario invocation order")?
        .iter()
        .flat_map(|id| {
            std::iter::repeat_n(
                id.clone(),
                expected_scopes[id.as_str().unwrap()].as_u64().unwrap_or(0) as usize,
            )
        })
        .collect::<Vec<_>>();
    if scopes
        .iter()
        .map(|scope| scope["id"].clone())
        .collect::<Vec<_>>()
        != expected_order
    {
        return Err("scenario invocation order/multiplicity mismatch".into());
    }
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut previous_end = 0;
    for scope in scopes {
        let id = scope["id"]
            .as_str()
            .ok_or("missing scenario timing identity")?;
        let start = scope["start_ns"].as_u64().ok_or("missing scenario start")?;
        let end = scope["end_ns"].as_u64().ok_or("missing scenario end")?;
        if scope.as_object().unwrap().len() != 4
            || start > end
            || end < previous_end
            || start < groups["start_ns"].as_u64().unwrap()
            || end > groups["end_ns"].as_u64().unwrap()
        {
            return Err("invalid scenario scope timing bounds/order".into());
        }
        let n = counts.entry(id.into()).or_default();
        *n += 1;
        if scope["invocation"] != *n {
            return Err("scenario invocation identity mismatch".into());
        }
        previous_end = end;
    }
    if json!(counts) != *expected_scopes {
        return Err("missing/extra/duplicate scenario scope timing".into());
    }
    for case in report["cases"].as_array().unwrap() {
        let owner = case["site_id"].as_str().unwrap().split('.').next().unwrap();
        let invocation = &inventory()["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|spec| spec["id"] == case["id"])
            .unwrap()["invocation"];
        if !scopes.iter().any(|s| {
            s["invocation"] == *invocation
                && s["id"].as_str().unwrap().starts_with(&format!("{owner}."))
                && s["start_ns"].as_u64() <= case["start_ns"].as_u64()
                && s["end_ns"].as_u64() >= case["end_ns"].as_u64()
        }) {
            return Err("case outside its scenario scope".into());
        }
    }
    Ok(())
}

pub fn timing(phase: &str, start: u64) -> Value {
    json!({"phase":phase,"start_ns":start,"end_ns":now()})
}

pub async fn supervise(
    mode: &str,
    served: &Path,
    tracer: &Path,
    explicit: &[String],
) -> Result<(), String> {
    let capture = super::diagnostics::supervisor()?;
    let result = supervise_capture(mode, served, tracer, explicit, &capture).await;
    if result.is_err() {
        super::diagnostics::supervision_failed();
    }
    super::diagnostics::terminal(result.is_ok() && super::diagnostics::healthy());
    result
}

async fn supervise_capture(
    mode: &str,
    served: &Path,
    tracer: &Path,
    explicit: &[String],
    capture: &Path,
) -> Result<(), String> {
    super::diagnostics::phase("preflight");
    // Admission is repeated in the child. The parent also refuses before reading artifacts.
    let selection = super::selection::admit(mode, explicit)?;
    let plan = if mode == "targeted" {
        super::selection::plan(&selection)?
    } else {
        Value::Null
    };
    if mode == "full" {
        super::checks::absence(served)?;
        super::checks::csp(served)?;
    }
    let preflight = json!({"schema":1,"duration_ns":now(),"auxiliary_calls":super::auxiliary::snapshot(),"served_checks":super::served_checks::snapshot()});
    super::auxiliary::validate_preflight(&preflight, mode == "full")?;
    super::served_checks::validate_preflight(&preflight, mode == "full", served)?;
    println!("TRACER_PREFLIGHT {preflight}");
    super::diagnostics::phase("provenance");
    let actual = provenance(served, tracer)?;
    let directory = super::diagnostics::Directory::open(capture, false)?;
    directory.write_capture("identity.json", &actual)?;
    directory.write_capture("preflight.json", &preflight)?;
    use std::io::{BufWriter, Write};
    let mut log = BufWriter::new(directory.create("execution.log")?);
    let mut forwarded = BufWriter::new(std::io::stdout());
    let mut command =
        tokio::process::Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .arg("execute")
        .arg(mode)
        .arg(served)
        .arg(tracer)
        .args(explicit);
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());
    super::diagnostics::configure(&mut command, capture);
    super::diagnostics::phase("execution");
    let mut child = command
        .spawn()
        .inspect_err(|_| super::diagnostics::error("spawn"))
        .map_err(|e| e.to_string())?;
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut lines = BufReader::new(child.stdout.take().ok_or("child stdout missing")?).lines();
    let mut evidence = None;
    let mut duplicate = false;
    let mut malformed = false;
    let mut census = FixtureCensus::default();
    let mut forged_verdict = false;
    let mut timing_output = super::timing_output::Output::default();
    let mut malformed_timing = false;
    let mut io_error = false;
    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(_) => {
                super::diagnostics::error("forwarding");
                io_error = true;
                break;
            }
        };
        if timing_output.observe(&line).is_err() {
            malformed_timing = true;
        }
        if census.observe(&line).is_err() {
            malformed = true;
        }
        if writeln!(log, "{line}").is_err() {
            super::diagnostics::error("forwarding");
            io_error = true;
        }
        if is_success_verdict(&line) {
            forged_verdict = true;
        } else if writeln!(forwarded, "{line}").is_err() {
            super::diagnostics::error("forwarding");
            io_error = true;
        }
        if let Some(raw) = line.strip_prefix("TRACER_EVIDENCE ") {
            if evidence.is_some() {
                duplicate = true;
            }
            match super::strict_json::parse(raw) {
                Ok(report) => evidence = Some(report),
                Err(_) => malformed = true,
            }
        }
    }
    drop(lines);
    let waited = child.wait().await;
    super::diagnostics::waited(waited.as_ref().ok().copied());
    let status = waited
        .inspect_err(|_| super::diagnostics::error("wait"))
        .map_err(|e| e.to_string())?;
    io_error |= finish_capture(&mut log, &mut forwarded, &directory, status)?;
    drop(log);
    println!("evidence capture: {}", capture.display());
    println!(
        "TRACER_EXIT {}",
        json!({"code":status.code(),"success":status.success()})
    );
    super::diagnostics::phase("validation");
    if io_error {
        return Err("execution forwarding/capture failed".into());
    }
    if malformed_timing {
        return Err("invalid printed timing schema/bounds/order".into());
    }
    if duplicate || malformed || forged_verdict {
        return Err("duplicate or malformed evidence report".into());
    }
    let report = evidence.ok_or("incomplete execution: no evidence report")?;
    if report["plan"] != plan
        || mode == "targeted"
            && (report["selected"] != plan["selected"] || report["support"] != plan["support"])
    {
        return Err("targeted evidence differs from the admitted execution plan".into());
    }
    if provenance(served, tracer)? != actual {
        return Err("inputs changed during execution".into());
    }
    if census.helpers.as_ref() != Some(&report["prerequisite_requests"]) {
        return Err("prerequisite request observation mismatch".into());
    }
    validate_observed(
        &report,
        status.code(),
        &actual,
        mode == "full",
        &census.value(),
    )?;
    timing_output.validate(&report)?;
    if !super::diagnostics::healthy() {
        return Err("diagnostic retention failed".into());
    }
    let count: usize = report["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["assertions"].as_array().unwrap().len())
        .sum();
    let expected_count: usize = report["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let spec = inventory()["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["id"] == case["id"])
                .unwrap();
            expected_assertions(spec, case, &report).map(|ids| ids.len())
        })
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .sum();
    let expected_prerequisites =
        super::history::expected_prerequisites(if mode == "full" { inventory() } else { &plan })
            .values()
            .sum::<u64>()
            + report["prerequisite_requests"]["runtime.store.not_failed"]
                .as_u64()
                .unwrap_or(0);
    println!(
        "inventory {} expected primary={} completed primary={} expected assertions={expected_count} completed assertions={count} expected prerequisites={expected_prerequisites} completed prerequisites={}",
        inventory_hash(),
        if mode == "full" {
            inventory()["cases"].as_array().unwrap().len()
        } else {
            plan["expected_execution"].as_array().unwrap().len()
        },
        report["cases"].as_array().unwrap().len(),
        report["prerequisites"].as_array().unwrap().len()
    );
    println!(
        "{}",
        success_verdict(&inventory()["coverage"], mode == "full")?
    );
    Ok(())
}

// These are observed capture errors, distinct from a child that simply leaves no
// report. Retain them even after the actual waited status has been persisted.
pub(crate) fn finish_capture(
    log: &mut impl std::io::Write,
    forwarded: &mut impl std::io::Write,
    directory: &super::diagnostics::Directory,
    status: std::process::ExitStatus,
) -> Result<bool, String> {
    log.flush()
        .inspect_err(|_| super::diagnostics::error("capture_flush"))
        .map_err(|e| e.to_string())?;
    let forwarding_failed = forwarded.flush().is_err();
    if forwarding_failed {
        super::diagnostics::error("forwarding");
    }
    let log_hash = directory
        .hash("execution.log")
        .inspect_err(|_| super::diagnostics::error("capture_digest"))?;
    let preflight_hash = directory
        .hash("preflight.json")
        .inspect_err(|_| super::diagnostics::error("capture_digest"))?;
    let exit = json!({"code":status.code(),"success":status.success(),"log":log_hash,"preflight":preflight_hash});
    directory
        .write_capture("exit.json", &exit)
        .inspect_err(|_| super::diagnostics::error("capture_receipt"))?;
    Ok(forwarding_failed)
}

/// Recheck a capture against the current compiled source and actual artifacts/preconditions.
/// The exit receipt must come from the supervising process, outside child-controlled output.
pub fn verify_capture(capture: &Path, served: &Path, tracer: &Path) -> Result<(), String> {
    let read = |name| -> Result<Value, String> {
        super::strict_json::parse(
            &std::fs::read_to_string(capture.join(name)).map_err(|e| e.to_string())?,
        )
    };
    let exit = read("exit.json")?;
    if exit["success"] != true || exit["code"] != 0 {
        return Err("capture records unsuccessful actual exit".into());
    }
    if exit["log"] != identity::file(&capture.join("execution.log"))? {
        return Err("capture log digest mismatch".into());
    }
    if exit["preflight"] != identity::file(&capture.join("preflight.json"))? {
        return Err("capture preflight digest mismatch".into());
    }
    super::auxiliary::validate_preflight(&read("preflight.json")?, true)?;
    super::served_checks::validate_preflight(&read("preflight.json")?, true, served)?;
    let actual = provenance(served, tracer)?;
    if read("identity.json")? != actual {
        return Err("stale capture provenance".into());
    }
    let log = std::fs::read_to_string(capture.join("execution.log")).map_err(|e| e.to_string())?;
    let mut census = FixtureCensus::default();
    let mut timing_output = super::timing_output::Output::default();
    for line in log.lines() {
        timing_output.observe(line)?;
        census.observe(line)?;
        if is_success_verdict(line) {
            return Err("child supplied forged verdict".into());
        }
    }
    let reports: Vec<_> = log
        .lines()
        .filter_map(|l| l.strip_prefix("TRACER_EVIDENCE "))
        .collect();
    let [report] = reports.as_slice() else {
        return Err("capture needs exactly one complete evidence report".into());
    };
    let report = super::strict_json::parse(report)?;
    if census.helpers.as_ref() != Some(&report["prerequisite_requests"]) {
        return Err("prerequisite request observation mismatch".into());
    }
    validate_observed(&report, Some(0), &actual, true, &census.value())?;
    timing_output.validate(&report)?;
    println!(
        "FULL EXECUTION EVIDENCE VALID: {} {}",
        inventory_hash(),
        success_verdict(&inventory()["coverage"], true)?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncertified_coverage_only_publishes_partial_execution_credit() {
        assert_eq!(
            success_verdict(&json!({"complete":false}), true).unwrap(),
            "TRACER PARTIAL PASS (coverage.complete=false)"
        );
        assert_eq!(
            success_verdict(&json!({"complete":false}), false).unwrap(),
            "TARGETED PASS"
        );
        assert_eq!(
            success_verdict(&json!({"complete":true}), true).unwrap(),
            "TRACER PASS"
        );
        for invalid in [
            json!({}),
            json!({"complete":1}),
            json!({"complete":"false"}),
        ] {
            assert!(success_verdict(&invalid, true).is_err());
        }
        for forged in [
            "TRACER PASS",
            "TRACER PARTIAL PASS (coverage.complete=false)",
            "TARGETED PASS",
        ] {
            assert!(is_success_verdict(forged));
        }
    }

    #[test]
    fn partial_capture_still_rejects_failed_exit_and_changed_receipts() {
        let capture = std::env::temp_dir().join(format!(
            "tau-partial-receipt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&capture).unwrap();
        let log = capture.join("execution.log");
        let preflight = capture.join("preflight.json");
        std::fs::write(&log, "synthetic receipt control\n").unwrap();
        std::fs::write(&preflight, "{}").unwrap();
        let mut exit = json!({"code":0,"success":true,
            "log":identity::file(&log).unwrap(),
            "preflight":identity::file(&preflight).unwrap()});
        let verify = |receipt: &Value| {
            std::fs::write(capture.join("exit.json"), receipt.to_string()).unwrap();
            verify_capture(
                &capture,
                Path::new("unused-served"),
                Path::new("unused-tracer"),
            )
            .unwrap_err()
        };
        exit["code"] = json!(1);
        assert!(verify(&exit).contains("unsuccessful actual exit"));
        exit["code"] = json!(0);
        std::fs::write(&log, "changed synthetic receipt control\n").unwrap();
        assert!(verify(&exit).contains("log digest mismatch"));
        exit["log"] = json!(identity::file(&log).unwrap());
        std::fs::write(&preflight, "{\"changed\":true}").unwrap();
        assert!(verify(&exit).contains("preflight digest mismatch"));
        std::fs::remove_dir_all(&capture).unwrap();
    }

    // Synthetic evidence exercises the production validator without starting fixtures.
    // It earns no execution or conformance credit.
    fn complete() -> Value {
        let mut report = json!({"schema":1,"mode":"full","inventory":inventory_hash(),
            "provenance":{"source":"current-source","served":"current-served","tracer":"current-tracer",
                "preconditions":{"fresh_profile":true,"serial":true,"local_fixtures":true,"declaration_witnesses":true}},
            "execution_ok":true,"mandatory":{"cleanup":true,"same_browser_policy_command":true},
            "selected":[],"support":[],"cases":[],"domains":{"inference-credentials":{"count":2,"bound":3}},
            "prerequisite_requests":{"runtime.worker.ready":704,"runtime.store.ready_nontransient":1313,"runtime.store.not_failed":1313,"binding.fixture_class.ready":95,"binding.page.bound":677},"duration_ns":10000,"timings":[
                {"phase":"fixtures","start_ns":0,"end_ns":1},
                {"phase":"browser","start_ns":1,"end_ns":2},
                {"phase":"groups","start_ns":2,"end_ns":9998},
                {"phase":"cleanup","start_ns":9998,"end_ns":9999}]});
        let cases: Vec<_> = inventory()["cases"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, spec)| {
                let mut case = json!({"id":spec["id"],"site_id":spec["site_id"],"ok":true,
                "start_ns":3+i*2,"end_ns":4+i*2,
                "branches":{"reload-revoke":"absent","second-worker":"unopened"}});
                case["assertions"] = json!(
                    expected_assertions(spec, &case, &report)
                        .unwrap()
                        .into_iter()
                        .map(|id| json!({"id":id,"ok":true}))
                        .collect::<Vec<_>>()
                );
                case
            })
            .collect();
        let mut groups: Vec<Value> = Vec::new();
        for case in &cases {
            let spec = inventory()["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["id"] == case["id"])
                .unwrap();
            if let Some(last) = groups.last_mut().filter(|g| g["id"] == spec["scenario_id"]) {
                last["end_ns"] = case["end_ns"].clone();
            } else {
                groups.push(json!({"id":spec["scenario_id"],"start_ns":case["start_ns"],"end_ns":case["end_ns"]}));
            }
        }
        report["group_spans"] = json!(groups);
        report["cases"] = json!(cases);
        report["scenario_spans"] = json!(
            inventory()["scope_order"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|id| inventory()["scenario_scopes"]
                    .get(id.as_str().unwrap())
                    .map(|count| (id, count)))
                .flat_map(|(id, count)| (1..=count.as_u64().unwrap())
                    .map(|invocation| json!({"id":id,"invocation":invocation,"start_ns":2,"end_ns":9998}))
                    .collect::<Vec<_>>())
                .collect::<Vec<_>>()
        );
        report["catalogue"] = super::super::catalogue::cases();
        populate_prerequisites(&mut report);
        report
    }

    fn populate_prerequisites(report: &mut Value) {
        let mut counts =
            super::super::history::expected_prerequisites(if report["mode"] == "full" {
                inventory()
            } else {
                &report["plan"]
            });
        let polls = counts
            .get("runtime.store.ready_nontransient")
            .copied()
            .unwrap_or(0);
        counts.insert("runtime.store.not_failed".into(), polls);
        report["prerequisite_requests"] = json!(
            counts
                .iter()
                .filter(|(id, _)| inventory()["dynamic_prerequisites"].get(*id).is_some())
                .map(|(id, n)| (id.clone(), *n))
                .collect::<BTreeMap<_, _>>()
        );
        report["prerequisites"] = json!(
            counts
                .iter()
                .flat_map(|(id, count)| (1..=*count)
                    .map(move |n| json!({"id":id,"instance":format!("{id}.i{n:03}"),"ok":true})))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn full_neighbor_and_missing_extra_duplicate_assertions() {
        let base = complete();
        validate_inventory(&base, Some(0), &base["provenance"], true).unwrap();
        // The first expected assertion is independently fixed here, including its site.
        assert_eq!(base["cases"][0]["assertions"][0]["id"], "main.a001.i001");
        for action in ["missing", "extra", "duplicate", "removed-predicate"] {
            let mut bad = base.clone();
            let assertions = bad["cases"][0]["assertions"].as_array_mut().unwrap();
            match action {
                "missing" | "removed-predicate" => {
                    assertions.remove(0);
                }
                "extra" => assertions.push(json!({"id":"unregistered.i001","ok":true})),
                _ => {
                    assertions[1] = assertions[0].clone();
                }
            }
            assert!(
                validate_inventory(&bad, Some(0), &base["provenance"], true)
                    .unwrap_err()
                    .contains("assertion"),
                "{action}"
            );
            validate_inventory(&base, Some(0), &base["provenance"], true).unwrap();
        }
    }

    #[test]
    fn serial_history_incomplete_exit_and_targeted_promotion_refuse() {
        let base = complete();
        for position in [0, 3, base["cases"].as_array().unwrap().len() - 1] {
            let mut bad = base.clone();
            bad["cases"].as_array_mut().unwrap().remove(position);
            assert!(validate_inventory(&bad, Some(0), &base["provenance"], true).is_err());
        }
        let mut bad = base.clone();
        bad["cases"].as_array_mut().unwrap().swap(0, 1);
        // Keep valid monotonic slots: this control targets scenario order itself.
        for i in 0..2 {
            bad["cases"][i]["start_ns"] = json!(3 + i * 2);
            bad["cases"][i]["end_ns"] = json!(4 + i * 2);
        }
        assert!(
            validate_inventory(&bad, Some(0), &base["provenance"], true)
                .unwrap_err()
                .contains("order/history")
        );
        bad = base.clone();
        bad["mandatory"]["same_browser_policy_command"] = false.into();
        assert!(validate_inventory(&bad, Some(0), &base["provenance"], true).is_err());
        for status in [None, Some(1), Some(137)] {
            assert!(
                validate_inventory(&base, status, &base["provenance"], true)
                    .unwrap_err()
                    .contains("exit")
            );
        }
        for field in ["mode", "selected", "support"] {
            bad = base.clone();
            bad[field] = if field == "mode" {
                json!("targeted")
            } else {
                json!(["main.c001.p001"])
            };
            assert!(
                validate_inventory(&bad, Some(0), &base["provenance"], true)
                    .unwrap_err()
                    .contains("targeted/incomplete")
            );
        }
        validate_inventory(&base, Some(0), &base["provenance"], true).unwrap();
    }

    #[test]
    fn provenance_inventory_verdict_and_timings_are_checked() {
        let base = complete();
        for key in ["source", "served", "tracer", "preconditions"] {
            let mut bad = base.clone();
            bad["provenance"][key] = json!("stale");
            assert!(
                validate_inventory(&bad, Some(0), &base["provenance"], true)
                    .unwrap_err()
                    .contains("provenance")
            );
        }
        for bad in [
            json!("TRACER PASS"),
            json!({"verdict":"TRACER PASS"}),
            json!({}),
        ] {
            assert!(validate_inventory(&bad, Some(0), &base["provenance"], true).is_err());
        }
        let mut bad = base.clone();
        bad["inventory"] = json!("stale");
        assert!(validate_inventory(&bad, Some(0), &base["provenance"], true).is_err());
        bad = base.clone();
        bad["execution_ok"] = false.into();
        assert!(validate_inventory(&bad, Some(0), &base["provenance"], true).is_err());
        bad = base.clone();
        bad["timings"][2]["end_ns"] = 1.into();
        assert!(
            validate_inventory(&bad, Some(0), &base["provenance"], true)
                .unwrap_err()
                .contains("timing")
        );
        bad = base.clone();
        bad["timings"][0]["unexpected"] = json!("value");
        assert!(
            validate_inventory(&bad, Some(0), &base["provenance"], true)
                .unwrap_err()
                .contains("timing")
        );
        validate_inventory(&base, Some(0), &base["provenance"], true).unwrap();
    }

    #[test]
    fn fixture_census_does_not_shrink_when_an_assertion_is_removed() {
        let base = complete();
        let mut bad = base.clone();
        let case = bad["cases"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|c| c["id"] == "inference_cases.c014.p001")
            .unwrap();
        let checks = case["assertions"].as_array_mut().unwrap();
        let at = checks
            .iter()
            .position(|a| a["id"] == "inference_cases.a068.i002")
            .unwrap();
        checks.remove(at);
        assert!(validate_inventory(&bad, Some(0), &base["provenance"], true).is_err());
        validate_inventory(&base, Some(0), &base["provenance"], true).unwrap();
    }

    #[test]
    fn full_rejects_targeted_overrides_and_forged_census() {
        let base = complete();
        // This synthetic fixture tests the inventory/census components. Real helper
        // and reader histories are required by the combined execution boundary.
        assert_eq!(
            base["domains"],
            json!({"inference-credentials":{"count":2,"bound":3}})
        );
        validate_inventory(&base, Some(0), &base["provenance"], true).unwrap();
        let mut bad = base.clone();
        bad["plan"] = json!({"assertion_overrides":{"main.c001.p001":{"assertions":[]}}});
        bad["cases"][0]["assertions"] = json!([]);
        assert!(
            validate_inventory(&bad, Some(0), &base["provenance"], true)
                .unwrap_err()
                .contains("targeted/incomplete")
        );
        assert!(
            validate_observed(
                &base,
                Some(0),
                &base["provenance"],
                true,
                &json!({"inference-credentials":{"count":3,"bound":4}})
            )
            .unwrap_err()
            .contains("mint history")
        );
        bad = base.clone();
        bad["group_spans"][0]["id"] = json!("wrong-scenario");
        assert!(
            validate_inventory(&bad, Some(0), &base["provenance"], true)
                .unwrap_err()
                .contains("group timing")
        );
        bad = base.clone();
        bad["prerequisites"].as_array_mut().unwrap().remove(0);
        assert!(
            validate_inventory(&bad, Some(0), &base["provenance"], true)
                .unwrap_err()
                .contains("prerequisite")
        );
    }

    #[test]
    fn fixture_observation_order_duplicates_and_cut_census_refuse() {
        let mut census = FixtureCensus::default();
        assert!(
            census
                .observe("TRACER_FIXTURE {\"kind\":\"mint\",\"ordinal\":1}")
                .is_err()
        );
        let mut census = FixtureCensus::default();
        census
            .observe("TRACER_FIXTURE {\"kind\":\"request\"}")
            .unwrap();
        census
            .observe("TRACER_FIXTURE {\"kind\":\"mint\",\"ordinal\":1}")
            .unwrap();
        census
            .observe("TRACER_FIXTURE {\"kind\":\"census\",\"id\":\"inference-credentials\"}")
            .unwrap();
        assert_eq!(
            census.value(),
            json!({"inference-credentials":{"count":2,"bound":2}})
        );
        assert!(
            census
                .observe("TRACER_FIXTURE {\"kind\":\"census\",\"id\":\"inference-credentials\"}")
                .is_err()
        );
    }

    #[test]
    fn every_targeted_plan_has_an_eligible_complete_neighbor() {
        let base = complete();
        for selection in super::super::selection::test_selections() {
            let plan = super::super::selection::plan(&selection).unwrap();
            let mut report = base.clone();
            report["mode"] = json!("targeted");
            report["plan"] = plan.clone();
            report["selected"] = plan["selected"].clone();
            report["support"] = plan["support"].clone();
            let cases: Vec<_> = plan["expected_execution"]
                .as_array()
                .unwrap()
                .iter()
                .map(|id| {
                    let mut case = base["cases"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|c| c["id"] == *id)
                        .unwrap()
                        .clone();
                    let spec = inventory()["cases"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|c| c["id"] == *id)
                        .unwrap();
                    case["assertions"] = json!(
                        expected_assertions(spec, &case, &report)
                            .unwrap()
                            .iter()
                            .map(|id| json!({"id":id,"ok":true}))
                            .collect::<Vec<_>>()
                    );
                    case
                })
                .collect();
            let mut groups: Vec<Value> = Vec::new();
            for case in &cases {
                let spec = inventory()["cases"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|s| s["id"] == case["id"])
                    .unwrap();
                if let Some(last) = groups.last_mut().filter(|g| g["id"] == spec["scenario_id"]) {
                    last["end_ns"] = case["end_ns"].clone();
                } else {
                    groups.push(json!({"id":spec["scenario_id"],"start_ns":case["start_ns"],"end_ns":case["end_ns"]}));
                }
            }
            report["group_spans"] = json!(groups);
            report["cases"] = json!(cases);
            report["scenario_spans"] = json!(
                inventory()["scope_order"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|id| plan["scenario_scopes"]
                        .get(id.as_str().unwrap())
                        .map(|count| (id, count)))
                    .flat_map(|(id, count)| (1..=count.as_u64().unwrap())
                        .map(|invocation| json!({"id":id,"invocation":invocation,"start_ns":2,"end_ns":9998}))
                        .collect::<Vec<_>>())
                    .collect::<Vec<_>>()
            );
            populate_prerequisites(&mut report);
            validate_inventory(&report, Some(0), &base["provenance"], false)
                .unwrap_or_else(|e| panic!("{}: {e}", plan["name"]));
            assert!(validate_inventory(&report, Some(0), &base["provenance"], true).is_err());
        }
    }
}
