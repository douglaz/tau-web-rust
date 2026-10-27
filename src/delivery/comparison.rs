//! Runtime adapter for the pinned opaque witness contract. No companion source is used.
use super::*;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
const NAMES: [&str; 9] = [
    "version",
    "listeners.inbound",
    "listeners.outbound",
    "services",
    "key_material.spendable",
    "key_material.permitted",
    "drift_checks",
    "required",
    "default_credentials",
];
const WITNESSES: [&str; 8] = [
    "adhoc_delivered",
    "empty_inbound_refused",
    "empty_inbound_admitted",
    "undeclared_listener_finding",
    "empty_outbound_not_finding",
    "template_blocked",
    "absent_field_refused",
    "spendable_declared_refused",
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    schema: u64,
    module: String,
    namespace: String,
    bound: Value,
    witnesses: Vec<Value>,
    enumeration: Vec<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Trace {
    assumptions: Assumptions,
    declarations: Vec<String>,
    start: Start,
    pair: Option<Pair>,
    steps: Vec<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assumptions {
    #[serde(rename = "emptyMeansPerField")]
    empty_means_per_field: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pair {
    side: String,
    with: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Start {
    declaration: BTreeMap<String, Value>,
    machine: Machine,
    record: Projection,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Machine {
    multi_tenant: bool,
    observed: BTreeMap<String, Vec<u16>>,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
struct Projection {
    delivered: bool,
    verdicts: BTreeMap<String, Outcome>,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Pass,
    Refused,
    Blocked,
    Finding,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Check { field: String, provenance: String },
    Deliver { provenance: String },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    event: Event,
    record: Projection,
    verdict: Option<Outcome>,
    delivered: Option<bool>,
}

fn inbound(n: u16) -> Inbound {
    Inbound {
        proto: Protocol::Tcp,
        port: n,
        from: From::Any,
    }
}
fn outbound(n: u16) -> Outbound {
    Outbound {
        proto: Protocol::Tcp,
        host: format!("fixture-{n}.example"),
        port: 443,
    }
}
fn service(n: u16) -> Service {
    Service {
        name: format!("fixture-{n}"),
        scope: Scope::System,
        lifecycle: Lifecycle::RunningAtDelivery,
    }
}
fn material(n: u16) -> Material {
    Material {
        kind: MaterialKind::Public,
        r#where: format!("/fixture/key-{n}.pub"),
    }
}
fn presence<T>(v: Option<&Value>, parse: impl FnOnce(&Value) -> Option<T>) -> Stated<T> {
    match v {
        None => Stated::Missing,
        Some(v) if v == "unspecified" => Stated::Unspecified,
        Some(v) => parse(v).map(Stated::Specified).unwrap_or(Stated::Invalid),
    }
}
fn list<T>(v: &Value, map: impl Fn(u16) -> T) -> Option<Vec<T>> {
    v.as_array()?
        .iter()
        .map(|v| u16::try_from(v.as_u64()?).ok().map(&map))
        .collect()
}
fn inputs(start: &Start) -> Result<(Intended, Measurements), String> {
    if start
        .declaration
        .keys()
        .any(|k| !NAMES.contains(&k.as_str()))
        || start
            .machine
            .observed
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != NAMES.into_iter().collect()
    {
        return Err("unknown or missing input field".into());
    }
    let d = &start.declaration;
    let intended = Intended {
        version: presence(d.get("version"), |v| {
            v.as_u64().and_then(|v| u32::try_from(v).ok())
        }),
        inbound: presence(d.get("listeners.inbound"), |v| list(v, inbound)),
        outbound: presence(d.get("listeners.outbound"), |v| list(v, outbound)),
        services: presence(d.get("services"), |v| list(v, service)),
        spendable: presence(d.get("key_material.spendable"), Value::as_bool),
        permitted: presence(d.get("key_material.permitted"), |v| list(v, material)),
        drift: presence(d.get("drift_checks"), |v| {
            list(v, |n| CheckIdentity(format!("check-{n}")))
        }),
        required: presence(d.get("required"), |v| {
            list(v, |n| CheckIdentity(format!("check-{n}")))
        }),
        credentials: presence(d.get("default_credentials"), |v| {
            if v == "none" {
                Some(vec![])
            } else {
                list(v, |n| format!("credential-{n}"))
            }
        }),
    };
    let seen = &start.machine.observed;
    // For a service the opaque observation is a demonstration of the named promise. A
    // measured empty set means those promises were read and not demonstrated.
    let service_facts = match &intended.services {
        Stated::Specified(services) => services
            .iter()
            .map(|s| ServiceFact {
                service: s.clone(),
                state: if seen["services"].iter().any(|n| service(*n) == *s) {
                    ServiceState::Running
                } else {
                    ServiceState::Difference
                },
                running_after_last_placement: false,
            })
            .collect(),
        _ => vec![],
    };
    let m = Measurements {
        inbound: Measured::Value(
            seen["listeners.inbound"]
                .iter()
                .copied()
                .map(inbound)
                .collect(),
        ),
        outbound: Measured::Value(
            seen["listeners.outbound"]
                .iter()
                .copied()
                .map(outbound)
                .collect(),
        ),
        services: Measured::Value(service_facts),
        spendable: Measured::Value(!seen["key_material.spendable"].is_empty()),
        permitted: Measured::Value(
            seen["key_material.permitted"]
                .iter()
                .copied()
                .map(material)
                .collect(),
        ),
        required: Measured::Value(
            seen["required"]
                .iter()
                .map(|n| format!("check-{n}"))
                .collect(),
        ),
        credentials: Measured::Value(
            seen["default_credentials"]
                .iter()
                .map(|n| format!("credential-{n}"))
                .collect(),
        ),
        fixed_default_credentials: Measured::Value(true),
        sshd_posture: Measured::Value(true),
        placing_session: false,
    };
    Ok((intended, m))
}
fn outcome(s: Status) -> Result<Outcome, String> {
    Ok(match s {
        Status::Checked => Outcome::Pass,
        Status::Finding => Outcome::Finding,
        Status::Blocked => Outcome::Blocked,
        Status::SchemaError => Outcome::Refused,
        Status::Unavailable => return Err("comparison lacks a measured observation".into()),
    })
}
fn trace(value: &Value, name: &str, admitted: bool) -> Result<(), String> {
    let run = || -> Result<(), String> {
        let t: Trace =
            serde_json::from_value(value.clone()).map_err(|e| format!("trace contract: {e}"))?;
        if t.assumptions.empty_means_per_field == admitted {
            return Err("unknown assumption".into());
        }
        if t.declarations != [format!("TauWeb.Declaration.{name}")] && name != "bounded" {
            return Err("unknown declaration provenance".into());
        }
        if name == "bounded" && t.declarations != ["TauWeb.Declaration.bounded"] {
            return Err("enumeration provenance".into());
        }
        if t.pair.is_some() && !matches!(name, "empty_inbound_refused" | "empty_inbound_admitted") {
            return Err("unexpected pair metadata".into());
        }
        if let Some(pair) = &t.pair {
            let (side, other) = if admitted {
                ("admitted", "empty_inbound_refused")
            } else {
                ("refused", "empty_inbound_admitted")
            };
            if pair.side != side || pair.with != format!("TauWeb.Declaration.{other}") {
                return Err("broken pair".into());
            }
        } else if name.starts_with("empty_inbound_") {
            return Err("missing pair".into());
        }
        if t.start.record
            != (Projection {
                delivered: false,
                verdicts: BTreeMap::new(),
            })
        {
            return Err("start projection differs".into());
        }
        if t.steps.len() != 10 {
            return Err("incomplete event coverage".into());
        }
        let (d, m) = inputs(&t.start)?;
        let class = if t.start.machine.multi_tenant {
            MachineClass::MultiTenant
        } else {
            MachineClass::SinglePurpose
        };
        let results = fields(&d, class, &m, &[]);
        let mut checked = vec![];
        let mut previous_expected = t.start.record.clone();
        let mut projection = t.start.record;
        let mut differences = BTreeSet::new();
        for (i, value) in t.steps.iter().enumerate() {
            let mut step_run = || -> Result<_, String> {
                let s: Step = serde_json::from_value(value.clone())
                    .map_err(|e| format!("unknown event/outcome or step shape: {e}"))?;
                let names = NAMES[..(i + 1).min(9)]
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>();
                if s.record
                    .verdicts
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>()
                    != names
                    || previous_expected
                        .verdicts
                        .iter()
                        .any(|(field, outcome)| s.record.verdicts.get(field) != Some(outcome))
                {
                    return Err("unknown, missing or changed checked-field projection".into());
                }
                match &s.event {
                    Event::Check { field, provenance } => {
                        if i >= 9
                            || field != NAMES[i]
                            || provenance != "adapter observation"
                            || s.delivered.is_some()
                            || s.verdict.is_none()
                            || s.record.delivered
                            || s.record.verdicts.get(field) != s.verdict.as_ref()
                        {
                            return Err("check event/provenance".into());
                        }
                        let result = results[i].clone();
                        let actual = outcome(result.status)?;
                        let mismatch = s.verdict.as_ref() != Some(&actual);
                        projection.verdicts.insert(field.clone(), actual);
                        checked.push(result);
                        Ok((s.record, mismatch))
                    }
                    Event::Deliver { provenance } => {
                        if i != 9
                            || provenance != "model request"
                            || s.verdict.is_some()
                            || s.delivered.is_none()
                            || Some(s.record.delivered) != s.delivered
                        {
                            return Err("deliver event/provenance".into());
                        }
                        projection.delivered = aggregate(checked.clone(), &[], false).delivered;
                        Ok((s.record, s.delivered != Some(projection.delivered)))
                    }
                }
            };
            let (expected, mismatch) = step_run().map_err(|e| format!("step {i}: {e}"))?;
            previous_expected = expected.clone();
            if admitted {
                // Assert each consequence of this known weakened guard separately. A
                // carried inbound difference cannot satisfy the final delivery outcome.
                if i >= 1
                    && (projection.verdicts.get("listeners.inbound") != Some(&Outcome::Finding)
                        || expected.verdicts.get("listeners.inbound") != Some(&Outcome::Pass))
                {
                    return Err(format!(
                        "step {i}: admitted inbound outcome/projection must be pass against production finding; actual {projection:?}, expected {expected:?}"
                    ));
                }
                if i == 9 && (projection.delivered || !expected.delivered || !mismatch) {
                    return Err(format!(
                        "step {i}: admitted final-delivery outcome/projection must be true against production false; actual {projection:?}, expected {expected:?}"
                    ));
                }
                // Only this pair's inbound guard and consequent final delivery may differ.
                // These are assertions on projections, never an evaluator assumption switch.
                let mut actual_rest = projection.clone();
                let mut expected_rest = expected.clone();
                actual_rest.verdicts.remove("listeners.inbound");
                expected_rest.verdicts.remove("listeners.inbound");
                if i == 9 {
                    actual_rest.delivered = false;
                    expected_rest.delivered = false;
                }
                if actual_rest != expected_rest || (mismatch && i != 1 && i != 9) {
                    return Err(format!(
                        "step {i}: unrelated admitted-side outcome/knowledge mismatch"
                    ));
                }
            }
            if expected != projection || mismatch {
                differences.insert(i);
            }
            if !admitted && differences.contains(&i) {
                return Err(format!(
                    "step {i}: outcome/knowledge mismatch: actual {projection:?}, expected {expected:?}"
                ));
            }
        }
        if admitted && differences != (1..10).collect() {
            return Err(format!(
                "admitted negative control must differ at steps 1..9, got {differences:?}"
            ));
        }
        Ok(())
    };
    run().map_err(|e| format!("{name}: {e}"))
}
fn base() -> Value {
    json!({"declaration":{"version":2,"listeners.inbound":[22],"listeners.outbound":[],"services":[],
        "key_material.spendable":false,"key_material.permitted":[],"drift_checks":[],"required":[],"default_credentials":"none"},
        "machine":{"multi_tenant":false,"observed":NAMES.into_iter().map(|f|(f,if f=="listeners.inbound"{json!([22])}else{json!([])})).collect::<BTreeMap<_,_>>()}})
}
fn bound() -> Value {
    let presences: BTreeMap<_, _> = NAMES
        .into_iter()
        .map(|f| {
            (
                f,
                match f {
                    "version" => json!(["missing", "unspecified", 1, 2]),
                    "key_material.spendable" => json!(["missing", "unspecified", false, true]),
                    "default_credentials" => json!(["missing", "unspecified", "none", [1]]),
                    _ => json!(["missing", "unspecified", [], [1]]),
                },
            )
        })
        .collect();
    json!({"declaration":"TauWeb.Declaration.bound","base":base(),"presences":presences,"observations":[[],[1]],"tenancies":[false,true]})
}
fn compare(path: &Path) -> Result<(), String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("input-validation {}: {e}", path.display()))?;
    compare_bytes(&bytes, path)
}
fn compare_bytes(bytes: &[u8], path: &Path) -> Result<(), String> {
    let f: File = serde_json::from_slice(bytes)
        .map_err(|e| format!("input-validation {}: {e}", path.display()))?;
    if f.schema != 1
        || f.module != "declaration"
        || f.namespace != "TauWeb.Declaration"
        || f.bound != bound()
    {
        return Err(format!(
            "input-validation {}: unknown header or bound",
            path.display()
        ));
    }
    if f.witnesses.len() != 8 || f.enumeration.len() != 144 {
        return Err("input-validation: incomplete witness/field sweep".into());
    }
    for (name, t) in WITNESSES.iter().zip(&f.witnesses) {
        trace(t, name, *name == "empty_inbound_admitted")?;
    }
    if f.witnesses[1]["start"] != f.witnesses[2]["start"]
        || f.witnesses[1]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| &s["event"])
            .collect::<Vec<_>>()
            != f.witnesses[2]["steps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| &s["event"])
                .collect::<Vec<_>>()
    {
        return Err("empty_inbound_refused: pair inputs differ".into());
    }
    let mut expected = BTreeMap::<String, usize>::new();
    for field in NAMES {
        for presence in f.bound["presences"][field].as_array().unwrap() {
            for observation in f.bound["observations"].as_array().unwrap() {
                for tenancy in f.bound["tenancies"].as_array().unwrap() {
                    let mut start = base();
                    if presence == "missing" {
                        start["declaration"].as_object_mut().unwrap().remove(field);
                    } else {
                        start["declaration"][field] = presence.clone();
                    }
                    start["machine"]["observed"][field] = observation.clone();
                    start["machine"]["multi_tenant"] = tenancy.clone();
                    *expected.entry(start.to_string()).or_default() += 1;
                }
            }
        }
    }
    let mut actual = BTreeMap::<String, usize>::new();
    for (i, t) in f.enumeration.iter().enumerate() {
        trace(t, "bounded", false).map_err(|e| format!("enumeration[{i}] {e}"))?;
        let mut start = t["start"].clone();
        start
            .as_object_mut()
            .ok_or("bounded: start object")?
            .remove("record");
        *actual.entry(start.to_string()).or_default() += 1;
    }
    if actual != expected {
        return Err("bounded: incomplete bound sweep".into());
    }
    eprintln!(
        "declaration comparison: {}: bound TauWeb.Declaration.bound; 8 witnesses, 144 cases, 1520 steps; refused matches, admitted differs; spec {}",
        path.display(),
        crate::SPEC_COMMIT
    );
    Ok(())
}
#[test]
fn declaration_companion_comparison() {
    let path = std::env::var_os("TAU_DECLARATION_WITNESSES")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("spec/docs/design/declaration-witnesses-v1.json")
        });
    compare(&path).unwrap_or_else(|e| panic!("declaration comparison: {e}"));
}

#[test]
fn admitted_outcomes_are_independent_of_carried_differences() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("spec/docs/design/declaration-witnesses-v1.json");
    let original = std::fs::read(&path).unwrap();
    compare_bytes(&original, &path).expect("unmodified corpus including admitted control");
    for (change, diagnostic) in [
        (
            "final_delivery",
            "step 9: admitted final-delivery outcome/projection",
        ),
        (
            "inbound_blocked",
            "step 1: admitted inbound outcome/projection",
        ),
    ] {
        let mut v: Value = serde_json::from_slice(&original).unwrap();
        let steps = v["witnesses"][2]["steps"].as_array_mut().unwrap();
        match change {
            "final_delivery" => {
                steps[9]["delivered"] = json!(false);
                steps[9]["record"]["delivered"] = json!(false);
            }
            "inbound_blocked" => {
                steps[1]["verdict"] = json!("blocked");
                for step in &mut steps[1..] {
                    step["record"]["verdicts"]["listeners.inbound"] = json!("blocked");
                }
            }
            _ => unreachable!(),
        }
        let why = compare_bytes(&serde_json::to_vec(&v).unwrap(), &path)
            .err()
            .unwrap_or_else(|| {
                panic!("{change}: corrupted admitted outcome must refuse comparison")
            });
        assert!(
            why.contains(&format!("empty_inbound_admitted: {diagnostic}")),
            "{change}: {why}"
        );
    }
}

#[test]
fn declaration_comparison_refuses_incomplete_and_unknown_contracts() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("spec/docs/design/declaration-witnesses-v1.json");
    let original: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for change in [
        "schema",
        "member",
        "bound",
        "empty",
        "assumption",
        "provenance",
        "pair",
        "admitted_pair",
        "unknown_pair",
        "extra_pair",
        "admitted_member",
        "admitted_missing_outcome",
        "admitted_unrelated",
        "outcome",
        "coverage",
        "start",
    ] {
        let mut v = original.clone();
        match change {
            "schema" => v["schema"] = json!(100),
            "member" => v["unexpected"] = json!(true),
            "bound" => {
                v["bound"]["presences"]
                    .as_object_mut()
                    .unwrap()
                    .remove("services");
            }
            "empty" => v["enumeration"] = json!([]),
            "assumption" => v["witnesses"][0]["assumptions"]["unknown"] = json!(true),
            "provenance" => {
                v["witnesses"][0]["steps"][0]["event"]["provenance"] = json!("model text")
            }
            "pair" => {
                v["witnesses"][1].as_object_mut().unwrap().remove("pair");
            }
            "admitted_pair" => {
                v["witnesses"][2].as_object_mut().unwrap().remove("pair");
            }
            "unknown_pair" => v["witnesses"][2]["pair"]["side"] = json!("unknown"),
            "extra_pair" => {
                v["witnesses"][0]["pair"] =
                    json!({"side":"refused","with":"TauWeb.Declaration.empty_inbound_admitted"})
            }
            "admitted_member" => {
                v["witnesses"][2]["steps"][1]["record"]["verdicts"]["unknown"] = json!("pass")
            }
            "admitted_missing_outcome" => {
                v["witnesses"][2]["steps"][1]
                    .as_object_mut()
                    .unwrap()
                    .remove("verdict");
            }
            "admitted_unrelated" => {
                v["witnesses"][2]["steps"][2]["verdict"] = json!("blocked");
                v["witnesses"][2]["steps"][2]["record"]["verdicts"]["listeners.outbound"] =
                    json!("blocked");
            }
            "outcome" => v["witnesses"][0]["steps"][0]["verdict"] = json!("unknown"),
            "coverage" => v["enumeration"][0] = v["enumeration"][10].clone(),
            "start" => v["witnesses"][0]["start"]["record"]["delivered"] = json!(true),
            _ => unreachable!(),
        }
        let why = compare_bytes(
            &serde_json::to_vec(&v).unwrap(),
            Path::new("contract-refusal-fixture"),
        )
        .expect_err(change);
        assert!(
            why.contains("input-validation")
                || why.contains("adhoc_delivered")
                || why.contains("empty_inbound_refused")
                || why.contains("empty_inbound_admitted")
                || why.contains("bounded"),
            "{change}: {why}"
        );
    }
}
