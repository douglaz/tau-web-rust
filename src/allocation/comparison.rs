//! The companion comparison (ADR-0032, "How the implementation is compared"; `CNF-3`): the
//! allocation witness file, read at run time from the pinned tree and never compiled in
//! (ADR-0031), drives the production core, [`Metadata`], through every trace. After each step the
//! outcome members and the `journal` projection (`spec/docs/design/witness-file-v1.md`) are
//! compared with what the core says and holds. Anything the reader does not know fails, and every
//! failure names its trace — a witness by its declarations, an enumerated trace by its index —
//! and its step.

use super::*;
use crate::seed::Seed;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

/// The file, under the pinned tree.
const FILE: &str = "spec/docs/design/allocation-witnesses-v1.json";

/// The module's one guard parameter (witness-file-v1.md, "Both arrays hold traces").
const GUARD: &str = "restoredAllocatesNone";

/// The header's members, sorted: they are compared sorted, whatever order the map keeps.
const HEADER: [&str; 6] = [
    "bound",
    "enumeration",
    "module",
    "namespace",
    "schema",
    "witnesses",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    #[allow(dead_code, reason = "required by the schema; nothing compares it")]
    declaration: String,
    events: u32,
    alphabet: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Trace {
    declarations: Vec<String>,
    assumptions: BTreeMap<String, Value>,
    #[serde(default)]
    pair: Option<Pair>,
    start: Journal,
    steps: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pair {
    side: Side,
    with: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Side {
    Refused,
    Admitted,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    event: Value,
    #[serde(default)]
    allocation: Option<Outcome>,
    #[serde(default)]
    identity: Option<Projected>,
    journal: Journal,
}

#[derive(Clone, Copy, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Admitted,
    Refused,
}

/// The allocation rows of witness-file-v1.md's event table.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Witnessed {
    Allocate {
        provenance: Provenance,
        family: Family,
    },
    Created {
        provenance: Provenance,
        identity: Projected,
    },
    Failed {
        provenance: Provenance,
        identity: Projected,
    },
    Destroyed {
        provenance: Provenance,
        identity: Projected,
    },
    ExportSheet {
        provenance: Provenance,
    },
    Restore {
        provenance: Provenance,
    },
    Replace {
        provenance: Provenance,
    },
}

/// The provenances ADR-0032's closed vocabulary gives the allocation events.
#[derive(Clone, Copy, Debug, PartialEq, Deserialize)]
enum Provenance {
    #[serde(rename = "model request")]
    ModelRequest,
    #[serde(rename = "adapter observation")]
    AdapterObservation,
    #[serde(rename = "operator act")]
    OperatorAct,
    #[serde(rename = "import or restore")]
    ImportOrRestore,
}

impl Witnessed {
    /// The kind, the provenance the file gives and the one the event table gives the kind.
    fn kind(&self) -> (&'static str, Provenance, Provenance) {
        use Provenance::*;
        match self {
            Witnessed::Allocate { provenance, .. } => ("allocate", *provenance, ModelRequest),
            Witnessed::Created { provenance, .. } => ("created", *provenance, AdapterObservation),
            Witnessed::Failed { provenance, .. } => ("failed", *provenance, AdapterObservation),
            Witnessed::Destroyed { provenance, .. } => {
                ("destroyed", *provenance, AdapterObservation)
            }
            Witnessed::ExportSheet { provenance } => ("export_sheet", *provenance, OperatorAct),
            Witnessed::Restore { provenance } => ("restore", *provenance, ImportOrRestore),
            Witnessed::Replace { provenance } => ("replace", *provenance, OperatorAct),
        }
    }
}

/// An identity in the projection: the seed as an ordinal.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Projected {
    seed: usize,
    derivation_version: u32,
    family: Family,
    index: u32,
}

#[derive(Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectedEntry {
    seed: usize,
    derivation_version: u32,
    family: Family,
    index: u32,
    status: Status,
}

/// The `journal` projection.
#[derive(Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    seed: usize,
    derivation_version: u32,
    next_unused: NextUnused,
    entries: Vec<ProjectedEntry>,
    restored_from_import: bool,
}

/// The seed identifiers the driver generates, by ordinal: generated on first use, so ordinal
/// `n` is the same seed in every trace.
#[derive(Default)]
struct Seeds(Vec<String>);

impl Seeds {
    fn id(&mut self, ordinal: usize) -> String {
        while self.0.len() <= ordinal {
            self.0.push(Seed::generate().expect("the CSPRNG").id());
        }
        self.0[ordinal].clone()
    }

    fn ordinal(&self, id: &str) -> Result<usize, String> {
        self.0
            .iter()
            .position(|known| known == id)
            .ok_or_else(|| format!("a seed the driver never generated ({id})"))
    }

    fn identity(&mut self, p: &Projected) -> Identity {
        Identity {
            seed: self.id(p.seed),
            derivation_version: p.derivation_version,
            family: p.family,
            index: p.index,
        }
    }

    fn project(&self, identity: &Identity) -> Result<Projected, String> {
        Ok(Projected {
            seed: self.ordinal(&identity.seed)?,
            derivation_version: identity.derivation_version,
            family: identity.family,
            index: identity.index,
        })
    }

    fn journal(&self, core: &Metadata) -> Result<Journal, String> {
        Ok(Journal {
            seed: self.ordinal(&core.seed)?,
            derivation_version: core.derivation_version,
            next_unused: core.next_unused,
            entries: core
                .entries
                .iter()
                .map(|e| {
                    let p = self.project(&e.identity)?;
                    Ok(ProjectedEntry {
                        seed: p.seed,
                        derivation_version: p.derivation_version,
                        family: p.family,
                        index: p.index,
                        status: e.status,
                    })
                })
                .collect::<Result<_, String>>()?,
            restored_from_import: core.restored_from_import,
        })
    }

    /// The core in the state `start` projects.
    fn build(&mut self, start: &Journal) -> Metadata {
        Metadata {
            seed: self.id(start.seed),
            derivation_version: start.derivation_version,
            next_unused: start.next_unused,
            entries: start
                .entries
                .iter()
                .map(|e| Entry {
                    identity: Identity {
                        seed: self.id(e.seed),
                        derivation_version: e.derivation_version,
                        family: e.family,
                        index: e.index,
                    },
                    status: e.status,
                })
                .collect(),
            restored_from_import: start.restored_from_import,
        }
    }
}

fn outcome(identity: &Option<Projected>) -> String {
    match identity {
        Some(identity) => format!("admitted {identity:?}"),
        None => "refused".into(),
    }
}

/// Drives the core through `trace`. A step the reader cannot read is an error; each step where
/// the core differs from the file is one entry of the result, with its step number.
fn drive(label: &str, trace: &Trace, seeds: &mut Seeds) -> Result<Vec<(usize, String)>, String> {
    let mut core = seeds.build(&trace.start);
    // A Replace takes the next ordinal after every one the trace has named.
    let mut fresh = trace
        .start
        .entries
        .iter()
        .map(|e| e.seed)
        .chain([trace.start.seed])
        .max()
        .unwrap_or_default()
        + 1;
    let mut exported: Option<Metadata> = None;
    let mut differences = Vec::new();
    for (n, step) in (1..).zip(&trace.steps) {
        let at = format!("{label}, step {n}");
        let step: Step = serde_json::from_value(step.clone()).map_err(|e| format!("{at}: {e}"))?;
        let event: Witnessed =
            serde_json::from_value(step.event.clone()).map_err(|e| format!("{at}: event: {e}"))?;
        let (kind, provenance, expected) = event.kind();
        if provenance != expected {
            return Err(format!(
                "{at}: {kind} with provenance {provenance:?}, not {expected:?}"
            ));
        }
        let at = format!("{at} ({kind})");
        if let Witnessed::Allocate { family, .. } = &event {
            let expected = match (step.allocation, step.identity) {
                (Some(Outcome::Admitted), Some(identity)) => Some(identity),
                (Some(Outcome::Refused), None) => None,
                (allocation, identity) => {
                    return Err(format!(
                        "{at}: an outcome of {allocation:?} with identity {identity:?}"
                    ));
                }
            };
            let issued = core.issue(*family).and_then(|identity| {
                core.apply(&Event::Reserve(identity.clone()))?;
                Ok(identity)
            });
            let actual = match issued {
                Ok(identity) => match seeds.project(&identity) {
                    Ok(p) => Some(p),
                    Err(e) => return Err(format!("{at}: {e}")),
                },
                Err(_) => None,
            };
            if actual != expected {
                differences.push((
                    n,
                    format!(
                        "{at}: allocation: expected {}, actual {}",
                        outcome(&expected),
                        outcome(&actual)
                    ),
                ));
            }
        } else {
            if step.allocation.is_some() || step.identity.is_some() {
                return Err(format!("{at}: an outcome member on an event that has none"));
            }
            // A refused observation changes nothing, which is what the file expects of an
            // observation the journal cannot apply; only the journal after it is compared.
            let applied = match &event {
                Witnessed::Created { identity, .. } => {
                    core.apply(&Event::Created(seeds.identity(identity)))
                }
                Witnessed::Failed { identity, .. } => {
                    core.apply(&Event::Failed(seeds.identity(identity)))
                }
                Witnessed::Destroyed { identity, .. } => {
                    core.apply(&Event::Destroyed(seeds.identity(identity)))
                }
                Witnessed::ExportSheet { .. } => {
                    exported = Some(core.export());
                    Ok(())
                }
                // With no sheet exported, there is nothing to restore.
                Witnessed::Restore { .. } => match &exported {
                    Some(export) => core.apply(&Event::Restore(export.clone())),
                    None => Ok(()),
                },
                Witnessed::Replace { .. } => {
                    fresh += 1;
                    core.apply(&Event::Replace {
                        seed: seeds.id(fresh - 1),
                    })
                }
                Witnessed::Allocate { .. } => unreachable!(),
            };
            drop(applied);
        }
        let actual = seeds.journal(&core).map_err(|e| format!("{at}: {e}"))?;
        if actual != step.journal {
            differences.push((
                n,
                format!(
                    "{at}: journal: expected {:?}, actual {actual:?}",
                    step.journal
                ),
            ));
        }
    }
    Ok(differences)
}

/// What a passing comparison records (ADR-0032, "Evidence").
#[derive(Debug)]
struct Record {
    events: u32,
    alphabet: usize,
    witnesses: usize,
    enumerated: usize,
    /// The pair: the refused side's declaration, the admitted side's and its first differing step.
    pair: (String, String, usize),
}

/// Compares the core with the witness file `bytes`. Every failure is listed, each naming its
/// trace and step.
fn compare(bytes: &[u8]) -> Result<Record, String> {
    let file: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("not a JSON document: {e}"))?;
    let header = file.as_object().ok_or("not a JSON object")?;
    let mut members: Vec<&str> = header.keys().map(String::as_str).collect();
    members.sort_unstable();
    if members != HEADER {
        return Err(format!(
            "the header's members are {members:?}, not {HEADER:?}"
        ));
    }
    if file["schema"] != 1 {
        return Err(format!("schema {}, not 1", file["schema"]));
    }
    if file["module"] != "allocation" {
        return Err(format!("module {}, not \"allocation\"", file["module"]));
    }
    if !file["namespace"].is_string() {
        return Err("the namespace is not a string".into());
    }
    let bound: Bound =
        serde_json::from_value(file["bound"].clone()).map_err(|e| format!("bound: {e}"))?;
    for (i, event) in bound.alphabet.iter().enumerate() {
        serde_json::from_value::<Witnessed>(event.clone())
            .map_err(|e| format!("bound.alphabet[{i}]: {e}"))?;
    }
    let array = |name: &str| {
        file[name]
            .as_array()
            .filter(|a| !a.is_empty())
            .ok_or_else(|| format!("`{name}` is not a non-empty array"))
    };
    let (witnesses, enumeration) = (array("witnesses")?, array("enumeration")?);

    // The initial journal every enumerated trace runs from (witness-file-v1.md, `enumeration`): a
    // fresh seed's metadata, projected. A named witness starts wherever the file says.
    let initial = Journal {
        seed: 0,
        derivation_version: 1,
        next_unused: NextUnused {
            machines: 0,
            passes: 0,
            handoffs: 0,
        },
        entries: Vec::new(),
        restored_from_import: false,
    };
    let mut failures = Vec::new();
    let mut seeds = Seeds::default();
    let mut sequences = HashSet::new();
    // Per declaration of a paired trace: its side, the other side's name, and its differences.
    let mut pairs = BTreeMap::new();
    let labelled = witnesses
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let names: Option<Vec<&str>> = w["declarations"]
                .as_array()
                .and_then(|a| a.iter().map(Value::as_str).collect());
            let label = names
                .filter(|n| !n.is_empty())
                .map_or_else(|| format!("witnesses[{i}]"), |n| n.join(", "));
            (label, w, false)
        })
        .chain(
            (enumeration.iter().enumerate()).map(|(i, t)| (format!("enumeration[{i}]"), t, true)),
        );
    for (label, value, enumerated) in labelled {
        let trace: Trace = match serde_json::from_value(value.clone()) {
            Ok(trace) => trace,
            Err(e) => {
                failures.push(format!("{label}: {e}"));
                continue;
            }
        };
        if enumerated {
            if trace.start != initial {
                failures.push(format!(
                    "{label}: its start is not the initial journal: expected {initial:?}, actual {:?}",
                    trace.start
                ));
            }
            let mut sequence = Vec::new();
            for (n, step) in (1..).zip(&trace.steps) {
                match bound.alphabet.iter().position(|a| *a == step["event"]) {
                    Some(letter) => sequence.push(letter),
                    None => {
                        failures.push(format!("{label}, step {n}: not an event of the alphabet"))
                    }
                }
            }
            if trace.steps.len() > bound.events as usize {
                failures.push(format!("{label}: longer than the bound"));
            }
            // A step outside the alphabet is already a failure, and its sequence a shorter one.
            if sequence.len() == trace.steps.len() && !sequences.insert(sequence) {
                failures.push(format!("{label}: a sequence the enumeration already holds"));
            }
        }
        let side = trace.pair.as_ref().map(|p| p.side);
        let admitted = side == Some(Side::Admitted);
        let names: Vec<&str> = trace.assumptions.keys().map(String::as_str).collect();
        if names != [GUARD] || trace.assumptions[GUARD] != Value::Bool(!admitted) {
            failures.push(format!(
                "{label}: assumptions {:?}, not {{{GUARD:?}: {}}}",
                trace.assumptions, !admitted
            ));
            continue;
        }
        let differences = match drive(&label, &trace, &mut seeds) {
            Ok(differences) => differences,
            Err(e) => {
                failures.push(e);
                continue;
            }
        };
        if let Some(pair) = &trace.pair {
            for name in &trace.declarations {
                pairs.insert(
                    name.clone(),
                    (
                        pair.side,
                        pair.with.clone(),
                        differences.first().map(|d| d.0),
                    ),
                );
            }
        }
        if !admitted {
            failures.extend(differences.into_iter().map(|(_, d)| d));
        }
    }
    let expected = (0..=bound.events)
        .map(|k| bound.alphabet.len().pow(k))
        .sum::<usize>();
    if enumeration.len() != expected {
        failures.push(format!(
            "the enumeration holds {} traces, not the {expected} of at most {} events over {}",
            enumeration.len(),
            bound.events,
            bound.alphabet.len()
        ));
    }

    // ADR-0032: each side names the other, which names it back; the refused side matches (its
    // differences are failures above), and the admitted side must differ.
    let mut found = None;
    for (name, (side, with, differs)) in &pairs {
        match pairs.get(with) {
            Some((other, back, _)) if other != side && back == name => {}
            _ => failures.push(format!(
                "{name}: its pair names {with}, which is not the other side naming it"
            )),
        }
        match (side, differs) {
            (Side::Refused, _) => {}
            (Side::Admitted, Some(step)) => found = Some((with.clone(), name.clone(), *step)),
            (Side::Admitted, None) => failures.push(format!(
                "{name}: the admitted side matches the core at every step, so the negative \
                 control shows nothing"
            )),
        }
    }
    if !pairs.values().any(|(side, ..)| *side == Side::Admitted) {
        failures.push("no admitted side: no negative control".into());
    }
    if !failures.is_empty() {
        let shown = failures.iter().take(12).cloned().collect::<Vec<_>>();
        return Err(format!(
            "{} failures, the first {}:\n{}",
            failures.len(),
            shown.len(),
            shown.join("\n")
        ));
    }
    Ok(Record {
        events: bound.events,
        alphabet: bound.alphabet.len(),
        witnesses: witnesses.len(),
        enumerated: enumeration.len(),
        pair: found.expect("an admitted side that differed, or a failure above"),
    })
}

/// Reads `path` and compares; every failure names the path.
fn compare_file(path: &str) -> Result<Record, String> {
    std::fs::read(path)
        .map_err(|e| e.to_string())
        .and_then(|bytes| compare(&bytes))
        .map_err(|e| format!("{path}: {e}"))
}

fn pinned_path() -> String {
    format!("{}/{FILE}", env!("CARGO_MANIFEST_DIR"))
}

/// The test record: the file, its bound, what was compared, the pair, and the spec commit. The
/// implementation revision is the commit the test ran at.
#[test]
fn the_allocation_core_passes_the_companion_comparison() {
    let path = pinned_path();
    let record = compare_file(&path).unwrap_or_else(|e| panic!("{e}"));
    let (refused, admitted, step) = &record.pair;
    println!("allocation companion comparison: passed");
    println!("  file: {path}");
    println!(
        "  schema 1, module allocation, bound: {} events over an alphabet of {}",
        record.events, record.alphabet
    );
    println!(
        "  compared: {} witnesses and {} enumerated traces, every step",
        record.witnesses, record.enumerated
    );
    println!("  pair: {refused} matched; {admitted} differed at step {step}");
    println!("  spec commit: {}", crate::SPEC_COMMIT);
}

/// `CNF-3`'s three breaks, made in memory from the pinned file: each must fail, naming the trace.
mod breaks {
    use super::*;

    fn pinned() -> Value {
        serde_json::from_slice(&std::fs::read(pinned_path()).unwrap()).unwrap()
    }

    fn failure(file: &Value) -> String {
        match compare(&serde_json::to_vec(file).unwrap()) {
            Ok(record) => panic!("the comparison passed: {record:?}"),
            Err(e) => e,
        }
    }

    /// An enumerated trace with an allocate step: its index and the step's index.
    fn allocating(file: &Value) -> (usize, usize) {
        file["enumeration"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .find_map(|(i, t)| {
                let steps = t["steps"].as_array().unwrap();
                let at = steps.iter().position(|s| s.get("allocation").is_some())?;
                Some((i, at))
            })
            .unwrap()
    }

    #[test]
    fn one_expected_outcome_flipped() {
        let mut file = pinned();
        let witness = &mut file["witnesses"][0];
        let label = witness["declarations"][0].as_str().unwrap().to_string();
        let at = witness["steps"]
            .as_array()
            .unwrap()
            .iter()
            .position(|s| s["allocation"] == "admitted")
            .unwrap();
        let step = &mut witness["steps"][at];
        step["allocation"] = "refused".into();
        step.as_object_mut().unwrap().remove("identity");
        let e = failure(&file);
        assert!(
            e.contains(&format!("{label}, step {} (allocate): allocation", at + 1)),
            "{e}"
        );
    }

    #[test]
    fn the_file_empty_or_absent() {
        assert!(compare(b"").unwrap_err().contains("not a JSON document"));
        let absent = format!(
            "{}/spec/docs/design/absent.json",
            env!("CARGO_MANIFEST_DIR")
        );
        assert!(compare_file(&absent).unwrap_err().starts_with(&absent));
    }

    #[test]
    fn an_unrecognised_event_kind_and_an_unrecognised_outcome() {
        let mut file = pinned();
        file["enumeration"][1]["steps"][0]["event"]["kind"] = "reallocate".into();
        let e = failure(&file);
        assert!(
            e.contains("enumeration[1], step 1: event: unknown variant `reallocate`"),
            "{e}"
        );

        let mut file = pinned();
        let (trace, at) = allocating(&file);
        file["enumeration"][trace]["steps"][at]["allocation"] = "granted".into();
        let e = failure(&file);
        assert!(
            e.contains(&format!(
                "enumeration[{trace}], step {}: unknown variant `granted`",
                at + 1
            )),
            "{e}"
        );
    }

    #[test]
    fn a_truncated_file_or_an_unknown_member() {
        let mut file = pinned();
        file["enumeration"].as_array_mut().unwrap().pop();
        assert!(failure(&file).contains("the enumeration holds 399 traces, not the 400"));

        let mut file = pinned();
        let (trace, at) = allocating(&file);
        file["enumeration"][trace]["steps"][at]["journal"]["note"] = 1.into();
        let e = failure(&file);
        assert!(
            e.contains(&format!("enumeration[{trace}], step {}", at + 1)),
            "{e}"
        );
        assert!(e.contains("unknown field `note`"), "{e}");

        let mut file = pinned();
        file["witnesses"][0]["steps"][0]["event"]["note"] = 1.into();
        let label = file["witnesses"][0]["declarations"][0]
            .as_str()
            .unwrap()
            .to_string();
        let e = failure(&file);
        assert!(
            e.contains(&format!("{label}, step 1: event: unknown field `note`")),
            "{e}"
        );
    }

    /// An enumerated trace starting elsewhere fails, naming it, whether it has no step to compare
    /// (the empty trace) or steps whose journals differ too.
    fn started_elsewhere(trace: usize, change: impl FnOnce(&mut Value)) {
        let mut file = pinned();
        change(&mut file["enumeration"][trace]["start"]);
        let e = failure(&file);
        assert!(
            e.contains(&format!(
                "enumeration[{trace}]: its start is not the initial journal: expected"
            )),
            "{e}"
        );
    }

    #[test]
    fn the_empty_trace_starting_elsewhere() {
        assert_eq!(pinned()["enumeration"][0]["steps"], serde_json::json!([]));
        started_elsewhere(0, |start| start["next_unused"]["machines"] = 5.into());
    }

    #[test]
    fn a_trace_with_steps_starting_elsewhere() {
        let (trace, _) = allocating(&pinned());
        started_elsewhere(trace, |start| start["restored_from_import"] = true.into());
    }

    /// Without its admitted side, the refused side names the missing pair.
    #[test]
    fn a_pair_without_its_admitted_side() {
        let mut file = pinned();
        let witnesses = file["witnesses"].as_array_mut().unwrap();
        let admitted = witnesses
            .iter()
            .position(|w| w["pair"]["side"] == "admitted")
            .unwrap();
        let refused = witnesses[admitted]["pair"]["with"]
            .as_str()
            .unwrap()
            .to_string();
        witnesses.remove(admitted);
        let e = failure(&file);
        assert!(e.contains(&format!("{refused}: its pair names")), "{e}");
        assert!(e.contains("no admitted side: no negative control"), "{e}");
    }
}
