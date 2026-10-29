//! Dispatch companion comparison, read at run time under ADR-0032.
use super::*;
use crate::credential::{LocalPassphrase, WrappingKey};
use crate::harness::{AppendRefusal, Entry, Journal};
use crate::store::{self, Event, Fault, Kdf, MemoryStorage, OperationError, Salt, Store, block_on};
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashSet};
use std::path::Path;

const FILE: &str = "spec/docs/design/dispatch-witnesses-v8.json";
const GUARDS: &[&str] = &[
    "approvalResetRequiresRescue",
    "approvedReinstallBoundary",
    "commandHold",
    "destructiveStops",
    "dispositionBindsContinuation",
    "dispositionOwnResource",
    "durableBeforeApply",
    "endedBelowSucceeded",
    "failedPrerequisiteWithdraws",
    "identityExclusion",
    "lapse",
    "newestActivationRead",
    "orderAssociation",
    "reach",
    "rebootBootChange",
    "reinstallWithdrawalEffective",
    "resetIntoRescueOnly",
    "resetOfferCurrentInstallation",
    "resetOfferFreshKeys",
    "resourceKey",
    "sessionDestroyRefused",
];
const PAIRS: &[(&str, &str, &str)] = &[
    (
        "excluded_order_refused",
        "excluded_order_sent_without_guard",
        "identityExclusion",
    ),
    (
        "order_receipt_association_required",
        "order_receipt_without_association_admitted",
        "orderAssociation",
    ),
    (
        "second_command_held",
        "second_command_without_hold",
        "commandHold",
    ),
    (
        "session_destroy_under_abandonment_refused",
        "session_destroy_lifts_abandonment_without_guard",
        "sessionDestroyRefused",
    ),
    (
        "same_action_new_call_id_refused",
        "same_action_new_call_id_admitted",
        "resourceKey",
    ),
    (
        "second_index_same_entry_refused",
        "second_index_same_entry_admitted",
        "resourceKey",
    ),
    (
        "boot_id_change_not_success_refused",
        "boot_id_change_not_success_admitted",
        "endedBelowSucceeded",
    ),
    (
        "resolution_append_failed_refused",
        "resolution_append_failed_admitted",
        "durableBeforeApply",
    ),
    (
        "disposition_one_continuation_refused",
        "disposition_unrestricted_admitted",
        "dispositionBindsContinuation",
    ),
    (
        "read_does_not_lift_abandonment",
        "read_lifts_abandonment_without_guard",
        "lapse",
    ),
    (
        "destructive_choice_stops_commands",
        "command_preempts_reinstall_without_guard",
        "destructiveStops",
    ),
    (
        "read_and_inference_never_restricted",
        "read_and_inference_restricted_without_guard",
        "reach",
    ),
    (
        "disposition_names_own_unresolved_calls",
        "disposition_ends_call_elsewhere_without_guard",
        "dispositionOwnResource",
    ),
    (
        "replacement_in_force",
        "replaced_continuation_dispatched_without_guard",
        "reach",
    ),
];

fn name(short: &str) -> String {
    format!("TauWeb.Dispatch.{short}")
}
fn production(guard: &str) -> Value {
    match guard {
        "resourceKey" => json!("entry"),
        "reach" => json!("disposed"),
        "lapse" => json!("continuation"),
        _ => json!(true),
    }
}
fn members(value: &Value, keys: &[&str]) -> Result<(), String> {
    let actual: BTreeSet<_> = value
        .as_object()
        .ok_or("not an object")?
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<_> = keys.iter().copied().collect();
    if actual == expected {
        Ok(())
    } else {
        Err(format!("members: expected {expected:?}, actual {actual:?}"))
    }
}
fn parse<T: serde::de::DeserializeOwned + Serialize>(value: &Value) -> Result<T, String> {
    let parsed: T = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    if serde_json::to_value(&parsed).map_err(|e| e.to_string())? != *value {
        return Err("record must use its schema object shape".into());
    }
    Ok(parsed)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum WResource {
    MachineEntry(u64),
    Inference(bool),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum WTarget {
    Entry(u64),
    AllocationIndex(u32),
    VendorMachineId(u64),
    InferenceCap(bool),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WApproval {
    #[serde(deserialize_with = "required_option")]
    receipt_binding: Option<ReceiptBinding>,
    session: u64,
    facts: u64,
}
// Journal compatibility defaults must not allow absent schema-8 witness fields.
fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WReceipt {
    source: ReceiptSource,
    call: u64,
    resource: WResource,
    target: WTarget,
    binding: ReceiptBinding,
    validated: bool,
    #[serde(deserialize_with = "required_option")]
    returned_vendor: Option<u64>,
    returned_withheld: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WCall {
    call: u64,
    target: WTarget,
    resource: WResource,
    operation: Operation,
    session: u64,
    approved: WApproval,
    state: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WAssociation {
    target: WTarget,
    entry: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WDisposition {
    resource: WResource,
    calls: Vec<u64>,
    continuation: Continuation,
    valid: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WStanding {
    resource: WResource,
    calls: Vec<u64>,
    continuation: Continuation,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WUnresolved {
    resource: WResource,
    calls: Vec<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installation {
    entry: u64,
    installation: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WQuarantined {
    #[serde(deserialize_with = "required_option")]
    vendor: Option<u64>,
    entry: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WExclusion {
    entry: u64,
    records: Vec<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Knowledge {
    associations: Vec<WAssociation>,
    quarantined: Vec<WQuarantined>,
    identity_exclusions: Vec<WExclusion>,
    calls: Vec<WCall>,
    current_installations: Vec<Installation>,
    dispatched: Vec<u64>,
    dispositions: Vec<WDisposition>,
    durable: bool,
    prerequisite_records: Vec<Value>,
    reboot_results: Vec<Value>,
    receipts: Vec<WReceipt>,
    reinstall_approvals: Vec<Value>,
    reinstall_withdrawals: Vec<Value>,
    reset_offer: Vec<Value>,
    standing: Vec<WStanding>,
    unresolved: Vec<WUnresolved>,
}
impl Knowledge {
    fn normalize(&mut self) {
        self.current_installations.sort_by_key(|x| x.entry);
        self.identity_exclusions.sort_by_key(|x| x.entry);
        self.standing
            .sort_by_key(|x| serde_json::to_string(&x.resource).unwrap());
        self.unresolved
            .sort_by_key(|x| serde_json::to_string(&x.resource).unwrap());
    }
    fn validate(&self) -> Result<(), String> {
        for (key, v) in [
            ("prerequisite_records", &self.prerequisite_records),
            ("reboot_results", &self.reboot_results),
            ("reinstall_approvals", &self.reinstall_approvals),
            ("reinstall_withdrawals", &self.reinstall_withdrawals),
            ("reset_offer", &self.reset_offer),
        ] {
            if !v.is_empty() {
                return Err(format!("{key}: stage1 must retain its initial empty value"));
            }
        }
        for c in &self.calls {
            if !["unresolved", "terminal", "no_effect"].contains(&c.state.as_str()) {
                return Err(format!("unknown call state {}", c.state));
            }
            to_resource(&c.resource)?;
            to_target(&c.target)?;
        }
        for x in &self.identity_exclusions {
            if x.records.windows(2).any(|w| w[0] >= w[1]) {
                return Err("identity exclusion record order".into());
            }
        }
        if self
            .identity_exclusions
            .iter()
            .map(|x| x.entry)
            .collect::<BTreeSet<_>>()
            .len()
            != self.identity_exclusions.len()
        {
            return Err("duplicate identity exclusion entry".into());
        }
        for r in &self.receipts {
            if r.returned_withheld && r.returned_vendor.is_some() {
                return Err("contradictory returned presence".into());
            }
            to_resource(&r.resource)?;
            to_target(&r.target)?;
        }
        for a in &self.associations {
            to_target(&a.target)?;
        }
        for r in self
            .dispositions
            .iter()
            .map(|d| &d.resource)
            .chain(self.standing.iter().map(|d| &d.resource))
            .chain(self.unresolved.iter().map(|d| &d.resource))
        {
            to_resource(r)?;
        }
        // Keyed sets still refuse duplicate keys rather than normalizing a malformed file away.
        for keys in [
            self.standing
                .iter()
                .map(|x| json!(x.resource).to_string())
                .collect::<Vec<_>>(),
            self.unresolved
                .iter()
                .map(|x| json!(x.resource).to_string())
                .collect(),
            self.current_installations
                .iter()
                .map(|x| x.entry.to_string())
                .collect(),
        ] {
            if keys.iter().collect::<BTreeSet<_>>().len() != keys.len() {
                return Err("duplicate projection key".into());
            }
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trace {
    declarations: Vec<String>,
    assumptions: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pair: Option<Pair>,
    start: Value,
    steps: Vec<Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pair {
    side: String,
    with: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Witnessed {
    Request {
        provenance: String,
        call: u64,
        target: WTarget,
        operation: Operation,
        session: u64,
        facts: u64,
        #[serde(deserialize_with = "required_option")]
        approved: Option<WApproval>,
        appended: bool,
    },
    Receive {
        provenance: String,
        receipt: WReceipt,
        appended: bool,
    },
    Associate {
        provenance: String,
        target: WTarget,
        entry: u64,
    },
    AssociateEvidence {
        provenance: String,
        vendor: u64,
        entry: u64,
        withheld: bool,
        appended: bool,
    },
    Read {
        provenance: String,
        source: Source,
        resource: WResource,
        operation: Operation,
        reports: Reading,
        appended: bool,
    },
    Dispose {
        provenance: String,
        resource: WResource,
        calls: Vec<u64>,
        continuation: Continuation,
        appended: bool,
    },
    Replay {
        provenance: String,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Source {
    AdapterRead,
    JobRecord,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Reading {
    Succeeded,
    Ended,
}

// Partition supplied by the ticket, an implementation reading of ADR-0032.
// Python, verbatim:
// def rescue(t):
//     start=t['start']; dispositions=list(start['dispositions'])
//     if start['reset_offer'] or any(start[k] for k in
//             ('reinstall_approvals','reinstall_withdrawals','prerequisite_records')):
//         return True
//     for step in t['steps']:
//         e=step['event']; kind=e['kind']
//         if kind in ('reset_prereqs','approve_reinstall','withdraw_reinstall'):
//             return True
//         if kind in ('request','read'):
//             if e['operation'] in ('activate','register_key'): return True
//             if kind=='request' and e['operation']=='reset' and any(
//                     d['continuation']=='destructive_reinstall' for d in dispositions):
//                 return True
//         if kind=='dispose': dispositions.append(e)
//     return False
//
// def reboot(t):
//     s=t['start']
//     return bool(s.get('reboot_results')) or any(
//         c['operation']=='delivery_reboot' for c in s['calls']) or any(
//         x['event']['kind']=='collect_reboot' or (
//             x['event']['kind']=='request' and x['event']['operation']=='delivery_reboot')
//         for x in t['steps'])
//
// def dispatch(t):
//     if rescue(t): return 'dedicated'
//     if reboot(t): return 'reboot'
//     return 'stage1'
fn bucket(trace: &Trace) -> Result<usize, String> {
    let start = &trace.start;
    let mut dispositions = start["dispositions"]
        .as_array()
        .ok_or("start dispositions is not an array")?
        .clone();
    if [
        "reset_offer",
        "reinstall_approvals",
        "reinstall_withdrawals",
        "prerequisite_records",
    ]
    .iter()
    .any(|k| start[k].as_array().is_some_and(|v| !v.is_empty()))
    {
        return Ok(1);
    }
    for step in &trace.steps {
        let e = &step["event"];
        match e["kind"].as_str().ok_or("event has no kind")? {
            "reset_prereqs" | "approve_reinstall" | "withdraw_reinstall" => return Ok(1),
            kind @ ("request" | "read") => {
                if [json!("activate"), json!("register_key")].contains(&e["operation"]) {
                    return Ok(1);
                }
                if kind == "request"
                    && e["operation"] == "reset"
                    && dispositions
                        .iter()
                        .any(|d| d["continuation"] == "destructive_reinstall")
                {
                    return Ok(1);
                }
            }
            "dispose" => dispositions.push(e.clone()),
            _ => {}
        }
    }
    if start["reboot_results"]
        .as_array()
        .is_some_and(|v| !v.is_empty())
        || start["calls"]
            .as_array()
            .ok_or("start calls is not an array")?
            .iter()
            .any(|c| c["operation"] == "delivery_reboot")
        || trace.steps.iter().any(|s| {
            s["event"]["kind"] == "collect_reboot"
                || (s["event"]["kind"] == "request" && s["event"]["operation"] == "delivery_reboot")
        })
    {
        return Ok(2);
    }
    Ok(0)
}

fn to_resource(value: &WResource) -> Result<Resource, String> {
    match value {
        WResource::MachineEntry(n) => Ok(Resource::Entry(format!("entry-{n}"))),
        WResource::Inference(true) => Ok(Resource::Inference),
        _ => Err("unknown inference resource".into()),
    }
}
fn to_target(value: &WTarget) -> Result<Target, String> {
    match value {
        WTarget::Entry(n) => Ok(Target::Entry(format!("entry-{n}"))),
        WTarget::AllocationIndex(n) => Ok(Target::AllocationIndex(*n)),
        WTarget::VendorMachineId(n) => Ok(Target::VendorMachine(format!("vendor-{n}"))),
        WTarget::InferenceCap(true) => Ok(Target::Inference),
        _ => Err("unknown inference target".into()),
    }
}
fn ordinal(value: &str, prefix: &str) -> u64 {
    value
        .strip_prefix(prefix)
        .expect("bijection prefix")
        .parse()
        .expect("bijection ordinal")
}
fn from_resource(value: &Resource) -> WResource {
    match value {
        Resource::Entry(e) => WResource::MachineEntry(ordinal(e, "entry-")),
        Resource::Inference => WResource::Inference(true),
    }
}
fn from_target(value: &Target) -> WTarget {
    match value {
        Target::Entry(e) => WTarget::Entry(ordinal(e, "entry-")),
        Target::AllocationIndex(n) => WTarget::AllocationIndex(*n),
        Target::VendorMachine(e) => WTarget::VendorMachineId(ordinal(e, "vendor-")),
        Target::Inference => WTarget::InferenceCap(true),
    }
}
fn facts(n: u64) -> Facts {
    Facts {
        arguments: BTreeMap::from([("fixture_fact".into(), n.to_string())]),
        cost_bound: 0,
        bundle_commit: crate::SPEC_COMMIT.into(),
    }
}
struct FixtureKdf;
impl Kdf for FixtureKdf {
    async fn derive(&self, _: LocalPassphrase, _: &Salt) -> Result<WrappingKey, String> {
        Ok(WrappingKey([17; 32]))
    }
}
fn pass() -> LocalPassphrase {
    LocalPassphrase::new(b"comparison fixture passphrase".to_vec())
}
struct Driver {
    store: Store<MemoryStorage>,
    calls: BTreeMap<u64, u64>,
    indices: BTreeMap<u32, u32>,
    // Member 0 is a whole record; setup's implicit associations use members 1.. .
    // The fixture setup shell itself is not an abstract journal occurrence.
    record_ordinals: BTreeMap<(u64, usize), u64>,
    next_ordinal: u64,
}
impl Driver {
    fn new(start: &Value) -> Result<Self, String> {
        let knowledge: Knowledge = parse(start)?;
        knowledge.validate()?;
        let store = block_on(store::create(MemoryStorage::default(), &FixtureKdf, pass()))
            .map_err(|e| format!("create: {e:?}"))?;
        let mut driver = Self {
            store,
            calls: BTreeMap::new(),
            indices: BTreeMap::new(),
            record_ordinals: BTreeMap::new(),
            next_ordinal: 0,
        };
        block_on(
            driver
                .store
                .seed_backup(crate::allocation::Completion::Skipped),
        )?;
        let mut entries = fixture_setup();
        entries[0].machine = "entry-2".into();
        entries[1].machine = "entry-1".into();
        let setup_number = driver.store.records().end;
        let approval = block_on(driver.store.approve_setup(entries))?;
        for (i, entry) in approval.entries.iter().enumerate() {
            let expected = knowledge
                .associations
                .get(i)
                .ok_or("missing start association")?;
            if expected.entry != ordinal(&entry.entry.machine, "entry-")
                || expected.target != [WTarget::AllocationIndex(2), WTarget::AllocationIndex(0)][i]
            {
                return Err("start setup association differs".into());
            }
            driver.record_occurrence(setup_number, i + 1);
        }
        for entry in &approval.entries {
            driver.store.fixture_requirements(&entry.entry.machine);
        }
        driver.indices.insert(2, approval.entries[0].identity.index);
        driver.indices.insert(0, approval.entries[1].identity.index);
        let extra = block_on(driver.store.allocate(crate::allocation::Family::Machines))?;
        driver.indices.insert(1, extra.index);
        if driver.indices.values().collect::<BTreeSet<_>>().len() != driver.indices.len() {
            return Err("allocation map is not injective".into());
        }
        // Extra mappings use the same committed association primitive as later order ids.
        for target in [WTarget::AllocationIndex(1), WTarget::VendorMachineId(10)] {
            let association = Association {
                target: driver.to_target(&target)?,
                entry: "entry-1".into(),
            };
            let number = driver.store.records().end;
            block_on(driver.store.associate(association))?;
            driver.recorded(number);
        }
        if knowledge.associations.len() != driver.next_ordinal as usize {
            return Err("unsupported starting associations".into());
        }
        for c in &knowledge.calls {
            if c.state != "unresolved" {
                return Err("start: unsupported settled call".into());
            }
            let request = driver.request(
                &c.target,
                c.operation,
                c.session,
                c.approved.facts,
                Some(&c.approved),
            )?;
            let resource = to_resource(&c.resource)?;
            if driver.store.dispatch().resolve(&request.target) != Some(resource) {
                return Err("start call resource differs from harness association".into());
            }
            let intent = block_on(driver.store.operation(&request))
                .map_err(|e| format!("start call: {e:?}"))?;
            driver.recorded(intent.call);
            driver.calls.insert(c.call, intent.call);
        }
        for d in &knowledge.dispositions {
            let resource = to_resource(&d.resource)?;
            let disposition = driver.disposition(&resource, &d.calls, d.continuation);
            if resource == Resource::Inference {
                return Err("start inference disposition is outside this comparison".into());
            }
            // Only the invalid historical disposition needs a writer that bypasses
            // admission: the production writer correctly refuses to record it.
            let number = driver.store.records().end;
            if d.valid {
                block_on(driver.store.dispose(disposition))?;
            } else {
                block_on(
                    driver
                        .store
                        .dispatch_fixture_record(Event::Disposition(disposition)),
                )?;
            }
            driver.recorded(number);
        }
        driver.replay()?;
        Ok(driver)
    }
    fn record_occurrence(&mut self, number: u64, member: usize) {
        assert!(
            self.record_ordinals
                .insert((number, member), self.next_ordinal)
                .is_none(),
            "each abstract durable occurrence is mapped once"
        );
        self.next_ordinal += 1;
    }
    fn recorded(&mut self, number: u64) {
        self.record_occurrence(number, 0);
    }
    fn record_symbol(&self, number: u64) -> u64 {
        *self
            .record_ordinals
            .get(&(number, 0))
            .expect("durable witness record bijection")
    }
    fn replay(&mut self) -> Result<(), String> {
        self.store = block_on(store::unlock(
            MemoryStorage::with_files(self.store.storage().files()),
            &FixtureKdf,
            pass(),
        ))?;
        Ok(())
    }
    fn to_target(&self, value: &WTarget) -> Result<Target, String> {
        if let WTarget::AllocationIndex(n) = value {
            return self
                .indices
                .get(n)
                .copied()
                .map(Target::AllocationIndex)
                .ok_or_else(|| "unmapped witness index".into());
        }
        to_target(value)
    }
    fn witness_target(&self, value: &Target) -> WTarget {
        if let Target::AllocationIndex(n) = value {
            return WTarget::AllocationIndex(
                *self
                    .indices
                    .iter()
                    .find(|(_, actual)| **actual == *n)
                    .expect("production index bijection")
                    .0,
            );
        }
        from_target(value)
    }
    fn id(&self, symbolic: u64) -> u64 {
        self.calls
            .get(&symbolic)
            .copied()
            .unwrap_or(u64::MAX - symbolic)
    }
    fn symbol(&self, actual: u64) -> u64 {
        *self
            .calls
            .iter()
            .find(|(_, id)| **id == actual)
            .expect("production call bijection")
            .0
    }
    fn transient(&self) -> u64 {
        (1 << 62)
            + (self.store.dispatch().intent_order.len() + self.store.dispatch().dispositions.len())
                as u64
    }
    fn request(
        &self,
        target: &WTarget,
        operation: Operation,
        session: u64,
        fact: u64,
        approved: Option<&WApproval>,
    ) -> Result<Request, String> {
        let target = self.to_target(target)?;
        let resource = self
            .store
            .dispatch()
            .resolve(&target)
            .unwrap_or(Resource::Entry("unmapped".into()));
        Ok(Request {
            receipt_binding: approved.and_then(|a| a.receipt_binding.clone()),
            target: target.clone(),
            operation,
            session: format!("session-{session}"),
            requester: Requester::Session,
            facts: facts(fact),
            approved: approved.map(|a| OperationApproval {
                receipt_binding: a.receipt_binding.clone(),
                restated_modes: Vec::new(),
                resource,
                target,
                operation,
                session: format!("session-{}", a.session),
                requester: Requester::Session,
                facts: facts(a.facts),
            }),
        })
    }
    fn disposition(
        &self,
        resource: &Resource,
        calls: &[u64],
        continuation: Continuation,
    ) -> Disposition {
        Disposition {
            machine: match resource {
                Resource::Entry(e) => e.clone(),
                Resource::Inference => String::new(),
            },
            calls: calls.iter().map(|c| self.id(*c)).collect(),
            continuation,
            uncertainty: "outcome unknown".into(),
        }
    }
    fn project(&self) -> Knowledge {
        let d = self.store.dispatch();
        let ids = d.call_ids();
        let mut resources = Vec::new();
        for id in &ids {
            let r = d.call_resource(*id).unwrap();
            if !resources.contains(&r) {
                resources.push(r);
            }
        }
        let mut projection = Knowledge {
            quarantined: d
                .association_records
                .iter()
                .filter(|a| !a.association.admitted())
                .map(|a| WQuarantined {
                    vendor: a.association.target().map(|t| match t {
                        Target::VendorMachine(v) => ordinal(v, "vendor-"),
                        _ => panic!("quarantined target kind"),
                    }),
                    entry: ordinal(
                        d.association_entry(&a.association)
                            .expect("canonical entry"),
                        "entry-",
                    ),
                })
                .collect(),
            identity_exclusions: d
                .approved_entries
                .keys()
                .map(|entry| WExclusion {
                    entry: ordinal(entry, "entry-"),
                    records: d
                        .identity_exclusions(entry)
                        .iter()
                        .map(|n| self.record_symbol(*n))
                        .collect(),
                })
                .collect(),
            associations: d
                .associations
                .iter()
                .map(|a| WAssociation {
                    target: self.witness_target(&a.target),
                    entry: ordinal(&a.entry, "entry-"),
                })
                .collect(),
            calls: ids
                .iter()
                .map(|id| {
                    let state = d.call_state(*id).expect("recorded call");
                    let (target, resource, operation, session, approved) =
                        if let Some(c) = d.typed_calls.get(id) {
                            let intent = &c.intent;
                            assert_eq!(
                                intent.receipt_binding, intent.approved.receipt_binding,
                                "recorded call and approved receipt bindings differ"
                            );
                            (
                                self.witness_target(&intent.target),
                                from_resource(&intent.resource),
                                intent.operation,
                                ordinal(&intent.session, "session-"),
                                WApproval {
                                    receipt_binding: intent.approved.receipt_binding.clone(),
                                    session: ordinal(&intent.approved.session, "session-"),
                                    facts: intent.approved.facts.arguments["fixture_fact"]
                                        .parse()
                                        .unwrap(),
                                },
                            )
                        } else {
                            let intent = &d.calls[id].intent;
                            let provenance = intent
                                .provenance
                                .as_ref()
                                .expect("recorded command provenance");
                            let session = ordinal(
                                provenance.session.as_deref().expect("comparison session"),
                                "session-",
                            );
                            let Some(Approval::HarnessPin { fingerprint, .. }) = &intent.approval
                            else {
                                panic!("recorded command admission")
                            };
                            (
                                self.witness_target(&provenance.target),
                                from_resource(&Resource::Entry(intent.machine.clone())),
                                Operation::Exec,
                                session,
                                WApproval {
                                    receipt_binding: None,
                                    session,
                                    facts: ordinal(fingerprint, "SHA256:comparison-fact-"),
                                },
                            )
                        };
                    WCall {
                        call: self.symbol(*id),
                        target,
                        resource,
                        operation,
                        session,
                        approved,
                        state: match state {
                            CallState::Unresolved => "unresolved",
                            CallState::NoEffect => "no_effect",
                            CallState::Disposed { .. }
                            | CallState::Finished { .. }
                            | CallState::Confirmed { .. }
                            | CallState::ReceiptConfirmed { .. } => "terminal",
                            CallState::Cancelled => "cancelled",
                        }
                        .into(),
                    }
                })
                .collect(),
            current_installations: d
                .current_installations
                .iter()
                .map(|(e, n)| Installation {
                    entry: ordinal(e, "entry-"),
                    installation: *n,
                })
                .collect(),
            dispatched: ids.iter().map(|id| self.symbol(*id)).collect(),
            dispositions: d
                .dispositions
                .iter()
                .map(|r| WDisposition {
                    resource: from_resource(&r.resource),
                    calls: r
                        .disposition
                        .calls
                        .iter()
                        .map(|id| self.symbol(*id))
                        .collect(),
                    continuation: r.disposition.continuation,
                    valid: matches!(r.report, DispositionReport::Accepted { .. }),
                })
                .collect(),
            standing: d
                .standing
                .values()
                .chain(d.inference_standing.iter())
                .map(|r| WStanding {
                    resource: from_resource(&r.resource),
                    calls: r
                        .disposition
                        .calls
                        .iter()
                        .map(|id| self.symbol(*id))
                        .collect(),
                    continuation: r.disposition.continuation,
                })
                .collect(),
            unresolved: resources
                .iter()
                .map(|r| WUnresolved {
                    resource: from_resource(r),
                    calls: d.unresolved(r).iter().map(|id| self.symbol(*id)).collect(),
                })
                .collect(),
            durable: true,
            reset_offer: vec![],
            prerequisite_records: vec![],
            reinstall_approvals: vec![],
            reinstall_withdrawals: vec![],
            reboot_results: vec![],
            receipts: d
                .receipts
                .iter()
                .map(|r| {
                    let f = r.receipt.facts();
                    let call = f.call.expect("witness retains call operand");
                    WReceipt {
                        source: f.source,
                        call: self
                            .calls
                            .iter()
                            .find(|(_, id)| **id == call)
                            .map_or(u64::MAX - call, |(symbol, _)| *symbol),
                        resource: from_resource(
                            f.resource.as_ref().expect("witness retains resource"),
                        ),
                        target: self
                            .witness_target(f.target.as_ref().expect("witness retains target")),
                        binding: ReceiptBinding {
                            operation: f.binding.operation,
                            account: f.binding.account.unwrap(),
                            signed_request: f.binding.signed_request.unwrap(),
                        },
                        validated: f.validated,
                        returned_vendor: f.returned_vendor.as_ref().map(|v| ordinal(v, "vendor-")),
                        returned_withheld: r.receipt.returned_presence()
                            == ReturnedPresence::Withheld,
                    }
                })
                .collect(),
        };
        projection.normalize();
        projection
    }
    fn request_refusal(&self, refusal: RequestRefusal) -> Result<Value, String> {
        let refusal = match refusal {
            RequestRefusal::IdentityExclusion { records } => {
                json!({"reason":"identity_exclusion","records":records.iter().map(|n|self.record_symbol(*n)).collect::<Vec<_>>()})
            }
            RequestRefusal::Barrier { calls } => json!({"reason":"barrier",
                "calls":calls.iter().map(|id| self.symbol(*id)).collect::<Vec<_>>()}),
            RequestRefusal::Continuation { in_force } => {
                json!({"reason":"continuation","in_force":in_force.continuation})
            }
            other => return Err(format!("outside stage1 refusal vocabulary: {other:?}")),
        };
        Ok(json!({"dispatch":"refused","refusal":refusal}))
    }
    fn command_refusal(&self, refusal: DispatchRefusal) -> Value {
        let refusal = match refusal {
            DispatchRefusal::Held(hold) => RequestRefusal::Barrier {
                calls: hold.calls.iter().map(|i| i.call).collect(),
            },
            DispatchRefusal::TypedBarrier { calls } => RequestRefusal::Barrier {
                calls: calls.iter().map(|i| i.call).collect(),
            },
            other @ (DispatchRefusal::NoEntry { .. } | DispatchRefusal::Provenance) => {
                panic!("unexpected command refusal: {other:?}")
            }
            DispatchRefusal::Disposition(in_force) => RequestRefusal::Continuation { in_force },
        };
        self.request_refusal(refusal)
            .expect("box-plane refusal vocabulary")
    }
    fn step(&mut self, event: Witnessed) -> Result<Value, String> {
        match event {
            Witnessed::Request {
                provenance,
                call,
                target,
                operation,
                session,
                facts,
                approved,
                appended,
            } => {
                if provenance != "model request" {
                    return Err(format!("unknown request provenance {provenance}"));
                }
                let result = if operation == Operation::Exec {
                    let target = self.to_target(&target)?;
                    let resource = self
                        .store
                        .dispatch()
                        .resolve(&target)
                        .ok_or("command target is unmapped")?;
                    let Resource::Entry(machine) = resource else {
                        return Err("exec names no entry".into());
                    };
                    let approved = approved.as_ref().ok_or("command has no scope admission")?;
                    if approved.session != session {
                        return Err("command admission session differs from its provenance".into());
                    }
                    let entry = Entry {
                        machine: machine.clone(),
                        command: b"true".to_vec(),
                        provenance: Some(CommandProvenance {
                            target,
                            session: Some(format!("session-{session}")),
                            requester: Requester::Session,
                        }),
                    };
                    let approval = Approval::HarnessPin {
                        machine,
                        fingerprint: format!("SHA256:comparison-fact-{}", approved.facts),
                    };
                    // These are the pre-contact check and atomic append run_command uses.
                    match block_on(self.store.check(&entry.machine)) {
                        Err(AppendRefusal::Policy(refusal)) => {
                            return Ok(self.command_refusal(refusal));
                        }
                        Err(e) => return Err(e.to_string()),
                        Ok(()) => {}
                    }
                    if !appended {
                        self.store.storage().fault(Fault::Fail(3));
                    }
                    match block_on(self.store.append(&entry, &approval)) {
                        Ok(number) => Ok(number),
                        Err(AppendRefusal::Policy(refusal)) => {
                            return Ok(self.command_refusal(refusal));
                        }
                        Err(AppendRefusal::Storage(e)) => Err(e),
                        Err(AppendRefusal::SignatureLowering(_)) => {
                            Err("unexpected signature lowering".into())
                        }
                    }
                } else {
                    let request =
                        self.request(&target, operation, session, facts, approved.as_ref())?;
                    if operation == Operation::Inference {
                        let number = self.transient();
                        match self.store.dispatch().prepare(number, &request) {
                            Err(refusal) => return self.request_refusal(refusal),
                            Ok(intent) => {
                                if !appended {
                                    return Err("stage1 inference append is unsupported".into());
                                }
                                self.store.dispatch_mut().operation_intent(number, intent)?;
                                Ok(number)
                            }
                        }
                    } else {
                        if !appended {
                            self.store.storage().fault(Fault::Fail(3));
                        }
                        match block_on(self.store.operation(&request)) {
                            Ok(intent) => Ok(intent.call),
                            Err(OperationError::Policy(refusal)) => {
                                return self.request_refusal(refusal);
                            }
                            Err(OperationError::Storage(e)) => Err(e),
                        }
                    }
                };
                let number = result?;
                self.recorded(number);
                self.calls.insert(call, number);
                Ok(json!({"dispatch":"dispatched"}))
            }
            Witnessed::Dispose {
                provenance,
                resource,
                calls,
                continuation,
                appended,
            } => {
                if provenance != "disposition" {
                    return Err(format!("unknown disposition provenance {provenance}"));
                }
                let resource = to_resource(&resource)?;
                let disposition = self.disposition(&resource, &calls, continuation);
                let number = if resource == Resource::Inference {
                    self.transient()
                } else {
                    self.store.records().end
                };
                if matches!(
                    self.store.dispatch().check_resource_disposition(
                        number,
                        &resource,
                        &disposition
                    ),
                    DispositionReport::Refused { .. }
                ) {
                    return Ok(json!({"disposition":"refused"}));
                }
                if !appended {
                    if resource != Resource::Inference {
                        self.store.storage().fault(Fault::Fail(3));
                        if block_on(self.store.dispose(disposition)).is_ok() {
                            return Err("append unexpectedly succeeded".into());
                        }
                    }
                    return Ok(json!({"disposition":"not_appended"}));
                }
                if resource == Resource::Inference {
                    self.store
                        .dispatch_mut()
                        .resource_disposition(number, resource, disposition);
                } else {
                    block_on(self.store.dispose(disposition))?;
                }
                self.recorded(number);
                Ok(json!({"disposition":"recorded"}))
            }
            Witnessed::Read {
                provenance,
                source,
                resource,
                operation,
                reports,
                appended,
            } => {
                if provenance != "adapter observation" {
                    return Err(format!("unknown read provenance {provenance}"));
                }
                let resource = to_resource(&resource)?;
                let reports = match reports {
                    Reading::Succeeded => Reports::Confirmed,
                    Reading::Ended => Reports::Ended,
                };
                let before = self.store.dispatch().unresolved(&resource);
                let number = self.store.records().end;
                if !appended {
                    self.store.storage().fault(Fault::Fail(3));
                }
                let mut result = if matches!(source, Source::JobRecord)
                    && operation == Operation::Exec
                {
                    let mut result = Ok(());
                    for id in &before {
                        if let Some(call) = self.store.dispatch().calls.get(id) {
                            let record = match reports {
                                Reports::Unknown => crate::jobs::Record::Missing,
                                Reports::Confirmed | Reports::Ended => {
                                    crate::jobs::Record::Present {
                                        machine: hex::encode(&call.intent.machine),
                                        command: call.intent.command.clone(),
                                        boot: "fixture-boot".into(),
                                        current_boot: "fixture-boot".into(),
                                        pid: 7,
                                        alive: false,
                                        exit_status: (reports == Reports::Confirmed).then_some(0),
                                        stdout: String::new(),
                                        stderr: String::new(),
                                    }
                                }
                            };
                            let evidence = crate::jobs::Evidence {
                                call: *id,
                                job: call.intent.job.clone().expect("fixture job identity"),
                                record,
                            };
                            result = block_on(self.store.job_evidence(&evidence)).map(|_| ());
                            if result.is_err() {
                                break;
                            }
                        }
                    }
                    result
                } else {
                    // An adapter read cannot settle exec; job evidence cannot settle cloud operations.
                    let reports = if matches!(source, Source::AdapterRead) {
                        reports
                    } else {
                        Reports::Unknown
                    };
                    let observation =
                        self.store
                            .dispatch()
                            .observation(resource.clone(), operation, reports);
                    block_on(self.store.operation_observation(observation)).map(|_| ())
                };
                // A read still journals an observation when there is no collectable job.
                // Several concrete job constituents, if needed, support one abstract read.
                if result.is_ok() && self.store.records().end == number {
                    let observation = self.store.dispatch().observation(
                        resource.clone(),
                        operation,
                        Reports::Unknown,
                    );
                    result = block_on(self.store.operation_observation(observation)).map(|_| ());
                }
                if appended {
                    result?;
                    self.recorded(number);
                } else if result.is_ok() {
                    return Err("append unexpectedly succeeded".into());
                }
                let after = self.store.dispatch().unresolved(&resource);
                Ok(
                    json!({"settled":before.into_iter().filter(|id| !after.contains(id)).map(|id| self.symbol(id)).collect::<Vec<_>>()}),
                )
            }
            Witnessed::Associate {
                provenance,
                target,
                entry,
            } => {
                if provenance != "operator act" {
                    return Err(format!("unknown association provenance {provenance}"));
                }
                let association = Association {
                    target: self.to_target(&target)?,
                    entry: format!("entry-{entry}"),
                };
                let number = self.store.records().end;
                match block_on(self.store.associate(association)) {
                    Ok(()) => {
                        if self.store.records().end > number {
                            self.recorded(number);
                        }
                    }
                    Err(e) if e == "identity_conflict" || e == "target already associated" => {}
                    Err(e) => return Err(e),
                }
                Ok(json!({}))
            }
            Witnessed::AssociateEvidence {
                provenance,
                vendor,
                entry,
                withheld,
                appended,
            } => {
                if provenance != "adapter observation" {
                    return Err("unknown association evidence provenance".into());
                }
                let raw = Association {
                    target: Target::VendorMachine(format!("vendor-{vendor}")),
                    entry: format!("entry-{entry}"),
                };
                let protection = if withheld {
                    EvidenceProtection::transient("fixture input".into(), &["target"])?
                } else {
                    EvidenceProtection::default()
                };
                // Validate construction before fault injection: a parser or policy error is
                // never credited as evidence of append failure.
                let number = self.store.records().end;
                let expected = self.store.dispatch().protect_association(
                    number,
                    raw.clone(),
                    protection.clone(),
                );
                match expected {
                    Err(e) if e == "identity_conflict" || e == "target already associated" => {
                        return Ok(json!({}));
                    }
                    Err(e) => return Err(e),
                    Ok(None) => return Ok(json!({})),
                    Ok(Some(_)) => {}
                }
                if !appended {
                    self.store.storage().fault(Fault::Fail(3));
                }
                match block_on(self.store.association_evidence(raw, protection)) {
                    Ok(()) if appended => self.recorded(number),
                    Err(e) if !appended && e.contains("made to fail") => {}
                    Err(e) => return Err(e),
                    Ok(()) => return Err("association append unexpectedly succeeded".into()),
                }
                Ok(json!({}))
            }
            Witnessed::Receive {
                provenance,
                receipt,
                appended,
            } => {
                if provenance != "adapter observation" {
                    return Err(format!("unknown receipt provenance {provenance}"));
                }
                let withheld = receipt.returned_withheld;
                if withheld && receipt.returned_vendor.is_some() {
                    return Err("contradictory returned identity".into());
                }
                let receipt = Receipt {
                    source: receipt.source,
                    call: self.id(receipt.call),
                    resource: to_resource(&receipt.resource)?,
                    target: self.to_target(&receipt.target)?,
                    binding: receipt.binding,
                    validated: receipt.validated,
                    returned_vendor: if withheld {
                        Some("fixture received identity".into())
                    } else {
                        receipt.returned_vendor.map(|n| format!("vendor-{n}"))
                    },
                };
                if !appended {
                    self.store.storage().fault(Fault::Fail(3));
                }
                let number = self.store.records().end;
                let result = if withheld {
                    let protection = EvidenceProtection::transient(
                        "fixture input".into(),
                        &["returned_vendor"],
                    )?;
                    block_on(self.store.protected_operation_receipt(receipt, protection))
                } else {
                    block_on(self.store.operation_receipt(receipt))
                };
                let settled = match result {
                    Ok(settled) if appended => settled,
                    Err(_) if !appended => Vec::new(),
                    Ok(_) => return Err("receipt append unexpectedly succeeded".into()),
                    Err(e) => return Err(e),
                };
                if appended {
                    self.recorded(number);
                }
                Ok(
                    json!({"settled": settled.iter().map(|id| self.symbol(*id)).collect::<Vec<_>>()}),
                )
            }
            Witnessed::Replay { provenance } => {
                if provenance != "replay" {
                    return Err(format!("unknown replay provenance {provenance}"));
                }
                self.replay()?;
                Ok(json!({}))
            }
        }
    }
}

fn validate_trace(trace: &Trace) -> Result<(), String> {
    let label = trace.declarations.join(", ");
    let validate_knowledge =
        |v: &Value| -> Result<(), String> { parse::<Knowledge>(v)?.validate() };
    validate_knowledge(&trace.start).map_err(|e| format!("{label}, start: {e}"))?;
    for (index, step) in trace.steps.iter().enumerate() {
        let validate = || -> Result<(), String> {
            let event: Witnessed = parse(&step["event"])?;
            match event {
                Witnessed::Request {
                    target, provenance, ..
                } => {
                    to_target(&target)?;
                    if provenance != "model request" {
                        return Err(format!("unknown request provenance {provenance}"));
                    }
                }
                Witnessed::Read {
                    resource,
                    provenance,
                    ..
                } => {
                    to_resource(&resource)?;
                    if provenance != "adapter observation" {
                        return Err(format!("unknown read provenance {provenance}"));
                    }
                }
                Witnessed::Dispose {
                    resource,
                    provenance,
                    ..
                } => {
                    to_resource(&resource)?;
                    if provenance != "disposition" {
                        return Err(format!("unknown disposition provenance {provenance}"));
                    }
                }
                Witnessed::Associate {
                    provenance, target, ..
                } => {
                    to_target(&target)?;
                    if provenance != "operator act" {
                        return Err(format!("unknown association provenance {provenance}"));
                    }
                }
                Witnessed::Receive {
                    provenance,
                    receipt,
                    ..
                } => {
                    to_resource(&receipt.resource)?;
                    to_target(&receipt.target)?;
                    if provenance != "adapter observation" {
                        return Err(format!("unknown receipt provenance {provenance}"));
                    }
                }
                Witnessed::AssociateEvidence { provenance, .. } => {
                    if provenance != "adapter observation" {
                        return Err("unknown association evidence provenance".into());
                    }
                }
                Witnessed::Replay { provenance } => {
                    if provenance != "replay" {
                        return Err(format!("unknown replay provenance {provenance}"));
                    }
                }
            }
            validate_knowledge(&step["knowledge"])?;
            let mut outcome = step.clone();
            let object = outcome.as_object_mut().ok_or("step is not an object")?;
            object.remove("event");
            object.remove("knowledge");
            validate_outcome(&step["event"], &outcome)
        };
        validate().map_err(|e| format!("{label}, step {}: {e}", index + 1))?;
    }
    Ok(())
}
fn compare_knowledge(expected: &Value, actual: Knowledge) -> Result<(), String> {
    let mut expected: Knowledge = parse(expected)?;
    expected.validate()?;
    expected.normalize();
    if expected == actual {
        Ok(())
    } else {
        Err(format!(
            "knowledge: expected {}, actual {}",
            json!(expected),
            json!(actual)
        ))
    }
}
fn run_trace(trace: &Trace) -> Result<Option<(usize, String)>, String> {
    validate_trace(trace)?;
    let label = trace.declarations.join(", ");
    let mut driver = Driver::new(&trace.start).map_err(|e| format!("{label}, start: {e}"))?;
    let mut difference = compare_knowledge(&trace.start, driver.project())
        .err()
        .map(|e| (0, e));
    for (index, step) in trace.steps.iter().enumerate() {
        let step_number = index + 1;
        let fail = |e: String| format!("{label}, step {step_number}: {e}");
        let event: Witnessed = parse(&step["event"]).map_err(fail)?;
        let outcome = driver.step(event).map_err(fail)?;
        let mut keys: Vec<_> = outcome
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.extend(["event", "knowledge"]);
        // A refusal may be missing or extra only as an outcome difference, not an unknown member.
        let allowed = [
            "event",
            "knowledge",
            "dispatch",
            "refusal",
            "disposition",
            "settled",
        ];
        for key in step
            .as_object()
            .ok_or_else(|| fail("step is not an object".into()))?
            .keys()
        {
            if !allowed.contains(&key.as_str()) {
                return Err(fail(format!("unknown member {key}")));
            }
        }
        let mut expected = step.clone();
        expected.as_object_mut().unwrap().remove("event");
        expected.as_object_mut().unwrap().remove("knowledge");
        validate_outcome(&step["event"], &expected).map_err(fail)?;
        if expected != outcome && difference.is_none() {
            difference = Some((
                step_number,
                format!("outcome: expected {expected}, actual {outcome}"),
            ));
        }
        if let Err(e) = compare_knowledge(&step["knowledge"], driver.project()) {
            // Unknown vocabulary is always an error, even on an admitted negative control.
            let parsed: Knowledge = parse(&step["knowledge"]).map_err(fail)?;
            parsed.validate().map_err(fail)?;
            if difference.is_none() {
                difference = Some((step_number, e));
            }
        }
    }
    Ok(difference)
}
fn validate_outcome(event: &Value, value: &Value) -> Result<(), String> {
    let keys: &[&str] = match event["kind"].as_str().ok_or("missing event kind")? {
        "request" => match value["dispatch"].as_str() {
            Some("dispatched") => &["dispatch"],
            Some("refused") => &["dispatch", "refusal"],
            _ => return Err("missing or invalid dispatch outcome".into()),
        },
        "receive" | "read" | "collect_reboot" => &["settled"],
        "dispose" => &["disposition"],
        "reset_prereqs" => &["offer"],
        "withdraw_reinstall" => &["withdrawal"],
        "replay" | "associate" | "associate_evidence" | "approve_reinstall" => &[],
        _ => return Err("unknown outcome event".into()),
    };
    members(value, keys)?;
    for (key, v) in value.as_object().ok_or("outcome is not an object")? {
        match key.as_str() {
            "dispatch" if [json!("dispatched"), json!("refused")].contains(v) => {}
            "offer" if v.is_boolean() => {}
            "disposition" | "withdrawal"
                if [json!("recorded"), json!("refused"), json!("not_appended")].contains(v) => {}
            "settled"
                if v.as_array()
                    .is_some_and(|a| a.iter().all(|v| v.as_u64().is_some())) => {}
            "refusal" => match v["reason"].as_str() {
                Some("barrier") => {
                    members(v, &["reason", "calls"])?;
                    if !v["calls"]
                        .as_array()
                        .is_some_and(|a| a.iter().all(|x| x.as_u64().is_some()))
                    {
                        return Err("unknown barrier calls".into());
                    }
                }
                Some("identity_exclusion") => {
                    members(v, &["reason", "records"])?;
                    let records = v["records"]
                        .as_array()
                        .ok_or("identity exclusion records")?;
                    if records.is_empty()
                        || records.iter().any(|x| x.as_u64().is_none())
                        || records.windows(2).any(|w| w[0].as_u64() >= w[1].as_u64())
                    {
                        return Err("identity exclusion record order".into());
                    }
                }
                Some("binding" | "approval_activation") => members(v, &["reason"])?,
                Some("withdrawn_approval") => {
                    members(v, &["reason", "approved", "call", "resource"])?;
                    if v["call"].as_u64().is_none() {
                        return Err("withdrawn approval call".into());
                    }
                    let _: WApproval = parse(&v["approved"])?;
                    to_resource(&parse::<WResource>(&v["resource"])?)?;
                }
                Some("continuation") => {
                    members(v, &["reason", "in_force"])?;
                    let _: Continuation = parse(&v["in_force"])?;
                }
                _ => return Err(format!("unknown refusal {v}")),
            },
            _ => return Err(format!("unknown outcome {key}: {v}")),
        }
    }
    Ok(())
}
fn sequences(alphabet: &[Value], events: usize) -> HashSet<String> {
    fn walk(
        alphabet: &[Value],
        remaining: usize,
        sequence: &mut Vec<Value>,
        out: &mut HashSet<String>,
    ) {
        let ids: Vec<_> = sequence
            .iter()
            .filter(|e| e["kind"] == "request")
            .map(|e| e["call"].clone())
            .collect();
        if ids
            .iter()
            .map(Value::to_string)
            .collect::<HashSet<_>>()
            .len()
            != ids.len()
        {
            return;
        }
        out.insert(json!(sequence).to_string());
        if remaining > 0 {
            for event in alphabet {
                sequence.push(event.clone());
                walk(alphabet, remaining - 1, sequence, out);
                sequence.pop();
            }
        }
    }
    let mut out = HashSet::new();
    walk(alphabet, events, &mut vec![], &mut out);
    out
}
fn check(bytes: &[u8]) -> Result<String, String> {
    let root = serde_json::from_slice::<super::evidence::UniqueValue>(bytes)
        .map_err(|e| format!("{FILE}: not a JSON document: {e}"))?
        .0;
    members(
        &root,
        &[
            "schema",
            "module",
            "namespace",
            "bound",
            "witnesses",
            "enumeration",
        ],
    )?;
    if root["schema"] != 8 || root["module"] != "dispatch" || root["namespace"] != "TauWeb.Dispatch"
    {
        return Err(format!("{FILE}: unknown header"));
    }
    let bound = &root["bound"];
    members(bound, &["declaration", "events", "alphabet", "start"])?;
    if bound["declaration"] != "TauWeb.Dispatch.bound" || bound["events"] != 3 {
        return Err("bound: expected TauWeb.Dispatch.bound, 3 events".into());
    }
    let alphabet = bound["alphabet"]
        .as_array()
        .ok_or("bound: alphabet is not an array")?;
    if alphabet.len() != 8
        || alphabet
            .iter()
            .map(Value::to_string)
            .collect::<HashSet<_>>()
            .len()
            != 8
    {
        return Err("bound: expected 8 distinct events".into());
    }
    let mut counts = [[0usize; 3]; 2];
    let mut traces = Vec::new();
    for (group, key) in ["witnesses", "enumeration"].iter().enumerate() {
        let values = root[key].as_array().ok_or(format!("{key}: not an array"))?;
        for (i, value) in values.iter().enumerate() {
            let label = if group == 0 {
                value["declarations"].to_string()
            } else {
                format!("enumeration[{i}]")
            };
            let mut trace: Trace = parse(value).map_err(|e| format!("{label}: {e}"))?;
            if group == 1 {
                trace.declarations = vec![label.clone()];
            }
            let route = bucket(&trace).map_err(|e| format!("{label}: {e}"))?;
            counts[group][route] += 1;
            traces.push((group, i, route, trace));
        }
    }
    for (_, _, route, trace) in &traces {
        if *route == 0 {
            validate_trace(trace)?;
        } else {
            validate_routed_trace(trace)
                .map_err(|e| format!("{}, routed schema: {e}", trace.declarations.join(", ")))?;
        }
    }
    let enumerated: Vec<_> = traces.iter().filter(|(g, _, _, _)| *g == 1).collect();
    let mut seen = HashSet::new();
    for (_, i, _, trace) in &enumerated {
        if trace.start != bound["start"] {
            return Err(format!("enumeration[{i}], start: differs from bound.start"));
        }
        let sequence: Vec<_> = trace.steps.iter().map(|s| s["event"].clone()).collect();
        if sequence.len() > 3 || sequence.iter().any(|e| !alphabet.contains(e)) {
            return Err(format!("enumeration[{i}]: not a trace of the alphabet"));
        }
        if !seen.insert(json!(sequence).to_string()) {
            return Err(format!("enumeration[{i}]: duplicate trace"));
        }
    }
    let required = sequences(alphabet, 3);
    if required.len() != 470 || seen != required {
        return Err(format!(
            "enumeration: expected all 470 distinct-request traces, actual {}",
            seen.len()
        ));
    }
    let names: Vec<_> = traces
        .iter()
        .filter(|(g, _, _, _)| *g == 0)
        .flat_map(|(_, _, b, t)| t.declarations.iter().map(move |n| (n.clone(), (*b, t))))
        .collect();
    let mut pair_records = Vec::new();
    let mut actual_pairs = BTreeSet::new();
    let mut hold = [0; 2];
    for (group, _, route, trace) in &traces {
        let label = trace.declarations.join(", ");
        if let Some(pair) = &trace.pair {
            if !["refused", "admitted"].contains(&pair.side.as_str()) {
                return Err(format!("{label}: unknown pair side {}", pair.side));
            }
            let (_, (other_bucket, other)) = names
                .iter()
                .find(|(n, (_, other))| {
                    n == &pair.with
                        && other.start == trace.start
                        && other
                            .steps
                            .iter()
                            .map(|s| &s["event"])
                            .eq(trace.steps.iter().map(|s| &s["event"]))
                })
                .ok_or(format!("{label}: missing paired side {}", pair.with))?;
            if other_bucket != route
                || other
                    .pair
                    .as_ref()
                    .is_none_or(|p| p.with != trace.declarations[0] || p.side == pair.side)
            {
                return Err(format!("{label}: pair is not whole in one bucket"));
            }
        }
        if *route != 0 {
            continue;
        }
        if trace.assumptions.len() != GUARDS.len()
            || GUARDS.iter().any(|g| !trace.assumptions.contains_key(*g))
        {
            return Err(format!("{label}: unknown or missing assumption"));
        }
        let off: Vec<_> = GUARDS
            .iter()
            .filter(|g| trace.assumptions[**g] != production(g))
            .copied()
            .collect();
        let admitted = trace.pair.as_ref().is_some_and(|p| p.side == "admitted");
        if admitted {
            let pair = trace.pair.as_ref().unwrap();
            let expected = PAIRS
                .iter()
                .find(|(r, a, _)| name(r) == pair.with && trace.declarations.contains(&name(a)))
                .ok_or(format!("{label}: unknown stage1 pair"))?;
            if off != [expected.2] {
                return Err(format!(
                    "{label}: admitted side must change exactly {}, actual {off:?}",
                    expected.2
                ));
            }
        } else if !off.is_empty() {
            return Err(format!("{label}: production assumptions differ: {off:?}"));
        }
        for step in &trace.steps {
            if step["event"]["kind"] == "request"
                && step["event"]["operation"] == "exec"
                && step["dispatch"] == "refused"
                && step["refusal"]["reason"] == "barrier"
                && step["refusal"]["calls"].as_array().is_some_and(|ids| {
                    ids.iter().any(|id| {
                        step["knowledge"]["calls"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|c| c["call"] == *id && c["operation"] == "exec")
                    })
                })
            {
                hold[*group] += 1;
            }
        }
        let difference = run_trace(trace)?;
        if admitted {
            let (step, _) =
                difference.ok_or(format!("{label}: admitted negative control never differed"))?;
            pair_records.push((trace.pair.as_ref().unwrap().with.clone(), (label, step)));
        } else {
            if let Some((step, why)) = difference {
                return Err(format!("{label}, step {step}: {why}"));
            }
            if trace.pair.is_some() {
                actual_pairs.insert(trace.declarations[0].clone());
            }
        }
    }
    let expected_pairs: BTreeSet<_> = PAIRS.iter().map(|(r, _, _)| name(r)).collect();
    if actual_pairs != expected_pairs
        || pair_records
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<BTreeSet<_>>()
            != expected_pairs
    {
        return Err("witnesses: stage1 pair inventory differs".into());
    }
    for (refused, _, guard) in PAIRS {
        let actual = pair_records
            .iter()
            .filter(|(r, _)| *r == name(refused))
            .count();
        let expected = if *guard == "orderAssociation" { 2 } else { 1 };
        if actual != expected {
            return Err(format!(
                "{refused}: expected {expected} admitted traces, actual {actual}"
            ));
        }
    }
    if counts != [[52, 54, 12], [286, 184, 0]] {
        return Err(format!(
            "routing: expected [[52,54,12],[286,184,0]], actual {counts:?}"
        ));
    }
    if hold != [4, 28] {
        return Err(format!("commandHold: expected [4,28], actual {hold:?}"));
    }
    let mut record = format!(
        "dispatch companion comparison: passed\n  rule: ADR-0032, How the implementation is compared; ticket partition is an implementation reading\n  file: {FILE}\n  schema 8, module dispatch, namespace TauWeb.Dispatch, bound: 3 events over an alphabet of 8, distinct request call ids\n  stage1: 52 witnesses / 286 enumerated traces (twr-ggw.8)\n  dedicated: 54 witnesses / 184 enumerated traces (twr-i6k.3)\n  reboot: 12 witnesses / 0 enumerated traces (twr-i6k.11)\n  total: 118 witnesses / 470 enumerated traces\n  compared: start, every outcome and projection member at every stage1 step; keyed sets compared by key\n  commandHold: 4 named / 28 enumerated refusals\n"
    );
    for (refused, (admitted, step)) in pair_records {
        record.push_str(&format!(
            "  pair: {refused} refused matched; {admitted} admitted differed at step {step}\n"
        ));
    }
    record.push_str(&format!(
        "  spec commit: {}\n  implementation revision: the commit the test ran at\n",
        crate::SPEC_COMMIT
    ));
    Ok(record)
}
fn check_file(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    check(&bytes)
}
#[test]
fn the_dispatch_core_passes_the_companion_comparison() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FILE);
    let record = check_file(&path).unwrap_or_else(|e| panic!("{e}"));
    assert!(!record.contains("uncommitted"));
    println!("{record}");
}
#[test]
fn every_stage1_projection_and_outcome_rejects_unknown_vocabulary() {
    let bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(FILE)).unwrap();
    let original: Value = serde_json::from_slice(&bytes).unwrap();
    for (short, pointer, bad) in [
        (
            "second_command_without_hold",
            "/steps/0/knowledge/associations/0/target",
            json!({"inference_cap":false}),
        ),
        (
            "disposition_unrestricted_admitted",
            "/steps/1/knowledge/dispositions/0/resource",
            json!({"inference":false}),
        ),
        (
            "second_command_without_hold",
            "/steps/0/knowledge/standing",
            json!([{"resource":{"inference":false},"calls":[1],"continuation":"as_if_done"}]),
        ),
        (
            "second_command_without_hold",
            "/steps/0/refusal",
            json!({"reason":"binding"}),
        ),
    ] {
        let mut document = original.clone();
        let label = name(short);
        let trace = document["witnesses"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|t| {
                t["declarations"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(label))
            })
            .unwrap();
        // The refusal is absent on this admitted step, so insert at its parent.
        if pointer.ends_with("/refusal") {
            trace["steps"][0]["refusal"] = bad;
        } else {
            *trace
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("{label}: missing {pointer}")) = bad;
        }
        let why = check(&serde_json::to_vec(&document).unwrap()).unwrap_err();
        assert!(
            why.contains(&label) && why.contains("step"),
            "expected {label}: {why}"
        );
    }
}

#[test]
fn comparison_breaks_are_red_and_name_the_trace() {
    let bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(FILE)).unwrap();
    let mut original: Value = serde_json::from_slice(&bytes).unwrap();
    let witnesses = original["witnesses"].as_array_mut().unwrap();
    let first = witnesses
        .iter()
        .position(|t| t["declarations"][0] == name("second_command_held"))
        .unwrap();
    witnesses.swap(0, first);
    let second = witnesses
        .iter()
        .position(|t| t["declarations"][0] == name("second_command_without_hold"))
        .unwrap();
    witnesses.swap(1, second);
    let mut checks = Vec::new();
    let mut d = original.clone();
    d["witnesses"][0]["steps"][0]["dispatch"] = json!("refused");
    checks.push((d, "TauWeb.Dispatch.second_command_held"));
    let mut d = original.clone();
    d["witnesses"][0]["steps"][0]["event"]["kind"] = json!("unrecognised");
    checks.push((d, "TauWeb.Dispatch.second_command_held"));
    let mut d = original.clone();
    d["witnesses"][0]["steps"][0]["dispatch"] = json!("unrecognised");
    checks.push((d, "TauWeb.Dispatch.second_command_held"));
    let mut d = original.clone();
    d["enumeration"].as_array_mut().unwrap().pop();
    checks.push((d, "enumeration"));
    let mut d = original.clone();
    d["witnesses"][0]["steps"][0]["knowledge"]["extra"] = json!(true);
    checks.push((d, "TauWeb.Dispatch.second_command_held"));
    let mut d = original.clone();
    d["witnesses"].as_array_mut().unwrap().remove(1);
    checks.push((d, "TauWeb.Dispatch.second_command_held"));
    let mut d = original.clone();
    d["witnesses"][1]["assumptions"]["destructiveStops"] = json!(false);
    checks.push((d, "TauWeb.Dispatch.second_command_without_hold"));
    let mut d = original.clone();
    d["witnesses"]
        .as_array_mut()
        .unwrap()
        .push(original["witnesses"][2].clone());
    checks.push((d, "routing"));
    for (d, label) in checks {
        let why = check(&serde_json::to_vec(&d).unwrap()).unwrap_err();
        assert!(why.contains(label), "expected {label}: {why}");
    }
    assert!(check(b"").unwrap_err().contains(FILE));
    let absent = Path::new(env!("CARGO_MANIFEST_DIR")).join("absent-dispatch-witnesses.json");
    assert!(
        check_file(&absent)
            .unwrap_err()
            .contains("absent-dispatch-witnesses.json")
    );
}

#[test]
fn schema8_requires_all_binding_and_receipt_fields_and_rejects_unknown_vocabulary() {
    let root: Value = serde_json::from_slice(
        &std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(FILE)).unwrap(),
    )
    .unwrap();
    let witness = root["witnesses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["declarations"][0] == name("lnvps_receipt_confirms"))
        .unwrap();
    let mutations = [
        ("/steps/0/event/approved", "receipt_binding", None),
        (
            "/steps/0/knowledge/calls/0/approved",
            "receipt_binding",
            None,
        ),
        (
            "/steps/0/event/approved",
            "receipt_binding",
            Some(json!(["restart", 41, 73])),
        ),
        (
            "/steps/1/event/receipt",
            "binding",
            Some(json!(["restart", 41, 73])),
        ),
        (
            "/steps/0/event",
            "approved",
            Some(json!([{"operation":"restart","account":41,"signed_request":73},1,1])),
        ),
        ("/start", "receipts", None),
        ("/steps/1/event/receipt", "returned_vendor", None),
        ("/steps/1/knowledge/receipts/0", "returned_vendor", None),
        ("/steps/1/event/receipt", "binding", None),
        ("/steps/1/event/receipt/binding", "operation", None),
        ("/steps/1/event/receipt/binding", "account", None),
        ("/steps/1/event/receipt/binding", "signed_request", None),
        (
            "/steps/1/event/receipt",
            "source",
            Some(json!("adapter_read")),
        ),
        (
            "/steps/1/event/receipt/binding",
            "operation",
            Some(json!("reinstall")),
        ),
        (
            "/steps/0/event/approved/receipt_binding",
            "operation",
            Some(json!("reset")),
        ),
        ("/steps/1/event/receipt", "unexpected", Some(json!(true))),
        (
            "/steps/1/knowledge/receipts/0",
            "unexpected",
            Some(json!(true)),
        ),
        (
            "/steps/0/event/approved/receipt_binding",
            "unexpected",
            Some(json!(true)),
        ),
        (
            "/steps/1/event/receipt",
            "resource",
            Some(json!({"inference":false})),
        ),
        (
            "/steps/1/event/receipt",
            "target",
            Some(json!({"inference_cap":false})),
        ),
    ];
    for (pointer, key, replacement) in mutations {
        let mut trace = witness.clone();
        let object = trace.pointer_mut(pointer).unwrap().as_object_mut().unwrap();
        if let Some(value) = replacement {
            object.insert(key.into(), value);
        } else {
            assert!(object.remove(key).is_some());
        }
        let why = validate_trace(&parse::<Trace>(&trace).unwrap()).unwrap_err();
        assert!(
            why.contains("lnvps_receipt_confirms"),
            "{pointer}/{key}: {why}"
        );
    }
}

// The routed owners do not execute production behavior here. Their complete wire
// vocabulary is nevertheless checked, so routing cannot conceal a schema-8 omission.
fn validate_routed_trace(trace: &Trace) -> Result<(), String> {
    fn array<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
        v[key]
            .as_array()
            .ok_or_else(|| format!("{key}: not an array"))
    }
    fn uint(v: &Value) -> Result<(), String> {
        v.as_u64()
            .map(|_| ())
            .ok_or("expected unsigned ordinal".into())
    }
    fn nums(v: &Value) -> Result<(), String> {
        for n in v.as_array().ok_or("ordinal array")? {
            uint(n)?;
        }
        Ok(())
    }
    fn operation(v: &Value) -> Result<(), String> {
        if [
            "activate",
            "register_key",
            "delivery_reboot",
            "create",
            "reset",
            "reinstall",
            "destroy",
            "exec",
            "read",
            "inference",
        ]
        .iter()
        .any(|s| v == *s)
        {
            Ok(())
        } else {
            Err("unknown operation".into())
        }
    }
    fn knowledge(v: &Value) -> Result<(), String> {
        members(
            v,
            &[
                "associations",
                "calls",
                "current_installations",
                "dispatched",
                "dispositions",
                "durable",
                "identity_exclusions",
                "prerequisite_records",
                "quarantined",
                "reboot_results",
                "receipts",
                "reinstall_approvals",
                "reinstall_withdrawals",
                "reset_offer",
                "standing",
                "unresolved",
            ],
        )?;
        for a in array(v, "associations")? {
            let a: WAssociation = parse(a)?;
            to_target(&a.target)?;
        }
        for a in array(v, "quarantined")? {
            let _: WQuarantined = parse(a)?;
        }
        for a in array(v, "identity_exclusions")? {
            let a: WExclusion = parse(a)?;
            if a.records.windows(2).any(|w| w[0] >= w[1]) {
                return Err("identity exclusion record order".into());
            }
        }
        for r in array(v, "receipts")? {
            let r: WReceipt = parse(r)?;
            to_resource(&r.resource)?;
            to_target(&r.target)?;
            if r.returned_withheld && r.returned_vendor.is_some() {
                return Err("contradictory returned presence".into());
            }
        }
        for c in array(v, "calls")? {
            members(
                c,
                &[
                    "call",
                    "target",
                    "resource",
                    "operation",
                    "session",
                    "approved",
                    "state",
                ],
            )?;
            uint(&c["call"])?;
            uint(&c["session"])?;
            to_target(&parse::<WTarget>(&c["target"])?)?;
            to_resource(&parse::<WResource>(&c["resource"])?)?;
            let _: WApproval = parse(&c["approved"])?;
            operation(&c["operation"])?;
            if ![json!("unresolved"), json!("terminal"), json!("no_effect")].contains(&c["state"]) {
                return Err("unknown call state".into());
            }
        }
        for a in array(v, "current_installations")? {
            let _: Installation = parse(a)?;
        }
        nums(&v["dispatched"])?;
        nums(&v["reset_offer"])?;
        if !v["durable"].is_boolean() {
            return Err("durable is not boolean".into());
        }
        for d in array(v, "dispositions")? {
            let d: WDisposition = parse(d)?;
            to_resource(&d.resource)?;
        }
        for d in array(v, "standing")? {
            let d: WStanding = parse(d)?;
            to_resource(&d.resource)?;
        }
        for d in array(v, "unresolved")? {
            let d: WUnresolved = parse(d)?;
            to_resource(&d.resource)?;
        }
        for key in ["reinstall_approvals", "reinstall_withdrawals"] {
            for a in array(v, key)? {
                members(a, &["approved", "call", "entry"])?;
                uint(&a["call"])?;
                uint(&a["entry"])?;
                let _: WApproval = parse(&a["approved"])?;
            }
        }
        for a in array(v, "reboot_results")? {
            members(a, &["call", "observed_boot", "record_boot", "resource"])?;
            for k in ["call", "observed_boot", "record_boot"] {
                if k != "record_boot" || !a[k].is_null() {
                    uint(&a[k])?;
                }
            }
            to_resource(&parse::<WResource>(&a["resource"])?)?;
        }
        for a in array(v, "prerequisite_records")? {
            match a["kind"].as_str() {
                Some("command") => members(a, &["entry", "installation", "kind"])?,
                Some("result") => {
                    members(a, &["entry", "installation", "keys", "kind"])?;
                    uint(&a["keys"])?;
                }
                _ => return Err("unknown prerequisite record".into()),
            }
            uint(&a["entry"])?;
            uint(&a["installation"])?;
        }
        Ok(())
    }
    members(&json!(trace.assumptions), GUARDS)?;
    for (guard, value) in &trace.assumptions {
        let valid = match guard.as_str() {
            "lapse" => ["continuation", "first_operation", "any_intent"]
                .iter()
                .any(|x| value == *x),
            "reach" => ["disposed", "still_unresolved", "every_dispatch", "resource"]
                .iter()
                .any(|x| value == *x),
            "resourceKey" => ["entry", "call", "index"].iter().any(|x| value == *x),
            _ => value.is_boolean(),
        };
        if !valid {
            return Err(format!("unknown {guard} assumption"));
        }
    }
    knowledge(&trace.start)?;
    for step in &trace.steps {
        let e = &step["event"];
        let kind = e["kind"].as_str().ok_or("missing event kind")?;
        match kind {
            "request" | "read" => {
                operation(&e["operation"])?;
                let keys = if kind == "request" {
                    vec![
                        "kind",
                        "provenance",
                        "call",
                        "target",
                        "operation",
                        "session",
                        "facts",
                        "approved",
                        "appended",
                    ]
                } else {
                    vec![
                        "kind",
                        "provenance",
                        "source",
                        "resource",
                        "operation",
                        "reports",
                        "appended",
                    ]
                };
                members(e, &keys)?;
                if kind == "request" {
                    let expected = if e["operation"] == "delivery_reboot" {
                        "operator act"
                    } else {
                        "model request"
                    };
                    if e["provenance"] != expected {
                        return Err("request provenance".into());
                    }
                    for key in ["call", "session", "facts"] {
                        uint(&e[key])?;
                    }
                    to_target(&parse::<WTarget>(&e["target"])?)?;
                    if !e["approved"].is_null() {
                        let _: WApproval = parse(&e["approved"])?;
                    }
                } else {
                    if e["provenance"] != "adapter observation"
                        || ![
                            json!("adapter_read"),
                            json!("job_record"),
                            json!("pin_checked_handshake"),
                        ]
                        .contains(&e["source"])
                    {
                        return Err("read provenance".into());
                    }
                    to_resource(&parse::<WResource>(&e["resource"])?)?;
                    if ![json!("succeeded"), json!("ended"), json!("unknown")]
                        .contains(&e["reports"])
                    {
                        return Err("unknown read report".into());
                    }
                }
            }
            "collect_reboot" => {
                members(
                    e,
                    &[
                        "kind",
                        "provenance",
                        "call",
                        "resource",
                        "record_boot",
                        "observed_boot",
                        "appended",
                    ],
                )?;
                for key in ["call", "record_boot", "observed_boot"] {
                    if key != "record_boot" || !e[key].is_null() {
                        uint(&e[key])?;
                    }
                }
                to_resource(&parse::<WResource>(&e["resource"])?)?;
                if e["provenance"] != "adapter observation" {
                    return Err("reboot provenance".into());
                }
            }
            "approve_reinstall" | "withdraw_reinstall" => {
                members(
                    e,
                    &[
                        "kind",
                        "provenance",
                        "approved",
                        "call",
                        "entry",
                        "appended",
                    ],
                )?;
                uint(&e["call"])?;
                uint(&e["entry"])?;
                let _: WApproval = parse(&e["approved"])?;
                if e["provenance"] != "operator act" {
                    return Err("approval provenance".into());
                }
            }
            "reset_prereqs" => {
                members(e, &["kind", "provenance", "entry", "keys", "appended"])?;
                uint(&e["entry"])?;
                uint(&e["keys"])?;
                if e["provenance"] != "adapter observation" {
                    return Err("prerequisite provenance".into());
                }
            }
            _ => {
                let parsed: Witnessed = parse(e)?;
                let expected = match parsed {
                    Witnessed::Receive { receipt, .. } => {
                        to_resource(&receipt.resource)?;
                        to_target(&receipt.target)?;
                        if receipt.returned_withheld && receipt.returned_vendor.is_some() {
                            return Err("returned presence".into());
                        }
                        "adapter observation"
                    }
                    Witnessed::Associate { target, .. } => {
                        to_target(&target)?;
                        "operator act"
                    }
                    Witnessed::AssociateEvidence { .. } => "adapter observation",
                    Witnessed::Dispose { resource, .. } => {
                        to_resource(&resource)?;
                        "disposition"
                    }
                    Witnessed::Replay { .. } => "replay",
                    _ => return Err("unhandled routed event".into()),
                };
                if e["provenance"] != expected {
                    return Err("event provenance".into());
                }
            }
        }
        if kind != "replay" && kind != "associate" && !e["appended"].is_boolean() {
            return Err("append outcome".into());
        }
        knowledge(&step["knowledge"])?;
        let mut outcome = step.clone();
        let o = outcome.as_object_mut().ok_or("step object")?;
        o.remove("event");
        o.remove("knowledge");
        validate_outcome(&step["event"], &outcome)?;
    }
    Ok(())
}

// These small journals come from the Markdown event vocabulary, independently of
// the companion's expected outcomes. Setup supplies the first two associations.
fn ordinal_start() -> Value {
    json!({
        "associations":[{"entry":2,"target":{"allocation_index":2}},
            {"entry":1,"target":{"allocation_index":0}},
            {"entry":1,"target":{"allocation_index":1}},
            {"entry":1,"target":{"vendor_machine_id":10}}],
        "quarantined":[],"identity_exclusions":[{"entry":1,"records":[]},{"entry":2,"records":[]}],
        "calls":[],"current_installations":[{"entry":1,"installation":0},{"entry":2,"installation":0}],
        "dispatched":[],"dispositions":[],"durable":true,"prerequisite_records":[],
        "reboot_results":[],"receipts":[],"reinstall_approvals":[],"reinstall_withdrawals":[],
        "reset_offer":[],"standing":[],"unresolved":[]
    })
}
fn ordinal_request(call: u64, entry: u64) -> Witnessed {
    parse(&json!({"kind":"request","provenance":"model request","call":call,
        "target":{"entry":entry},"operation":"create","session":2,"facts":7,
        "approved":{"session":2,"facts":7,"receipt_binding":{"operation":"order","account":41,"signed_request":73}},
        "appended":true})).unwrap()
}
fn assert_risk_ordinal(driver: &mut Driver, ordinal: u64) {
    let actual_risk = driver.store.records().end;
    assert_eq!(
        driver
            .step(
                parse(
                    &json!({"kind":"associate_evidence","provenance":"adapter observation",
        "vendor":99,"entry":1,"withheld":true,"appended":true})
                )
                .unwrap()
            )
            .unwrap(),
        json!({})
    );
    assert_eq!(driver.record_symbol(actual_risk), ordinal);
    assert_eq!(
        driver.store.dispatch().identity_exclusions("entry-2"),
        [actual_risk]
    );
    let before = driver.store.records().end;
    let expected =
        json!({"dispatch":"refused","refusal":{"reason":"identity_exclusion","records":[ordinal]}});
    assert_eq!(driver.step(ordinal_request(23, 2)).unwrap(), expected);
    assert_eq!(
        driver.store.records().end,
        before,
        "refusal appends no intent"
    );
    assert_eq!(
        driver.project().identity_exclusions,
        vec![
            WExclusion {
                entry: 1,
                records: vec![]
            },
            WExclusion {
                entry: 2,
                records: vec![ordinal]
            }
        ]
    );
    let map = driver.record_ordinals.clone();
    driver.replay().unwrap();
    assert_eq!(driver.record_ordinals, map);
    assert_eq!(driver.step(ordinal_request(24, 2)).unwrap(), expected);
    assert_eq!(
        driver.store.dispatch().identity_exclusions("entry-2"),
        [actual_risk]
    );
}
#[test]
fn driver_counts_appended_reads_before_risks_but_not_failed_appends_or_duplicates() {
    let mut d = Driver::new(&ordinal_start()).unwrap();
    assert_eq!(d.next_ordinal, 4);
    // A successful read is an abstract durable observation even when it settles nothing.
    for source in ["adapter_read", "job_record"] {
        let number = d.store.records().end;
        assert_eq!(d.step(parse(&json!({"kind":"read","provenance":"adapter observation",
            "source":source,"resource":{"machine_entry":1},"operation":"exec","reports":"ended","appended":true})).unwrap()).unwrap(), json!({"settled":[]}));
        assert_eq!(
            d.record_symbol(number),
            if source == "adapter_read" { 4 } else { 5 }
        );
    }
    let before = d.store.records().end;
    d.step(
        parse(&json!({"kind":"associate","provenance":"operator act",
        "target":{"vendor_machine_id":10},"entry":1}))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(d.store.records().end, before);
    d.step(
        parse(
            &json!({"kind":"associate_evidence","provenance":"adapter observation",
        "vendor":88,"entry":1,"withheld":true,"appended":false}),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(d.next_ordinal, 6);
    d.replay().unwrap();
    let before_failed_read = d.store.records().end;
    assert_eq!(
        d.step(
            parse(&json!({"kind":"read","provenance":"adapter observation",
        "source":"adapter_read","resource":{"machine_entry":1},"operation":"read",
        "reports":"ended","appended":false}))
            .unwrap()
        )
        .unwrap(),
        json!({"settled":[]})
    );
    assert_eq!(d.store.records().end, before_failed_read);
    assert_eq!(d.next_ordinal, 6);
    d.replay().unwrap(); // A failed writer cannot be used for subsequent appends.
    assert_risk_ordinal(&mut d, 6);
    // Same-entry admission remains usable after a cross-entry refusal.
    assert_eq!(
        d.step(ordinal_request(25, 1)).unwrap(),
        json!({"dispatch":"dispatched"})
    );
}
#[test]
fn driver_counts_authenticated_start_calls_and_dispositions_before_later_risks() {
    for valid in [false, true] {
        let mut start = ordinal_start();
        start["calls"] = json!([{"call":1,"target":{"vendor_machine_id":10},
            "resource":{"machine_entry":1},"operation":"reset","session":1,
            "approved":{"session":1,"facts":1,"receipt_binding":null},"state":"unresolved"}]);
        start["dispositions"] = json!([{"resource":{"machine_entry":if valid {1} else {2}},
            "calls":[1],"continuation":"as_if_done","valid":valid}]);
        let mut d = Driver::new(&start).unwrap();
        assert_eq!(d.next_ordinal, 6);
        assert_eq!(d.record_symbol(d.id(1)), 4);
        assert_risk_ordinal(&mut d, 6);
    }
}

#[test]
fn parser_contract_requires_exact_event_outcomes_in_every_route() {
    let document: Value = serde_json::from_slice(
        &std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(FILE)).unwrap(),
    )
    .unwrap();
    let mut routes = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    for group in ["witnesses", "enumeration"] {
        for raw in document[group].as_array().unwrap() {
            let trace: Trace = parse(raw).unwrap();
            let route = bucket(&trace).unwrap();
            validate_routed_trace(&trace).unwrap();
            for (i, step) in trace.steps.iter().enumerate() {
                let kind = step["event"]["kind"].as_str().unwrap();
                routes.insert(route);
                kinds.insert(kind.to_owned());
                for required in step
                    .as_object()
                    .unwrap()
                    .keys()
                    .filter(|k| !["event", "knowledge"].contains(&k.as_str()))
                {
                    let mut bad: Trace = parse(raw).unwrap();
                    bad.steps[i].as_object_mut().unwrap().remove(required);
                    assert!(
                        validate_routed_trace(&bad).is_err(),
                        "route {route} {kind}: missing {required}"
                    );
                    if route == 0 {
                        assert!(validate_trace(&bad).is_err());
                    }
                }
                for (extra, value) in [
                    ("dispatch", json!("dispatched")),
                    ("settled", json!([])),
                    ("disposition", json!("recorded")),
                    ("offer", json!(false)),
                    ("withdrawal", json!("recorded")),
                    ("refusal", json!({"reason":"binding"})),
                ] {
                    if step.get(extra).is_some() {
                        continue;
                    }
                    let mut bad: Trace = parse(raw).unwrap();
                    bad.steps[i][extra] = value;
                    assert!(
                        validate_routed_trace(&bad).is_err(),
                        "route {route} {kind}: extra {extra}"
                    );
                    if route == 0 {
                        assert!(validate_trace(&bad).is_err());
                    }
                }
            }
        }
    }
    assert_eq!(routes, BTreeSet::from([0, 1, 2]));
    for kind in [
        "request",
        "receive",
        "read",
        "collect_reboot",
        "dispose",
        "reset_prereqs",
        "withdraw_reinstall",
        "replay",
        "associate",
        "associate_evidence",
        "approve_reinstall",
    ] {
        assert!(kinds.contains(kind), "missing parser control for {kind}");
    }
}
