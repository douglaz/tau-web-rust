//! Canonical operation evidence (Protected browser evidence v1 §§3a–4).
//! Raw vendor abstractions, stored evidence and read-only projections are distinct types.
use super::*;
use serde_json::{Value, json};
use zeroize::Zeroize;

/// Deserialize objects without letting a Value or untagged enum erase duplicate members.
pub(crate) struct UniqueValue(pub Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON with unique object members")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if out.contains_key(&k) {
                        return Err(serde::de::Error::custom("duplicate member"));
                    }
                    out.insert(k, a.next_value::<UniqueValue>()?.0);
                }
                Ok(UniqueValue(Value::Object(out)))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = a.next_element::<UniqueValue>()? {
                    out.push(v.0);
                }
                Ok(UniqueValue(Value::Array(out)))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(json!(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(json!(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(json!(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                Ok(UniqueValue(json!(v)))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(json!(v)))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(json!(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
        }
        d.deserialize_any(Visitor)
    }
}
fn canonical<T: serde::de::DeserializeOwned + Serialize>(v: Value) -> Result<T, String> {
    if !v.is_object() {
        return Err("evidence must be an object".into());
    }
    let parsed: T = serde_json::from_value(v.clone()).map_err(|_| "invalid evidence shape")?;
    if serde_json::to_value(&parsed).map_err(|_| "invalid evidence shape")? != v {
        return Err("noncanonical evidence shape".into());
    }
    Ok(parsed)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NameAssociation {
    Registered { placement: u64 },
    Transient { id: String },
    Unregistered { id: String },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithheldFact {
    pub slot: String,
    pub marker: String,
    pub associations: Vec<NameAssociation>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameRow {
    pub association: NameAssociation,
    pub ordinal: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_withheld: Option<WithheldFact>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCustody {
    pub version: u32,
    pub substitutions: Vec<Value>,
    pub names: Vec<NameRow>,
}

/// Whole-fact conversion controls. Placement discovery, scanning and release are owned
/// by the protected finalizer; these controls grant no external-response authority.
#[derive(Clone, Debug, Default)]
pub struct EvidenceProtection {
    withheld: Vec<WithheldFact>,
    custody: Option<EvidenceCustody>,
}
impl EvidenceProtection {
    /// A scoped, independently generated transient identity, never derived from an input.
    pub fn transient(name: String, slots: &[&str]) -> Result<Self, String> {
        let mut id = [0u8; 24];
        getrandom::fill(&mut id).map_err(|_| "evidence identity entropy unavailable")?;
        let association = NameAssociation::Transient {
            id: hex::encode(id),
        };
        let mut withheld: Vec<_> = slots
            .iter()
            .map(|slot| WithheldFact {
                slot: (*slot).into(),
                marker: format!("[withheld:{name}]"),
                associations: vec![association.clone()],
            })
            .collect();
        withheld.sort_by(|a, b| a.slot.cmp(&b.slot));
        Ok(Self {
            withheld,
            custody: Some(EvidenceCustody {
                version: 1,
                substitutions: vec![],
                names: vec![NameRow {
                    association,
                    ordinal: 1,
                    name: Some(name),
                    name_withheld: None,
                }],
            }),
        })
    }
    /// Validates protection operands, including copied projection names. Durable
    /// constructors separately enforce the stricter stored custody contract.
    pub fn from_custody(
        mut withheld: Vec<WithheldFact>,
        custody: EvidenceCustody,
    ) -> Result<Self, String> {
        withheld.sort_by(|a, b| a.slot.cmp(&b.slot));
        validate_custody(&withheld, Some(&custody), CustodyContext::Projection)?;
        Ok(Self {
            withheld,
            custody: Some(custody),
        })
    }
    fn has(&self, slot: &str) -> bool {
        self.withheld.iter().any(|w| w.slot == slot)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum CustodyContext {
    Stored,
    Projection,
}

fn validate_custody(
    withheld: &[WithheldFact],
    custody: Option<&EvidenceCustody>,
    context: CustodyContext,
) -> Result<(), String> {
    if withheld.windows(2).any(|w| w[0].slot >= w[1].slot) {
        return Err("withholding slots not unique and sorted".into());
    }
    let Some(c) = custody else {
        return if withheld.is_empty() {
            Ok(())
        } else {
            Err("withholding needs custody".into())
        };
    };
    if c.version != 1 || !c.substitutions.is_empty() {
        return Err("invalid evidence custody".into());
    }
    let mut identities = Vec::new();
    for (i, row) in c.names.iter().enumerate() {
        if row.ordinal != i as u64 + 1 || identities.contains(&row.association) {
            return Err("invalid name order or duplicate identity".into());
        }
        // This store has no placement journal owner yet. A registered reference cannot
        // acquire authority from a fabricated number or a transient name row.
        let id = match &row.association {
            NameAssociation::Registered { .. } => {
                return Err("no earlier registered placement".into());
            }
            NameAssociation::Transient { id } | NameAssociation::Unregistered { id } => id,
        };
        if id.len() != 48
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid lease identity".into());
        }
        if row.name.is_some() == row.name_withheld.is_some() {
            return Err("name presence".into());
        }
        if matches!(row.association, NameAssociation::Unregistered { .. })
            && match row.name.as_deref() {
                Some(name) => name != "unregistered input",
                // Stored unregistered rows retain the fixed label. A newly copied
                // projection name can be obligated, under the same identity.
                None => context == CustodyContext::Stored,
            }
        {
            return Err("unregistered name".into());
        }
        identities.push(row.association.clone());
    }
    let check = |w: &WithheldFact, index_only: bool| -> Result<(), String> {
        if w.associations.is_empty() {
            return Err("empty withholding associations".into());
        }
        let indices: Vec<_> = w
            .associations
            .iter()
            .map(|a| {
                identities
                    .iter()
                    .position(|x| x == a)
                    .ok_or("missing custody name")
            })
            .collect::<Result<_, _>>()?;
        if indices.windows(2).any(|w| w[0] >= w[1]) {
            return Err("withholding association order".into());
        }
        let indexed = format!(
            "[withheld:{}]",
            indices
                .iter()
                .map(|i| format!("#{}", i + 1))
                .collect::<Vec<_>>()
                .join(",")
        );
        let names = indices
            .iter()
            .map(|i| c.names[*i].name.as_deref())
            .collect::<Option<Vec<_>>>();
        let normal = names.map(|names| format!("[withheld:{}]", names.join(",")));
        if w.marker != indexed && (index_only || normal.as_ref() != Some(&w.marker)) {
            return Err("withholding marker disagrees with names".into());
        }
        Ok(())
    };
    for w in withheld {
        check(w, false)?;
    }
    for row in &c.names {
        if let Some(w) = &row.name_withheld {
            if w.slot != "name" {
                return Err("name withholding slot".into());
            }
            check(w, true)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    NoIntent,
    Same,
    Different,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IntentReference {
    None,
    Earlier { call: u64 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReturnedPresence {
    Absent,
    Retained,
    Withheld,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptRelations {
    pub intent: IntentReference,
    pub call: Comparison,
    pub resource: Comparison,
    pub target: Comparison,
    pub operation: Comparison,
    pub account: Comparison,
    pub signed_request: Comparison,
    pub returned_vendor: ReturnedPresence,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedBinding {
    pub operation: ReceiptOperation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_request: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptFacts {
    pub source: ReceiptSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<Target>,
    pub binding: ProtectedBinding,
    pub validated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returned_vendor: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProtectedKind {
    Protected,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedReceipt {
    kind: ProtectedKind,
    version: u32,
    pub facts: ReceiptFacts,
    pub relations: ReceiptRelations,
    pub withheld: Vec<WithheldFact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custody: Option<EvidenceCustody>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum StoredReceipt {
    Legacy(Receipt),
    Protected(ProtectedReceipt),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssociationAdmission {
    Mapped,
    Quarantined,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssociationReason {
    None,
    IdentityWithheld,
    AliasUnavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    AllocationIndex,
    VendorMachine,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedEntryReference {
    pub setup: u64,
    pub index: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasCheck {
    pub record: u64,
    pub result: AliasResult,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasResult {
    Unavailable,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssociationRelations {
    pub approved_entry: ApprovedEntryReference,
    pub target_kind: TargetKind,
    pub admission: AssociationAdmission,
    pub reason: AssociationReason,
    pub alias_checks: Vec<AliasCheck>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssociationFacts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<Target>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedAssociation {
    kind: ProtectedKind,
    version: u32,
    pub facts: AssociationFacts,
    pub relations: AssociationRelations,
    pub withheld: Vec<WithheldFact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custody: Option<EvidenceCustody>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum StoredAssociation {
    Legacy(Association),
    Protected(ProtectedAssociation),
}
macro_rules! stored_decode {
    ($ty:ident,$raw:ty,$protected:ty) => {
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let value = UniqueValue::deserialize(d)?.0;
                let result = if value.get("kind").is_some() {
                    canonical::<$protected>(value).map(Self::Protected)
                } else {
                    canonical::<$raw>(value).map(Self::Legacy)
                };
                result.map_err(serde::de::Error::custom)
            }
        }
    };
}
stored_decode!(StoredReceipt, Receipt, ProtectedReceipt);
stored_decode!(StoredAssociation, Association, ProtectedAssociation);
impl From<Receipt> for StoredReceipt {
    fn from(r: Receipt) -> Self {
        Self::Legacy(r)
    }
}
impl From<Association> for StoredAssociation {
    fn from(a: Association) -> Self {
        Self::Legacy(a)
    }
}
impl PartialEq<Receipt> for StoredReceipt {
    fn eq(&self, r: &Receipt) -> bool {
        matches!(self,Self::Legacy(a) if a==r)
    }
}
impl PartialEq<Association> for StoredAssociation {
    fn eq(&self, a: &Association) -> bool {
        matches!(self,Self::Legacy(b) if b==a)
    }
}

fn compare(same: bool) -> Comparison {
    if same {
        Comparison::Same
    } else {
        Comparison::Different
    }
}
impl StoredReceipt {
    pub fn facts(&self) -> ReceiptFacts {
        match self {
            Self::Protected(p) => p.facts.clone(),
            Self::Legacy(r) => ReceiptFacts {
                source: r.source,
                call: Some(r.call),
                resource: Some(r.resource.clone()),
                target: Some(r.target.clone()),
                binding: ProtectedBinding {
                    operation: r.binding.operation,
                    account: Some(r.binding.account),
                    signed_request: Some(r.binding.signed_request),
                },
                validated: r.validated,
                returned_vendor: r.returned_vendor.clone(),
            },
        }
    }
    pub fn returned_presence(&self) -> ReturnedPresence {
        match self {
            Self::Protected(p) => p.relations.returned_vendor,
            Self::Legacy(r) => {
                if r.returned_vendor.is_some() {
                    ReturnedPresence::Retained
                } else {
                    ReturnedPresence::Absent
                }
            }
        }
    }
}
impl StoredAssociation {
    pub fn admitted(&self) -> bool {
        match self {
            Self::Legacy(_) => true,
            Self::Protected(p) => p.relations.admission == AssociationAdmission::Mapped,
        }
    }
    pub fn target(&self) -> Option<&Target> {
        match self {
            Self::Legacy(a) => Some(&a.target),
            Self::Protected(p) => p.facts.target.as_ref(),
        }
    }
}

/// Consumed input scopes clear recoverable originals on every return, including errors.
struct ReceiptInput(Receipt);
fn clear_target(t: &mut Target) {
    match t {
        Target::Entry(s) | Target::VendorMachine(s) => s.zeroize(),
        Target::AllocationIndex(n) => *n = 0,
        Target::Inference => {}
    }
}
fn clear_resource(r: &mut Resource) {
    if let Resource::Entry(s) = r {
        s.zeroize();
    }
}
impl Drop for ReceiptInput {
    fn drop(&mut self) {
        self.0.call = 0;
        clear_resource(&mut self.0.resource);
        clear_target(&mut self.0.target);
        self.0.binding.account = 0;
        self.0.binding.signed_request = 0;
        if let Some(v) = &mut self.0.returned_vendor {
            v.zeroize();
        }
    }
}
struct AssociationInput(Association);
impl Drop for AssociationInput {
    fn drop(&mut self) {
        clear_target(&mut self.0.target);
        self.0.entry.zeroize();
    }
}
fn slots(
    withheld: &[WithheldFact],
    allowed: &[&str],
    presence: &[(&str, bool)],
) -> Result<(), String> {
    if withheld.iter().any(|w| !allowed.contains(&w.slot.as_str())) {
        return Err("inapplicable withholding slot".into());
    }
    for (slot, present) in presence {
        if *present == withheld.iter().any(|w| w.slot == *slot) {
            return Err("required fact presence or withholding overlap".into());
        }
    }
    Ok(())
}

impl Dispatch {
    pub fn receipt_relations(&self, number: u64, r: &Receipt) -> ReceiptRelations {
        let intent = self
            .typed_calls
            .get(&r.call)
            .filter(|c| c.intent.call < number)
            .map(|c| &c.intent);
        let (reference, comparisons) = if let Some(i) = intent {
            (
                IntentReference::Earlier { call: i.call },
                [
                    Comparison::Same,
                    compare(r.resource == i.resource),
                    compare(r.target == i.target),
                    compare(
                        i.receipt_binding
                            .as_ref()
                            .is_some_and(|b| b.operation == r.binding.operation)
                            && i.operation == r.binding.operation.operation(),
                    ),
                    compare(
                        i.receipt_binding
                            .as_ref()
                            .is_some_and(|b| b.account == r.binding.account),
                    ),
                    compare(
                        i.receipt_binding
                            .as_ref()
                            .is_some_and(|b| b.signed_request == r.binding.signed_request),
                    ),
                ],
            )
        } else {
            (IntentReference::None, [Comparison::NoIntent; 6])
        };
        ReceiptRelations {
            intent: reference,
            call: comparisons[0],
            resource: comparisons[1],
            target: comparisons[2],
            operation: comparisons[3],
            account: comparisons[4],
            signed_request: comparisons[5],
            returned_vendor: if r.returned_vendor.is_some() {
                ReturnedPresence::Retained
            } else {
                ReturnedPresence::Absent
            },
        }
    }
    pub fn protect_receipt(
        &self,
        number: u64,
        raw: Receipt,
        mut protection: EvidenceProtection,
    ) -> Result<StoredReceipt, String> {
        let input = ReceiptInput(raw);
        protection.withheld.sort_by(|a, b| a.slot.cmp(&b.slot));
        let mut relations = self.receipt_relations(number, &input.0);
        if protection.has("returned_vendor") {
            if input.0.returned_vendor.is_none() {
                return Err("cannot withhold absent returned identity".into());
            }
            relations.returned_vendor = ReturnedPresence::Withheld;
        }
        let keep = |s: &str| !protection.has(s);
        let r = &input.0;
        let evidence = StoredReceipt::Protected(ProtectedReceipt {
            kind: ProtectedKind::Protected,
            version: 1,
            facts: ReceiptFacts {
                source: r.source,
                call: keep("call").then_some(r.call),
                resource: keep("resource").then(|| r.resource.clone()),
                target: keep("target").then(|| r.target.clone()),
                binding: ProtectedBinding {
                    operation: r.binding.operation,
                    account: keep("binding/account").then_some(r.binding.account),
                    signed_request: keep("binding/signed_request")
                        .then_some(r.binding.signed_request),
                },
                validated: r.validated,
                returned_vendor: if keep("returned_vendor") {
                    r.returned_vendor.clone()
                } else {
                    None
                },
            },
            relations,
            withheld: protection.withheld,
            custody: protection.custody,
        });
        self.validate_receipt(number, &evidence)?;
        Ok(evidence)
    }
    pub(crate) fn validate_receipt(&self, number: u64, r: &StoredReceipt) -> Result<(), String> {
        let StoredReceipt::Protected(p) = r else {
            return Ok(());
        };
        if p.version != 1 {
            return Err("invalid protected receipt version".into());
        }
        validate_custody(&p.withheld, p.custody.as_ref(), CustodyContext::Stored)?;
        let f = &p.facts;
        slots(
            &p.withheld,
            &[
                "call",
                "resource",
                "target",
                "binding/account",
                "binding/signed_request",
                "returned_vendor",
            ],
            &[
                ("call", f.call.is_some()),
                ("resource", f.resource.is_some()),
                ("target", f.target.is_some()),
                ("binding/account", f.binding.account.is_some()),
                ("binding/signed_request", f.binding.signed_request.is_some()),
            ],
        )?;
        let withheld = p.withheld.iter().any(|w| w.slot == "returned_vendor");
        if match p.relations.returned_vendor {
            ReturnedPresence::Absent => f.returned_vendor.is_some() || withheld,
            ReturnedPresence::Retained => f.returned_vendor.is_none() || withheld,
            ReturnedPresence::Withheld => f.returned_vendor.is_some() || !withheld,
        } {
            return Err("returned presence disagrees".into());
        }
        let relations = &p.relations;
        let checks = [
            relations.call,
            relations.resource,
            relations.target,
            relations.operation,
            relations.account,
            relations.signed_request,
        ];
        match relations.intent {
            IntentReference::None => {
                if checks != [Comparison::NoIntent; 6]
                    || f.call
                        .is_some_and(|c| c < number && self.typed_calls.contains_key(&c))
                {
                    return Err("missing genuine earlier intent".into());
                }
            }
            IntentReference::Earlier { call } => {
                let i = &self
                    .typed_calls
                    .get(&call)
                    .filter(|_| call < number)
                    .ok_or("invalid earlier intent reference")?
                    .intent;
                if relations.call != Comparison::Same
                    || checks.contains(&Comparison::NoIntent)
                    || f.call.is_some_and(|c| c != call)
                {
                    return Err("invalid call relation".into());
                }
                for valid in [
                    f.resource
                        .as_ref()
                        .is_none_or(|r| compare(*r == i.resource) == relations.resource),
                    f.target
                        .as_ref()
                        .is_none_or(|t| compare(*t == i.target) == relations.target),
                    compare(
                        i.receipt_binding
                            .as_ref()
                            .is_some_and(|b| b.operation == f.binding.operation)
                            && i.operation == f.binding.operation.operation(),
                    ) == relations.operation,
                    f.binding.account.is_none_or(|a| {
                        compare(i.receipt_binding.as_ref().is_some_and(|b| b.account == a))
                            == relations.account
                    }),
                    f.binding.signed_request.is_none_or(|a| {
                        compare(
                            i.receipt_binding
                                .as_ref()
                                .is_some_and(|b| b.signed_request == a),
                        ) == relations.signed_request
                    }),
                    i.receipt_binding.is_some()
                        || (relations.account == Comparison::Different
                            && relations.signed_request == Comparison::Different),
                ] {
                    if !valid {
                        return Err("retained receipt contradicts relation".into());
                    }
                }
            }
        }
        Ok(())
    }
    pub(crate) fn receipt_intent<'a>(
        &'a self,
        number: u64,
        r: &StoredReceipt,
    ) -> Option<&'a OperationIntent> {
        let relations = match r {
            StoredReceipt::Legacy(r) => self.receipt_relations(number, r),
            StoredReceipt::Protected(p) => p.relations.clone(),
        };
        let IntentReference::Earlier { call } = relations.intent else {
            return None;
        };
        let f = r.facts();
        if f.source != ReceiptSource::BrowserVendorTls
            || !f.validated
            || [
                relations.call,
                relations.resource,
                relations.target,
                relations.operation,
                relations.account,
                relations.signed_request,
            ] != [Comparison::Same; 6]
        {
            return None;
        }
        self.typed_calls.get(&call).map(|c| &c.intent)
    }
    /// All permanent different-entry risk numbers, in authenticated journal order.
    pub fn identity_exclusions(&self, entry: &str) -> Vec<u64> {
        let mut risks = Vec::new();
        for r in &self.receipts {
            if r.receipt.returned_presence() == ReturnedPresence::Withheld
                && r.receipt.facts().binding.operation == ReceiptOperation::Order
                && let Some(i) = self.receipt_intent(r.number, &r.receipt)
                && let Resource::Entry(owner) = &i.resource
                && self.approved_entries.contains_key(owner)
                && owner != entry
            {
                risks.push(r.number);
            }
        }
        for a in &self.association_records {
            if let StoredAssociation::Protected(p) = &a.association
                && p.relations.reason == AssociationReason::IdentityWithheld
                && let Ok(owner) = self.association_entry(&a.association)
                && owner != entry
            {
                risks.push(a.number);
            }
        }
        risks.sort_unstable();
        risks.dedup();
        risks
    }
    pub fn has_identity_risk(&self) -> bool {
        self.approved_entries.keys().any(|entry| !self.identity_exclusions(entry).is_empty())
            || self.receipts.iter().any(|r| r.receipt.returned_presence()==ReturnedPresence::Withheld && r.receipt.facts().binding.operation==ReceiptOperation::Order && self.receipt_intent(r.number,&r.receipt).is_some_and(|i| matches!(&i.resource,Resource::Entry(e) if self.approved_entries.contains_key(e))))
            || self.association_records.iter().any(|a| matches!(&a.association,StoredAssociation::Protected(p) if p.relations.reason==AssociationReason::IdentityWithheld))
    }
    pub(crate) fn association_entry<'a>(
        &'a self,
        a: &'a StoredAssociation,
    ) -> Result<&'a str, String> {
        match a {
            StoredAssociation::Legacy(a) => Ok(&a.entry),
            StoredAssociation::Protected(p) => {
                if self.setup_approval != Some(p.relations.approved_entry.setup) {
                    return Err("invalid setup approval reference".into());
                }
                self.approved_entries
                    .iter()
                    .find(|(_, e)| e.approved.identity.index == p.relations.approved_entry.index)
                    .map(|(e, _)| e.as_str())
                    .ok_or_else(|| "invalid approved entry index".into())
            }
        }
    }
    fn known_identity_conflict(&self, target: &Target, entry: &str) -> bool {
        self.association_records.iter().any(|a| a.association.target()==Some(target) && self.association_entry(&a.association).is_ok_and(|e|e!=entry))
            || self.receipts.iter().any(|r| r.receipt.facts().binding.operation==ReceiptOperation::Order && r.receipt.facts().returned_vendor.as_ref().is_some_and(|id|target==&Target::VendorMachine(id.clone())) && self.receipt_intent(r.number,&r.receipt).is_some_and(|i|matches!(&i.resource,Resource::Entry(e) if e!=entry && self.approved_entries.contains_key(e))))
    }
    /// Genuine checks must run before the consumed input can be omitted.
    pub(crate) fn association_duplicate(&self, a: &Association) -> Result<bool, String> {
        if !matches!(
            a.target,
            Target::AllocationIndex(_) | Target::VendorMachine(_)
        ) {
            return Err("only allocation indices and vendor ids can be associated".into());
        }
        if !self.approved_entries.contains_key(&a.entry) {
            return Err("association names no approved entry".into());
        }
        if let Some(old) = self.associations.iter().find(|old| old.target == a.target) {
            return if old.entry == a.entry {
                Ok(true)
            } else {
                Err("target already associated".into())
            };
        }
        if matches!(a.target, Target::VendorMachine(_))
            && self.known_identity_conflict(&a.target, &a.entry)
        {
            return Err("identity_conflict".into());
        }
        Ok(false)
    }
    pub fn protect_association(
        &self,
        number: u64,
        raw: Association,
        mut protection: EvidenceProtection,
    ) -> Result<Option<StoredAssociation>, String> {
        let input = AssociationInput(raw);
        if self.association_duplicate(&input.0)? {
            return Ok(None);
        }
        if !matches!(input.0.target, Target::VendorMachine(_)) {
            return Err("AllocationIndex storage must remain legacy".into());
        }
        let entry = &input.0.entry;
        let alias_checks = self
            .identity_exclusions(entry)
            .into_iter()
            .map(|record| AliasCheck {
                record,
                result: AliasResult::Unavailable,
            })
            .collect::<Vec<_>>();
        let reason = if protection.has("target") {
            AssociationReason::IdentityWithheld
        } else if !alias_checks.is_empty() {
            AssociationReason::AliasUnavailable
        } else {
            AssociationReason::None
        };
        let admission = if reason == AssociationReason::None {
            AssociationAdmission::Mapped
        } else {
            AssociationAdmission::Quarantined
        };
        protection.withheld.sort_by(|a, b| a.slot.cmp(&b.slot));
        let evidence = StoredAssociation::Protected(ProtectedAssociation {
            kind: ProtectedKind::Protected,
            version: 1,
            facts: AssociationFacts {
                target: (!protection.has("target")).then(|| input.0.target.clone()),
                entry: (!protection.has("entry")).then(|| entry.clone()),
            },
            relations: AssociationRelations {
                approved_entry: ApprovedEntryReference {
                    setup: self.setup_approval.ok_or("missing setup approval")?,
                    index: self.approved_entries[entry].approved.identity.index,
                },
                target_kind: TargetKind::VendorMachine,
                admission,
                reason,
                alias_checks,
            },
            withheld: protection.withheld,
            custody: protection.custody,
        });
        self.validate_association(number, &evidence)?;
        Ok(Some(evidence))
    }
    pub(crate) fn validate_association(
        &self,
        number: u64,
        a: &StoredAssociation,
    ) -> Result<(), String> {
        match a {
            StoredAssociation::Legacy(a) => {
                if matches!(a.target, Target::VendorMachine(_)) && self.has_identity_risk() {
                    return Err("raw VendorMachine association after identity risk".into());
                }
                self.association_duplicate(a)?;
            }
            StoredAssociation::Protected(p) => {
                if p.version != 1 || p.relations.target_kind != TargetKind::VendorMachine {
                    return Err("noncanonical protected association".into());
                }
                validate_custody(&p.withheld, p.custody.as_ref(), CustodyContext::Stored)?;
                slots(
                    &p.withheld,
                    &["target", "entry"],
                    &[
                        ("target", p.facts.target.is_some()),
                        ("entry", p.facts.entry.is_some()),
                    ],
                )?;
                let entry = self.association_entry(a)?;
                if p.relations.approved_entry.setup >= number
                    || p.facts.entry.as_deref().is_some_and(|e| e != entry)
                {
                    return Err("association contradicts approved entry".into());
                }
                if let Some(target) = &p.facts.target {
                    if !matches!(target, Target::VendorMachine(_)) {
                        return Err("association target kind".into());
                    }
                    if self.association_duplicate(&Association {
                        target: target.clone(),
                        entry: entry.into(),
                    })? {
                        return Err("protected duplicate must not append".into());
                    }
                }
                let expected = self
                    .identity_exclusions(entry)
                    .into_iter()
                    .map(|record| AliasCheck {
                        record,
                        result: AliasResult::Unavailable,
                    })
                    .collect::<Vec<_>>();
                let reason = if p.facts.target.is_none() {
                    AssociationReason::IdentityWithheld
                } else if expected.is_empty() {
                    AssociationReason::None
                } else {
                    AssociationReason::AliasUnavailable
                };
                let admission = if reason == AssociationReason::None {
                    AssociationAdmission::Mapped
                } else {
                    AssociationAdmission::Quarantined
                };
                if p.relations.reason != reason
                    || p.relations.admission != admission
                    || p.relations.alias_checks != expected
                {
                    return Err(
                        "association admission or alias checks disagree with earlier prefix".into(),
                    );
                }
            }
        }
        Ok(())
    }
}

/// Diagnostic owners have neither a journal number nor historical settlement authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum EvidenceDiagnostic {
    Receipt {
        committed: bool,
        receipt: StoredReceipt,
    },
    Association {
        committed: bool,
        association: StoredAssociation,
    },
}

/// A read-only display cannot be passed to a stored-evidence writer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct EvidenceProjection(Value);
impl EvidenceProjection {
    pub fn value(&self) -> &Value {
        &self.0
    }
}

impl Dispatch {
    pub fn project_receipt(
        &self,
        record: &ReceiptRecord,
        protection: EvidenceProtection,
    ) -> Result<EvidenceProjection, String> {
        let mut protected = match &record.receipt {
            StoredReceipt::Protected(p) => p.clone(),
            StoredReceipt::Legacy(r) => {
                let StoredReceipt::Protected(p) =
                    self.protect_receipt(record.number, r.clone(), EvidenceProtection::default())?
                else {
                    unreachable!()
                };
                p
            }
        };
        project_facts(
            &mut protected.facts,
            &mut protected.withheld,
            &mut protected.custody,
            protection,
            &[
                "call",
                "resource",
                "target",
                "binding/account",
                "binding/signed_request",
                "returned_vendor",
            ],
        )?;
        Ok(EvidenceProjection(
            json!({"number":record.number,"receipt":protected,"settled":record.settled}),
        ))
    }
    pub fn project_association(
        &self,
        record: &AssociationRecord,
        protection: EvidenceProtection,
    ) -> Result<EvidenceProjection, String> {
        let mut protected = match &record.association {
            StoredAssociation::Protected(p) => p.clone(),
            StoredAssociation::Legacy(a) => ProtectedAssociation {
                kind: ProtectedKind::Protected,
                version: 1,
                facts: AssociationFacts {
                    target: Some(a.target.clone()),
                    entry: Some(a.entry.clone()),
                },
                relations: AssociationRelations {
                    approved_entry: ApprovedEntryReference {
                        setup: self.setup_approval.ok_or("missing setup approval")?,
                        index: self
                            .approved_entries
                            .get(&a.entry)
                            .ok_or("unknown entry")?
                            .approved
                            .identity
                            .index,
                    },
                    target_kind: match a.target {
                        Target::AllocationIndex(_) => TargetKind::AllocationIndex,
                        Target::VendorMachine(_) => TargetKind::VendorMachine,
                        _ => return Err("invalid target kind".into()),
                    },
                    admission: AssociationAdmission::Mapped,
                    reason: AssociationReason::None,
                    alias_checks: vec![],
                },
                withheld: vec![],
                custody: None,
            },
        };
        project_facts(
            &mut protected.facts,
            &mut protected.withheld,
            &mut protected.custody,
            protection,
            &["target", "entry"],
        )?;
        Ok(EvidenceProjection(
            json!({"number":record.number,"association":protected}),
        ))
    }
}
fn project_facts<T: Serialize + serde::de::DeserializeOwned>(
    facts: &mut T,
    withheld: &mut Vec<WithheldFact>,
    custody: &mut Option<EvidenceCustody>,
    protection: EvidenceProtection,
    allowed: &[&str],
) -> Result<(), String> {
    validate_custody(
        &protection.withheld,
        protection.custody.as_ref(),
        CustodyContext::Projection,
    )?;
    let mut value = serde_json::to_value(&*facts).map_err(|_| "projection facts")?;
    let mut names = custody
        .as_ref()
        .map(|c| c.names.clone())
        .unwrap_or_default();
    if let Some(c) = protection.custody {
        for mut row in c.names {
            if let Some(old) = names.iter_mut().find(|n| n.association == row.association) {
                match (&old.name, &row.name) {
                    (Some(a), Some(b)) if a == b => {}
                    (Some(_), None) => {
                        old.name = None;
                        old.name_withheld = row.name_withheld;
                    }
                    (None, None) => {
                        let existing = old
                            .name_withheld
                            .as_mut()
                            .ok_or("missing name withholding")?;
                        for a in row
                            .name_withheld
                            .ok_or("missing name withholding")?
                            .associations
                        {
                            if !existing.associations.contains(&a) {
                                existing.associations.push(a);
                            }
                        }
                    }
                    _ => return Err("contradictory projection name".into()),
                }
            } else {
                row.ordinal = names.len() as u64 + 1;
                names.push(row);
            }
        }
    }
    for w in protection.withheld {
        if !allowed.contains(&w.slot.as_str()) {
            return Err("inapplicable projection slot".into());
        }
        if let Some(old) = withheld.iter_mut().find(|old| old.slot == w.slot) {
            for a in w.associations {
                if !old.associations.contains(&a) {
                    old.associations.push(a);
                }
            }
            continue;
        }
        let parts = w.slot.split('/').collect::<Vec<_>>();
        let (last, parents) = parts.split_last().ok_or("projection slot")?;
        let mut owner = &mut value;
        for parent in parents {
            owner = owner.get_mut(*parent).ok_or("absent projection parent")?;
        }
        if owner
            .as_object_mut()
            .ok_or("projection owner")?
            .remove(*last)
            .is_none()
        {
            return Err("cannot withhold absent fact".into());
        }
        withheld.push(w);
    }
    // Membership is complete before repair. Every marker is regenerated from identity,
    // including unavailable names whose input ordinals belonged to a different owner.
    let identities: Vec<_> = names.iter().map(|n| n.association.clone()).collect();
    let reindex = |w: &mut WithheldFact| -> Result<(), String> {
        let mut indices = w
            .associations
            .iter()
            .map(|a| identities.iter().position(|n| n == a).ok_or("missing name"))
            .collect::<Result<Vec<_>, _>>()?;
        indices.sort_unstable();
        w.associations = indices.iter().map(|i| identities[*i].clone()).collect();
        w.marker = format!(
            "[withheld:{}]",
            indices
                .iter()
                .map(|i| format!("#{}", i + 1))
                .collect::<Vec<_>>()
                .join(",")
        );
        Ok(())
    };
    for row in &mut names {
        if let Some(w) = &mut row.name_withheld {
            reindex(w)?;
        }
    }
    for w in withheld.iter_mut() {
        reindex(w)?;
    }
    withheld.sort_by(|a, b| a.slot.cmp(&b.slot));
    if !names.is_empty() {
        *custody = Some(EvidenceCustody {
            version: 1,
            substitutions: vec![],
            names,
        });
    }
    validate_custody(withheld, custody.as_ref(), CustodyContext::Projection)?;
    *facts = serde_json::from_value(value).map_err(|_| "invalid projection facts")?;
    Ok(())
}

impl<'de> Deserialize<'de> for Receipt {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            source: ReceiptSource,
            call: u64,
            resource: Resource,
            target: Target,
            binding: ReceiptBinding,
            validated: bool,
            #[serde(deserialize_with = "required_returned")]
            returned_vendor: Option<String>,
        }
        fn required_returned<'de, D: serde::Deserializer<'de>>(
            d: D,
        ) -> Result<Option<String>, D::Error> {
            Option::deserialize(d)
        }
        let f: Fields =
            canonical(UniqueValue::deserialize(d)?.0).map_err(serde::de::Error::custom)?;
        Ok(Receipt {
            source: f.source,
            call: f.call,
            resource: f.resource,
            target: f.target,
            binding: f.binding,
            validated: f.validated,
            returned_vendor: f.returned_vendor,
        })
    }
}
impl<'de> Deserialize<'de> for Association {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            target: Target,
            entry: String,
        }
        let f: Fields =
            canonical(UniqueValue::deserialize(d)?.0).map_err(serde::de::Error::custom)?;
        Ok(Association {
            target: f.target,
            entry: f.entry,
        })
    }
}

impl Dispatch {
    pub fn project_typed_call(
        &self,
        call: &OperationCall,
        protection: EvidenceProtection,
    ) -> Result<EvidenceProjection, String> {
        self.project_intent_value(
            serde_json::to_value(call).map_err(|_| "typed call projection")?,
            protection,
        )
    }
    pub fn project_operation_intent(
        &self,
        intent: &OperationIntent,
        protection: EvidenceProtection,
    ) -> Result<EvidenceProjection, String> {
        self.project_intent_value(
            serde_json::to_value(intent).map_err(|_| "intent projection")?,
            protection,
        )
    }
    fn project_intent_value(
        &self,
        mut value: Value,
        protection: EvidenceProtection,
    ) -> Result<EvidenceProjection, String> {
        let mut withheld = Vec::new();
        let mut custody = None;
        project_facts(
            &mut value,
            &mut withheld,
            &mut custody,
            protection,
            &[
                "resource",
                "target",
                "receipt_binding/account",
                "receipt_binding/signed_request",
                "approved/resource",
                "approved/target",
                "approved/receipt_binding/account",
                "approved/receipt_binding/signed_request",
            ],
        )?;
        if !withheld.is_empty() {
            value["withheld"] = json!(withheld);
        }
        if let Some(c) = custody {
            value["custody"] = json!(c);
        }
        Ok(EvidenceProjection(value))
    }
}
