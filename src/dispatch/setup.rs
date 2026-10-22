//! Approved setup entries, their journaled allocation identities and operator answers.
use super::*;
use crate::allocation::{self, Family, Identity, Metadata};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecurringCost {
    pub amount: u64,
    pub unit: Unit,
    pub period: Period,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Sat,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Period {
    Month,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineEntry {
    pub machine: String,
    pub vendor: String,
    pub product: String,
    pub region: String,
    pub cost: RecurringCost,
}

/// Implementation reading: compiled fixture data, not a vendor's price.
pub fn fixture_setup() -> Vec<MachineEntry> {
    ["fixture", "fixture-other"]
        .into_iter()
        .enumerate()
        .map(|(i, machine)| MachineEntry {
            machine: machine.into(),
            vendor: "Fixture vendor".into(),
            product: "Fixture machine".into(),
            region: "Fixture region".into(),
            cost: RecurringCost {
                amount: 1000 * (i as u64 + 1),
                unit: Unit::Sat,
                period: Period::Month,
            },
        })
        .collect()
}

pub fn totals(entries: &[MachineEntry]) -> Result<(u64, u64), String> {
    let monthly = entries
        .iter()
        .try_fold(0u64, |n, e| n.checked_add(e.cost.amount))
        .ok_or("setup cost overflow")?;
    Ok((
        monthly,
        monthly.checked_mul(12).ok_or("setup cost overflow")?,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessModel {
    Maintained,
    Sealed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Access {
    pub model: AccessModel,
    pub profile: String,
    pub revision: u32,
}

pub fn ad_hoc_revision() -> u32 {
    crate::TENANT_PROFILES
        .iter()
        .find(|(name, _)| *name == "ad-hoc")
        .expect("compiled ad-hoc profile")
        .1
        .lines()
        .find_map(|line| line.strip_prefix("Profile revision: "))
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .expect("profile revision")
}
impl Access {
    pub fn ad_hoc() -> Self {
        Self {
            model: AccessModel::Maintained,
            profile: "ad-hoc".into(),
            revision: ad_hoc_revision(),
        }
    }
    fn validate(&self) -> Result<(), String> {
        if self.model != AccessModel::Maintained || self.profile != "ad-hoc" {
            return Err("unsupported ad-hoc access model or profile".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassAnswer {
    Yes,
    No,
    NotSure,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineClass {
    SinglePurpose,
    MultiTenant,
}
impl ClassAnswer {
    pub fn class(self) -> MachineClass {
        match self {
            Self::No => MachineClass::SinglePurpose,
            Self::Yes | Self::NotSure => MachineClass::MultiTenant,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassRecord {
    pub machine: String,
    pub answer: ClassAnswer,
    pub class: MachineClass,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRecord {
    pub machine: String,
    pub access: Access,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedEntry {
    pub entry: MachineEntry,
    pub identity: Identity,
    #[serde(deserialize_with = "required_access")]
    pub access: Option<Access>,
}
fn required_access<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Access>, D::Error> {
    Option::<Access>::deserialize(deserializer)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupApproval {
    pub entries: Vec<ApprovedEntry>,
    pub monthly_sat: u64,
    pub annual_sat: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SetupRecord {
    Approval(SetupApproval),
    Class(ClassRecord),
    Access(AccessRecord),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedMachine {
    pub approved: ApprovedEntry,
    pub answer: Option<ClassAnswer>,
    pub class: Option<MachineClass>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingRefusal {
    NoEntry,
    ClassMissing,
    AccessMissing,
}

impl Dispatch {
    /// The entry and its index must be journaled, then its class and access model, before binding.
    /// Access at binding is an implementation reading of ARC-44's installation boundary.
    pub fn check_binding(&self, entry: &str) -> Result<(), BindingRefusal> {
        let machine = self
            .approved_entries
            .get(entry)
            .ok_or(BindingRefusal::NoEntry)?;
        if machine.class.is_none() {
            return Err(BindingRefusal::ClassMissing);
        }
        if machine.approved.access.is_none() {
            return Err(BindingRefusal::AccessMissing);
        }
        Ok(())
    }

    pub(crate) fn apply_setup(
        &mut self,
        allocation: &mut Metadata,
        event: &SetupRecord,
    ) -> Result<(), String> {
        match event {
            SetupRecord::Approval(approval) => {
                if !self.approved_entries.is_empty() || approval.entries.is_empty() {
                    return Err("setup already approved or empty".into());
                }
                let entries: Vec<_> = approval.entries.iter().map(|a| a.entry.clone()).collect();
                if totals(&entries)? != (approval.monthly_sat, approval.annual_sat) {
                    return Err("setup totals differ from approved costs".into());
                }
                for approved in &approval.entries {
                    let name = &approved.entry.machine;
                    if name.is_empty() || self.approved_entries.contains_key(name) {
                        return Err("approved entry name reused or empty".into());
                    }
                    if approved.identity.family != Family::Machines {
                        return Err("approved entry needs a machine-family index".into());
                    }
                    if let Some(access) = &approved.access {
                        access.validate()?;
                    }
                    allocation
                        .apply(&allocation::Event::Reserve(approved.identity.clone()))
                        .map_err(|e| e.to_string())?;
                    self.approved_entries.insert(
                        name.clone(),
                        ApprovedMachine {
                            approved: approved.clone(),
                            answer: None,
                            class: None,
                        },
                    );
                    self.associations.push(Association {
                        target: Target::AllocationIndex(approved.identity.index),
                        entry: name.clone(),
                    });
                    self.current_installations.entry(name.clone()).or_default();
                }
            }
            SetupRecord::Class(record) => {
                let machine = self
                    .approved_entries
                    .get_mut(&record.machine)
                    .ok_or("class names no approved entry")?;
                if machine.class.is_some() {
                    return Err("class already answered".into());
                }
                if record.class != record.answer.class() {
                    return Err("class differs from the answer".into());
                }
                machine.answer = Some(record.answer);
                machine.class = Some(record.class);
            }
            SetupRecord::Access(record) => {
                record.access.validate()?;
                let machine = self
                    .approved_entries
                    .get_mut(&record.machine)
                    .ok_or("access names no approved entry")?;
                if machine.approved.access.is_some() {
                    return Err("access already recorded".into());
                }
                machine.approved.access = Some(record.access.clone());
            }
        }
        Ok(())
    }

    /// Page-safe projection: allocation family and index, never the seed identifier.
    pub fn setup_view(&self) -> serde_json::Value {
        let machines: Vec<_> = self.approved_entries.values().map(|m| serde_json::json!({
            "entry": m.approved.entry, "family": m.approved.identity.family, "index": m.approved.identity.index,
            "answer": m.answer, "class": m.class, "access": m.approved.access,
        })).collect();
        serde_json::Value::Array(machines)
    }
}
