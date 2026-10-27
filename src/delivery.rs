//! Delivery compares intended fields with typed evidence, never with command reports.
//! ARC-17/39/43 and the declaration table define these rules. Real observation producers
//! remain separate; the current harness supplies explicitly labelled fixture measurements.
use crate::declaration::*;
use crate::dispatch::MachineClass;
use serde::{Deserialize, Serialize};

pub const FIXTURE_LIMIT: &str = "Fixture measurements and fixed lockdown fixture checks only; no live machine was read. The bundle's lockdown checklist and real observation paths are not implemented.";
pub const REPORT_LABEL: &str = "Checks the AI wrote — not part of Delivered";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldId {
    Version,
    Inbound,
    Outbound,
    Services,
    Spendable,
    Permitted,
    DriftChecks,
    Required,
    DefaultCredentials,
    FixedDefaultCredentials,
    SshdPosture,
}
impl FieldId {
    pub const DECLARATION: [Self; 9] = [
        Self::Version,
        Self::Inbound,
        Self::Outbound,
        Self::Services,
        Self::Spendable,
        Self::Permitted,
        Self::DriftChecks,
        Self::Required,
        Self::DefaultCredentials,
    ];
    pub fn class(self) -> FindingClass {
        if self == Self::Services {
            FindingClass::Lifecycle
        } else {
            FindingClass::Lockdown
        }
    }
}

/// Wider than approval admission. Explicit empty stays a specified value, interpreted by
/// that field's row; evaluating a missing/invalid field grants no approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stated<T> {
    Missing,
    Invalid,
    Unspecified,
    Specified(T),
}
impl<T: Clone> std::convert::From<&Field<T>> for Stated<T> {
    fn from(field: &Field<T>) -> Self {
        match field {
            Field::Value(v) => Self::Specified(v.clone()),
            Field::Unspecified(_) => Self::Unspecified,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckIdentity(pub String);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intended {
    pub version: Stated<u32>,
    pub inbound: Stated<Vec<Inbound>>,
    pub outbound: Stated<Vec<Outbound>>,
    pub services: Stated<Vec<Service>>,
    pub spendable: Stated<bool>,
    pub permitted: Stated<Vec<Material>>,
    pub drift: Stated<Vec<CheckIdentity>>,
    pub required: Stated<Vec<CheckIdentity>>,
    pub credentials: Stated<Vec<String>>,
}
impl std::convert::From<&Declaration> for Intended {
    fn from(d: &Declaration) -> Self {
        fn checks(f: &Field<Vec<serde_json::Value>>) -> Stated<Vec<CheckIdentity>> {
            match f {
                Field::Unspecified(_) => Stated::Unspecified,
                Field::Value(v) if v.is_empty() => Stated::Specified(vec![]),
                // The current approval boundary admits no nonempty check library.
                Field::Value(_) => Stated::Invalid,
            }
        }
        Self {
            version: Stated::Specified(d.version),
            inbound: (&d.listeners.inbound).into(),
            outbound: (&d.listeners.outbound).into(),
            services: (&d.services).into(),
            spendable: (&d.key_material.spendable).into(),
            permitted: (&d.key_material.permitted).into(),
            drift: checks(&d.drift_checks),
            required: checks(&d.required),
            credentials: match &d.default_credentials {
                Field::Unspecified(_) => Stated::Unspecified,
                Field::Value(Credentials::None(_)) => Stated::Specified(vec![]),
                Field::Value(Credentials::Changed(v)) => Stated::Specified(v.clone()),
            },
        }
    }
}

/// Missing is different from an observation of an empty set; failed reads carry no values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "read",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Measured<T> {
    Missing,
    Failed,
    Value(T),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Running,
    RestartDemonstrated,
    EnabledRestartNotDemonstrated,
    StoppedSinceRestart,
    Difference,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceFact {
    pub service: Service,
    pub state: ServiceState,
    /// Supplied by the placing-session producer; a restart note cannot substitute for it.
    pub running_after_last_placement: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measurements {
    pub inbound: Measured<Vec<Inbound>>,
    pub outbound: Measured<Vec<Outbound>>,
    pub services: Measured<Vec<ServiceFact>>,
    pub spendable: Measured<bool>,
    pub permitted: Measured<Vec<Material>>,
    pub required: Measured<Vec<String>>,
    pub credentials: Measured<Vec<String>>,
    pub fixed_default_credentials: Measured<bool>,
    pub sshd_posture: Measured<bool>,
    pub placing_session: bool,
}
impl Measurements {
    pub fn missing() -> Self {
        Self {
            inbound: Measured::Missing,
            outbound: Measured::Missing,
            services: Measured::Missing,
            spendable: Measured::Missing,
            permitted: Measured::Missing,
            required: Measured::Missing,
            credentials: Measured::Missing,
            fixed_default_credentials: Measured::Missing,
            sshd_posture: Measured::Missing,
            placing_session: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingClass {
    Lockdown,
    Lifecycle,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub field: FieldId,
    pub detail: String,
    pub service: Option<Service>,
}
impl Finding {
    pub fn class(&self) -> FindingClass {
        self.field.class()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
    pub service: Service,
    pub text: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Checked,
    Finding,
    Blocked,
    SchemaError,
    Unavailable,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldResult {
    pub field: FieldId,
    pub status: Status,
    pub findings: Vec<Finding>,
    pub notes: Vec<Note>,
}
impl FieldResult {
    fn new(field: FieldId, status: Status) -> Self {
        Self {
            field,
            status,
            findings: vec![],
            notes: vec![],
        }
    }
    fn difference(&mut self, detail: String, service: Option<Service>) {
        self.status = Status::Finding;
        self.findings.push(Finding {
            field: self.field,
            detail,
            service,
        });
    }
}
fn stated<T>(
    field: FieldId,
    value: &Stated<T>,
    check: impl FnOnce(&T) -> FieldResult,
) -> FieldResult {
    match value {
        Stated::Missing | Stated::Invalid => FieldResult::new(field, Status::SchemaError),
        Stated::Unspecified => FieldResult::new(field, Status::Blocked),
        Stated::Specified(v) => check(v),
    }
}
fn measured<T>(
    field: FieldId,
    value: &Measured<T>,
    check: impl FnOnce(&T) -> FieldResult,
) -> FieldResult {
    match value {
        Measured::Missing | Measured::Failed => FieldResult::new(field, Status::Unavailable),
        Measured::Value(v) => check(v),
    }
}
fn subset<T: PartialEq + std::fmt::Debug>(
    field: FieldId,
    needles: &[T],
    haystack: &[T],
) -> FieldResult {
    let mut result = FieldResult::new(field, Status::Checked);
    for v in needles {
        if !haystack.contains(v) {
            result.difference(format!("{field:?}: {v:?}"), None);
        }
    }
    result
}

/// Presence is checked separately from each row's meaning. No expectation or companion
/// assumption enters this function. The journaled production result uses it too.
pub fn fields(
    d: &Intended,
    class: MachineClass,
    m: &Measurements,
    standing: &[Finding],
) -> Vec<FieldResult> {
    use FieldId::*;
    let mut results = vec![
        stated(Version, &d.version, |v| {
            FieldResult::new(
                Version,
                if *v == 2 {
                    Status::Checked
                } else {
                    Status::SchemaError
                },
            )
        }),
        stated(Inbound, &d.inbound, |allowed| {
            measured(Inbound, &m.inbound, |seen| subset(Inbound, seen, allowed))
        }),
        stated(Outbound, &d.outbound, |required| {
            if required.is_empty() {
                return FieldResult::new(Outbound, Status::Checked);
            }
            measured(Outbound, &m.outbound, |seen| {
                subset(Outbound, required, seen)
            })
        }),
        stated(Services, &d.services, |services| {
            if services.is_empty() {
                return FieldResult::new(Services, Status::Checked);
            }
            measured(Services, &m.services, |facts| {
                let mut result = FieldResult::new(Services, Status::Checked);
                for service in services {
                    let matches: Vec<_> = facts.iter().filter(|f| f.service == *service).collect();
                    let [fact] = matches.as_slice() else {
                        result.status = Status::Unavailable;
                        continue;
                    };
                    let old = standing
                        .iter()
                        .any(|f| f.field == Services && f.service.as_ref() == Some(service));
                    let (passes, note) = match (&service.lifecycle, &fact.state) {
                        (Lifecycle::RunningAtDelivery, ServiceState::Running) => (true, None),
                        (Lifecycle::EnabledSurvivesReboot, ServiceState::RestartDemonstrated) => {
                            (true, None)
                        }
                        (
                            Lifecycle::EnabledSurvivesReboot,
                            ServiceState::EnabledRestartNotDemonstrated,
                        ) => (true, Some("enabled, restart not demonstrated")),
                        (Lifecycle::RunningAtDelivery, ServiceState::StoppedSinceRestart)
                            if !old && !m.placing_session =>
                        {
                            (true, Some("stopped since a restart, as approved"))
                        }
                        _ => (false, None),
                    };
                    if !passes
                        || (m.placing_session
                            && service.lifecycle == Lifecycle::RunningAtDelivery
                            && (!fact.running_after_last_placement
                                || fact.state != ServiceState::Running))
                    {
                        result.difference(
                            format!(
                                "Service {} ({:?}) differs from its declared lifecycle",
                                service.name, service.scope
                            ),
                            Some(service.clone()),
                        );
                    } else if let Some(text) = note {
                        result.notes.push(Note {
                            service: service.clone(),
                            text: text.into(),
                        });
                    }
                }
                result
            })
        }),
        stated(Spendable, &d.spendable, |allowed| {
            if class == MachineClass::MultiTenant && *allowed {
                return FieldResult::new(Spendable, Status::SchemaError);
            }
            measured(Spendable, &m.spendable, |seen| {
                let mut r = FieldResult::new(Spendable, Status::Checked);
                if *seen && !*allowed {
                    r.difference("Spendable tenant material found".into(), None);
                }
                r
            })
        }),
        stated(Permitted, &d.permitted, |allowed| {
            if class == MachineClass::MultiTenant
                && allowed
                    .iter()
                    .any(|e| e.kind == MaterialKind::PrivateNonSpendable)
            {
                return FieldResult::new(Permitted, Status::SchemaError);
            }
            measured(Permitted, &m.permitted, |seen| {
                subset(Permitted, seen, allowed)
            })
        }),
        stated(DriftChecks, &d.drift, |_| {
            FieldResult::new(DriftChecks, Status::Checked)
        }),
        stated(Required, &d.required, |required| {
            if required.is_empty() {
                return FieldResult::new(Required, Status::Checked);
            }
            measured(Required, &m.required, |seen| {
                subset(
                    Required,
                    &required.iter().map(|c| c.0.clone()).collect::<Vec<_>>(),
                    seen,
                )
            })
        }),
        stated(DefaultCredentials, &d.credentials, |required| {
            if required.is_empty() {
                return FieldResult::new(DefaultCredentials, Status::Checked);
            }
            measured(DefaultCredentials, &m.credentials, |seen| {
                subset(DefaultCredentials, required, seen)
            })
        }),
    ];
    // A difference on another service must not hide an incomplete service read.
    if let Stated::Specified(services) = &d.services
        && let Measured::Value(facts) = &m.services
        && services
            .iter()
            .any(|s| facts.iter().filter(|f| f.service == *s).count() != 1)
    {
        results[3].status = Status::Unavailable;
    }
    results
}
fn fixed(field: FieldId, value: &Measured<bool>) -> FieldResult {
    measured(field, value, |pass| {
        let mut result = FieldResult::new(field, Status::Checked);
        if !pass {
            result.difference(format!("Fixed lockdown fixture check: {field:?}"), None);
        }
        result
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultSet {
    pub fields: Vec<FieldResult>,
    pub findings: Vec<Finding>,
    pub notes: Vec<Note>,
    pub complete: bool,
    pub delivered: bool,
    pub placement_eligible: bool,
    pub findings_unknown: bool,
}
/// Shared aggregation for production and comparison. Unknown restored findings clear only
/// with a complete re-check. An incomplete check can add findings, never erase them.
pub fn aggregate(fields: Vec<FieldResult>, standing: &[Finding], unknown: bool) -> ResultSet {
    let complete = FieldId::DECLARATION
        .iter()
        .all(|f| fields.iter().filter(|r| r.field == *f).count() == 1)
        && fields
            .iter()
            .all(|r| matches!(r.status, Status::Checked | Status::Finding));
    let mut findings = if complete { vec![] } else { standing.to_vec() };
    for finding in fields.iter().flat_map(|r| &r.findings) {
        if !findings.contains(finding) {
            findings.push(finding.clone());
        }
    }
    let notes = fields.iter().flat_map(|r| r.notes.clone()).collect();
    let findings_unknown = unknown && !complete;
    let delivered = complete && findings.is_empty() && !findings_unknown;
    let placement_eligible = complete
        && findings
            .iter()
            .all(|f| f.class() == FindingClass::Lifecycle);
    ResultSet {
        fields,
        findings,
        notes,
        complete,
        delivered,
        placement_eligible,
        findings_unknown,
    }
}
pub fn evaluate(
    d: &Declaration,
    class: MachineClass,
    measurements: &Measurements,
    standing: &[Finding],
    unknown: bool,
) -> ResultSet {
    let mut results = fields(&Intended::from(d), class, measurements, standing);
    results.push(fixed(
        FieldId::FixedDefaultCredentials,
        &measurements.fixed_default_credentials,
    ));
    results.push(fixed(FieldId::SshdPosture, &measurements.sshd_posture));
    aggregate(results, standing, unknown)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod comparison;
#[cfg(test)]
pub(crate) mod tests;
