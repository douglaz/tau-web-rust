//! Intended machine requirements, never observations or model-authored measuring procedures.
use crate::dispatch::MachineClass;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Unspecified {
    #[serde(rename = "unspecified")]
    Unspecified,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Field<T> {
    Value(T),
    Unspecified(Unspecified),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum From {
    Any,
    Peers,
    None,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inbound {
    pub proto: Protocol,
    pub port: u16,
    pub from: From,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outbound {
    pub proto: Protocol,
    pub host: String,
    pub port: u16,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listeners {
    pub inbound: Field<Vec<Inbound>>,
    pub outbound: Field<Vec<Outbound>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Scope {
    System,
    User { account: String },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lifecycle {
    RunningAtDelivery,
    EnabledSurvivesReboot,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub name: String,
    pub scope: Scope,
    pub lifecycle: Lifecycle,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterialKind {
    Public,
    WatchOnly,
    PrivateNonSpendable,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Material {
    pub kind: MaterialKind,
    pub r#where: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyMaterial {
    pub spendable: Field<bool>,
    pub permitted: Field<Vec<Material>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoneCredentials {
    #[serde(rename = "none")]
    None,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Credentials {
    None(NoneCredentials),
    Changed(Vec<String>),
}

// No signed check library exists at this pin. Value retains rejected entries for a named
// semantic refusal; validate never admits a nonempty list, regardless of provenance claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    pub version: u32,
    pub listeners: Listeners,
    pub services: Field<Vec<Service>>,
    pub key_material: KeyMaterial,
    pub drift_checks: Field<Vec<Value>>,
    pub required: Field<Vec<Value>>,
    pub default_credentials: Field<Credentials>,
}
impl Declaration {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let declaration: Self =
            serde_json::from_value(value.clone()).map_err(|_| "declaration schema")?;
        // Reject positional containers; every table and entry is a JSON object.
        if serde_json::to_value(&declaration).expect("declaration serializes") != *value {
            return Err("declaration object shape".into());
        }
        declaration.validate(MachineClass::SinglePurpose)?;
        Ok(declaration)
    }
    pub fn validate(&self, class: MachineClass) -> Result<(), String> {
        if self.version != 2 {
            return Err("declaration version".into());
        }
        if let Field::Value(entries) = &self.listeners.inbound
            && entries.iter().any(|e| e.port == 0)
        {
            return Err("inbound port".into());
        }
        if let Field::Value(entries) = &self.listeners.outbound
            && entries.iter().any(|e| e.port == 0 || !host(&e.host))
        {
            return Err("outbound host or port".into());
        }
        if let Field::Value(entries) = &self.services {
            for e in entries {
                if !service_name(&e.name) {
                    return Err("service name".into());
                }
                if let Scope::User { account } = &e.scope
                    && !user_account(account)
                {
                    return Err("service account".into());
                }
            }
        }
        if let Field::Value(entries) = &self.key_material.permitted
            && entries.iter().any(|e| {
                !e.r#where.starts_with('/')
                    || !e
                        .r#where
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"/._-".contains(&c))
            })
        {
            return Err("tenant material path".into());
        }
        if class == MachineClass::MultiTenant
            && (self.key_material.spendable != Field::Value(false)
                || matches!(&self.key_material.permitted, Field::Value(es) if es.iter().any(|e| e.kind == MaterialKind::PrivateNonSpendable)))
        {
            return Err("multi-tenant material".into());
        }
        for entries in [&self.required, &self.drift_checks] {
            if matches!(entries, Field::Value(es) if !es.is_empty()) {
                return Err("no signed bundle check entries".into());
            }
        }
        if let Field::Value(Credentials::Changed(entries)) = &self.default_credentials
            && entries.iter().any(|e| {
                e.is_empty()
                    || !e
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
            })
        {
            return Err("default credential identifier".into());
        }
        Ok(())
    }

    /// Ad-hoc proposals add to the signed minimum; schema emptiness/unspecified alone
    /// cannot assert that its concrete inbound permission has been retained.
    pub fn validate_ad_hoc_minimum(&self) -> Result<(), String> {
        let Field::Value(baseline) = ad_hoc_minimum().listeners.inbound else {
            unreachable!("pinned minimum has concrete inbound listeners");
        };
        if !matches!(&self.listeners.inbound, Field::Value(entries)
            if baseline.iter().all(|entry| entries.contains(entry)))
        {
            return Err("ad-hoc declaration must preserve signed inbound minimum".into());
        }
        Ok(())
    }
}
pub fn service_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 247
        && (s.as_bytes()[0].is_ascii_alphanumeric() || s.starts_with('_'))
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_:.-".contains(&b))
        && ![
            "service",
            "socket",
            "timer",
            "target",
            "path",
            "mount",
            "automount",
            "swap",
            "slice",
            "scope",
            "device",
        ]
        .iter()
        .any(|suffix| s.ends_with(&format!(".{suffix}")))
}
pub fn user_account(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && (s.as_bytes()[0].is_ascii_lowercase() || s.starts_with('_'))
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}
fn host(s: &str) -> bool {
    if s == "any" {
        return true;
    }
    if let Some((ip, prefix)) = s.split_once('/') {
        return ip.parse::<std::net::IpAddr>().is_ok_and(|ip| {
            prefix
                .parse::<u8>()
                .is_ok_and(|n| n <= if ip.is_ipv4() { 32 } else { 128 })
        });
    }
    s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.as_bytes()[0].is_ascii_alphanumeric()
                && l.as_bytes()[l.len() - 1].is_ascii_alphanumeric()
                && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}

/// Compile the complete normative ad-hoc minimum from the pinned source, not a runtime fetch
/// or an implicit schema default. The profile itself links this exact companion.
pub fn ad_hoc_minimum() -> Declaration {
    let source = include_str!("../spec/docs/design/delivery-declaration-v1.md");
    let section = source
        .split("## ad-hoc, v2 (complete)")
        .nth(1)
        .expect("pinned minimum");
    let json = section
        .split("```json\n")
        .nth(1)
        .expect("minimum JSON")
        .split("```")
        .next()
        .expect("minimum end");
    Declaration::parse(&serde_json::from_str(json).expect("minimum document"))
        .expect("valid pinned minimum")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Proposal {
    Declaration {
        machine: String,
        declaration: Declaration,
    },
    TightenClass {
        machine: String,
        class: MachineClass,
    },
}
impl Proposal {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let proposal: Self =
            serde_json::from_value(value.clone()).map_err(|_| "proposal schema")?;
        if serde_json::to_value(&proposal).expect("proposal serializes") != *value {
            return Err("proposal object shape".into());
        }
        if let Self::Declaration { declaration, .. } = &proposal {
            declaration.validate(MachineClass::SinglePurpose)?;
        }
        if matches!(
            proposal,
            Self::TightenClass {
                class: MachineClass::SinglePurpose,
                ..
            }
        ) {
            return Err("class tightening only".into());
        }
        Ok(proposal)
    }
    pub fn machine(&self) -> &str {
        match self {
            Self::Declaration { machine, .. } | Self::TightenClass { machine, .. } => machine,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecord {
    pub session: String,
    pub candidate: u64,
    pub access: crate::dispatch::Access,
    pub proposal: Proposal,
}
