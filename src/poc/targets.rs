//! Immutable operator-entered access records and independently obtained host pins.
use crate::credential::HostKeyPin;
use crate::harness::PinSource;
use crate::jobs::Elevation;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde::{Deserialize, Serialize};

/// A machine as reached through the relay: `wss://<relay>/v1/tcp/<host>/<port>` (`WIR-1`,
/// paid-tcp-relay `844e834`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub machine: String,
    /// The relay's URL, `wss://…/`, which the AUTH's `relay` tag names.
    pub relay: String,
    pub profile: String,
    /// Resolve all access and elevation from the encrypted target record at every boundary.
    pub stored: bool,
    pub host: String,
    pub port: u16,
    pub user: String,
}

impl Target {
    /// This exact URL is passed to WebSocket connect after access resolution. Shared by
    /// command and collection, with no contact possible until pin and profile admission.
    pub fn contact_url(&self, pin: Option<&str>) -> Result<String, String> {
        let pin = pin.ok_or("stored target pin missing")?;
        TargetRecord {
            machine: self.machine.clone(),
            relay: self.relay.clone(),
            profile: self.profile.clone(),
            host: self.host.clone(),
            port: self.port,
            user: self.user.clone(),
            elevation: Elevation::None,
            pin: pin.into(),
        }
        .relay_url()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetRecord {
    pub machine: String,
    pub relay: String,
    pub profile: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub elevation: Elevation,
    pub pin: String,
}

fn token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

fn host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part.as_bytes()[0].is_ascii_alphanumeric()
                && part.as_bytes()[part.len() - 1].is_ascii_alphanumeric()
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// A deliberately narrow WSS URL grammar: DNS/IPv4 authority, optional numeric port and path.
/// It excludes user information, query, fragment, escapes and dot segments.
pub fn valid_relay(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("wss://") else {
        return false;
    };
    if value.len() > 2048 || !value.ends_with('/') {
        return false;
    }
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    let (name, port_ok) = match authority.split_once(':') {
        Some((name, port)) => (
            name,
            port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok_and(|p| p != 0),
        ),
        None => (authority, true),
    };
    host(name)
        && port_ok
        && path.split('/').all(|segment| {
            segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-./".contains(&b))
        })
}

impl TargetRecord {
    pub fn validate(&self) -> Result<(), String> {
        if !token(&self.machine, 64) {
            return Err("invalid machine name".into());
        }
        if !valid_relay(&self.relay) {
            return Err("invalid relay URL; use wss with a trailing slash".into());
        }
        if !token(&self.profile, 32) {
            return Err("invalid relay profile".into());
        }
        if !host(&self.host) {
            return Err("invalid target host; use a DNS name or IPv4 address".into());
        }
        if self.port == 0 {
            return Err("invalid target port".into());
        }
        if !token(&self.user, 64) {
            return Err("invalid target user".into());
        }
        let valid_pin = self.pin.strip_prefix("SHA256:").is_some_and(|encoded| {
            STANDARD_NO_PAD
                .decode(encoded)
                .is_ok_and(|bytes| bytes.len() == 32 && STANDARD_NO_PAD.encode(bytes) == encoded)
        });
        if !valid_pin {
            return Err("invalid host pin; use a canonical SHA256 fingerprint".into());
        }
        Ok(())
    }

    /// Admission occurs before the transport may contact a relay.
    pub fn relay_url(&self) -> Result<String, String> {
        self.validate()?;
        if self.profile != "v1" {
            return Err(format!("unsupported relay profile: {}", self.profile));
        }
        Ok(format!("{}v1/tcp/{}/{}", self.relay, self.host, self.port))
    }
}

/// A read-only snapshot of committed pins. There is no presented-key enrollment method.
#[cfg_attr(
    not(target_arch = "wasm32"),
    allow(
        dead_code,
        reason = "the stored transport pin source is used by the browser and host tests"
    )
)]
#[derive(Default)]
pub struct StoredPins(std::collections::BTreeMap<String, String>);
impl PinSource for StoredPins {
    fn pin(&self, machine: &str) -> Option<HostKeyPin> {
        self.0.get(machine).cloned().map(HostKeyPin)
    }
}
#[cfg_attr(
    not(target_arch = "wasm32"),
    allow(
        dead_code,
        reason = "the stored transport pin source is used by the browser and host tests"
    )
)]
impl StoredPins {
    pub fn from_record(record: &TargetRecord) -> Result<Self, String> {
        record.validate()?;
        Ok(Self([(record.machine.clone(), record.pin.clone())].into()))
    }
}

pub fn resolve<S: crate::store::Storage>(
    store: &crate::store::Store<S>,
    machine: &str,
) -> Result<(crate::harness::Target, StoredPins), String> {
    let record = store
        .poc_target(machine)
        .ok_or("machine has no stored target or pin")?;
    let pins = StoredPins::from_record(record)?;
    let target = Target {
        machine: record.machine.clone(),
        relay: record.relay.clone(),
        profile: record.profile.clone(),
        host: record.host.clone(),
        port: record.port,
        user: record.user.clone(),
        stored: true,
    };
    target.contact_url(pins.pin(machine).as_ref().map(|pin| pin.0.as_str()))?;
    Ok((target, pins))
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(crate) fn target() -> TargetRecord {
        TargetRecord {
            machine: "machine-a".into(),
            relay: "wss://relay.invalid/".into(),
            profile: "v1".into(),
            host: "192.0.2.1".into(),
            port: 22,
            user: "arch".into(),
            elevation: Elevation::None,
            pin: format!("SHA256:{}", STANDARD_NO_PAD.encode([7; 32])),
        }
    }
    #[test]
    fn poc_production_contact_url_preserves_v1_bytes_and_requires_a_pin() {
        for (relay, host, port, expected) in [
            (
                "wss://relay.invalid/",
                "192.0.2.1",
                22,
                "wss://relay.invalid/v1/tcp/192.0.2.1/22",
            ),
            (
                "wss://relay.invalid:8443/base/path/",
                "host-a.example",
                2222,
                "wss://relay.invalid:8443/base/path/v1/tcp/host-a.example/2222",
            ),
            (
                "wss://relay.invalid/tau/",
                "127.0.0.1",
                65535,
                "wss://relay.invalid/tau/v1/tcp/127.0.0.1/65535",
            ),
        ] {
            let record = target();
            let transport = Target {
                machine: record.machine,
                relay: relay.into(),
                profile: "v1".into(),
                host: host.into(),
                port,
                user: record.user,
                stored: true,
            };
            assert_eq!(transport.contact_url(Some(&record.pin)).unwrap(), expected);
            assert!(transport.contact_url(None).is_err());
        }
    }

    #[test]
    fn poc_target_validation_pin_source_and_profile_admission() {
        let record = target();
        assert_eq!(
            record.relay_url().unwrap(),
            "wss://relay.invalid/v1/tcp/192.0.2.1/22"
        );
        let pins = StoredPins::from_record(&record).unwrap();
        assert_eq!(pins.pin("machine-a").unwrap().0, record.pin);
        assert!(pins.pin("unknown").is_none());
        for bad in [
            "ws://relay.invalid/",
            "wss://user@relay.invalid/",
            "wss://relay.invalid/?x",
            "wss://relay.invalid/#x",
            "wss://relay.invalid/../",
            "wss://relay.invalid/%2f/",
            "wss://relay.invalid:0/",
            "wss://relay.invalid:65536/",
            "wss://relay.invalid\\evil/",
        ] {
            assert!(!valid_relay(bad), "{bad}");
        }
        for field in ["machine", "host", "user", "pin", "port"] {
            let mut bad = record.clone();
            match field {
                "machine" => bad.machine = "a;id".into(),
                "host" => bad.host = "a/22".into(),
                "user" => bad.user = "a\nid".into(),
                "pin" => bad.pin.push('='),
                _ => bad.port = 0,
            }
            assert!(bad.validate().is_err(), "{field}");
        }
        let mut unsupported = record.clone();
        unsupported.profile = "v2".into();
        assert!(unsupported.validate().is_ok());
        assert_eq!(
            unsupported.relay_url().unwrap_err(),
            "unsupported relay profile: v2"
        );
    }
}
