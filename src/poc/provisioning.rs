//! Bounded provider protocol. Responses are observations, never instructions.
use base64::{Engine, engine::general_purpose::STANDARD};
use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const ORIGIN: &str = "https://api.lnvps.net";
pub const REFUSED: &str = "Provider response refused; saved identities remain unchanged.";
pub const INCOMPLETE: &str = "Provider request incomplete or browser access unavailable; unlock, re-enter the same account and Refresh. Uncertain operations are never resent.";
pub const BODY_LIMIT: usize = 256 * 1024;

/// Separate from inference credential admission: a hexadecimal scalar is required here.
pub struct Account(Zeroizing<[u8; 32]>);
impl Account {
    pub fn parse(input: &[u8]) -> Result<Self, String> {
        if input.len() != 64 || !input.iter().all(u8::is_ascii_hexdigit) {
            return Err("Enter a valid 64-hex provider account private key.".into());
        }
        let mut bytes = Zeroizing::new([0; 32]);
        hex::decode_to_slice(input, bytes.as_mut()).map_err(|_| REFUSED)?;
        SigningKey::from_bytes(bytes.as_ref()).map_err(|_| "Invalid provider account scalar.")?;
        Ok(Self(bytes))
    }
    pub fn public(&self) -> String {
        hex::encode(
            SigningKey::from_bytes(self.0.as_ref())
                .expect("validated scalar")
                .verifying_key()
                .to_bytes(),
        )
    }
    pub(crate) fn filter(&self, input: &[u8]) -> crate::poc::inference::EchoFilter {
        let lower = Zeroizing::new(hex::encode(*self.0));
        let upper = Zeroizing::new(lower.to_uppercase());
        crate::poc::inference::EchoFilter::new(&[
            input,
            self.0.as_ref(),
            lower.as_bytes(),
            upper.as_bytes(),
        ])
    }
    /// A random nonce changes the event id even for repeated reads in the same second.
    pub fn authorization(
        &self,
        url: &str,
        method: &str,
        body: Option<&[u8]>,
        now: u64,
        nonce: &[u8; 32],
    ) -> Result<Zeroizing<String>, String> {
        let key = SigningKey::from_bytes(self.0.as_ref()).map_err(|_| REFUSED)?;
        let public = self.public();
        let mut tags = json!([
            ["u", url],
            ["method", method],
            ["nonce", hex::encode(nonce)]
        ]);
        if let Some(body) = body {
            tags.as_array_mut()
                .expect("tags")
                .push(json!(["payload", hex::encode(Sha256::digest(body))]));
        }
        let id = crate::relay_auth::event_id(&public, now, 27235, &tags, "");
        let signature = key.sign_raw(&id, nonce).map_err(|_| REFUSED)?;
        let event = Zeroizing::new(json!({"id":hex::encode(id),"pubkey":public,"created_at":now,"kind":27235,"tags":tags,"content":"","sig":hex::encode(signature.to_bytes())}).to_string());
        Ok(Zeroizing::new(format!(
            "Nostr {}",
            STANDARD.encode(event.as_bytes())
        )))
    }
}

/// Protect request material in both its transmitted and decoded representations.
pub(crate) fn request_filter(auth: &str) -> Result<crate::poc::inference::EchoFilter, String> {
    let event = Zeroizing::new(
        STANDARD
            .decode(auth.strip_prefix("Nostr ").ok_or(REFUSED)?)
            .map_err(|_| REFUSED)?,
    );
    let signed: Value = serde_json::from_slice(&event).map_err(|_| REFUSED)?;
    let signature = signed["sig"]
        .as_str()
        .filter(|s| s.len() == 128)
        .ok_or(REFUSED)?;
    let mut raw = Zeroizing::new([0u8; 64]);
    hex::decode_to_slice(signature, raw.as_mut()).map_err(|_| REFUSED)?;
    Ok(crate::poc::inference::EchoFilter::new(&[
        auth.as_bytes(),
        &event,
        signature.as_bytes(),
        raw.as_ref(),
    ]))
}

#[allow(async_fn_in_trait)]
pub(crate) trait Api {
    /// Prepare exact request protection before any bytes can leave the browser.
    fn prepare(
        &mut self,
        _method: &str,
        _path: &str,
        _body: Option<&Value>,
    ) -> Result<Option<crate::poc::inference::EchoFingerprints>, String> {
        Ok(None)
    }
    /// One exchange; no retries. All successful data must pass store credential protection.
    async fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, String>;
    fn account(&self) -> String;
    fn now(&self) -> u64;
    fn current(&self) -> Result<(), String>;
    fn take_filter(&mut self) -> Option<crate::poc::inference::EchoFilter> {
        None
    }
}

pub(crate) fn number(v: &Value, name: &str) -> Result<u64, String> {
    v[name]
        .as_u64()
        .filter(|n| *n <= 9_007_199_254_740_991)
        .ok_or_else(|| REFUSED.into())
}
pub(crate) fn id(v: &Value) -> Result<u64, String> {
    number(v, "id").and_then(|id| if id > 0 { Ok(id) } else { Err(REFUSED.into()) })
}
pub(crate) fn text<'a>(v: &'a Value, name: &str, max: usize) -> Result<&'a str, String> {
    v[name]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control))
        .ok_or_else(|| REFUSED.into())
}
pub(crate) fn array(v: &Value) -> Result<&Vec<Value>, String> {
    v.as_array()
        .filter(|a| a.len() <= 128)
        .ok_or_else(|| REFUSED.into())
}
pub(crate) fn unique_ids(v: &Value) -> Result<Vec<u64>, String> {
    let ids = array(v)?.iter().map(id).collect::<Result<Vec<_>, _>>()?;
    if ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len() {
        return Err(REFUSED.into());
    }
    Ok(ids)
}

pub(crate) fn validate_vm(vm: &Value) -> Result<(), String> {
    id(vm)?;
    timestamp(text(vm, "created", 40)?)?;
    id(&vm["image"])?;
    id(&vm["template"])?;
    id(&vm["ssh_key"])?;
    resources(&vm["template"], "disk_size")?;
    transfer_allowance(&vm["template"])?;
    region(&vm["template"]["region"])?;
    let cost = &vm["template"]["cost_plan"];
    number(cost, "amount")?;
    number(cost, "interval_amount")?;
    text(cost, "currency", 3)?;
    text(cost, "interval_type", 5)?;
    array(&vm["ip_assignments"])?;
    array(&vm["host_ssh_keys"])?;
    if !vm["status"].is_object() {
        return Err(REFUSED.into());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Charge {
    pub currency: String,
    pub amount: u64,
    pub interval_amount: u64,
    pub interval_type: String,
}
impl Charge {
    pub fn parse(v: &Value) -> Result<Self, String> {
        let charge = Self {
            currency: text(v, "currency", 3)?.into(),
            amount: number(v, "amount")?,
            interval_amount: number(v, "interval_amount")?,
            interval_type: text(v, "interval_type", 5)?.into(),
        };
        if !matches!(charge.currency.as_str(), "BTC" | "EUR" | "USD")
            || charge.amount == 0
            || !(1..=12).contains(&charge.interval_amount)
            || !matches!(charge.interval_type.as_str(), "day" | "month" | "year")
        {
            return Err("Hourly credit plans or unknown charge terms are unsupported.".into());
        }
        Ok(charge)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub offer: Value,
    pub image: Value,
    pub resources: Option<Value>,
    pub charge: Charge,
}
fn region(v: &Value) -> Result<(), String> {
    id(v)?;
    text(v, "name", 128)?;
    number(v, "company_id")?;
    Ok(())
}
fn resources(v: &Value, disk: &str) -> Result<(), String> {
    if !(1..=256).contains(&number(v, "cpu")?)
        || !(128 * 1024 * 1024..=16 * 1024u64.pow(4)).contains(&number(v, "memory")?)
        || !(1024u64.pow(3)..=1024u64.pow(5)).contains(&number(v, disk)?)
        || !matches!(text(v, "disk_type", 3)?, "hdd" | "ssd")
        || !matches!(text(v, "disk_interface", 4)?, "sata" | "scsi" | "pcie")
    {
        return Err(REFUSED.into());
    }
    Ok(())
}

/// Only documented, bounded catalogue fields may reach a page or an approval candidate.
pub(crate) fn catalogue_public(
    mut offers: Value,
    mut images: Value,
) -> Result<(Value, Value), String> {
    fn keep(value: &mut Value, names: &[&str]) -> Result<(), String> {
        value
            .as_object_mut()
            .ok_or(REFUSED)?
            .retain(|name, _| names.contains(&name.as_str()));
        Ok(())
    }
    fn bounded(value: &Value, depth: usize) -> Result<(), String> {
        if depth > 12 {
            return Err(REFUSED.into());
        }
        match value {
            Value::String(s) if s.len() > 8192 || s.chars().any(char::is_control) => {
                Err(REFUSED.into())
            }
            Value::Array(a) => {
                if a.len() > 128 {
                    return Err(REFUSED.into());
                }
                for v in a {
                    bounded(v, depth + 1)?;
                }
                Ok(())
            }
            Value::Object(o) => {
                if o.len() > 64 || o.keys().any(|k| k.len() > 64) {
                    return Err(REFUSED.into());
                }
                for v in o.values() {
                    bounded(v, depth + 1)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    keep(&mut offers, &["templates", "custom_template"])?;
    for (field, is_custom) in [("templates", false), ("custom_template", true)] {
        if field == "custom_template" && offers.get(field).is_none() {
            continue;
        }
        unique_ids(&offers[field])?;
        for offer in offers[field].as_array_mut().ok_or(REFUSED)? {
            keep(
                offer,
                &[
                    "id",
                    "name",
                    "created",
                    "expires",
                    "cpu",
                    "cpu_mfg",
                    "cpu_arch",
                    "cpu_features",
                    "memory",
                    "disk_size",
                    "disk_type",
                    "disk_interface",
                    "cost_plan",
                    "region",
                    "limits",
                    "transfer_gb",
                    "min_cpu",
                    "max_cpu",
                    "min_memory",
                    "max_memory",
                    "disks",
                    "interval_amount",
                    "interval_type",
                    "transfer",
                    "network",
                ],
            )?;
            id(offer)?;
            text(offer, "name", 128)?;
            keep(
                &mut offer["region"],
                &["id", "name", "country_code", "company_id"],
            )?;
            region(&offer["region"])?;
            if let Some(country) = offer["region"].get("country_code").filter(|v| !v.is_null())
                && !country
                    .as_str()
                    .is_some_and(|s| s.len() == 2 && s.bytes().all(|b| b.is_ascii_alphabetic()))
            {
                return Err(REFUSED.into());
            }
            normalize_cpu(offer)?;
            transfer_allowance(offer)?;
            if is_custom {
                for (min, max) in [("min_cpu", "max_cpu"), ("min_memory", "max_memory")] {
                    if number(offer, min)? == 0 || number(offer, min)? > number(offer, max)? {
                        return Err(REFUSED.into());
                    }
                }
                if array(&offer["disks"])?.is_empty() {
                    return Err(REFUSED.into());
                }
                for disk in offer["disks"].as_array_mut().ok_or(REFUSED)? {
                    keep(
                        disk,
                        &["min_disk", "max_disk", "disk_type", "disk_interface"],
                    )?;
                    if number(disk, "min_disk")? == 0
                        || number(disk, "min_disk")? > number(disk, "max_disk")?
                        || !matches!(text(disk, "disk_type", 3)?, "ssd" | "hdd")
                        || !matches!(text(disk, "disk_interface", 4)?, "sata" | "scsi" | "pcie")
                    {
                        return Err(REFUSED.into());
                    }
                }
                for field in ["transfer", "network"] {
                    if let Some(range) = offer.get_mut(field) {
                        keep(range, &["min", "max", "default"])?;
                        if number(range, "min")? > number(range, "default")?
                            || number(range, "default")? > number(range, "max")?
                        {
                            return Err(REFUSED.into());
                        }
                    }
                }
            } else {
                resources(offer, "disk_size")?;
                timestamp(text(offer, "created", 40)?)?;
                keep(
                    &mut offer["cost_plan"],
                    &[
                        "id",
                        "name",
                        "currency",
                        "amount",
                        "interval_amount",
                        "interval_type",
                    ],
                )?;
                id(&offer["cost_plan"])?;
                text(&offer["cost_plan"], "name", 128)?;
            }
            let mut terms = if is_custom {
                json!({"currency":"BTC","amount":1,"interval_amount":offer["interval_amount"],"interval_type":offer["interval_type"]})
            } else {
                offer["cost_plan"].clone()
            };
            if terms["interval_type"] == "hour" {
                terms["interval_type"] = "day".into();
            }
            Charge::parse(&terms)?;
            if !offer["limits"].is_object() {
                return Err(REFUSED.into());
            }
            if let Some(limits) = offer.get_mut("limits") {
                keep(
                    limits,
                    &[
                        "disk_iops_read",
                        "disk_iops_write",
                        "disk_mbps_read",
                        "disk_mbps_write",
                        "network_mbps",
                        "cpu_limit",
                        "firewall_rule_limit",
                    ],
                )?;
                if limits
                    .as_object()
                    .ok_or(REFUSED)?
                    .values()
                    .any(|v| v.as_f64().is_none_or(|n| !n.is_finite() || n < 0.0))
                {
                    return Err(REFUSED.into());
                }
            }
            bounded(offer, 0)?;
        }
    }
    unique_ids(&images)?;
    for image in images.as_array_mut().ok_or(REFUSED)? {
        keep(
            image,
            &[
                "id",
                "distribution",
                "flavour",
                "version",
                "release_date",
                "cpu_arch",
                "default_username",
                "encrypted",
                "popularity",
            ],
        )?;
        for field in ["distribution", "flavour", "version"] {
            text(image, field, 128)?;
        }
        for field in ["cpu_arch", "default_username"] {
            if image.get(field).is_some_and(|v| !v.is_null()) {
                text(image, field, 64)?;
            }
        }
        timestamp(text(image, "release_date", 40)?)?;
        if !image["encrypted"].is_boolean()
            || image["popularity"]
                .as_f64()
                .is_none_or(|n| !(0.0..=1.0).contains(&n))
        {
            return Err(REFUSED.into());
        }
        bounded(image, 0)?;
    }
    Ok((offers, images))
}
pub fn supported_image(image: &Value) -> bool {
    id(image).is_ok()
        && image["distribution"] == "archlinux"
        && image["encrypted"] == false
        && image.get("default_username").is_none_or(|v| v == "arch")
        && text(image, "flavour", 128).is_ok()
        && text(image, "version", 128).is_ok()
}
fn optional_cpu(value: &Value, field: &str) -> Result<Option<String>, String> {
    if value.get(field).is_none_or(Value::is_null) {
        return Ok(None);
    }
    Ok(Some(text(value, field, 32)?.to_ascii_lowercase()))
}
fn cpu_features(value: &Value) -> Result<std::collections::BTreeSet<String>, String> {
    if value.get("cpu_features").is_none_or(Value::is_null) {
        return Ok(Default::default());
    }
    array(&value["cpu_features"])?
        .iter()
        .map(|feature| {
            feature
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control))
                .map(str::to_ascii_lowercase)
                .ok_or_else(|| REFUSED.to_string())
        })
        .collect()
}
fn normalize_cpu(value: &mut Value) -> Result<(), String> {
    for field in ["cpu_arch", "cpu_mfg"] {
        match optional_cpu(value, field)? {
            Some(v) => value[field] = v.into(),
            None => {
                value.as_object_mut().ok_or(REFUSED)?.remove(field);
            }
        }
    }
    let features = cpu_features(value)?;
    if features.is_empty() {
        value.as_object_mut().ok_or(REFUSED)?.remove("cpu_features");
    } else {
        value["cpu_features"] = json!(features);
    }
    Ok(())
}
fn same_limits(approved: &Value, observed: &Value) -> bool {
    let (Some(approved), Some(observed)) = (approved.as_object(), observed.as_object()) else {
        return false;
    };
    approved.len() == observed.len()
        && approved.iter().all(|(key, expected)| {
            expected.as_f64().is_some_and(|number| {
                number.is_finite()
                    && number >= 0.0
                    && observed.get(key).and_then(Value::as_f64) == Some(number)
            })
        })
}
fn cpu_matches(offer: &Value, image: &Value, vm: &Value) -> Result<bool, String> {
    let template = &vm["template"];
    for field in ["cpu_arch", "cpu_mfg"] {
        let approved = optional_cpu(offer, field)?;
        let observed = optional_cpu(template, field)?;
        if approved.is_some() && approved != observed {
            return Ok(false);
        }
    }
    let approved_features = cpu_features(offer)?;
    if !approved_features.is_subset(&cpu_features(template)?) {
        return Ok(false);
    }
    let image_arch = optional_cpu(image, "cpu_arch")?;
    let template_arch = optional_cpu(template, "cpu_arch")?;
    let host_arch = optional_cpu(vm, "cpu_arch")?;
    if let Some(expected) = image_arch
        && (template_arch.as_ref().is_some_and(|a| a != &expected)
            || host_arch.as_ref().is_some_and(|a| a != &expected)
            || template_arch.is_none() && host_arch.is_none())
    {
        return Ok(false);
    }
    if template_arch.is_some() && host_arch.is_some() && template_arch != host_arch {
        return Ok(false);
    }
    Ok(true)
}

/// Image statistics do not identify the installed image. Missing optional fields and null
/// both mean unspecified; every stable identity/configuration field must otherwise agree.
fn same_image(left: &Value, right: &Value) -> bool {
    [
        "id",
        "distribution",
        "flavour",
        "version",
        "release_date",
        "cpu_arch",
        "default_username",
        "encrypted",
    ]
    .iter()
    .all(|field| left[*field] == right[*field])
}
impl Selection {
    pub fn same_terms(&self, other: &Self) -> bool {
        self.offer == other.offer
            && same_image(&self.image, &other.image)
            && self.resources == other.resources
            && self.charge == other.charge
    }

    pub fn validate(&self) -> Result<(), String> {
        transfer_allowance(&self.offer)?;
        if !self.offer["limits"].is_object() {
            return Err(REFUSED.into());
        }
        id(&self.offer)?;
        region(&self.offer["region"])?;
        text(&self.offer, "name", 128)?;
        if !supported_image(&self.image) {
            return Err(
                "Choose a supported unencrypted Arch image; console unlock is unsupported.".into(),
            );
        }
        if let (Some(a), Some(b)) = (
            self.offer["cpu_arch"].as_str(),
            self.image["cpu_arch"].as_str(),
        ) && a != b
        {
            return Err(REFUSED.into());
        }
        let charge = Charge::parse(&serde_json::to_value(&self.charge).map_err(|_| REFUSED)?)?;
        if let Some(r) = &self.resources {
            resources(r, "disk")?;
            if !r.as_object().is_some_and(|o| {
                o.keys().all(|k| {
                    [
                        "pricing_id",
                        "cpu",
                        "memory",
                        "disk",
                        "disk_type",
                        "disk_interface",
                        "ip4_count",
                        "ip6_count",
                        "transfer_gb",
                        "network_mbps",
                    ]
                    .contains(&k.as_str())
                })
            }) || number(r, "pricing_id")? != id(&self.offer)?
            {
                return Err(REFUSED.into());
            }
            for (field, min, max) in [
                ("cpu", "min_cpu", "max_cpu"),
                ("memory", "min_memory", "max_memory"),
            ] {
                let n = number(r, field)?;
                if n < number(&self.offer, min)? || n > number(&self.offer, max)? {
                    return Err(REFUSED.into());
                }
            }
            if !array(&self.offer["disks"])?.iter().any(|d| {
                d["disk_type"] == r["disk_type"]
                    && d["disk_interface"] == r["disk_interface"]
                    && number(d, "min_disk")
                        .is_ok_and(|min| number(r, "disk").is_ok_and(|n| n >= min))
                    && number(d, "max_disk")
                        .is_ok_and(|max| number(r, "disk").is_ok_and(|n| n <= max))
            }) {
                return Err(REFUSED.into());
            }
            if number(r, "ip4_count")? != 1 || number(r, "ip6_count")? > 1 {
                return Err(REFUSED.into());
            }
            for (field, range) in [("transfer_gb", "transfer"), ("network_mbps", "network")] {
                if self.offer.get(range).is_some() {
                    let n = number(r, field)?;
                    if n < number(&self.offer[range], "min")?
                        || n > number(&self.offer[range], "max")?
                    {
                        return Err(REFUSED.into());
                    }
                } else if r.get(field).is_some() {
                    return Err(REFUSED.into());
                }
            }
            if charge.interval_amount != number(&self.offer, "interval_amount")?
                || charge.interval_type != text(&self.offer, "interval_type", 5)?
            {
                return Err(REFUSED.into());
            }
        } else {
            resources(&self.offer, "disk_size")?;
            if charge != Charge::parse(&self.offer["cost_plan"])? {
                return Err(REFUSED.into());
            }
        }
        Ok(())
    }
    pub fn create(&self, key: u64) -> (&'static str, Value) {
        if let Some(resources) = &self.resources {
            let mut body = resources.clone();
            body["image_id"] = self.image["id"].clone();
            body["ssh_key_id"] = key.into();
            ("/api/v1/vm/custom-template", body)
        } else {
            (
                "/api/v1/vm",
                json!({"template_id":self.offer["id"],"image_id":self.image["id"],"ssh_key_id":key}),
            )
        }
    }
    /// Sufficient association requires creation, key, image, region, price and every resource.
    pub fn matches(&self, vm: &Value, key: u64, not_before: u64) -> bool {
        let check = || -> Result<bool, String> {
            validate_vm(vm)?;
            if !self.offer["limits"].is_object() {
                return Ok(false);
            }
            let created = timestamp(text(vm, "created", 40)?)?;
            // Authentication permits 60s clock skew; journal/dispatch work shares the 60s action bound.
            if created.saturating_add(60) < not_before
                || created > not_before.saturating_add(120)
                || !cpu_matches(&self.offer, &self.image, vm)?
                || id(&vm["ssh_key"])? != key
                || !same_image(&vm["image"], &self.image)
                || vm["template"]["region"] != self.offer["region"]
                || Charge::parse(&vm["template"]["cost_plan"])? != self.charge
            {
                return Ok(false);
            }
            let template = &vm["template"];
            resources(template, "disk_size")?;
            let expected = self.resources.as_ref().unwrap_or(&self.offer);
            // Omission is an approved unmetered service, not permission to add a cap.
            if transfer_allowance(expected)? != transfer_allowance(template)? {
                return Ok(false);
            }
            if self.resources.is_none() {
                if id(template)? != id(&self.offer)? {
                    return Ok(false);
                }
                if let Some(limits) = self.offer.get("limits")
                    && !same_limits(limits, &template["limits"])
                {
                    return Ok(false);
                }
            }
            for field in ["cpu", "memory", "disk_type", "disk_interface"] {
                if template[field] != expected[field] {
                    return Ok(false);
                }
            }
            if template["disk_size"]
                != expected[if self.resources.is_some() {
                    "disk"
                } else {
                    "disk_size"
                }]
            {
                return Ok(false);
            }
            if let Some(r) = &self.resources {
                // Chosen network speed overrides only that inherited cap. Omitted
                // cap fields mean uncapped, so extra observed caps also conflict.
                let mut limits = self
                    .offer
                    .get("limits")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                if let Some(network) = r.get("network_mbps") {
                    limits["network_mbps"] = network.clone();
                }
                if !same_limits(&limits, &template["limits"]) {
                    return Ok(false);
                }
                if let Some(value) = r.get("network_mbps")
                    && template.pointer("/limits/network_mbps") != Some(value)
                {
                    return Ok(false);
                }
                // The published address counts must agree, including pending allocation.
                let ips = array(&vm["ip_assignments"])?;
                let v4 = ips
                    .iter()
                    .filter(|ip| ip["ip"].as_str().is_some_and(|s| s.contains('.')))
                    .count() as u64;
                let v6 = ips
                    .iter()
                    .filter(|ip| ip["ip"].as_str().is_some_and(|s| s.contains(':')))
                    .count() as u64;
                if v4 != number(r, "ip4_count")? || v6 != number(r, "ip6_count")? {
                    return Ok(false);
                }
            }
            Ok(true)
        };
        check().unwrap_or(false)
    }
}
fn transfer_allowance(value: &Value) -> Result<Option<u64>, String> {
    value
        .get("transfer_gb")
        .map(|_| number(value, "transfer_gb"))
        .transpose()
}

/// ISO-8601 UTC provider dates, optionally fractional. No locale or permissive date parser.
pub fn timestamp(text: &str) -> Result<u64, String> {
    let bytes = text.as_bytes();
    if bytes.len() < 20
        || bytes.len() > 30
        || &bytes[4..5] != b"-"
        || &bytes[7..8] != b"-"
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || *bytes.last().ok_or(REFUSED)? != b'Z'
    {
        return Err(REFUSED.into());
    }
    if bytes.len() > 20
        && (bytes[19] != b'.' || !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return Err(REFUSED.into());
    }
    let n = |start: usize, end: usize| {
        std::str::from_utf8(&bytes[start..end])
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| REFUSED.to_string())
    };
    let (year, month, day, hour, minute, second) = (
        n(0, 4)?,
        n(5, 7)?,
        n(8, 10)?,
        n(11, 13)?,
        n(14, 16)?,
        n(17, 19)?,
    );
    let leap = |y: u64| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    if !(1970..=2200).contains(&year)
        || !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(REFUSED.into());
    }
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > months[month as usize - 1] {
        return Err(REFUSED.into());
    }
    let days = (1970..year)
        .map(|y| if leap(y) { 366 } else { 365 })
        .sum::<u64>()
        + months[..month as usize - 1].iter().sum::<u64>()
        + day
        - 1;
    Ok(days * 86400 + hour * 3600 + minute * 60 + second)
}

pub fn payment_id(payment: &Value) -> Result<&str, String> {
    text(payment, "id", 128).and_then(|s| {
        if s.len() >= 2 && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(s)
        } else {
            Err(REFUSED.into())
        }
    })
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingTerms {
    pub amount: u64,
    pub tax: u64,
    pub processing_fee: u64,
    pub currency: String,
    pub time: u64,
}
impl BillingTerms {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let terms = Self {
            amount: number(value, "amount")?,
            tax: number(value, "tax")?,
            processing_fee: number(value, "processing_fee")?,
            currency: text(value, "currency", 3)?.into(),
            time: number(value, "time")?,
        };
        if terms.amount == 0 || terms.time == 0 || terms.currency != "BTC" {
            return Err(REFUSED.into());
        }
        Ok(terms)
    }
    pub fn validate(&self) -> Result<(), String> {
        Self::parse(&serde_json::to_value(self).map_err(|_| REFUSED)?).map(|_| ())
    }
}
pub fn suitable_payment(payment: &Value, vm: u64, expected: &BillingTerms, created: u64) -> bool {
    let check = || -> Result<bool, String> {
        payment_id(payment)?;
        let invoice = text(&payment["data"], "lightning", 8192)?;
        let made = timestamp(text(payment, "created", 40)?)?;
        let expires = timestamp(text(payment, "expires", 40)?)?;
        expected.validate()?;
        Ok(number(payment, "vm_id")? == vm
            && payment["is_upgrade"] == false
            && payment["is_paid"].is_boolean()
            && payment["currency"] == expected.currency
            && number(payment, "amount")? == expected.amount
            && number(payment, "time")? == expected.time
            && number(payment, "tax")? == expected.tax
            && number(payment, "processing_fee")? == expected.processing_fee
            && made >= created
            && expires > made
            && invoice.starts_with("lnbc")
            && invoice
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
    };
    check().unwrap_or(false)
}

/// Support Ed25519 first, which the existing SSH client also negotiates first.
pub fn published_pin(vm: &Value) -> Result<(Value, String), String> {
    let mut supported = Vec::new();
    for key in array(&vm["host_ssh_keys"])? {
        if key["key_type"] != "ssh-ed25519" {
            continue;
        }
        let blob = STANDARD
            .decode(text(key, "public_key", 256)?)
            .map_err(|_| REFUSED)?;
        if blob.len() != 51 || &blob[..19] != b"\0\0\0\x0bssh-ed25519\0\0\0\x20" {
            return Err(REFUSED.into());
        }
        let bytes: [u8; 32] = blob[19..].try_into().map_err(|_| REFUSED)?;
        let public = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| REFUSED)?;
        if public.is_weak() {
            return Err(REFUSED.into());
        }
        let fingerprint = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&blob))
        );
        if key["fingerprint_sha256"] != fingerprint {
            return Err(REFUSED.into());
        }
        supported.push((key.clone(), fingerprint));
    }
    supported.sort_by(|a, b| a.1.cmp(&b.1));
    supported.dedup();
    if supported.len() != 1 {
        return Err(
            "Waiting for an unambiguous supported published host key; Refresh later.".into(),
        );
    }
    Ok(supported.remove(0))
}
pub fn allocated_ipv4(vm: &Value) -> Result<String, String> {
    let mut found = std::collections::BTreeSet::new();
    for ip in array(&vm["ip_assignments"])? {
        let text = text(ip, "ip", 64)?;
        if text.contains(':') {
            continue;
        }
        let (address, prefix) = text.split_once('/').ok_or(REFUSED)?;
        if prefix.parse::<u8>().ok().is_none_or(|p| p > 32) {
            return Err(REFUSED.into());
        }
        let address = address.parse::<std::net::Ipv4Addr>().map_err(|_| REFUSED)?;
        if address.is_unspecified()
            || address.is_loopback()
            || address.is_multicast()
            || address.is_broadcast()
            || address.is_link_local()
        {
            return Err(REFUSED.into());
        }
        found.insert(address.to_string());
    }
    if found.len() != 1 {
        return Err("Waiting for one allocated IPv4 address.".into());
    }
    Ok(found.into_iter().next().expect("one"))
}

#[cfg(target_arch = "wasm32")]
pub(crate) mod browser;
#[cfg(test)]
pub(crate) mod tests;
