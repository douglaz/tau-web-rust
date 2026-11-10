//! Inference credit protocol and deliberately limited payment knowledge.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

pub const CAP: f64 = 0.25;
pub const LIFETIME: u64 = 86_400;
pub const POLL_SECONDS: u64 = 5;
pub const ACCOUNT_FAILED: &str = "Couldn't create the credit account. Try again.";
pub const INVOICE_FAILED: &str = "No invoice was received. Try again.";
pub const INVOICE_INVALID: &str = "The credit service sent an invoice this page can't use.";
pub const UNKNOWN: &str = "Payment status unknown.";
pub const MINT_FAILED: &str = "Couldn't create this session's inference key.";
pub const REFUSED: &str = "The credit service refused this request.";
pub const DISCLOSURE: &str = "Inference uses a key capped at 0.25 USD of your credit and valid 24 hours (requested limits, per key). A new key with the same limits is made after each Unlock or New key press, so a session can use more than 0.25 USD in total; your credit balance is the overall limit.";

/// A decoded secret clears even when a later field fails to decode.
pub(crate) struct SecretText(pub Zeroizing<String>);
impl Serialize for SecretText {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|s| Self(Zeroizing::new(s)))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountRecord {
    pub credit_id: SecretText,
    pub default_key: SecretText,
}
impl AccountRecord {
    pub fn validate(&self) -> Result<(), String> {
        for value in [&self.credit_id.0, &self.default_key.0] {
            super::inference::valid_key(value.as_bytes()).map_err(|_| ACCOUNT_FAILED)?;
        }
        if self.credit_id.0 == self.default_key.0 {
            return Err(ACCOUNT_FAILED.into());
        }
        Ok(())
    }
    pub fn from_response(status: u16, value: &Value) -> Result<Self, String> {
        if status != 201 || value["success"] != true {
            return Err(ACCOUNT_FAILED.into());
        }
        let record = Self {
            credit_id: SecretText(Zeroizing::new(
                value["credit_id"].as_str().ok_or(ACCOUNT_FAILED)?.into(),
            )),
            default_key: SecretText(Zeroizing::new(
                value["api_key"].as_str().ok_or(ACCOUNT_FAILED)?.into(),
            )),
        };
        record.validate()?;
        Ok(record)
    }
}

/// Service bodies and shape-validation copies have no unprotected drop path.
pub(crate) struct ClearedValue(pub Value);
impl<'de> Deserialize<'de> for ClearedValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Read;
        impl<'de> serde::de::Visitor<'de> for Read {
            type Value = ClearedValue;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("credit JSON")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(ClearedValue(Value::Null))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(ClearedValue(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(ClearedValue(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(ClearedValue(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| ClearedValue(Value::Number(n)))
                    .ok_or_else(|| E::custom("credit number refused"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(ClearedValue(v.into()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(ClearedValue(v.into()))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Self::Value, A::Error> {
                let mut result = ClearedValue(Value::Array(Vec::new()));
                while let Some(mut child) = a.next_element::<ClearedValue>()? {
                    result
                        .0
                        .as_array_mut()
                        .expect("array")
                        .push(std::mem::take(&mut child.0));
                }
                Ok(result)
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Self::Value, A::Error> {
                let mut result = ClearedValue(Value::Object(Default::default()));
                while let Some(mut key) = a.next_key::<SecretText>()? {
                    let mut child = a.next_value::<ClearedValue>()?;
                    let map = result.0.as_object_mut().expect("object");
                    if let Some(old) = map.get_mut(key.0.as_str()) {
                        drop(ClearedValue(std::mem::replace(
                            old,
                            std::mem::take(&mut child.0),
                        )));
                    } else {
                        map.insert(std::mem::take(&mut *key.0), std::mem::take(&mut child.0));
                    }
                }
                Ok(result)
            }
        }
        d.deserialize_any(Read)
    }
}
pub(crate) fn decode(bytes: &[u8]) -> Result<ClearedValue, String> {
    serde_json::from_slice(bytes).map_err(|_| REFUSED.to_string())
}

impl Drop for ClearedValue {
    fn drop(&mut self) {
        fn clear(value: &mut Value) {
            match value {
                Value::String(text) => text.zeroize(),
                Value::Array(values) => values.iter_mut().for_each(clear),
                Value::Object(values) => {
                    for (mut name, mut value) in std::mem::take(values) {
                        name.zeroize();
                        clear(&mut value);
                    }
                }
                _ => (),
            }
        }
        clear(&mut self.0);
    }
}

pub fn balance(value: &Value) -> Option<f64> {
    value["balance"]
        .as_f64()
        .filter(|n| n.is_finite() && *n >= 0.0 && *n <= 1e12)
}
pub fn display_balance(value: f64) -> String {
    format!(
        "Inference credit: {:.2} USD, as reported by the credit service",
        (value * 100.0).floor() / 100.0
    )
}
pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invoice {
    pub id: String,
    pub bolt11: String,
    pub amount_sat: u64,
    pub expires_at: u64,
    pub baseline: f64,
    pub last_status: String,
    pub outcome: Payment,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Payment {
    Pending,
    Abandoned,
    Paid,
    ExpiredUnpaid,
    Unknown,
    Seen,
}
impl Payment {
    pub fn message(self) -> &'static str {
        match self {
            Self::Abandoned => "Invoice marked abandoned.",
            Self::Pending => "Waiting for external payment.",
            Self::Paid => "Payment seen; inference credit read.",
            Self::ExpiredUnpaid => "This invoice expired unpaid, according to the credit service.",
            Self::Unknown => UNKNOWN,
            Self::Seen => "Payment seen; balance not read yet.",
        }
    }
}
impl Invoice {
    pub fn resolved(&self) -> bool {
        matches!(
            self.outcome,
            Payment::Paid | Payment::ExpiredUnpaid | Payment::Abandoned
        )
    }
    pub fn from_response(
        status: u16,
        value: &Value,
        requested: u64,
        baseline: f64,
    ) -> Result<Self, String> {
        let id = value["invoice_id"].as_str().ok_or(INVOICE_INVALID)?;
        let bolt11 = value["lightning_invoice"].as_str().ok_or(INVOICE_INVALID)?;
        let expires_at = value["expires_at"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or(INVOICE_INVALID)?;
        if status != 201
            || !identifier(id)
            || !(100..=5000).contains(&requested)
            || value["amount"].as_f64() != Some(requested as f64)
            || value["currency"] != "SATS"
            || !bolt11.starts_with("lnbc")
            || bolt11.len() <= 4
            || bolt11.len() > 8192
            || !bolt11
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            || !baseline.is_finite()
            || baseline < 0.0
        {
            return Err(INVOICE_INVALID.into());
        }
        Ok(Self {
            id: id.into(),
            bolt11: bolt11.into(),
            amount_sat: requested,
            expires_at,
            baseline,
            last_status: "New".into(),
            outcome: Payment::Pending,
        })
    }
    pub fn may_poll(&self, now: u64) -> bool {
        !matches!(
            self.outcome,
            Payment::Paid | Payment::ExpiredUnpaid | Payment::Abandoned
        ) && now <= self.expires_at.saturating_add(60)
    }
    pub fn observe(&self, status: Option<&Value>, fresh_balance: Option<f64>, now: u64) -> Payment {
        if self.resolved() {
            return self.outcome;
        }
        let fresh_balance = fresh_balance.filter(|n| n.is_finite() && (0.0..=1e12).contains(n));
        let Some(status) = status.filter(|s| s["invoice_id"] == self.id) else {
            return Payment::Unknown;
        };
        match status["status"].as_str() {
            Some("Settled") => {
                if fresh_balance.is_some() {
                    Payment::Paid
                } else {
                    Payment::Seen
                }
            }
            Some("New") if now < self.expires_at && fresh_balance.is_some() => Payment::Pending,
            Some("Expired") => {
                if let Some(current) = fresh_balance {
                    if current > self.baseline {
                        return Payment::Paid;
                    }
                    if status["amount_paid"].as_f64() == Some(0.0) {
                        return Payment::ExpiredUnpaid;
                    }
                }
                Payment::Unknown
            }
            _ => Payment::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mint {
    pub session: String,
    pub name: String,
    pub requested_cap: f64,
    pub requested_expiry: u64,
    pub issuer_id: Option<String>,
    pub returned_cap: Option<f64>,
    pub returned_expiry: Option<String>,
}
/// A 96-bit random name occupies exactly 25 characters, independently of session length.
pub fn mint_name() -> Result<String, String> {
    let mut bytes = [0u8; 12];
    getrandom::fill(&mut bytes).map_err(|_| MINT_FAILED)?;
    Ok(format!("k{}", hex::encode(bytes)))
}
pub(crate) fn expiry_matches(requested: u64, text: &str) -> bool {
    let Ok(seconds) = super::provisioning::timestamp(text) else {
        return false;
    };
    let fraction = if text.len() == 20 {
        0
    } else {
        let digits = &text[20..text.len() - 1];
        if digits.is_empty() || digits.len() > 9 {
            return false;
        }
        let Ok(number) = digits.parse::<u128>() else {
            return false;
        };
        number * 10u128.pow(9 - digits.len() as u32)
    };
    let actual = u128::from(seconds) * 1_000_000_000 + fraction;
    actual.abs_diff(u128::from(requested) * 1_000_000_000) <= 60_000_000_000
}
pub fn returned_mint(value: &Value, mint: &Mint) -> Result<(String, String), String> {
    let data = &value["data"];
    let expiry = data["expire_at"].as_str().ok_or(MINT_FAILED)?;
    let id = data["_id"]
        .as_str()
        .filter(|s| identifier(s))
        .ok_or(MINT_FAILED)?;
    if value["status"] != "success"
        || data["name"] != mint.name
        || data["usage_limit_usd"].as_f64() != Some(CAP)
        || data.get("reset_period") != Some(&Value::Null)
        || !expiry_matches(mint.requested_expiry, expiry)
    {
        return Err(MINT_FAILED.into());
    }
    Ok((id.into(), expiry.into()))
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum InferenceFailure {
    Exhaustion(Option<f64>),
    Expired,
    Refused,
}
pub fn inference_failure(status: u16, body: &[u8]) -> InferenceFailure {
    let value = decode(body).unwrap_or_else(|_| ClearedValue(Value::Null));
    let message = value
        .0
        .get("error")
        .and_then(Value::as_str)
        .or_else(|| value.0.pointer("/error/message").and_then(Value::as_str))
        .unwrap_or("");
    if status == 401 && message == "API key expired" {
        return InferenceFailure::Expired;
    }
    if status == 402 && message.starts_with("Insufficient credit") {
        let minimum = message
            .split_whitespace()
            .find_map(|part| {
                part.strip_prefix('$')
                    .and_then(|n| n.trim_end_matches([',', '.', ';']).parse::<f64>().ok())
            })
            .filter(|n| n.is_finite() && *n > 0.0);
        return InferenceFailure::Exhaustion(minimum);
    }
    InferenceFailure::Refused
}

#[cfg(target_arch = "wasm32")]
pub mod browser;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
