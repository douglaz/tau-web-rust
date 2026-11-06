//! The credential-redaction boundary for adapter responses.

use crate::credential::{
    AttestRecipientKey, AttestSenderKey, PostHarnessCredential, RelayKey, SshClientKey,
};
use crate::store::{Storage, Store};
use std::fmt;
use zeroize::Zeroizing;

pub const MARKER: &str = "<redacted>";

/// A response that has passed the store's credential boundary. Only the boundary constructs it.
///
/// ```compile_fail
/// use tau_web::redaction::Redacted;
/// let response = Redacted { bytes: vec![] };
/// ```
///
/// ```compile_fail
/// use tau_web::redaction::Redacted;
/// let response = Redacted::from(vec![1u8]);
/// ```
///
/// The same paths and legitimate entry compile without constructing a response from raw bytes:
///
/// ```
/// use tau_web::redaction::Redacted;
/// use tau_web::store::{Storage, Store};
/// async fn response<S: Storage>(store: &mut Store<S>, call: u64) -> Result<Redacted, String> {
///     store.operation_response(call, b"{}", &["/root_password"]).await
/// }
/// ```
pub struct Redacted {
    bytes: Vec<u8>,
}

impl Redacted {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Include the request's transient credentials even after session holdings are cleared.
    pub(crate) fn for_inference<S: Storage>(
        store: &Store<S>,
        body: &[u8],
        credentials: &[&[u8]],
    ) -> Result<Self, String> {
        crate::poc::inference::work::scope(|| {
            let mut held = store.held_credentials()?;
            held.borrowed.extend_from_slice(credentials);
            let scanned = store.scan_output(&[body])?;
            let output = redact(&scanned, &[], &held)?;
            // Only replacement can introduce a new echo into already protected bytes.
            if output.as_bytes() != scanned.as_slice()
                && !store.poc_output_is_safe(output.as_bytes())?
            {
                return Err(crate::poc::wait::PROTECTED_UNAVAILABLE.into());
            }
            Ok(output)
        })
    }

    /// Refuse decoded values rather than execute a command altered by redaction.
    pub(crate) fn inference_value_is_safe<S: Storage>(
        store: &Store<S>,
        value: &serde_json::Value,
        credentials: &[&[u8]],
    ) -> bool {
        crate::poc::inference::work::scope(|| {
            Ok((|| {
                use serde_json::Value;
                let Ok(mut held) = store.held_credentials() else {
                    return false;
                };
                held.borrowed.extend_from_slice(credentials);
                fn safe(value: &Value, held: &Held<'_>) -> bool {
                    let exact = |bytes: &[u8]| {
                        redact(bytes, &[], held).is_ok_and(|r| r.as_bytes() == bytes)
                    };
                    match value {
                        Value::String(s) => exact(s.as_bytes()),
                        Value::Array(a) => a.iter().all(|v| safe(v, held)),
                        Value::Object(o) => {
                            o.iter().all(|(k, v)| exact(k.as_bytes()) && safe(v, held))
                        }
                        _ => exact(value.to_string().as_bytes()),
                    }
                }
                safe(value, &held) && store.protect_output(value).is_ok_and(|safe| safe == *value)
            })())
        })
        .unwrap_or(false)
    }

    /// One decoded representation, without recursively invoking the PoC decoder.
    pub(crate) fn decoded<S: Storage>(store: &Store<S>, body: &[u8]) -> Result<Self, String> {
        crate::poc::inference::work::scope(|| {
            crate::poc::inference::work::charge(body.len().saturating_mul(4))?;
            redact(&store.scan_decoded(body)?, &[], &store.held_credentials()?)
        })
    }

    pub(crate) fn for_store<S: Storage>(
        store: &Store<S>,
        body: &[u8],
        fields: &[&str],
    ) -> Result<Self, String> {
        Self::for_store_cached(store, body, fields, &mut Vec::new())
    }

    /// Cache belongs to this store and these immutable filters, within one synchronous call.
    /// Exact placed-secret and held-credential boundaries still run on every representation.
    pub(crate) fn for_store_cached<S: Storage>(
        store: &Store<S>,
        body: &[u8],
        fields: &[&str],
        cache: &mut Vec<crate::poc::inference::EchoCache>,
    ) -> Result<Self, String> {
        crate::poc::inference::work::scope(|| {
            let scanned = store.scan_output_cached(&[body], cache)?;
            let output = redact(&scanned, fields, &store.held_credentials()?)?;
            if output.as_bytes() != scanned.as_slice()
                && !store.poc_output_is_safe(output.as_bytes())?
            {
                return Err(crate::poc::wait::PROTECTED_UNAVAILABLE.into());
            }
            Ok(output)
        })
    }
}

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Redacted(..)")
    }
}

/// Transient enumeration: existing holders are borrowed; derived copies keep their registered
/// credential types and zeroize on drop. No unregistered key buffer extends their lifetime.
pub(crate) struct Held<'a> {
    pub borrowed: Vec<&'a [u8]>,
    pub mnemonic: Zeroizing<String>,
    pub derived: Vec<Derived>,
    pub bindings: Vec<std::cell::Ref<'a, Vec<crate::binding::Holding>>>,
}

pub(crate) enum Derived {
    Ssh(SshClientKey),
    Sender(AttestSenderKey),
    Recipient(AttestRecipientKey),
    Relay(RelayKey),
    Handoff(PostHarnessCredential),
}

impl Held<'_> {
    fn values(&self) -> impl Iterator<Item = &[u8]> {
        self.borrowed
            .iter()
            .copied()
            .chain(
                self.bindings
                    .iter()
                    .flat_map(|given| given.iter().filter_map(|h| h.credential.response_bytes())),
            )
            .chain(std::iter::once(self.mnemonic.as_bytes()))
            .chain(self.derived.iter().map(|key| match key {
                Derived::Ssh(key) => key.0.as_slice(),
                Derived::Sender(key) => key.0.as_slice(),
                Derived::Recipient(key) => key.0.as_slice(),
                Derived::Relay(key) => key.0.as_slice(),
                Derived::Handoff(key) => key.0.as_slice(),
            }))
            .filter(|value| !value.is_empty())
    }
}

impl fmt::Debug for Held<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Held(..)")
    }
}

fn redact(body: &[u8], fields: &[&str], held: &Held<'_>) -> Result<Redacted, String> {
    let bytes = if fields.is_empty() {
        body.to_vec()
    } else {
        let mut value: serde_json::Value = serde_json::from_slice(body)
            .map_err(|_| "response is not JSON for declared fields".to_string())?;
        for field in fields {
            if let Some(password) = value.pointer_mut(field)
                && !password.is_null()
            {
                *password = MARKER.into();
            }
        }
        serde_json::to_vec(&value).map_err(|_| "response JSON cannot be serialized".to_string())?
    };
    let bytes = Zeroizing::new(bytes);
    // Collect before replacing: overlapping copies must produce a single marker, and replacing
    // one needle must not conceal an overlapping needle from another credential.
    let mut ranges = Vec::new();
    for needle in held.values() {
        credential_matches(&bytes, needle, |start| {
            crate::poc::inference::work::charge(32)?;
            ranges.push((start, start + needle.len()));
            Ok(false)
        })?;
    }
    crate::poc::inference::work::charge(
        ranges
            .len()
            .saturating_mul(ranges.len().max(1).ilog2() as usize + 1),
    )?;
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && start < last.1
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end));
    }
    let mut output = Vec::new();
    let mut cursor = 0;
    for (start, end) in merged {
        output.extend_from_slice(&bytes[cursor..start]);
        output.extend_from_slice(MARKER.as_bytes());
        cursor = end;
    }
    output.extend_from_slice(&bytes[cursor..]);
    // The marker itself (or its junction with preserved bytes) could contain a held value.
    // Refuse instead of claiming that such an output passed.
    for needle in held.values() {
        if credential_matches(&output, needle, |_| Ok(true))? {
            return Err(crate::poc::wait::REDACTION_MARKER.into());
        }
    }
    Ok(Redacted { bytes: output })
}

/// KMP compares at most linear byte-work, including overlapping occurrences. Charge before
/// allocating the prefix table or scanning, rather than charging every window's full length.
fn credential_matches(
    bytes: &[u8],
    needle: &[u8],
    mut found: impl FnMut(usize) -> Result<bool, String>,
) -> Result<bool, String> {
    crate::poc::inference::work::charge(
        bytes
            .len()
            .saturating_mul(4)
            .saturating_add(needle.len().saturating_mul(16)),
    )?;
    let mut prefix = Zeroizing::new(vec![0usize; needle.len()]);
    let mut matched = 0;
    for i in 1..needle.len() {
        while matched > 0 && needle[i] != needle[matched] {
            matched = prefix[matched - 1];
        }
        if needle[i] == needle[matched] {
            matched += 1;
        }
        prefix[i] = matched;
    }
    matched = 0;
    for (i, byte) in bytes.iter().enumerate() {
        while matched > 0 && *byte != needle[matched] {
            matched = prefix[matched - 1];
        }
        if *byte == needle[matched] {
            matched += 1;
        }
        if matched == needle.len() {
            if found(i + 1 - matched)? {
                return Ok(true);
            }
            matched = prefix[matched - 1];
        }
    }
    Ok(false)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn overlapping_empty_and_marker_matches() {
        let held = Held {
            borrowed: vec![b"abc", b"bcd", b""],
            mnemonic: Zeroizing::new(String::new()),
            derived: vec![],
            bindings: vec![],
        };
        assert_eq!(
            redact(b"zabcd!abc", &[], &held).unwrap().as_bytes(),
            b"z<redacted>!<redacted>"
        );
        let held = Held {
            borrowed: vec![b"red"],
            ..held
        };
        let error = redact(b"red", &[], &held).unwrap_err();
        assert_eq!(error, "redaction marker cannot exclude held credentials");
        assert_eq!(format!("{held:?}"), "Held(..)");
    }
}
