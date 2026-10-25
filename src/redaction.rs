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
        let mut held = store.held_credentials()?;
        held.borrowed.extend_from_slice(credentials);
        redact(body, &[], &held)
    }

    /// Refuse decoded values rather than execute a command altered by redaction.
    pub(crate) fn inference_value_is_safe<S: Storage>(
        store: &Store<S>,
        value: &serde_json::Value,
        credentials: &[&[u8]],
    ) -> bool {
        use serde_json::Value;
        let Ok(mut held) = store.held_credentials() else {
            return false;
        };
        held.borrowed.extend_from_slice(credentials);
        fn safe(value: &Value, held: &Held<'_>) -> bool {
            let exact =
                |bytes: &[u8]| redact(bytes, &[], held).is_ok_and(|r| r.as_bytes() == bytes);
            match value {
                Value::String(s) => exact(s.as_bytes()),
                Value::Array(a) => a.iter().all(|v| safe(v, held)),
                Value::Object(o) => o.iter().all(|(k, v)| exact(k.as_bytes()) && safe(v, held)),
                _ => exact(value.to_string().as_bytes()),
            }
        }
        safe(value, &held)
    }

    pub(crate) fn for_store<S: Storage>(
        store: &Store<S>,
        body: &[u8],
        fields: &[&str],
    ) -> Result<Self, String> {
        redact(body, fields, &store.held_credentials()?)
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
        for (start, window) in bytes.windows(needle.len()).enumerate() {
            if window == needle {
                ranges.push((start, start + needle.len()));
            }
        }
    }
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
    if held
        .values()
        .any(|needle| output.windows(needle.len()).any(|w| w == needle))
    {
        return Err("redaction marker cannot exclude held credentials".into());
    }
    Ok(Redacted { bytes: output })
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
