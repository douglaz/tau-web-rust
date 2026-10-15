//! The relay AUTH: the one text frame a client answers the relay's challenge with
//! (paid-tcp-relay `WIR-5`, at commit `844e834`, which `CHN-15` names as the wire's owner). A
//! NIP-42-shaped Nostr event of kind 22242 carrying the relay, the challenge and the
//! destination, with its NIP-01 id and a BIP-340 signature over that id by the relay key.
//!
//! Built on every target: the harness worker signs with it, and the tracer's relay fixture
//! verifies with it. `auth_event_known_answer` holds both to paid-tcp-relay's own vector.

use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// `kind` of the AUTH event (`WIR-5`, paid-tcp-relay `844e834`).
pub const AUTH_KIND: u64 = 22242;

/// The NIP-01 event id: SHA-256 over `[0, pubkey, created_at, kind, tags, content]`, serialized
/// with no whitespace.
pub fn event_id(pubkey: &str, created_at: u64, kind: u64, tags: &Value, content: &str) -> [u8; 32] {
    let canonical = json!([0, pubkey, created_at, kind, tags, content]).to_string();
    Sha256::digest(canonical.as_bytes()).into()
}

/// The AUTH for one connection, signed by `secret` (the relay key). `aux` is BIP-340's auxiliary
/// randomness; the caller supplies it so this module needs no RNG of its own.
pub fn auth_event(
    secret: &[u8; 32],
    relay_url: &str,
    challenge: &str,
    host: &str,
    port: u16,
    created_at: u64,
    aux: &[u8; 32],
) -> Result<Value, String> {
    let key = SigningKey::from_bytes(secret).map_err(|e| format!("relay key: {e}"))?;
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let tags = json!([
        ["relay", relay_url],
        ["challenge", challenge],
        ["destination", host, port.to_string()],
    ]);
    let id = event_id(&pubkey, created_at, AUTH_KIND, &tags, "");
    let sig = key
        .sign_raw(&id, aux)
        .map_err(|e| format!("BIP-340 signing: {e}"))?;
    Ok(json!({
        "id": hex::encode(id),
        "pubkey": pubkey,
        "created_at": created_at,
        "kind": AUTH_KIND,
        "tags": tags,
        "content": "",
        "sig": hex::encode(sig.to_bytes()),
    }))
}

/// The signature half of check 2 of `WIR-6` (paid-tcp-relay `844e834`): `id` is the event's NIP-01 id, and `sig` is a BIP-340
/// signature over it by `pubkey`. The challenge half is the relay's, which knows the challenge.
pub fn verify_signature(event: &Value) -> Result<(), String> {
    let field = |name: &str| {
        event
            .get(name)
            .ok_or_else(|| format!("no `{name}`"))
            .cloned()
    };
    let text = |name: &str| -> Result<String, String> {
        field(name)?
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("`{name}` is not a string"))
    };
    let number = |name: &str| -> Result<u64, String> {
        field(name)?
            .as_u64()
            .ok_or_else(|| format!("`{name}` is not an unsigned integer"))
    };
    let pubkey = text("pubkey")?;
    let id = event_id(
        &pubkey,
        number("created_at")?,
        number("kind")?,
        &field("tags")?,
        &text("content")?,
    );
    if hex::encode(id) != text("id")? {
        return Err("`id` is not the event's NIP-01 id".into());
    }
    let pubkey = hex::decode(&pubkey).map_err(|e| format!("`pubkey`: {e}"))?;
    let key = VerifyingKey::from_bytes(&pubkey).map_err(|e| format!("`pubkey`: {e}"))?;
    let sig = hex::decode(text("sig")?).map_err(|e| format!("`sig`: {e}"))?;
    let sig = Signature::try_from(sig.as_slice()).map_err(|e| format!("`sig`: {e}"))?;
    key.verify_raw(&id, &sig)
        .map_err(|_| "the BIP-340 signature does not verify".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// paid-tcp-relay's complete signed AUTH, `fixtures/wire/auth.json` at `844e834`.
    const VECTOR: &str = include_str!("../tests/vectors/paid-tcp-relay-844e834-auth.json");

    #[test]
    fn auth_event_known_answer() {
        let event: Value = serde_json::from_str(VECTOR).unwrap();
        let id = event_id(
            event["pubkey"].as_str().unwrap(),
            event["created_at"].as_u64().unwrap(),
            event["kind"].as_u64().unwrap(),
            &event["tags"],
            event["content"].as_str().unwrap(),
        );
        assert_eq!(hex::encode(id), event["id"].as_str().unwrap());
        verify_signature(&event).unwrap();

        let mut flipped = event.clone();
        let mut sig = hex::decode(event["sig"].as_str().unwrap()).unwrap();
        sig[0] ^= 1;
        flipped["sig"] = hex::encode(sig).into();
        assert!(verify_signature(&flipped).is_err());

        let mut moved = event;
        moved["tags"][2][2] = "2222".into();
        assert!(
            verify_signature(&moved).is_err(),
            "the id covers the destination"
        );
    }

    #[test]
    fn auth_event_signs_what_verify_accepts() {
        let event = auth_event(&[7; 32], "wss://r/", "c", "127.0.0.1", 22, 1, &[0; 32]).unwrap();
        assert_eq!(event["kind"], AUTH_KIND);
        assert_eq!(event["tags"][2], json!(["destination", "127.0.0.1", "22"]));
        verify_signature(&event).unwrap();
    }
}
