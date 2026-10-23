//! Fixture host keys and public-key encodings, never included in a wasm build.

use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::{HashAlg, PrivateKey};

/// The host key the pin source pins for the machine `fixture`.
pub const HOST_KEY_PINNED: [u8; 32] = [
    0x75, 0x03, 0xda, 0x2f, 0x64, 0xb1, 0xe6, 0xfc, 0xba, 0x5f, 0x76, 0x5e, 0xeb, 0xb4, 0x00, 0xb7,
    0xe1, 0x8b, 0xc6, 0xf9, 0x59, 0x69, 0x04, 0x7b, 0x9f, 0x9e, 0x48, 0x56, 0x2b, 0x7d, 0x92, 0xe7,
];

/// Another host key, which the fixture sshd presents in the wrong-key case.
pub const HOST_KEY_OTHER: [u8; 32] = [
    0x68, 0x70, 0x51, 0x9b, 0x0d, 0x53, 0xd5, 0x68, 0x60, 0x63, 0xf6, 0x12, 0xb2, 0xed, 0x97, 0x81,
    0xc0, 0xe8, 0x99, 0x16, 0x46, 0x2d, 0x2a, 0xca, 0x5c, 0x76, 0x39, 0x37, 0xfb, 0x67, 0x55, 0xf1,
];

pub fn ed25519(seed: &[u8; 32]) -> PrivateKey {
    PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(seed)), "")
        .expect("an ed25519 key from 32 bytes")
}

pub fn fingerprint(seed: &[u8; 32]) -> String {
    ed25519(seed)
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string()
}

/// A relay key's public half: the x-only key an AUTH's `pubkey` carries.
pub fn relay_public(secret: &[u8; 32]) -> [u8; 32] {
    k256::schnorr::SigningKey::from_bytes(secret)
        .expect("a valid secp256k1 secret")
        .verifying_key()
        .to_bytes()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pin_source_pins_the_fixture_host_key() {
        let pins = tau_web::testonly::PINS;
        let pin = fingerprint(&HOST_KEY_PINNED);
        assert_eq!(
            pins,
            &[("fixture-other", pin.as_str()), ("fixture", pin.as_str())]
        );
        assert_ne!(fingerprint(&HOST_KEY_PINNED), fingerprint(&HOST_KEY_OTHER));
    }
}
