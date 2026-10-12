//! The operator seed and its child keys, credential format v1 (`STA-22`, `STA-22a`, the companion
//! `spec/docs/design/credential-format-v1.md`, "Seed and child keys"): a 12-word English BIP-39
//! mnemonic with the empty BIP-39 passphrase, and hardened BIP-32 derivation at
//! `m/707285'/1'/role'/index'` for roles 0–4.
//!
//! Built on every target. Nothing calls it at runtime yet: the local store (twr-ggw.5),
//! allocation (twr-ggw.6) and binding (twr-ggw.11) wire it in. No `wasm_bindgen` export returns or
//! accepts a mnemonic, a seed or a child key.
//!
//! Derivation refuses rather than aliases: an unknown version, a role outside 0–4, an index above
//! 2^31−1 and an invalid BIP-32 step are each an error, and no step ever moves on to another index
//! (the companion: it "rejects an invalid BIP-32 master or child rather than silently skipping to
//! another path"). Chain codes and intermediate keys stay inside `child`; nothing public returns
//! one.

use crate::credential::{
    AttestRecipientKey, AttestSenderKey, PostHarnessCredential, RelayKey, SshClientKey,
};
use hmac::{Hmac, KeyInit, Mac};
use k256::elliptic_curve::PrimeField;
use k256::{NonZeroScalar, Scalar};
use sha2::{Digest, Sha256, Sha512};

/// The derivation version this code implements: the `1'` in the path (`STA-22a`).
pub const VERSION: u32 = 1;

/// The application's namespace, the path's first component.
const NAMESPACE: u32 = 707_285;

/// The highest index a family may allocate: 2^31−1. Indices never wrap.
pub const MAX_INDEX: u32 = 0x7fff_ffff;

/// BIP-39's English word list, `bip-0039/english.txt` at bitcoin/bips `927b6de`, byte for byte
/// (`tests/vectors/README.md`).
const ENGLISH: &str = include_str!("bip39-english.txt");

/// A role of credential format v1's role table. Role 5, the derived vendor identity, does not
/// exist: `SEC-5` row 22 is "not derivable today".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Role 0, the machine's SSH client key (`SEC-5` row 3).
    SshClient = 0,
    /// Role 1, the machine's attest sender key (row 7).
    AttestSender = 1,
    /// Role 2, the machine's attest recipient key (row 16).
    AttestRecipient = 2,
    /// Role 3, a relay pass's relay key (row 4).
    Relay = 3,
    /// Role 4, a declared handoff's post-harness credential (row 17).
    PostHarness = 4,
}

impl TryFrom<u32> for Role {
    type Error = DeriveError;

    fn try_from(role: u32) -> Result<Self, DeriveError> {
        Ok(match role {
            0 => Role::SshClient,
            1 => Role::AttestSender,
            2 => Role::AttestRecipient,
            3 => Role::Relay,
            4 => Role::PostHarness,
            _ => return Err(DeriveError::UnknownRole(role)),
        })
    }
}

/// Why a child key was not derived. Each is a refusal, never a different key.
#[derive(Debug, PartialEq, Eq)]
pub enum DeriveError {
    /// A derivation version other than [`VERSION`]: "Unknown versions are refused" (`STA-22a`).
    UnknownVersion(u32),
    /// A role number outside 0–4.
    UnknownRole(u32),
    /// An index above [`MAX_INDEX`].
    IndexOutOfRange(u32),
    /// BIP-32's first step gave a key outside 1..n−1.
    InvalidFirstStep,
    /// A hardened child step gave IL ≥ n or a zero key.
    InvalidChild,
}

/// Why a mnemonic was not imported. No refusal echoes a word, and a refused word is named by its
/// position (1-based): the error may reach a `JsValue` or a log.
#[derive(Debug, PartialEq, Eq)]
pub enum ImportError {
    /// Not 12 words, after splitting on ASCII whitespace.
    WordCount(usize),
    /// The word at this position is not exactly a word of the English list.
    UnknownWord { position: usize },
    /// Every word is on the list, but the checksum does not hold.
    Checksum,
}

/// The operator seed (`SEC-5` row 15): its mnemonic and the 64-byte BIP-39 seed derived from it.
pub struct Seed {
    #[allow(
        dead_code,
        reason = "the seed backup ceremony (STA-23) shows the words; only tests read them yet"
    )]
    words: [&'static str; 12],
    bytes: [u8; 64],
}

impl Seed {
    /// A new seed from 16 bytes of the CSPRNG: the browser's on wasm32, the OS's on the host. A
    /// CSPRNG failure is an error, never a fallback.
    pub fn generate() -> Result<Seed, getrandom::Error> {
        let mut entropy = [0u8; 16];
        getrandom::fill(&mut entropy)?;
        Ok(Seed::from_words(mnemonic(&entropy)))
    }

    /// Imports a 12-word English mnemonic. Leading, trailing and repeated ASCII whitespace is
    /// accepted; anything else is refused: another word count, a word not exactly on the list (no
    /// case folding, no prefixes, no Unicode folding, so another language's words are refused),
    /// non-ASCII whitespace, or a bad checksum.
    pub fn import(text: &str) -> Result<Seed, ImportError> {
        let found: Vec<&str> = text.split_ascii_whitespace().collect();
        if found.len() != 12 {
            return Err(ImportError::WordCount(found.len()));
        }
        let mut indices = [0usize; 12];
        for (position, word) in found.iter().enumerate() {
            indices[position] = ENGLISH.lines().position(|listed| listed == *word).ok_or(
                ImportError::UnknownWord {
                    position: position + 1,
                },
            )?;
        }
        // The 132 bits the words carry: the entropy, then its 4-bit checksum.
        let mut bits = [0u8; 17];
        for (w, index) in indices.iter().enumerate() {
            for b in 0..11 {
                if index >> (10 - b) & 1 == 1 {
                    let n = 11 * w + b;
                    bits[n / 8] |= 0x80 >> (n % 8);
                }
            }
        }
        let entropy: [u8; 16] = bits[..16].try_into().expect("16 of 17 bytes");
        // The words determine the entropy, so they encode it back exactly when the checksum holds.
        let words = mnemonic(&entropy);
        if words.iter().ne(found.iter()) {
            return Err(ImportError::Checksum);
        }
        Ok(Seed::from_words(words))
    }

    /// The 64-byte BIP-39 seed: PBKDF2-HMAC-SHA512, 2048 iterations, over the canonical sentence
    /// (the words joined by single ASCII spaces), with salt `mnemonic`, which is the **empty**
    /// BIP-39 passphrase. No function here takes a BIP-39 passphrase, and the local unlock
    /// passphrase (`SEC-5` row 18) never reaches this one.
    ///
    /// BIP-39 normalizes both inputs with NFKD. The sentence is ASCII, which NFKD leaves
    /// unchanged, so no normalization crate is needed.
    fn from_words(words: [&'static str; 12]) -> Seed {
        let mut bytes = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<Sha512>(words.join(" ").as_bytes(), b"mnemonic", 2048, &mut bytes);
        Seed { words, bytes }
    }

    /// The seed identifier: lowercase hex SHA-256 of `tau-web seed id v1`, one zero byte and the
    /// 64-byte seed. An integrity association, not authentication.
    pub fn id(&self) -> String {
        hex::encode(
            Sha256::new()
                .chain_update(b"tau-web seed id v1\0")
                .chain_update(self.bytes)
                .finalize(),
        )
    }

    /// Role 0 at `machine`: the SSH client key.
    pub fn ssh_client_key(&self, version: u32, machine: u32) -> Result<SshClientKey, DeriveError> {
        self.child(version, Role::SshClient, machine)
            .map(SshClientKey)
    }

    /// Role 1 at `machine`: the attest sender key.
    pub fn attest_sender_key(
        &self,
        version: u32,
        machine: u32,
    ) -> Result<AttestSenderKey, DeriveError> {
        self.child(version, Role::AttestSender, machine)
            .map(AttestSenderKey)
    }

    /// Role 2 at `machine`: the attest recipient key.
    pub fn attest_recipient_key(
        &self,
        version: u32,
        machine: u32,
    ) -> Result<AttestRecipientKey, DeriveError> {
        self.child(version, Role::AttestRecipient, machine)
            .map(AttestRecipientKey)
    }

    /// Role 3 at `pass`: the relay key.
    pub fn relay_key(&self, version: u32, pass: u32) -> Result<RelayKey, DeriveError> {
        self.child(version, Role::Relay, pass).map(RelayKey)
    }

    /// Role 4 at `handoff`: the post-harness credential.
    pub fn post_harness_credential(
        &self,
        version: u32,
        handoff: u32,
    ) -> Result<PostHarnessCredential, DeriveError> {
        self.child(version, Role::PostHarness, handoff)
            .map(PostHarnessCredential)
    }

    /// The child secret at `m/707285'/1'/role'/index'`. The version and the index are refused
    /// before anything is derived, and a refused step is this role and index's error: there is no
    /// next index to try.
    fn child(&self, version: u32, role: Role, index: u32) -> Result<[u8; 32], DeriveError> {
        if version != VERSION {
            return Err(DeriveError::UnknownVersion(version));
        }
        let path = [
            hardened(NAMESPACE)?,
            hardened(version)?,
            hardened(role as u32)?,
            hardened(index)?,
        ];
        let (mut key, mut chain) = first_step(&self.bytes)?;
        for i in path {
            (key, chain) = child_step(&key, &chain, i)?;
        }
        Ok(key)
    }
}

/// The 12 words for 16 bytes of entropy: the entropy and the first 4 bits of its SHA-256, read as
/// twelve 11-bit indices into the English list.
pub(crate) fn mnemonic(entropy: &[u8; 16]) -> [&'static str; 12] {
    let mut bits = [0u8; 17];
    bits[..16].copy_from_slice(entropy);
    bits[16] = Sha256::digest(entropy)[0];
    let bit = |n: usize| usize::from(bits[n / 8] >> (7 - n % 8) & 1);
    std::array::from_fn(|w| {
        let index = (0..11).fold(0, |acc, b| acc << 1 | bit(11 * w + b));
        ENGLISH.lines().nth(index).expect("2048 words")
    })
}

/// `index` as a hardened child number, i + 2^31, refused above [`MAX_INDEX`]. The range is
/// checked first: the hardened bit is never set on an unchecked index.
fn hardened(index: u32) -> Result<u32, DeriveError> {
    if index > MAX_INDEX {
        return Err(DeriveError::IndexOutOfRange(index));
    }
    Ok(index + 0x8000_0000)
}

/// BIP-32's validity predicate for a secret scalar: 1 ≤ x < n.
pub(crate) fn valid_scalar(x: &[u8; 32]) -> bool {
    NonZeroScalar::from_repr((*x).into()).is_some().into()
}

fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC takes any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn halves(i: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let (left, right) = i.split_at(32);
    (
        left.try_into().expect("32 bytes"),
        right.try_into().expect("32 bytes"),
    )
}

/// BIP-32's first step, I = HMAC-SHA512(`Bitcoin seed`, seed): the key and chain code at `m`.
/// v1 always passes the 64-byte BIP-39 seed; BIP-32's own vectors pass 16 to 64 bytes.
pub(crate) fn first_step(seed: &[u8]) -> Result<([u8; 32], [u8; 32]), DeriveError> {
    first_step_check(&hmac_sha512(b"Bitcoin seed", &[seed]))
}

/// The first step's validity check over its HMAC output: IL is the key, refused unless it passes
/// [`valid_scalar`].
pub(crate) fn first_step_check(i: &[u8; 64]) -> Result<([u8; 32], [u8; 32]), DeriveError> {
    let (il, ir) = halves(i);
    if !valid_scalar(&il) {
        return Err(DeriveError::InvalidFirstStep);
    }
    Ok((il, ir))
}

/// One hardened child step, I = HMAC-SHA512(c_par, 0x00 ‖ ser256(k_par) ‖ ser32(i)), where `i`
/// already carries the hardened bit ([`hardened`]).
pub(crate) fn child_step(
    k_par: &[u8; 32],
    c_par: &[u8; 32],
    i: u32,
) -> Result<([u8; 32], [u8; 32]), DeriveError> {
    child_step_check(&hmac_sha512(c_par, &[&[0], k_par, &i.to_be_bytes()]), k_par)
}

/// The child step's validity check over its HMAC output: k_i = parse256(IL) + k_par mod n,
/// refused if parse256(IL) ≥ n or k_i fails [`valid_scalar`]. IL = 0 is valid and gives k_par.
pub(crate) fn child_step_check(
    i: &[u8; 64],
    k_par: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), DeriveError> {
    let (il, ir) = halves(i);
    let il =
        Option::<Scalar>::from(Scalar::from_repr(il.into())).ok_or(DeriveError::InvalidChild)?;
    let k_par = Option::<Scalar>::from(Scalar::from_repr((*k_par).into()))
        .ok_or(DeriveError::InvalidChild)?;
    let key: [u8; 32] = (il + k_par).to_repr().into();
    if !valid_scalar(&key) {
        return Err(DeriveError::InvalidChild);
    }
    Ok((key, ir))
}

/// `CNF-83` and `STA-22a`. Host only: the second implementation and the Base58Check decoder are
/// host-only dev-dependencies, and the `web` job's wasm32 clippy compiles test code too.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::credential::{ed25519_public, xonly_public};
    use serde_json::Value;
    use std::collections::{BTreeMap, BTreeSet};

    /// secp256k1's group order n.
    const N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

    fn spec(path: &str) -> String {
        let path = format!("{}/spec/{path}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    fn bytes32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    /// An HMAC output with this IL and an arbitrary IR.
    fn crafted(il: [u8; 32]) -> [u8; 64] {
        let mut i = [0x5a; 64];
        i[..32].copy_from_slice(&il);
        i
    }

    /// n + delta, for small delta.
    fn n_plus(delta: u8) -> [u8; 32] {
        let mut x = bytes32(N);
        x[31] += delta;
        x
    }

    /// The child secret and public key of `role` at `index`, through the role's own method.
    fn derive(
        seed: &Seed,
        version: u32,
        role: u32,
        index: u32,
    ) -> Result<([u8; 32], [u8; 32]), DeriveError> {
        Ok(match Role::try_from(role)? {
            Role::SshClient => {
                let key = seed.ssh_client_key(version, index)?;
                (key.0, key.public_key())
            }
            Role::AttestSender => {
                let key = seed.attest_sender_key(version, index)?;
                (key.0, key.public_key())
            }
            Role::AttestRecipient => {
                let key = seed.attest_recipient_key(version, index)?;
                (key.0, key.public_key())
            }
            Role::Relay => {
                let key = seed.relay_key(version, index)?;
                (key.0, key.public_key())
            }
            Role::PostHarness => {
                let key = seed.post_harness_credential(version, index)?;
                (key.0, key.public_key())
            }
        })
    }

    fn vector_seed() -> Seed {
        Seed::from_words(mnemonic(&[0; 16]))
    }

    #[test]
    fn the_word_list_is_bip39s() {
        assert_eq!(
            hex::encode(Sha256::digest(ENGLISH)),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        assert_eq!(ENGLISH.lines().count(), 2048);
    }

    /// `spec/docs/design/credential-vectors-v1.json`, read from the pinned tree.
    #[test]
    fn every_v1_known_answer_matches() {
        let v1: Value =
            serde_json::from_str(&spec("docs/design/credential-vectors-v1.json")).unwrap();
        assert_eq!(v1["version"], VERSION);
        assert_eq!(v1["bip39_passphrase"], "");
        let seed = Seed::import(v1["mnemonic"].as_str().unwrap()).unwrap();
        assert_eq!(hex::encode(seed.bytes), v1["bip39_seed_hex"]);
        assert_eq!(seed.id(), v1["seed_id"]);

        let vectors = v1["vectors"].as_array().unwrap();
        assert_eq!(
            vectors.len(),
            10,
            "one vector per role 0-4 at indices 0 and 1"
        );
        let mut seen = BTreeSet::new();
        for vector in vectors {
            let role = u32::try_from(vector["role"].as_u64().unwrap()).unwrap();
            let index = u32::try_from(vector["index"].as_u64().unwrap()).unwrap();
            assert!(
                seen.insert((role, index)),
                "role {role} index {index} twice"
            );
            assert_eq!(vector["path"], format!("m/707285'/1'/{role}'/{index}'"));
            let encoding = if matches!(role, 0 | 4) {
                "ed25519"
            } else {
                "secp256k1-xonly"
            };
            assert_eq!(vector["public_encoding"], encoding, "role {role}");
            let (secret, public) = derive(&seed, VERSION, role, index).unwrap();
            assert_eq!(
                hex::encode(secret),
                vector["private_hex"],
                "role {role} index {index}"
            );
            assert_eq!(
                hex::encode(public),
                vector["public_hex"],
                "role {role} index {index}"
            );
        }
        let all: BTreeSet<_> = (0..5).flat_map(|r| [(r, 0), (r, 1)]).collect();
        assert_eq!(seen, all);
    }

    /// BIP-32's test vectors, `tests/vectors/bips-927b6de-bip-0032.mediawiki`: per vector, its
    /// seed and each chain's xprv, or (vector 5) each entry with its comment.
    fn bip32_vectors() -> BTreeMap<u32, (String, Vec<(String, String)>)> {
        let text = include_str!("../tests/vectors/bips-927b6de-bip-0032.mediawiki");
        let mut vectors = BTreeMap::new();
        let mut current = None;
        let mut chain = String::new();
        for line in text.lines() {
            if let Some(n) = line.strip_prefix("===Test vector ") {
                let n: u32 = n.trim_end_matches('=').parse().unwrap();
                vectors.insert(n, (String::new(), Vec::new()));
                current = Some(n);
                continue;
            }
            let Some(entry) = current.and_then(|n| vectors.get_mut(&n)) else {
                continue;
            };
            if line.starts_with("==") {
                current = None;
            } else if let Some(seed) = line.strip_prefix("Seed (hex): ") {
                entry.0 = seed.to_string();
            } else if let Some(name) = line.strip_prefix("* Chain ") {
                chain = name.replace("<sub>H</sub>", "H");
            } else if let Some(xprv) = line.strip_prefix("** ext prv: ") {
                entry.1.push((chain.clone(), xprv.to_string()));
            } else if let Some(rest) = line.strip_prefix("* ") {
                let (key, comment) = rest.split_once(" (").unwrap();
                entry
                    .1
                    .push((comment.trim_end_matches(')').to_string(), key.to_string()));
            }
        }
        vectors
    }

    /// An xprv's chain code and key: Base58Check, then version (4), depth (1), parent
    /// fingerprint (4), child number (4), chain code (32), 0x00 and the key (33).
    fn decode_xprv(xprv: &str) -> ([u8; 32], [u8; 32]) {
        let raw = bs58::decode(xprv).with_check(None).into_vec().unwrap();
        assert_eq!(raw.len(), 78, "{xprv}");
        assert_eq!(raw[45], 0, "{xprv}: a private key's prefix");
        (
            raw[13..45].try_into().unwrap(),
            raw[46..].try_into().unwrap(),
        )
    }

    /// Vectors 1 (`m` and `m/0H`, its hardened steps), 3 and 4 (leading zeros), at every step,
    /// on key and chain code, through `first_step` and `child_step`. Vector 2 starts with a
    /// non-hardened step, which v1 never takes, and is left out.
    #[test]
    fn upstream_bip32_vectors_match() {
        let vectors = bip32_vectors();
        let wanted: [(u32, &[&str]); 3] = [
            (1, &["m", "m/0H"]),
            (3, &["m", "m/0H"]),
            (4, &["m", "m/0H", "m/0H/1H"]),
        ];
        for (n, chains) in wanted {
            let (seed, entries) = &vectors[&n];
            let seed = hex::decode(seed).unwrap();
            let (mut key, mut chain) = first_step(&seed).unwrap();
            for (depth, name) in chains.iter().enumerate() {
                if depth > 0 {
                    let i: u32 = name
                        .rsplit('/')
                        .next()
                        .unwrap()
                        .trim_end_matches('H')
                        .parse()
                        .unwrap();
                    (key, chain) = child_step(&key, &chain, hardened(i).unwrap()).unwrap();
                }
                let xprv = &entries.iter().find(|(c, _)| c == name).unwrap().1;
                assert_eq!((chain, key), decode_xprv(xprv), "vector {n} chain {name}");
            }
        }
    }

    /// Vector 5's two key-range entries go to the predicate and the first step's check, which
    /// refuse both. The other 14 are not applicable: serialization faults (version bytes, key
    /// prefixes, depth, parent fingerprint, child number, checksum) and one invalid public point;
    /// v1 parses no extended key and no public key, and import takes a mnemonic only.
    #[test]
    fn upstream_bip32_invalid_keys_are_refused() {
        const NOT_APPLICABLE: [&str; 14] = [
            "pubkey version / prvkey mismatch",
            "prvkey version / pubkey mismatch",
            "invalid pubkey prefix 04",
            "invalid prvkey prefix 04",
            "invalid pubkey prefix 01",
            "invalid prvkey prefix 01",
            "zero depth with non-zero parent fingerprint",
            "zero depth with non-zero parent fingerprint",
            "zero depth with non-zero index",
            "zero depth with non-zero index",
            "unknown extended key version",
            "unknown extended key version",
            "invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007",
            "invalid checksum",
        ];
        let (_, entries) = &bip32_vectors()[&5];
        assert_eq!(entries.len(), 16);
        let entry = |comment: &str| &entries.iter().find(|(c, _)| c == comment).unwrap().1;
        let (zero_chain, zero) = decode_xprv(entry("private key 0 not in 1..n-1"));
        let (n_chain, n) = decode_xprv(entry("private key n not in 1..n-1"));
        assert_eq!(zero, [0; 32], "the decoder read the zero key");
        assert_eq!(n, bytes32(N), "the decoder read n");
        for (key, chain) in [(zero, zero_chain), (n, n_chain)] {
            assert!(!valid_scalar(&key));
            let mut i = [0; 64];
            i[..32].copy_from_slice(&key);
            i[32..].copy_from_slice(&chain);
            assert_eq!(first_step_check(&i), Err(DeriveError::InvalidFirstStep));
        }
        let rest: Vec<&str> = entries
            .iter()
            .map(|(c, _)| c.as_str())
            .filter(|c| !c.starts_with("private key "))
            .collect();
        assert_eq!(rest, NOT_APPLICABLE);
    }

    /// RFC 8032 section 7.1, `tests/vectors/rfc8032-section-7.1.txt`: each test's secret key
    /// gives its public key through `ed25519_public`, roles 0 and 4's mapping, and signs its
    /// message to its signature.
    #[test]
    fn rfc8032_ed25519_vectors_match() {
        use ed25519_dalek::Signer;
        let text = include_str!("../tests/vectors/rfc8032-section-7.1.txt");
        // Each test's name, its fields' bytes, and its message's stated length.
        type Test<'a> = (String, BTreeMap<&'a str, Vec<u8>>, usize);
        let mut tests: Vec<Test> = Vec::new();
        let mut label = None;
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(name) = trimmed.strip_prefix("-----TEST ") {
                tests.push((name.to_string(), BTreeMap::new(), 0));
                label = None;
            } else if trimmed.ends_with(':') {
                let test = tests.last_mut().unwrap();
                label = match trimmed {
                    "SECRET KEY:" => Some("SECRET KEY"),
                    "PUBLIC KEY:" => Some("PUBLIC KEY"),
                    "SIGNATURE:" => Some("SIGNATURE"),
                    _ => trimmed.strip_prefix("MESSAGE (length ").map(|length| {
                        test.2 = length.split(' ').next().unwrap().parse().unwrap();
                        "MESSAGE"
                    }),
                };
                if let Some(label) = label {
                    test.1.insert(label, Vec::new());
                }
            } else if let (Some(label), Some(test)) = (label, tests.last_mut()) {
                // Only the indented hex lines: the page footer and header between are skipped.
                if line.starts_with("   ")
                    && !trimmed.is_empty()
                    && let Ok(bytes) = hex::decode(trimmed)
                {
                    test.1.get_mut(label).unwrap().extend(bytes);
                }
            }
        }
        let names: Vec<&str> = tests.iter().map(|(n, _, _)| n.as_str()).collect();
        assert_eq!(names, ["1", "2", "3", "1024", "SHA(abc)"]);
        for (name, fields, length) in &tests {
            let secret: [u8; 32] = fields["SECRET KEY"].clone().try_into().unwrap();
            let message = &fields["MESSAGE"];
            assert_eq!(
                message.len(),
                *length,
                "TEST {name}: the message's stated length"
            );
            assert_eq!(
                ed25519_public(&secret).as_slice(),
                fields["PUBLIC KEY"],
                "TEST {name}"
            );
            let signature = ed25519_dalek::SigningKey::from_bytes(&secret).sign(message);
            assert_eq!(
                signature.to_bytes().as_slice(),
                fields["SIGNATURE"],
                "TEST {name}"
            );
        }
    }

    /// BIP-340's `test-vectors.csv` at bitcoin/bips `927b6de`: every row with a secret key gives
    /// its x-only public key through `xonly_public`, roles 1-3's mapping. The signing columns
    /// are not run: signing with a derived key is not this module's.
    #[test]
    fn bip340_public_keys_match() {
        let text = include_str!("../tests/vectors/bips-927b6de-bip-0340-test-vectors.csv");
        let mut rows = Vec::new();
        for line in text.lines().skip(1) {
            let cells: Vec<&str> = line.split(',').collect();
            if cells[1].is_empty() {
                continue;
            }
            let public = xonly_public(&bytes32(cells[1])).unwrap();
            assert_eq!(hex::encode_upper(public), cells[2], "row {}", cells[0]);
            rows.push(cells[0].parse::<u32>().unwrap());
        }
        assert_eq!(rows, [0, 1, 2, 3, 15, 16, 17, 18]);
    }

    /// trezor/python-mnemonic's `vectors.json` at `b57a5ad`, its eight 12-word English entries:
    /// the entropy gives the mnemonic, which imports. Their seeds use the passphrase `TREZOR`,
    /// and are not run: no function here takes a BIP-39 passphrase.
    #[test]
    fn bip39_reference_vectors_match() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../tests/vectors/python-mnemonic-b57a5ad-vectors.json"
        ))
        .unwrap();
        let mut count = 0;
        for entry in vectors["english"].as_array().unwrap() {
            let words = entry[1].as_str().unwrap();
            if words.split(' ').count() != 12 {
                continue;
            }
            let entropy: [u8; 16] = hex::decode(entry[0].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(mnemonic(&entropy).join(" "), words);
            assert_eq!(Seed::import(words).unwrap().words.join(" "), words);
            count += 1;
        }
        assert_eq!(count, 8);
    }

    /// The second implementation: rust-bitcoin's `bip39` and iqlusion's `bip32`, against the
    /// primary, on the v1 vector's entropy (all zero) and 17 others. `bip32`'s k256 backend
    /// shares the primary's curve arithmetic; the independent checks on that arithmetic are the
    /// v1 vectors, generated with Python's integers, and BIP-32's own vectors.
    #[test]
    fn a_second_implementation_agrees() {
        use bip32::{ChildNumber, XPrv};
        let v1: Value =
            serde_json::from_str(&spec("docs/design/credential-vectors-v1.json")).unwrap();
        assert_eq!(
            mnemonic(&[0; 16]).join(" "),
            v1["mnemonic"],
            "the v1 vector's entropy"
        );
        let mut entropies = vec![[0u8; 16], [0xff; 16], [0x80; 16], [0x7f; 16]];
        entropies.extend(
            (0u8..14).map(|i| -> [u8; 16] { Sha256::digest([i])[..16].try_into().unwrap() }),
        );
        let indices = [0, 1, 2, 1000, MAX_INDEX - 1, MAX_INDEX];
        for entropy in entropies {
            let primary = Seed::from_words(mnemonic(&entropy));
            let second = bip39::Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(primary.words.join(" "), second.to_string());
            let second_seed = second.to_seed_normalized("");
            assert_eq!(primary.bytes, second_seed);
            let step = |key: &XPrv, i| {
                key.derive_child(ChildNumber::new(i, true).unwrap())
                    .unwrap()
            };
            let top = XPrv::new(second_seed).unwrap();
            for role in 0..5 {
                let branch = step(&step(&step(&top, NAMESPACE), VERSION), role);
                for index in indices {
                    let child = step(&branch, index);
                    let (secret, public) = derive(&primary, VERSION, role, index).unwrap();
                    let at = format!("entropy {} role {role} index {index}", hex::encode(entropy));
                    assert_eq!(
                        secret,
                        <[u8; 32]>::from(child.private_key().to_bytes()),
                        "{at}"
                    );
                    if (1..=3).contains(&role) {
                        assert_eq!(public, child.public_key().to_bytes()[1..], "{at}");
                    }
                }
            }
        }
    }

    #[test]
    fn roles_and_indices_give_distinct_keys() {
        let seed = vector_seed();
        let mut secrets = BTreeSet::new();
        let mut publics = BTreeSet::new();
        for role in 0..5 {
            for index in [0, 1, 2, MAX_INDEX] {
                let (secret, public) = derive(&seed, VERSION, role, index).unwrap();
                assert!(
                    secrets.insert(secret),
                    "role {role} index {index}'s secret repeats"
                );
                assert!(
                    publics.insert(public),
                    "role {role} index {index}'s public key repeats"
                );
            }
        }
        let machine: BTreeSet<_> = (0..3)
            .map(|role| derive(&seed, VERSION, role, 7).unwrap().0)
            .collect();
        assert_eq!(machine.len(), 3, "roles 0, 1 and 2 at one machine index");
    }

    #[test]
    fn an_out_of_range_index_is_refused_not_aliased() {
        let seed = vector_seed();
        for role in 0..5 {
            let low = [0, 1].map(|i| derive(&seed, VERSION, role, i).unwrap().0);
            for index in [MAX_INDEX + 1, MAX_INDEX + 2, u32::MAX] {
                match derive(&seed, VERSION, role, index) {
                    Err(DeriveError::IndexOutOfRange(i)) => assert_eq!(i, index),
                    Ok((secret, _)) => panic!(
                        "role {role} index {index} derived a key{}",
                        if low.contains(&secret) {
                            ", index 0's or 1's"
                        } else {
                            ""
                        }
                    ),
                    Err(other) => panic!("role {role} index {index}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let seed = vector_seed();
        for role in 0..5 {
            for version in [0, 2, u32::MAX] {
                assert_eq!(
                    derive(&seed, version, role, 0),
                    Err(DeriveError::UnknownVersion(version)),
                    "role {role}"
                );
            }
        }
    }

    #[test]
    fn an_unknown_role_is_refused() {
        for role in [5, 6, 255] {
            assert_eq!(Role::try_from(role), Err(DeriveError::UnknownRole(role)));
        }
        assert_eq!(Role::try_from(4), Ok(Role::PostHarness));
    }

    #[test]
    fn an_invalid_first_step_is_refused() {
        let mut max = [0xff; 32];
        for il in [[0; 32], n_plus(0), n_plus(1), max] {
            assert!(!valid_scalar(&il));
            assert_eq!(
                first_step_check(&crafted(il)),
                Err(DeriveError::InvalidFirstStep),
                "IL {}",
                hex::encode(il)
            );
        }
        max[0] = 0x7f;
        assert!(first_step_check(&crafted(max)).is_ok());
        let mut one = [0; 32];
        one[31] = 1;
        assert_eq!(first_step_check(&crafted(one)).unwrap().0, one);
    }

    #[test]
    fn an_invalid_child_is_refused() {
        let (k_par, _) = first_step(&vector_seed().bytes).unwrap();
        // IL = n − k_par, so that k_i = 0.
        let n = Scalar::from_repr(n_plus(0).into());
        assert!(bool::from(n.is_none()), "n is not a scalar");
        let k = Scalar::from_repr(k_par.into()).unwrap();
        let zeroing: [u8; 32] = (-k).to_repr().into();
        for il in [n_plus(0), [0xff; 32], zeroing] {
            assert_eq!(
                child_step_check(&crafted(il), &k_par),
                Err(DeriveError::InvalidChild),
                "IL {}",
                hex::encode(il)
            );
        }
        // IL = 0 is a valid child step, which gives k_par.
        assert_eq!(
            child_step_check(&crafted([0; 32]), &k_par).unwrap().0,
            k_par
        );
    }

    #[test]
    fn import_refuses_anything_but_twelve_english_words() {
        let words = mnemonic(&[0; 16]);
        let with = |at: usize, word: &str| {
            let mut changed = words.map(str::to_string);
            changed[at] = word.to_string();
            changed.join(" ")
        };
        let vectors: Value = serde_json::from_str(include_str!(
            "../tests/vectors/python-mnemonic-b57a5ad-vectors.json"
        ))
        .unwrap();
        let first = |language: &str, count: usize| {
            vectors[language]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e[1].as_str().unwrap().to_string())
                .find(|m| m.split_whitespace().count() == count)
                .unwrap()
        };
        let english_24 = first("english", 24);
        assert!(
            bip39::Mnemonic::parse_normalized(&english_24).is_ok(),
            "a valid 24-word one"
        );
        for count in [11, 13, 15, 18] {
            let text = words
                .iter()
                .cycle()
                .take(count)
                .copied()
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(
                Seed::import(&text).err(),
                Some(ImportError::WordCount(count))
            );
        }
        assert_eq!(
            Seed::import(&english_24).err(),
            Some(ImportError::WordCount(24))
        );
        let unknown = |position| Some(ImportError::UnknownWord { position });
        assert_eq!(Seed::import(&with(2, "bitcoinx")).err(), unknown(3));
        assert_eq!(Seed::import(&with(0, "Abandon")).err(), unknown(1));
        assert_eq!(Seed::import(&with(11, "ABOUT")).err(), unknown(12));
        assert_eq!(Seed::import(&with(4, "aban")).err(), unknown(5));
        for language in ["spanish", "french", "italian", "czech"] {
            let other = first(language, 12);
            assert_eq!(Seed::import(&other).err(), unknown(1), "{language}");
        }
        for separator in ["\u{3000}", "\u{a0}"] {
            assert!(
                Seed::import(&words.join(separator)).is_err(),
                "{separator:?}"
            );
        }
        assert_eq!(
            Seed::import(&["abandon"; 12].join(" ")).err(),
            Some(ImportError::Checksum)
        );
    }

    #[test]
    fn import_tolerates_ascii_whitespace_only() {
        let canonical = mnemonic(&[0; 16]).join(" ");
        let wanted = Seed::import(&canonical).unwrap().bytes;
        for text in [
            format!("  {canonical}\n"),
            format!("\t{canonical} \r\n"),
            canonical.replace(' ', "\t"),
            canonical.replace(' ', "\n"),
            canonical.replace(' ', "   "),
        ] {
            assert_eq!(Seed::import(&text).unwrap().bytes, wanted, "{text:?}");
        }
    }

    /// `CNF-83`: "The mnemonic passphrase is empty regardless of local unlock passphrase."
    #[test]
    fn the_mnemonic_passphrase_is_empty() {
        // The seed function takes the mnemonic and nothing else: adding a passphrase parameter
        // stops this compiling.
        let from_words: fn([&'static str; 12]) -> Seed = Seed::from_words;
        let v1: Value =
            serde_json::from_str(&spec("docs/design/credential-vectors-v1.json")).unwrap();
        let seed = from_words(mnemonic(&[0; 16]));
        assert_eq!(hex::encode(seed.bytes), v1["bip39_seed_hex"]);
        let second = bip39::Mnemonic::from_entropy(&[0; 16]).unwrap();
        assert_eq!(second.to_seed_normalized(""), seed.bytes);
        assert_ne!(second.to_seed_normalized("unlock passphrase"), seed.bytes);
    }

    #[test]
    fn generate_gives_a_fresh_mnemonic_that_imports() {
        let (a, b) = (Seed::generate().unwrap(), Seed::generate().unwrap());
        assert_ne!(a.words, b.words);
        for seed in [a, b] {
            assert_eq!(seed.words.len(), 12);
            assert_eq!(
                Seed::import(&seed.words.join(" ")).unwrap().bytes,
                seed.bytes
            );
        }
    }

    #[test]
    fn debug_prints_no_secret() {
        let seed = vector_seed();
        assert_eq!(format!("{seed:?}"), "Seed(..)");
        let key = seed.relay_key(VERSION, 0).unwrap();
        assert_eq!(format!("{key:?}"), "RelayKey(..)");
        let key = seed.ssh_client_key(VERSION, 0).unwrap();
        assert_eq!(format!("{key:?}"), "SshClientKey(..)");
        let key = seed.attest_sender_key(VERSION, 0).unwrap();
        assert_eq!(format!("{key:?}"), "AttestSenderKey(..)");
        let key = seed.attest_recipient_key(VERSION, 0).unwrap();
        assert_eq!(format!("{key:?}"), "AttestRecipientKey(..)");
        let key = seed.post_harness_credential(VERSION, 0).unwrap();
        assert_eq!(format!("{key:?}"), "PostHarnessCredential(..)");
    }
}
