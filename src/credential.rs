//! The credential types the harness handles, each naming its row in `SEC-5`, the credential
//! inventory: "Every credential the harness holds or places MUST appear in the table below".
//! `CNF-13` blocks on a credential class with no row, and the tests below hold every type here to
//! the pinned table, and fail on a type in `src/` whose field types reveal key material without
//! a row, within the limits documented on `Scan` below.
//!
//! The secret-bearing types follow ADR-0024's discipline: no `Clone`, no `Serialize`, a `Debug`
//! that prints no byte of the secret, and raw bytes reachable only inside the crate, so a
//! credential cannot be copied into a log line or a prompt (`OVR-3`).

use std::fmt;

/// A credential type and its `SEC-5` row. Sealed: only this crate can implement it.
pub trait Credential: sealed::Sealed {
    /// The row's number in `SEC-5`'s table.
    const ROW: u8;
    /// The name the row's credential cell carries.
    const NAME: &'static str;
}

mod sealed {
    pub trait Sealed {}
}

/// Role 0: a machine's SSH client key, the child secret used as an RFC 8032 Ed25519 seed.
pub struct SshClientKey(pub(crate) [u8; 32]);

/// Role 1: a machine's attest sender key, a secp256k1 secret.
pub struct AttestSenderKey(pub(crate) [u8; 32]);

/// Role 2: a machine's attest recipient key, a secp256k1 secret.
pub struct AttestRecipientKey(pub(crate) [u8; 32]);

/// Role 3: a relay pass's relay key, a secp256k1 secret, which signs the relay AUTH.
pub struct RelayKey(pub(crate) [u8; 32]);

/// Role 4: a declared handoff's post-harness credential, an RFC 8032 Ed25519 seed.
pub struct PostHarnessCredential(pub(crate) [u8; 32]);

/// The local unlock passphrase (`STA-23`): the UTF-8 bytes the worker received, neither
/// normalized nor trimmed. Zeroized on drop, which comes as soon as the KDF has run.
pub struct LocalPassphrase(pub(crate) Vec<u8>);

/// The wrapping key PBKDF2 derives from the local passphrase. Zeroized on drop, right after the
/// data key is wrapped or unwrapped.
pub struct WrappingKey(pub(crate) [u8; 32]);

/// The local store's data key, which encrypts its journal; only its wrapped copy persists.
/// Zeroized on drop, when the store is dropped or its worker ends.
pub struct DataKey(pub(crate) [u8; 32]);

/// A machine's host-key pin: the `SHA256:…` fingerprint of its host key. An integrity
/// reference, not a secret: what the row says it authorizes is "Nothing — integrity reference".
#[derive(Debug, PartialEq, Eq)]
pub struct HostKeyPin(pub String);

impl sealed::Sealed for crate::seed::Seed {}
impl Credential for crate::seed::Seed {
    const ROW: u8 = 15;
    const NAME: &'static str = "Operator seed";
}

impl sealed::Sealed for SshClientKey {}
impl Credential for SshClientKey {
    const ROW: u8 = 3;
    const NAME: &'static str = "SSH client private key";
}

impl sealed::Sealed for AttestSenderKey {}
impl Credential for AttestSenderKey {
    const ROW: u8 = 7;
    const NAME: &'static str = "Attest sender key";
}

impl sealed::Sealed for AttestRecipientKey {}
impl Credential for AttestRecipientKey {
    const ROW: u8 = 16;
    const NAME: &'static str = "Attest recipient key";
}

impl sealed::Sealed for RelayKey {}
impl Credential for RelayKey {
    const ROW: u8 = 4;
    const NAME: &'static str = "Relay key";
}

impl sealed::Sealed for PostHarnessCredential {}
impl Credential for PostHarnessCredential {
    const ROW: u8 = 17;
    const NAME: &'static str = "Post-harness credential";
}

impl sealed::Sealed for HostKeyPin {}
impl Credential for HostKeyPin {
    const ROW: u8 = 5;
    const NAME: &'static str = "Host-key pins";
}

impl sealed::Sealed for LocalPassphrase {}
impl Credential for LocalPassphrase {
    const ROW: u8 = 18;
    const NAME: &'static str = "Local unlock passphrase";
}

impl sealed::Sealed for WrappingKey {}
impl Credential for WrappingKey {
    const ROW: u8 = 19;
    const NAME: &'static str = "Wrapping key";
}

impl sealed::Sealed for DataKey {}
impl Credential for DataKey {
    const ROW: u8 = 20;
    const NAME: &'static str = "Data-encryption key";
}

impl LocalPassphrase {
    /// Takes the bytes as received; the caller clears any other copy it holds.
    pub fn new(bytes: Vec<u8>) -> LocalPassphrase {
        LocalPassphrase(bytes)
    }
}

// `SEC-5` rows 18–20: "Input and buffers cleared after use", "Cleared after wrap/unwrap",
// "Cleared on lock/end". Best effort, as `STA-23` says ("Clearing buffers is best effort in a
// browser"): a copy the allocator moved is not reached.
impl Drop for LocalPassphrase {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl Drop for WrappingKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl Drop for DataKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl Drop for SshClientKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}
impl Drop for RelayKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// The Ed25519 public key of a 32-byte RFC 8032 seed, never an already-expanded scalar: the
/// mapping of roles 0 and 4.
pub(crate) fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

/// The BIP-340 x-only public key of a secp256k1 secret, or `None` outside 1..n−1: the mapping of
/// roles 1–3.
pub(crate) fn xonly_public(secret: &[u8; 32]) -> Option<[u8; 32]> {
    let key = k256::schnorr::SigningKey::from_bytes(secret).ok()?;
    Some(key.verifying_key().to_bytes().into())
}

impl SshClientKey {
    /// The raw 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        ed25519_public(&self.0)
    }
}

impl PostHarnessCredential {
    /// The raw 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        ed25519_public(&self.0)
    }
}

// Derivation only hands out secrets in 1..n−1, so the x-only key always exists.
const VALID: &str = "a secp256k1 credential holds a secret in 1..n-1";

impl AttestSenderKey {
    /// The BIP-340 x-only public key.
    pub fn public_key(&self) -> [u8; 32] {
        xonly_public(&self.0).expect(VALID)
    }
}

impl AttestRecipientKey {
    /// The BIP-340 x-only public key.
    pub fn public_key(&self) -> [u8; 32] {
        xonly_public(&self.0).expect(VALID)
    }
}

impl RelayKey {
    /// The BIP-340 x-only public key, the one its relay pass is bound to.
    pub fn public_key(&self) -> [u8; 32] {
        xonly_public(&self.0).expect(VALID)
    }
}

/// `Debug` names the type and nothing of the secret.
fn redacted(name: &str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{name}(..)")
}

impl fmt::Debug for crate::seed::Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted("Seed", f)
    }
}

impl fmt::Debug for SshClientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted("SshClientKey", f)
    }
}

impl fmt::Debug for AttestSenderKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted("AttestSenderKey", f)
    }
}

impl fmt::Debug for AttestRecipientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted("AttestRecipientKey", f)
    }
}

impl fmt::Debug for RelayKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted("RelayKey", f)
    }
}

impl fmt::Debug for PostHarnessCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted("PostHarnessCredential", f)
    }
}

impl fmt::Debug for LocalPassphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted("LocalPassphrase", f)
    }
}

impl fmt::Debug for WrappingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted("WrappingKey", f)
    }
}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted("DataKey", f)
    }
}

/// `CNF-13`: "Every credential the implementation handles appears as a row in `SEC-5`." Host
/// only: the scan parses with `syn`, a host-only dev-dependency.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use syn::visit::{self, Visit};

    /// Types the scan finds holding key material that are no credential, each with its reason.
    const EXEMPT: &[(&str, &str)] = &[
        (
            "StoreId",
            "the local store's ID: persisted in the clear in its envelope, and bound into every AAD",
        ),
        (
            "Salt",
            "the PBKDF2 salt: persisted in the clear in the envelope, as the format says",
        ),
        (
            "Address",
            "a record's content address, SHA-256 of its stored ciphertext record: persisted in the next record",
        ),
    ];

    /// Every type implementing `Credential`: its bare name, row and `NAME`.
    fn registered() -> Vec<(&'static str, u8, &'static str)> {
        fn entry<T: Credential>() -> (&'static str, u8, &'static str) {
            let name = std::any::type_name::<T>().rsplit("::").next().unwrap();
            (name, T::ROW, T::NAME)
        }
        vec![
            entry::<crate::seed::Seed>(),
            entry::<SshClientKey>(),
            entry::<AttestSenderKey>(),
            entry::<AttestRecipientKey>(),
            entry::<RelayKey>(),
            entry::<PostHarnessCredential>(),
            entry::<HostKeyPin>(),
            entry::<LocalPassphrase>(),
            entry::<WrappingKey>(),
            entry::<DataKey>(),
        ]
    }

    /// `SEC-5`'s table in `spec/04-security-model.md`, read from the pinned tree (`build.rs`
    /// refuses any other): each row's number and credential cell.
    fn sec5() -> BTreeMap<u8, String> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/spec/04-security-model.md");
        let text = std::fs::read_to_string(path).unwrap();
        let section = text.split("### SEC-5").nth(1).expect("a SEC-5 section");
        let section = section.split("\n#").next().unwrap();
        let table: BTreeMap<u8, String> = section
            .lines()
            .filter_map(|line| {
                let cells: Vec<&str> = line.split('|').map(str::trim).collect();
                Some((cells.get(1)?.parse().ok()?, cells.get(2)?.to_string()))
            })
            .collect();
        assert_eq!(
            table.keys().copied().collect::<Vec<_>>(),
            (1..=23).collect::<Vec<_>>()
        );
        table
    }

    /// A credential class's row must exist, be live (not struck through), be derivable today,
    /// and name the class in its credential cell.
    fn check_row(table: &BTreeMap<u8, String>, row: u8, name: &str) -> Result<(), String> {
        let cell = table
            .get(&row)
            .ok_or_else(|| format!("SEC-5 has no row {row}"))?;
        if cell.starts_with("~~") {
            return Err(format!("SEC-5 row {row} is retired: {cell}"));
        }
        if cell.contains("not derivable today") {
            return Err(format!("SEC-5 row {row} is not derivable today"));
        }
        if !cell.contains(name) {
            return Err(format!("SEC-5 row {row} does not name {name:?}: {cell}"));
        }
        Ok(())
    }

    #[test]
    fn every_credential_type_names_its_live_sec5_row() {
        let table = sec5();
        for (ty, row, name) in registered() {
            check_row(&table, row, name).unwrap_or_else(|e| panic!("{ty}: {e}"));
        }
    }

    #[test]
    fn the_row_check_refuses_retired_absent_and_misnamed_rows() {
        let table = sec5();
        for row in [8, 13, 22, 24, 99] {
            assert!(check_row(&table, row, "").is_err(), "row {row}");
        }
        assert!(check_row(&table, 4, "SSH client private key").is_err());
        assert!(check_row(&table, 3, "SSH client private key").is_ok());
    }

    /// What one parse finds: types holding key material by a field's type, the types
    /// implementing `Credential`, and how many type definitions carry each name. Modules under
    /// `#[cfg(test)]` or `#[cfg(all(test, …))]` are skipped: they compile only into tests, and
    /// hold test code, not credentials the harness handles. A guardrail, not a proof: a key in a
    /// `String` or a `Vec<u8>` is not seen, which is why the pin type is registered by hand.
    /// A union's fields are not checked; only its name is counted for the defined-twice rule.
    /// A key type imported under another name (for example `use ed25519_dalek::SigningKey as Sk;`)
    /// is not seen: key types are matched by the last segment of the path as written.
    ///
    /// Types are known by bare name, so a name defined twice is refused rather than resolved
    /// (`unregistered`): a second `RelayKey` cannot pass on the registered one's `impl`.
    #[derive(Default)]
    struct Scan {
        holders: BTreeSet<String>,
        registered: BTreeSet<String>,
        defined: BTreeMap<String, usize>,
    }

    impl Scan {
        fn define(&mut self, ident: &syn::Ident, holds_key: bool) {
            *self.defined.entry(ident.to_string()).or_default() += 1;
            if holds_key {
                self.holders.insert(ident.to_string());
            }
        }
    }

    /// Key material by type: a `u8` array of 16, 32 or 64 bytes, or of a length that is not an
    /// integer literal (`[u8; KEY_LEN]`), anywhere in the type (inside an `Option`, a tuple, a
    /// reference), or a secret key type of k256, ed25519-dalek, russh or ssh-key.
    #[derive(Default)]
    struct HoldsKey(bool);

    const KEY_TYPES: [&str; 7] = [
        "SigningKey",
        "SecretKey",
        "NonZeroScalar",
        "Scalar",
        "PrivateKey",
        "Ed25519Keypair",
        "Ed25519PrivateKey",
    ];

    impl<'ast> Visit<'ast> for HoldsKey {
        fn visit_type_array(&mut self, array: &'ast syn::TypeArray) {
            let byte = matches!(&*array.elem, syn::Type::Path(p) if p.path.is_ident("u8"));
            let key_length = match &array.len {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Int(n),
                    ..
                }) => matches!(n.base10_parse::<usize>(), Ok(16 | 32 | 64)),
                _ => true,
            };
            self.0 |= byte && key_length;
            visit::visit_type_array(self, array);
        }

        fn visit_path(&mut self, path: &'ast syn::Path) {
            let last = path.segments.last().map(|s| s.ident.to_string());
            self.0 |= last.is_some_and(|l| KEY_TYPES.contains(&l.as_str()));
            visit::visit_path(self, path);
        }
    }

    fn holds_key<'a>(types: impl IntoIterator<Item = &'a syn::Type>) -> bool {
        let mut found = HoldsKey::default();
        types.into_iter().for_each(|ty| found.visit_type(ty));
        found.0
    }

    fn cfg_test(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|attr| match &attr.meta {
            syn::Meta::List(list) if list.path.is_ident("cfg") => {
                let tokens = list.tokens.to_string();
                tokens == "test" || tokens.starts_with("all (test ,")
            }
            _ => false,
        })
    }

    impl<'ast> Visit<'ast> for Scan {
        fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
            if !cfg_test(&module.attrs) {
                visit::visit_item_mod(self, module);
            }
        }

        fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
            self.define(&item.ident, holds_key(item.fields.iter().map(|f| &f.ty)));
            visit::visit_item_struct(self, item);
        }

        fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
            let fields = item.variants.iter().flat_map(|v| &v.fields);
            self.define(&item.ident, holds_key(fields.map(|f| &f.ty)));
            visit::visit_item_enum(self, item);
        }

        fn visit_item_union(&mut self, item: &'ast syn::ItemUnion) {
            self.define(&item.ident, false);
            visit::visit_item_union(self, item);
        }

        fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
            self.define(&item.ident, holds_key([&*item.ty]));
            visit::visit_item_type(self, item);
        }

        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            let credential = item.trait_.as_ref().and_then(|(_, t, _)| t.segments.last());
            if credential.is_some_and(|t| t.ident == "Credential")
                && let syn::Type::Path(ty) = &*item.self_ty
            {
                let name = ty.path.segments.last().unwrap().ident.to_string();
                self.registered.insert(name);
            }
            visit::visit_item_impl(self, item);
        }
    }

    fn scan(scan: &mut Scan, source: &str) {
        scan.visit_file(&syn::parse_file(source).unwrap());
    }

    /// Every `.rs` file under `src/`, `cfg`-gated ones (`harness/run.rs`, `testonly.rs`)
    /// included.
    fn scan_src() -> Scan {
        fn walk(dir: &std::path::Path, found: &mut Scan) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, found);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    scan(found, &std::fs::read_to_string(&path).unwrap());
                }
            }
        }
        let mut found = Scan::default();
        walk(
            concat!(env!("CARGO_MANIFEST_DIR"), "/src").as_ref(),
            &mut found,
        );
        found
    }

    /// What fails the scan: a holder or registered name defined by more than one type, named
    /// with its count; then each holder neither registered nor in `EXEMPT`.
    fn unregistered(scan: &Scan) -> Vec<String> {
        let duplicates = scan.holders.union(&scan.registered).filter_map(|ty| {
            let n = scan.defined.get(ty).copied().unwrap_or(0);
            (n > 1).then(|| format!("{ty} (defined {n} times)"))
        });
        let unrowed = scan
            .holders
            .iter()
            .filter(|ty| !scan.registered.contains(*ty))
            .filter(|ty| !EXEMPT.iter().any(|(name, _)| name == ty))
            .cloned();
        duplicates.chain(unrowed).collect()
    }

    #[test]
    fn every_type_holding_key_material_has_a_row() {
        let found = scan_src();
        assert!(found.holders.contains("SshClientKey"), "the scan sees src/");
        let unregistered = unregistered(&found);
        assert!(
            unregistered.is_empty(),
            "types holding key material with no SEC-5 row, or an ambiguous name: {unregistered:?}"
        );
    }

    #[test]
    fn the_scan_finds_unregistered_key_holders_in_every_form() {
        let mut found = Scan::default();
        scan(
            &mut found,
            r#"
            struct Named { secret: [u8; 32] }
            struct Tuple(pub(crate) Option<[u8; 64]>);
            enum Variant { Empty, Key { k: k256::schnorr::SigningKey } }
            type Alias = (u16, [u8; 16]);
            struct Wrapped(Box<russh::keys::PrivateKey>);
            const KEY_LEN: usize = 32;
            struct ConstLen([u8; KEY_LEN]);
            struct Digest([u8; 20]);
            struct Registered([u8; 32]);
            impl Credential for Registered {}
            struct RelayKey([u8; 32]);
            impl Credential for RelayKey {}
            mod overlooked { struct RelayKey([u8; 32]); }
            #[cfg(test)]
            mod tests { struct InTests([u8; 32]); }
            #[cfg(all(test, not(target_arch = "wasm32")))]
            mod host_tests { struct InHostTests([u8; 32]); }
            "#,
        );
        assert_eq!(
            unregistered(&found),
            [
                "RelayKey (defined 2 times)",
                "Alias",
                "ConstLen",
                "Named",
                "Tuple",
                "Variant",
                "Wrapped"
            ]
        );
    }

    /// The types the scan finds implementing `Credential` are exactly the ones the pinned-table
    /// test checks, so no registered type skips it.
    #[test]
    fn the_scan_and_the_table_check_agree() {
        let checked: BTreeSet<String> = registered()
            .iter()
            .map(|(ty, _, _)| ty.to_string())
            .collect();
        assert_eq!(scan_src().registered, checked);
    }
}
