//! The local store (`STA-23`): the harness worker's encrypted, append-only journal, written by
//! that worker alone (`STA-1`), in the browser's origin-private file system (`STA-2`, spec
//! ADR-0022). Credential format v1, "Local encryption envelope"
//! (`spec/docs/design/credential-format-v1.md`), is followed exactly:
//!
//! - **The envelope**, `envelope.json`: a fresh 32-byte data key, wrapped with AES-256-GCM under
//!   a wrapping key PBKDF2-HMAC-SHA-256 derives from the local passphrase (600,000 iterations, a
//!   fresh 16-byte salt), with the AAD `tau-web/local/v1/<id>`. It is parsed strictly, and every
//!   structural refusal comes before the KDF runs.
//! - **One file per record**, named by its record number in unsigned decimal, the first `0`. Each
//!   record is encrypted separately under the data key, with the AAD
//!   `tau-web/local/v1/<id>/<type>/<number>/<previous>`, `previous` being the predecessor's
//!   content address.
//! - **The commit boundary.** A file under a record name, or under the envelope's, is only ever
//!   made by moving a complete, closed staging file onto it: in OPFS, `getFileHandle(create)`
//!   makes an empty entry at once, so writing the final name directly could leave an empty
//!   record behind a killed worker. A record-named file therefore always holds a complete
//!   record, and one that fails to parse, decrypt or chain is corruption: replay stops and the
//!   store is refused. An append commits when the move resolves; only then is it applied
//!   (`STA-3`).
//! - **Never onto an existing name.** Chromium's `move()` overwrites silently, so after any
//!   failed append (whose move may still have landed) the store refuses further appends until
//!   the worker restarts and re-reads the directory.
//!
//! - **Allocation** (`STA-22b`). Every allocation event is a record of its own, appended before it
//!   is applied, and replay applies each through the same core (`crate::allocation`). A record
//!   the core cannot apply stops replay and refuses the store.
//!
//! What it does not detect, as the format says: the rollback of the whole store, a missing tail
//! of records included.
//!
//! The format and its validation are built on every target, so host tests run them on
//! `MemoryStorage`; the browser's storage and KDF are `opfs` (wasm32 only).

use crate::allocation::{self, Family, Identity, Metadata};
use crate::credential::{DataKey, LocalPassphrase, WrappingKey};
use crate::harness::{Entry, Journal};
use crate::seed::Seed;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_arch = "wasm32")]
pub mod opfs;

/// The directory the store owns in the origin-private file system.
pub const DIRECTORY: &str = "tau-web-store";
/// The envelope's file name.
pub const ENVELOPE: &str = "envelope.json";
/// The one staging name, which is never a record name or the envelope's.
pub const STAGING: &str = "staging";
/// The first record number: the seed record's.
pub const FIRST: u64 = 0;
/// PBKDF2-HMAC-SHA-256's work factor, the format's and nothing else.
pub const ITERATIONS: u32 = 600_000;
/// The shortest local passphrase, in Unicode code points.
pub const MIN_PASSPHRASE: usize = 16;

/// What a failed unlock reports. A wrong passphrase and a modified envelope fail the same tag,
/// so it claims neither.
pub const WRONG: &str = "wrong passphrase, or the store was modified";

/// The store's 16-byte ID, persisted in the clear.
pub struct StoreId(pub [u8; 16]);

/// The PBKDF2 salt, persisted in the clear.
pub struct Salt(pub [u8; 16]);

/// A record's content address: SHA-256 over the exact bytes stored in its file.
pub struct Address(pub [u8; 32]);

/// Where the store's files live: the directory it owns. The browser's is OPFS (`opfs::Opfs`), the
/// host tests' `MemoryStorage`.
#[allow(
    async_fn_in_trait,
    reason = "used generically and only on one thread: the browser's worker, or a host test"
)]
pub trait Storage {
    /// The names in the store's directory; none if the directory does not exist.
    async fn list(&self) -> Result<Vec<String>, String>;
    /// The bytes of `name`.
    async fn read(&self, name: &str) -> Result<Vec<u8>, String>;
    /// Writes `bytes` as the whole of `name`, creating it if absent. In OPFS this is
    /// `getFileHandle(name, { create: true })`, which makes an empty entry at once, then
    /// `createWritable()`, `write()` and `close()`, which commits the contents.
    async fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String>;
    /// Moves `from` onto `to`, which silently replaces an existing `to`.
    async fn rename(&self, from: &str, to: &str) -> Result<(), String>;
}

/// PBKDF2-HMAC-SHA-256 at [`ITERATIONS`], 32 bytes out: WebCrypto's in the worker, the `pbkdf2`
/// crate's on the host. It takes the passphrase by value, so the passphrase is dropped, and
/// zeroized, as soon as the derivation has run.
#[allow(
    async_fn_in_trait,
    reason = "used generically and only on one thread: the browser's worker, or a host test"
)]
pub trait Kdf {
    async fn derive(&self, passphrase: LocalPassphrase, salt: &Salt)
    -> Result<WrappingKey, String>;
}

/// The host's KDF, the same derivation as WebCrypto's.
#[cfg(not(target_arch = "wasm32"))]
pub struct Pbkdf2;

#[cfg(not(target_arch = "wasm32"))]
impl Kdf for Pbkdf2 {
    async fn derive(
        &self,
        passphrase: LocalPassphrase,
        salt: &Salt,
    ) -> Result<WrappingKey, String> {
        let mut key = WrappingKey([0; 32]);
        pbkdf2_sha256(&passphrase.0, &salt.0, ITERATIONS, &mut key.0);
        Ok(key)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn pbkdf2_sha256(passphrase: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, salt, iterations, out);
}

/// The envelope as stored: exactly these fields, each of exactly this JSON type.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeJson {
    version: u64,
    purpose: String,
    id: String,
    kdf: String,
    iterations: u64,
    salt: String,
    nonce: String,
    wrapped_key: String,
}

/// A record as stored, its "journal envelope": the AAD's fields, the nonce, and the ciphertext
/// followed by its tag. The number is a JSON number, so leading zeros are not JSON at all. Stored
/// as exactly this serialization: a JSON object with these members in this order, no
/// whitespace, binary fields as unpadded base64url; any other bytes are refused.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordJson {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    number: u64,
    previous: String,
    nonce: String,
    ciphertext: String,
}

/// What a record carries, encrypted. The first record is the seed, every later one a command or
/// an allocation event.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum Event {
    /// The operator seed's mnemonic, so a seed-backup ceremony can show the words.
    Seed { mnemonic: String },
    /// One box-plane command, recorded before it is sent (`ARC-8`): its bytes as hex.
    Command { machine: String, command: String },
    /// One allocation event, recorded before it is applied: a reservation before any external
    /// effect (`STA-22b`), with its seed identifier and derivation version (`STA-22a`).
    Allocation(allocation::Event),
}

impl Drop for Event {
    fn drop(&mut self) {
        if let Event::Seed { mnemonic } = self {
            mnemonic.zeroize();
        }
    }
}

/// Only `event` records exist yet: snapshots are later work, and a record of type `snapshot` is
/// refused as unsupported.
const EVENT: &str = "event";

fn envelope_aad(id: &str) -> String {
    format!("tau-web/local/v1/{id}")
}

/// `<id>` is the envelope's encoded ID, unpadded base64url. The format's envelope AAD uses "the
/// encoded ID" and its record template the same `<id>`, so this is read as the same string.
fn record_aad(id: &str, kind: &str, number: u64, previous: &str) -> String {
    format!("tau-web/local/v1/{id}/{kind}/{number}/{previous}")
}

fn cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key).expect("a 32-byte key")
}

/// Unpadded base64url of exactly `N` bytes: padding, the standard alphabet's `+` and `/`, and
/// non-canonical trailing bits are all refused.
fn decode<const N: usize>(field: &str, text: &str) -> Result<[u8; N], String> {
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|e| format!("{field}: not unpadded base64url ({e})"))?,
    );
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{field}: {} bytes, not {N}", bytes.len()))
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|e| format!("getrandom: {e}"))?;
    Ok(bytes)
}

/// The envelope, parsed and checked: everything the KDF and the unwrap need.
struct Envelope {
    id: String,
    salt: Salt,
    nonce: [u8; 12],
    wrapped_key: [u8; 48],
}

impl Envelope {
    /// Refuses, before any KDF: input that is not JSON; a field missing, unknown or of the wrong
    /// type; another version, purpose, KDF or iteration count; a field of the wrong length or not
    /// unpadded base64url.
    fn parse(bytes: &[u8]) -> Result<Envelope, String> {
        let json: EnvelopeJson = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if json.version != 1 {
            return Err(format!("version {}, not 1", json.version));
        }
        if json.purpose != "local" {
            return Err(format!("purpose {:?}, not \"local\"", json.purpose));
        }
        if json.kdf != "PBKDF2-SHA256" {
            return Err(format!("kdf {:?}, not \"PBKDF2-SHA256\"", json.kdf));
        }
        if json.iterations != u64::from(ITERATIONS) {
            return Err(format!("{} iterations, not {ITERATIONS}", json.iterations));
        }
        decode::<16>("id", &json.id)?;
        Ok(Envelope {
            salt: Salt(decode("salt", &json.salt)?),
            nonce: decode("nonce", &json.nonce)?,
            wrapped_key: decode("wrapped_key", &json.wrapped_key)?,
            id: json.id,
        })
    }
}

/// Whether `name` is a record name: unsigned decimal without leading zeros. Anything else that is
/// not the envelope's name (a staging file, a browser swap file) is not a record.
fn is_record_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_digit())
        && (name == "0" || !name.starts_with('0'))
}

/// What the store's directory holds, before any unlock.
#[derive(Debug, PartialEq, Eq)]
pub enum Found {
    /// No envelope and no record-named file: the only state in which a store is created.
    NoStore,
    /// An envelope, to unlock.
    Envelope,
}

/// Reads the directory. Records without an envelope are refused, never "no store".
pub async fn probe(storage: &impl Storage) -> Result<Found, String> {
    let names = storage.list().await?;
    let envelope = names.iter().any(|n| n == ENVELOPE);
    let records = names.iter().any(|n| is_record_name(n));
    match (envelope, records) {
        (true, _) => Ok(Found::Envelope),
        (false, false) => Ok(Found::NoStore),
        (false, true) => Err("records without an envelope".into()),
    }
}

/// Why a create or an unlock did not give a store.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// The input was refused and nothing was attempted: the state is unchanged.
    Input(String),
    /// The store is refused (fail closed).
    Refused(String),
}

/// An unlocked store: the data key, the chain's head, and the state replayed from the journal.
pub struct Store<S> {
    storage: S,
    key: DataKey,
    id: String,
    /// The number the next append takes.
    next: u64,
    /// The content address of the record before `next`; zeros before the first.
    previous: Address,
    seed: Option<Seed>,
    /// The allocation metadata, from the seed record on.
    allocation: Option<Metadata>,
    commands: Vec<(u64, Entry)>,
    /// Set by a failed append, whose move may have landed: no append follows in this worker.
    failed: Option<String>,
}

/// Creates a store where there is none: the envelope first, then the seed record. A worker killed
/// between the two leaves an envelope with no record, which an unlock with that envelope's
/// passphrase finishes by generating the seed (`Store::finish_creation`); a worker killed before
/// the envelope's move leaves no store, at most a staging file.
pub async fn create<S: Storage>(
    storage: S,
    kdf: &impl Kdf,
    passphrase: LocalPassphrase,
) -> Result<Store<S>, Failure> {
    // Counted as Unicode code points of the UTF-8 received, never UTF-16 units; neither
    // normalized nor trimmed.
    let length = std::str::from_utf8(&passphrase.0)
        .map_err(|_| Failure::Input("The passphrase is not UTF-8.".into()))?
        .chars()
        .count();
    if length < MIN_PASSPHRASE {
        return Err(Failure::Input(format!(
            "The passphrase has {length} characters; at least {MIN_PASSPHRASE} are needed."
        )));
    }
    match probe(&storage).await {
        Ok(Found::NoStore) => {}
        Ok(Found::Envelope) => return Err(Failure::Refused("a store already exists".into())),
        Err(e) => return Err(Failure::Refused(e)),
    }
    let refused = Failure::Refused;
    let id = URL_SAFE_NO_PAD.encode(StoreId(random()?).0);
    let salt = Salt(random().map_err(refused)?);
    let nonce: [u8; 12] = random().map_err(refused)?;
    let mut key = DataKey([0; 32]);
    getrandom::fill(&mut key.0).map_err(|e| Failure::Refused(format!("getrandom: {e}")))?;
    let wrapping = kdf.derive(passphrase, &salt).await.map_err(refused)?;
    let wrapped_key = cipher(&wrapping.0)
        .encrypt(
            &nonce.into(),
            Payload {
                msg: &key.0,
                aad: envelope_aad(&id).as_bytes(),
            },
        )
        .expect("AES-GCM seals 32 bytes");
    drop(wrapping);
    let envelope = serde_json::to_vec(&EnvelopeJson {
        version: 1,
        purpose: "local".into(),
        id: id.clone(),
        kdf: "PBKDF2-SHA256".into(),
        iterations: ITERATIONS.into(),
        salt: URL_SAFE_NO_PAD.encode(salt.0),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        wrapped_key: URL_SAFE_NO_PAD.encode(wrapped_key),
    })
    .expect("the envelope serializes");
    storage.write(STAGING, &envelope).await.map_err(refused)?;
    storage.rename(STAGING, ENVELOPE).await.map_err(refused)?;
    let mut store = Store::new(storage, key, id);
    store.finish_creation().await.map_err(refused)?;
    Ok(store)
}

impl From<String> for Failure {
    fn from(why: String) -> Failure {
        Failure::Refused(why)
    }
}

/// Unlocks the store: the envelope is parsed strictly, then the wrapping key derived and
/// cleared once the data key is unwrapped, then every record replayed in order. Any failure is a
/// refusal, and nothing is written.
pub async fn unlock<S: Storage>(
    storage: S,
    kdf: &impl Kdf,
    passphrase: LocalPassphrase,
) -> Result<Store<S>, String> {
    if probe(&storage).await? != Found::Envelope {
        return Err("there is no store to unlock".into());
    }
    let envelope = Envelope::parse(&storage.read(ENVELOPE).await?)
        .map_err(|e| format!("the envelope is not a v1 local envelope: {e}"))?;
    let wrapping = kdf.derive(passphrase, &envelope.salt).await?;
    let unwrapped = cipher(&wrapping.0).decrypt(
        &envelope.nonce.into(),
        Payload {
            msg: &envelope.wrapped_key,
            aad: envelope_aad(&envelope.id).as_bytes(),
        },
    );
    drop(wrapping);
    let unwrapped = Zeroizing::new(unwrapped.map_err(|_| WRONG.to_string())?);
    let mut key = DataKey([0; 32]);
    key.0.copy_from_slice(&unwrapped);
    let mut store = Store::new(storage, key, envelope.id);
    store.replay().await?;
    if store.next == FIRST {
        store.finish_creation().await?;
    }
    Ok(store)
}

impl<S: Storage> Store<S> {
    fn new(storage: S, key: DataKey, id: String) -> Store<S> {
        Store {
            storage,
            key,
            id,
            next: FIRST,
            previous: Address([0; 32]),
            seed: None,
            allocation: None,
            commands: Vec::new(),
            failed: None,
        }
    }

    /// The storage the store writes to.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// The operator seed, from the first record.
    pub fn seed(&self) -> Option<&Seed> {
        self.seed.as_ref()
    }

    /// The record numbers, in order.
    pub fn records(&self) -> std::ops::Range<u64> {
        FIRST..self.next
    }

    /// The allocation metadata (`STA-22b`), as journaled.
    pub fn allocation(&self) -> &Metadata {
        self.allocation
            .as_ref()
            .expect("a created or unlocked store holds its seed")
    }

    /// Reserves `family`'s next unused index (`STA-22`, `STA-22b`): the core issues it, the
    /// reservation is appended, applied once the append commits (`STA-3`), and only then
    /// returned. The caller names no index, so no call reserves a recorded one (`CNF-72`).
    pub async fn allocate(&mut self, family: Family) -> Result<Identity, String> {
        let identity = self.allocation().issue(family).map_err(|e| e.to_string())?;
        self.record(allocation::Event::Reserve(identity.clone()))
            .await?;
        Ok(identity)
    }

    /// Journals an adapter's observation of an identity: created, failed or destroyed. One the
    /// metadata cannot apply is refused and never journaled.
    pub async fn observe(&mut self, observation: allocation::Event) -> Result<(), String> {
        use allocation::Event::{Created, Destroyed, Failed};
        if !matches!(observation, Created(_) | Failed(_) | Destroyed(_)) {
            return Err("only created, failed and destroyed are observations".into());
        }
        self.record(observation).await
    }

    /// Appends `event` if the core applies it, then applies it once committed.
    async fn record(&mut self, event: allocation::Event) -> Result<(), String> {
        let mut next = self.allocation().clone();
        next.apply(&event).map_err(|e| e.to_string())?;
        self.commit(&Event::Allocation(event)).await?;
        self.allocation = Some(next);
        Ok(())
    }

    /// The recorded commands, by record number. None has a terminal record yet (twr-ggw.7), so
    /// every one of them may have been sent.
    pub fn commands(&self) -> &[(u64, Entry)] {
        &self.commands
    }

    /// Generates the seed inside the worker and appends it as the first record. Only for a
    /// store with no record: a store that holds a seed never gets another.
    async fn finish_creation(&mut self) -> Result<(), String> {
        assert_eq!(self.next, FIRST, "a seed only for a store with no record");
        let seed = Seed::generate().map_err(|e| format!("getrandom: {e}"))?;
        self.commit(&Event::Seed {
            mnemonic: seed.phrase().to_string(),
        })
        .await?;
        self.allocation = Some(Metadata::new(seed.id()));
        self.seed = Some(seed);
        Ok(())
    }

    /// Replays every record from the first, in order: a record that fails to parse, decrypt or
    /// chain, or a missing number before a later record, stops replay and refuses the store.
    /// Names that are not record names are not records, and are ignored.
    async fn replay(&mut self) -> Result<(), String> {
        let mut numbers = Vec::new();
        for name in self.storage.list().await? {
            if is_record_name(&name) {
                let number: u64 = name
                    .parse()
                    .map_err(|_| format!("record {name}: the number is out of range"))?;
                numbers.push(number);
            }
        }
        numbers.sort_unstable();
        for (expected, number) in (FIRST..).zip(numbers) {
            if number != expected {
                return Err(format!(
                    "record {expected} is missing before record {number}; replay stopped"
                ));
            }
            let bytes = self.storage.read(&number.to_string()).await?;
            let event = self
                .open(number, &bytes)
                .map_err(|e| format!("record {number}: {e}; replay stopped"))?;
            match (number, &event) {
                (FIRST, Event::Seed { mnemonic }) => {
                    let seed = Seed::import(mnemonic).map_err(|e| {
                        format!("record {number}: the seed does not import ({e:?}); replay stopped")
                    })?;
                    self.allocation = Some(Metadata::new(seed.id()));
                    self.seed = Some(seed);
                }
                (FIRST, _) => return Err("the first record is not the seed; replay stopped".into()),
                (_, Event::Command { machine, command }) => {
                    let command = hex::decode(command)
                        .map_err(|e| format!("record {number}: {e}; replay stopped"))?;
                    self.commands.push((
                        number,
                        Entry {
                            machine: machine.clone(),
                            command,
                        },
                    ));
                }
                (_, Event::Allocation(event)) => {
                    let allocation = self.allocation.as_mut().expect("record 0 is the seed");
                    let applied = match event {
                        // The store holds one seed, record 0's: a replace would move allocation
                        // to a seed it cannot derive from (twr-ggw.29 opens this).
                        allocation::Event::Replace { .. } => {
                            Err("a replace, and the store holds one seed".to_string())
                        }
                        allocation::Event::Restore(export)
                            if export.seed() != allocation.seed() =>
                        {
                            Err("a restore of another seed's metadata".to_string())
                        }
                        event => allocation.apply(event).map_err(|e| e.to_string()),
                    };
                    applied.map_err(|e| format!("record {number}: {e}; replay stopped"))?;
                }
                (_, Event::Seed { .. }) => {
                    return Err(format!(
                        "record {number}: a second seed record; replay stopped"
                    ));
                }
            }
            self.next = number + 1;
            self.previous = Address(Sha256::digest(&bytes).into());
        }
        Ok(())
    }

    /// Parses, checks and decrypts the record stored as `bytes` under `number`.
    fn open(&self, number: u64, bytes: &[u8]) -> Result<Event, String> {
        let record: RecordJson = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        // Only this serialization is ever written, so any other bytes are a modification, even
        // one the parser tolerates (whitespace after the last record, where no successor's
        // `previous` would catch it). It is compared, never hashed in place of the stored bytes.
        if serde_json::to_vec(&record).ok().as_deref() != Some(bytes) {
            return Err("it is not stored as written".into());
        }
        if record.id != self.id {
            return Err("it belongs to another store".into());
        }
        match record.kind.as_str() {
            EVENT => {}
            "snapshot" => return Err("snapshots are not supported".into()),
            other => return Err(format!("unknown type {other:?}")),
        }
        if record.number != number {
            return Err(format!("it carries number {}", record.number));
        }
        let previous = hex::encode(self.previous.0);
        if record.previous != previous {
            return Err("it does not follow its predecessor".into());
        }
        let nonce: [u8; 12] = decode("nonce", &record.nonce)?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&record.ciphertext)
            .map_err(|e| format!("ciphertext: not unpadded base64url ({e})"))?;
        let plaintext = Zeroizing::new(
            cipher(&self.key.0)
                .decrypt(
                    &nonce.into(),
                    Payload {
                        msg: &ciphertext,
                        aad: record_aad(&self.id, EVENT, number, &previous).as_bytes(),
                    },
                )
                .map_err(|_| "authentication failed".to_string())?,
        );
        // The parser's message would quote the plaintext, and the reason reaches the page.
        serde_json::from_slice(&plaintext)
            .map_err(|_| "its event is not one this version reads".to_string())
    }

    /// Encrypts `event` as the record numbered `next` and commits it: written whole under the
    /// staging name, then moved onto its own name. The caller applies it only once this returns.
    async fn commit(&mut self, event: &Event) -> Result<u64, String> {
        if let Some(why) = &self.failed {
            return Err(format!(
                "an earlier append failed ({why}), so none follows until the worker restarts"
            ));
        }
        let number = self.next;
        // Credential format v1: "Never perform 2^32 encryptions under one data key". Record 0 is
        // the first, so record 2^32 - 1 would be the 2^32nd. Nothing is written, so no move can
        // have landed. Re-encrypting under a fresh key does not exist yet: appends stop here.
        if number >= u64::from(u32::MAX) {
            return Err(format!(
                "record {number} would be the 2^32nd encryption under this store's data key"
            ));
        }
        let previous = hex::encode(self.previous.0);
        let nonce: [u8; 12] = random()?;
        let plaintext = Zeroizing::new(serde_json::to_vec(event).expect("an event serializes"));
        let ciphertext = cipher(&self.key.0)
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plaintext,
                    aad: record_aad(&self.id, EVENT, number, &previous).as_bytes(),
                },
            )
            .map_err(|_| "AES-GCM refused the record".to_string())?;
        let bytes = serde_json::to_vec(&RecordJson {
            id: self.id.clone(),
            kind: EVENT.into(),
            number,
            previous,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
        .expect("a record serializes");
        let written = match self.storage.write(STAGING, &bytes).await {
            Ok(()) => self.storage.rename(STAGING, &number.to_string()).await,
            Err(e) => Err(e),
        };
        if let Err(e) = written {
            self.failed = Some(e.clone());
            return Err(e);
        }
        self.next = number + 1;
        self.previous = Address(Sha256::digest(&bytes).into());
        Ok(number)
    }
}

impl<S: Storage> Journal for Store<S> {
    /// Appends the command's record, and applies it once committed (`STA-3`).
    async fn append(&mut self, entry: &Entry) -> Result<u64, String> {
        let number = self
            .commit(&Event::Command {
                machine: entry.machine.clone(),
                command: hex::encode(&entry.command),
            })
            .await?;
        self.commands.push((number, entry.clone()));
        Ok(number)
    }

    async fn read(&self, seq: u64) -> Option<Entry> {
        self.commands
            .iter()
            .find(|(number, _)| *number == seq)
            .map(|(_, entry)| entry.clone())
    }
}

/// The harness worker's store, as the page sees it: exactly one state at a time. A refusal is
/// final for this worker: it never becomes "no store", so Create is never offered after a failed
/// unlock or a corrupt store (`STA-23`: they "fail closed without creating a replacement store").
pub enum State<S> {
    /// The directory has not been read yet: the worker has not got the writer lock.
    Unopened,
    NoStore,
    Locked,
    Unlocked(Box<Store<S>>),
    Refused(String),
}

/// The store's state machine, which the worker's exports drive.
pub struct Local<S, K> {
    storage: S,
    kdf: K,
    state: State<S>,
}

impl<S: Storage + Clone, K: Kdf> Local<S, K> {
    pub fn new(storage: S, kdf: K) -> Local<S, K> {
        Local {
            storage,
            kdf,
            state: State::Unopened,
        }
    }

    /// Reads the directory, once the worker holds the writer lock.
    pub async fn open(&mut self) -> Value {
        if let State::Unopened = self.state {
            self.state = match probe(&self.storage).await {
                Ok(Found::NoStore) => State::NoStore,
                Ok(Found::Envelope) => State::Locked,
                Err(e) => State::Refused(e),
            };
        }
        self.report(None)
    }

    /// Creates a store, only where there is none.
    pub async fn create(&mut self, passphrase: LocalPassphrase) -> Value {
        if !matches!(self.state, State::NoStore) {
            return self.report(Some("a store is created only where there is none"));
        }
        match create(self.storage.clone(), &self.kdf, passphrase).await {
            Ok(store) => self.state = State::Unlocked(Box::new(store)),
            Err(Failure::Input(why)) => return self.report(Some(&why)),
            Err(Failure::Refused(why)) => self.state = State::Refused(why),
        }
        self.report(None)
    }

    /// Unlocks the store, only when locked. A failure refuses it for this worker.
    pub async fn unlock(&mut self, passphrase: LocalPassphrase) -> Value {
        if !matches!(self.state, State::Locked) {
            return self.report(Some("only a locked store is unlocked"));
        }
        self.state = match unlock(self.storage.clone(), &self.kdf, passphrase).await {
            Ok(store) => State::Unlocked(Box::new(store)),
            Err(why) => State::Refused(why),
        };
        self.report(None)
    }

    /// The unlocked store, if any.
    pub fn store(&mut self) -> Option<&mut Store<S>> {
        match &mut self.state {
            State::Unlocked(store) => Some(store),
            _ => None,
        }
    }

    /// The state the page shows: `none`, `locked`, `unlocked` or `refused` with its reason, and
    /// an `error` for a request that changed nothing.
    pub fn report(&self, error: Option<&str>) -> Value {
        let mut report = match &self.state {
            State::Unopened => json!({ "state": "unopened" }),
            State::NoStore => json!({ "state": "none" }),
            State::Locked => json!({ "state": "locked" }),
            State::Unlocked(_) => json!({ "state": "unlocked" }),
            State::Refused(why) => json!({ "state": "refused", "reason": why }),
        };
        if let Some(error) = error {
            report["error"] = error.into();
        }
        report
    }

    /// The replayed state, for the tracer to read in the worker's own context: whether the store
    /// is locked, the record numbers, and each recorded command's machine and bytes as hex. No
    /// key material, and nothing of the seed record but its number.
    pub fn inspect(&self) -> Value {
        let mut report = self.report(None);
        report["locked"] = (!matches!(self.state, State::Unlocked(_))).into();
        if let State::Unlocked(store) = &self.state {
            report["records"] = store.records().collect::<Vec<_>>().into();
            report["commands"] = store
                .commands()
                .iter()
                .map(|(number, entry)| {
                    json!({
                        "number": number,
                        "machine": entry.machine,
                        "command": hex::encode(&entry.command),
                    })
                })
                .collect::<Vec<_>>()
                .into();
        }
        report
    }
}

/// The host tests' storage: files in memory, with OPFS's behaviour as measured in Chromium 154 —
/// `write` makes an empty entry under the name at once and commits the contents only at its
/// close, and `rename` silently replaces an existing name. A `Fault` makes one operation fail,
/// land and then report failure, or "die": that operation and every later one do nothing, as
/// when the worker is killed. Clones share the files.
#[cfg(any(test, feature = "tracer"))]
#[derive(Clone, Default)]
pub struct MemoryStorage(std::rc::Rc<std::cell::RefCell<Memory>>);

#[cfg(any(test, feature = "tracer"))]
#[derive(Default)]
pub struct Memory {
    pub files: std::collections::BTreeMap<String, Vec<u8>>,
    /// Every operation, in order: `list`, `read`, `create`, `close` and `move`.
    pub log: Vec<String>,
    fault: Option<Fault>,
    dead: bool,
}

/// One storage operation that goes wrong, counted from 1 since the fault was set.
#[cfg(any(test, feature = "tracer"))]
#[derive(Clone, Copy, Debug)]
pub enum Fault {
    /// The operation fails and does nothing.
    Fail(usize),
    /// The operation does what it does, then reports a failure.
    LandThenFail(usize),
    /// The operation and every later one fail and do nothing.
    Die(usize),
}

#[cfg(any(test, feature = "tracer"))]
impl MemoryStorage {
    /// A fresh storage holding a copy of `files`: a reopened store, after a reload.
    pub fn with_files(files: std::collections::BTreeMap<String, Vec<u8>>) -> MemoryStorage {
        let storage = MemoryStorage::default();
        storage.0.borrow_mut().files = files;
        storage
    }

    pub fn files(&self) -> std::collections::BTreeMap<String, Vec<u8>> {
        self.0.borrow().files.clone()
    }

    pub fn memory(&self) -> std::cell::RefMut<'_, Memory> {
        self.0.borrow_mut()
    }

    /// Sets `fault`, counted from the next operation.
    pub fn fault(&self, fault: Fault) {
        let mut memory = self.0.borrow_mut();
        memory.log.clear();
        memory.fault = Some(fault);
    }

    fn step<T>(
        &self,
        op: &str,
        effect: impl FnOnce(&mut std::collections::BTreeMap<String, Vec<u8>>) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut memory = self.0.borrow_mut();
        memory.log.push(op.to_string());
        let at = memory.log.len();
        if memory.dead {
            return Err(format!("{op}: the worker is dead"));
        }
        match memory.fault {
            Some(Fault::Fail(n)) if n == at => Err(format!("{op}: made to fail")),
            Some(Fault::Die(n)) if n == at => {
                memory.dead = true;
                Err(format!("{op}: the worker died"))
            }
            Some(Fault::LandThenFail(n)) if n == at => {
                effect(&mut memory.files)?;
                Err(format!("{op}: landed, then reported failure"))
            }
            _ => effect(&mut memory.files),
        }
    }
}

#[cfg(any(test, feature = "tracer"))]
impl Storage for MemoryStorage {
    async fn list(&self) -> Result<Vec<String>, String> {
        self.step("list", |files| Ok(files.keys().cloned().collect()))
    }

    async fn read(&self, name: &str) -> Result<Vec<u8>, String> {
        self.step("read", |files| {
            files
                .get(name)
                .cloned()
                .ok_or_else(|| format!("{name}: not found"))
        })
    }

    async fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.step("create", |files| {
            files.entry(name.to_string()).or_default();
            Ok(())
        })?;
        self.step("close", |files| {
            files.insert(name.to_string(), bytes.to_vec());
            Ok(())
        })
    }

    async fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        self.step("move", |files| {
            let bytes = files
                .remove(from)
                .ok_or_else(|| format!("{from}: not found"))?;
            files.insert(to.to_string(), bytes);
            Ok(())
        })
    }
}

/// Runs a future that never waits, as every `MemoryStorage` and host KDF call is.
#[cfg(any(test, feature = "tracer"))]
pub fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => panic!("a host store future waited"),
    }
}

/// `CNF-82`'s host half, on `MemoryStorage`: what fails closed and leaves the store's bytes as
/// they were, append before apply, a worker killed at every storage operation, the passphrase's
/// rules, and no plaintext in the persisted bytes. The independent reader's tests are the
/// tracer's (`tracer/src/reader.rs`). Host only: the KDF here is the `pbkdf2` crate's.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::allocation::tests::keys;
    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeMap, HashMap};

    const PASS: &str = "correct horse battery staple";
    const OTHER: &str = "a different passphrase entirely";

    /// The host KDF, counting its calls. It derives each passphrase and salt once and remembers
    /// the result, so the matrix runs 600,000 iterations a handful of times, not once per case.
    /// Wrapping keys by passphrase and salt.
    type Derived = HashMap<(Vec<u8>, [u8; 16]), [u8; 32]>;

    #[derive(Default)]
    struct Counting {
        calls: Cell<u32>,
        derived: RefCell<Derived>,
    }

    impl Kdf for Counting {
        async fn derive(
            &self,
            passphrase: LocalPassphrase,
            salt: &Salt,
        ) -> Result<WrappingKey, String> {
            self.calls.set(self.calls.get() + 1);
            let mut derived = self.derived.borrow_mut();
            let key = derived
                .entry((passphrase.0.clone(), salt.0))
                .or_insert_with(|| {
                    let mut key = [0; 32];
                    pbkdf2_sha256(&passphrase.0, &salt.0, ITERATIONS, &mut key);
                    key
                });
            Ok(WrappingKey(*key))
        }
    }

    thread_local! {
        static KDF: &'static Counting = Box::leak(Box::default());
    }

    /// One KDF per test thread, shared by its tests, so a passphrase and salt seen before costs
    /// nothing; its call count is read as a difference.
    fn kdf() -> &'static Counting {
        KDF.with(|kdf| *kdf)
    }

    impl Kdf for &Counting {
        async fn derive(
            &self,
            passphrase: LocalPassphrase,
            salt: &Salt,
        ) -> Result<WrappingKey, String> {
            (**self).derive(passphrase, salt).await
        }
    }

    fn pass(text: &str) -> LocalPassphrase {
        LocalPassphrase::new(text.as_bytes().to_vec())
    }

    fn command(n: u8) -> Entry {
        Entry {
            machine: "fixture".into(),
            command: format!("echo {n}; printf '\\xff'").into_bytes(),
        }
    }

    type Files = BTreeMap<String, Vec<u8>>;

    /// A store with the seed record and `commands` commands: records 0 to `commands`.
    fn store(passphrase: &str, commands: u8) -> (MemoryStorage, Store<MemoryStorage>) {
        let storage = MemoryStorage::default();
        let mut store = block_on(create(storage.clone(), &kdf(), pass(passphrase))).unwrap();
        for n in 1..=commands {
            assert_eq!(block_on(store.append(&command(n))), Ok(u64::from(n)));
        }
        (storage, store)
    }

    fn reopen(files: &Files, passphrase: &str) -> Result<Store<MemoryStorage>, String> {
        block_on(unlock(
            MemoryStorage::with_files(files.clone()),
            &kdf(),
            pass(passphrase),
        ))
    }

    fn recorded(store: &Store<MemoryStorage>) -> Vec<Entry> {
        store.commands().iter().map(|(_, e)| e.clone()).collect()
    }

    fn json(files: &Files, name: &str) -> Value {
        serde_json::from_slice(&files[name]).unwrap()
    }

    /// Stores `value` under `name`, a record in the serialization the store writes.
    fn set_json(files: &mut Files, name: &str, value: &Value) {
        let bytes = if is_record_name(name) {
            serde_json::to_vec(&serde_json::from_value::<RecordJson>(value.clone()).unwrap())
        } else {
            serde_json::to_vec(value)
        };
        files.insert(name.into(), bytes.unwrap());
    }

    /// One byte of a base64url field, flipped.
    fn flip(value: &mut Value, field: &str, at: usize) {
        let mut bytes = URL_SAFE_NO_PAD
            .decode(value[field].as_str().unwrap())
            .unwrap();
        let at = if at == usize::MAX {
            bytes.len() - 1
        } else {
            at
        };
        bytes[at] ^= 0x01;
        value[field] = URL_SAFE_NO_PAD.encode(bytes).into();
    }

    /// What the worker makes of `files` unlocked with `passphrase`: the store must be refused,
    /// stay refused (no Create, and a create request creates nothing), and leave every byte as
    /// it was. The refusal's reason and the KDF calls it took.
    fn refused(files: &Files, passphrase: &str) -> (String, u32) {
        let storage = MemoryStorage::with_files(files.clone());
        let mut local = Local::new(storage.clone(), kdf());
        assert_eq!(block_on(local.open()), json!({ "state": "locked" }));
        let calls = kdf().calls.get();
        let report = block_on(local.unlock(pass(passphrase)));
        let calls = kdf().calls.get() - calls;
        assert_eq!(report["state"], "refused", "{report}");
        let again = block_on(local.create(pass(PASS)));
        assert_eq!(again["state"], "refused", "never \"no store\": {again}");
        assert_eq!(block_on(local.unlock(pass(PASS)))["state"], "refused");
        assert!(local.store().is_none());
        assert_eq!(storage.files(), *files, "the store's bytes are unchanged");
        (report["reason"].as_str().unwrap().to_string(), calls)
    }

    #[test]
    fn the_host_kdf_matches_rfc_7914_section_11() {
        // RFC 7914, section 11: "Test Vectors for PBKDF2 with HMAC-SHA-256".
        for (passphrase, salt, iterations, expected) in [
            (
                "passwd",
                "salt",
                1,
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
                 49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
            ),
            (
                "Password",
                "NaCl",
                80_000,
                "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56\
                 a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
            ),
        ] {
            let mut out = [0; 64];
            pbkdf2_sha256(passphrase.as_bytes(), salt.as_bytes(), iterations, &mut out);
            assert_eq!(hex::encode(out), expected, "{passphrase}");
        }
    }

    #[test]
    fn a_created_store_unlocks_and_replays_in_order() {
        let (storage, store) = store(PASS, 2);
        let files = storage.files();
        assert_eq!(
            files.keys().collect::<Vec<_>>(),
            ["0", "1", "2", ENVELOPE],
            "the staging file was moved each time"
        );
        let envelope = json(&files, ENVELOPE);
        assert_eq!(
            envelope.as_object().unwrap().keys().collect::<Vec<_>>(),
            [
                "id",
                "iterations",
                "kdf",
                "nonce",
                "purpose",
                "salt",
                "version",
                "wrapped_key"
            ]
        );
        assert_eq!(envelope["version"], 1);
        assert_eq!(envelope["iterations"], 600_000);
        let reopened = reopen(&files, PASS).unwrap();
        assert_eq!(reopened.records(), 0..3);
        assert_eq!(recorded(&reopened), [command(1), command(2)]);
        assert_eq!(
            reopened.seed().unwrap().id(),
            store.seed().unwrap().id(),
            "the seed record carries the seed"
        );
        assert_eq!(storage.files(), files, "an unlock writes nothing");
    }

    #[test]
    fn a_wrong_passphrase_and_each_modified_envelope_field_fail_closed() {
        let (storage, _) = store(PASS, 1);
        let files = storage.files();
        assert_eq!(refused(&files, OTHER), (WRONG.to_string(), 1));
        assert_eq!(refused(&files, &format!("{PASS} ")), (WRONG.to_string(), 1));
        // Each authenticated field: one byte flipped. The tag fails, after the KDF.
        for (field, at) in [
            ("salt", 0),
            ("nonce", 5),
            ("wrapped_key", 0),
            ("wrapped_key", usize::MAX),
            ("id", 15),
        ] {
            let mut changed = files.clone();
            let mut envelope = json(&changed, ENVELOPE);
            flip(&mut envelope, field, at);
            set_json(&mut changed, ENVELOPE, &envelope);
            let (reason, calls) = refused(&changed, PASS);
            assert_eq!((reason.as_str(), calls), (WRONG, 1), "{field}");
        }
        // Each parameter and structural defect: refused before the KDF runs.
        type Change = Box<dyn Fn(&mut Value)>;
        let structural: Vec<(&str, Change)> = vec![
            ("version 2", Box::new(|e| e["version"] = 2.into())),
            ("version 0", Box::new(|e| e["version"] = 0.into())),
            ("purpose sheet", Box::new(|e| e["purpose"] = "sheet".into())),
            ("kdf", Box::new(|e| e["kdf"] = "PBKDF2-SHA512".into())),
            (
                "599999 iterations",
                Box::new(|e| e["iterations"] = 599_999.into()),
            ),
            (
                "600001 iterations",
                Box::new(|e| e["iterations"] = 600_001.into()),
            ),
            ("an unknown field", Box::new(|e| e["note"] = "x".into())),
            (
                "a missing field",
                Box::new(|e| {
                    e.as_object_mut().unwrap().remove("nonce");
                }),
            ),
            ("a wrong type", Box::new(|e| e["version"] = "1".into())),
            ("a float version", Box::new(|e| e["version"] = 1.0.into())),
            (
                "a short salt",
                Box::new(|e| e["salt"] = URL_SAFE_NO_PAD.encode([7; 15]).into()),
            ),
            (
                "a long nonce",
                Box::new(|e| e["nonce"] = URL_SAFE_NO_PAD.encode([7; 13]).into()),
            ),
            (
                "a short wrapped key",
                Box::new(|e| e["wrapped_key"] = URL_SAFE_NO_PAD.encode([7; 47]).into()),
            ),
            (
                "a short id",
                Box::new(|e| e["id"] = URL_SAFE_NO_PAD.encode([7; 15]).into()),
            ),
            (
                "padded base64url",
                Box::new(|e| e["salt"] = format!("{}==", e["salt"].as_str().unwrap()).into()),
            ),
            (
                "standard base64",
                Box::new(|e| {
                    e["salt"] = base64::engine::general_purpose::STANDARD_NO_PAD
                        .encode([0xfb; 16])
                        .into()
                }),
            ),
        ];
        for (what, change) in structural {
            let mut changed = files.clone();
            let mut envelope = json(&changed, ENVELOPE);
            change(&mut envelope);
            set_json(&mut changed, ENVELOPE, &envelope);
            let (reason, calls) = refused(&changed, PASS);
            assert!(
                reason.starts_with("the envelope is not a v1 local envelope"),
                "{what}: {reason}"
            );
            assert_eq!(calls, 0, "{what}: no KDF");
        }
        let mut changed = files.clone();
        changed.insert(ENVELOPE.into(), b"not JSON".to_vec());
        assert_eq!(refused(&changed, PASS).1, 0, "not JSON: no KDF");
        changed.insert(ENVELOPE.into(), Vec::new());
        assert_eq!(refused(&changed, PASS).1, 0, "empty: no KDF");
    }

    #[test]
    fn a_modified_record_fails_closed() {
        let (storage, _) = store(PASS, 2);
        let files = storage.files();
        let mut cases: Vec<(String, Files)> = Vec::new();
        for name in ["0", "1", "2"] {
            let record = json(&files, name);
            let mut variants = Vec::new();
            for field in ["id", "previous"] {
                let mut changed = record.clone();
                let text = changed[field].as_str().unwrap().to_string();
                let first = if text.starts_with('a') { "b" } else { "a" };
                changed[field] = format!("{first}{}", &text[1..]).into();
                variants.push((format!("header {field}"), changed));
            }
            let mut changed = record.clone();
            changed["number"] = (changed["number"].as_u64().unwrap() + 1).into();
            variants.push(("header number".into(), changed));
            for (part, field, at) in [
                ("nonce", "nonce", 0),
                ("ciphertext", "ciphertext", 0),
                ("tag", "ciphertext", usize::MAX),
            ] {
                let mut changed = record.clone();
                flip(&mut changed, field, at);
                variants.push((part.into(), changed));
            }
            for kind in ["snapshot", "intent"] {
                let mut changed = record.clone();
                changed["type"] = kind.into();
                variants.push((format!("type {kind}"), changed));
            }
            for (what, changed) in variants {
                let mut modified = files.clone();
                set_json(&mut modified, name, &changed);
                cases.push((format!("record {name}, {what}"), modified));
            }
            let mut padded = files.clone();
            let mut bytes = files[name].clone();
            bytes.push(b' ');
            padded.insert(name.into(), bytes);
            cases.push((format!("record {name}, one byte appended"), padded));
        }
        let mut renamed = files.clone();
        let two = renamed.remove("2").unwrap();
        renamed.insert("3".into(), two);
        cases.push(("record 2 renamed to 3".into(), renamed));
        let mut swapped = files.clone();
        swapped.insert("1".into(), files["2"].clone());
        swapped.insert("2".into(), files["1"].clone());
        cases.push(("records 1 and 2 swapped".into(), swapped));
        let mut gap = files.clone();
        gap.remove("1");
        cases.push(("record 1 missing before 2".into(), gap));
        let mut empty = files.clone();
        empty.insert("3".into(), Vec::new());
        cases.push(("an empty file under a record name".into(), empty));
        let mut not_json = files.clone();
        not_json.insert("1".into(), b"{\"id\":".to_vec());
        cases.push(("a truncated record".into(), not_json));
        let mut no_envelope = files.clone();
        no_envelope.remove(ENVELOPE);
        let storage = MemoryStorage::with_files(no_envelope.clone());
        let mut local = Local::new(storage.clone(), kdf());
        assert_eq!(
            block_on(local.open())["state"],
            "refused",
            "records without an envelope"
        );
        assert_eq!(block_on(local.create(pass(PASS)))["state"], "refused");
        assert_eq!(storage.files(), no_envelope);
        for (what, modified) in cases {
            let (reason, calls) = refused(&modified, PASS);
            assert!(reason.ends_with("replay stopped"), "{what}: {reason}");
            assert_eq!(calls, 1, "{what}");
        }
    }

    /// The type of a record the format does not support yet is refused as such, before it is
    /// decrypted, never skipped.
    #[test]
    fn a_snapshot_record_is_refused_as_unsupported() {
        let (storage, _) = store(PASS, 1);
        let mut files = storage.files();
        let mut record = json(&files, "1");
        record["type"] = "snapshot".into();
        set_json(&mut files, "1", &record);
        let (reason, _) = refused(&files, PASS);
        assert_eq!(
            reason,
            "record 1: snapshots are not supported; replay stopped"
        );
    }

    #[test]
    fn a_record_from_another_store_is_refused() {
        // Another data key, at the same number.
        let (ours, _) = store(PASS, 2);
        let (theirs, _) = store(PASS, 2);
        let mut files = ours.files();
        files.insert("2".into(), theirs.files()["2"].clone());
        let (reason, _) = refused(&files, PASS);
        assert_eq!(
            reason,
            "record 2: it belongs to another store; replay stopped"
        );
        // The same data key and another ID, the header's ID rewritten to ours and its
        // predecessor the same: only the ID in the AAD refuses it.
        let (ours, store) = store(PASS, 0);
        let other = MemoryStorage::default();
        let mut foreign = Store::new(
            other.clone(),
            DataKey(store.key.0),
            URL_SAFE_NO_PAD.encode([9; 16]),
        );
        block_on(foreign.finish_creation()).unwrap();
        let mut files = ours.files();
        let mut record = json(&other.files(), "0");
        record["id"] = json(&files, ENVELOPE)["id"].clone();
        set_json(&mut files, "0", &record);
        let (reason, _) = refused(&files, PASS);
        assert_eq!(reason, "record 0: authentication failed; replay stopped");
    }

    #[test]
    fn another_stores_envelope_is_refused_with_either_passphrase() {
        let (ours, _) = store(PASS, 1);
        let (theirs, _) = store(OTHER, 1);
        let mut files = ours.files();
        files.insert(ENVELOPE.into(), theirs.files()[ENVELOPE].clone());
        assert_eq!(refused(&files, PASS).0, WRONG);
        assert_eq!(
            refused(&files, OTHER).0,
            "record 0: it belongs to another store; replay stopped"
        );
    }

    #[test]
    fn a_failed_append_is_not_applied() {
        // The staging write's create, its close, and the move: each fails.
        for at in 1..=3 {
            let (storage, mut store) = store(PASS, 1);
            storage.fault(Fault::Fail(at));
            assert!(block_on(store.append(&command(2))).is_err(), "op {at}");
            assert_eq!(recorded(&store), [command(1)], "op {at}: nothing applied");
            assert_eq!(block_on(store.read(2)), None);
            assert_eq!(store.records(), 0..2);
            let reopened = reopen(&storage.files(), PASS).unwrap();
            assert_eq!(
                recorded(&reopened),
                [command(1)],
                "op {at}: nothing replayed"
            );
        }
    }

    #[test]
    fn a_move_that_lands_but_reports_failure_is_never_overwritten() {
        let (storage, mut store) = store(PASS, 1);
        storage.fault(Fault::LandThenFail(3));
        assert!(block_on(store.append(&command(2))).is_err());
        assert_eq!(storage.memory().log, ["create", "close", "move"]);
        assert_eq!(recorded(&store), [command(1)], "not applied");
        let landed = storage.files()["2"].clone();
        let refused = block_on(store.append(&command(3))).unwrap_err();
        assert!(refused.contains("until the worker restarts"), "{refused}");
        assert_eq!(storage.files()["2"], landed, "record 2 is not overwritten");
        assert!(!storage.files().contains_key("3"));
        // After a restart the directory is read again: the landed record is replayed, and the
        // next append takes the next number.
        let files = storage.files();
        let storage = MemoryStorage::with_files(files);
        let mut reopened = block_on(unlock(storage.clone(), &kdf(), pass(PASS))).unwrap();
        assert_eq!(recorded(&reopened), [command(1), command(2)]);
        assert_eq!(block_on(reopened.append(&command(3))), Ok(3));
        assert_eq!(storage.files()["2"], landed);
    }

    #[test]
    fn appends_stop_before_the_2_to_the_32nd_encryption_under_the_data_key() {
        let (storage, mut store) = store(PASS, 1);
        let last = u64::from(u32::MAX) - 1;
        store.next = last;
        assert_eq!(block_on(store.append(&command(2))), Ok(last));
        let files = storage.files();
        let log = storage.memory().log.clone();
        let refused = block_on(store.append(&command(3))).unwrap_err();
        assert!(refused.contains("2^32nd"), "{refused}");
        assert_eq!(storage.files(), files, "nothing written");
        assert_eq!(storage.memory().log, log, "no storage operation");
        assert_eq!(
            recorded(&store),
            [command(1), command(2)],
            "nothing applied"
        );
        assert_eq!(block_on(store.read(last + 1)), None);
    }

    /// A worker killed at each storage operation of an append: the reopened store holds the
    /// record wholly or not at all, and ignores what staging left.
    #[test]
    fn a_killed_append_leaves_the_record_wholly_present_or_absent() {
        for at in 1.. {
            let (storage, mut store) = store(PASS, 1);
            storage.fault(Fault::Die(at));
            let appended = block_on(store.append(&command(2)));
            let files = storage.files();
            let reopened = reopen(&files, PASS).unwrap_or_else(|e| panic!("op {at}: {e}"));
            match recorded(&reopened).as_slice() {
                [one] if *one == command(1) => assert!(appended.is_err()),
                [one, two] if *one == command(1) && *two == command(2) => {}
                other => panic!("op {at}: {other:?}"),
            }
            if appended.is_ok() {
                assert_eq!(at, 4, "an append is three operations: create, close, move");
                break;
            }
        }
    }

    /// A worker killed at each storage operation of a creation: what is left is no store, or an
    /// envelope whose unlock finishes the creation; never a refusal, and never a second seed.
    #[test]
    fn a_killed_creation_is_no_store_or_finishes_at_unlock() {
        let mut outcomes = Vec::new();
        for at in 1.. {
            let storage = MemoryStorage::default();
            storage.fault(Fault::Die(at));
            let created = block_on(create(storage.clone(), &kdf(), pass(PASS)));
            let files = storage.files();
            let reopened = MemoryStorage::with_files(files.clone());
            let mut local = Local::new(reopened.clone(), kdf());
            let state = block_on(local.open())["state"].clone();
            outcomes.push(state.clone());
            if state == "none" {
                assert!(!files.contains_key(ENVELOPE), "op {at}");
                assert_eq!(block_on(local.create(pass(PASS)))["state"], "unlocked");
            } else {
                assert_eq!(state, "locked", "op {at}");
                assert_eq!(
                    block_on(local.unlock(pass(PASS)))["state"],
                    "unlocked",
                    "op {at}"
                );
                assert_eq!(local.store().unwrap().records(), 0..1);
                if files.contains_key("0") {
                    assert_eq!(reopened.files(), files, "op {at}: the seed record is kept");
                }
            }
            if created.is_ok() {
                break;
            }
        }
        // Killed at the list, or at the envelope's create, close or move: no store. At the seed
        // record's create, close or move: an envelope to unlock. Then no kill: created.
        assert_eq!(
            outcomes,
            [
                "none", "none", "none", "none", "locked", "locked", "locked", "locked"
            ],
        );
    }

    #[test]
    fn the_passphrase_has_16_code_points_at_least_and_is_neither_trimmed_nor_normalized() {
        let create_with =
            |text: &str| block_on(create(MemoryStorage::default(), &kdf(), pass(text)));
        let refused = |text: &str| matches!(create_with(text), Err(Failure::Input(_)));
        assert!(refused("fifteen chars!!"), "15 code points");
        assert!(create_with("sixteen chars!!!").is_ok(), "16 code points");
        assert!(
            refused(&"\u{1F600}".repeat(8)),
            "8 astral characters, 16 UTF-16 units"
        );
        assert!(create_with(&"\u{1F600}".repeat(16)).is_ok());
        assert!(matches!(
            block_on(create(
                MemoryStorage::default(),
                &kdf(),
                LocalPassphrase::new(vec![0xff; 20])
            )),
            Err(Failure::Input(_))
        ));
        let spaced = "  sixteen chars!!!  ";
        let storage = MemoryStorage::default();
        block_on(create(storage.clone(), &kdf(), pass(spaced))).unwrap();
        let files = storage.files();
        assert!(reopen(&files, spaced.trim()).is_err());
        assert!(reopen(&files, spaced.trim_end()).is_err());
        assert!(reopen(&files, spaced).is_ok());
        // Not normalized: the composed and decomposed forms of "é" are different passphrases.
        let composed = "caf\u{e9} au lait, s'il vous pla\u{ee}t";
        let decomposed = "cafe\u{301} au lait, s'il vous pla\u{ee}t";
        let storage = MemoryStorage::default();
        block_on(create(storage.clone(), &kdf(), pass(composed))).unwrap();
        assert!(reopen(&storage.files(), decomposed).is_err());
        assert!(reopen(&storage.files(), composed).is_ok());
    }

    /// A record the core never issued, committed with the data key as the store commits any.
    fn craft(store: &mut Store<MemoryStorage>, event: allocation::Event) {
        block_on(store.commit(&Event::Allocation(event))).unwrap();
    }

    /// `CNF-72` and `STA-22`: an identity allocated through the store derives the same keys
    /// after a reopen, and another index different ones. Each family counts on its own.
    #[test]
    fn allocated_identities_derive_the_same_keys_after_a_reopen() {
        let (storage, mut store) = store(PASS, 1);
        let mut allocated = Vec::new();
        for family in [
            Family::Machines,
            Family::Machines,
            Family::Passes,
            Family::Handoffs,
            Family::Passes,
        ] {
            allocated.push(block_on(store.allocate(family)).unwrap());
        }
        let indices: Vec<_> = allocated.iter().map(|i| (i.family, i.index)).collect();
        assert_eq!(
            indices,
            [
                (Family::Machines, 0),
                (Family::Machines, 1),
                (Family::Passes, 0),
                (Family::Handoffs, 0),
                (Family::Passes, 1)
            ]
        );
        assert!(
            allocated
                .iter()
                .all(|i| i.seed == store.seed().unwrap().id())
        );
        let reopened = reopen(&storage.files(), PASS).unwrap();
        assert_eq!(reopened.allocation(), store.allocation());
        assert_eq!(recorded(&reopened), [command(1)]);
        for identity in &allocated {
            let before = keys(store.seed().unwrap(), identity);
            assert_eq!(
                keys(reopened.seed().unwrap(), identity),
                before,
                "{identity:?}"
            );
            let other = Identity {
                index: identity.index + 7,
                ..identity.clone()
            };
            let others = keys(reopened.seed().unwrap(), &other);
            assert!(
                before.iter().zip(&others).all(|(a, b)| a != b),
                "{identity:?}"
            );
        }
    }

    /// `CNF-72`: an observation the core cannot apply is refused and journals nothing.
    #[test]
    fn an_observation_that_does_not_apply_is_not_journaled() {
        let (storage, mut store) = store(PASS, 0);
        let created = block_on(store.allocate(Family::Machines)).unwrap();
        block_on(store.observe(allocation::Event::Created(created.clone()))).unwrap();
        let failed = block_on(store.allocate(Family::Machines)).unwrap();
        block_on(store.observe(allocation::Event::Failed(failed.clone()))).unwrap();
        let files = storage.files();
        let metadata = store.allocation().clone();
        for observation in [
            allocation::Event::Created(created.clone()),
            allocation::Event::Created(failed.clone()),
            allocation::Event::Destroyed(failed.clone()),
            allocation::Event::Failed(created.clone()),
            allocation::Event::Reserve(created.clone()),
            allocation::Event::Replace { seed: "x".into() },
        ] {
            assert!(
                block_on(store.observe(observation.clone())).is_err(),
                "{observation:?}"
            );
            assert_eq!(storage.files(), files, "{observation:?}: nothing journaled");
            assert_eq!(*store.allocation(), metadata);
        }
        assert_eq!(reopen(&files, PASS).unwrap().allocation(), &metadata);
    }

    /// `CNF-72`: a journal that would put a second machine at a recorded identity, or skip an
    /// index, or carry what this store cannot apply, is refused at unlock.
    #[test]
    fn a_reservation_the_core_did_not_issue_fails_closed_at_replay() {
        let (storage, mut store) = store(PASS, 0);
        let first = block_on(store.allocate(Family::Machines)).unwrap();
        let files = storage.files();
        let at = |index| Identity {
            index,
            ..first.clone()
        };
        let cases = [
            ("not the next unused", allocation::Event::Reserve(at(0))),
            ("not the next unused", allocation::Event::Reserve(at(2))),
            (
                "not the next unused",
                allocation::Event::Reserve(Identity {
                    seed: "0".repeat(64),
                    ..at(1)
                }),
            ),
            (
                "unknown derivation version 2",
                allocation::Event::Reserve(Identity {
                    derivation_version: 2,
                    ..at(1)
                }),
            ),
            (
                "a replace, and the store holds one seed",
                allocation::Event::Replace {
                    seed: "f".repeat(64),
                },
            ),
            ("does not apply", allocation::Event::Created(at(5))),
        ];
        for (why, event) in cases {
            let mut store = reopen(&files, PASS).unwrap();
            craft(&mut store, event);
            let (reason, _) = refused(&store.storage().files(), PASS);
            assert!(
                reason.starts_with("record 2: ") && reason.contains(why),
                "{reason}"
            );
        }
    }

    /// `STA-3`, `STA-22b`: the reservation's move commits before the identity is returned.
    #[test]
    fn a_reservation_is_committed_before_its_identity_is_returned() {
        let (storage, mut store) = store(PASS, 0);
        storage.memory().log.clear();
        let identity = block_on(store.allocate(Family::Passes)).unwrap();
        assert_eq!(storage.memory().log, ["create", "close", "move"]);
        let reopened = reopen(&storage.files(), PASS).unwrap();
        assert_eq!(reopened.allocation().entries()[0].identity, identity);
    }

    /// A failed append returns no identity and moves no counter, in memory or on disk.
    #[test]
    fn a_failed_reservation_returns_no_identity_and_moves_no_counter() {
        for at in 1..=3 {
            let (storage, mut store) = store(PASS, 0);
            let before = store.allocation().clone();
            storage.fault(Fault::Fail(at));
            assert!(
                block_on(store.allocate(Family::Machines)).is_err(),
                "op {at}"
            );
            assert_eq!(*store.allocation(), before, "op {at}: not applied");
            let reopened = reopen(&storage.files(), PASS).unwrap();
            assert_eq!(*reopened.allocation(), before, "op {at}: nothing replayed");
        }
    }

    /// A move that lands and reports failure: no identity now, and the index is consumed after
    /// the restart, so the next allocation takes the following one.
    #[test]
    fn a_reservation_that_landed_but_reported_failure_stays_consumed() {
        let (storage, mut store) = store(PASS, 0);
        storage.fault(Fault::LandThenFail(3));
        assert!(block_on(store.allocate(Family::Handoffs)).is_err());
        assert_eq!(store.allocation().next_unused().handoffs, 0, "not applied");
        let mut reopened = reopen(&storage.files(), PASS).unwrap();
        let entries = reopened.allocation().entries().to_vec();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            (entries[0].identity.index, entries[0].status),
            (0, allocation::Status::Reserved)
        );
        assert_eq!(
            block_on(reopened.allocate(Family::Handoffs)).unwrap().index,
            1
        );
    }

    /// A reservation committed and then the worker killed, before any observation: consumed.
    #[test]
    fn a_reservation_never_observed_stays_consumed_after_a_kill() {
        let (storage, mut store) = store(PASS, 0);
        let reserved = block_on(store.allocate(Family::Machines)).unwrap();
        storage.fault(Fault::Die(1));
        assert!(block_on(store.observe(allocation::Event::Created(reserved.clone()))).is_err());
        let mut reopened = reopen(&storage.files(), PASS).unwrap();
        assert_eq!(
            reopened.allocation().entries(),
            [allocation::Entry {
                identity: reserved,
                status: allocation::Status::Reserved
            }]
        );
        assert_eq!(
            block_on(reopened.allocate(Family::Machines)).unwrap().index,
            1
        );
    }

    /// `STA-22b`: failed and destroyed entries are tombstones, before and after a reopen.
    #[test]
    fn failed_and_destroyed_indices_are_never_issued_again() {
        let (storage, mut store) = store(PASS, 0);
        let failed = block_on(store.allocate(Family::Machines)).unwrap();
        block_on(store.observe(allocation::Event::Failed(failed.clone()))).unwrap();
        let destroyed = block_on(store.allocate(Family::Machines)).unwrap();
        block_on(store.observe(allocation::Event::Created(destroyed.clone()))).unwrap();
        block_on(store.observe(allocation::Event::Destroyed(destroyed.clone()))).unwrap();
        assert_eq!(block_on(store.allocate(Family::Machines)).unwrap().index, 2);
        let mut reopened = reopen(&storage.files(), PASS).unwrap();
        let statuses: Vec<_> = reopened
            .allocation()
            .entries()
            .iter()
            .map(|e| (e.identity.index, e.status))
            .collect();
        use allocation::Status::{Destroyed, Failed, Reserved};
        assert_eq!(statuses, [(0, Failed), (1, Destroyed), (2, Reserved)]);
        assert!(block_on(reopened.observe(allocation::Event::Created(failed))).is_err());
        assert_eq!(
            block_on(reopened.allocate(Family::Machines)).unwrap().index,
            3
        );
    }

    /// The consultation's condition on criterion 3: a restore event is an ordinary allocation
    /// record, so it goes through the store's encoding and back into the core, and the restriction
    /// holds after replay. No store method writes one: durable import is twr-ggw.27's.
    #[test]
    fn a_journaled_restore_refuses_allocation_in_every_family_after_replay() {
        let (storage, mut ours) = store(PASS, 0);
        for family in Family::ALL {
            block_on(ours.allocate(family)).unwrap();
        }
        let export = ours.allocation().export();
        craft(&mut ours, allocation::Event::Restore(export.clone()));
        let files = storage.files();
        let mut reopened = reopen(&files, PASS).unwrap();
        assert!(reopened.allocation().restored_from_import());
        assert_eq!(reopened.allocation().entries(), export.entries());
        let storage = reopened.storage().clone();
        for family in Family::ALL {
            let refused = block_on(reopened.allocate(family)).unwrap_err();
            assert!(refused.contains("restored"), "{family:?}: {refused}");
        }
        assert_eq!(storage.files(), files, "nothing appended");
        // Observations still apply under the restriction, which survives them.
        let machine = export.entries()[0].identity.clone();
        block_on(reopened.observe(allocation::Event::Created(machine))).unwrap();
        let mut again = reopen(&storage.files(), PASS).unwrap();
        assert!(block_on(again.allocate(Family::Machines)).is_err());
        // A reservation journaled after the restore is refused at unlock.
        let next = Identity {
            index: 1,
            ..export.entries()[0].identity.clone()
        };
        craft(&mut again, allocation::Event::Reserve(next));
        let (reason, _) = refused(&again.storage().files(), PASS);
        assert!(reason.contains("restored"), "{reason}");
        // So is a restore of another seed's metadata.
        let (storage, mut other) = store(PASS, 0);
        craft(&mut other, allocation::Event::Restore(export));
        let (reason, _) = refused(&storage.files(), PASS);
        assert!(reason.contains("another seed"), "{reason}");
    }

    /// Every way the item could be written in a file: raw, hex in either case, base64, base64url,
    /// and the last two inside a longer encoded value too. There the item starts at a byte offset
    /// `k` modulo 3, so for each `k` it is the characters of `k` filler bytes and the item that
    /// depend on the item's bits alone.
    fn encodings(what: &str, bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        use base64::engine::general_purpose::STANDARD_NO_PAD;
        let mut out = vec![
            (format!("{what}, raw"), bytes.to_vec()),
            (format!("{what}, hex"), hex::encode(bytes).into_bytes()),
            (
                format!("{what}, HEX"),
                hex::encode_upper(bytes).into_bytes(),
            ),
        ];
        for (name, engine) in [("base64", STANDARD_NO_PAD), ("base64url", URL_SAFE_NO_PAD)] {
            out.push((format!("{what}, {name}"), engine.encode(bytes).into_bytes()));
            for k in 0..3 {
                let mut value = vec![0; k];
                value.extend_from_slice(bytes);
                let encoded = engine.encode(&value).into_bytes();
                out.push((
                    format!("{what}, {name} at offset {k} mod 3"),
                    encoded[(8 * k).div_ceil(6)..8 * value.len() / 6].to_vec(),
                ));
            }
        }
        out
    }

    #[test]
    fn the_encodings_find_a_secret_inside_a_longer_encoded_value() {
        use base64::engine::general_purpose::STANDARD_NO_PAD;
        let secret: Vec<u8> = (0x80..0xa0).collect();
        let needles = encodings("the secret", &secret);
        for offset in 0..6 {
            let mut value = vec![0x55; offset];
            value.extend_from_slice(&secret);
            value.extend_from_slice(b"and more");
            for (name, encoded) in [
                ("base64", STANDARD_NO_PAD.encode(&value)),
                ("base64url", URL_SAFE_NO_PAD.encode(&value)),
            ] {
                assert!(
                    needles.iter().any(|(_, needle)| encoded
                        .as_bytes()
                        .windows(needle.len())
                        .any(|w| w == needle.as_slice())),
                    "offset {offset}, {name}"
                );
            }
        }
    }

    #[test]
    fn the_persisted_bytes_hold_no_plaintext_secret() {
        let (storage, store) = store(PASS, 2);
        let files = storage.files();
        let seed = store.seed().unwrap();
        let phrase = seed.phrase();
        let mnemonic = bip39::Mnemonic::parse_normalized(&phrase).unwrap();
        let envelope = Envelope::parse(&files[ENVELOPE]).unwrap();
        let mut wrapping = [0; 32];
        pbkdf2_sha256(PASS.as_bytes(), &envelope.salt.0, ITERATIONS, &mut wrapping);
        let mut needles = Vec::new();
        needles.extend(encodings("the passphrase", PASS.as_bytes()));
        needles.extend(encodings("the mnemonic", phrase.as_bytes()));
        let (entropy, length) = mnemonic.to_entropy_array();
        needles.extend(encodings("the entropy", &entropy[..length]));
        needles.extend(encodings(
            "the 64-byte seed",
            &mnemonic.to_seed_normalized(""),
        ));
        needles.extend(encodings("the seed identifier", seed.id().as_bytes()));
        needles.extend(encodings(
            "the seed identifier's bytes",
            &hex::decode(seed.id()).unwrap(),
        ));
        needles.extend(encodings("the data key", &store.key.0));
        needles.extend(encodings("the wrapping key", &wrapping));
        for index in 0..2 {
            let keys = [
                (
                    "role 0",
                    seed.ssh_client_key(1, index).unwrap().0,
                    seed.ssh_client_key(1, index).unwrap().public_key(),
                ),
                (
                    "role 1",
                    seed.attest_sender_key(1, index).unwrap().0,
                    seed.attest_sender_key(1, index).unwrap().public_key(),
                ),
                (
                    "role 2",
                    seed.attest_recipient_key(1, index).unwrap().0,
                    seed.attest_recipient_key(1, index).unwrap().public_key(),
                ),
                (
                    "role 3",
                    seed.relay_key(1, index).unwrap().0,
                    seed.relay_key(1, index).unwrap().public_key(),
                ),
                (
                    "role 4",
                    seed.post_harness_credential(1, index).unwrap().0,
                    seed.post_harness_credential(1, index).unwrap().public_key(),
                ),
            ];
            for (role, private, public) in keys {
                needles.extend(encodings(
                    &format!("{role} index {index}, private"),
                    &private,
                ));
                needles.extend(encodings(&format!("{role} index {index}, public"), &public));
            }
        }
        let mut found = Vec::new();
        for (name, bytes) in &files {
            for (what, needle) in &needles {
                if bytes.windows(needle.len()).any(|w| w == needle.as_slice()) {
                    found.push(format!("{name}: {what}"));
                }
            }
        }
        assert!(found.is_empty(), "{found:?}");
        assert!(needles.len() > 100);
    }
}
