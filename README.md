# tau-web-rust

The implementation of the tau-web harness: a client-side AI harness that runs in a phone
browser and provisions real infrastructure on its operator's behalf. Rust, compiled to
WebAssembly, following the configuration the specification records.

**The specification lives in [`douglaz/tau-web-spec`](https://github.com/douglaz/tau-web-spec)
and is vendored here at `spec/`, pinned to an exact commit, today `ee133d0`** (spec ADR-0031).
The build refuses to run if the checked-out tree does not match the pin, and every release
records the spec commit it was built from. What the build compiles in from the pin:

- `spec/bundle/` — the artifact pin and accepted signers, the inference target, the named
  timings, and the CORS probe;
- `spec/docs/tenants/` — the tenant profiles;
- the briefs promoted out of draft (none yet).

`spec/bundle/cors-probe.sh` and `spec/prototypes/spec-checks/` run from the pinned tree as this
repository's CI gate. The probe is spec `CNF-4`, "The CORS probe runs on every push (`ARC-34`),
and its failure fails the build"; the disk checks are evidence for spec `CNF-85` and for nothing
else. Both were once labelled `CNF-1`–`CNF-4`; the specification's own task list (T29) records
that mislabel as corrected on 2026-09-21, at the pin bump that took this repository to the
commit closing the formal companion.

Start reading at [`spec/00-overview.md`](./spec/00-overview.md). What to build first is
[`spec/06-first-stage.md`](./spec/06-first-stage.md); what it must demonstrate is the
"Stage 1" rows of the stage applicability table in
[`spec/07-conformance.md`](./spec/07-conformance.md), and its "Before declaring stage 1
complete" paragraph.

At the pin `ee133d0`, stage 1 is `STG-21`'s scenario:
"One live LNVPS machine on catalogue plain Arch with no tenant", created through a typed
adapter and paid by a Lightning invoice from the operator's own wallet. Hermes is installed
with its own installer.
LNVPS accepts no buyer boot configuration, so attest cannot run there (`STG-21`);
first contact uses `CHN-R7`'s published-key route. The table's attest row does not gate
LNVPS stage 1.

The pinned table's CNF items are **Stage 1: required**
`1–7, 10–17, 21, 23–26, 28–30, 32, 34–35, 37, 39–44, 49–56, 66–73, 78–79, 81–83, 87–91, 93–95, 99–104, 109–110`;
**Stage 1: record measurements** `45–47`; **Stage 1: model-written check reports** `107`;
**Stage 1: re-entry** `108`; and **Stage 1: recovery export/import and Replace** `19–20, 84`.
The **Attest first-contact route** items `18, 23 (attest-window case), 61, 74–75` do not gate
stage 1. These rows define completion requirements; the implementation described below is
still under construction.

## The harness

`src/` is the harness worker's wasm module, built for `wasm32-unknown-unknown` on spec ADR-0024's
configuration, beside the pinned inputs above. It runs in a dedicated worker the page starts,
because spec `STA-1` says "A single **harness worker** MUST be the only writer of durable state".
What it does so far is the tracer bullet of twr-ggw.2, one command over a pinned SSH connection
through the relay, recorded in the encrypted local store of twr-ggw.5 (below). The module exports
`run_command`, the same entry point in both builds below. The page defines no global and holds
no reference to the worker's instance of the module. It sends the worker one kind of message, a
passphrase to create or unlock the store, and no request; today only the tracer calls
`run_command` there (below). Another same-origin script could still load its own copy of the
module and call it; that copy has no unlocked store, so it refuses every request before any
contact. While the store is not unlocked, every request is refused before any contact. The pins,
keys and journal never come from the request: the journal is the store's, in both builds. The
tracer build runs on test pins and keys. The served build runs on the pins and keys it has
stored, which are none until the seed-derived keys are bound to sessions (twr-ggw.11), so it
refuses every machine at the pin lookup, before any contact and any append. The connection path
below is still whole in the served wasm, which is what the absence check below reads.
`src/harness/run.rs` does it in this order:

- **Pin first.** It looks up the machine's host-key pin, and with none it contacts nothing.
  `CHN-R4` says "the harness MUST NOT do it through the relay".
- **Relay handshake.** It opens the relay WebSocket and runs the handshake of
  [paid-tcp-relay](https://github.com/douglaz/paid-tcp-relay) at `844e834` (its `WIR-4`–`WIR-8`),
  which `CHN-15` names as the wire's owner. The AUTH is signed by the relay key in
  `src/relay_auth.rs`, known-answer tested against that repository's `fixtures/wire/auth.json`
  (`tests/vectors/`).
- **Host-key check.** It runs SSH over the binary frames with `russh::client::connect_stream`, and
  checks the presented host key against the pin inside the key exchange, before authentication.
  A mismatch halts and names both fingerprints (`SEC-11`). Nothing reconnects (`ARC-41`: "the
  harness does not reconnect on its own").
- **Record, then send.** It appends the command to the store's journal immediately before
  sending it as one `exec`, sends nothing if the append fails, and reconciles the journal's
  read-back against what was sent (`ARC-8`, `STA-3`, `STA-4`, `CNF-30`).

The page in `www/` holds no key, pin or record:

- `index.html` carries `ARC-33`'s policy in a `<meta>` element, before any script;
- `boot.js` starts the harness worker, shows whether it came up and the store's one state, sends
  a passphrase once per create or unlock, locks, and reports the persistent-storage request
  (below);
- `worker.js` loads the module, takes the store's writer lock, and opens the store.

There are two builds of the same page, both release builds:

- **The served build**, `scripts/build-web.sh served`, written to `dist/served/` (ignored by git).
  It is what a static HTTPS host serves (`ARC-32`), with no test-only part.
- **The tracer build**, `scripts/build-web.sh tracer`, written to `dist/tracer/`. It is the same
  build with the `tracer` feature, which compiles in `src/testonly.rs`:
  - the test SSH client key, and two test relay keys, each with its public half recorded beside
    it: one the relay fixture holds a pass for, and one it holds none for;
  - the host-key pin source;
  - the test switches a request can set: `test_relay_key` names the test relay key the AUTH is
    signed with, `with-pass` or `without-pass`, and any other value, or none, or a key whose
    secret does not derive its recorded public half, fails the request before any contact (a
    name, never key material); `fail_append` makes the store's append fail at a real OPFS call,
    its `move()` to a name OPFS rejects; `tamper_auth` sends a wrongly signed AUTH. twr-ggw.11
    replaces the test relay keys with the relay key derived from the seed.

  Binding seed-derived keys in place of the test keys belongs to twr-ggw.11. Derivation itself
  exists, below, and both builds journal to the local store.

### Dispatch

`src/dispatch.rs` is the shared, synchronous core, written from the pinned Markdown requirements.
A call is unresolved after its approved intent, finished after its exit status's terminal record,
disposed with outcome unknown after an accepted disposition, or cancelled when a new-format
intent has no approval decision. These states are derived from committed records in journal
order (`STA-3`, `STA-8`); the core takes no time input and no timer clears anything. Replay
writes nothing, surfaces uncertain calls and never resumes or automatically reissues them
(`STA-6`, `STA-7`). The cancellation branch is exercised only through an authenticated crafted
record and a real unlock; no path in this build produces that record.

Today the harness admits a machine for which it holds a host-key pin. The decision's identity
will become the bound session's binding in twr-ggw.11 without changing the intent's shape.
The resource here is an implementation reading: the machine name checked against the pin
source, until approved machine entries exist in twr-ggw.10. There is no barrier between
box-plane commands, including explicit reissues of the same bytes while another call is
unresolved (`STA-24`'s box-plane carve-out).

A disposition must name at least one call, each unresolved on its own resource or disposed by
the disposition currently standing there. A subset leaves unnamed calls unresolved. One
stands per machine, the latest accepted one, and the report shows what it replaces. Refusal
writes nothing and shows why, any settling record, and the resource's unresolved calls.
Destructive reinstall and abandonment refuse commands to that machine, before contact and
again atomically at the intent append. Continuing as if done and as if not done restrict
nothing, explicit reissues included; their recorded assumption is shown, never turned into an
outcome. Here only replacement ends a destructive restriction: no operation dispatching its
continuation exists yet. Later terminal evidence is recorded and shown without reopening the
call or removing its disposition (`STA-24`).

Replay tests dispositions in order with the same eligibility test. A refused one stays in the
journal and is shown with its refusal report, but ends no call, restricts nothing and replaces
nothing; it does not refuse the store. Parse, authentication and chain failures still do, as
does a terminal naming no call, a cancelled call or an already finished call, or an intent whose
identity is not its record number or whose command is not lowercase hex.
`store_state` shows calls and their approval decisions and states, terminals, all disposition
reports and the disposition standing per machine, without key material. No operator screen,
page message or disposition export exists. The browser disposition case uses a store built by
the independent reader, with no added request switch.

`run_command` reports completion as `{"done":true,"seq":1,"call":1,"terminal":2,...}`,
with output, exit status and the reconciled bytes. After an intent commits, an exec error,
channel close without an exit status, exit signal alone, lost connection or terminal append
failure reports `{"unresolved":true,"call":1,"why":"…"}`, never failed. An exit status
is journaled on receipt. Pre-intent refusals keep their existing shape; a disposition refusal
is `{"refused":"disposition","disposition":2,"continuation":"abandonment"}`.

Typed cloud-plane operations and their barriers belong to twr-ggw.8; continuation dispatch to
twr-ggw.40, twr-ggw.45 and twr-i6k.3; job records and waiting to twr-ggw.12; sessions and approved
entries to twr-ggw.10, twr-ggw.11 and twr-ggw.22; inference records to twr-ggw.17. Disposition
screens, snapshots, compaction and transcript retention are outside this change. The untyped
vendor hold is stage 2. This change demonstrates the box-plane disposition rule of `STA-24`.

### The seed

`src/seed.rs` holds the operator seed and its child keys, credential format v1 (spec `STA-22`,
`STA-22a`, and `spec/docs/design/credential-format-v1.md`, "Seed and child keys"):

- **Generate and import.** Generate draws 16 bytes from the CSPRNG (the browser's in the worker,
  the OS's on the host; a failure is an error) and encodes them as 12 English BIP-39 words.
  Import takes exactly 12 words, each exactly a word of the vendored English list, with a valid
  checksum. It tolerates ASCII whitespace around and between the words, and nothing else: no
  case folding, no prefixes, no other language, no non-ASCII separator. No refusal echoes a
  word, and a refused word is named by its position.
- **The seed.** PBKDF2-HMAC-SHA512 over the words joined by single spaces, salt `mnemonic`: the
  empty BIP-39 passphrase. No function takes a BIP-39 passphrase, so the local unlock passphrase
  can never become one (`CNF-83`). The seed identifier is the companion's: hex SHA-256 over
  `tau-web seed id v1`, a zero byte and the seed.
- **Roles 0–4** at `m/707285'/1'/role'/index'`, every step hardened: the SSH client key, the
  attest sender and recipient keys, the relay key and the post-harness credential. Roles 0 and 4
  are Ed25519 seeds, roles 1–3 secp256k1 secrets with BIP-340 x-only public keys. Derivation
  refuses, and never aliases, a version other than 1, a role outside 0–4, an index above
  2^31−1, and an invalid BIP-32 first step or child; it never moves on to another index. No
  chain code or extended key leaves it.
- **The credential types** are in `src/credential.rs`. A sealed `Credential` trait gives each one
  its `SEC-5` row and the name that row's credential cell carries:

  | Type | `SEC-5` row |
  |---|---|
  | `Seed`, the mnemonic and the 64-byte seed | 15, Operator seed |
  | `SshClientKey` (role 0) | 3 |
  | `AttestSenderKey` (role 1) | 7 |
  | `AttestRecipientKey` (role 2) | 16 |
  | `RelayKey` (role 3) | 4 |
  | `PostHarnessCredential` (role 4) | 17 |
  | `HostKeyPin` | 5 |
  | `LocalPassphrase`, the local unlock passphrase's bytes | 18 |
  | `WrappingKey`, PBKDF2's output | 19 |
  | `DataKey`, the local store's data key | 20 |

  `Credentials` hands out the role 0 and role 3 types and `PinSource` the pin type, and the
  tracer's test keys are built as them. The secret types print nothing of the secret, implement
  neither `Clone` nor `Serialize`, and keep their bytes inside the crate (`OVR-3`, spec
  ADR-0024). `CNF-13`'s tests read `SEC-5` from the pinned tree and fail on a type whose row is
  absent, struck through, not derivable today (row 22) or does not name it. A scan of every
  file under `src/` (with `syn`) fails on a type that holds key material by its field types
  (16-, 32- or 64-byte arrays, arrays whose length is not a literal, or a k256, ed25519-dalek,
  russh or ssh-key secret type) and has no row. It knows types by name, so it also fails when
  such a name, or a registered one, is defined by more than one type. The scan is a guardrail,
  not a proof: it cannot see a key carried in a `String`. Three types it flags are exempt, each
  with its reason: the store's ID, the PBKDF2 salt and a record's content address, all
  persisted in the clear by design. The three local-store types also zeroize their bytes on
  drop.

The local store generates the seed in the worker and keeps its mnemonic in its first record
(below). No `wasm_bindgen` export takes or returns a mnemonic, a seed or a key. Allocation
(twr-ggw.6, below) issues the indices the keys derive at; binding the keys to sessions
(twr-ggw.11) comes next.

The tests hold it to the specification's v1 known answers, `credential-vectors-v1.json`, read
from `spec/` at the pin. They also check the upstream vectors vendored in `tests/vectors/` (see
its `README.md`): BIP-32's test vectors 1, 3, 4 and 5, RFC 8032's Ed25519 vectors, BIP-340's
public keys and the BIP-39 reference vectors. And a second implementation, the `bip39` and
`bip32` crates, agrees with it on 18 entropies, every role and indices up to 2^31−1. Those two
crates, `bs58` and `syn` are host-only dev-dependencies.

### The local store

`src/store.rs` is the harness worker's durable state: spec `STA-23`'s local store, the
append-only journal of `STA-2` and spec ADR-0022, in the origin-private file system (OPFS). It
follows credential format v1's "Local encryption envelope"
(`spec/docs/design/credential-format-v1.md`) exactly. `src/store/opfs.rs` is its browser half.
WebCrypto runs the PBKDF2 in the worker. AES-256-GCM runs in Rust (`aes-gcm`), the same code
the host tests run.

**What is on disk**, in one directory, `tau-web-store`:

- **`envelope.json`**, with exactly the fields `version`, `purpose`, `id`, `kdf`, `iterations`,
  `salt`, `nonce` and `wrapped_key`. It holds a fresh 32-byte data key, wrapped with
  AES-256-GCM. The wrapping key comes from the passphrase through PBKDF2-HMAC-SHA-256, with
  600,000 iterations and a fresh 16-byte salt. The AAD is `tau-web/local/v1/<id>`.
- **One file per record**, named by its record number in unsigned decimal; the first is `0`.
  - Each record is encrypted separately under the data key, with a fresh 12-byte nonce.
  - Its AAD is `tau-web/local/v1/<id>/event/<number>/<previous>`. `<id>` is the envelope's
    encoded ID: an implementation reading, since the format's two templates use the same
    `<id>`.
  - `<previous>` is the predecessor's content address, 64 zeros for record 0. The content
    address is lowercase hex SHA-256 over the exact bytes stored in the record's file, never
    over a re-serialization.
- **The record serialization**: a JSON object with exactly `id`, `type`, `number`, `previous`,
  `nonce` and `ciphertext` (the ciphertext followed by its tag), in that order, with no
  whitespace; binary fields are unpadded base64url. Any other bytes under a record name are
  refused.
- **What the records carry.** Each record's plaintext is one event, compact JSON:
  - record 0, the seed, generated in the worker: `{"seed":{"mnemonic":"…"}}`, the mnemonic's
    words;
  - an intent, immediately before one `exec`:
    `{"intent":{"call":1,"machine":"fixture","command":"<lowercase hex>","approval":{"harness_pin":{"machine":"fixture","fingerprint":"SHA256:…"}}}}`.
    The call identity is the intent's record number, unique and never reused. The approval
    decision identifies the harness's admission using that machine's pin; it is not the
    operator's approval of the command's contents. A new-format intent with `approval:null`
    (or an absent approval member) means never dispatched. No path in this build writes one.
  - a terminal record, only when an exit status arrives:
    `{"terminal":{"call":1,"exit_status":7}}`. It carries no output; the command report carries
    output. An exit signal alone leaves the call unresolved: `STA-20` says exit code present
    means finished.
  - an operator disposition:
    `{"disposition":{"machine":"fixture","calls":[1],"continuation":"abandonment","uncertainty":"the command outcome is unknown"}}`.
    The other continuation values are `destructive_reinstall`, `as_if_done` and `as_if_not_done`.
    It carries the uncertainty accepted and no outcome.
  - a pre-ticket `{"command":{"machine":"…","command":"<hex>"}}` record remains readable.
    Its missing approval member proves nothing: it was written before transmission. It becomes
    an unresolved call with its record number and the admission marker `legacy_command`, never
    a cancelled call.
  - a later record, one allocation event appended before it is applied ("Allocation", below):
    `{"allocation":{"reserve":{"seed":"<seed identifier>","derivation_version":1,"family":"machines","index":0}}}`;
    `created`, `failed` and `destroyed` carry the same identity; `restore` carries an export,
    `{"seed":…,"derivation_version":1,"next_unused":{"machines":…,"passes":…,"handoffs":…},"entries":[{"identity":{…},"status":"reserved"}],"restored_from_import":…}`;
    `replace` carries `{"seed":…}`. The seed identifier is in the clear only inside the
    encrypted record, where credential format v1 puts it.

  The independent reader in the tracer crate decrypts every record and reads the seed, legacy
  command, intent, terminal and disposition shapes; it does not interpret allocation records.
- **`staging`**, the one staging name, which is never a record name or the envelope's.

**The commit boundary.**

- A file under a record name, or under the envelope's, is only ever made by moving a complete,
  closed staging file onto it:
  - `staging` is written whole, with `getFileHandle(create)`, `createWritable()`, `write()` and
    `close()`;
  - then `move()` puts it under its name.
- In Chromium 154, `getFileHandle(create)` makes an empty entry at once. Writing the final name
  directly could therefore leave an empty record behind a killed worker.
- An append commits when the move resolves, and only then is it applied (`STA-3`).
- A record-named file therefore always holds a complete record. One that fails to parse, decrypt
  or chain is corruption, never skipped.
- Chromium's `move()` replaces an existing name silently. A failed append's move may still have
  landed, so after any failed append the store refuses appends until the worker restarts and
  reads the directory again.
- A name that is neither the envelope's nor a record name is not a record, and replay ignores
  it: a staging file, a browser swap file.

**What fails closed.**

- **Before any KDF**, unlock refuses an envelope that is not v1:
  - input that is not JSON;
  - a field missing, unknown or of the wrong type;
  - a version, purpose, KDF or iteration count other than v1's;
  - a field of the wrong length, padded, or in standard base64.
- **The tag.** A wrong passphrase and a modified envelope fail the same tag. The page says
  "wrong passphrase, or the store was modified", and claims neither.
- **Replay** walks the records from `0`. Any of these stops it:
  - a record that fails to parse, decrypt or chain;
  - a number missing before a later record;
  - a record of another store;
  - a record of type `snapshot` (unsupported) or of an unknown type;
  - an allocation record the allocation core does not apply ("Allocation", below).
- **Records without an envelope** are refused too.
- **A refusal is final for that worker.** It dispatches nothing, appends nothing and uses no
  partial state. The page shows the reason and offers no Create; a reload tries again.
- **Create** is offered only when the directory holds no envelope and no record-named file.

**Creating a store.**

- The passphrase must be at least 16 Unicode code points of the UTF-8 the worker receives. It
  is never normalized or trimmed. The page asks for it twice, compares the two, states the
  minimum and encourages a password manager.
- The envelope is written first, then the seed record.
- A worker killed before the envelope's move leaves no store, at most a staging file, and Create
  is offered again.
- A worker killed between the two leaves an envelope with no record. Unlocking that envelope
  with its passphrase finishes the creation: it generates the seed then. An unlock generates a
  seed only for a store with no record, so a store that holds one never gets another.

**Unlock and lock.**

- **The passphrase.** The page sends its UTF-8 bytes once, in one create or unlock message, and
  clears both fields at once.
  - The module copies the bytes into its secret type and zero-fills the array they came in.
  - It also zero-fills the copy it hands WebCrypto's `importKey` and the buffer `deriveBits`
    returns.
  - The passphrase is zeroized once the derivation has run, and the wrapping key right after
    the unwrap. The data key lives until the worker ends.
  - The harness never persists the passphrase.
- **Lock is termination.** The page terminates the harness worker and starts a fresh one, which
  loads locked, on each of these:
  - `visibilitychange` to hidden;
  - `pagehide`;
  - a back/forward-cache restore, a `pageshow` with `persisted` set;
  - the Lock button.

  A lock also empties both passphrase fields, so text typed and never submitted does not
  outlive it (`SEC-5` row 18: "Input UI briefly"). A reload and a killed worker reach the same
  state by themselves. There is no grace timer, and
  nothing is journaled on the way out (`STA-23`: "No unload callback is relied on for
  journaling"). Terminating the worker ends everything inside it: its relay WebSocket, the SSH
  connection that WebSocket carries, and any command in flight. After an unlock, the worker
  replays the journal.
- **The single writer.** `worker.js` takes an exclusive Web Lock, `tau-web-store`, before the
  module reads the store, and holds it for the worker's whole life (`STA-1`, `STA-7`).
  - A worker that cannot get the lock queues for it, and the page says "Waiting for the local
    store: another tab, or this page's previous harness worker, still holds it."
  - Chromium releases a terminated worker's lock asynchronously, so a fresh worker queues
    behind it.
- **Session workers.** None exists yet; they are twr-ggw.14's.
  - A session worker must be started by the harness worker, never by the page, so terminating
    the harness worker ends it.
  - The ticket that adds session workers must show, by a test, that they have ended after a
    lock, not assume it from the nesting.

**Persistent storage.** On every load where `navigator.storage.persisted()` is false, the page
calls `navigator.storage.persist()`, which exists in the page and not in the worker. It shows the
outcome: a refusal as a refusal, and a grant, requested in that load or not, as "Persistent
storage is granted." Both say "This is a request, not
a guarantee: eviction, device loss or corruption can still lose the local store, so the seed
backup and recovery remain necessary." Nothing on the page promises the store cannot be lost.

**Limits.**

- **Whole-store rollback is not detected,** as the format says. An older copy of the store
  unlocks, and so does one with its last records deleted: a missing tail looks like fewer
  appends. Deleting every record leaves an envelope with no record. The next unlock treats that
  as an interrupted creation and generates a new seed.
- **Clearing buffers is best effort** (`STA-23`). It does not reach the strings the page's
  fields held, copies the allocator left behind, or the `CryptoKey` that `importKey` makes.
- **The interrupted-creation window** above.
- **No seed-backup ceremony exists yet,** so the mnemonic is displayed nowhere. It lives only
  in the encrypted seed record.
- **The data key's bound.** Credential format v1 says "Never perform 2^32 encryptions under one
  data key". Record 0 is the first encryption under it, so an append whose record number is
  2^32−1 or above is refused before it encrypts: nothing is written and nothing applied.
  Re-encryption under a fresh key does not exist yet, so the store refuses appends at the bound
  until it does.
- **Durability.** A committed append survives a killed worker or tab. Whether `close()`
  reached the disk before a power loss is the browser's to say.

**The host tests** (`cargo test`) run the store's code on an in-memory double of OPFS. The
double behaves as measured in Chromium 154: a write makes an empty entry under its name at once
and commits its contents only at the close, and a move replaces an existing name silently. It
can make any storage operation fail, land and then report failure, or "die" with every later
one, as a killed worker does. They show, for `CNF-82` and `CNF-15`:

- **The KDF.** The host's PBKDF2-HMAC-SHA-256 matches RFC 7914's section 11 vectors.
- **Fail closed.** Every refusal leaves the double's bytes identical, and a create request after
  it creates nothing. The refusals:
  - a wrong passphrase;
  - each envelope field changed: one byte of the salt, the nonce, the wrapped key and the ID;
  - the version, `purpose: "sheet"`, the KDF, 599,999 and 600,001 iterations;
  - an unknown field, a missing one, a wrong type, a wrong length, padded or standard base64,
    and not JSON. These and the line above invoke the KDF zero times;
  - one byte changed in each part of each record, or appended to it;
  - another store's record, and the same data key under another ID, whose AAD alone refuses it;
  - another store's envelope, with either passphrase;
  - a renamed record, two swapped, a gap, an empty record file, records without an envelope, and
    a record of type `snapshot` or of an unknown type.
- **Append before apply.** A storage call that fails during an append leaves nothing applied or
  replayed. A move that lands but reports failure is never overwritten, and its number is never
  reused.
- **Kills.** A worker killed at every storage operation of an append leaves the record wholly
  present or absent. Killed at every operation of a creation, it leaves no store or an envelope
  whose unlock finishes the creation, never a refusal or a second seed.
- **The passphrase.** 15 code points are refused, as are eight astral characters (16 UTF-16
  units), and 16 are accepted. Spaces around it, and the difference between composed and
  decomposed characters, are kept.
- **The bound.** With the next record number set one below 2^32−1, the append commits; at
  2^32−1 it is refused, with no storage operation and nothing applied.
- **No plaintext.** The persisted bytes hold none of the secrets listed in the tracer's
  no-plaintext case, in any of its encodings. Base64 and base64url are searched as whole values
  and inside a longer encoded value, at each of the three byte alignments: for each `k` of 0, 1
  and 2, the characters of `k` filler bytes and the secret that depend on the secret alone. A
  test in each crate finds a secret embedded at byte offsets 0–5 in a longer value, in both.

In the tracer crate, the independent reader reads a store the harness wrote, and the harness
unlocks and replays a store the reader built. Decrypted, the seed is in the seed record alone,
and no other secret is in any record of that store, which holds seed, intent, terminal and disposition records.
A record the harness cannot read is refused with a reason that quotes none of its plaintext,
since the reason reaches the page.

### Allocation

`src/allocation.rs` is spec `STA-22b`'s allocation metadata and the one core every allocation
event goes through, in the local store and in the companion comparison alike. It is pure and
synchronous, built on every target, and holds no seed and no key: a seed is known by its
identifier.

- **The metadata.** The seed identifier, the derivation version (1), the next unused index of
  each family — machines, passes, handoffs — and the allocated entries, oldest first. Each entry
  is an identity (seed identifier, derivation version, family, index) with a status: `reserved`,
  `created`, `failed` or `destroyed`. Beside them, whether the metadata was imported after loss
  of the canonical journal with no Replace since.
- **Families.** Roles 0–2 share the machine index; role 3 takes a pass index and role 4 a handoff
  index (`STA-22`; credential format v1's role table). Each family has its own counter.
- **Allocate** issues the family's next unused index as a reserved entry. Indices are monotonic
  and run from 0 through 2^31−1; once 2^31−1 is issued the family refuses, and it never wraps
  (credential format v1, "Seed and child keys").
- **Observations.** `created` moves a reserved entry to created, `failed` a reserved one to
  failed, `destroyed` a created one to destroyed. Failed and destroyed are `STA-22b`'s
  tombstones: never revived, and their index never issued again. An observation the metadata
  cannot apply — `created` for an identity never reserved, already created or tombstoned,
  `destroyed` for one never created — is refused and changes nothing.
- **Export** is the whole metadata. The sheet's export time and journal sequence are twr-ggw.27's.
- **Restore** is an event that takes an export. The listed identities come back, and every
  allocation, in every family, is refused until a Replace: `STA-22b`'s "a seed imported after
  loss of the canonical journal may restore listed identities but MUST NOT allocate new ones". An
  export recording a derivation version other than 1 is refused (`STA-22a`).
- **Replace** is an event that takes a freshly generated seed's identifier. The restriction
  clears, each family starts at 0 under the new seed, which has derived nothing, and the old
  entries are retained under the old seed's identifier (`STA-22b`: "old records are retained
  until migration is complete"). A Replace to the current seed, or to one an entry already names,
  is refused: it would issue a recorded identity again.

**Journaled in the local store.** Each allocation event is a record of its own ("What the records
carry", above).

- **Append before apply** (`STA-3`). `Store::allocate` takes a family and no index. It asks the
  core what it would issue, appends the reservation, applies it once the append commits, and
  only then returns the identity. A failed append returns no identity and moves no counter. A
  move that landed but reported failure is replayed after the restart, so its index stays
  consumed and is never issued again.
- **Observations** are journaled the same way, so tombstones survive a restart. One the core
  cannot apply is refused and never journaled.
- **Replay** rebuilds the core from record 0's seed identifier and applies each allocation record
  through it. A record that does not apply stops replay and refuses the store, as corruption
  does:
  - a reservation of a recorded identity, of an index other than the family's next unused one,
    under another seed or an unknown derivation version, or under the restriction;
  - an observation that does not apply;
  - a replace record: the store holds one seed, record 0's, and a replace would move allocation
    to a seed it cannot derive from (twr-ggw.29 opens this when the store gains a second seed);
  - a restore of another seed's metadata.

  A restore record of the store's own seed is applied, so the restriction holds after every
  replay. No store method writes a restore or a replace record.

**Not here: durable import.** A store created from an imported seed and its sheet, the recovery
sheet itself and `CNF-84`'s import refusals are twr-ggw.27's. This ticket shows the restriction
on the core — the seed's mnemonic imported with `Seed::import`, the core's own export restored,
the same keys re-derived, allocation refused in all three families until a Replace — and through
a restore record crafted with the data key and replayed. Neither is evidence that a store can be
created from an imported seed today. No `wasm_bindgen` export, UI or page message reaches
allocation, since nothing calls it yet.

**The tests** (`cargo test`). On the core: each family's own counter; a recorded identity never
reserved again or revived; tombstones never reissued; exhaustion, started at 2^31−1; an unknown
derivation version; and the import after loss above. On `MemoryStorage` stores: roles 0–4 derive
the same keys at an allocated identity after a reopen, and different keys at another index
(`CNF-72`); an observation that does not apply journals nothing; each crafted record listed under
Replay refuses the store at unlock; the reservation's move commits before the identity returns; a
failed append, a move that lands then fails, and a worker killed after the commit; failed and
destroyed indices never reissued across a reopen; and the journaled restore.

**The companion comparison** (spec ADR-0032, "How the implementation is compared").
`src/allocation/comparison.rs`, a host test, reads `spec/docs/design/allocation-witnesses-v1.json`
from the pinned tree at run time with `std::fs`. It is never compiled in (ADR-0031), so a missing
file is a red test.

- **The header.** Schema 1, module `allocation`, non-empty `witnesses` and `enumeration`, and an
  enumeration of exactly every trace of at most `bound.events` events over `bound.alphabet`,
  each once: Σ|alphabet|^k traces for k = 0…events, every event from the alphabet, no sequence
  twice, each starting from the initial journal: seed ordinal 0, derivation version 1, every
  family's `next_unused` 0, no entries and `restored_from_import` false. A named witness starts
  where the file says. A truncated file fails.
- **Every trace**, all 6 witnesses and all 400 enumerated traces, drives the production core from
  the trace's `start`. Seed ordinals map to seed identifiers the driver generates, in order;
  `export_sheet` keeps the core's export, and `restore` passes the latest one, or with none
  restores nothing. After each step it compares the outcome (`allocation`, and `identity` when
  admitted) and the `journal` projection with what the core says and holds.
- **The pair.** A trace under `restoredAllocatesNone: true` must match at every step. The core
  has no switch for that guard, so the pair's admitted side, under `false`, must differ from the
  core at some step, and the refused side it names must match: the negative control.
- **Anything unknown fails**: an event kind, provenance, family, status, outcome, assumption or
  member. Every failure names its trace — a witness by its declarations, an enumerated trace as
  `enumeration[i]` — and its step, with the expected and actual values.
- **Its own negative controls.** Unit tests build `CNF-3`'s three breaks in memory from the
  pinned file — an outcome flipped; empty bytes and an absent file; an unknown event kind and an
  unknown outcome — plus a truncated enumeration, an unknown member, a pair without its admitted
  side, and an enumerated trace starting elsewhere than the initial journal, both the empty
  trace and one with steps, and each must fail naming the trace.

The core was written from the requirement text before the comparison existed, and the
comparison raised no disagreement with it. Its record, printed on success
(`cargo test --locked allocation::comparison -- --nocapture`), names the file, its bound, what
was compared, the pair and the spec commit; the implementation revision is the commit the test
ran at:

```
allocation companion comparison: passed
  file: <checkout>/spec/docs/design/allocation-witnesses-v1.json
  schema 1, module allocation, bound: 3 events over an alphabet of 7
  compared: 6 witnesses and 400 enumerated traces, every step
  pair: TauWeb.Allocation.stale_sheet_refused matched; TauWeb.Allocation.stale_sheet_admitted differed at step 7
  spec commit: ee133d0e84622bf079b577576091277bce72214f
```

A pass is evidence about harness knowledge alone: never about external state, about whether an
effect ran before its append returned, or about concurrency (ADR-0032, "Evidence").

### The tracer

`scripts/tracer.sh` builds both directories, then runs `tracer/`. That is a host binary, never
compiled for wasm32 and never served. It starts these fixtures on ephemeral loopback ports:

- **A fixture sshd** (russh) whose host key the test chooses. It records every connection,
  authentication attempt and channel request, and the `exec` command byte for byte. It starts no
  process: it answers the tracer's one command with the stdout, stderr and exit status the tracer
  gives it, and any other command with a fixed failure.
- **A relay fixture** over `wss:`, speaking paid-tcp-relay's handshake at `844e834`, its
  `WIR-4`–`WIR-10`:
  - a fresh challenge (`WIR-4`);
  - checks 1–4 and 6 of `WIR-6`, in order: shape, with `created_at` within `relay.auth_skew`;
    signature, and the challenge is this connection's, so a replayed AUTH fails (`WIR-9`); pass,
    against passes recorded by hand (`PAS-6`), each a relay key's public half, its destination
    hosts and an expiry; destination, read at the host and not at the port (`PAS-4`, `DST-2`);
    and pace, per recorded host across its ports: at least `relay.min_spacing` between dials
    and at most `relay.window_cap` dials in any `relay.window`, a sliding window (`DST-3`);
  - on a failed check, `{"ok": false, "reason": …}` and close 1008, before any dial (`WIR-7`);
  - then the dial, `{"ok": true}` once it is up, and binary frames. A binary frame before OK, in
    place of the AUTH or after it, or a text frame after OK, closes with 1002 (`WIR-8`);
  - an ordered log per connection: challenge sent, AUTH received, accepted or refused (reason and
    check), dial, OK sent, bytes forwarded each way, frames the client sent otherwise, and the
    close code sent. It shows no dial before the AUTH is accepted and no byte forwarded, either
    way, before OK (`WIR-10`).

  The limits are read from paid-tcp-relay's `bundle/timing.toml` at `844e834`, vendored under
  `tests/vectors/`, where they live by name (its `OPR-7`). The tracer holds a pass for the test
  relay key for the sshd's host, expiring in an hour, and resets the pace state before each case
  that dials.

  It is not the relay product. It does not implement check 5, `DST-4`, paid-tcp-relay's address
  rule, which refuses the fixture's loopback destinations: checking a real relay's address policy
  is twr-ggw.26's (`CNF-81`, `CHN-16a`). Nor does it implement the strict path grammar of
  `WIR-1`–`WIR-3`, which is not among `CNF-87`'s items.
- **An HTTPS server for each build.** The certificate is made per run, and Chrome is told to
  accept it by its key hash alone. It logs every request line, header and body.

The fixture sshd also never answers one command, which stays in flight until its client goes.
The relay fixture logs a client connection that ends with no close frame.

The tracer then drives headless Chrome over the DevTools protocol. It runs a request by evaluating
in the harness worker's own context, over that worker's DevTools session: it imports the module
the worker already loaded, by the same URL, and calls its `run_command`. Neither build's page holds
a hook for it. Every case asserts on what the fixtures observed, not only on what the harness
reports. The relay fixture counts every TCP connection it accepts, at `accept`, before TLS and the
WebSocket upgrade.

For the local store, the tracer works the page as an operator would and inspects what the
browser holds:

- **The page.** It types each passphrase into the page's fields and presses the page's buttons.
  A store is created in each build before its cases, so the existing cases run on the tracer
  build's store.
- **The messages.** It records every message between each page and its harness workers, from
  before the first, with a script it installs over the DevTools protocol before the page's own
  (`Page.addScriptToEvaluateOnNewDocument`). The product carries no hook. At any depth and
  either way, before a transfer detaches anything:
  - it reads what structured cloning reads, never through a value's own `Symbol.iterator` or an
    inherited setter: a plain object's own enumerable properties, `__proto__` included; an
    array's elements by index, from 0 to `length − 1`; a `Map`'s keys and values and a `Set`'s
    members through `Map.prototype.forEach` and `Set.prototype.forEach`, as they were when the
    hook installed; and these are recorded and searched like any others;
  - every `ArrayBuffer` is recorded as its bytes, and every typed array and `DataView` as all the
    bytes of its backing buffer, which structured cloning sends whole, not only the view's
    range; they are searched as bytes;
  - any other object that is not a plain object or an array, such as a `Blob` or an `Error`, and
    an array with a named property, is one the hook cannot read, and is recorded as such and
    reported as a finding;
  - a message the serializer throws on, on either side, is recorded as `unserializable` and
    reported as a finding; it is still sent, or fails to send, exactly as without the hook;
  - sixteen negative controls, planted through the same guarded serializer into the same
    `__tracerMessages` log, read back from it over the DevTools protocol, and searched by the
    same check in the tracer build's "no plaintext" case, must each be reported for their own
    reason:
    - as `binary: SSH client key, private half, raw`: the test SSH client key as a
      `Uint8Array`, an `ArrayBuffer`, a `Uint32Array` nested in an object, a one-byte
      `Uint8Array` view and a one-byte `DataView` over a buffer holding the key outside the
      view, a `Uint8Array` as a `Map`'s value, an `ArrayBuffer` in a `Set`, a `Uint8Array` as a
      plain object's own enumerable `__proto__` property (which must also come back through the
      DevTools protocol as a member named `__proto__`), and a `Uint8Array` in an array, a
      `Uint8Array` as a `Map`'s value and an `ArrayBuffer` in a `Set`, each of these three with
      an own `Symbol.iterator` that yields nothing;
    - as the passphrase: a passphrase in an unlock message that carries something else;
    - as `unreadable: <kind>`: a `Uint8Array` as an array's named property (`Array with named
      properties`), a `Blob` (`Blob`), an `Error` whose message is the passphrase (`Error`), and
      an object whose getter throws in the serializer (`unserializable`).

  The hook guards against a mistaken product, a secret the harness's own code puts into a
  message, not against hostile code in the page.
- **OPFS.** It dumps and edits OPFS from the page's context, recursively from
  `navigator.storage.getDirectory()`.
- **The replayed state.** It reads it in the worker's own context, through the module's
  `store_state`, which returns whether the store is locked, record numbers, calls and their
  states, terminal evidence and disposition reports and standing continuations, with command
  bytes as hex and no key material.
- **The stores' contents.** It reads them with an independent reader, `tracer/src/reader.rs`.
  The reader is written from the format's text and never calls the harness's store code. It
  runs on `ring`'s PBKDF2, AES-256-GCM and SHA-256, and derives the seed's keys with the
  `bip39` and `bip32` crates.

In headless Chromium 154 a new tab hides the one before it, which then restarts its worker, as
page hide must. The cases account for it.

The cases:

| Case | What the fixtures show |
|---|---|
| the served build loads | its worker comes up and nothing errs, and the page has no `tauWeb` global and no global holding the worker. With no store, the page offers Create alone, and a request is refused before any contact. A store is created; then, called in its worker on the machine the tracer build pins, it refuses for the missing pin, the relay accepts no connection and the sshd sees none, and nothing is appended |
| create and unlock (twr-ggw.5, `CNF-82`) | the page offers Create, stating the 16-character minimum and a password manager, and refuses 15 characters. The independent reader reads the store the browser created, from the passphrase alone: record 0, the seed. A store the reader built, put into OPFS, unlocks in the browser and replays its command, and the unlock writes nothing: WebCrypto's PBKDF2 agrees with the host's |
| 1. recorded, then sent (`CNF-30`, `ARC-8`) | exactly one relay connection; the sshd received exactly the journal entry, which the replayed state holds as approved intent 1 and terminal 2 (exit status 7), and the output and exit status came back. With the append made to fail, the sshd received no `exec`, read only once that SSH connection has ended at the sshd |
| a failed append is not applied (twr-ggw.5 AC2, `STA-3`) | that failed append failed at its `move()`, a real OPFS call; the replayed state has no record for it, and none appears after a reload and an unlock |
| 2. a wrong host key halts (`CNF-21`, `SEC-11`) | no authentication attempt, no `exec`, no journal entry, and exactly one connection |
| 3. no pin, no contact (`CNF-23`'s no-pin case, `CHN-R4`) | no TCP connection accepted at the relay, none at the sshd, no dial, and nothing pinned afterwards |
| 4. the policy is enforced (`ARC-33`) | the loaded page carries the served page's policy token for token. An injected inline script raises a `script-src` violation and does not run. A `ws:` socket raises a `connect-src` violation in the page and in the worker |
| 5. the relay fixture's AUTH check is real | exactly one relay connection, and a wrongly signed AUTH gets `{"ok": false, "reason": "auth"}` and close 1008 at check 2, and nothing is dialed |
| 6. a relay key with no pass (`CNF-87`) | an unrecognised `test_relay_key` fails the request with no relay connection. Signed by the key with no pass, the harness reports `{"refused": "relay", "reason": "pass", "close_code": 1008}` |
| 7. an unrecorded destination (`CNF-87`) | the pinned machine `fixture` at `127.0.0.2`, a host the pass does not record: `destination` and 1008 |
| 8. pace (`CNF-87`) | the tracer puts the sshd's host at its window cap just before the run, so the refusal holds whatever the timing: `pace` and 1008 |
| fail closed (twr-ggw.5 AC1, `CNF-82`) | five edits to OPFS: a wrong passphrase, one byte of the envelope's salt, one byte of record 1's ciphertext, another store's record at the same number, and an envelope of version 2. For each, unlock is refused and the page offers neither Create nor Unlock; for the first two it says "wrong passphrase, or the store was modified". A create request creates nothing, a request is refused before any contact, and OPFS is byte-identical afterwards |
| reload, explicit lock, page hide and a killed worker (twr-ggw.5 AC3, `CNF-82`) | one case each. The old worker target is gone and one new harness worker exists. The page offers Unlock alone. A request is refused with no TCP connection at the relay. After an unlock, the replayed state lists every command recorded before. Explicit lock, page hide and the killed worker also catch a held command: once the sshd has its `exec`, the lock comes, and the sshd sees its connection end; explicit lock and page hide also check that the relay fixture sees the client's WebSocket end. After the unlock the held command reads unresolved in the replayed state and the sshd receives no second `exec`. Before the Lock button is pressed, text is typed into both passphrase fields and never submitted; both are empty once it is pressed |
| close without exit status (twr-ggw.7, `STA-8`) | the sshd closes without an exit status; the report names an unresolved call, replay preserves it, and no second exec occurs |
| dispositions (twr-ggw.7, `STA-24`) | the independent reader builds a destructive disposition: the request is refused before contact, with no relay connection, SSH connection or append. Replacing it with a continuing disposition admits the command and journals its terminal record |
| one writer (twr-ggw.5, `STA-1`, `STA-7`) | a second tab opens, which hides the first and restarts its worker, so either tab's worker may win the lock. The holder is the tab that offers Unlock while the other says it is waiting; the roles follow from that. The holder unlocks. The other says it is waiting for the store and offers neither Create nor Unlock; its worker has not read the store, runs nothing and appends nothing. Once the holder's tab closes, the other offers Unlock and unlocks the same store |
| persistent storage (twr-ggw.5 AC6, `STA-23`) | with the `persistent-storage` permission denied, then granted, through `Browser.setPermission`: `navigator.storage.persisted()` reads false, then true, and the page shows the refusal, then "Persistent storage is granted." (`persisted()` already reads true, so that load makes no request), each with the statement that this is a request, not a guarantee |
| no plaintext (twr-ggw.5 AC4 and AC5, `CNF-15`, `STG-10`), in each build | from the passphrase the tracer typed, the independent reader learns the wrapping key, the data key and the seed. None of these appears, raw, hex, HEX, base64 or base64url (whole, or inside a longer value at any byte alignment), in any OPFS file: the passphrase, the wrapping and data keys, the mnemonic, the entropy, the 64-byte seed, the seed identifier, and roles 0–4's private and public keys at indices 0 and 1, plus the test keys in the tracer build. Local storage, session storage, IndexedDB and Cache Storage hold nothing, and no service worker is registered. A passphrase reaches the worker only as the one create or unlock message, and no message from the worker carries any of the items, in its text or in a binary payload's bytes; any other passphrase occurrence, text or binary, is a finding. In the tracer build's case, the sixteen negative controls listed under "The messages" run first, through the same guarded serializer and the same check, and each must be reported for its own reason. The fields were empty after every submit. The HTTPS fixtures' requests and the console hold none |

In cases 6–8 the relay fixture also accepted exactly one connection, dialed nothing, and its log
shows no frame from the client after the refusal but the close; the sshd saw no connection.
Case 1 also reads the order from the relay fixture's log: challenge sent, AUTH received,
accepted, dial, OK sent, then the first forwarded byte.

How the twr-ggw.5 AC3 cases cause their event, where headless Chromium could not give the real one:

- **Page hide** is two events, each caught with a command in flight:
  - the browser's own `visibilitychange` to hidden, from opening a second tab, and the page
    records it;
  - then a `pagehide` dispatched on the real window. The browser fires its own `pagehide` only
    as a page unloads, which is the reload case.
- **A killed worker** is `Page.crash`, after which neither the page nor its worker runs
  anything. Headless Chromium 154 reports no crash and the tab answers nothing more, so the
  tracer closes it and loads the page in a new one.

### The relay matrix

The cases a correct client never produces run on the host instead, in `tracer/src/matrix.rs`:
a native client over `wss:` (tokio-tungstenite on tokio-rustls, trusting the run's certificate)
drives the relay fixture through the fixture half of `CNF-87`, misbehaviour included. It runs
under `cargo test`, so in CI's `build` job. Each case starts its own relay fixture, asserts
first on what is visible outside the relay (the frames, the reason, the close code, and what
the test's own destination listeners accepted and received), then on the fixture's log. The
cases are written against a description of the relay under test, for twr-ggw.26. The `WIR-*`,
`PAS-*` and `DST-*` ids below are paid-tcp-relay's at `844e834`:

| Case | What it shows |
|---|---|
| 1. fresh challenge | pairwise distinct challenges, each 32 bytes as base64url with no padding, naming the relay |
| 2. stale challenge | an AUTH signed now by the key with the pass, for a recorded host, over an earlier connection's challenge: `auth`, 1008, check 2 |
| 3. replayed signature | an accepted AUTH resent verbatim on a new connection: `auth`, 1008, check 2 (`WIR-9`) |
| 4. skew | `created_at` beyond `relay.auth_skew` either way: `auth`, 1008; a minute inside it is accepted |
| 5. unknown key, expired pass | a key with no pass, and a pass past its expiry: `pass`, 1008 |
| 6. recorded destinations only | a recorded host on another port is dialed, and bytes reach it; `127.0.0.2`, unrecorded: `destination`, 1008 |
| 7. pace | on another port within `relay.min_spacing`: `pace`, 1008; after it, accepted (the fixture's clock, frozen and moved). The window: the (`window_cap`+1)th dial in a window is refused, and accepted once the window has passed (on an injected clock) |
| 8. order | challenge, then OK after the AUTH, then binary; the log reads challenge sent, AUTH received, accepted, dial, OK sent, first forwarded byte |
| 9. a binary frame before OK | in place of the AUTH: 1002, no dial. After an accepted AUTH: 1002 and no OK, the destination receives no byte. The fixture holds OK until the frame has been read, one release per held connection. A frame ready when the dial completes is read first, which `the_pre_ok_step_reads_a_ready_frame_first` shows on the fixture's own pre-OK step, both ready at the first poll |
| 10. a text frame after OK | 1002; the destination receives none of its bytes, and its TCP connection closes |
| 11. a destination that speaks first | its bytes reach the client after `{"ok": true}`, and the log shows them forwarded after OK sent |

Every refused case also asserts that the fixture's log has no dial for that connection and the
listeners saw no connection and no byte. The limits are the bundle's, never shrunk to fit: the
fixture reads them from the vendored file, and `the_limits_are_the_bundles` holds what it reads
to that file's values.

**Where the policy reaches.** The page carries it in its `<meta>` element, which is all the served
build ships. A dedicated worker takes its policy from its own response, not from the page. The
tracer's HTTPS server sends the page's policy as a header on `worker.js`, so the worker runs under
it in the tracer, and case 4 shows it enforced there. A static host that sends no header leaves
the worker with no policy of its own; this repository ships no host configuration.

`CHROME` names the Chrome or Chromium binary. A missing browser or fixture fails the tracer and
never skips it. The tracer stops only the processes it started.

### Building and checking it locally

These are the `web` job's steps. They need the `wasm32-unknown-unknown` target, the wasm-bindgen
CLI at the version `Cargo.lock` pins for the crate (0.2.127; `scripts/build-web.sh` refuses any
other), and a clang that targets wasm32 for ring's C code, given as `CC_wasm32_unknown_unknown`
and `AR_wasm32_unknown_unknown`:

```sh
cargo clippy --locked -p tau-web --target wasm32-unknown-unknown --all-targets -- -D warnings
cargo clippy --locked -p tau-web --target wasm32-unknown-unknown --all-targets --features tracer -- -D warnings
scripts/check-adr-0024.sh                               # the wasm32 graph holds nothing ADR-0024 keeps out
scripts/build-web.sh served                             # -> dist/served
cargo run --locked -p tracer -- check-absence dist/served
cargo run --locked -p tracer -- check-csp dist/served
CHROME=/path/to/chrome scripts/tracer.sh                # builds both directories, runs every case
```

- `check-absence` reads every byte of the directory. It fails on any test key, private or
  public half, as raw bytes, hex or base64 (and the SSH key in OpenSSH's encoding), on the pin
  source's pins and marker, and on the test switches' names (`fail_append` among them). Run on
  `dist/tracer`, it fails and names each finding.
- `check-csp` parses the served page's policy into directives and sources, order-free, and fails
  unless it is exactly `ARC-33`'s four, naming each difference.
- `check-adr-0024.sh` reads `cargo tree` for the wasm32 build, with and without `tracer`. It fails
  on tokio `net` or `rt-multi-thread`, and on any russh feature but `ring`.

On Nix, ring's C code needs an unwrapped clang:

```sh
export CC_wasm32_unknown_unknown=$(nix build --no-link --print-out-paths nixpkgs#llvmPackages.clang-unwrapped)/bin/clang
export AR_wasm32_unknown_unknown=$(nix build --no-link --print-out-paths nixpkgs#llvmPackages.llvm)/bin/llvm-ar
```

## The gates

`build.rs` refuses to build unless `spec/` is the pinned tree — the commit HEAD records for the
submodule, actually checked out there, with no local change under it, an untracked file
included, since a scan of `docs/tenants/` would compile one in. It then parses every
`spec/bundle/*.toml` and compiles them and each `spec/docs/tenants/*/profile.md` in, exposing
the spec commit as `tau_web::SPEC_COMMIT`.

No brief is promoted out of draft yet, so none is compiled in. Since the corpus marks a draft
only in its own prose, the build watches that sentence: a brief that stops saying it is "not
yet in the signed bundle" stops the build, so promotion is decided here rather than shipping
as nothing.

**A `[session]` the specification's reference validator would refuse fails the build, by
design.** The build accepts exactly the `[session]` of `spec/bundle/inference.toml` that
`validate_session` accepts — in
`spec/docs/findings/2026-09-22-provider-routing/eligible-set.py`, the check the specification's
proposing job runs — so the two agree on what a valid bundle is. The specification's task list
(T37) says of a bundle that function raises on: "file reading, strict selection, draft
construction and the proposing job (before any network call) all refuse it". The gate is
`session_gate.rs`,
which mirrors that function check for check and adds no rule of its own. Each of these is a
publisher decision the build must not guess, and each fails the build:

- **the candidate order**, `model`: missing, not an array or empty; an entry that is not a table
  of exactly `slug`, `maker` and `provider`; a value that is not a string, or is empty or only
  whitespace. `ARC-31b`: "Each candidate also carries its hand-taken requested `provider`",
  "Missing or empty candidate providers MUST be rejected as selection inputs and MUST fail the
  build", and an empty value fails the build, "as does an empty candidate list". The maker is
  `SEC-9`'s too: "The maker is a fact the bundle records beside the model, never parsed from
  the model's name";
- **the allowlist**: missing or not an array — an empty one is accepted, and is today's value;
  an entry that is not a table of exactly `slug` and `provider`; a value that is not a
  string, or is empty or only whitespace. `TRU-A1a`: "Missing or empty allowlist providers
  MUST be rejected as selection inputs and MUST fail the build";
- **one slug, two providers**: a slug in both lists whose provider strings differ, compared
  exactly. `TRU-A1a`: "A slug that appears both in the candidate order and on the allowlist
  MUST carry the same provider in both; a mismatch MUST be rejected as a selection input and
  MUST fail the build.";
- **`context_floor` and `depth`**: missing, not an integer, or not positive. `ARC-31b`: "The
  floor is the publisher's decision, carried in `bundle/inference.toml` under `context_floor`;
  an empty value fails the build, as does an empty candidate list."; the order runs "to a
  fixed depth";
- **a `provider` directly under `[session]`**: the pin at `dde9e14` carried one there, and it
  now belongs on each entry (`ARC-31b`);
- **`retention`** other than `"strictest"`. `ARC-31a`: "`retention = "strictest"` in
  `bundle/inference.toml` means that request."

Where the validator checks more than a requirement says in "MUST fail the build" words — the
depth, an empty `slug` or `maker`, the exact key sets, the session-level `provider`, the
retention — the ground is that rule, the build accepts what `validate_session` accepts, and the
requirement cited is the one that owns the field. A slug listed twice within one list is
accepted, as the validator accepts it: the specification's task list (T37) says "*Undecided:* a
slug listed twice within one list."

`tests/session_gate.rs` compiles the same `session_gate.rs` and holds the build fixtures of
`CNF-88` — "Build fixtures reject missing or empty providers on either candidate or allowlist
entries, as well as the empty candidate list and context floor, and a slug carrying different
providers in the candidate order and on the allowlist." — beside one case for every other
refusal above and the pinned bundle's acceptance. The session-start selection that is the
rest of `CNF-88` has no code here yet.

`.github/workflows/ci.yml` runs, on every push and pull request:

| Job | Runs | For |
|---|---|---|
| `spec-checks` | `spec/bundle/cors-probe.sh` | `CNF-4` |
| | `spec/prototypes/spec-checks/check-install-disks.py`, and `--baseline`, which must fail | evidence for `CNF-85` |
| `build` (the job is `CNF-1`) | `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings` | `CNF-2`, at that strictness |
| | `cargo test --locked` | runs `build.rs`, so the gates above run here, and the `[session]` fixtures (`CNF-88`'s build fixtures); the relay matrix, `CNF-87`'s fixture half; the seed's tests, `CNF-83`'s derivation tests and `CNF-13`'s tests; the local store's, `CNF-82`'s and `CNF-15`'s host half (below); dispatch and journal recovery for `CNF-29`'s box-plane case, `CNF-30`, `CNF-39` and `STA-24` dispositions; and allocation's, `CNF-72`'s tests and the companion comparison against the allocation witness file (ADR-0032), with `CNF-3`'s three breaks as its unit tests |
| `web` (the job is `CNF-1` for the browser build) | `cargo clippy -D warnings` on wasm32, the served and the tracer build | `CNF-2`, on the new target |
| | `scripts/check-adr-0024.sh` | spec ADR-0024's build check |
| | `scripts/build-web.sh served`, then `tracer check-absence dist/served` | the served build (`ARC-32`) carries no test key, pin source or test switch |
| | `tracer check-csp dist/served` | `ARC-33`'s policy, exactly |
| | `scripts/tracer.sh`, in headless Chrome | `CNF-30`, `CNF-21`, `CNF-23`'s no-pin case and `ARC-33`, as above, the relay refusals of `CNF-87` a correct client meets, and the local store's `CNF-82` and `CNF-15` in the browser |

Every job checks out the submodule; `spec-checks` takes the full history, which
`check-install-disks.py --baseline` reads to reconstruct the pre-fix brief. `web` installs
Rust 1.97.1 with the wasm32 target, clang and llvm-ar, and the wasm-bindgen CLI at the pinned
version and checksum, with no manual step; the browser is the runner's Chrome.

`CNF-3` in its general form — "The test suite fails when a test is deliberately broken" — was
verified by hand on 2026-09-21, against a temporary pin filling the inference slugs: the one
test was broken deliberately, `cargo test` went red naming it, the restored test went green.
The three further breaks `CNF-3` names are the companion comparison's (ADR-0032). They were made
by hand on 2026-10-12 against `allocation::comparison::the_allocation_core_passes_the_companion_comparison`,
its path edited temporarily to a scratch copy of the witness file outside `spec/` (inside it,
`build.rs` refuses the build, which would be red for the wrong reason). Green against the
unmodified copy first; then:

- **One expected outcome flipped**: `TauWeb.Allocation.successful_trace`, step 1, `allocation`
  from `admitted` with its identity to `refused`. Red: "TauWeb.Allocation.successful_trace,
  step 1 (allocate): allocation: expected refused, actual admitted".
- **The file missing, then empty.** Red, naming the path: "…/allocation-witnesses-v1.json: No
  such file or directory (os error 2)", then "…/allocation-witnesses-v1.json: not a JSON
  document: EOF while parsing a value at line 1 column 0".
- **Unrecognised.** `enumeration[1]`'s event kind from `allocate` to `reallocate`. Red:
  "enumeration[1], step 1: not an event of the alphabet" and "enumeration[1], step 1: event:
  unknown variant `reallocate`". Then its outcome from `admitted` to `granted`. Red:
  "enumeration[1], step 1: unknown variant `granted`, expected `admitted` or `refused`".

Restored, the copy byte-identical to the pinned file, it went green, and the path edit was
undone, the test file byte-identical to its saved copy. The same three breaks stay as the
comparator's unit tests.
The tracer was broken the same way on 2026-10-12: case 1 was made to expect exit status 8 where
the fixture sshd answers the command with 7. `scripts/tracer.sh` (the `web` job's command, run
locally, not on GitHub) exited 1, naming case 1 and the assertion "the output and exit status came back". Restored, it
exited 0.
