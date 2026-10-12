# tau-web-rust

The implementation of the tau-web harness: a client-side AI harness that runs in a phone
browser and provisions real infrastructure on its operator's behalf. Rust, compiled to
WebAssembly, following the configuration the specification records.

**The specification lives in [`douglaz/tau-web-spec`](https://github.com/douglaz/tau-web-spec)
and is vendored here at `spec/`, pinned to an exact commit, today `1cc8498`** (spec ADR-0031).
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

## The harness

`src/` is the harness worker's wasm module, built for `wasm32-unknown-unknown` on spec ADR-0024's
configuration, beside the pinned inputs above. It runs in a dedicated worker the page starts,
because spec `STA-1` says "A single **harness worker** MUST be the only writer of durable state".
What it does so far is the tracer bullet of twr-ggw.2: one command over a pinned SSH connection
through the relay. The module exports `run_command`, the same entry point in both builds below.
The page defines no global and holds no reference to the worker's instance of the module, and
passes the worker no request; today only the tracer calls it there (below). Another same-origin
script could still load its own copy of the module and call it; in the served build that copy
refuses every machine for want of a pin, before any contact. The pins, keys and journal never
come from the request. The tracer build runs on test ones. The served build
runs on what it has stored, which is nothing until the local store exists and the seed-derived
keys are bound to sessions (twr-ggw.5, twr-ggw.11), so it refuses every machine at the first
step, before any contact. The connection path below is still whole in the served wasm, which is
what the absence check below reads. The seed code (below) has no caller yet, so the release build
drops it.
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
- **Record, then send.** It appends the command to the journal immediately before sending it as
  one `exec`, sends nothing if the append fails, and reconciles the journal's read-back against
  what was sent (`ARC-8`, `STA-3`, `STA-4`, `CNF-30`).

The page in `www/` is a bootstrap and holds no key, pin or record:

- `index.html` carries `ARC-33`'s policy in a `<meta>` element, before any script;
- `boot.js` starts the harness worker and shows whether it came up;
- `worker.js` loads the module and reports that it is up.

There are two builds of the same page, both release builds:

- **The served build**, `scripts/build-web.sh served`, written to `dist/served/` (ignored by git).
  It is what a static HTTPS host serves (`ARC-32`), with no test-only part.
- **The tracer build**, `scripts/build-web.sh tracer`, written to `dist/tracer/`. It is the same
  build with the `tracer` feature, which compiles in `src/testonly.rs`:
  - the test SSH client key, and two test relay keys, each with its public half recorded beside
    it: one the relay fixture holds a pass for, and one it holds none for;
  - the host-key pin source;
  - the in-memory journal;
  - the test switches a request can set: `test_relay_key` names the test relay key the AUTH is
    signed with, `with-pass` or `without-pass`, and any other value, or none, or a key whose
    secret does not derive its recorded public half, fails the request before any contact (a
    name, never key material); `fail_append` makes the journal refuse its
    append; `tamper_auth` sends a wrongly signed AUTH. twr-ggw.11 replaces the test relay keys
    with the relay key derived from the seed.

  Binding seed-derived keys in place of the test keys (twr-ggw.11) and a durable journal
  (twr-ggw.5) belong to later tickets. Derivation itself exists, below.

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

  `Credentials` hands out the role 0 and role 3 types and `PinSource` the pin type, and the
  tracer's test keys are built as them. The secret types print nothing of the secret, implement
  neither `Clone` nor `Serialize`, and keep their bytes inside the crate (`OVR-3`, spec
  ADR-0024). `CNF-13`'s tests read `SEC-5` from the pinned tree and fail on a type whose row is
  absent, struck through, not derivable today (row 22) or does not name it. A scan of every
  file under `src/` (with `syn`) fails on a type that holds key material by its field types
  (16-, 32- or 64-byte arrays, arrays whose length is not a literal, or a k256, ed25519-dalek,
  russh or ssh-key secret type) and has no row. It knows types by name, so it also fails when
  such a name, or a registered one, is defined by more than one type. The scan is a guardrail,
  not a proof: it cannot see a key carried in a `String`.

Nothing calls it at runtime yet, so the release build leaves it out of the served wasm, and no
`wasm_bindgen` export takes or returns a mnemonic, a seed or a key. The local store
(twr-ggw.5), allocation (twr-ggw.6) and binding the keys to sessions (twr-ggw.11) come next.

The tests hold it to the specification's v1 known answers, `credential-vectors-v1.json`, read
from `spec/` at the pin. They also check the upstream vectors vendored in `tests/vectors/` (see
its `README.md`): BIP-32's test vectors 1, 3, 4 and 5, RFC 8032's Ed25519 vectors, BIP-340's
public keys and the BIP-39 reference vectors. And a second implementation, the `bip39` and
`bip32` crates, agrees with it on 18 entropies, every role and indices up to 2^31−1. Those two
crates, `bs58` and `syn` are host-only dev-dependencies.

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
  accept it by its key hash alone.

The tracer then drives headless Chrome over the DevTools protocol. It runs a request by evaluating
in the harness worker's own context, over that worker's DevTools session: it imports the module
the worker already loaded, by the same URL, and calls its `run_command`. Neither build's page holds
a hook for it. Every case asserts on what the fixtures observed, not only on what the harness
reports. The relay fixture counts every TCP connection it accepts, at `accept`, before TLS and the
WebSocket upgrade:

| Case | What the fixtures show |
|---|---|
| the served build loads | its worker comes up and nothing errs, and the page has no `tauWeb` global and no global holding the worker. Called in its worker on the machine the tracer build pins, it refuses for the missing pin, and the relay accepts no connection and the sshd sees none |
| 1. recorded, then sent (`CNF-30`, `ARC-8`) | exactly one relay connection; the sshd received exactly the journal entry, and the output and exit status came back. With the append made to fail, the sshd received no `exec`, read only once that SSH connection has ended at the sshd |
| 2. a wrong host key halts (`CNF-21`, `SEC-11`) | no authentication attempt, no `exec`, no journal entry, and exactly one connection |
| 3. no pin, no contact (`CNF-23`'s no-pin case, `CHN-R4`) | no TCP connection accepted at the relay, none at the sshd, no dial, and nothing pinned afterwards |
| 4. the policy is enforced (`ARC-33`) | the loaded page carries the served page's policy token for token. An injected inline script raises a `script-src` violation and does not run. A `ws:` socket raises a `connect-src` violation in the page and in the worker |
| 5. the relay fixture's AUTH check is real | exactly one relay connection, and a wrongly signed AUTH gets `{"ok": false, "reason": "auth"}` and close 1008 at check 2, and nothing is dialed |
| 6. a relay key with no pass (`CNF-87`) | an unrecognised `test_relay_key` fails the request with no relay connection. Signed by the key with no pass, the harness reports `{"refused": "relay", "reason": "pass", "close_code": 1008}` |
| 7. an unrecorded destination (`CNF-87`) | the pinned machine `fixture` at `127.0.0.2`, a host the pass does not record: `destination` and 1008 |
| 8. pace (`CNF-87`) | the tracer puts the sshd's host at its window cap just before the run, so the refusal holds whatever the timing: `pace` and 1008 |

In cases 6–8 the relay fixture also accepted exactly one connection, dialed nothing, and its log
shows no frame from the client after the refusal but the close; the sshd saw no connection.
Case 1 also reads the order from the relay fixture's log: challenge sent, AUTH received,
accepted, dial, OK sent, then the first forwarded byte.

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
  source's pins and marker, on the journal's marker, and on the test switches' names. Run on
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
| | `cargo test --locked` | runs `build.rs`, so the gates above run here, and the `[session]` fixtures (`CNF-88`'s build fixtures); the relay matrix, `CNF-87`'s fixture half; and the seed's tests, `CNF-83`'s derivation tests and `CNF-13`'s tests |
| `web` (the job is `CNF-1` for the browser build) | `cargo clippy -D warnings` on wasm32, the served and the tracer build | `CNF-2`, on the new target |
| | `scripts/check-adr-0024.sh` | spec ADR-0024's build check |
| | `scripts/build-web.sh served`, then `tracer check-absence dist/served` | the served build (`ARC-32`) carries no test key, pin source, journal or test switch |
| | `tracer check-csp dist/served` | `ARC-33`'s policy, exactly |
| | `scripts/tracer.sh`, in headless Chrome | `CNF-30`, `CNF-21`, `CNF-23`'s no-pin case and `ARC-33`, as above, and the relay refusals of `CNF-87` a correct client meets |

Every job checks out the submodule; `spec-checks` takes the full history, which
`check-install-disks.py --baseline` reads to reconstruct the pre-fix brief. `web` installs
Rust 1.97.1 with the wasm32 target, clang and llvm-ar, and the wasm-bindgen CLI at the pinned
version and checksum, with no manual step; the browser is the runner's Chrome.

`CNF-3` in its general form — "The test suite fails when a test is deliberately broken" — was
verified by hand on 2026-09-21, against a temporary pin filling the inference slugs: the one
test was broken deliberately, `cargo test` went red naming it, the restored test went green.
The three further breaks `CNF-3` names are the companion comparison's (ADR-0032), and wait on
the test that reads a witness file, which does not exist here yet.
The tracer was broken the same way on 2026-10-12: case 1 was made to expect exit status 8 where
the fixture sshd answers the command with 7. `scripts/tracer.sh` (the `web` job's command, run
locally, not on GitHub) exited 1, naming case 1 and the assertion "the output and exit status came back". Restored, it
exited 0.
