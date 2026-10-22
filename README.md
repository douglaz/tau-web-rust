# tau-web-rust

The implementation of the tau-web harness: a client-side AI harness that runs in a phone
browser and provisions real infrastructure on its operator's behalf. Rust, compiled to
WebAssembly, following the configuration the specification records.

**The specification lives in [`douglaz/tau-web-spec`](https://github.com/douglaz/tau-web-spec)
and is vendored here at `spec/`, pinned to an exact commit, today `d029ebd`** (spec ADR-0031).
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

At the pin `d029ebd`, stage 1 is `STG-21`'s scenario: one live LNVPS machine on
catalogue plain Arch with no tenant, created through a typed adapter and paid by a Lightning
invoice from the operator's own wallet. Hermes is installed with its own installer.
Items 53 and 55 leave their `delivery_reboot` cases to the dedicated row. Item 95
cases (e) and (f) run on M alone at stage 1; their A/B output-release assertions, and
case (e)'s copied-key assertions, belong to stage 2.
LNVPS accepts no buyer boot configuration, so attest cannot run there (`STG-21`);
first contact uses `CHN-R7`'s published-key route. The table's attest row does not gate
LNVPS stage 1.

The pinned table's CNF items are **Stage 1: required**
`1–7, 10–17, 21, 23–26, 28–30, 32, 34–35, 37, 39–44, 49–56, 66–73, 78–79, 81–83, 87–91, 93–95, 99–104, 109–111`;
**Stage 1: record measurements** `45–47`; **Stage 1: model-written check reports** `107`;
**Stage 1: re-entry** `108`; and **Stage 1: recovery export/import and Replace** `19–20, 84`.
The **Attest first-contact route** items `18, 23 (attest-window case), 61, 74–75, 109 (attest admission)` do not gate
stage 1. These rows define completion requirements; the implementation described below is
still under construction.

## The harness

`src/` is the harness worker's wasm module, built for `wasm32-unknown-unknown` on spec ADR-0024's
configuration, beside the pinned inputs above. It runs in a dedicated worker the page starts,
because spec `STA-1` says "A single **harness worker** MUST be the only writer of durable state".
What it does so far is the tracer bullet of twr-ggw.2, one command over a pinned SSH connection
through the relay, recorded in the encrypted local store of twr-ggw.5 (below). The module exports
`run_command` and `collect_jobs`, the same entry points in both builds below. The page defines no global and holds
no reference to the worker's instance of the module. It sends passphrase, seed-backup, setup-approval and per-entry class-answer
messages to the worker, with no dispatch request; today only the tracer calls
`run_command` there (below). Another same-origin script could still load its own copy of the
module and call it; that copy has no unlocked store, so it refuses every request before any
contact. For approval and class-answer acts, the harness cannot distinguish an operator's click
from an identical message another same-origin script posts. While locked or running the
seed-backup ceremony, every request is refused before contact. The pins,
keys and journal never come from the request: the journal is the store's, in both builds. The
tracer build runs on test pins and keys. The served build runs on the pins and keys it has
stored, which are none until the seed-derived keys are bound to sessions (twr-ggw.11), so
after the seed-backup ceremony it refuses a command to an unapproved machine as `no-entry`,
and a command to an approved entry, like every collection, at the pin lookup, before contact
or append. The connection path
below is still whole in the served wasm, which is what the absence check below reads.
`src/harness/run.rs` does it in this order:

- **Entry first.** The journal check refuses a machine naming no approved entry before contact
  or append, then checks unresolved calls and dispositions.
- **Pin next.** It looks up the machine's host-key pin, and with none it contacts nothing.
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
- **Record, then send.** It appends the command and a fresh job identity to the store's journal
  immediately before sending one composed job wrapper as one `exec`. A failed append sends
  nothing. Recomposition from the journal's read-back must equal the transmitted wrapper bytes
  (`ARC-8`, `STA-3`, `STA-4`, `CNF-30`).

The page in `www/` holds no key or pin; it briefly displays mnemonic words only in the seed-backup ceremony:

- `index.html` carries `ARC-33`'s policy in a `<meta>` element, before any script;
- `boot.js` starts the harness worker, shows whether it came up and the store's one state, sends
  passphrase and re-entry buffers once, displays the seed-backup ceremony, locks, and reports the persistent-storage request
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
A box-plane call is unresolved after its approved intent, finished after its exit status's terminal record,
disposed with outcome unknown after an accepted disposition, or cancelled when a new-format
intent has no approval decision. These states are derived from committed records in journal
order (`STA-3`, `STA-8`); the core takes no time input and no timer clears anything. Replay
writes nothing, surfaces uncertain calls and never resumes or automatically reissues them
(`STA-6`, `STA-7`). The cancellation branch is exercised only through an authenticated crafted
record and a real unlock; no path in this build produces that record.

The harness admits an approved machine entry for which it holds a host-key pin. The decision's
identity will become the bound session's binding in twr-ggw.11 without changing the intent's shape.
The resource is the journaled approved entry, with its approval-time machine allocation index. `STA-20`'s unresolved-command
hold prevents every further box-plane command on that machine, reads and identical bytes
included. The check runs before contact and atomically with intent append under the single
writer. A held request records no intent and never runs afterwards: it collects the calls
holding it and answers held, even when that collection finishes them. The caller asks again.
Other machines remain independent. The unresolved-command hold is derived from the journal
and survives reopen; ended, missing, incomplete or unread records and elapsed time release
nothing. A finished record or a disposition naming the call releases its hold.

A disposition must name at least one call, each unresolved on its own resource or disposed by
the disposition currently standing there. A subset leaves unnamed calls unresolved. One
stands per machine, the latest accepted one, and the report shows what it replaces. Refusal
writes nothing and shows why, any settling record, and the resource's unresolved calls.
Destructive reinstall and abandonment refuse commands to that machine, before contact and
again atomically at the intent append. Continuing as if done and as if not done restrict
nothing, explicit reissues included, subject to any unnamed unresolved command's hold; their
recorded assumption is returned as an assumption with outcome `unknown`. A destructive
restriction ends only when its continuation's typed intent commits: the vendor reinstall, or
the abandonment flow's destroy. A failed append leaves it standing. The new intent's own barrier
then governs. Later terminal
evidence is recorded and shown without reopening the call or removing its disposition
(`STA-24`).

Replay tests dispositions in order with the same eligibility test. A refused one stays in the
journal and is shown with its refusal report, but ends no call, restricts nothing and replaces
nothing; it does not refuse the store. Parse, authentication and chain failures still do, as
does a terminal naming no call, a cancelled call or an already finished call, or an intent whose
identity is not its record number or whose command is not lowercase hex.
`store_state` shows calls and their job identities, approval decisions and states, terminals,
job-record evidence and findings, all disposition reports and the disposition standing per
machine, plus `typed_calls`, `observations`, `current_installations`, `setup` and `setup_offer`, without key material.
`setup` lists each entry's facts and cost, allocation family/index, nullable answer and class, and access model/profile/revision.
It contains no seed identifier; the page's store report carries the same setup projection.
Disposition records include both `machine` and `resource`: `machine` retains the command-era
shape, while `resource` names the entry or inference resource used by the typed derivation.
No disposition screen, disposition page message or disposition export exists. The browser disposition case uses a store built by
the independent reader, with no added request switch.

`run_command` reports completion as `{"done":true,"seq":1,"call":1,"terminal":2,...}`,
with output, exit status, the exact wrapper bytes in `sent`, journal command bytes in
`recorded`, and advisory `job_record` evidence. After an intent commits, an exec error,
channel close without a complete record, lost connection or evidence append failure reports
`{"unresolved":true,"call":1,"why":"…"}`, never failed. Whenever a valid job record was read,
the unresolved response also includes `job_record`, with the same state, comparison, output
and exit status as a finished response. Evidence whose append failed has `number:null`. The command's exit code is read from
its job record and journaled before completion is reported; the SSH wrapper's own exit status
never settles the command. An unapproved command refuses before the pin lookup as
`{"refused":"no-entry","machine":"fixture"}`, with no intent and no failed-append latch.
A mismatched command provenance target refuses at append as `{"refused":"provenance"}`.
As an **implementation reading**, `crate::harness::valid_request` refuses `run_command` and
`collect_jobs` JSON input that is not an object, has a member outside the build's fixed set,
or has a member of the wrong type. After JSON parsing, it reports
`{"outcome":{"refused":"request"}}` before other checks, with no contact or record.
Text that is not JSON fails earlier as a JavaScript error (`request: …`). The fixed set is `machine`, `relay`, `host`,
`user` and `command` (strings), and `port` (an unsigned integer from 1 through 65535).
The tracer build also accepts `test_relay_key` (string), `fail_append`, `tamper_auth` and
`test_no_credentials` (booleans). It validates supplied members without requiring them to be
present; the worker uses empty text and port zero for absent values.
Other pre-intent refusals keep their existing shape; a disposition refusal
is `{"refused":"disposition","disposition":2,"continuation":"abandonment"}`. An oversized
launch is refused before contact or intent with
`{"refused":"launch-too-long","why":"command is too long to launch; shorten the command","bytes":156406,"limit":131071}`
(the composed `bytes` vary with the command and machine). It allocates no call and leaves the
store able to admit the next command.

Typed operations share that derivation with commands. The fixture adapter offers `create`,
`reset`, `reinstall`, `destroy` and status `read`. Its retry safety is
`reconcile-before-retry`: mutation responses never confirm an effect. Its **fixture contract**
is a status observation reporting that operation's effect observed; an ended system or a boot
change establishes no success. This is fixture evidence, not an LNVPS reconciliation contract.
The fixture vendor and its receive log compile only in host tests, never in the served build.

A typed request carries its target, operation, session, requester and structured facts
(arguments, cost bound and bundle commit), with an approval on exactly those values and the
resolved resource. No approval, changed facts or an unmapped target refuses without a record.
As an **implementation reading**, the typed request check in `src/dispatch/typed.rs` also
refuses any `facts.arguments` key named `class`, `answer`, `access_model`, `setup`, `entries`,
`question`, `goal` or `proposal`, or any argument value equal to `sealed`. It reports
`RequestRefusal::Facts` with no record.
`Store::operation` repeats admission under the writer, commits, applies, then returns the
journaled approved intent for the adapter to send. Status reads have their own pre-send intent,
with state `no_effect`; observations are separately committed before they settle anything.
They carry the call snapshot taken before the read, so a delayed response cannot settle a
later reissue. Failed appends apply nothing; a landed move reporting failure applies on reopen.

The resource is an approved entry. Approval and its one allocation index replay from the journal.
As an **implementation reading**, ARC-15's batch is the setup's one approval: a second setup
approval is refused at the act and on replay, even with distinct entry names
(`setup already approved or empty`). Adding a machine to the set later belongs to twr-ggw.22.
Entry names resolve directly, and both entries and their indices exist after reopen with no
`associate` call. Approved entries start at installation 0. Requests supply no association and no resource.
`Dispatch::associate` accepts only allocation-index and vendor-machine targets on an already
approved entry, and refuses a target assigned elsewhere; `Store::associate` also refuses an
allocation index the machine family has not reserved. Its **implementation reading** is
in-memory harness knowledge: a vendor id learned at create, or a further index reserved for
another create attempt. Both wait for twr-ggw.21 to journal them; until then the harness supplies
only those associations again after reopen. They create neither entries nor installation ordinals.
The production command append resolves any provenance target against its command's approved entry
before commit. Existing intents retain their recorded resource, holds and dispositions without
requiring approval records; replay never treats those historical calls as a store refusal.
Inference has a distinct resource type, so no entry name can collide with it; this core admits
it, while twr-ggw.17 owns its journal.

Every unresolved machine call bars cloud-plane mutations on that entry, whatever its call id,
session or requester, including the operator flow. A second index for the same entry changes
nothing. Another entry is independent. Only an unresolved reset, reinstall or destroy adds a
box-plane stop; a create can remain unresolved beside a command. Commands retain their existing
hold. `run_command` checks both before contact and at append; a typed barrier answers
`{"refused":"barrier","calls":[<recorded typed intents>]}` and makes no connection. Pinned SSH
attempts and job collection remain reads, with no intent and no disposition check.

Within the disposed calls' reach, destructive reinstall permits the vendor reinstall only;
abandonment permits only the harness flow's destroy, never a session's destroy. Both stop every
box-plane command regardless of its requester or the disposed operation. Continuing choices
restrict nothing, including an explicit reissue. Reads and inference neither restrict nor end
a choice, nor does an operation on another entry. A replacement reports `replaces`, `dropped`
and an optional `assumption` containing the recorded continuing choice and outcome `unknown`.
Dropped calls stay disposed under the old record and cannot be named again. Refused replayed
records retain their reports. Later observations remain beside disposed calls and change
neither their outcome nor the standing choice. Each vendor reinstall intent advances the
entry's derived installation ordinal; display and its bound belong to twr-i6k.8.

Host fixture tests cover record-before-send at every storage kill boundary, lost creates across
all existing requester routes and aliases, facts approval, durable observations, failed and
landed appends, the 20 operation/continuation cases, naming and replay, replacement drops, late
evidence and continuation boundaries. In every matrix row collection names exactly the
collectable commands; command rows append collected job evidence and retain the disposition
and command verdict. The pinned SSH attempt has no host form; its evidence is the browser
cases. Browser cases use the independent writer to show an
unresolved reset refusing without relay or SSH contact, confirmation permitting a command, and
all four continuations preserving the real pinned attempt and collection with no intent.

**The dispatch companion comparison** follows ADR-0032's comparison rule. It reads
`spec/docs/design/dispatch-witnesses-v6.json` at run time, never compiled in. Its partition is an
**implementation reading**: rescue content first, then reboot content in start or steps, then
stage1. Empty reboot results and installation entries alone never route a trace; pairs stay
whole. The header requires schema 6, namespace `TauWeb.Dispatch`, 3 events over 8 distinct
alphabet events, and all 470 traces filtered to distinct request call ids, exactly once and
starting at `bound.start`. A truncated enumeration fails.

It runs stage1 only: 31 witnesses and 286 enumerated traces. The dedicated bucket, 54/184,
belongs to twr-i6k.3; reboot, 12/0, belongs to twr-i6k.11. Together they cover 97/470. Each start
journals a seed-backup completion, one batch approval with one index per entry, its calls and
dispositions, including the invalid historical disposition. Only the extra index and vendor-id
associations remain supplied in memory, including after reopen, until twr-ggw.21 journals them.
Every outcome and projection member is compared at every step. Oldest-first
members stay lists; resource/entry members are keyed sets. Unmoved members must stay empty.
Inference and dispositions on its resource run in the core without store records. Replay
actually reopens the store. Command requests use the existing intent and job-evidence path,
with target, session and requester provenance recorded by the production append. The file's
approval facts map bijectively to the recorded pin admission's fingerprint, and its approval
session maps to the recorded command session. No typed operation approval is attached to a
command. Current `run_command` records its named target with no session; older command records
retain their shape.
The driver maps witness allocation indices bijectively from production returns: approve entry 2
then entry 1, reserve the extra index with `Store::allocate`, then associate the vendor id. At this
start the map is witness 2 ↔ production 0, 0 ↔ 1, 1 ↔ 2. It is fixed, injective, retained across
reopen, and applied in target conversion both ways, beside the entry, vendor, session, fact and
call mappings. Associations stay an oldest-first list under this ordering. Reopen supplies only
the extra index and vendor id; it never reconstructs approved entries or their journaled indices.
The driver retains only identity mappings beside that production store and never projects its
own request cache.

Production assumptions are `resourceKey: entry`, `reach: disposed`, `lapse: continuation` and
all boolean guards true. Every unpaired trace and refused side matches, and each admitted side
changes exactly its named guard and differs somewhere. All twelve stage1 pairs are required.
Unknown vocabulary or members fail with the trace and step. Permanent negative controls include
an outcome flip, empty/absent file, unknown event/outcome, truncated enumeration, unknown
member, missing pair side, a second disabled guard and wrong routing counts.

The core and fixture tests were written from the Markdown before the witness JSON was read.
Projection setup exposed two omissions before the first comparison: known entries must resolve
when named directly (`STA-24`), and named entries start at installation zero (`STG-20`). Both
were corrected from those requirements. The comparison then raised no behavioral disagreement.
Its successful record is printed by
`cargo test --locked dispatch::comparison -- --nocapture`; the implementation revision is the
commit the test ran at:

```text
dispatch companion comparison: passed
  rule: ADR-0032, How the implementation is compared; ticket partition is an implementation reading
  file: spec/docs/design/dispatch-witnesses-v6.json
  schema 6, module dispatch, namespace TauWeb.Dispatch, bound: 3 events over an alphabet of 8, distinct request call ids
  stage1: 31 witnesses / 286 enumerated traces (twr-ggw.8)
  dedicated: 54 witnesses / 184 enumerated traces (twr-i6k.3)
  reboot: 12 witnesses / 0 enumerated traces (twr-i6k.11)
  total: 97 witnesses / 470 enumerated traces
  compared: start, every outcome and projection member at every stage1 step; keyed sets compared by key
  commandHold: 4 named / 28 enumerated refusals
  pair: TauWeb.Dispatch.boot_id_change_not_success_refused refused matched; TauWeb.Dispatch.boot_id_change_not_success_admitted admitted differed at step 2
  pair: TauWeb.Dispatch.destructive_choice_stops_commands refused matched; TauWeb.Dispatch.command_preempts_reinstall_without_guard admitted differed at step 3
  pair: TauWeb.Dispatch.disposition_names_own_unresolved_calls refused matched; TauWeb.Dispatch.disposition_ends_call_elsewhere_without_guard admitted differed at step 3
  pair: TauWeb.Dispatch.disposition_one_continuation_refused refused matched; TauWeb.Dispatch.disposition_unrestricted_admitted admitted differed at step 2
  pair: TauWeb.Dispatch.read_and_inference_never_restricted refused matched; TauWeb.Dispatch.read_and_inference_restricted_without_guard admitted differed at step 5
  pair: TauWeb.Dispatch.read_does_not_lift_abandonment refused matched; TauWeb.Dispatch.read_lifts_abandonment_without_guard admitted differed at step 3
  pair: TauWeb.Dispatch.replacement_in_force refused matched; TauWeb.Dispatch.replaced_continuation_dispatched_without_guard admitted differed at step 5
  pair: TauWeb.Dispatch.resolution_append_failed_refused refused matched; TauWeb.Dispatch.resolution_append_failed_admitted admitted differed at step 2
  pair: TauWeb.Dispatch.same_action_new_call_id_refused refused matched; TauWeb.Dispatch.same_action_new_call_id_admitted admitted differed at step 2
  pair: TauWeb.Dispatch.second_command_held refused matched; TauWeb.Dispatch.second_command_without_hold admitted differed at step 2
  pair: TauWeb.Dispatch.second_index_same_entry_refused refused matched; TauWeb.Dispatch.second_index_same_entry_admitted admitted differed at step 3
  pair: TauWeb.Dispatch.session_destroy_under_abandonment_refused refused matched; TauWeb.Dispatch.session_destroy_lifts_abandonment_without_guard admitted differed at step 3
  spec commit: d029ebd9f632696bb027a22559d774d165685947
  implementation revision: the commit the test ran at
```

This comparison is evidence about harness knowledge alone; the storage and browser fault tests
carry ordering and contact evidence. Approved entries and their approval-time indices are
journaled here. Binding waits for twr-ggw.11, and actual session tools/routes for twr-ggw.14. The
per-tool create case waits there; no extra route is invented here. Creating/paying and learning
the vendor id are twr-ggw.21's; inference records twr-ggw.17's; the abandonment flow and its
authorization twr-ggw.31's; LNVPS fixture and criterion 23's LNVPS half twr-ggw.32's; stop and
renewal-off twr-ggw.40's; LNVPS reinstall twr-ggw.45's; operator rendering twr-ggw.66's and
refused request results twr-ggw.67's. Rescue rules and remaining reboot traces belong to
twr-i6k.3 and twr-i6k.11. Snapshots, compaction, retention and stage 2's untyped-scope hold remain
outside this work.

### Job records and collection

`src/jobs.rs` composes the installed-system wrapper from the journal's command bytes. Its
POSIX `sh` text receives command and machine bytes as octal `printf '%b'` operands, so quoting,
newlines and non-ASCII bytes do not become wrapper syntax. Each intent has a fresh 192-bit
random job identity, lowercase hex, recorded before transmission. It is independent of the
store's record number and exposes no store-wide identifier. Older intents without a job
identity remain unresolved and are not collected.

Before any contact or intent, the harness measures the whole composed launch, using a
48-byte placeholder for the job identity. `MAX_LAUNCH_BYTES` is 131071: sshd runs this text as
one `$SHELL -c` argument, and Linux `MAX_ARG_STRLEN` is 32 × `PAGE_SIZE`, or 131072 bytes at
4 KiB pages, including the terminating NUL. Larger pages only raise that limit. A longer
launch is refused with its size, limit and a request to shorten the command; nothing is
journaled. This is a byte bound on the wrapper, including the octal-encoded machine and
command and embedded scripts, rather than on the command alone.

The wrapper reserves `/var/lib/tau-web/jobs/<job>/` with `mkdir`, under `umask 077`: directories
are 0700 and files 0600. It writes `command` (the bytes received), `machine`, and `boot` from
`/proc/sys/kernel/random/boot_id`. `setsid` starts a detached runner with no SSH descriptors.
The runner atomically records its own PID and Linux `/proc/<pid>/stat` start time in `runner`.
A small interpreter atomically records its own PID and start time in `pid`, then uses
`exec sh "$d/command"`: the command runs as its own script with that same PID and start time,
without sharing wrapper variables or traps. Startup is marked with `ready`. Both startup
loops re-test their file (`pid` in the runner, `ready` in the launch) after `kill -0` fails:
a fast child may have published it and ended between the first file test and the liveness
test. The runner still waits for the command's saved exit status after the shell reaps it.
The command's stdout and stderr go directly to the files `stdout` and `stderr`. The runner
waits for that command alone. For a `wait` status of 0–128, it writes the exit code to `exit.pending` and
renames it to `exit`. It never waits for background descendants. No standard
input is written to disk; no command takes input yet. A connected exec reads these files as soon
as the command ends, including when a background process retains stdout (`STA-20a`).

An existing job directory is refused without changing its record. This is an implementation
reading stricter than `STA-20` for an installed system, carried over from the rescue rule;
normal operation never resends a wrapper. A wrapper refusal or setup failure leaves the call
unresolved and never becomes a command exit code. The reason includes up to 2048 bytes of
wrapper stderr, decoded lossily; a nonzero wrapper status never becomes a command exit code.

`collect_jobs` takes the same target fields as `run_command`, without a command. It is refused
while locked, and without a host-key pin before contact. It reads every unresolved call's job
record on that machine, and disposed calls without job evidence. Each collection exec contains
only read text and an identity, never the original command or launch text. Collection appends
no intent, writes nothing on the machine and bypasses the command disposition check. Its
`{"outcome":{"collected":[...]}}` report carries each call's evidence, state, output and exit
code. Each call is independent: a read, parse, validation or append failure reports
`{"call":1,"job":"…","failed":true,"why":"…"}` and collection proceeds to the next call.
An append failure also retains the read evidence in `job_record` with `number:null`.
Nothing is retried. If the connection ends, earlier outcomes remain in the response and the
unreached calls are listed with `not_read:true`. Evidence is durably appended before the
projection changes (`STA-3`).

Waiting runs on the machine with shell sleeps and no browser or Tokio timer. An existing
exit record is final and is read before any liveness wait. Both command and runner liveness
require the recorded boot and PID start time to match, so a recycled PID establishes no
liveness. If the command has ended but its original runner is still publishing its exit, the
read lets publication complete and checks the exit file again after observing runner death.
Scalar files are read with shell builtins and checked against their exact byte counts once,
before waiting (or when an exit file appears); discarded bytes fail the read. Process liveness
is read with shell builtins; a waiting pass spawns only
one `sleep`. The first second uses 50 ms sleeps, the next two use 250 ms sleeps, then sleeps
are one second. Output encoding runs only when returning the record.

An exit code establishes `finished`, even after a reboot. **Only a `wait` status of 0–128 is
recorded as an exit code.** POSIX `sh` cannot distinguish signal death from a genuine exit of
129–255, so all those statuses read `ended`, stay unresolved with outcome unknown, and write
no terminal record. This includes `exit 137` and a script whose last child was killed by a
signal and which exits with that child's 128+n. This ceiling is chosen so that no signal death
is ever recorded as an exit code.

An unreadable or invalid required record file makes the whole read fail: the wrapper returns
nonzero with the filename in stderr, and no record fields are reported. Missing output is
never presented as empty output. Collection reports that failed read and continues to the
next call.

A changed boot or a gone command without an exit code likewise establishes `ended`, outcome
unknown: **no terminal is written**. A missing record stays `missing`, unresolved, and is never
proof of death. An interrupted launch can leave an `incomplete` record: any received machine
and command bytes are retained as evidence, but it establishes no end or outcome. A record
with no command PID and no exit code is also incomplete. Another machine's record settles
nothing. Ended, missing and incomplete calls remain eligible for later collection. No timer
ends a call or gives up on it.

Every received command is compared with the journal, on the live path as well as collection
(`CNF-56`, `STA-21`). Agreement is `advisory_match`; a mismatch is a `finding` carrying `journal`
and `received` bytes. These are machine-reported evidence, with no claim against a machine that
lies. **A mismatched record still settles the call** with its recorded exit code, beside the
finding. The evidence and finding survive reload and unlock.

Collection is never held by the unresolved-command hold or a disposition. A standing disposition
stays standing and its call stays disposed, with later evidence shown beside it (`STA-24`).
`collect_jobs` reports a call whose own dispatch still awaits its record as `not_read`, with
`why: "own dispatch awaits its record"`; it neither reads nor appends that call separately.
A held `run_command` instead waits for that dispatch's exact result. Registration happens in
the same worker poll as intent append returns, before another await. This registry is only
in memory: after restart, a held request reads the job record normally.

A held request reads only its holding calls, using the existing reader that waits while the
command's own process or runner is alive on the recorded boot. The wait holds no store lock.
`store_state`, collection and another machine's requests can proceed. A machine that cannot
be reached is answered immediately with why nothing was read, with no reconnect or retry.
No job identity means nothing can be read and only a disposition can release that call.

Both builds export `stop_waits(machine: string): number`: it stops all currently registered
unresolved-command waits on that machine and returns their count. It leaves other requests
and detached commands running. An interrupted read is abandoned without appending evidence;
waiting to acquire the writer is also stoppable. No evidence append begins after a stop,
but an append already begun completes whole and its evidence stands. A stopped wait answers
held with what was read so far and why the other calls were not read. It settles nothing and
arms no later dispatch. There is no timer for the wait.

The held answer is distinct from `done`, `unresolved` and `refused`. For example, a stopped
request reports:

```json
{"held":true,"machine":"fixture","calls":[{"call":1,"not_read":true,"why":"stopped while reading record"}],"release":["finished_record","disposition"]}
```

Each `calls` entry names the holding call and either carries the collected job report directly
(including `state`, `record`, output, comparison and committed record number), `not_read` and
`why`, or `dispatch_result` containing its own dispatch's exact report. A completed read whose
evidence append did not land carries `not_journaled: true`, `job_record` with the record as read,
and `why`, without `not_read`. This includes a stop before journaling and an append error,
for example when concurrent collection already finished the call. A collected call may
show `state: "finished"` while the request still says `held: true`. An unreachable `why` carries
an `unreachable` object naming the connection refusal. Under a standing destructive disposition
the held answer also carries `disposition`, `continuation` and `dispatch_still_restricted: true`;
releasing the unresolved-command hold does not lift that restriction.

Sessions will call collection at re-entry in their own tickets. Rescue records and planned-reset
handoff, service lifecycle and standard-input harness jobs are outside this change.

The host wrapper suite in `tracer/src/machine.rs` runs against the real reader under bash
and dash. `missing_record_files_fail_instead_of_fabricating_fields` covers absent files,
directories and dangling links; `invalid_scalar_files_fail_without_malformed_output` covers
malformed scalars. `nul_bytes_in_scalars_fail_instead_of_being_discarded` covers all five scalar
sources, and `scalar_records_accept_only_exact_ascii_forms` checks exact spacing and optional
newlines. `exit_file_above_128_fails_the_read`, the record validation test
`exit_status_ceiling_is_128_in_records_and_deliveries`, and the store test
`job_terminal_above_128_refuses_replay` enforce the same ceiling at each boundary.
`incomplete_record_present_unreadable_files_fail_instead_of_null` distinguishes absent entries
from unreadable ones. The signal-collision and background-output tests record their detached
children's PID and start time and end them only while that identity still matches.

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
  not a proof: it cannot see a key carried in a `String` or a `Vec<u8>`, a union's fields, or a
  key type imported under another name. Three types it flags are exempt, each with its reason:
  the store's ID, the PBKDF2 salt and a record's content address, all persisted in the clear by
  design. The three local-store types also zeroize their bytes on drop.

The local store generates the seed in the worker and keeps its mnemonic in its first record
(below). Only seed-backup exports display and accept mnemonic words; no export returns a seed
or child key. Allocation
(twr-ggw.6, below) issues the indices the keys derive at; binding the keys to sessions
(twr-ggw.11) comes next.

The tests hold it to the specification's v1 known answers, `credential-vectors-v1.json`, read
from `spec/` at the pin. They also check the upstream vectors vendored in `tests/vectors/` (see
its `README.md`): BIP-32's test vectors 1, 3, 4 and 5, RFC 8032's Ed25519 vectors, BIP-340's
public keys and the BIP-39 reference vectors. And a second implementation, the `bip39` and
`bip32` crates, agrees with it on 18 entropies, every role and indices up to 2^31−1. Those two
crates, `bs58` and `syn` are host-only dev-dependencies.

### The seed-backup ceremony

`STA-23` and ADR-0047 require a record for each generated seed. Create, a creation-finishing
unlock and every later unlock with no completion show all twelve numbered words. The page
says new machines, relay passes and handoffs are refused until the record exists (`STA-22b`).
Imported seeds owe no new seed-backup ceremony and still cannot allocate.

The operator explicitly hides the words before answering. The word container is removed from
the document, then the operator re-enters all twelve words or explicitly skips the check.
`Store::seed_backup_reentry` imports the zeroizing input and compares its seed identifier;
any mismatch, word-count, list or checksum error returns to display without recording anything.
The textarea disables completion, spelling and capitalization hints and clears immediately on
submit and every lock. Re-entry refusals use fixed plain text, naming an unlisted word only by
its position.

A completion appends `seed_backup` with this seed's identifier and `full_reentry` or `skipped`
before applying it. The page always states which completion is recorded (`SEC-2`). A failed
append changes no completion; the page explains that it was not recorded and requires reload
and unlock. For a generated seed with no earlier record it says the seed-backup ceremony is
still owed; on re-display over an earlier record it names the completion that still stands.
An imported seed with no earlier record remains exempt. Inspection exposes `seed_backup_owed`,
`seed_backup_stage` and `seed_backup_completion`, with no words. Every dispatch request and collection refuses before
contact while the seed-backup ceremony runs. Allocation's independent gate still checks the
durable completion in all three families.

Re-display terminates the worker through the ordinary lock, ending its connections and held
waits. The local passphrase must unwrap a fresh worker's store before the same seed-backup
ceremony shows words. It journals another completion; a failed append preserves the previous
record. Nothing stopped resumes: a cut-off call stays unresolved and a held request records no
intent. Tab close, page hide, worker death, pagehide, bfcache restore and explicit lock remove
words and input; an incomplete generated seed still owes its seed-backup ceremony at unlock.

The custody exceptions are exactly worker-to-page `{seed_backup_display: "<twelve words>"}`
and page-to-worker `{seed_backup_reentry: <UTF-8 Uint8Array>}`. Re-entry uses a transferred
buffer, zero-filled by the module, and a zeroizing Rust buffer. Passphrases have separate exact
create, unlock and `seed_backup_redisplay` shapes. The two seed-backup exceptions exempt only
the mnemonic needles of seeds displayed during the run; passphrases, keys and seed identifiers
remain findings in those messages. No other message, log, fixture request or storage may
contain the joined mnemonic, entropy, seed or keys. The tracer searches these secrets in raw,
hex, HEX, base64 and base64url forms, including all seed secrets from earlier fixture stores.
It searches whole console event payloads, including property names, URLs, stacks and arguments.
Decrypted non-seed records are checked too; only a record's canonical allocation seed association
is allowed at its specified field. Consecutive mnemonic string elements are detected inside
parsed JSON arrays, so object values cannot collide with the next field name. There are no
single-word token searches and no field-name exceptions in the literal search.

Hiding checks compare the complete document and every field value at the same stage under
different seeds. Attribute order is canonicalized without removing content or attribute values.
Four valid collision-control mnemonics include the fixed texts' listed words and adjacent
phrases. They exercise host refusals and inspection, the independent reader, and browser
display, answering, mismatch, full re-entry and lock in both builds. Planting twelve hidden
word elements changes the document and is reported; phrase, array and binary leaks still fire.

The Replace flow and a second store seed belong to twr-ggw.29; the core already clears the
record for a fresh seed and gates its allocations, while store replay refuses Replace today.
Sheet import belongs to twr-ggw.27. Session workers do not exist until twr-ggw.11 and twr-ggw.14;
the seed-backup ceremony stops the dispatch waits and connections that do exist.

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
- **What the records carry.** Each record's plaintext is one event, compact JSON. Command
  examples also describe pre-ticket records; a new store now journals its seed, ceremony
  completion and setup approval before its first intent:
  - record 0, the seed, generated in the worker: `{"seed":{"mnemonic":"…"}}`, the mnemonic's
    words;
  - an intent, immediately before one `exec`:
    `{"intent":{"call":1,"machine":"fixture","command":"<lowercase hex>","approval":{"harness_pin":{"machine":"fixture","fingerprint":"SHA256:…"}},"job":"<48 lowercase hex digits>"}}`.
    The call identity is the intent's record number, unique and never reused. The approval
    decision identifies the harness's admission using that machine's pin; it is not the
    operator's approval of the command's contents. Optional `provenance` contains `target`,
    `session` (text or null) and `requester` (`session`, `operator` or `harness_flow`), separately
    from that admission. The production append resolves its target to the command's approved entry
    before commit, then records the provenance;
    `run_command` supplies its directly named entry, no session, and requester `session`.
    No command carries typed operation facts or an `OperationApproval`. A new-format intent with `approval:null`
    (or an absent approval member) means never dispatched. No path in this build writes one.
  - a typed intent under `operation_intent`: `call` (its record number), `resource`
    (`{"entry":"fixture"}`), `target` (`{"entry":"fixture"}`, `{"allocation_index":0}` or
    `{"vendor_machine":"id"}`), `operation`, `session`, `requester` (`session`, `operator` or
    `harness_flow`), `facts` and `approved`. Facts contain `arguments` (a map of text values),
    `cost_bound` (an unsigned integer) and `bundle_commit`. Approval repeats the resource,
    target, operation, session, requester and facts exactly. Operations here are `create`, `reset`,
    `reinstall`, `destroy` and `read`; the writer refuses `exec` and `inference` as policy, and
    replay and the independent reader reject such typed records and intents naming the inference
    resource or target, naming the record.
    No command text is accepted for a typed act.
  - `{"operation_observation":{"resource":{"entry":"fixture"},"operation":"reset","reports":"confirmed","calls":[1]}}`.
    `reports` is `confirmed`, `ended` or `unknown`; `calls` is the snapshot at read time.
    Only the fixture's confirming observation settles an unresolved matching mutation.
    Disposed calls retain their unknown outcome; the observation is still journaled and shown.
  - a legacy terminal record, still read and used by host dispatch tests:
    `{"terminal":{"call":1,"exit_status":7}}`. It carries no output; the command report carries
    output. New command completion uses the job terminal below.
  - a job terminal, carrying the machine-reported record and its output:
    `{"job_terminal":{"call":1,"job":"<48 hex digits>","record":{"kind":"present","machine":"<hex>","command":"<hex>","boot":"…","current_boot":"…","pid":123,"alive":false,"exit_status":7,"stdout":"<hex>","stderr":"<hex>"}}}`.
    The exit code is 0–128, following the rule under "Job records and collection". This is the terminal that settles an unresolved call; a disposed call
    keeps its disposition. Replay derives the advisory comparison and any finding from it.
  - a job observation, the same evidence envelope under `job_observation`: a present record
    without an exit code establishes `ended` when the boot changed or the command is gone;
    `{"kind":"missing"}` establishes no outcome; `{"kind":"incomplete","machine":null,"command":"<hex>"}`
    preserves available startup bytes (each field may be null). A present record naming another
    machine is an observation even if it has an exit code. None of these is a terminal, and
    replay refuses an observation pretending to carry a same-machine finished or running job.
    Both evidence shapes must name an eligible call and its exact job identity. Unknown,
    cancelled and already finished calls, malformed bytes and mismatched identities refuse replay.
  - an operator disposition:
    `{"disposition":{"machine":"fixture","calls":[1],"continuation":"abandonment","uncertainty":"the command outcome is unknown"}}`.
    The other continuation values are `destructive_reinstall`, `as_if_done` and `as_if_not_done`.
    It carries the uncertainty accepted and no outcome.
  - a pre-ticket `{"command":{"machine":"…","command":"<hex>"}}` record remains readable.
    Its missing approval member proves nothing: it was written before transmission. It becomes
    an unresolved call with its record number and the admission marker `legacy_command`, never
    a cancelled call.
  - a setup act: `{"setup":{"approval":{"entries":[{"entry":{"machine":"fixture","vendor":"Fixture vendor","product":"Fixture machine","region":"Fixture region","cost":{"amount":1000,"unit":"sat","period":"month"}},"identity":{"seed":"<seed identifier>","derivation_version":1,"family":"machines","index":0},"access":{"model":"maintained","profile":"ad-hoc","revision":3}}],"monthly_sat":1000,"annual_sat":12000}}}`.
    Production approves both fixture entries in this one record (the single-entry example only
    illustrates the shape). Every index is reserved through the allocation core on a clone;
    the record commits before either projection is swapped in. No separate reservation precedes it.
    A per-entry answer is `{"setup":{"class":{"machine":"fixture","answer":"not_sure","class":"multi_tenant"}}}`.
    Answers are `yes`, `no`, `not_sure`; classes are `single_purpose`, `multi_tenant`.
    Replay also reads `{"setup":{"access":{"machine":"fixture","access":{"model":"maintained","profile":"ad-hoc","revision":3}}}}`.
    This last shape and an approval's explicit `access:null` support independent missing-fact
    replay fixtures; the production approval always records maintained access.
    The independent reader requires exact object members and enum values throughout these setup
    shapes. Production always writes objects and refuses unknown members and enum values, but
    its derived replay deserializers also accept positional arrays for setup struct bodies.
    Repeated entries/answers, unapproved facts, inconsistent
    classes/totals, invalid allocation order or gate, and sealed ad-hoc access refuse replay,
    naming the record without quoting plaintext. None carries derived key material.
  - a later record, one allocation event appended before it is applied ("Allocation", below):
    `{"allocation":{"reserve":{"seed":"<seed identifier>","derivation_version":1,"family":"machines","index":0}}}`;
    `created`, `failed` and `destroyed` carry the same identity; `restore` carries an export,
    `{"seed":…,"derivation_version":1,"next_unused":{"machines":…,"passes":…,"handoffs":…},"entries":[{"identity":{…},"status":"reserved"}],"restored_from_import":…,"seed_backup":null}`;
    `seed_backup` carries `{"seed":…,"completion":"full_reentry"}` (or `skipped`); the metadata
    stores that completion or `null`. `replace` carries `{"seed":…}`. The seed identifier is in the clear only inside the
    encrypted record, where credential format v1 puts it.

  The independent reader in the tracer crate decrypts every record and reads the seed, legacy
  command, intent, typed intent, typed observation, terminal, job terminal, job observation,
  disposition, seed-backup and setup approval/class/access shapes, with exact setup members.
  It checks a completion against the seed identifier it derives independently, and inspects reservations.
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

- **The passphrase.** The page sends its UTF-8 bytes once, in one create, unlock or seed re-display message, and
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
  connection that WebSocket carries, and its exec. A detached job continues on the machine,
  to be collected after unlock; the worker replays the journal.
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
- **The seed-backup ceremony** above is the only mnemonic display; every other record and
  inspection excludes its words.
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
  `created`, `failed` or `destroyed`. Beside them, the current seed's seed-backup ceremony record,
  `full_reentry`, `skipped` or none, and whether the seed was imported with no Replace since.
- **Families.** Roles 0–2 share the machine index; role 3 takes a pass index and role 4 a handoff
  index (`STA-22`; credential format v1's role table). Each family has its own counter.
- **The seed-backup gate.** Every family under a generated seed refuses allocation until that seed
  has its journaled `STA-23` completion. Both full re-entry and explicit skip admit allocation;
  neither is a verified-backup claim.
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
  allocation, in every family, is refused until a Replace, with or without a seed-backup ceremony record:
  `STA-22b` says "every imported seed may restore listed identities but MUST NOT allocate new ones".
  Restore copies the exported seed-backup ceremony record. An
  export recording a derivation version other than 1 is refused (`STA-22a`).
- **Replace** is an event that takes a freshly generated seed's identifier. The restriction
  clears, and the seed-backup ceremony record clears too. Generating the fresh seed is never gated, but
  its allocations wait for its own record. Each family starts at 0 under it, and the old
  entries are retained under the old seed's identifier (`STA-22b`: "old records are retained
  until migration is complete"). A Replace to the current seed, or to one an entry already names,
  is refused: it would issue a recorded identity again.

**Journaled in the local store.** A standalone allocation event is a record of its own ("What the records
carry", above); setup approval carries its own machine reservations atomically.

- **Append before apply** (`STA-3`). `Store::allocate` takes a family and no index. It asks the
  core what it would issue, appends the reservation, applies it once the append commits, and
  only then returns the identity. A failed append returns no identity and moves no counter. A
  move that landed but reported failure is replayed after the restart, so its index stays
  consumed and is never issued again.
- **Seed-backup completions.** `Store::seed_backup` journals the stated completion for its own seed,
  append before apply. Replay takes it through the core; another seed's completion refuses the
  store. A failed append leaves no completion. The dedicated seed-backup ceremony supplies it after full re-entry or explicit skip.
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
created from an imported seed today. The tracer-only `test_allocate` export reaches
`Store::allocate`; setup approval is also a machine-family allocation consumer in the served build.

**The tests** (`cargo test`). On the core: each family's own counter; a recorded identity never
reserved again or revived; tombstones never reissued; exhaustion, started at 2^31−1; an unknown
derivation version; every import above; the seed-backup ceremony gate in each family for both completions; wrong-seed
completion refusal; and Restore copying and Replace clearing the record. On `MemoryStorage` stores: roles 0–4 derive
the same keys at an allocated identity after a reopen, and different keys at another index
(`CNF-72`); an observation that does not apply journals nothing; each crafted record listed under
Replay refuses the store at unlock; the reservation's move commits before the identity returns; a
failed append, a move that lands then fails, and a worker killed after the commit; failed and
destroyed indices never reissued across a reopen; the journaled restore; and seed-backup ceremony persistence and failed appends across a reopen.

**The companion comparison** (spec ADR-0032, "How the implementation is compared").
`src/allocation/comparison.rs`, a host test, reads `spec/docs/design/allocation-witnesses-v2.json`
from the pinned tree at run time with `std::fs`. It is never compiled in (ADR-0031), so a missing
file is a red test.

- **The header.** Schema 2, module `allocation`, non-empty `witnesses` and `enumeration`, and an
  enumeration of exactly every trace of at most `bound.events` events over `bound.alphabet`,
  each once: Σ|alphabet|^k traces for k = 0…events, every event from the alphabet, no sequence
  twice, each starting from the initial journal: seed ordinal 0, derivation version 1, every
  family's `next_unused` 0, no entries, `seed_backup: "none"` and `restored_from_import` false. A named witness starts
  where the file says. A truncated file fails.
- **Every trace**, all 8 witnesses and all 4681 enumerated traces, drives the production core from
  the trace's `start`. Seed ordinals map to seed identifiers the driver generates, in order;
  `export_sheet` keeps the core's export, and `restore` passes the latest one, or with none
  restores nothing. After each step it compares the outcome (`allocation`, and `identity` when
  admitted), `recorded` for `seed_backup`, and the `journal` projection with what the core says
  and holds. A seed-backup event takes its completion and nested append outcome; a non-durable
  append applies nothing.
- **Both pairs.** The guards are exactly `restoredAllocatesNone` and `backupRecorded`.
  Unpaired traces and refused sides run with both true and must match every step. Each admitted
  side runs with exactly one false and must differ somewhere, and each guard needs its own such
  side. The production core has neither switch. Both the `backup_missing` and `stale_sheet` pairs
  are recorded as negative controls.
- **Anything unknown fails**: an event kind, provenance, family, status, outcome, assumption or
  member. Every failure names its trace — a witness by its declarations, an enumerated trace as
  `enumeration[i]` — and its step, with the expected and actual values.
- **Its own negative controls.** Unit tests build `CNF-3`'s three breaks in memory from the
  pinned file — an outcome flipped; empty bytes and an absent file; an unknown event kind and an
  unknown outcome — plus a truncated enumeration, an unknown member, a pair without its admitted
  side, no admitted sides, a guard without its own pair (dropped, or its admitted side run
  without the other guard), an unknown completion, a flipped `recorded` outcome, and an enumerated
  trace starting elsewhere than the initial journal, both the empty
  trace and one with steps, and each must fail naming the trace.

The core was written from the requirement text before the comparison existed, and the
comparison raised no disagreement with it. Its record, printed on success
(`cargo test --locked allocation::comparison -- --nocapture`), names the file, its bound, what
was compared, both pairs and the spec commit; the implementation revision is the commit the test
ran at:

```
allocation companion comparison: passed
  file: <checkout>/spec/docs/design/allocation-witnesses-v2.json
  schema 2, module allocation, bound: 4 events over an alphabet of 8
  compared: 8 witnesses and 4681 enumerated traces, every step
  pair: TauWeb.Allocation.backup_missing_refused matched; TauWeb.Allocation.backup_missing_admitted differed at step 2
  pair: TauWeb.Allocation.stale_sheet_refused matched; TauWeb.Allocation.stale_sheet_admitted differed at step 8
  spec commit: d029ebd9f632696bb027a22559d774d165685947
```

A pass is evidence about harness knowledge alone: never about external state, about whether an
effect ran before its append returned, or about concurrency (ADR-0032, "Evidence").

### The setup's machine entries

After unlock and completion of the seed-backup ceremony, one batch card shows both machine
entries, vendor, product, region and recurring sat/month cost, plus monthly and annual totals.
It states that each machine is bound alone in its own session, and explains billing from
creation until destruction or abandonment, including unfinished setups. Only the operator can
stop vendor billing; tau-web never pays for a machine. One button approves exactly that card.
Approval and both allocation identities commit as one record before the act returns. The
allocation core's own seed-backup and restored-seed checks apply to approval and answers.
Answering checks issuance read-only and consumes no further index. Refusal journals nothing.
Failed appends apply neither entries nor indices and latch the store. A landed move that
reports failure replays as approved, with both indices consumed.

The page then asks each machine's class with nothing preselected. The three explicit button
acts are Yes, No, only me and people I know, and Not sure. Yes and Not sure journal
`multi_tenant`; No journals `single_purpose`. No control is checked, selected, autofocused or
an implicit form default, and no draft survives lock or reload. Each entry's access model is
journaled as `maintained`, with profile `ad-hoc` and the revision read from compiled
`TENANT_PROFILES` (3 at this pin). The two stricter request refusals are documented under
Dispatch as implementation readings. Neither dispatch requests, typed requests nor unknown or
malformed page messages can supply questions, answers or access models. Only the dedicated
operator class-answer message supplies a shipped answer; no request, typed request or page
message supplies question wording or an access model. The access type represents `sealed` so
replay and boundary tests can reject it; no production act emits it. Replay and the independent
reader retain the recorded unsigned profile revision that fits in `u32` for maintained ad-hoc
access rather than comparing it to the compiled revision (ADR-0030). Inspection and the page
show that recorded revision. Sealed access, another profile, missing or extra access members,
and a revision above `4294967295` or of any other JSON type are refused.

`src/dispatch/setup.rs` exports
`Dispatch::check_binding(&self, entry: &str) -> Result<(), BindingRefusal>`.
Its distinct refusals are `NoEntry`, `ClassMissing` and `AccessMissing`; both recorded facts
admit the entry, also after reopen. This builds no binding act, session, create, payment or
delivery declaration. Those wait for twr-ggw.11, twr-ggw.14, twr-ggw.21 and twr-ggw.15.

**Implementation readings.** The compiled two-entry setup (`fixture`, `fixture-other`), its
vendor/product/region labels and 1000/2000 sat per month prices are fixture data, not a vendor's
price, until a real source exists. Approving in the served build consumes real machine-family
indices in the operator's store; they are never reused. The question wording is also a
compile-time fixture until twr-ggw.34 supplies the bundle's wording; no page message changes it.
The approved-entry refusal precedes binding; binding will narrow it to the session's bound set
in twr-ggw.11. Access is checked at binding as an implementation reading of ARC-44's installation
boundary. One answer per entry is an implementation reading; tightening waits for twr-ggw.15.
The one-approval-per-store reading and remaining in-memory associations are described under
Dispatch above.

The same-origin limit also applies to these acts: the harness cannot distinguish an operator's
click from an identical message posted by another same-origin script. Page messages have exact
members; unknown fields or values are refused or ignored with no journal entry.

### The tracer

`scripts/tracer.sh` builds both directories, then runs `tracer/`. That is a host binary, never
compiled for wasm32 and never served. It starts these fixtures on ephemeral loopback ports:

- **A fixture sshd** (russh) whose host key the test chooses. It records every connection,
  authentication attempt and channel request, and the `exec` command byte for byte, unmodified.
  It runs that text in real POSIX shells, mapping only `/var/lib/tau-web/jobs` and the boot-id
  file into a unique per-run scratch directory under `std::env::temp_dir()` (`TMPDIR` on
  Unix). Both browser
  builds send the same text; no path override reaches the served build. The fixture records
  each job launch and end from its own files and process table. A dropped connection kills
  each exec's recorded process group; detached jobs survive. A fixture reboot kills the job
  groups it started, changes its boot identity and keeps the jobs directory. At shutdown it
  signals a recorded group only while its leader's PID and start time still match, and removes
  its exact scratch directory, leaving no shared scratch parent. The close-without-status
  trigger matches the exact sentinel command operand, including no machine-name substring.
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

The held command is a finite 15-second sleep. Explicit-lock, visibility/pagehide and
renderer-crash cases drop its connection while it runs; a reboot before the collection cases ends any
remaining earlier jobs while keeping their records, so they cannot hang a later collection.
The close-without-status case runs a real command but closes its channel without sending a
status or record. The relay fixture logs a client connection that ends with no close frame.

The tracer then drives headless Chrome over the DevTools protocol. It runs a request by evaluating
in the harness worker's own context, over that worker's DevTools session: it imports the module
the worker already loaded, by the same URL, and calls `run_command` or `collect_jobs`. Neither build's page holds
a hook for it. Every case asserts on what the fixtures observed, not only on what the harness
reports. The relay fixture counts every TCP connection it accepts, at `accept`, before TLS and the
WebSocket upgrade.

For the local store, the tracer works the page as an operator would and inspects what the
browser holds:

- **The page.** It types each passphrase into the page's fields and presses the page's buttons.
  Stores created through the page complete seed backup and approve the fixture setup through the page before dispatch. The seed-record
  reader and write-free unlock checks run before completion.
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
  states, job identities, terminal and job evidence, findings, disposition reports and standing
  continuations, approved setup entries and their facts/cost/index/class/access, with command
  bytes as hex and no seed identifier or key material.
- **The stores' contents.** It reads them with an independent reader, `tracer/src/reader.rs`.
  The reader is written from the format's text and never calls the harness's store code. It
  runs on `ring`'s PBKDF2, AES-256-GCM and SHA-256, and derives the seed's keys with the
  `bip39` and `bip32` crates.

In headless Chromium 154 a new tab hides the one before it, which then restarts its worker, as
page hide must. The cases account for it.

The full run has 98 cases.

The cases:

| Case | What the fixtures show |
|---|---|
| the served build loads | its worker comes up and nothing errs, and the page has no `tauWeb` global and no global holding the worker. With no store, the page offers Create alone, and a request is refused before any contact. A store is created and refuses dispatch for seed backup without contact or append; after explicit skip an unapproved command refuses as no-entry; after approval through the card, called in its worker on the machine the tracer build pins, it refuses for the missing pin, the relay accepts no connection and the sshd sees none, and nothing is appended |
| setup batch card and indices, each build | all entries and approved costs, totals and recurring statement precede the click; no approval/reservation before it; unapproved command refuses before contact; one approval records both indices and exactly the offer the worker reported before the click (`setup_offer`) |
| setup class questions, each build | no checked, selected, autofocus, focus or keyboard default before answering or after reload; Not sure is multi-tenant and No is single-purpose in the independent reader; maintained access with ad-hoc revision; second answer refuses |
| setup non-operator inputs, each build | extra dispatch/collection members and malformed page messages change no journal or store state, supply no question or answer and seal nothing |
| setup ceremony refusal, each build | locked and ceremony-active approval attempts append nothing |
| create and unlock (twr-ggw.5, `CNF-82`) | the page offers Create, stating the 16-character minimum and a password manager, and refuses 15 characters. The independent reader reads the store the browser created, from the passphrase alone: record 0, the seed. A store the reader built, put into OPFS, unlocks in the browser and replays its command, and the unlock writes nothing: WebCrypto's PBKDF2 agrees with the host's |
| seed-backup create and mismatch, each build | twelve numbered words match the independent reader; dispatch contacts neither fixture; answering leaves the same complete document and field values as an independent seed; another valid mnemonic restores display without an append; tracer allocation refuses in all families |
| seed-backup collision controls, four per build | fixed-text words and adjacent phrases cause no false finding; seed-independent answering, lock, re-display and wrong-passphrase documents agree; twelve planted hidden word elements and a hidden reserved claim alongside displayed words are reported; cross-word language collisions cause no finding; mismatch and durable full re-entry work |
| seed-backup full re-entry and explicit skip, each build | independent decryption reads the distinct completion for its own seed identifier; the page names it; restart retains it without display; tracer reservations start at zero in every family, then one after restart |
| seed-backup failed OPFS move at create, both completions | real move failure leaves no in-memory or replayed completion and every family refuses with the gate's reason; page says not recorded and still owed at create, and requests reload and unlock; host re-display failure checks name the earlier completion that still stands |
| seed-backup creation-finishing unlock, each build | an envelope with no record gains record 0 and displays exactly its mnemonic |
| seed-backup interruption, twelve cases per build | display and answering each meet explicit lock, visibility hidden, pagehide, bfcache restore, close and renderer crash; words and input disappear and next unlock still owes the same record |
| seed-backup re-display, each build | fresh passphrase is required; wrong passphrase shows no word; answering removes words; tracer relay and SSH connections end before display, held waits end, no stopped request resumes and the cut-off call stays unresolved |
| 1. recorded, then sent (`CNF-30`, `ARC-8`) | exactly one relay connection; the sshd received exactly the wrapper recomposed from the journal entry, and its job record holds exactly the journal command; the replayed state holds the command intent after the setup approval and its following job terminal (exit status 7), and the output and exit status came back. With the append made to fail, the sshd received no `exec`, read only once that SSH connection has ended at the sshd |
| a failed append is not applied (twr-ggw.5 AC2, `STA-3`) | that failed append failed at its `move()`, a real OPFS call; the replayed state has no record for it, and none appears after a reload and an unlock |
| 2. a wrong host key halts (`CNF-21`, `SEC-11`) | no authentication attempt, no `exec`, no journal entry, and exactly one connection |
| 3. no pin, no contact (`CNF-23`'s no-pin case, `CHN-R4`) | no TCP connection accepted at the relay, none at the sshd, no dial, and nothing pinned afterwards |
| oversized launch (twr-ggw.71) | a 30000-byte command is refused with the composed size and limit before intent or contact: no journal entry, changed store state, relay connection or sshd exec. The same store then runs `echo ok; exit 7` and records its terminal |
| 4. the policy is enforced (`ARC-33`) | the loaded page carries the served page's policy token for token. An injected inline script raises a `script-src` violation and does not run. A `ws:` socket raises a `connect-src` violation in the page and in the worker |
| 5. the relay fixture's AUTH check is real | exactly one relay connection, and a wrongly signed AUTH gets `{"ok": false, "reason": "auth"}` and close 1008 at check 2, and nothing is dialed |
| 6. a relay key with no pass (`CNF-87`) | an unrecognised `test_relay_key` fails the request with no relay connection. Signed by the key with no pass, the harness reports `{"refused": "relay", "reason": "pass", "close_code": 1008}` |
| 7. an unrecorded destination (`CNF-87`) | the pinned machine `fixture` at `127.0.0.2`, a host the pass does not record: `destination` and 1008 |
| 8. pace (`CNF-87`) | the tracer puts the sshd's host at its window cap just before the run, so the refusal holds whatever the timing: `pace` and 1008 |
| fail closed (twr-ggw.5 AC1, `CNF-82`) | five edits to OPFS: a wrong passphrase, one byte of the envelope's salt, one byte of record 1's ciphertext, another store's record at the same number, and an envelope of version 2. For each, unlock is refused and the page offers neither Create nor Unlock; for the first two it says "wrong passphrase, or the store was modified". A create request creates nothing, a request is refused before any contact, and OPFS is byte-identical afterwards |
| reload, explicit lock, page hide and a killed worker (twr-ggw.5 AC3, `CNF-82`) | one case each. The old worker target is gone and one new harness worker exists. The page offers Unlock alone. A request is refused with no TCP connection at the relay. After an unlock, the replayed state lists every command recorded before. Explicit lock, page hide and the killed worker also catch a running command: once the sshd has its `exec`, the lock comes, and the sshd sees its connection end; explicit lock and page hide also check that the relay fixture sees the client's WebSocket end. After the unlock the command reads unresolved in the replayed state and the sshd receives no second `exec`. Before the Lock button is pressed, text is typed into both passphrase fields and never submitted; both are empty once it is pressed |
| close without exit status (twr-ggw.7, `STA-8`) | the sshd closes without an exit status; replay preserves the unresolved call. A second command answers held, reads its finished record and records no intent or launch |
| dispositions (twr-ggw.7, `STA-24`) | the independent reader builds a destructive disposition: the request is refused before contact, with no relay connection, SSH connection or append. Replacing it with a continuing disposition admits the command and journals its terminal record |
| typed reset bars commands before contact until durable confirmation (twr-ggw.8, `STA-24`) | an independently written unresolved reset refuses a command, names its intent and makes no relay or SSH contact or append; a confirming observation permits the command |
| typed running-system disposition: pinned attempt and collection stay permitted, four cases (twr-ggw.8, `CNF-110`) | one disposed reset per continuation: commands through `run_command` obey the choice before and after collection; a bare pinned attempt reaches the relay and sshd, collects no jobs and appends no intent; the typed call stays disposed with unknown outcome and the choice stays in force |
| one writer (twr-ggw.5, `STA-1`, `STA-7`) | a second tab opens, which hides the first and restarts its worker, so either tab's worker may win the lock. The holder is the tab that offers Unlock while the other says it is waiting; the roles follow from that. The holder unlocks. The other says it is waiting for the store and offers neither Create nor Unlock; its worker has not read the store, runs nothing and appends nothing. Once the holder's tab closes, the other offers Unlock and unlocks the same store |
| persistent storage (twr-ggw.5 AC6, `STA-23`) | with the `persistent-storage` permission denied, then granted, through `Browser.setPermission`: `navigator.storage.persisted()` reads false, then true, and the page shows the refusal, then "Persistent storage is granted." (`persisted()` already reads true, so that load makes no request), each with the statement that this is a request, not a guarantee |
| job drop (`CNF-40`) | lock drops a several-second command after launch; `collect_jobs` waits until its observed end, reads the finished record, records no intent and launches nothing |
| held request on a dropped running command (`CNF-40`) | a separate dropped command remains alive; a held request waits until its observed end, reads the finished record, records no intent and launches nothing |
| completed drop (`CNF-54`) | the job finishes while disconnected; collection immediately reads both streams and a nonzero exit from its persistent files |
| reboot (`CNF-55`, crafted older journal with several unresolved commands) | the persistent finished record still settles; a running old-boot command reads ended without a terminal; a removed record reads missing and stays unresolved; neither is waited on |
| background stdout (`STA-20a`) | `sleep 30 & echo hi` returns promptly with output and exit 0; the fixture saw the command launch and end |
| received-command finding (`CNF-56`) | the fixture changes the recorded command during a live job; the result still settles with its exit and output, and the advisory finding survives reload and unlock; the reader reads every new shape |
| disposition collection (`CNF-110`, box-plane case) | all four continuations over a real dropped job: collection reaches the relay and sshd, launches nothing, appends evidence and no intent; disposition and disposed state stay unchanged; destructive continuations refuse commands before contact both before and after collection, continuing ones admit them |
| live signal | a self-killed command returns unresolved with ended evidence, partial output and advisory agreement; no terminal is journaled |
| collection after a bad record (crafted older journal) | a malformed first record reports its failure; the later finished job still returns its output and exit 23 and receives a terminal record |
| held request after replay (`CNF-40`) | reads only its holding call to finished, names release, records no intent and never runs afterwards; only a new request runs |
| simultaneous requests (`CNF-40`) | same-tick requests pass pre-contact admission together; exactly one records an intent and launches. The held request shares that dispatch's finished or unresolved result. Collection during the dispatch reports not read and appends no second result. This fixture temporarily removes relay dial spacing so it tests journal serialization |
| stopped held collection (`STA-20`) | while a read waits, store_state, another machine's command and collection complete. Stopping appends nothing, leaves the detached command alive and returns held |
| stopped shared-result wait (`STA-20`) | stopping a held wait leaves the independent original dispatch running to completion |
| legacy and unreadable commands (`STA-20`) | after replay, identical bytes and reads name every holding call; each has no job identity and reports why only a disposition can release it, with no contact or writes |
| held unreachable machine (`STA-20`) | no pin, no credentials, relay refusal, host-key halt, authentication failure, unreachable SSH destination and a connection lost during a record read each answer held at once with why nothing was read, without retry or intent |
| destructive replacement with unnamed command (`STA-24`) | a continuing disposition releases A, B runs, replacement of A is destructive. A held request collects B only and names the standing restriction; collection of disposed A remains permitted and never removes that restriction |
| no plaintext (twr-ggw.5 AC4 and AC5, `CNF-15`, `STG-10`), in each build | from the passphrase the tracer typed, the independent reader learns the wrapping key, the data key and the seed. None of these appears, raw, hex, HEX, base64 or base64url (whole, or inside a longer value at any byte alignment), in any OPFS file: the passphrase, the wrapping and data keys, the mnemonic, the entropy, the 64-byte seed, the seed identifier, and roles 0–4's private and public keys at indices 0 and 1, plus the test keys in the tracer build. Local storage, session storage, IndexedDB and Cache Storage hold nothing, and no service worker is registered. Passphrase bytes appear only in exact create, unlock or re-display messages. Only the displayed seeds' mnemonic needles are exempt in the exact directed display and re-entry messages described above; other secrets remain findings in those shapes. Non-seed decrypted records are checked, retaining only canonical allocation seed associations. In the tracer build's case, the sixteen negative controls listed under "The messages" run first, through the same guarded serializer and the same check, and each must be reported for its own reason. Four seed message controls run for the final seed and each collision-control mnemonic in each build: phrase, array, wrong-direction re-entry and binary. Further controls report a passphrase and a data key in the re-entry shape, an earlier store's seed identifier, and mnemonic and passphrase console property names. Fields are empty after every submit. The HTTPS fixtures' requests and the console hold none |

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
the worker with no policy of its own. At `d029ebd`, `ARC-32` requires that host header and
`ARC-33` requires every worker to check policy before loading dependencies or receiving
credentials. This repository ships no host configuration or worker self-check yet; twr-ggw.54
owns them and `CNF-111`'s integrated evidence.

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
| | `cargo test --locked` | runs `build.rs`, so the gates above run here, and the `[session]` fixtures (`CNF-88`'s build fixtures); the relay matrix, `CNF-87`'s fixture half; the seed's tests, `CNF-83`'s derivation tests and `CNF-13`'s tests; the local store's, `CNF-82`'s and `CNF-15`'s host half (below); dispatch and journal recovery for `CNF-29`'s box-plane case, including the unresolved-command hold before contact and at append, identical bytes and reads, no writes on refusal, replay, every holding call and other-machine independence, `CNF-30`, `CNF-39` and `STA-24` dispositions; job classification, channel deliveries, unresolved evidence, append failures, replay and all four dispositions, plus real-shell signals, high exit codes, missing and unreadable record files, NUL-corrupted scalars, exact scalar forms, the reader and replay exit ceiling, incomplete unreadable entries, owned-child cleanup, recycled PIDs, stale fixture groups, exact sentinel matching, drop, duplicate-id, boot, output and cross-store identity tests for `CNF-40`'s dropped command not re-run, waiting on its job record, `CNF-54`–`CNF-56` and `CNF-110`'s collection case; and allocation's, `CNF-72`'s tests and the companion comparison against the allocation witness file (ADR-0032), with `CNF-3`'s three breaks as its unit tests; atomic setup approval and indices, ceremony gates, unanswered classes, maintained access/profile, binding prerequisites, provenance resolution and replay; typed fixture operations through the adapter's send path at every append kill boundary and a suspended record/send boundary, the resource barrier across both planes, all requester provenances through production command admission/append, disposition reach/end/replacement, exact collectable calls and committed job evidence in the 20-row matrix, unsupported typed-record replay refusals, and the dispatch companion's production-path stage1 comparison and complete vocabulary negative controls |
| `web` (the job is `CNF-1` for the browser build) | `cargo clippy -D warnings` on wasm32, the served and the tracer build | `CNF-2`, on the new target |
| | `scripts/check-adr-0024.sh` | spec ADR-0024's build check |
| | `scripts/build-web.sh served`, then `tracer check-absence dist/served` | the served build (`ARC-32`) carries no test key, pin source or test switch |
| | `tracer check-csp dist/served` | `ARC-33`'s policy, exactly |
| | `scripts/tracer.sh`, in headless Chrome | `CNF-30`, `CNF-21`, `CNF-23`'s no-pin case and `ARC-33`, as above, the relay refusals of `CNF-87` a correct client meets, and the local store's `CNF-82` and `CNF-15` in the browser; seed-backup display, hiding, full re-entry/skip, interruptions, re-display and custody in both builds (`CNF-44`, `CNF-82`), and integrated allocation refusals, completions and failed OPFS appends (`CNF-72`); `CNF-40`'s dropped command not re-run, waiting on its job record, `CNF-54`–`CNF-56`, `STA-20a` and `CNF-110`'s box-plane collection case; unresolved-command hold, concurrent admission and shared results, stopped waits with the writer free, unreachable answers and destructive replacement; typed reset confirmation and every continuation on the real pinned connection; setup batch costs and indices, unanswered class controls, Not sure and No, maintained access and non-operator boundaries in both builds; these browser cases supply the pinned SSH attempt evidence, which has no host form |

Every job checks out the submodule; `spec-checks` takes the full history, which
`check-install-disks.py --baseline` reads to reconstruct the pre-fix brief. `web` installs
Rust 1.97.1 with the wasm32 target, clang and llvm-ar, and the wasm-bindgen CLI at the pinned
version and checksum, with no manual step; the browser is the runner's Chrome.

`CNF-3`'s general requirement that deliberately breaking a test makes the suite fail was
verified by hand on 2026-09-21, against a temporary pin filling the inference slugs: the one
test was broken deliberately, `cargo test` went red naming it, the restored test went green.
The three further breaks `CNF-3` names are the companion comparison's (ADR-0032). They were made
by hand again on 2026-10-18 against schema 2, using
`allocation::comparison::the_allocation_core_passes_the_companion_comparison`,
its path edited temporarily to a scratch copy of the witness file outside `spec/` (inside it,
`build.rs` refuses the build, which would be red for the wrong reason). Green against the
unmodified copy first; then:

- **One expected outcome flipped**: `TauWeb.Allocation.successful_trace`, step 2, `allocation`
  from `admitted` with its identity to `refused`. Red: "TauWeb.Allocation.successful_trace,
  step 2 (allocate): allocation: expected refused, actual admitted".
- **The file missing, then empty.** Red, naming the path: "…/allocation-witnesses-v2.json: No
  such file or directory (os error 2)", then "…/allocation-witnesses-v2.json: not a JSON
  document: EOF while parsing a value at line 1 column 0".
- **Unrecognised.** `enumeration[1]`'s event kind from `allocate` to `reallocate`. Red:
  "enumeration[1], step 1: not an event of the alphabet" and "enumeration[1], step 1: event:
  unknown variant `reallocate`". Then its outcome from `refused` to `granted`. Red:
  "enumeration[1], step 1: unknown variant `granted`, expected `admitted` or `refused`".

Restored, the copy byte-identical to the pinned file, it went green, and the path edit was
undone, the test file byte-identical to its saved copy. The same three breaks stay as the
comparator's unit tests.
The dispatch breaks were made by hand on 2026-10-21 against schema 6, with only the comparison
path temporarily changed to a scratch copy outside `spec/`. The unmodified copy first passed.
Each edited trace was checked to remain in stage1:

- **Expected outcome flipped**, `TauWeb.Dispatch.second_command_held`, step 1: red,
  `outcome: expected {"dispatch":"refused"}, actual {"dispatch":"dispatched"}`.
- **File removed**, then empty: red with the exact scratch path and `No such file or directory
  (os error 2)`, then `not a JSON document: EOF while parsing a value at line 1 column 0`.
- **Unknown event kind**, then outcome, on that same trace's step 1: red,
  ``unknown variant `unrecognised_event`, expected one of `request`, `read`, `dispose`, `replay` ``,
  then `unknown outcome dispatch: "unrecognised_outcome"`.

The restored copy compared byte-identically with the pinned file and passed; the path edit was
undone, the comparison source compared byte-identically with its saved copy, and the pinned-file
run passed. The same breaks remain permanent unit tests. Separate production mutations removed
the typed barrier, applied a failed observation append, ended a continuation restriction
before its intent committed, sent to the fixture before append, and removed the shared rule's
destructive command stop. Respectively the lost-create test and comparison, the failed-read
barrier test, the continuation-boundary test, the adapter kill-boundary test, and both the
comparison and requester matrix failed. Removing the replay refusal of an inference resource
or target also failed the extended unsupported-record test. Restoring the exact source bytes
made each green.

The tracer was broken the same way on 2026-10-12: case 1 was made to expect exit status 8 where
the fixture command exits with 7. `scripts/tracer.sh` (the `web` job's command, run
locally, not on GitHub) exited 1, naming case 1 and the assertion "the output and exit status
came back". Restored, it exited 0.

For focused unresolved-command fixture checks, set `TAU_TRACER_HOLD_CASE` to `all`, `drop`,
`simultaneous`, `stop`, `writer-stop`, `append-error`, `shared-stop`, `legacy`, `unreachable`
or `destructive` when running the tracer. The default run always includes every case.
Host tests cover the writer acquisition helper: stopping after a completed read without
waiting for the writer, rechecking the stop under the writer, and completing a begun commit.
The tracer covers stopping a completed read's evidence append through the worker, held request
and store journal while the real writer is occupied, plus an evidence append error. Both
retain the read as `not_journaled` and leave the call unresolved and its machine held.
The tracer-only `test_writer` and `test_completed_reads` exports coordinate the writer and
observe completed reads. The `test_no_credentials` switch exercises a held request's unavailable
credentials. The served-build absence check covers all three.

For focused seed-backup checks, set `TAU_TRACER_SEED_CASE` to `create`, `mismatch`,
`failed-append` or `all`. These selectors are test-only; unset both tracer selectors for the
full gate. `test_allocate` and `test_seed_backup_fail_append` exist only under `tracer` and
are included in `check-absence`.

For focused setup checks, set `TAU_TRACER_SETUP_CASE=all`. The `existing` value runs the existing
dispatch/job cases without seed-display-dependent custody controls. The full gate leaves
`TAU_TRACER_SETUP_CASE`, `TAU_TRACER_SEED_CASE` and `TAU_TRACER_HOLD_CASE` unset and runs all 98 cases.
