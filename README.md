# tau-web-rust

The implementation of the tau-web harness: a client-side AI harness that runs in a phone
browser and provisions real infrastructure on its operator's behalf. Rust, compiled to
WebAssembly, following the configuration the specification records.

**The specification lives in [`douglaz/tau-web-spec`](https://github.com/douglaz/tau-web-spec)
and is vendored here at `spec/`, pinned to an exact commit, today `9086166`** (spec ADR-0031).
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

At the pin `9086166`, stage 1 is `STG-21`'s scenario: one live LNVPS machine on
catalogue plain Arch with no tenant, created through a typed adapter and paid by a Lightning
invoice from the operator's own wallet. Hermes is installed with its own installer.
Items 53 and 55 leave their `delivery_reboot` cases to the dedicated row. Item 95
cases (e) and (f) run on M alone at stage 1; their A/B output-release assertions, and
case (e)'s copied-key assertions, belong to stage 2.
LNVPS accepts no buyer boot configuration, so attest cannot run there (`STG-21`);
first contact uses `CHN-R7`'s published-key route. The table's attest row does not gate
LNVPS stage 1.

The pinned table's CNF items are **Stage 1: required**
`1–7, 10–17, 21, 23–26, 28–30, 32, 34–35, 37, 39–44, 49–56, 66–73, 78–79, 81–83, 87–91, 93–95, 99–104, 109–112`;
**Stage 1: publisher-default hosting** `113` (required deployment/live admission evidence remains pending);
**Stage 1: record measurements** `45–47`; **Stage 1: model-written check reports** `107`;
**Stage 1: re-entry** `108`; and **Stage 1: recovery export/import and Replace** `19–20, 84`.
The **Attest first-contact route** items `18, 23 (attest-window case), 61, 74–75, 109 (attest admission)` do not gate
stage 1. These rows define completion requirements; the implementation described below is
still under construction.

See [the source-delta and open-citation inventory](docs/spec-9086166-uptake.md) for this pin's wider contracts and remaining owners. Shared receipt fixtures below establish no live
adapter, complete protected-finalizer, native-policy or publisher-hosting
acceptance. Ordinary visibility-only hide preserves eligible sessions in `www/boot.js`;
explicit app Lock and pagehide end them.

## The harness

`src/` is the harness worker's wasm module, built for `wasm32-unknown-unknown` on spec ADR-0024's
configuration, beside the pinned inputs above. It runs in a dedicated worker the page starts,
because spec `STA-1` says "A single **harness worker** MUST be the only writer of durable state".
The command path began with twr-ggw.2's tracer: one command over a pinned SSH connection
through the relay, recorded in twr-ggw.5's encrypted local store (below). Goals and tools now
drive that same recorded path through the session loop described below. The module exports
`run_command` and `collect_jobs`, the same entry points in both builds below. The page defines no global and holds
no reference to the worker's instance of the module. It sends passphrase, seed-backup, setup-approval, per-entry class-answer,
binding, goal and no-brief acceptance messages to the worker. Goal acceptance starts the
model loop there; only the tracer directly calls the `run_command` export (below). Another same-origin script could still load its own copy of the
module and call it; that copy has no unlocked store, so it refuses every request before any
contact. For approval, class answers, binding and goal entry, the harness cannot distinguish an operator's
click from an identical message another same-origin script posts. While locked or running the
seed-backup ceremony, every request is refused before contact. The pins, keys and journal never
come from the request. Both builds use the bound machine's derived client key and the
harness-derived relay key. The tracer build alone has fixture host-key pins. The served build,
once bound, refuses at the pin lookup before contact; pins are twr-ggw.43's. An unapproved
machine refuses as `no-entry`; an approved but unbound machine refuses as `unbound`, recording
that refusal before reporting it. The connection path is whole in the served wasm.
`src/harness/run.rs` does it in this order:

- **Entry first.** Connection admission (`Store::connection_session`, through `resolve`) refuses
  `no-entry` before contact or append, then resolves the live session holding the machine or
  appends a `connection_refusal` record and refuses `unbound`, creating no binding or intent.
  Then signature-lowering admission records and refuses literal lowering commands where the
  installation mode stands, before any contact. Only then does the journal check (`Store::check`) check unresolved calls and dispositions,
  before contact or intent append.
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
  - the host-key pin source;
  - `fail_append`, which fails the store's next append at a real OPFS move;
    `tamper_auth`, which corrupts the derived relay key's AUTH signature; and
    `test_no_credentials`, which withholds the machine client key and relay key.
  The writer, allocator, seed-backup append and completed-read exports remain tracer-only.
  Neither build contains a compiled client key or relay key.

### Goals and the model's tools

For each live bound session, the page offers a goal card containing the operator's own words
and one optional https document source. `goal_request` accepts the exact object
`{session,text,document_source}` (the optional source may be omitted). Only an unlocked store
outside the seed-backup ceremony accepts it. A missing live session, unknown member, wrong
type, empty text, non-https source, second goal or ended session changes nothing. The worker
journals an encrypted `goal` event before applying it. `store_state.goals` shows history;
`sessions[].goal` and the page show that live session's text and provenance without keys.
There is no import, export, sharing, stored-goal selector or reuse control. Fresh bindings have
no goal and empty input fields, even after replay of earlier goals.

**Implementation reading: provenance and lifetime.** The source is the fixed
`operator_session_goal_card` marker; a session accepts exactly one goal. `document_source` is
always present in the record, null when absent. There is no document metadata record. A goal
is never a configurable brief or feed list. Unknown brief/feed members are rejected at the
goal, tool and inference boundaries or ignored by the exact-member page protocol. The bundle
still contains no promoted brief and no runtime brief/feed configuration exists.

The card labels acceptance **Acting on a goal with no brief**, through the existing
`Store::accept_mode` act and encrypted `mode_acceptance`. `goal_accept` takes exactly
`{session}` and requires that live session's goal. Accepting starts its model loop in the
harness worker. **Implementation reading: admission.** A turn waits for acceptance; each
acting tool also checks acceptance before any contact or intent. Collection keeps its existing admission. Install-capable commands additionally require the
journaled machine facts described below. No session worker was added. Typed proposals wait for
the operator on the declaration card before their companion tool is dispatched.

**Implementation reading: fixture protocol.** Each turn is a real request through the shared
inference driver, including its mint, route, intent, terminal and redaction boundaries. A
harness-owned `tools` array contains exactly these four definitions, each requiring a machine
string. The fixture returns one `{name,arguments}` call in
`choices[0].message.tool_calls`. This is a loopback fixture protocol, with no claim about a
live service's tool-call format. The loop accepts one call per turn and at most ten turns,
starts at most once for a goal, and ends on bound `done`, session end, a refused, lost or
unresolved inference request, a finished non-2xx turn, or the turn bound. Every dispatched
result, including a hold,
dispatch refusal or unresolved command, is the call's untrusted tool output in the next turn;
the model then decides again. Delivering a result arms no dispatch or retry. **Implementation
reading: invalid calls.** An unknown tool, invalid arguments or an out-of-set machine ends
the loop before dispatch or any tool record. A 2xx turn also ends the loop when its body
does not parse, has zero tool calls or has more than one tool call. No turn is retried and
replay resumes nothing. The served build has no session-start selection and refuses its turn
before contact.

| Tool | Arguments and dispatch |
|---|---|
| `exec` | `{machine,command}`; live bound-set and no-brief checks, then the existing command path: session admission, signature lowering, command hold/disposition/barrier, launch size, connect, append and exec. Its intent records requester `session` and the live identity. |
| `request_harness_job` | `{machine,job,arguments}`; schema, bound set and no-brief checks, then the shared box-plane hold/disposition/barrier check before job availability. Held work collects its holding calls, records no intent and never runs afterwards. Unheld requests refuse as unavailable, naming the job's owner. |
| `request_typed_operation` | `{machine,operation,arguments}`; harness-resolved approved entry, caller-bound admission, no-brief gate and shared barrier/continuation check before approval. A request passing these checks refuses awaiting operator approval, with no intent or contact. The typed `check_request` also enforces the installation-facts guard; pinned companion witnesses and their recorded outcomes are unchanged. |
| `done` | `{machine}`; bound-set resolution, no checked value and no contact. Ends the loop. |

Unknown tools, missing/extra/ill-typed arguments, out-of-set targets and harness-only job names
are refused without command intent or contact. The model supplies no address, pin, user,
approval, cost bound or bundle commit. Tracer-only `test_model_target` supplies exact loopback
connection targets, and `test_model_tool` exercises dispatch admission directly; both names
are in the served absence needles. The served build has no target source, so a directly
requested model exec reaches its existing missing-pin refusal. **Implementation reading: unavailable jobs and facts.**
`fetch_artifact` (twr-i6k.5) and `ready_to_reset` (twr-i6k.3) admit empty argument objects.
`place_secret` (twr-ggw.23) admits exactly text fields `application,path,owner,mode,secret_name,purpose`,
never a value. Typed arguments are a text map; the harness supplies cost bound zero and its
compiled spec commit while awaiting approval. Browser builds contain no typed adapter.
The lost-create per-tool test now reaches the shared barrier before approval. Held and
barrier-refused tool-result content remains twr-ggw.67's; these cases claim only dispatch,
recording, contact behavior and delivery of each call's untrusted result to the next turn.
**Implementation reading: job-only admission.** `check_job` admits jobs only. Exec hold
evidence is the shared `Journal::check` host tests
and the scripted browser case, through production `run_command`.

**Implementation reading: context typing.** There is no fixed system instruction or fetched
instruction text. A user message contains a JSON context: `goal:{type:"operator_goal",text}`,
optional `document:{type:"untrusted",source:"fetched_document",content}`, and `history` of
calls beside `result:{type:"untrusted",source:"tool_output",content}`. Command results contain
stdout, stderr and exit status. Composed bodies pass the existing credential boundary;
bodies are never journaled. **Implementation reading: unsafe decoded calls.** The inference
response boundary scans decoded completion-message values and member names, including proposals, with every held credential
and the request's transient credentials before releasing a call. Admission rechecks current
holdings under the writer. **Implementation reading: admission scan.** Both scans remain.
**Implementation reading: original completion text.** The response boundary decodes the
original completion body lossily, exactly as the loop does, before inspecting tool calls and proposals.
An invalid UTF-8 byte outside a call therefore cannot hide a literal or escaped credential
inside it. Before release, the boundary also requires the original and redacted bodies to
decode to identical completion messages, including proposal presence and when the original has no parseable message.
Neither byte-level escaping nor redaction that repairs malformed JSON can produce executable
marker text in place of a call. Both held
credentials and the request's transient credentials are checked; admission still independently
checks current holdings. A credential-bearing call is refused whole, sends nothing and
records no tool intent; its next-turn history withholds the call and carries only the
credential-boundary refusal as untrusted tool output. A JSON escape cannot bypass these checks.
Tool output and documents change no acceptance, approval,
binding, disposition, hold, barrier or capability, including when claiming policy authority.
No vendor credential is held by this build (SEC-5 row 1); the hostile-goal/document tests search
all credentials the store enumerates, including both inference tiers, with the existing raw,
hex, HEX, base64 and base64url needles and embedded alignments. **Implementation reading:
credential attempt.** The scripted attempt writes
hex of the actual received completion body to the machine. Planting a held credential into
that context therefore fails all three scans: completion bodies, SSH commands and machine files.
The SSH scan includes octal forms of every needle, because the job wrapper sends command
bytes as printf octal operands; scanning only the literal wire would miss the hex attempt.

**Implementation reading: document URL grammar.** Entry and replay share a conservative
HTTPS predicate; the independent reader applies the same grammar. Hosts are ASCII DNS labels
of 1–63 letters, digits or hyphens, starting and ending with a letter or digit, with at most
253 host bytes, or canonical dotted-decimal IPv4. The last DNS label starts with a letter. Encoded internationalized labels (`xn--`), IPv6, user information, trailing dots and alternative
numeric hosts are excluded. An optional port contains decimal digits and is in 1–65535.
An optional path, query or fragment contains no whitespace, control character or backslash.
The browser request parser also checks entry. Malformed ports and empty hosts refuse replay
with the record number. Accepted examples include `https://localhost`,
`https://127.0.0.1:443/document`, `https://docs.example:65535/path?q=1#part` and
`https://a-b.example:000443/é`. Refused examples include `https://:443/document`,
`https://127.0.0.1:65536/document`, `https://docs.example:0/`, `https://xn--a/`,
`https://user:pass@docs.example/`, `https://[::1]/`, `https://docs.example./`,
`https://0177.0.0.1/` and `https://docs.example/path with space`. The reader checks these
examples, label and host byte bounds, port bounds and the excluded forms using its own
byte-oriented authority and decimal-number parser. A comparison also requires every
harness-admitted example to pass the independent record reader.

The operator-named document source commits with the goal before one credential-less GET:
CORS, manual redirects, no-store caching, no Authorization/account headers or browser
credentials. No other path fetches documents into model context. **Implementation reading:
failed document fetch.** An unreadable, redirected or non-2xx response retains the journaled
goal and source and supplies no document text. **Implementation reading: pending document.**
Acceptance refuses until the fetch has settled, including reading its body. Since each
session accepts one goal, the loop-start pending guard is defence in depth: ordinary accepted
entry cannot reach it. Loop-start admission passes through the actual tool-check refusal.
The pending marker is installed under the source-append writer before any other report can
expose that goal. The fetch and its settlement hold no writer, and the end step never waits
for them. Document text remains transient. Session end
aborts active document requests, clears retained text, and is checked after source append and
immediately before send. The new browser case suspends the real source append, begins end,
releases append and observes no GET. The TLS fixture reuses the tracer's certificate.

| Send path | Session-end stop | Browser evidence |
|---|---|---|
| Model turn | Shared inference `can_send`, post-append check, response boundary and loop ending check; pending documents refuse start | `session end withholds completion body at finish_writer`; shared inference intent stop cases; pending-document acceptance case |
| Model exec | Decoded credential boundary, current-holding admission, existing command stops and post-append check | `session end during box-plane intent commit prevents exec`; existing command/evidence stop cases |
| Requested harness job | Shared command check and held-read stops; unheld jobs send nothing | `session end stops held read before acquiring writer`; `model exec and every admitted job collect holding calls and never launch` |
| Requested typed operation | Ending checked under writer; browser has no adapter or send | `model typed create reaches the shared barrier before operator approval` |
| Document GET | Post-source-append and immediate pre-send ending checks; AbortController; pending-fetch guard never delays end | `document source commits before fetch and session end prevents a late send`; `session end aborts an active document request without waiting for it` |
| `done` | Bound-set check, no send | `scripted exec and done preserve untrusted typing and keep credentials off the machine` |

The focused browser selector is `TAU_TRACER_GOALS=1`; optional `TAU_TRACER_GOAL_CASE`
ends that focused run after `card`, `context`, `outcome`, `hold`, `barrier`, `credential`,
`document_pending` or `document_end`. Leave both unset
for the full gate. **Implementation reading: loop outcome.** When the page starts a loop,
the worker reports its outcome in a fresh
store report after it ends; the goal card shows the outcome. **Implementation reading:
outcome members.** An inference stop reports only numeric `call` and `status`, boolean
`finished` and `unresolved`, and the fixed `refused: "inference request refused"` when a
refusal exists, omitting absent or ill-typed members. Bound completion reports only
`done: true`; other loop refusals contain fixed harness text. No response body or aggregator
text leaves the loop. **Implementation reading: outcome labels.** An unresolved outcome
is labelled only as unresolved. Otherwise a refusal takes precedence over a finished status;
a finished outcome without refusal is labelled by its HTTP status, including non-2xx turns.
An outcome with none of these members has the neutral label `Goal loop ended.`.
The two-completion check waits
for that terminal report before counting. The tracer-only `goal_turn` suspension point lets
the authority case snapshot all policy state after acceptance and before the first turn;
it is included in the served absence needles. Its inference key is prepared before that
snapshot, so sessions compare exactly across the hostile content. Only the command's intent
and job terminal and the two inference intent/terminal pairs may be added.

### Procured inference

`src/inference.rs` owns composition, response metadata parsing, the probe and record-before-send
order over a small transport interface. Host fixtures never touch a network. The wasm transport
in `src/harness/inference.rs` uses real fetch without holding the store writer while waiting.
Every fetch uses manual redirects, omitted browser credentials and no-store caching. Unreadable
responses, redirects and lost responses leave unresolved intents; a readable error has a terminal.
Once its terminal commits, the report says the call finished; a later failure has its own
refusal, and a late-revoke preparation failure says no revoke was recorded and leaves the key
to the next unlock's sweep or its expiry. The shared `inference::infer` driver preserves that
committed mint's call id, finished status and refusal even when its later session-key lookup
fails. An unresolved mint likewise retains its call id and `unresolved: true` beside its refusal,
whether the session is live or ended, its response was lost or session end prevented send
after append. The host test
`infer_preserves_committed_mint_report_when_sessions_end_in_flight` ends sessions inside the
fake mint exchange and checks both a failed late-revoke preparation and a successfully
recorded late revoke, including durable terminal replay.
No inference intent ends a machine disposition or bars the next inference request. The existing
typed-inference refusals remain in place.

A real unload can kill the dedicated worker before its asynchronous revoke completes. After a
crash or real unload, the session inference key stays usable until the next unlock or its
expiry, bounded by its cap. A revoke whose intent committed but whose terminal was cut off
stays unresolved and is never retried; that key is bounded only by its expiry.

The following are **implementation readings**, not claims about the real account endpoints:

- **Credential entry:** `test_inference_account` is tracer-only, called in the worker context.
  It clears the supplied array on every exit and requires an unlocked store outside the
  seed-backup ceremony. The production store method commits one encrypted account-credential
  record before installing it; a second credential is refused. There is no operator control
  or page message for entry or funding. Their ownership is tracked by twr-ggw.84.
- **Mint timing and custody:** the first inference request mints, never binding. Concurrent
  requests for the same session share that attempt. Row 14 remains in the store, and row 2
  lives only in that session's worker-memory holding. The held-credential enumeration scans
  both tiers. Neither management calls nor completion bodies carry the session inference key;
  completions carry it only in Authorization. Model responses and composed request bodies pass
  the existing exact-value redaction boundary. Decoded response metadata passes the boundary
  again before any terminal append, including account reads, mints and revokes. The scan uses
  held credentials and the request's transient credentials even after holdings are cleared.
  Unsafe identifiers and values the marker cannot exclude are withheld. A readable response
  still commits its status and safe metadata if body redaction refuses; the caller receives a
  refusal naming the boundary and no body. Response bodies are never journaled here.
- **One attempt:** any recorded mint prevents another mint in that session. An identifier-only
  readable mint records its identifier, cap and expiry without installing a holding, so both
  session end and replay can revoke it. Only the mint attempt is serialized; completions can
  proceed while an earlier completion's response is withheld. A lost response
  cannot supply an identifier for revocation; its cap and expiry bound that key. A new binding
  has a fresh session identity and may mint its own key.
- **Top-up:** the latest account read for that same session must be 2xx and explicitly report
  automatic top-up off before mint, both live and on replay. A non-2xx, on, missing or unreadable setting refuses
  the request. An unresolved account read retains its call id and `unresolved: true` beside
  a refusal explaining that no mint is sent without a recorded top-up-off read; a finished
  read that refuses also keeps its call id, HTTP status and `finished: true`, including a
  non-2xx body that says top-up is off. No mint is prepared or sent after that read.
  Nothing writes account configuration.
- **Bounds:** `SESSION_CAP` is `0.10` fixture account units and `SESSION_LIFETIME_SECONDS` is
  900 seconds, measured from the injected host clock or worker clock at mint. The page's
  `END_SESSIONS_BOUND_MS` is 5000. The pin assigns no cap or expiry values or owner; twr-ggw.83
  asks for that decision. These constants add no bundle field.
- **Route:** worker memory records direct routes by exact origin. Before the first credentialed
  request, a dedicated unauthenticated OPTIONS request asks for the same headers using fixed
  placeholders. Browser CORS preflight is additional to that dedicated probe. Any readable
  status selects direct. An unreadable or redirected probe selects no route and sends no
  credentialed call; a later request may probe again. A real call's failure leaves the route
  chosen. With no aggregator tunnel built, no route means refusal. This is separate from
  twr-ggw.18's model-list read and never substitutes for it.
- **Session ends:** the bounded worker step stops dispatch, closes registered SSH WebSockets
  synchronously and drops holdings before revoking independently per identifier. A cold route
  probe rechecks session end after its route read; the revoke's own probe remains permitted.
  A post-append check prevents a concurrent intent from sending after the end begins.
  Readable responses still receive terminal records. The last response boundary withholds a
  completion body whenever ending has begun, including a finish ahead of the end snapshot
  and a body already built before the last writer wait. **Implementation reading:** retain
  `call`, `status` and `finished`, remove `body`, and add `refused: "sessions ended"` only if
  no refusal is already present. Admission and signature checks recheck ending under the
  writer, and the store also refuses them after its end snapshot. These requests stop before
  the binding or signature check, so they append neither `ConnectionRefusal` nor
  `SignatureRefusal`; ordinary unbound attempts and signature-lowering attempts still record
  their refusals. **Implementation reading** (`STA-23`, `CNF-7`): session end stops dispatch,
  so a request it stops is refused for session end before the binding check, as a request
  arriving after the end already is at request entry; it is not a connection attempt that
  the binding check refuses and records. A mint that supplies an identifier after the end's first snapshot
  commits and sends its own revoke; the end step waits for the mint guards and those revokes,
  subject to the page's bound. The response boundary also scans the request's transient
  credentials, so an echoed session inference key cannot enter late terminal metadata after
  its session holding was cleared, including when JSON escapes concealed its wire bytes.
  After replay, unlock and re-display answer first, then a separate worker step sweeps only
  the identifiers captured at unlock with no revoke intent. Keys minted by the current worker
  never enter that sweep. A revoke intent whose answer was cut off is never retried.
- **Unaccounted spend:** `store_state.inference_calls` lists every call and state. Unresolved
  completions name their key identifier and cap as unaccounted spend; unresolved account reads,
  mints and revokes remain listed too. Each live-session line shows its unresolved completion
  count against its cap. The disposition screen remains twr-ggw.66's.
- **Fixture protocol:** a loopback TLS server records raw request lines, headers and bodies.
  GET `/account`, POST `/keys` and POST `/revoke` authenticate only with X-Inference-Account.
  Mint asks for `cap` and `expires` and returns `key_id` and `key`; revoke names only `key_id`.
  POST `/completion` authenticates only with the session inference key. Response fixtures use
  the recorded case-I envelope with a reported provider and cost, case-H without either, and
  case-C's readable routing refusal, with fixture values and leading whitespace on successes.
  The fixture enforces requested caps, expiry, revocation and management-endpoint separation.
- **Served refusal:** the served build compiles the bundle's origin but has no candidate.
  An inference request refuses for missing session-start selection before contact. Only the
  tracer build carries `fixture-model`, `fixture-maker`, `fixture-provider` and the worker-state
  origin switch. In the served no-plaintext case, both new credential needles are vacuous by
  construction; the tracer build provides their nonvacuous evidence.
- **Comparison:** inference remains core-only in the companion comparison; no witness changes
  or typed-inference records are introduced.

| End | What happens |
|---|---|
| Lock button | revoked at once |
| ordinary `visibilitychange` hidden, document alive | same eligible session/key/limits continue while scheduled; no revoke or hidden deadline |
| processed freeze | cancel safe ordinary transport; retain writer/bindings and original limits; verify before further work hidden or visible |
| visibility hidden during seed ceremony | full local Lock; words/input cleared; interrupted completion remains owed |
| `pagehide` dispatched while the document lives | revoked at once (synthetic in the tracer) |
| bfcache restore | revoked at once (synthetic in the tracer) |
| seed-backup re-display | revoked at once |
| real unload: reload, navigation away, tab close | refused at once if its revoke completed; otherwise next-unlock sweep or expiry; if the unload cut off a recorded revoke, expiry only |
| crash | next-unlock sweep or expiry |
| revoke cut off by the bound | expiry only |
| lost mint response | expiry only |

**Inference record shapes.** These are compact encrypted event objects with exact members;
optional terminal members are absent, never null. Empty decoded optional text is omitted for
every terminal kind. The account credential is exempt only in
its own field when decrypted records are searched. No session inference key is exempt anywhere.

- `inference_account`: `{credential:<text>}`, zeroized after parsing and replayed into its
  registered row-14 type.
- `inference_intent`: exactly one nested kind: `account_read:{call,session}`;
  `mint:{call,session,cap,expires}`;
  `completion:{call,session,key_id,model,requested_provider,zdr}`; or `revoke:{call,key_id}`.
  `call` is the intent record number. A completion must name an earlier exposure and its mint.
- `inference_terminal`: required `call,status`; account reads may add `automatic_top_up`;
  mint adds `key_id,cap,expires` when available; completion requires `model,requested_provider`
  and may add `reported_provider,prompt_tokens,completion_tokens,total_tokens,spend,request_id`.
  Revoke adds no fields. Spend is the exact original JSON number text, stored as text, without
  floating-point conversion. Neither prompts nor raw responses appear in these shapes.

Replay and the tracer's independently written reader reject extra members, wrong types,
unknown intent references, repeated terminals and selections inconsistent with the intent.
Old journals continue to replay. Host tests exercise each storage kill boundary, metadata,
redaction, top-up and routing refusals, unresolved spend and the disposition matrix.

The focused browser selectors are `TAU_TRACER_INFERENCE`, `TAU_TRACER_INFERENCE_PHASE` and
`TAU_TRACER_INFERENCE_END`; unset all three for the full gate. The full browser gate covers
request order and bodies, header separation, held responses, crash/reload recovery, bounded
revocation, expiry and both builds' planted no-plaintext controls. The mutation evidence below
records each required production break and its restored rerun.
`spec/bundle/cors-probe.sh` is withheld by the no-live-vendor fence for this work.

### The credential-redaction boundary

Every typed adapter response and the injected response stand-in pass `src/redaction.rs` through
`Store::operation_response` before journal append or return. It applies the declared JSON field
redactions, then scans the exact resulting bytes for the store's held credentials. The boundary
and store entry compile in every build; the served build has no response-producing adapter yet.

The following are **implementation readings**, with deliberately limited claims:

- **Exact copies:** only raw bytes exactly as held. Hex, HEX, base64, base64url,
  JSON-escaped, partial and transformed copies pass the scan. Random 32- or 64-byte keys
  essentially cannot occur verbatim in valid UTF-8 JSON; typed JSON responses therefore catch
  credentials held as text (the mnemonic today, a vendor credential later). The arbitrary-byte
  injected stand-in exercises binary keys. JSON field editing serializes before the scan, so
  an escaped copy that serialization makes exact is caught. That serialization is serde_json's
  default: object members come back sorted, escapes and number text are rewritten, and an
  integer outside the 64-bit range is read as a float, losing precision. A recorded typed
  response with declared fields keeps its members' values within those limits, never the
  vendor's exact bytes.
- **Marker:** both mechanisms leave the fixed ASCII `<redacted>`. A declared password
  field keeps its name and becomes that JSON string; an absent field stays absent and a null
  stays null. Overlapping scan matches become one marker. If a marker would itself leave a
  held value in the output, the boundary refuses. A marker claims nothing about the rest of
  the response being scrubbed; named placed-secret markers belong to twr-ggw.23.
- **Recording:** `operation_response` carries exactly `call` and `body`, the response
  bytes in lowercase hex. It follows its typed intent, occurs at most once per call, settles
  nothing and changes no call state. Append failure returns the storage error and no output;
  the call stays unresolved and the existing failed-append latch applies. Older journals
  without responses replay unchanged. No response body appears in `store_state` or page reports.
- **Model context:** the boundary's returned `Redacted` bytes are the stand-in for model
  context, the only response form an adapter hands on. Session tools now compose their bodies through the same boundary. The inference adapter composes model request bodies; the fixture inspects every received body and the tracer searches them for credential needles under STG-10.
- **Two mechanisms:** the typed adapter declares root-password fields as RFC 6901 JSON
  Pointers; the fixture declares `/root_password`. Declared fields require JSON: malformed
  JSON refuses with no response record or output, leaving the call unresolved. Only the
  declared fields are covered. A copy of the vendor-generated root password elsewhere is
  not caught, since the harness does not hold it. The injected stand-in declares no fields,
  receives only the exact-value scan and has no password heuristic.
- **Held set:** the store enumerates the seed's 64 bytes and canonical mnemonic sentence,
  the data key, every credential given to live sessions, and roles 0–4 at every listed identity
  under the current seed, including reserved, failed and destroyed entries. Machines supply
  roles 0–2, passes role 3, handoffs role 4. A derived key counts as held because the held seed
  derives it at a listed identity. Existing holders are borrowed; derived copies keep their
  registered credential types and zeroize after scanning. The passphrase and wrapping key
  are cleared during create, unlock or re-display before responses can pass; neither lifetime
  is extended to scan for it. They are consequently absent from the scan set at response time.
  The inference account credential and each live session inference key also join this set.
  Later additions belong in the store's enumeration: the vendor credential and role-5 LNVPS
  key (twr-ggw.47).
- **Routing:** only the boundary constructs `Redacted`, whose field is private and which
  has no constructor from bytes, `Deserialize`, `Default` or `From`. The response append and
  adapter return accept only that output; its entry obtains holdings from the store itself.
  Passing and failing doctests protect the public construction restriction.

CNF-14's host fixture injects a root password into the typed adapter's response. CNF-17's
stage-1 evidence uses the host-only injected arbitrary-byte response fixture, journaled against
an ordinary fixture typed call through the same boundary. This enables no untyped call or
untyped vendor scope. **The repeat against real untyped responses is still owed before scopes
are enabled.** Independent tests derive absence needles separately, search every decrypted
record and decoded response body (except the intentional mnemonic in record 0), and search
returned bytes in raw, hex, HEX, base64 and base64url, including embedded byte alignments.
The tracer checks app-origin requests and logs for STG-10. Box-plane output does not pass this
boundary: placed-secret scanning, named markers, cross-chunk windows and withheld bytes are
twr-ggw.23's; the minimum secret length is twr-ggw.38's.

### Dispatch

`src/dispatch.rs` is the shared, synchronous core, written from the pinned Markdown requirements.
A box-plane call is unresolved after its approved intent, finished after its exit status's terminal record,
disposed with outcome unknown after an accepted disposition, or cancelled when a new-format
intent has no approval decision. These states are derived from committed records in journal
order (`STA-3`, `STA-8`); the core takes no time input and no timer clears anything. Replay
writes nothing, surfaces uncertain calls and never resumes or automatically reissues them
(`STA-6`, `STA-7`). The cancellation branch is exercised only through an authenticated crafted
record and a real unlock; no path in this build produces that record.

The harness resolves an approved machine to its live bound session before checking the command
hold. As an **implementation reading**, command admission remains `harness_pin` and
`provenance.session` records the bound session identity, preserving the intent shape and
accepting older intents with `null` on replay.
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
machine, plus `typed_calls`, `observations`, `current_installations`, `setup`, `setup_offer`,
`sessions` (with `standing_modes`), `exposure_ledger`, `connection_refusals`, `installations`,
`mode_acceptances` and `signature_refusals`, without key material.
`setup` lists each entry's facts and cost, allocation family/index, nullable answer and class, and access model/profile/revision.
It contains no seed identifier; the page's store report carries the same setup projection.
Disposition records include both `machine` and `resource`: `machine` retains the command-era
shape, while `resource` names the entry or inference resource used by the typed derivation.
No disposition screen, disposition page message or disposition export exists. The browser disposition case uses a store built by
the independent reader, with no added request switch.

`run_command` reports completion as `{"done":true,"seq":8,"call":8,"terminal":9,...}`,
with output, exit status, the exact wrapper bytes in `sent`, journal command bytes in
`recorded`, and advisory `job_record` evidence. After an intent commits, an exec error,
channel close without a complete record, lost connection or evidence append failure reports
`{"unresolved":true,"call":8,"why":"…"}`, never failed. Whenever a valid job record was read,
the unresolved response also includes `job_record`, with the same state, comparison, output
and exit status as a finished response. Evidence whose append failed has `number:null`. The command's exit code is read from
its job record and journaled before completion is reported; the SSH wrapper's own exit status
never settles the command. An unapproved command refuses before the pin lookup as
`{"refused":"no-entry","machine":"fixture"}`, with no intent and no failed-append latch.
A mismatched command provenance target refuses at append as `{"refused":"provenance"}`.
As an **implementation reading**, `crate::harness::valid_request` refuses `run_command` and
`collect_jobs` JSON input that is not an object, has a member outside the build's fixed set,
or has a member of the wrong type. After JSON parsing and the locked/seed-backup refusal,
it reports `{"outcome":{"refused":"request"}}` before admission checks, with no contact or record.
Text that is not JSON fails earlier as a JavaScript error (`request: …`). The fixed set is `machine`, `relay`, `host`,
`user` and `command` (strings), and `port` (an unsigned integer from 1 through 65535).
The tracer build also accepts `fail_append`, `tamper_auth` and
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
`reconcile-before-retry`: arbitrary response bytes never confirm an effect. Its **read fixture contract**
is a status observation reporting that operation's effect observed; an ended system or a boot
change establishes no success. This is fixture evidence, not an LNVPS reconciliation contract.
The fixture vendor and its receive log compile only in host tests, never in the served build.
A configured response can carry `root_password` plus unrelated members. `run_response` routes
it through the store boundary with `/root_password` declared and returns only `Redacted`
response bytes alongside the call identity. No configured response preserves the lost-response
behavior: no response record, with the typed intent still unresolved. Status responses use
the same route before the separate status observation.

A typed request carries its target, operation, session, requester, optional approved receipt binding and structured facts
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
allocation index the machine family has not reserved. Extra mappings use a closed encrypted association event through the same prepare/commit/apply
path. Replay checks reservation and ownership and restores them from files alone. No fixture
re-supplies mappings. They create neither entries nor installation ordinals and grant no retry
or successor-allocation authority.

Receipt evidence uses a separate closed encrypted event and provenance. The approved binding
contains operation (`order`, `stop`, `restart`), account and signed-request identities, propagated
unchanged into the intent and checked against its approval. Receipt source, call, resource,
target, complete binding and validated success must match; only browser-vendor-TLS fixtures
can settle create/order, destroy/stop or reset/restart. Unbound/Robot approvals and reinstall
gain no receipt authority. These are abstractions of external validation, not TLS/body validators.
An order additionally needs a returned id durably associated with its approved entry. Either
arrival order converges through the same dispatch derivation; a later association changes
current call state without rewriting the received event's historical `settled` list. Full
receipt evidence, including refusals, remains oldest first, with separate receipt/association
provenance in disposition diagnostics. Neither constituent affects live state before commit;
a failed append latches further writes, and genuinely landed records apply once on reopen.
Legacy missing bindings decode to None and serialize without the new member; old generic
observations retain their read meaning and stored bytes are never resealed. The distinct
OperationResponse event remains nonconfirming. Stop proves vendor-observed stopped only;
restart proves vendor task completion only; order proves its returned/associated id only.
Deletion, billing cessation, host creation/payment/readiness, service survival, delivery reboot,
placed-secret duties and host-key pins are independent downstream contracts.
The production command append resolves any provenance target against its command's approved entry
before commit. Existing intents retain their recorded resource, holds and dispositions without
requiring approval records; replay never treats those historical calls as a store refusal.
Inference has a distinct resource type, so no entry name can collide with it; this core admits
it through the shared admission rule. Its own inference intents and metadata terminals record
account reads, mints, completions and revokes, separately from typed operations.

Every unresolved machine call bars cloud-plane mutations on that entry, whatever its call id,
session or requester, including the operator flow. A second index for the same entry changes
nothing. Another entry is independent. Only an unresolved reset, reinstall or destroy adds a
box-plane stop; a create can remain unresolved beside a command. Commands retain their existing
hold. `run_command` checks both before contact and at append; a typed barrier answers
`{"refused":"barrier","calls":[<recorded typed intents>]}` and makes no connection. Pinned SSH
attempts and job collection require a live binding, remain reads, and create no intent or disposition check.

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

Canonical operation evidence also uses the closed protected-v1 receipt/association arms
from Protected browser evidence v1 §3a. Canonical absent, retained and received-present
withheld identities stay distinct from later display omission. Qualifying withheld evidence
permanently excludes other entries; quarantined associations grant no target or settling
constituent. Retained identity conflicts refuse before association append and admitted-map
duplicates append nothing. Store previews on a clone, applies only after append, and replays
the authenticated prefix. Scoped read-only projections preserve historical outcomes and
canonical custody while withholding copied names and reindexing markers. These helpers and
independent fixture controls supply shared prerequisites for .23's complete finalizer and
CNF-112's adapter owners; they do not complete either feature. See the
[uptake inventory](docs/spec-9086166-uptake.md) for exact contracts, unchanged inputs and owners.

**The dispatch companion comparison** follows ADR-0032's comparison rule. It reads
`spec/docs/design/dispatch-witnesses-v8.json` at run time, never compiled in. Its partition is an
**implementation reading**: rescue content first, then reboot content in start or steps, then
stage1. Empty reboot results and installation entries alone never route a trace; pairs stay
whole. The header requires schema 8, namespace `TauWeb.Dispatch`, 3 events over 8 distinct
alphabet events, and all 470 traces filtered to distinct request call ids, exactly once and
starting at `bound.start`. A truncated enumeration fails.

It runs stage1 only: 52 witnesses and 286 enumerated traces. The dedicated bucket, 54/184,
belongs to twr-i6k.3; reboot, 12/0, belongs to twr-i6k.11. Together they cover 118/470. Each start
journals a seed-backup completion, one batch approval with one index per entry, explicit fixture
class/declaration prerequisites, its calls and
dispositions, including the invalid historical disposition. Abstract durable journal ordinals
map explicitly to production record numbers, including starting records and successful reads.
Setup association constituents count individually; fixture seed/setup shells and approval
scaffolding do not. Failed appends, refusals and admitted-map duplicates advance no ordinal. Extra index and vendor-id mappings
are committed as association events and recover from files alone.
Every outcome and projection member is compared at every step. Oldest-first
members stay lists; resource/entry members are keyed sets. Unmoved members must stay empty.
Inference and dispositions on its resource run in the core without store records. This
comparison remains core-only for inference and does not use the new inference journal path;
the inference comparison remains core-only at schema 8. Replay
actually reopens the store. Command requests use the existing intent and job-evidence path,
with target, session and requester provenance recorded by the production append. The file's
approval facts map bijectively to the recorded pin admission's fingerprint, and its approval
session maps to the recorded command session. No typed operation approval is attached to a
command. Current `run_command` records its named target and the bound session's identity in
`provenance.session`; older command records, with `session` null, retain their shape.
The driver maps witness allocation indices bijectively from production returns: approve entry 2
then entry 1, reserve the extra index with `Store::allocate`, then associate the vendor id. At this
start the map is witness 2 ↔ production 0, 0 ↔ 1, 1 ↔ 2. It is fixed, injective, retained across
reopen, and applied in target conversion both ways, beside the entry, vendor, session, fact and
call mappings. Associations stay an oldest-first list under this ordering. Reopen supplies no
association knowledge; all mappings and approved entries come from journal replay.
The driver retains only identity mappings beside that production store and never projects its
own request cache.

Production assumptions are `resourceKey: entry`, `reach: disposed`, `lapse: continuation` and
all boolean guards true. Every unpaired trace and refused side matches, and each admitted side
changes exactly its named guard and differs somewhere. All fourteen stage1 guard pairs are required, with both separate orderAssociation admitted traces
run and checked. Bindings, receipt presence/withholding, quarantine and identity exclusions are compared; schema-8 nullable
fields must actually be present. Journal compatibility defaults do not loosen witness shapes.
Required event-specific outcomes and closed refusal shapes are validated on all three routes,
including admitted controls. Dedicated/reboot behavior is not executed here. Unknown, absent
or inapplicable vocabulary or members fail with the trace and step. Permanent negative controls include
an outcome flip, empty/absent file, unknown event/outcome, truncated enumeration, unknown
member, missing pair side, a second disabled guard and wrong routing counts.

The original core and read-fixture tests were written from the Markdown before the schema-6
witness JSON was read.
Projection setup exposed two omissions before the first comparison: known entries must resolve
when named directly (`STA-24`), and named entries start at installation zero (`STG-20`). Both
were corrected from those requirements. The comparison then raised no behavioral disagreement.
Its successful record is printed by
`cargo test --locked dispatch::comparison -- --nocapture`; the implementation revision is the
commit the test ran at:

```text
dispatch companion comparison: passed
  rule: ADR-0032, How the implementation is compared; ticket partition is an implementation reading
  file: spec/docs/design/dispatch-witnesses-v8.json
  schema 8, module dispatch, namespace TauWeb.Dispatch, bound: 3 events over an alphabet of 8, distinct request call ids
  stage1: 52 witnesses / 286 enumerated traces (twr-ggw.8)
  dedicated: 54 witnesses / 184 enumerated traces (twr-i6k.3)
  reboot: 12 witnesses / 0 enumerated traces (twr-i6k.11)
  total: 118 witnesses / 470 enumerated traces
  compared: start, every outcome and projection member at every stage1 step; keyed sets compared by key
  commandHold: 4 named / 28 enumerated refusals
  pair: TauWeb.Dispatch.excluded_order_refused refused matched; TauWeb.Dispatch.excluded_order_sent_without_guard admitted differed at step 4
  pair: TauWeb.Dispatch.order_receipt_association_required refused matched; TauWeb.Dispatch.order_receipt_without_association_admitted admitted differed at step 2
  pair: TauWeb.Dispatch.order_receipt_association_required refused matched; TauWeb.Dispatch.order_receipt_without_association_admitted admitted differed at step 3
  pair: TauWeb.Dispatch.second_command_held refused matched; TauWeb.Dispatch.second_command_without_hold admitted differed at step 2
  pair: TauWeb.Dispatch.session_destroy_under_abandonment_refused refused matched; TauWeb.Dispatch.session_destroy_lifts_abandonment_without_guard admitted differed at step 3
  pair: TauWeb.Dispatch.same_action_new_call_id_refused refused matched; TauWeb.Dispatch.same_action_new_call_id_admitted admitted differed at step 2
  pair: TauWeb.Dispatch.second_index_same_entry_refused refused matched; TauWeb.Dispatch.second_index_same_entry_admitted admitted differed at step 3
  pair: TauWeb.Dispatch.boot_id_change_not_success_refused refused matched; TauWeb.Dispatch.boot_id_change_not_success_admitted admitted differed at step 2
  pair: TauWeb.Dispatch.resolution_append_failed_refused refused matched; TauWeb.Dispatch.resolution_append_failed_admitted admitted differed at step 2
  pair: TauWeb.Dispatch.disposition_one_continuation_refused refused matched; TauWeb.Dispatch.disposition_unrestricted_admitted admitted differed at step 2
  pair: TauWeb.Dispatch.read_does_not_lift_abandonment refused matched; TauWeb.Dispatch.read_lifts_abandonment_without_guard admitted differed at step 3
  pair: TauWeb.Dispatch.destructive_choice_stops_commands refused matched; TauWeb.Dispatch.command_preempts_reinstall_without_guard admitted differed at step 3
  pair: TauWeb.Dispatch.read_and_inference_never_restricted refused matched; TauWeb.Dispatch.read_and_inference_restricted_without_guard admitted differed at step 5
  pair: TauWeb.Dispatch.disposition_names_own_unresolved_calls refused matched; TauWeb.Dispatch.disposition_ends_call_elsewhere_without_guard admitted differed at step 3
  pair: TauWeb.Dispatch.replacement_in_force refused matched; TauWeb.Dispatch.replaced_continuation_dispatched_without_guard admitted differed at step 5
  spec commit: 9086166b0ee62387da6440da059f5b89f01a0d8d
  implementation revision: the commit the test ran at
```

This comparison is evidence about harness knowledge alone; the storage and browser fault tests
carry ordering and contact evidence. Approved entries and their approval-time indices are
journaled here. Live bindings are enforced above this core. The model's typed-operation tool now
reaches the create barrier before approval. Creating/paying and learning
the vendor id are twr-ggw.21's; inference records now use their own store path; session-start
selection is twr-ggw.18's and the disposition screen twr-ggw.66's;
account-credential sheet export is twr-ggw.27's and Replace's statement about it twr-ggw.29's;
the real account checks and CNF-78's override measurement remain twr-ggw.51's; the abandonment flow and its
authorization twr-ggw.31's; LNVPS fixture and criterion 23's LNVPS half twr-ggw.32's; stop and
renewal-off twr-ggw.40's; LNVPS reinstall twr-ggw.45's; operator rendering twr-ggw.66's and
refused request results twr-ggw.67's. Rescue rules and remaining reboot traces belong to
twr-i6k.3 and twr-i6k.11. Snapshots, compaction, retention and stage 2's untyped-scope hold remain
outside this work.

### Job records and collection

`collect_jobs` and held-request reads require a live binding and use its machine client key.
They never create a binding and do not append a command intent.

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
and detached commands running. It also closes each stopped held wait's browser socket at once;
that wait makes no further SSH use. Command dispatch and collection use separate stops.
An interrupted read is abandoned without appending evidence;
waiting to acquire the writer is also stoppable. No evidence append begins after a stop,
but an append already begun completes whole and its evidence stands. A stopped wait answers
held with what was read so far and why the other calls were not read. It settles nothing and
arms no later dispatch. There is no timer for the wait.

Session end fires every command, held-wait and collection stop before acquiring the store
writer. Channels close when the end begins: the stop closes the registered browser socket
without awaiting the close event, the SSH driver's queue or a suspended append. Registration
outlives the byte stream's move into the driver; an already stopped registration closes
immediately. Connect, channel opening, command transmission and record reads are stoppable,
including SSH identification, key exchange, authentication and rekey stalls. A stopped path
sends no SSH DISCONNECT, and a stop cancels a normal disconnect wait already underway.

Held and collection read failures use one rule: after session end a sent read reports
`"sessions ended while reading record"`; an unsent read reports
`"sessions ended before record was read"`. Collection retains `failed: true` for a sent read
and `not_read: true` for an unsent one; held requests retain `not_read: true` in both cases.
Outside session end the read's own reason remains. A cancelled read whose `exec` was sent is
never described as unsent. **Implementation reading:** a stopped, sent command reports
unresolved with `"sessions ended while awaiting job record"`; before transmission it
retains `"sessions ended before command transmission"`. It stays collectable after unlock.
All three sites use the stoppable evidence-append boundary: no new append begins after a stop,
and a begun append completes whole. An uncommitted job record is returned as evidence
with an unresolved call. **Implementation reading:** when session end stops that command's
evidence append before it begins, `why` is
`"job evidence append: sessions ended before journaling job evidence"`.
Inference terminal records and mint/revoke cleanup remain permitted.
Nothing is retried. Browser cases observe socket closure while a revoke withholds the end
step, before worker termination, including while an intent or evidence append is suspended.

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

### Binding and the exposure ledger

The page's exact-member `{"bind":{"machine":"fixture"}}` message names one approved
machine. Locked stores and active seed-backup ceremonies refuse first; `Dispatch::check_binding`
then checks the entry, class and access. A second live binding refuses without journaling.
Binding also requires that exact identity to be listed under the current seed in allocation
metadata, including after Restore; status is not filtered here. The client key derives at
the entry's journaled identity, the exposure entry commits, and only
then does a live session receive the key. A failed append creates no session.

**Implementation readings:**

- A session lives in the harness worker's memory. Its identity uses its exposure record's
  number and is never reused after restart. Lock, pagehide, reload, crash, bfcache restore and
  seed-backup re-display end it. There is no separate end-session act. A bound set has one
  machine; larger sets belong to twr-ggw.22.
- Replay restores the exposure ledger, never live bindings. Re-entry after a worker ends needs
  another operator binding, a fresh session identity and another ledger entry. Exposure does
  not disappear when a session ends.
- The configured model is recorded at session start by twr-ggw.18; until then the entry names
  none. No model is guessed.
- An attempt uses the oldest journaled passes-family identity under the current seed whose
  status is reserved or created, including a listed Restore identity. No production act here
  allocates a pass: enrolment is twr-ggw.26's. With no listed pass there is no relay key. The
  credentials step refuses `no-credentials` after the pin lookup and before contact. The relay
  key derives in harness code per attempt and is given to no session. A restored seed can bind
  listed machines and use listed passes, and can allocate neither.
- An approved unbound attempt is recorded with its own encrypted refusal event, before the
  report. It creates no binding or intent. A failed append still refuses and latches the store.
  `no-entry` and other pre-contact policy refusals remain write-free.
- A command intent retains `harness_pin` approval and puts the bound session identity in
  `provenance.session`; older `null` values remain readable.
- No typed-operation approval screen exists yet. The adapter's caller-bound admission runs before any approval
  is composed or compared, including requests with no approval. It checks the harness-supplied
  caller identity, the request's session identity and the resolved resource against that live
  session's bound set. A caller-present request must have requester `session`; relabelling
  it as operator or harness-flow refuses before approval comparison. Outside any session,
  operator and harness-flow requests retain their existing behavior;
  their authorization and abandonment flow belong to twr-ggw.31. This seam is above the core,
  so the formal companion comparisons retain their recorded outcomes.

Session inspection and transport read the same credential collection. The type supplies its
`Credential::ROW`; inspection names each row and machine, with no key material. A session is
neither a credential type nor a credential-scan exemption. At binding it holds only row 3 for
its bound machine. Once the first inference request mints a session inference key, it holds
row 2 as well, with `machine:null` denoting the session. It never receives row 14, the seed or
the relay key.

### Acceptable weaker modes

The tracer's machine named `unpinned` has no host-key pin; it is unrelated to ARC-25's
unpinned installation. Installation history below is exercised on `fixture`.

The closed `Mode` type implements two SEC-14 labels: **An installation with no artifact pin**
(`no_artifact_pin`) and **Acting on a goal with no brief** (`no_brief`). Other identifiers,
including `unpinned`, are refused by deserialization and replay. Later modes need explicit
variants; the standing-mode hook and rendering iterate the modes present.

The acceptance surfaces and windows are **implementation readings**:

- Acceptance is a store act, following the dispositions precedent. Both builds now expose
  no-brief acceptance on the goal card through `goal_accept`; installation acceptance stays
  store-only. The binding message retains exactly
  `{"bind":{"machine":"fixture"}}`.
- `Store::bind_with_modes(machine, &[Mode::NoArtifactPin])` accepts the installation mode only
  on the machine's first binding, before any exposure record names it. The binding act stands
  in for before first contact: connection admission requires a live binding. Acceptance and
  binding share one encrypted exposure record. A failed append binds and accepts nothing;
  a move that lands and reports failure restores the exposure and mode on replay, with no
  live session. Asking for an invalid mode refuses the entire binding without a record.
- `Store::accept_mode(session, Mode::NoBrief)` requires a live session and precedes its first
  journaled command intent, identified by `provenance.session`. The model tool path requires
  this acceptance for its goal before acting. A duplicate, unknown or ended session,
  the installation mode through this act, and a no-brief acceptance inside binding all refuse
  without writing. **Implementation reading:** this gate applies to the model's acting tools;
  existing operator `run_command` and `collect_jobs` requests remain unchanged.

Installation history stands for the life of this store, through restarts, later sessions,
fixture destroy and fixture reinstall. A later binding shows it and refuses to accept it
again. No-brief is conduct of its accepting live session alone: ending the worker ends the
mode, while its journal record remains inspectable. Replay restores no session. Full re-entry
and what earlier conduct left live belong to twr-ggw.24. **Never entered by failing** means only
these two acceptance acts write acceptances; a host-key halt, failed admission, hold,
disposition, barrier, restatement refusal or signature refusal adds no mode.

`Store::standing_modes(machine)` is the single restatement hook: the target machine's history
plus conduct of the live session holding that target, including when an operator requests the
act. At fixture **destroy** and **reinstall**, approval's `restated_modes` must equal that
ordered list exactly. Missing, extra, duplicate or reordered entries refuse before append or
send, both through `Vendor::run` and direct `Store::operation`. Create, reset and read require
an empty list. The intent records the list beside its matching approval; old records omit it
and retain their meaning. **Implementation reading:** the approval is the restatement's
stand-in until an approval screen exists. Paid invoices (twr-ggw.21), added machines
(twr-ggw.22), placed secrets (twr-ggw.23), and LNVPS reinstall (twr-ggw.45) call this hook when
built.

**Implementation reading: fixture reinstall restates and does not re-accept.** This adapter
installs nothing. SEC-14 limits when history may be accepted again to a new installation;
its permission does not require a fixture acceptance. Spec `TASKS.md`, T47, leaves reinstall's
attest identity undecided and gives CNF-93's reinstall case to the jump-host route. The nearest
owner is twr-ggw.45, which today restates only; the jump-host route is stage 2. Re-acceptance
remains owed and has no owning ticket yet.

**Implementation reading: the trust display surface** until twr-ggw.18 is the page's live
session and bound-set view plus `store_state` inspection. Both report and inspection add:

- `sessions[].standing_modes`: every standing SEC-14 display label, in hook order;
- `installations`: approved machines with history, each `{"machine":"fixture","installation":"unpinned"}`;
- `mode_acceptances`: every acceptance, including ended sessions, with `session`, `mode`
  (display label), `bound_set` (machine names), and `standing` (boolean);
- `signature_refusals`: each refusal's `machine` and `form`.

The page renders `Installation: unpinned.` in that machine's section, and every standing label
as `Standing mode: <label>.` alongside its existing session and bound-set line, generically.
The unpinned installation names no bootstrap URL, hash or signer, including nothing from the
compiled Alpine artifact policy. History remains visible with no live session. The goal card
now offers no-brief acceptance and browser cases cover its standing label too. Replay restores
no session or active conduct. Trust layers and Delivered labels remain with their owners.

**Implementation readings: signature lowering.** On a machine with installation history, two
literal pacman assignment forms are refused (ARC-25a, CNF-67). `SigLevel`, `LocalFileSigLevel`
and `RemoteFileSigLevel` values containing whole `Never`, `PackageNever` or `DatabaseNever`
tokens are the signature-level form; `TrustAll`, `PackageTrustAll` or `DatabaseTrustAll` tokens
are the untrusted-repository form. Omarchy's `SigLevel = Optional TrustAll`, including inside
its repository heredoc, is inside the latter. A bare `Optional` is a presence level and passes
this check. **Implementation reading: matching** is case-sensitive, on raw bytes split at
newline bytes; lines whose first byte other than ASCII whitespace is `#` are ignored. A word is a
maximal run of ASCII letters, digits and underscore. Every whole directive word anywhere on
a line is examined: its next `=` on that line opens a value extending to the line's end.
Any whole lowering word in that value refuses, with the first such word determining the form.
Whitespace, quoting, backslashes, shell syntax, other directives and all other punctuation
between the directive and `=`, or between `=` and the lowering word, end nothing. Non-word
bytes delimit words rather than joining fragments; no shell evaluation runs. This deliberately
over-refuses: `echo SigLevel = Required; echo Never`, `echo /SigLevel=Never` and
`echo SigLevel = 'Never'more` all refuse. Quoted fragments such as `'Never'more` are separate
words in the raw bytes even when the shell would join them into `Nevermore`.

**Implementation reading:** the refusal applies **only where the installation mode stands**, computed from durable history,
so restart and rebind cannot evade it. `Journal::append` checks before the hold and before any
intent. `run_command` checks immediately after binding admission, before holds, launch size,
pin lookup, relay contact and SSH channels. A refusal commits its own encrypted record before
reporting `{"refused":"signature-lowering","machine":"fixture","form":"signature_level_never"}`
or form `untrusted_repository`. It writes no intent and sends nothing. Failed refusal appends
still refuse and latch the store. **Implementation reading:** records omit command bytes and
carry only the machine and first matching form.

**Implementation reading: matcher limits.** Fragments are never joined: a directive or
lowering word split by quoting, a brace or an escape (`Sig"Level"`, `Nev'er'`, `Nev{er,}`,
`Sig\Level`, or `printf 'Required\tNever'`, whose final word is `tNever`) remains outside.
Line continuations, lowering words absent literally from the bytes (`SigLevel = $LEVEL` or
`SigLevel = $(printf 'Nev%s' er)`), encodings (base64 and printf escapes), files written
elsewhere and pulled through `Include` or `--config`, substitutions such as
`sed 's/Required/Never/'` that never spell the directive, bare `SigLevel = Optional`, a commented
directive later uncommented by another stage, and scripts fetched at runtime are outside
these two forms. A lowering word counts only after a directive's `=` on the same raw line, so
one written earlier on the line or on another line and carried in by a variable
(`L=Never; echo "SigLevel = $L"`) stays outside. A raw line whose first byte other than ASCII
whitespace is `#` is skipped even where the shell does not read it as a comment, for example
when that `#` closes a string quoted across the line before. Those limits are owed to a
follow-up ticket; this matcher claims no general shell policy enforcement.

**Criterion 5 has a given half and an owed half; it is not claimed met.** Given here is refusal
of these lowering commands while leaving distribution checking on, plus the byte-for-byte
stock Arch configuration in `tests/vectors/pacman-c8ccc368.conf`, from Arch's packaging project
at `c8ccc368`. It sets `SigLevel = Required DatabaseOptional` and
`LocalFileSigLevel = Optional`. Under Required, missing or invalid signatures are fatal
([pacman.conf(5)](https://man.archlinux.org/man/pacman.conf.5.en)). **Implementation reading:**
this concerns unsigned repository packages. Stock Arch accepts a local unsigned `pacman -U`
file; the harness neither refuses it nor raises that setting. Owed is an observed refusal of
an unsigned repository package on real Arch in twr-ggw.51's live run. No fixture box plane runs
pacman, and CI's Ubuntu runner has neither pacman nor Nix; adding either was excluded. No gate
claims to demonstrate a package refusal. twr-ggw.51's live run owes that observation.

Host tests exercise late and atomic acceptance, unchanged modes after every existing failure,
all display members, both irreversible operations through adapter and direct store admission,
restart lifetimes, the two lowering forms, stock configuration admission and failed refusal
appends. The independent reader checks these records with its own shapes and acceptance-window
logic, keeping prior exposure, acceptance and command facts incrementally so each event is
parsed once. Browser cases seed a store independently, bind through the page in both builds, assert
exact rendered phrases and artifact absence, and refuse harmless printf commands before any
relay or SSH connection. Tracer controls complete the same printf bytes on `fixture-other`
without the mode and `echo ok; exit 7` on `fixture`; a wrong host key leaves existing modes and
acceptance records unchanged. Set `TAU_TRACER_MODE_CASE=all` for just these cases; unset every
selector for the full gate. The mutation evidence below records the boundary checks.

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

  Live sessions hold role 0; the harness derives role 3 per attempt; `PinSource` returns the
  pin type. The secret types print nothing of the secret, implement
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
  design. All secret-bearing credential types zeroize their bytes on drop; the seed clears its
  bytes and retains only pointers into the public word list.

The local store generates the seed in the worker and keeps its mnemonic in its first record
(below). Only seed-backup exports display and accept mnemonic words; no export returns a seed
or child key. Allocation issues the journaled indices; binding gives a session only its bound
machine's re-derived client key. The harness derives the relay key separately per attempt.

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
`seed_backup_stage` and `seed_backup_completion`, with no words. Every dispatch request, collection and binding act refuses before
contact while the seed-backup ceremony runs. Allocation's independent gate still checks the
durable completion in all three families.

Re-display terminates the worker through the ordinary lock, ending its live sessions, connections
and held waits. The local passphrase must unwrap a fresh worker's store before the same seed-backup
ceremony shows words. It journals another completion; a failed append preserves the previous
record. Nothing stopped resumes: a cut-off call stays unresolved and a held request records no
intent. Tab close, worker death, pagehide, bfcache restore and explicit lock remove
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
Decrypted non-seed records are checked too; only a record's canonical allocation or exposure seed association
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
Sheet import belongs to twr-ggw.27. Sessions, goals and tools run in the harness worker.
Seed-backup re-display ends sessions, waits and
connections, and requires a fresh binding after the ceremony completes.

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
    `run_command` supplies its directly named entry, the bound session identity, and requester `session`.
    No command carries typed operation facts or an `OperationApproval`. A new-format intent with `approval:null`
    (or an absent approval member) means never dispatched. No path in this build writes one.
  - `{"goal":{"session":"session-5","text":"…","source":"operator_session_goal_card","document_source":null}}`:
    the operator's text for that one live session, committed before it applies or its optional
    source is fetched. All four members are required; `document_source` is null or one https
    URL. The source marker is fixed by the harness. Extra members, arrays, missing session or
    source, an unknown exposure or a repeated goal for that session refuse replay. The
    independent reader checks the same documented shape without calling store code. The
    document text is never recorded. Replayed goals are history and start no work.
  - inference account, intent and terminal events use the exact shapes under "Procured
    inference" above, separately from typed operations.
  - a typed intent under `operation_intent`: `call` (its record number), `resource`
    (`{"entry":"fixture"}`), `target` (`{"entry":"fixture"}`, `{"allocation_index":0}` or
    `{"vendor_machine":"id"}`), `operation`, `session`, `requester` (`session`, `operator` or
    `harness_flow`), `facts` and `approved`. Facts contain `arguments` (a map of text values),
    `cost_bound` (an unsigned integer) and `bundle_commit`. Approval repeats the resource,
    target, operation, session, requester and facts exactly. Operations here are `create`, `reset`,
    `reinstall`, `destroy` and `read`; the writer refuses `exec` and `inference` as policy, and
    replay and the independent reader reject such typed records and intents naming the inference
    resource or target, naming the record.
    Optional `restated_modes` on both intent and approval is a list of closed mode identifiers,
    omitted when empty; the two lists agree exactly. Destroy and reinstall carry the restatement;
    create, reset and read carry no modes. No command text is accepted for a typed act.
  - `{"operation_response":{"call":1,"body":"<lowercase hex>"}}`: the boundary's response
    bytes, recorded after the typed intent and before return. Replay refuses a reference to no
    earlier typed call, a box-plane call, a second response for one call, non-lowercase-hex
    body bytes or an extra member. Refusals name the record and quote no plaintext. Responses
    do not settle calls and do not appear in page reports. Earlier journals contain none.
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
    Repeated entries/answers, an empty machine, vendor, product or region, unapproved facts, inconsistent
    classes/totals, invalid allocation order or gate, and sealed ad-hoc access refuse replay,
    naming the record without quoting plaintext. None carries derived key material.
  - a later record, one allocation event appended before it is applied ("Allocation", below):
    `{"allocation":{"reserve":{"seed":"<seed identifier>","derivation_version":1,"family":"machines","index":0}}}`;
    `created`, `failed` and `destroyed` carry the same identity; `restore` carries an export,
    `{"seed":…,"derivation_version":1,"next_unused":{"machines":…,"passes":…,"handoffs":…},"entries":[{"identity":{…},"status":"reserved"}],"restored_from_import":…,"seed_backup":null}`;
    `seed_backup` carries `{"seed":…,"completion":"full_reentry"}` (or `skipped`); the metadata
    stores that completion or `null`. `replace` carries `{"seed":…}`. The seed identifier is in the clear only inside the
    encrypted record, where credential format v1 puts it.

  - at binding, `{"exposure":{"session":"session-<record number>","bound_set":[{"machine":"fixture","identity":{"seed":"<seed identifier>","derivation_version":1,"family":"machines","index":0}}]}}`;
    Optional `accepted_modes:["no_artifact_pin"]` is inside the exposure body on a first binding,
    omitted when empty. Older records remain unchanged. Repeated-machine acceptances refuse replay.
  - `{"mode_acceptance":{"session":"session-5","mode":"no_brief"}}`: follows that session's
    exposure and precedes its first command intent; duplicates, unknown labels, installation
    modes here, and extra members refuse replay, naming the record without plaintext.
  - `{"signature_refusal":{"machine":"fixture","form":"signature_level_never"}}`, or
    form `untrusted_repository`: exact members, requires earlier installation history, changes
    no calls and contains no command bytes. Both new bodies refuse positional arrays.
  - an approved unbound connection attempt, `{"connection_refusal":{"machine":"fixture","reason":"unbound"}}`.
    These shapes have exact members and refuse positional arrays. Replay accepts serde's
    alternative enum encodings, as for setup and allocation records; the independent reader
    requires the exact documented forms. Replay rejects an unapproved machine,
    a mismatched or unlisted binding identity or missing binding prerequisites, naming only the record.
    It rebuilds ledger/refusal projections and creates no live session. Reports omit seed ids
    and every private and public key; session inspection names credential rows and machines.

  The independent reader in the tracer crate decrypts every record and reads the seed, legacy
  command, intent, typed intent, typed observation, terminal, job terminal, job observation,
  disposition, seed-backup, setup approval/class/access/requirements, exposure, connection-refusal, mode-acceptance and signature-refusal shapes,
  with exact members on the new records. It also independently parses and validates the
  inference account, intent and metadata-terminal shapes described above.
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
- **Lock ends sessions before termination.** On the Lock button, seed-ceremony hide, pagehide,
  bfcache restore and seed-backup re-display, the page clears words and inputs immediately and
  posts the exact-member `{end_sessions:true}` message. Channels close when this end step
  begins, before the store writer is acquired. The worker stops dispatch, clears
  session holdings, and independently records and sends each owed revoke. The page terminates
  it on its answer or the named 5000 ms bound, then the fresh worker loads locked. A detached
  machine job continues and can be collected after unlock.
  A killed worker cannot act. After a crash or real unload, the next-unlock sweep revokes a
  recorded minted identifier with no revoke intent, or expiry bounds the key. A revoke whose
  intent committed but whose terminal was cut off stays unresolved and is never retried.
- **The single writer.** `worker.js` takes an exclusive Web Lock, `tau-web-store`, before the
  module reads the store, and holds it for the worker's whole life (`STA-1`, `STA-7`).
  - A worker that cannot get the lock queues for it, and the page says "Waiting for the local
    store: another tab, or this page's previous harness worker, still holds it."
  - Chromium releases a terminated worker's lock asynchronously, so a fresh worker queues
    behind it.
- **Session workers.** None exists yet.
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

Binding reuses the entry's approval-time identity without moving a counter. Its client key
never derives at a computed next index. The harness uses an already journaled eligible pass
identity for relay authentication; there is no production pass allocator here. The tracer's
`test_allocate("passes")` stands in for enrolment. A replayed Restore can bind listed machines
and use a listed pass, and still refuses every new machine or pass reservation.

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
admit the entry, also after reopen. `Store::bind` calls this check before deriving or journaling
anything. The page offers a binding control after the class answer and shows each live session
and bound set. Session tools run in the harness worker; create/payment remains twr-ggw.21's. Declaration approval follows the flow below.

**Implementation readings.** The compiled two-entry setup (`fixture`, `fixture-other`), its
vendor/product/region labels and 1000/2000 sat per month prices are fixture data, not a vendor's
price, until a real source exists. Approving in the served build consumes real machine-family
indices in the operator's store; they are never reused. The question wording is also a
compile-time fixture until twr-ggw.34 supplies the bundle's wording; no page message changes it.
Connection attempts require a live binding; names with no approved entry keep the write-free
`no-entry` refusal. Access is checked at binding as an implementation reading of ARC-44's
installation boundary. One original answer per entry is an implementation reading; an approved tightening preserves
that answer and records the new class separately.
The one-approval-per-store reading and remaining in-memory associations are described under
Dispatch above.

The same-origin limit also applies to these acts: the harness cannot distinguish an operator's
click from an identical message posted by another same-origin script. Page messages have exact
members; unknown fields or values are refused or ignored with no journal entry.

### Delivery declaration proposals and approval

`src/declaration.rs` carries the pinned declaration v2 schema. Every field and nested member is
required; input never acquires an implicit default. Concrete values, explicit empty lists and
`"unspecified"` retain their schema meanings and, where the profile permits them, survive
approval and replay distinctly. The ad-hoc minimum is parsed from the
complete JSON example compiled from the pinned normative companion, which the compiled ad-hoc
profile links. Each goal's inference context includes that complete minimum alongside the goal;
the fixture proposes its typed additions while retaining the minimum's other facts. This uses
"signed bundle" in the glossary's compile-time sense and makes no signature claim in the page.
Ad-hoc proposal admission requires the exact signed TCP/22/from-any entry to remain in the
inbound list. Empty or unspecified inbound, an application-port replacement, or a changed
protocol/source refuses before retaining a card or writing approval; the same semantic check
runs again at approval, append and replay of new canonical requirements records. The candidate
is never filled or repaired. Generic schema parsing still distinguishes valid empty and
unspecified inbound from a missing field; this guard constrains ad-hoc proposals before
the delivery check.

**Implementation reading: local proposal envelope.** The existing loopback completion message
still requires exactly one valid tool call. Beside `tool_calls` it may contain `proposal`, one
of these exact objects:

```json
{"kind":"declaration","machine":"fixture","declaration":{"version":2,"listeners":{"inbound":[{"proto":"tcp","port":22,"from":"any"}],"outbound":[]},"services":[],"key_material":{"spendable":false,"permitted":[]},"drift_checks":[],"required":[],"default_credentials":"none"}}
{"kind":"tighten_class","machine":"fixture","class":"multi_tenant"}
```

The four tools, their arguments and meanings are unchanged. A proposal-only response is
refused. The whole response is validated before dispatch; both targets must match the live
bound machine. Unknown kinds, extra fields, malformed entries and relaxation refuse the turn.
This is a local fixture protocol, with no claim about a live provider's wire format.

**Implementation reading: approval identity and lifetime.** Under the writer, the worker checks
the current bound session, proposal, class and credentials, then retains one transient candidate
identified by that completion's journal call number. It publishes a harness-written card through
the ordinary worker/page path, releases the writer and waits. The card displays every proposed
fact as text, including emptiness versus unspecified. Its wording is fixture wording until
twr-ggw.34 supplies bundle wording. No answer is selected. Approval and rejection are exact
`requirements_answer` messages containing `session`, `machine`, `candidate` and `decision`
(`approve` or `reject`); they carry no replacement values or model-written approval text.
Wrong, stale, malformed, duplicate and ended-session acts make no canonical transition.

Approval rechecks the stored candidate, live binding, current class/declaration and current
credential holdings under the writer. It appends one encrypted `setup.requirements` record
before applying the fact or waking the loop. That record has exactly `session`, `candidate`,
`access` (the journaled maintained ad-hoc profile and revision) and `proposal`. A declaration
records the complete resolved values, rather than a profile lookup for later replay. A class
tightening requires an existing single-purpose answer and validates the existing declaration
against multi-tenant constraints before recording the new class. Inspection's `setup` retains
`answer`, the effective `class`, `declaration` and the `requirements` history. Both the original
answer and every approved tightening remain visible after unlock. No intermediate incompatible
state is applied. The existing one-machine binding path remains; larger-set tightening policy
is outside this change.

Pending approval blocks common model-tool admission and further inference preparation. The
companion tool waits, including plain `done`, and then passes its ordinary admission again.
Subsequent turns carry the accepted proposals as operator-approved intended requirements,
separately from untrusted tool output and from measured observations.
Approval grants no operation approval and clears no hold, barrier, disposition or no-brief
requirement. Rejection, session end and failed append release no deferred call. End cancels the
wait immediately, checks liveness under the approval writer and after append, and prevents a
late act from restarting work. An append whose move landed but reported failure may replay as
approved, under the existing failure latch; its current-session continuation stays stopped.
Replay restores only committed machine facts, without a card, binding, running goal or tool
continuation. Historical intents still replay without a new declaration prerequisite.

**Implementation reading: typed values.** Ports are integers 1–65535; protocols are `tcp` or
`udp`; inbound sources are `any`, `peers` or `none`. Outbound hosts admit `any`, ASCII DNS labels
(up to 63 bytes each and 253 total, alphanumeric ends, interior hyphens), or parsed IP CIDR
blocks with bounded prefix lengths. Service names follow the pinned stage-1 grammar and
247-byte bound, refusing instances and unit suffixes. System scope has no account; user scope
requires the pinned account grammar and 32-byte bound. Lifecycle values are exactly
`running-at-delivery` and `enabled-survives-reboot`. No lifecycle read or command composition
is performed here. For the companion's otherwise unenumerated material labels, the supported
typed kinds are `public`, `watch-only` and `private-non-spendable`; locations are absolute paths
containing ASCII letters, digits, slash, dot, underscore or hyphen. Default-credential lists
contain nonempty identifiers using letters, digits, underscore, dot, colon or hyphen. These are
narrow supported input grammars, not new measuring procedures. Multi-tenant declarations must
state spendable false and permit no private tenant material. Empty permitted tenant material
does not prohibit the separately classified application-secret path.

There is no signed check library at this pin: `required` and `drift_checks` admit only explicit
empty lists or the schema's unspecified marker. Nonempty entries, commands and claimed bundle
provenance are refused. No historical exec is scheduled as a declaration check. The response
boundary scans the original lossy-decoded message, its names and values, with held and transient
request credentials, and compares the original and redacted messages including proposal
presence. Unsafe messages withhold proposal and call together; redaction creates no replacement
candidate. Current holdings are checked again at retention, rendering and approval commit.
Raw completion bodies never enter approval records or the page's goal outcome.

**Implementation reading: conservative installation and create admission.** Arbitrary exec
can install software, so every new raw command requires journaled class, access and approved
declaration. All three requestable jobs also require those facts before their existing
availability boundary. The check runs before command contact/intent and again at command
append. Typed create and reinstall check the same prerequisites through resolved approved
entries, including all existing target aliases and requester routes, before contact and again
at durable append. Refusing create is a conservative implementation reading of
the catalogue-image ambiguity, which the specification has not settled. Missing facts do not
prevent binding, goal entry, inference, typed reads or record collection. Goal-loop preflight
uses its own acceptance/context check, so obtaining a declaration never requires one already.
A pending proposal also blocks command append and typed mutation append for that machine.
Complete facts permit progress only to the existing truthful boundary: unavailable job,
missing pin or operation approval still awaited. This supplies no install/create/payment
implementation; the fixture delivery check below consumes the journaled requirements.

Host checks cover schema and grammar, current credential safety, exact approval identity,
append failures and landed errors, replay validation, tightening and the installation/create
boundaries. Browser cases observe the actual inference request, card, buttons, paused loop,
approval/rejection, encrypted records and unlock, with end races at writer, move and companion
boundaries. The encrypted reader validates new record shapes and class/material constraints
independently in `tracer/src/declaration_reader.rs`. Inherited dispatch fixtures explicitly add
preapproved declaration history through independent encrypted records before testing later
boundaries; these fixture records are not an alternate production approval path. The dispatch
companion comparison retains its pinned witnesses and outcomes, with explicit prerequisite
history in its driver. The fixture delivery verdict is described below; observation evaluation
remains .20's, lifecycle evaluation .36/.73's, converging install .16's and real create/payment .21's.
The specification pin is retained; this change does not complete T42.

### Declaration mutation evidence (D01–D27, B01–B06)

On 2026-10-26 the host controls D01–D27 below changed one production property, compiled,
reached their named assertions, restored the original file byte for byte and passed the same
selected check, with red/green exits **101/0**. Their exact source, patch and selected host-test
coverage are unchanged by the browser correction below. Browser controls B01–B06 are rerun
against that correction, with red/green exits **1/0** and mutated/restored builds exiting **0**.
Every restored browser check passes all ten declaration cases, including the actual page
approval click, encrypted append and unlock. No compiler error, polling exhaustion, timeout
result or unexecuted assertion counts as a successful control.

An earlier B01 run stopped with “declaration card did not appear” and zero cases; it was
invalid evidence and is superseded here. The earlier B05 waiter failure depended on a timeout
sentinel; its replacement reads the real loop's published outcome after the end step returns.
The equality control D21 now asserts the inference boundary's refusal directly before any
proposal handler, so a later handler refusal cannot supply its negative evidence.
The earlier claim of thirty valid declaration controls is withdrawn. The Round 2 claim that
all 33 controls were valid is also withdrawn: B06's combined assertion short-circuited on a
timeout sentinel and never read the late-publication counter. That B06 result is invalid and
is superseded by the direct publication/state observations below. The original logs remain
historical. The tables combine 27 unchanged host controls with six rerun browser controls;
the three minimum controls remain included.

Criterion keys: **C1** goal-derived typed proposal, signed minimum and explicit approval;
**C2** signed-check provenance and measuring-command refusal; **C3** presence, emptiness and
unspecified; **C4** version, service/scope/account grammar; **C5** one-way tightening;
**C6** installation admission and append; **C7** conservative create admission;
**C8** durable authority, exact identity, credentials, replay and session end.
The schema, approval, failure/replay and requester/alias tests in `src/store/declaration_tests.rs`
exercise the corresponding positive and refusal paths, including unchanged journal bytes.
Empty/unspecified inbound remain schema values but refuse ad-hoc approval because they omit
the signed TCP/22/from-any entry. Other permitted empty/unspecified values retain their
representation through approval and replay. The independent encrypted reader has its own
minimum and grammar checks; it calls no production validator.

Exact command templates (the selector in each row is the literal test substring):

```sh
# H(selector), for D01–D26:
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web --lib SELECTOR -- --nocapture
# R(selector), for D27:
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tracer --bin tracer SELECTOR -- --nocapture
# B, for each browser control, with all other TAU_TRACER_* variables absent:
WEB=/var/tmp/tau-web-manager/ggw14/tools/web-env.sh
export TAU_TRACER_GOALS=1 TAU_TRACER_GOAL_CASE=declaration
bash "$WEB" bash scripts/build-web.sh tracer
bash "$WEB" cargo +1.97.1 run --locked -p tracer -- run dist/served dist/tracer
```

The web wrapper and compiler/browser versions are recorded under “Session goals and tools
mutation evidence (G1–G44)”. Commands ran serially in the foreground, without pipes, using an isolated `TMPDIR`.
For each B control, restoration was followed by rebuilding the fixed tracer and rerunning B.
A served build was already present; the final full gate rebuilt both builds without selectors.

The following are full SHA-256 values. Each S row is both the **before** and **after
restoration** hash of that file, measured separately for every listed control. Each control
also records its distinct mutated-file hash. These hashes describe these executions; they
are not reconstructed hashes for the earlier logs.

| Source | File | Before = restored SHA-256 |
|---|---|---|
| S1 | `src/declaration.rs` | `0419236ac5064b6f97cf6be5505f48d7e70c2377852356c0f10cf3c5e0ae75a3` |
| S2 | `src/dispatch/setup.rs` | `b9d9301e86723f12339e84953b2ffed61d1fab68d84d6a25500e5e892077b084` |
| S3 | `src/dispatch/typed.rs` | `6bb5f16b86f2ef1879c52d47f2bb2755fe3c89184a6fe2deff5265ac49042006` |
| S4 | `src/goals.rs` | `408d89f802cdfc8b06448c10b131fb193fb115cf8b1ba013e04c297ac4719517` |
| S5 | `src/harness/goals.rs` | `27810874fc872aeab73bdf3c83389081652a07c5bfdbe432abed3dbd2e2704b6` |
| S6 | `src/store.rs` | `b051c9d81c3040ccbad34e1276f7797bc4b2f8f407095c2742c43d8fcade752b` |
| S7 | `src/store/goals.rs` | `10696040335ac7d3d8dd824367c38a2962a789f0c8dce4ee7ff630c06ed5f285` |
| S8 | `src/store/inference.rs` | `e2211216088531bf746eb5ee21a83be76f41898feb5d730bb842494f6a3fb5ea` |
| S9 | `tracer/src/declaration_reader.rs` | `3ac23ac5fa2d8a2656b99a8d8698e45d51091eb3af704c31e31f559795614aac` |

The host controls are carried forward only after checking their source and selected-test
hashes against the exact earlier source receipt, reconstructing each mutant from its patch in
memory and matching its recorded mutant hash, and inspecting its intended panic plus red/green
logs. The source receipt covers all 95 implementation inputs. The selected test files below
are unchanged for D01–D27; the revised browser fixture is fixed for every rerun B control.
Each B mutation changes only its named production property, leaving that fixture untouched.

| Check input | SHA-256 |
|---|---|
| `src/store/declaration_tests.rs` | `c6290ae48b622487955d509967c7573791b1d16bb24182276d099924ca3a1e43` |
| `src/store/goals.rs` | `10696040335ac7d3d8dd824367c38a2962a789f0c8dce4ee7ff630c06ed5f285` |
| `tracer/src/declaration_reader.rs` | `3ac23ac5fa2d8a2656b99a8d8698e45d51091eb3af704c31e31f559795614aac` |
| `tracer/src/declaration_cases.rs` | `b3472b236253d20ab8e99bcf02dbb83723ca5efe0a1bf2558732790cc68ec4ea` |

| Control / criterion | Source; one-property mutation | Command selector | Expected and actual red assertion | Mutated SHA-256 | Red / restored green exit |
|---|---|---|---|---|---|
| D01 · C4: version | S1; Disable `version != 2` refusal | H(`declaration_requires_every_field`) | `/version: … "version":1` at the version rejection assertion | `7e8b11745e0cbdc81fc3eb86cc1e0bfd7b173df8fb525bb3ba096845ce91fd0c` | 101 / 0 |
| D02 · C2: provenance | S1; Disable nonempty required/drift refusal | H(`declaration_checks_cannot_claim`) | `Declaration::parse(&d).is_err()` fails for an invented check | `c45fa4affb7dbf6d6abc10659dc83de176451e8dc87495daf8567c6806d3da2b` | 101 / 0 |
| D03 · C4: service | S1; Disable `service_name` refusal | H(`declaration_service_scope`) | `""` at the invalid service-name assertion | `9c9136a9c6020e1fb2ad0399978087789ab325a44f185455b1750e860009f4f3` | 101 / 0 |
| D04 · C4: account | S1; Disable `user_account` refusal | H(`declaration_service_scope`) | `""` at the invalid user-account assertion | `a4a798bd1d16163cf1f22707c47c877382fe9181fa25c7e82ea96e70aa9f3d67` | 101 / 0 |
| D05 · C3: presence | S1; Insert missing services as `[]` before parsing | H(`declaration_requires_every_field`) | `missing /services` | `c71b6f520f6ad80963b39c7a4c1178010cf9371e5b0690d9abec6817d1850fdc` | 101 / 0 |
| D06 · C4: scope | S1; Drop system scope account before parsing | H(`declaration_service_scope`) | `parse(service("hermes", scope)).is_err()` | `1dc297dd5a6d7c22fe929055df9ac95be14fa9f718e3973ce8061bff96566d1b` | 101 / 0 |
| D07 · C5: tightening | S2; Disable current/resulting class direction guard | H(`declaration_tightening_is_operator`) | `propose_requirements(identity,43,…).is_err()` fails on relaxation | `33e231abc42d83fb68f093d040a925cea859741f2f900cfbc89c18826e6d1fb6` | 101 / 0 |
| D08 · C5: material | S1; Disable multi-tenant material guard | H(`declaration_tightening_refuses_incompatible`) | `propose_requirements(session,43,tightening,…).is_err()` | `9e22a623a95a74dd9d04bd77834b761f50446572ff7ff26e526f3321f0f73339` | 101 / 0 |
| D09 · C8: identity | S7; Disable machine/candidate match in `match_pending` | H(`declaration_pending_is_not_authority`) | `approve_requirements(identity,"fixture-other",42).is_err()` | `0e5465006549ead23e7b55273c2948d3e74f291bc2db7e99d872eb88a16d5b7a` | 101 / 0 |
| D10 · C8: durability | S6; Apply cloned dispatch before propagating failed commit | H(`declaration_failures_and_landed_errors`) | `approved_entries["fixture"].declaration.is_none()` | `72e804e4b80765e8428cd179f0c8b6da8811cff9ae0117ed02d248c1c7ab5a14` | 101 / 0 |
| D11 · C8: retention scan | S7; Disable credential scan in `check_candidate` | H(`declaration_current_credentials`) | `propose_requirements(identity,42,proposal(d),…).is_err()` | `47f4f3908d980aedf2156065abfdfd965648f8a6bccd79dcd6e90572dfd6b2a8` | 101 / 0 |
| D12 · C8: approval scan | S7; Replace approval `check_candidate` with `check_proposal` | H(`declaration_current_credentials`) | `approve_requirements(identity,"fixture",42).is_err()` | `b3cfd942d05c0889a3fa9ab214f31591eefd2aeef3856a71e3b49f7c403646d3` | 101 / 0 |
| D13 · C6: admission | S6; Drop `Journal::check` installation-facts guard | H(`declaration_exec_and_job_admission`) | `block_on(s.check("fixture")).is_err()` | `e8ce313f5fb7689d932e83f5c46a16b8cb558a010482804851dc2b7f33ec29ba` | 101 / 0 |
| D14 · C6: append | S6; Drop `Journal::append` current `self.check` | H(`declaration_exec_and_job_admission`) | `block_on(s.append(&entry,&approval)).is_err()` | `5a5e00757a24a2b8e953ffb44d3dc5e563e167e58d7dd6f3a9d671035de560c6` | 101 / 0 |
| D15 · C7: create | S3; Replace typed installation check with `Ok(())` | H(`declaration_create_refuses_each_missing`) | `class Session` at adapter InstallationFacts refusal assertion | `c85aa2cd5e1b17e31b714290122f18815ce4acfec051b06a72ea5cf1f4f5d892` | 101 / 0 |
| D16 · C8: replay class | S2; Skip requirements `apply_setup` proposal validation | H(`declaration_replay_rechecks_material`) | `reopen(&s).is_err()` fails on tightened-class material | `af77c1f217819f9879f137d04afec3f9475eb58df9d23df2f2c6eaa88f359420` | 101 / 0 |
| D17 · C6: pending tool | S7; Disable pending guard in `check_tool` | H(`declaration_pending_is_not_authority`) | `s.check_tool(&identity,&done()).is_err()` | `627c494f18613d414518bf4b098d4ac656fb36b76803fe736f25085d44782052` | 101 / 0 |
| D18 · C6: pending inference | S8; Disable pending guard in `inference_prepare` | H(`declaration_pending_blocks_new_inference`) | `block_on(s.inference_prepare(…)).is_err()` | `4bfc813d6549668a66ca63974f8cf42f5e7e18411a019aca3e50168d0d89d5ba` | 101 / 0 |
| D19 · C8: companion end | S4; Remove loop ending check immediately before `driver.tool` | H(`declaration_loop_checks_end`) | equality fails: actual `Null`, expected `"sessions ended"` | `207084ac895cdb2f5a43d388ec689bdbe6ca02d79a72f5dfe81d8200aa5d91fb` | 101 / 0 |
| D20 · C8: decoded scan | S8; Disable decoded completion-message scan | H(`proposal_boundary_scans_decoded`) | equality fails: actual `Null`, expected `"tool credential boundary"` | `c8b92114a0374a909826dcc38a41354aa4e4fb5f65dbbd1075faea36051ace2a` | 101 / 0 |
| D21 · C8: redaction equality | S8; Disable original/redacted completion-message equality | H(`proposal_redaction_cannot_repair`) | equality fails: actual `Null`, expected `"tool credential boundary"` | `a8384932c6747ae2880b2a8e2733577ec7ec89ccd156a48babed36ea9d964d95` | 101 / 0 |
| D22 · C8: lossy decoding | S8; Use strict `from_slice` for both original and redacted decoders | H(`proposal_boundary_scans_decoded`) | equality fails: actual `Null`, expected `"tool credential boundary"` | `daf7fb6a50eec0da0d4c06a9cf920c1ca1124477a6c8d327938dcea81b0f73cd` | 101 / 0 |
| D23 · C1: approval | S7; Apply declaration before inserting pending candidate | H(`declaration_pending_is_not_authority`) | `s.dispatch.check_installation("fixture").is_err()` | `a39b88951df79c0a28037b23bf457d4403c1016e55a76adf37ac5a1cf54f6259` | 101 / 0 |
| D24 · C5: approval | S7; Apply class before inserting pending candidate | H(`declaration_tightening_is_operator`) | equality fails: actual `Some(MultiTenant)`, expected `Some(SinglePurpose)` | `36885718d81263c6d5c6a25de6876a45c7126dff6bcf2bd937606d616e5470f4` | 101 / 0 |
| D25 · C1: minimum | S2; Skip `validate_ad_hoc_minimum` in `check_proposal` | H(`declaration_ad_hoc_minimum_is_preserved`) | `proposal must retain TCP/22/from-any`; actual `Ok(())`, expected minimum refusal | `fc5cf3c12c3cf7b4ed687a9bdd872f59ca03bdba40fdc3c74576bcbf675cf995` | 101 / 0 |
| D26 · C8: replay minimum | S2; Skip requirements `apply_setup` proposal validation | H(`declaration_replay_refuses_ad_hoc_minimum`) | `approval dropping minimum must refuse replay` | `39463871ce97b2107f9aa2b58e31e1173df799db3e1eb6ea492f2c1ef092b71d` | 101 / 0 |
| D27 · C8: independent reader | S9; Disable independent inbound-baseline check in reader history | R(`independent_reader_refuses_approval`) | `invalid ad-hoc approval` | `d2a9a73dc3d14622e3e6595141ee57986b542694fed7362812879d284584da12` | 101 / 0 |

| Browser control / criterion | Source; one-property mutation | Expected and actual failing assertion (command B) | Mutated SHA-256 | Red / restored green exit |
|---|---|---|---|---|
| B01 · C1: proposal pause | S4; Lookup `ignored_proposal` instead of `proposal` | `before approval the exact candidate is pending, with no companion or subsequent inference continuation` | `715d8f9530f3db5a4d97784b421a90b604da357105a74e98e578dfffafb61d82` | 1 / 0 |
| B02 · C1/C8: approval result | S5; Discard receiver rejection/error and return `Ok(())` | `rejection ends loop` | `af7068732df6785c23f66750ffa65259f607742ab61daad2fcc0a3966085f01a` | 1 / 0 |
| B03 · C8: approval writer | S5; Disable `requirements_answer` ending check after writer acquisition | `only a completed durable append restores facts` | `1050aad9c60cd3299b425ffa6e0da31da2748ea35169c7b17b5d07346b0a246c` | 1 / 0 |
| B04 · C8: post-append | S5; Disable `requirements_answer` post-append ending check | `operator act also refuses ending after its awaited append` | `be4e93e502b0be21c1607d3d707f030d60eeb80769771dcd20749166fdd4aec3` | 1 / 0 |
| B05 · C8: waiter cancellation | S5; Remove the approval-sender cancellation block from session end | `session end settles the approval wait with a stopped loop outcome` | `07909271ff17e4d8c6d999a80fd3b324b2e06120c04c725146f1d7c758a44532` | 1 / 0 |
| B06 · C8: proposal writer | S5; Disable `SessionDriver::proposal` ending check after writer acquisition | `proposal writer publishes no approval card after end begins`; independently, `proposal writer settles the loop with the sessions ended outcome` | `23850f5e6bed7ceb3b9ec0cd8dca5d36d27db59b51d27bc42018f409da0446c7` | 1 / 0 |

B01's red observation was `pending=false, approved=false, completions=2`, with page outcome
`"Goal loop ended: done."`; its safety assertion executed and the summary contained one failed
case. The restored observation was an exact pending candidate, no approval, one completion
and no loop outcome before the click. B05's red observation was `end-step loop outcome: null`;
restoration produced the explicit `sessions ended` outcome without a timeout race. B02 also
failed the companion-dispatch assertion after a failed append; rejection and failed durability
both reach their intended checks. B06 unconditionally reads both worker observations after
the controlled proposal/end writer queue drains. Its red observation is
`{"outcome":null,"publications":1}`: a real late card publication and no published loop outcome.
Both named boundary assertions execute and fail within ten evaluated cases. After byte-identical
restoration and rebuild the observation is
`{"outcome":{"refused":"sessions ended"},"publications":0}` and both assertions pass.
The publication assertion is independent of the outcome assertion; no unresolved promise,
timeout sentinel, polling error or deadline is used for this boundary. The B06 success predicate
requires exit 1, ten evaluated cases, that exact red observation and both exact `[FAILED]`
assertion lines, followed by restored exit 0 and the exact green observation.
The remaining browser controls print their named safety failures within the ten-case summary.

| New wait or continuation boundary | Cancellation and post-await checks | Discriminating controls |
|---|---|---|
| Proposal waits to acquire writer | Check ending under writer before retaining/publishing; no card after end begins | B06 queues the proposal behind a held writer, starts end and releases it; reads publication count and actual loop outcome unconditionally after end returns, asserting zero publications and the named stopped outcome separately |
| Operator approval wait | End cancels sender and clears transient store candidate; rejection/failed append propagates an error | B05 directly reads stopped loop result after end; B02 removes result enforcement; D17/D18 protect concurrent tool/inference admission |
| Approval waits to acquire writer | Ending check precedes candidate revalidation and any append | B03 queues approval behind the writer; no canonical approval may appear |
| Begun approval append and committed result | A begun append completes whole; after append check ending before returning success or releasing continuation; facts alone replay | B04 suspends the real OPFS move and the committed-result point; D10 tests failed/landed moves |
| Companion dispatch after approval | Waiter and loop recheck ending; companion then passes ordinary admission and existing send stops | D19 removes the loop check; browser `requirements_dispatch` suspends immediately before it and asserts no late done; pending/replay retains no continuation |

All existing holds, no-brief acceptance, credential, caller-bound, signature and session-end
rules remain in the full suite. The declaration checks assert intended facts and admission;
they make no delivery verdict, lifecycle, installation or real create/payment claim.

### Delivery verdict and operator card

The ordinary worker/page path compares a machine with its **journaled declaration in force**.
`src/delivery.rs` evaluates typed fields and aggregates their actual results; the encrypted
store records the declaration identity, fixture observations, field results, findings and
service-associated evidence notes before publishing the card. The fixture measurements and
fixed default-credential/sshd-posture checks **do not read a live machine**. The page states
this limit beside the claim. The served worker accepts no measurements or result overrides
in an operator request; the tracer's observation injection is absent from the served build.
Without a measurement producer, a served check records unavailable evidence, never a pass.

Missing, invalid and unspecified fields prevent delivery. An observation of an empty set is
distinct from a missing or failed read. Inbound and permitted tenant material constrain what
may exist; outbound restrictions and required entries must be found. Drift checks are
presence-only at delivery. The existing strict approval boundary still preserves TCP/22/from-any
and admits no nonempty required/drift entry at this pin. The lower semantic view permits inert
check identities for comparison without granting approval or execution capability.

A standing finding says **handed over with findings**, including a lifecycle-only finding.
Every finding remains visible; its class follows its field, with services producing lifecycle
findings. Acceptance/waiver requests are refused. An approved amendment uses the existing
proposal/approval history, retains findings and makes the prior check explicitly historical.
Only a complete re-check can clear findings, after a fix or journaled amendment. Fixed lockdown
findings remain independent. Incomplete checks preserve earlier findings and any newly observed
difference still prevents Delivered. Failed appends apply
nothing and latch further writes; a landed error is recovered only by replay. Restored/imported
findings can be marked unknown through the small fixture seam and remain unknown until a complete
re-check; this does not implement recovery or import.

The check consumes lifecycle evidence, including **enabled, restart not demonstrated** and
**stopped since a restart, as approved**, beside Delivered in the card and inspection projection.
Neither note hides another finding. A restart note cannot clear a standing crash finding, and
a placing session needs every running-at-delivery service running after its last placement.
An incomplete attempt retains the last completed verdict and pending subsequent-placement
evidence through session end and encrypted reopen. Inspection publishes the last completed
check separately from the latest attempt; the card identifies the historical result, carries
its evidence notes and shows the partial measurements, including missing versus failed reads.
The historical result grants no fresh placement eligibility. Unknown findings, newly observed
differences and changed declaration/class authority still prevent a current Delivered claim.
Only a complete re-check retires the pending-placement evidence.
These are typed fixture inputs, not boot-anchor or service-manager implementations.

Application names are durably associated with the machine, unique there by exact equality,
and substituted into both application-card sentences. Names, findings and historical reports
are rendered as text and checked against current credential holdings. The card explains that
Delivered covers the declared machine state and fixed lockdown checks. Historical commands and
output carry **Checks the AI wrote — not part of Delivered**, with neutral rendering; their
success or failure changes no verdict, finding or placement eligibility. A re-check never
schedules a historical command.

The runtime companion comparison reads `spec/docs/design/declaration-witnesses-v1.json` at
specification `d029ebd9f632696bb027a22559d774d165685947`, bound `TauWeb.Declaration.bound`.
It checks all 8 named witnesses, all 144 field/presence/observation/tenancy cases (including
their multiplicities), and all 152 start projections plus 1,520 event/outcome steps through the same field
evaluation and aggregation as the production path. The refused empty-inbound trace agrees;
the admitted negative control independently asserts its inbound pass against the production
finding, every carried inbound projection, and its final delivery true against production false.
An earlier difference cannot mask a corrupted final outcome or a different recognized inbound
outcome. No assumption changes the production rule. This is evidence
about harness knowledge only, with no claim about external state, effect timing or concurrency.

Remaining owners: **twr-ggw.20** supplies concrete observation evaluation/matching;
**.34** supplies the bundle checklist/wording and concrete delivery reads; **.36** supplies
service-state/enablement composition and lifecycle demonstration; **.50** supplies re-entry
lifecycle/reboot-offer rules; **.73** supplies boot anchors and sticky lifecycle/re-anchor
evaluation. **.23** retains real placement, placing-session tracking and provider/secret
machinery. **.16/.21/.39** retain installation, create/payment and the later vendor-contract
pin move. None of those production paths is demonstrated by the fixture card.

**Implementation readings.** The local operator message is an exact-member `delivery`
request: `check`, `application`, `accept_finding` or `waive_finding`, naming a live session
and its bound machine. Application association records a name only; it installs nothing.
Incomplete attempts retain earlier findings and the last completed result rather than clearing
partly measured state; a retained verdict is explicitly historical where a demonstration is pending.
The tracer-only unknown-findings and subsequent-placement inputs supply durable fixture
metadata without implementing import, recovery or secret placement.

Delivery evidence recorded on 2026-10-26, with corrected-state controls on 2026-10-27:

| Property | Checks and deliberate controls |
|---|---|
| Presence, row semantics, required measurements, version/class guards | Shared-core host cases and all 152 companion traces; H01–H11, H27–H28, H31–H37, H41 |
| Findings, incomplete re-checks, encrypted append/replay, unknown restored state | Store host cases and ordinary card; H19–H26, H46 |
| Amendment approval/append/replay and bound-machine identity | Separate authority-boundary cases, real page approval and stale fixture refusal; H29–H30, H38–H40, H42, B01, B07 |
| Both lifecycle labels, standing crash findings and placing-session evidence | Typed core/store cases and ordinary card/inspection; H12–H18, H26, B05 |
| Exact application wording, identity and text rendering | Per-machine store cases, encrypted reader and ordinary card; H24, H43–H44, B02–B04 |
| Finding acceptance, reports and actual rendered claims | Refused acceptance/waiver; real successful and failing model `exec`, replay with no command re-execution; H45, B08–B11 |
| Session end and append publication | Stopped fixture read, actual queued writer and begun append; B06 and the existing declaration/session-end cases |
| Incomplete attempt after placement, end and encrypted reopen | Failed/missing service reads after clean or finding-bearing complete checks; separate historical/partial evidence, unknown/new findings, changed declaration/class and later complete qualification; R01–R09, R12, RB01–RB04 |
| Admitted-side individual outcomes | Unmodified corpus accepted; corrupted final delivery and blocked inbound rejected at their named step assertions; R10–R11 and separate scratch-input executions |

H01–H46 originally compiled, reached their selected host assertion with exit **101**, restored the
fixed source byte for byte and passed the same selected check with exit **0**. Browser controls
rebuild both web variants and reach the intended assertion red (exit **1**), restore the source,
rebuild and pass (exit **0**): the original B01–B10 covered all 15 delivery cases, and B11 covered the
two real-command report cases. After correction, the 11 store controls and three comparator-dependent
host controls are repeated against the corrected source; B02–B05 and B08–B10 are repeated with
all 19 delivery cases. The other 36 control records retain explicitly checked unchanged guard
sources and assertion coverage. R01–R12 independently invert the new host properties with exits
**101/0**; RB01–RB04 rebuild and exercise all four new ordinary-card regressions with exits **1/0**.
Compiler failures, empty
runs and timeouts are excluded. Each control retains its exact command, patch, assertion,
exit statuses and before/mutant/restored SHA-256 receipts.

CNF-3's separate scratch-input breaks, repeated after the comparator correction, flip one expected outcome, remove the input file and
introduce an unknown event. Each turns `declaration_companion_comparison` red at its intended
diagnostic and passes after restoration, with exits **101/0**. Outcome/event diagnostics
name `adhoc_delivered` and its step; the missing-file diagnostic names the `input-validation`
case and its input. The pinned file is unchanged. The reader also refuses malformed headers,
incomplete sweeps, extra/missing/unknown pair metadata and unknown or inconsistent admitted-side
projections. Two further scratch controls coherently corrupt admitted final delivery and inbound
outcome/projections; each is rejected at `empty_inbound_admitted` step 9 or 1 respectively and
returns green on restoration, without changing the production evaluator's assumptions.

The final serial gates cover formatting, host clippy/tests, the disk check and its failing
baseline, both wasm clippy variants, ADR-0024, served build/absence/CSP, and the complete
tracer with every selector unset. The tracer includes the existing 194 cases plus 19 delivery
cases and both loopback assertions. Final logs are tied to an unchanged source/test/build-input
receipt; the live CORS job is excluded locally. The source receipt is recorded with those logs.

### The tracer

The independent reader accepts the exact-member `operation_response` shape (`call`, lowercase-hex
`body`) and rejects extra members. `check-absence` also searches independently for the host
fixture's injected root-password literal; a planted-password test proves that row can fail.

`scripts/tracer.sh` builds both directories, then runs `tracer/`. That is a host binary, never
compiled for wasm32 and never served. It starts these fixtures on ephemeral loopback ports:

- **One fixture sshd per entry**, each with its own port, scratch directory, job directory and
  `authorized_keys`. Both can present the pinned host key. Every authentication reads that
  machine's file, never the harness or an in-memory admitted key. The tracer stands in for the
  vendor: it independently decrypts the current store, reads the approval-time index and
  derives that machine's public key with `bip32`/`bip39`, then writes exactly that OpenSSH key.
  Each `authorized_keys` file is fixture setup the tracer writes for the vendor; the
  production-dependent evidence is the admitted fingerprint for each machine.
  Each fixture records every connection,
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
  `tests/vectors/`, where they live by name (its `OPR-7`). The tracer reserves a pass through `test_allocate("passes")` when the store becomes current,
  independently derives its public key from the decrypted mnemonic and updates the fixture
  pass list for the sshds' host, expiring in an hour. It resets pace before each dialing case.

  It is not the relay product. It does not implement check 5, `DST-4`, paid-tcp-relay's address
  rule, which refuses the fixture's loopback destinations: checking a real relay's address policy
  is twr-ggw.26's (`CNF-81`, `CHN-16a`). Nor does it implement the strict path grammar of
  `WIR-1`–`WIR-3`, which is not among `CNF-87`'s items.
- **An HTTPS server for each build.** The certificate is made per run, and Chrome is told to
  accept it by its key hash alone. It logs every request line, header and body.

The held command is a finite 15-second sleep. Explicit-lock, pagehide and
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
  Stores created through the page complete seed backup, approve the fixture setup, answer both
  machine classes and press the binding controls before dispatch. Every worker restart requires
  another binding; replay restores the exposure ledger alone. The seed-record
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
    - as `binary: SSH client key, private half, raw`: the current store's derived role-0 index-0 key as a
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
  continuations, approved setup entries and their facts/cost/index/class/access, live sets and
  standing modes, installation history, acceptance history and signature refusals, with command
  bytes as hex and no seed identifier or key material.
- **The stores' contents.** It reads them with an independent reader, `tracer/src/reader.rs`.
  The reader is written from the format's text and never calls the harness's store code. It
  runs on `ring`'s PBKDF2, AES-256-GCM and SHA-256, and derives the seed's keys with the
  `bip39` and `bip32` crates.

In headless Chromium 154 a new tab hides the one before it. Ordinary visibility-only hide
retains its worker and exclusive store lease; the cases account for it.

The full run defines 194 cases.

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
| session end during box-plane intent commit | a tracer-only switch suspends the intent's OPFS move while it holds the writer; the relay and sshd observe connection end before the append is released; the append completes, the sshd receives no exec, the report is unresolved, and unlock recovers the committed call as unresolved |
| session end before job-record reads, collection and held request | suspend the read after opening its channel, start end-sessions while the writer is held, release, and check no read exec, per-call `not_read` with session-end reasons, and no appended evidence; the held wait is stopped before the writer becomes available |
| session end after job-record reads are sent, collection and held request | wait until sshd receives the running job's read exec, then hold revocation open and end sessions; relay and sshd see connection end before termination; both reads report `sessions ended while reading record`, with held `not_read: true` and collection `failed: true`; no further exec, evidence or terminal |
| cold probe at session end and revoke control, two cases | queue a cold route read behind the writer, then begin ending; only the revoke's dedicated probe is sent; separately, the revoke and its cold probe both go out while the end step remains open |
| SSH stages at session end, 21 cases | command, held request and collection each hold before the relay challenge, after dial before verdict, at SSH identification, first key exchange, authentication without rekey or pending data, rekey during authentication, and rekey after connect; the authentication-rekey cases receive an authentication banner before starting the real rekey; sockets close during the held end step, dialed sshd connections end, a pre-dial hold makes no sshd contact, and no later channel or exec is sent |
| writer admission races at session end, six cases | approved unbound command admission and an unpinned installation's signature check queue ahead of and behind the end snapshot; bound command and collectable-call admission queue ahead; every answer is the session-end journal refusal, with no connection or signature refusal record |
| completion bodies at session end, two cases | finish queues ahead of the end snapshot, or the body is already built before the final writer wait; terminal metadata remains and body handback is suppressed in both cases |
| evidence append boundaries at session end, six cases | command, held request and collection each queue evidence behind the end or suspend an already begun OPFS move; queued appends add nothing, begun appends complete, and sockets close before the held append is released; command evidence remains unresolved after unlock when its append never began |
| evidence append with rekey stalled, three cases | command, held request and collection start a real rekey after reading their record and suspend a begun evidence append; the relay withholds the key-exchange response, yet relay and sshd see connection end before the append is released, and the append still completes |
| running command at session end | while revocation is withheld, the socket closes without SSH DISCONNECT, the sent command reports unresolved with session end as its reason, and no evidence or terminal is appended; unlock reads it unresolved and collection can finish it |
| procured inference | real fetch, mint, independent metadata parsing, unresolved spend, routing and manual redirects; concurrent held completions, identifier-only mints, unlock during a held sweep, and every session end and crash/reload/sweep/expiry |
| inference no-plaintext and loopback | account and all minted key needles, planted-needle controls, OPFS/decrypted-record inspection, browser storage, messages, store inspection, request bodies and logs; CDP blocks the off-loopback negative control |
| a failed append is not applied (twr-ggw.5 AC2, `STA-3`) | that failed append failed at its `move()`, a real OPFS call; the replayed state has no record for it, and none appears after a reload and an unlock |
| acceptable weaker modes, two cases (one per build) | installation history on fixture renders unpinned with its standing label and no artifact claim; two lowering forms commit one refusal each with no intent, relay connection or SSH connection; tracer controls run harmless commands, and a host-key halt adds no mode |
| 2. a wrong host key halts (`CNF-21`, `SEC-11`) | no authentication attempt, no `exec`, no journal entry, and exactly one connection |
| 3. no pin, no contact (`CNF-23`'s no-pin case, `CHN-R4`) | no TCP connection accepted at the relay, none at the sshd, no dial, and nothing pinned afterwards |
| oversized launch (twr-ggw.71) | a 30000-byte command is refused with the composed size and limit before intent or contact: no journal entry, changed store state, relay connection or sshd exec. The same store then runs `echo ok; exit 7` and records its terminal |
| 4. the policy is enforced (`ARC-33`) | the loaded page carries the served page's policy token for token. An injected inline script raises a `script-src` violation and does not run. A `ws:` socket raises a `connect-src` violation in the page and in the worker |
| 5. the relay fixture's AUTH check is real | exactly one relay connection, and a wrongly signed AUTH gets `{"ok": false, "reason": "auth"}` and close 1008 at check 2, and nothing is dialed |
| 6. a relay key with no pass (`CNF-87`) | a bound store with no journaled pass refuses `no-credentials` after the pin lookup with no relay connection. With a journaled pass whose derived key has no pass at the relay, the harness reports `{"refused": "relay", "reason": "pass", "close_code": 1008}` |
| 7. an unrecorded destination (`CNF-87`) | the pinned machine `fixture` at `127.0.0.2`, a host the pass does not record: `destination` and 1008 |
| 8. pace (`CNF-87`) | the tracer puts the sshd's host at its window cap just before the run, so the refusal holds whatever the timing: `pace` and 1008 |
| fail closed (twr-ggw.5 AC1, `CNF-82`) | five edits to OPFS: a wrong passphrase, one byte of the envelope's salt, one byte of record 1's ciphertext, another store's record at the same number, and an envelope of version 2. For each, unlock is refused and the page offers neither Create nor Unlock; for the first two it says "wrong passphrase, or the store was modified". A create request creates nothing, a request is refused before any contact, and OPFS is byte-identical afterwards |
| reload, explicit lock, pagehide and a killed worker (twr-ggw.5 AC3, `CNF-82`) | one case each. The old worker target is gone and one new harness worker exists. The page offers Unlock alone. A request is refused with no TCP connection at the relay. After an unlock, the replayed state lists every command recorded before. Explicit lock and pagehide invoke the end step: its socket-close guarantee begins there, as the held-end cases above observe before termination. A killed worker closes its transport by termination. These three lifecycle cases catch a running command after sshd receives its `exec` and observe connection end; explicit lock and pagehide also observe the relay's WebSocket end. After unlock the command reads unresolved and sshd receives no second `exec`. Before the Lock button is pressed, text is typed into both passphrase fields and never submitted; both are empty once it is pressed |
| close without exit status (twr-ggw.7, `STA-8`) | the sshd closes without an exit status; replay preserves the unresolved call. A second command answers held, reads its finished record and records no intent or launch |
| dispositions (twr-ggw.7, `STA-24`) | the independent reader builds a destructive disposition: the request is refused before contact, with no relay connection, SSH connection or append. Replacing it with a continuing disposition admits the command and journals its terminal record |
| typed reset bars commands before contact until durable confirmation (twr-ggw.8, `STA-24`) | an independently written unresolved reset refuses a command, names its intent and makes no relay or SSH contact or append; a confirming observation permits the command |
| typed running-system disposition: pinned attempt and collection stay permitted, four cases (twr-ggw.8, `CNF-110`) | one disposed reset per continuation: commands through `run_command` obey the choice before and after collection; a bare pinned attempt reaches the relay and sshd, collects no jobs and appends no intent; the typed call stays disposed with unknown outcome and the choice stays in force |
| one writer (twr-ggw.5, `STA-1`, `STA-7`) | a second tab opens and hides the first; the first retains its worker and exclusive lease. The holder is the tab that offers Unlock while the other says it is waiting. The holder unlocks. The other says it is waiting for the store and offers neither Create nor Unlock; its worker has not read the store, runs nothing and appends nothing. Once the holder's tab closes, the other offers Unlock and unlocks the same store |
| persistent storage (twr-ggw.5 AC6, `STA-23`) | with the `persistent-storage` permission denied, then granted, through `Browser.setPermission`: `navigator.storage.persisted()` reads false, then true, and the page shows the refusal, then "Persistent storage is granted." (`persisted()` already reads true, so that load makes no request), each with the statement that this is a request, not a guarantee |
| job drop (`CNF-40`) | lock drops a several-second command after launch; `collect_jobs` waits until its observed end, reads the finished record, records no intent and launches nothing |
| held request on a dropped running command (`CNF-40`) | a separate dropped command remains alive; a held request waits until its observed end, reads the finished record, records no intent and launches nothing |
| completed drop (`CNF-54`) | the job finishes while disconnected; collection immediately reads both streams and a nonzero exit from its persistent files |
| reboot (`CNF-55`, crafted older journal with several unresolved commands) | the persistent finished record still settles; a running old-boot command reads ended without a terminal; a removed record reads missing and stays unresolved; neither is waited on |
| background stdout (`STA-20a`) | `sleep 30 & echo hi` returns promptly with output and exit 0; the fixture saw the command launch and end |
| received-command finding (`CNF-56`) | the fixture changes the recorded command during a live job; the result still settles with its exit and output, and the advisory finding survives reload and unlock; the reader reads every new shape |
| disposition collection (`CNF-110`, box-plane case) | all four continuations over a real dropped job: collection reaches the relay and sshd, launches nothing, appends evidence and no intent; disposition and disposed state stay unchanged; destructive continuations refuse commands before contact both before and after collection, continuing ones admit them |
| goal card records one session source and refuses runtime briefs and feeds | independent decryption, exact messages, the actual loop-start admission reason, no-brief refusal for all acting tools, second-goal refusal and hostile document text |
| scripted exec and done preserve untrusted typing and keep credentials off the machine | waits for the page's terminal outcome before counting; compares `setup`, `exposure_ledger`, `connection_refusals`, `dispositions`, `standing`, `typed_calls`, `mode_acceptances`, `sessions`, `installations`, `signature_refusals` and `setup_offer` after acceptance; only its six named records may be added; writes received context hex and scans bodies, SSH commands and files |
| finished error turn reports metadata without a response body | a 503 completion carries non-empty untrusted fixture text; every page message lacks both a `body` member and that text, the outcome carries only safe terminal metadata and the card labels the finished status |
| finished refused turn displays its refusal | automatic top-up on produces a finished 200 account-read refusal; the page shows the fixed refusal, no finished-status label, no unresolved marker and no response body |
| scripted schema and bound set refusals and direct harness-only job refusals | unknown tool, missing machine, out-of-set target and harness-only jobs produce no command intent or contact |
| model exec and every admitted job collect holding calls and never launch | different/identical exec bytes and every admitted job cause exactly one holding-call read each, with fixture dial spacing temporarily removed so it cannot mask a duplicate dispatch; each untrusted result reaches the next turn, which chooses done, with no new command intent or retry |
| model typed create reaches the shared barrier before operator approval | independent lost create refuses model create; the call's untrusted result reaches the next turn and done, with no new typed intent or contact |
| hostile document cannot clear a destructive disposition | the destructive stop refuses exec; the next turn receives that refusal and chooses done |
| escaped session credential in a scripted exec is refused before dispatch | minted session key returned as JSON escapes produces no SSH exec or command intent; credential-boundary refusal reaches the next turn without the unsafe call |
| pending document fetch refuses acceptance until its response settles | holds the fixture response, asserts the exact pending acceptance refusal with no records or completions, releases it, and observes the document in the first turn |
| document source commits before fetch and session end prevents a late send | suspend source append, begin end, release it, observe no GET and historical provenance |
| session end aborts an active document request without waiting for it | a withheld document response is aborted; the fixture observes its connection close and session end answers independently |
| goals stay historical after replay and failed documents supply no context | old-session refusal, fresh empty fields, redirect/non-2xx sources retained without document context |
| live signal | a self-killed command returns unresolved with ended evidence, partial output and advisory agreement; no terminal is journaled |
| collection after a bad record (crafted older journal) | a malformed first record reports its failure; the later finished job still returns its output and exit 23 and receives a terminal record |
| held request after replay (`CNF-40`) | reads only its holding call to finished, names release, records no intent and never runs afterwards; only a new request runs |
| simultaneous requests (`CNF-40`) | same-tick requests pass pre-contact admission together; exactly one records an intent and launches. The held request shares that dispatch's finished or unresolved result. Collection during the dispatch reports not read and appends no second result. This fixture temporarily removes relay dial spacing so it tests journal serialization |
| stopped held collection (`STA-20`) | while a read waits, store_state, another machine's command and collection complete. Stopping appends nothing, leaves the detached command alive and returns held |
| stopped shared-result wait (`STA-20`) | stopping a held wait leaves the independent original dispatch running to completion |
| legacy and unreadable commands (`STA-20`) | after replay, identical bytes and reads name every holding call; each has no job identity and reports why only a disposition can release it, with no contact or writes |
| held unreachable machine (`STA-20`) | no pin, no credentials, relay refusal, host-key halt, authentication failure, unreachable SSH destination and a connection lost during a record read each answer held at once with why nothing was read, without retry or intent |
| destructive replacement with unnamed command (`STA-24`) | a continuing disposition releases A, B runs, replacement of A is destructive. A held request collects B only and names the standing restriction; collection of disposed A remains permitted and never removes that restriction |
| operator binding before contact, in both builds | approved unbound command and collection journal refusals with no intent, binding or contact; page binding enumerates only row 3 for each bound machine; duplicate and malformed binds write nothing |
| bound credentials and authorized keys, in both builds | read each machine's authorized_keys for exactly its derived key; tracer commands to both `fixture` and `fixture-other` complete, authenticate with each independently derived fingerprint and record each bound session in `provenance.session`; bound served command refuses for no pin |
| exposure ledger restart, in both builds | independent reader reads the bound sets; reload/unlock preserves the ledger with no live sessions; an unbound attempt refuses, and page re-entry gives fresh session identities |
| seed-backup re-display ends bindings, in both builds | completing re-display leaves the machine unbound until the page binds again |
| no plaintext (twr-ggw.5 AC4 and AC5, `CNF-15`, `STG-10`), in each build | from the passphrase the tracer typed, the independent reader learns the wrapping key, the data key and the seed. None of these appears, raw, hex, HEX, base64 or base64url (whole, or inside a longer value at any byte alignment), in any OPFS file: the passphrase, the wrapping and data keys, the mnemonic, the entropy, the 64-byte seed, the seed identifier, and roles 0–4's private and public keys at indices 0 and 1. Local storage, session storage, IndexedDB and Cache Storage hold nothing, and no service worker is registered. Passphrase bytes appear only in exact create, unlock or re-display messages. Only the displayed seeds' mnemonic needles are exempt in the exact directed display and re-entry messages described above; other secrets remain findings in those shapes. Non-seed decrypted records are checked, retaining only canonical allocation and exposure seed associations. In the tracer build's case, the sixteen negative controls listed under "The messages" run first, through the same guarded serializer and the same check, and each must be reported for its own reason. Four seed message controls run for the final seed and each collision-control mnemonic in each build: phrase, array, wrong-direction re-entry and binary. Further controls report a passphrase and a data key in the re-entry shape, an earlier store's seed identifier, and mnemonic and passphrase console property names. Fields are empty after every submit. The HTTPS fixtures' requests and the console hold none |

For case 6's relay refusal and cases 7–8 the relay fixture accepted exactly one connection, dialed nothing, and its log
shows no frame from the client after the refusal but the close; the sshd saw no connection.
Case 1 also reads the order from the relay fixture's log: challenge sent, AUTH received,
accepted, dial, OK sent, then the first forwarded byte.

How the twr-ggw.5 AC3 cases cause their event, where headless Chromium could not give the real one:

- **Page hide** is two events, each caught with a command in flight:
  - the browser's own `visibilitychange` to hidden, from opening a second tab, preserves the eligible worker and scheduled command; the page
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

`check-absence dist/served` includes the host fixture's root-password row as well as fixture
keys, pins and test switches; host tests plant that password to exercise the refusal.

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

- `check-absence` reads every byte of the directory. It fails on any fixture-derived key, private or
  public half derived from fixed fixture mnemonics, roles 0 and 3 at indices 0 and 1, as raw
  bytes, hex, HEX, base64 or base64url (and the SSH public half in OpenSSH encoding), on the pin
  source's pins and marker, and on the test switches' names (`fail_append` among them). Run on
  `dist/tracer`, it fails on pins, the marker and remaining switches. A host test plants a
  derived key and proves that the key rows still fail.
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
| | `cargo test --locked` | procured-inference host invariants, post-append end admission, late terminals and preservation of the committed mint report through `inference::infer`, per-session top-up reads and independent fixture/reader checks; runs `build.rs`, so the gates above run here, and the `[session]` fixtures (`CNF-88`'s build fixtures); the relay matrix, `CNF-87`'s fixture half; the seed's tests, `CNF-83`'s derivation tests and `CNF-13`'s tests; the local store's, `CNF-82`'s and `CNF-15`'s host half (below); dispatch and journal recovery for `CNF-29`'s box-plane case, including the unresolved-command hold before contact and at append, identical bytes and reads, no writes on refusal, replay, every holding call and other-machine independence, `CNF-30`, `CNF-39` and `STA-24` dispositions; job classification, channel deliveries, unresolved evidence, append failures, replay and all four dispositions, plus real-shell signals, high exit codes, missing and unreadable record files, NUL-corrupted scalars, exact scalar forms, the reader and replay exit ceiling, incomplete unreadable entries, owned-child cleanup, recycled PIDs, stale fixture groups, exact sentinel matching, drop, duplicate-id, boot, output and cross-store identity tests for `CNF-40`'s dropped command not re-run, waiting on its job record, `CNF-54`–`CNF-56` and `CNF-110`'s collection case; and allocation's, `CNF-72`'s tests and the companion comparison against the allocation witness file (ADR-0032), with `CNF-3`'s three breaks as its unit tests; atomic setup approval and indices, ceremony gates, unanswered classes, maintained access/profile, binding prerequisites and acts, exclusive live bindings, session credential inspection, durable exposure/refusal records, caller-bound adapter admission before approval, ceremony and Restore restrictions, independent sshd rejection of uninstalled and other-machine keys, provenance resolution and replay; typed fixture operations through the adapter's send path at every append kill boundary and a suspended record/send boundary, the resource barrier across both planes, all requester provenances through production command admission/append, disposition reach/end/replacement, exact collectable calls and committed job evidence in the 20-row matrix, unsupported typed-record replay refusals, and the dispatch companion's production-path stage1 comparison and complete vocabulary negative controls; acceptable weaker mode acceptance windows and atomicity, restatement through adapter and direct store admission, trust-display completeness, both lowering forms, durable refusal records, old shapes and independently parsed acceptance windows |
| `web` (the job is `CNF-1` for the browser build) | `cargo clippy -D warnings` on wasm32, the served and the tracer build | `CNF-2`, on the new target |
| | `scripts/check-adr-0024.sh` | spec ADR-0024's build check |
| | `scripts/build-web.sh served`, then `tracer check-absence dist/served` | the served build (`ARC-32`) carries no fixture-derived key, pin source or test switch |
| | `tracer check-csp dist/served` | `ARC-33`'s policy, exactly |
| | `scripts/tracer.sh`, in headless Chrome | procured-inference browser cases, crash/reload/sweep/expiry, held completion and sweep responses, and loopback enforcement; `CNF-30`, `CNF-21`, `CNF-23`'s no-pin case and `ARC-33`, as above, the relay refusals of `CNF-87` a correct client meets, and the local store's `CNF-82` and `CNF-15` in the browser; seed-backup display, hiding, full re-entry/skip, interruptions, re-display and custody in both builds (`CNF-44`, `CNF-82`), and integrated allocation refusals, completions and failed OPFS appends (`CNF-72`); `CNF-40`'s dropped command not re-run, waiting on its job record, `CNF-54`–`CNF-56`, `STA-20a` and `CNF-110`'s box-plane collection case; unresolved-command hold, concurrent admission and shared results, stopped waits with the writer free, unreachable answers and destructive replacement; typed reset confirmation and every continuation on the real pinned connection; setup batch costs and indices, unanswered class controls, Not sure and No, maintained access and non-operator boundaries in both builds; binding, derived client authentication, machine authorized_keys, ledger restart and re-display in both builds; acceptable weaker mode display and two pre-contact lowering refusals in both builds, with completed controls and unchanged modes at a host-key halt; these browser cases supply the pinned SSH attempt evidence, which has no host form |

The `build` job's `cargo test --locked` also gates mode acceptance windows and atomicity,
restatement through both typed admission paths, trust-display completeness, durable lowering
refusals, old shapes, and independently parsed acceptance windows. The `web` job runs the
same pre-contact lowering path in both builds; host tests alone never compile that path.

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
`TAU_TRACER_SETUP_CASE`, `TAU_TRACER_SEED_CASE` and `TAU_TRACER_HOLD_CASE` unset and runs all 194 cases. `TAU_TRACER_GOALS`, `TAU_TRACER_GOAL_CASE`, `TAU_TRACER_MODE_CASE`, `TAU_TRACER_INFERENCE`, `TAU_TRACER_INFERENCE_PHASE`,
`TAU_TRACER_INFERENCE_END` and `TAU_TRACER_SESSION_END` must also be unset. The focused
`session-end`, `sent-reads` and `command-intent` inference phases exercise the corresponding
session-end boundaries. `TAU_TRACER_SESSION_END` selects comma-separated case-name fragments
within the `session-end` phase; a fragment prefixed with `=` selects an exact case name.

The weaker-mode boundaries were mutation-checked on 2026-10-23 with Rust 1.97.1.
M1–M7, M12 and M14 retain their evidence from that date. M8–M11 and M13 were rerun,
and M15–M16 added, on 2026-10-23 with the current lowering regression cases.
Each command ran in the foreground, with its output redirected to a log and its exit status
checked. Only the named production change was present for each failing test. Before each
identical passing rerun, the saved source bytes were restored and compared byte for byte.
For the browser command, wasm-bindgen 0.2.127, Chromium 154 and the wasm32 clang/llvm-ar
were configured as described above; `TMPDIR` was `/var/tmp`.

**Weaker modes M1** — Disabled the earlier-exposure refusal in Store::check_binding_modes. File: `src/store.rs`. Exact command:

```sh
TMPDIR=/var/tmp nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web mode_acceptance_windows_and_atomic_binding
```

Red exit: 101. Failing test, assertion location and panic output:

```text
thread 'store::mode_tests::mode_acceptance_windows_and_atomic_binding' (3292280) panicked at src/store/mode_tests.rs:129:9:
late installation acceptance
```

Restored green rerun of the identical command: exit 0.

```text
test store::mode_tests::mode_acceptance_windows_and_atomic_binding ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 180 filtered out; finished in 0.46s
```

**Weaker modes M2** — Disabled the first-command window check in Store::check_acceptance. File: `src/store.rs`. Exact command:

```sh
TMPDIR=/var/tmp nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web mode_acceptance_windows_and_atomic_binding
```

Red exit: 101. Failing test, assertion location and panic output:

```text
thread 'store::mode_tests::mode_acceptance_windows_and_atomic_binding' (3293827) panicked at src/store/mode_tests.rs:140:9:
late conduct acceptance
```

Restored green rerun of the identical command: exit 0.

```text
test store::mode_tests::mode_acceptance_windows_and_atomic_binding ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 180 filtered out; finished in 0.45s
```

**Weaker modes M3** — Made the unbound refusal in Store::connection_session journal a conduct acceptance. File: `src/store.rs`. Exact command:

```sh
TMPDIR=/var/tmp nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web modes_never_entered_by_failing
```

Red exit: 101. Failing test, assertion location and panic output:

```text
thread 'store::mode_tests::modes_never_entered_by_failing' (3295380) panicked at src/store/mode_tests.rs:581:9:
assertion `left == right` failed: failure journaled a mode
  left: [Object {"exposure": Object {"accepted_modes": Array [String("no_artifact_pin")], "bound_set": Array [Object {"identity": Object {"derivation_version": Number(1), "family": String("machines"), "index": Number(0), "seed": String("4db80813e20ec4f97c9d7afc330b5aee4bdab6c15c3d3ca9e28e6387bb9f6d9a")}, "machine": String("fixture")}], "session": String("session-5")}}, Object {"mode_acceptance": Object {"mode": String("no_brief"), "session": String("session-5")}}, Object {"mode_acceptance": Object {"mode": String("no_brief"), "session": String("session-5")}}]
 right: [Object {"exposure": Object {"accepted_modes": Array [String("no_artifact_pin")], "bound_set": Array [Object {"identity": Object {"derivation_version": Number(1), "family": String("machines"), "index": Number(0), "seed": String("4db80813e20ec4f97c9d7afc330b5aee4bdab6c15c3d3ca9e28e6387bb9f6d9a")}, "machine": String("fixture")}], "session": String("session-5")}}, Object {"mode_acceptance": Object {"mode": String("no_brief"), "session": String("session-5")}}]
```

Restored green rerun of the identical command: exit 0.

```text
test store::mode_tests::modes_never_entered_by_failing ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 180 filtered out; finished in 0.21s
```

**Weaker modes M4** — Made Local::report claim the bundled bootstrap hash for an unpinned installation. File: `src/store.rs`. Exact command:

```sh
TMPDIR=/var/tmp nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web mode_trust_display_lists_every_mode_without_artifact_claims
```

Red exit: 101. Failing test, assertion location and panic output:

```text
thread 'store::mode_tests::mode_trust_display_lists_every_mode_without_artifact_claims' (3296762) panicked at src/store/mode_tests.rs:202:9:
assertion `left == right` failed
  left: Array [Object {"installation": String("unpinned"), "machine": String("fixture"), "sha256": String("41f73e3cf5fa919b8aa5ca6b30dc48f0da2720776d7423e2a7748211456fe081")}]
 right: Array [Object {"installation": String("unpinned"), "machine": String("fixture")}]
```

Restored green rerun of the identical command: exit 0.

```text
test store::mode_tests::mode_trust_display_lists_every_mode_without_artifact_claims ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 180 filtered out; finished in 0.16s
```

**Weaker modes M5** — Dropped the no-brief mode from Store::standing_modes. File: `src/store.rs`. Exact command:

```sh
TMPDIR=/var/tmp nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web mode_restatement_uses_target_set_at_destroy_and_reinstall
```

Red exit: 101. Failing test, assertion location and panic output:

```text
thread 'store::mode_tests::mode_restatement_uses_target_set_at_destroy_and_reinstall' (3298243) panicked at src/store/mode_tests.rs:255:13:
adapter bypassed restatement
```

Restored green rerun of the identical command: exit 0.

```text
test store::mode_tests::mode_restatement_uses_target_set_at_destroy_and_reinstall ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 180 filtered out; finished in 0.90s
```

**Weaker modes M6** — Bypassed the restatement hook for destroy in Store::check_operation. File: `src/store.rs`. Exact command:

```sh
TMPDIR=/var/tmp nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web mode_restatement_uses_target_set_at_destroy_and_reinstall
```

Red exit: 101. Failing test, assertion location and panic output:

```text
thread 'store::mode_tests::mode_restatement_uses_target_set_at_destroy_and_reinstall' (3299683) panicked at src/store/mode_tests.rs:255:13:
adapter bypassed restatement
```

Restored green rerun of the identical command: exit 0.

```text
test store::mode_tests::mode_restatement_uses_target_set_at_destroy_and_reinstall ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 180 filtered out; finished in 0.88s
```

**Weaker modes M7** — Omitted no-brief from the trust display in Store::sessions. File: `src/store.rs`. Exact command:

```sh
TMPDIR=/var/tmp nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web mode_trust_display_lists_every_mode_without_artifact_claims
```

Red exit: 101. Failing test, assertion location and panic output:

```text
thread 'store::mode_tests::mode_trust_display_lists_every_mode_without_artifact_claims' (3301419) panicked at src/store/mode_tests.rs:198:9:
assertion `left == right` failed: trust display completeness
  left: Array [String("An installation with no artifact pin")]
 right: Array [String("An installation with no artifact pin"), String("Acting on a goal with no brief")]
```

Restored green rerun of the identical command: exit 0.

```text
test store::mode_tests::mode_trust_display_lists_every_mode_without_artifact_claims ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 180 filtered out; finished in 0.18s
```

**Weaker modes M8** — Removed signature-lowering admission from the host `Journal::append`. File: `src/store.rs`. Exact command:

```sh
TMPDIR=/var/tmp nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web mode_lowering_refuses_each_form_before_intent_and_records_it
```

Red exit: 101. Failing test, assertion location and panic output:

```text
thread 'store::mode_tests::mode_lowering_refuses_each_form_before_intent_and_records_it' (3467239) panicked at src/store/mode_tests.rs:562:9:
assertion `left == right` failed: no intent was journaled
  left: [(7, Entry { machine: "fixture", command: [101, 99, 104, 111, 32, 39, 83, 105, 103, 76, 101, 118, 101, 108, 32, 61, 32, 78, 101, 118, 101, 114, 39, 32, 62, 62, 32, 47, 101, 116, 99, 47, 112, 97, 99, 109, 97, 110, 46, 99, 111, 110, 102], provenance: Some(CommandProvenance { target: Entry("fixture"), session: Some("session-5"), requester: Session }) })]
 right: []
```

Saved source bytes restored and compared byte for byte. Green rerun of the identical command:
exit 0.

```text
test store::mode_tests::mode_lowering_refuses_each_form_before_intent_and_records_it ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 180 filtered out; finished in 4.08s
```

**Weaker modes M9** — Disabled the signature-level-of-never form in `lowering`. File: `src/modes.rs`. Exact command:

```sh
TMPDIR=/var/tmp nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web mode_lowering_refuses_each_form_before_intent_and_records_it
```

Red exit: 101. Failing test, assertion location and panic output:

```text
thread 'store::mode_tests::mode_lowering_refuses_each_form_before_intent_and_records_it' (3469240) panicked at src/store/mode_tests.rs:562:9:
assertion `left == right` failed: no intent was journaled
  left: [(7, Entry { machine: "fixture", command: [101, 99, 104, 111, 32, 39, 83, 105, 103, 76, 101, 118, 101, 108, 32, 61, 32, 78, 101, 118, 101, 114, 39, 32, 62, 62, 32, 47, 101, 116, 99, 47, 112, 97, 99, 109, 97, 110, 46, 99, 111, 110, 102], provenance: Some(CommandProvenance { target: Entry("fixture"), session: Some("session-5"), requester: Session }) })]
 right: []
```

Saved source bytes restored and compared byte for byte. Green rerun of the identical command:
exit 0.

```text
test store::mode_tests::mode_lowering_refuses_each_form_before_intent_and_records_it ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 180 filtered out; finished in 4.27s
```

**Weaker modes M10** — Disabled the untrusted-repository form in `lowering`. File: `src/modes.rs`. Exact command:

```sh
TMPDIR=/var/tmp nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web mode_lowering_refuses_each_form_before_intent_and_records_it
```

Red exit: 101. Failing test, assertion location and panic output:

```text
thread 'store::mode_tests::mode_lowering_refuses_each_form_before_intent_and_records_it' (3470818) panicked at src/store/mode_tests.rs:562:9:
assertion `left == right` failed: no intent was journaled
  left: [(12, Entry { machine: "fixture", command: [83, 105, 103, 76, 101, 118, 101, 108, 32, 61, 32, 79, 112, 116, 105, 111, 110, 97, 108, 32, 84, 114, 117, 115, 116, 65, 108, 108], provenance: Some(CommandProvenance { target: Entry("fixture"), session: Some("session-5"), requester: Session }) })]
 right: []
```

Saved source bytes restored and compared byte for byte. Green rerun of the identical command:
exit 0.

```text
test store::mode_tests::mode_lowering_refuses_each_form_before_intent_and_records_it ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 180 filtered out; finished in 4.21s
```

**Weaker modes M11** — Removed the refusal record commit in `Journal::check_signature`. File: `src/store.rs`. Exact command:

```sh
TMPDIR=/var/tmp nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web mode_lowering_refuses_each_form_before_intent_and_records_it
```

Red exit: 101. Failing test, assertion location and panic output:

```text
thread 'store::mode_tests::mode_lowering_refuses_each_form_before_intent_and_records_it' (3472824) panicked at src/store/mode_tests.rs:573:9:
assertion `left == right` failed: exactly one refusal record
  left: 7
 right: 8
```

Saved source bytes restored and compared byte for byte. Green rerun of the identical command:
exit 0.

```text
test store::mode_tests::mode_lowering_refuses_each_form_before_intent_and_records_it ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 180 filtered out; finished in 4.15s
```

**Weaker modes M12** — Removed the pre-contact signature check from run_command; the append check remained. File: `src/harness/run.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTUP_TOOLCHAIN=1.97.1 CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-Clinker-features=-lld CHROME=<chromium> TAU_TRACER_MODE_CASE=all bash scripts/tracer.sh
```

Red exit: 1. Both browser cases failed the assertion at
`tracer/src/mode_cases.rs:120`; the served case also failed the record assertions at
`tracer/src/mode_cases.rs:129` and `tracer/src/mode_cases.rs:143`. These are tracer assertions,
not Rust panics. The append guard remained in place and prevented an intent in the tracer build.

```text
== acceptable weaker modes and pre-contact signature refusal: tracer
   [FAILED] lowering refused before relay or SSH contact and exec
   [FAILED] lowering refused before relay or SSH contact and exec
== acceptable weaker modes and pre-contact signature refusal: served
   [FAILED] lowering refused before relay or SSH contact and exec
   [FAILED] exactly one refusal, no intent, unchanged modes
   [FAILED] independent reader reads the exact refusal record
   [FAILED] lowering refused before relay or SSH contact and exec
   [FAILED] exactly one refusal, no intent, unchanged modes
   [FAILED] independent reader reads the exact refusal record
   FAIL acceptable weaker modes and pre-contact signature refusal: tracer: lowering refused before relay or SSH contact and exec; lowering refused before relay or SSH contact and exec
   FAIL acceptable weaker modes and pre-contact signature refusal: served: lowering refused before relay or SSH contact and exec; exactly one refusal, no intent, unchanged modes; independent reader reads the exact refusal record; lowering refused before relay or SSH contact and exec; exactly one refusal, no intent, unchanged modes; independent reader reads the exact refusal record
FAIL: tracer cases failed: acceptable weaker modes and pre-contact signature refusal: tracer, acceptable weaker modes and pre-contact signature refusal: served
```

Restored green rerun: exit 0, including both no-contact assertions:

```text
== acceptable weaker modes and pre-contact signature refusal: tracer
   [ok] lowering refused before relay or SSH contact and exec
   [ok] lowering refused before relay or SSH contact and exec
== acceptable weaker modes and pre-contact signature refusal: served
   [ok] lowering refused before relay or SSH contact and exec
   [ok] lowering refused before relay or SSH contact and exec
TRACER PASS
```

**Weaker modes M13** — Substituted the earlier matcher without quoted-token handling, keeping all current cases. File: `src/modes.rs`. Exact command:

```sh
TMPDIR=/var/tmp nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web mode_lowering_refuses_each_form_before_intent_and_records_it
```

Red exit: 101. Failing test, assertion location and panic output:

```text
thread 'store::mode_tests::mode_lowering_refuses_each_form_before_intent_and_records_it' (3474409) panicked at src/store/mode_tests.rs:562:9:
assertion `left == right` failed: no intent was journaled
  left: [(16, Entry { machine: "fixture", command: [101, 99, 104, 111, 32, 83, 105, 103, 76, 101, 118, 101, 108, 32, 61, 32, 39, 78, 101, 118, 101, 114, 39, 32, 62, 32, 47, 101, 116, 99, 47, 112, 97, 99, 109, 97, 110, 46, 99, 111, 110, 102], provenance: Some(CommandProvenance { target: Entry("fixture"), session: Some("session-5"), requester: Session }) })]
 right: []
```

Saved source bytes restored and compared byte for byte. Green rerun of the identical command:
exit 0.

```text
test store::mode_tests::mode_lowering_refuses_each_form_before_intent_and_records_it ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 180 filtered out; finished in 4.25s
```

**Weaker modes M14** — Disabled the later-exposure acceptance check in ModeHistory::check_and_apply. File: `tracer/src/reader.rs`. Exact command:

```sh
TMPDIR=/var/tmp nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tracer weaker_mode_records_and_windows_are_independently_checked
```

Red exit: 101. Failing test, assertion location and panic output:

```text
thread 'reader::tests::weaker_mode_records_and_windows_are_independently_checked' (3310490) panicked at tracer/src/reader.rs:1200:18:
independent reader must refuse
```

Restored green rerun of the identical command: exit 0.

```text
test reader::tests::weaker_mode_records_and_windows_are_independently_checked ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 60 filtered out; finished in 86.96s
```

**Weaker modes M15** — Made `check_signature` refuse whenever any machine has the installation mode, irrespective of the target. File: `src/store.rs`. The `fixture-other` control runs while `fixture` has both modes standing. Exact command:

```sh
TMPDIR=/var/tmp nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web mode_lowering_refuses_each_form_before_intent_and_records_it
```

Red exit: 101. Failing test, assertion location and panic output:

```text
thread 'store::mode_tests::mode_lowering_refuses_each_form_before_intent_and_records_it' (3476557) panicked at src/store/mode_tests.rs:633:9:
assertion failed: block_on(store.append(&command("fixture-other", None, bytes),
            &approval())).is_ok()
```

Saved source bytes restored and compared byte for byte. Green rerun of the identical command:
exit 0.

```text
test store::mode_tests::mode_lowering_refuses_each_form_before_intent_and_records_it ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 180 filtered out; finished in 4.19s
```

**Weaker modes M16** — Substituted the matcher that stops its value scan at punctuation and consumes later directives, keeping the new repeated-assignment and shell-syntax cases. File: `src/modes.rs`. Exact command:

```sh
TMPDIR=/var/tmp nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web mode_lowering_refuses_each_form_before_intent_and_records_it
```

Red exit: 101. Failing test, assertion location and panic output:

```text
thread 'store::mode_tests::mode_lowering_refuses_each_form_before_intent_and_records_it' (3478461) panicked at src/store/mode_tests.rs:562:9:
assertion `left == right` failed: no intent was journaled
  left: [(25, Entry { machine: "fixture", command: [112, 114, 105, 110, 116, 102, 32, 39, 37, 115, 92, 110, 39, 32, 39, 83, 105, 103, 76, 101, 118, 101, 108, 32, 61, 32, 82, 101, 113, 117, 105, 114, 101, 100, 39, 32, 39, 83, 105, 103, 76, 101, 118, 101, 108, 32, 61, 32, 78, 101, 118, 101, 114, 39], provenance: Some(CommandProvenance { target: Entry("fixture"), session: Some("session-5"), requester: Session }) })]
 right: []
```

Saved source bytes restored and compared byte for byte. Green rerun of the identical command:
exit 0.

```text
test store::mode_tests::mode_lowering_refuses_each_form_before_intent_and_records_it ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 180 filtered out; finished in 3.79s
```

Binding admission and fixture authentication were mutation-checked on 2026-10-23 with Rust
1.97.1. Each command below ran in the foreground, first with only the stated production
mutation and then after restoring the saved source bytes and comparing them byte-for-byte.
Every M1–M15 red run exited 101; every restored rerun of the identical command exited 0. Source
locations below are those reported by the mutated run. The values are from disposable test
stores. M1 exercises both missing prerequisites; M7 carries no approval.

**M1** — removed `Dispatch::check_binding` from `src/store.rs`, `Store::bind`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web binding_act_requires_journaled_
```

Failed test `store::binding_tests::binding_act_requires_journaled_class` at `src/store/binding_tests.rs:48:5`:

```text
assertion `left == right` failed
  left: Ok("session-3")
 right: Err("ClassMissing")
```

Failed test `store::binding_tests::binding_act_requires_journaled_access` at `src/store/binding_tests.rs:83:5`:

```text
assertion `left == right` failed
  left: Ok("session-4")
 right: Err("AccessMissing")
```

Restored green rerun: exit 0.

**M2** — added the seed as a row-15 holding in `src/store.rs`, `Store::bind`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web session_inspection_enumerates_only_its_machine_client_key
```

Failed test `store::binding_tests::session_inspection_enumerates_only_its_machine_client_key` at `src/store/binding_tests.rs:96:5`:

```text
assertion `left == right` failed
  left: Object {"bound_set": Array [String("fixture-other")], "given": Array [Object {"machine": String("fixture-other"), "row": Number(3)}, Object {"machine": String("fixture-other"), "row": Number(15)}], "identity": String("session-5")}
 right: Object {"bound_set": Array [String("fixture-other")], "given": Array [Object {"machine": String("fixture-other"), "row": Number(3)}], "identity": String("session-5")}
```

Restored green rerun: exit 0.

**M3** — added machine `fixture`'s client key to `fixture-other`'s session in `src/store.rs`, `Store::bind`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web session_inspection_enumerates_only_its_machine_client_key
```

Failed test `store::binding_tests::session_inspection_enumerates_only_its_machine_client_key` at `src/store/binding_tests.rs:96:5`:

```text
assertion `left == right` failed
  left: Object {"bound_set": Array [String("fixture-other")], "given": Array [Object {"machine": String("fixture-other"), "row": Number(3)}, Object {"machine": String("fixture"), "row": Number(3)}], "identity": String("session-5")}
 right: Object {"bound_set": Array [String("fixture-other")], "given": Array [Object {"machine": String("fixture-other"), "row": Number(3)}], "identity": String("session-5")}
```

Restored green rerun: exit 0.

**M4** — made `src/store.rs`, `Store::connection_session` bind and return a session on an unbound attempt. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web unbound_attempt_records_refusal_and_never_binds
```

Failed test `store::binding_tests::unbound_attempt_records_refusal_and_never_binds` at `src/store/binding_tests.rs:116:5`:

```text
assertion failed: matches!(block_on(store.connection_session("fixture")),
    Err(AdmissionRefusal::Unbound))
```

Restored green rerun: exit 0.

**M5** — removed the refusal append and projection update from `src/store.rs`, `Store::connection_session`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web unbound_attempt_records_refusal_and_never_binds
```

Failed test `store::binding_tests::unbound_attempt_records_refusal_and_never_binds` at `src/store/binding_tests.rs:123:5`:

```text
assertion `left == right` failed
  left: 5
 right: 6
```

Restored green rerun: exit 0.

**M6** — disabled the live-binding exclusivity refusal in `src/store.rs`, `Store::bind`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web a_machine_has_at_most_one_live_binding
```

Failed test `store::binding_tests::a_machine_has_at_most_one_live_binding` at `src/store/binding_tests.rs:153:5`:

```text
assertion `left == right` failed
  left: Ok("session-6")
 right: Err("already bound")
```

Restored green rerun: exit 0.

**M7** — removed bound-set admission from both `Vendor::run` and `Vendor::status` in `src/dispatch/fixture.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web adapter_refuses_outside_bound_set_before_any_approval
```

Failed test `store::binding_tests::adapter_refuses_outside_bound_set_before_any_approval` at `src/store/binding_tests.rs:206:9`:

```text
assertion `left == right` failed: before any approval screen renders
  left: Err(Policy(Facts))
 right: Err(Policy(BoundSet))
```

Restored green rerun: exit 0.

**M8** — removed the exposure commit, retaining its in-memory application, in `src/store.rs`, `Store::bind`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web exposure_replays_but_live_sessions_do_not_and_failed_append_binds_nothing
```

Failed test `store::binding_tests::exposure_replays_but_live_sessions_do_not_and_failed_append_binds_nothing` at `src/store/binding_tests.rs:167:5`:

```text
assertion `left == right` failed
  left: []
 right: [Exposure { session: "session-5", bound_set: [BoundMachine { machine: "fixture", identity: Identity { seed: "9ad53acce03485b410fa5c691d15a590666cce8e5281698f68e7671b25e34574", derivation_version: 1, family: Machines, index: 0 } }] }]
```

Restored green rerun: exit 0.

**M9** — ignored exposure events in `src/store.rs`, `Store::replay`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web exposure_replays_but_live_sessions_do_not_and_failed_append_binds_nothing
```

Failed test `store::binding_tests::exposure_replays_but_live_sessions_do_not_and_failed_append_binds_nothing` at `src/store/binding_tests.rs:167:5`:

```text
assertion `left == right` failed
  left: []
 right: [Exposure { session: "session-5", bound_set: [BoundMachine { machine: "fixture", identity: Identity { seed: "94bd47292efc550ac7fa9ceec55eb7d0357bc28a1e87b7abad22f0d7aa641e79", derivation_version: 1, family: Machines, index: 0 } }] }]
```

Restored green rerun: exit 0.

**M10a** — removed the `BackupMissing` ceremony refusal from `src/allocation.rs`, `Metadata::issue`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web binding_uses_ceremony_allocated_and_restored_listed_identities_only
```

Failed test `store::binding_tests::binding_uses_ceremony_allocated_and_restored_listed_identities_only` at `src/store/binding_tests.rs:350:5`:

```text
assertion failed: block_on(store.approve_setup(fixture_setup())).is_err()
```

Restored green rerun: exit 0.

**M10b** — derived at computed index 0 instead of the entry's journaled index in `src/store.rs`, `Store::bind`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web binding_uses_ceremony_allocated_and_restored_listed_identities_only
```

Failed test `store::binding_tests::binding_uses_ceremony_allocated_and_restored_listed_identities_only` at `src/store/binding_tests.rs:370:13`:

```text
assertion `left == right` failed
  left: [110, 195, 50, 247, 247, 46, 72, 55, 253, 132, 59, 80, 6, 13, 20, 8, 185, 29, 212, 177, 215, 35, 141, 233, 212, 209, 223, 213, 68, 32, 230, 119]
 right: [237, 132, 135, 33, 70, 30, 66, 75, 23, 47, 141, 122, 210, 128, 79, 10, 158, 1, 70, 32, 149, 226, 145, 130, 130, 33, 156, 155, 2, 110, 8, 18]
```

Restored green rerun: exit 0.

**M11** — removed the `Restored` allocation refusal from `src/allocation.rs`, `Metadata::issue`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web binding_uses_ceremony_allocated_and_restored_listed_identities_only
```

Failed test `store::binding_tests::binding_uses_ceremony_allocated_and_restored_listed_identities_only` at `src/store/binding_tests.rs:409:17`:

```text
assertion `left == right` failed
  left: Ok(Identity { seed: "6d4c2ca84dc82b729fa091d71b70bbbc491cc494a99a6a89c1997cd429c3881d", derivation_version: 1, family: Machines, index: 2 })
 right: Err("a restored seed allocates nothing until a Replace")
```

Restored green rerun: exit 0.

**M12** — made `SshSession::admit` accept every key in `tracer/src/fixtures.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tracer sshd_refuses_uninstalled_and_other_machine_keys_without_harness
```

Failed test `fixtures::binding_tests::sshd_refuses_uninstalled_and_other_machine_keys_without_harness` at `tracer/src/fixtures.rs:1172:13`:

```text
assertion `left == right` failed: fixture sshd must refuse an uninstalled or another machine's key
  left: true
 right: false
```

Removing the key-file check moves this assertion from restored line 1179 to mutated line 1172.

Restored green rerun: exit 0.

**M13** — returned success for every non-session requester, regardless of caller, in `src/store.rs`, `Store::check_bound_operation`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web adapter_refuses_caller_present_requester_relabelling
```

Failed test `store::binding_tests::adapter_refuses_caller_present_requester_relabelling` at `src/store/binding_tests.rs:269:9`:

```text
assertion `left == right` failed: caller-present Operator cannot bypass the bound set
  left: Ok(6)
 right: Err(Policy(BoundSet))
```

Restored green rerun: exit 0.

**M14** — removed allocation-entry membership checking, retaining the current-seed check, in `src/store.rs`, `Store::bind`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web binding_uses_ceremony_allocated_and_restored_listed_identities_only
```

Failed test `store::binding_tests::binding_uses_ceremony_allocated_and_restored_listed_identities_only` at `src/store/binding_tests.rs:338:5`:

```text
assertion `left == right` failed
  left: Ok("session-6")
 right: Err("binding identity is not listed under the current seed")
```

Restored green rerun: exit 0.

**M15** — removed allocation-entry membership checking, retaining the current-seed check, in `src/store.rs`, `Store::replay_exposure`. Exact command:

```sh
nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web replay_refuses_exposure_for_an_unlisted_identity
```

Failed test `store::binding_tests::replay_refuses_exposure_for_an_unlisted_identity` at `src/store/binding_tests.rs:325:6`:

```text
unlisted exposure must refuse replay
```

Restored green rerun: exit 0.

The second-machine browser check was also mutation-checked on 2026-10-23. In
`src/harness/run.rs`, `run_command`, only the `fixture-other` command whose bytes were
`true # bound credential witness` was made to record `wrong-session` in
`provenance.session`, while authentication and completion were unchanged. With Rust 1.97.1,
wasm-bindgen 0.2.127, Chromium 154 and the unwrapped wasm32 clang/llvm-ar configured as above,
the exact red command was:

```sh
nix shell nixpkgs#gcc -c env RUSTUP_TOOLCHAIN=1.97.1 CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-Clinker-features=-lld TAU_TRACER_SETUP_CASE=existing bash scripts/tracer.sh
```

It exited 1, naming only `bound credentials and machine authorized keys: tracer`, at the
assertion in `tracer/src/binding_cases.rs:291`:

```text
[FAILED] fixture-other: derived fingerprint authenticates and intent names the bound session
FAIL: tracer cases failed: bound credentials and machine authorized keys: tracer
```

This is a tracer assertion, not a Rust panic. The production source was restored from its
saved copy and compared byte-for-byte. With all three focus variables unset, the restored
full `CHROME=<chromium> scripts/tracer.sh` gate reruns that same case; it exited 0 with
`TRACER PASS` after all 106 cases.

### Procured inference mutation evidence (I1–I53)

On 2026-10-24, each mutation below changed production code, or the named tracer check. Every
red command ran in the foreground with output redirected to a log. Saved source bytes were
restored and compared byte for byte before the same command ran green. The initial I1–I24
record contains 32 red/green pairs: I10 removes six fields, I12 checks both an unresolved barrier and a held completion
lock, I18 uses both wrong sources, and I22 checks both a served export and the planted needles.
The full gate follows these focused checks with every selector unset.

The first top-up-driver and post-failure-route mutants stayed green. The tests were strengthened
to observe mint preparation and the next request's route, then rerun as recorded below. The
cut-off case explicitly awaits a sweep invocation after unlock so its count assertion observes
the duplicate transmission before the independent reader can refuse the record. A preliminary
cache mutant did not compile and is excluded from this evidence.

The initial browser commands used `/var/tmp/twr17-round2/wasm` with these exact contents:

```sh
#!/usr/bin/env bash
export TMPDIR=/var/tmp
export PATH=/nix/store/dys0df46hm84hikqkr0jx4shdnfhqwbn-wasm-bindgen-cli-0.2.127/bin:$PATH
export CC_wasm32_unknown_unknown=/nix/store/n90xmancjp0b1dg4ybnya9qfg5yrw62m-clang-21.1.7/bin/clang
export AR_wasm32_unknown_unknown=/nix/store/n96mcsx6qisxrpljz1lvzcxxqyip9z2m-llvm-21.1.7/bin/llvm-ar
export CHROME=/nix/store/s8l73vx0mmvmdarhx2i893iysdiklqh7-chromium-154.0.8037.97/bin/chromium
exec nix shell nixpkgs#gcc -c env RUSTUP_TOOLCHAIN=1.97.1 CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-Clinker-features=-lld "$@"
```

I22's `/var/tmp/twr17-round2/check-served` first runs that wrapper with
`bash scripts/build-web.sh served`, then runs
`nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 run --locked -p tracer -- check-absence dist/served`,
stopping on any nonzero exit. The host commands below include their complete environment.

**I1** — Give the inference account credential to each session as a row-14 holding. Files: `src/store/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web session_inspection_and_terminal_metadata_and_no_prompt_or_session_inference_key_in_records -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::session_inspection_and_terminal_metadata_and_no_prompt_or_session_inference_key_in_records' (427682) panicked at src/store/inference/tests.rs:130:5:
assertion `left == right` failed
  left: Array [Object {"machine": String("fixture"), "row": Number(3)}, Object {"machine": Null, "row": Number(14)}]
 right: Array [Object {"machine": String("fixture"), "row": Number(3)}]
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I2** — Journal the session inference key as completion metadata. Files: `src/store/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web decrypted_records_never_contain_session_inference_key_or_prompt -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::decrypted_records_never_contain_session_inference_key_or_prompt' (435942) panicked at src/store/inference/tests.rs:503:9:
decrypted record contains session inference key
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test store::inference::tests::decrypted_records_never_contain_session_inference_key_or_prompt ... FAILED

```

Restored byte-identically; green exit: 0.

**I3** — Persist the session inference key in browser Cache Storage. Files: `Cargo.toml`, `src/harness/inference.rs`. Exact command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=core /var/tmp/twr17-round2/wasm bash scripts/tracer.sh
```

Red exit: 1. Failing assertion:

```text
[FAILED] browser storage empty and no service worker
```

Restored byte-identically; green exit: 0.

**I4** — Omit cap from the mint body. Files: `src/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web refused_probe_top_up_and_lost_mint_contact_nothing_further -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::refused_probe_top_up_and_lost_mint_contact_nothing_further' (440400) panicked at src/store/inference/tests.rs:304:5:
assertion `left == right` failed
  left: Object {"expires": Number(1000)}
 right: Object {"cap": String("0.10"), "expires": Number(1000)}
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I5** — Omit expiry from the mint body. Files: `src/inference.rs`. Exact command:

```sh
env TAU_TRACER_INFERENCE=1 /var/tmp/twr17-round2/wasm bash scripts/tracer.sh
```

Red exit: 1. Failing assertion:

```text
[FAILED] fixture refuses past the requested expiry without an unlock
```

Restored byte-identically; green exit: 0.

**I6** — Skip revocation at the bounded session end. Files: `src/harness/inference.rs`. Exact command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_END=lock /var/tmp/twr17-round2/wasm bash scripts/tracer.sh
```

Red exit: 1. Failing assertion:

```text
[FAILED] the tracer uses the ended session's key and the fixture refuses it
```

Restored byte-identically; green exit: 0.

**I7** — Accept automatic top-up on in the driver. Files: `src/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web top_up_on_refuses_before_preparing_an_inference_mint -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::top_up_on_refuses_before_preparing_an_inference_mint' (444894) panicked at src/store/inference/tests.rs:890:5:
assertion `left == right` failed: top-up on must refuse before preparing a mint
  left: 1
 right: 0
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I8** — Append intent in finish, after transmission. Files: `src/store/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web committed_intents_survive_suspended_send_and_every_storage_kill_boundary -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::committed_intents_survive_suspended_send_and_every_storage_kill_boundary' (448269) panicked at src/store/inference/tests.rs:436:17:
send has no durable intent: mint, boundary 0
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test store::inference::tests::committed_intents_survive_suspended_send_and_every_storage_kill_boundary ... FAILED

```

Restored byte-identically; green exit: 0.

**I9** — Omit the durable inference intent. Files: `src/store/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web committed_intents_survive_suspended_send_and_every_storage_kill_boundary -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::committed_intents_survive_suspended_send_and_every_storage_kill_boundary' (459505) panicked at src/store/inference/tests.rs:427:14:
called `Result::unwrap()` on an `Err` value: "record 7: terminal has no earlier inference intent; replay stopped"
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test store::inference::tests::committed_intents_survive_suspended_send_and_every_storage_kill_boundary ... FAILED

```

Restored byte-identically; green exit: 0.

**I10-model** — Drop terminal model. Files: `src/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web session_inspection_and_terminal_metadata_and_no_prompt_or_session_inference_key_in_records -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::session_inspection_and_terminal_metadata_and_no_prompt_or_session_inference_key_in_records' (492134) panicked at src/store/inference/tests.rs:135:5:
assertion `left == right` failed: {"call":11,"unresolved":true,"why":"the response terminal could not be committed"}
  left: Null
 right: true
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I10-reported_provider** — Drop terminal reported_provider. Files: `src/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web session_inspection_and_terminal_metadata_and_no_prompt_or_session_inference_key_in_records -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::session_inspection_and_terminal_metadata_and_no_prompt_or_session_inference_key_in_records' (535473) panicked at src/store/inference/tests.rs:154:5:
assertion `left == right` failed
  left: None
 right: Some("Fixture Provider")
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I10-request_id** — Drop terminal request_id. Files: `src/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web session_inspection_and_terminal_metadata_and_no_prompt_or_session_inference_key_in_records -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::session_inspection_and_terminal_metadata_and_no_prompt_or_session_inference_key_in_records' (612842) panicked at src/store/inference/tests.rs:170:5:
assertion `left == right` failed
  left: None
 right: Some("gen-fixture")
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I10-requested_provider** — Drop terminal requested_provider. Files: `src/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web session_inspection_and_terminal_metadata_and_no_prompt_or_session_inference_key_in_records -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::session_inspection_and_terminal_metadata_and_no_prompt_or_session_inference_key_in_records' (513071) panicked at src/store/inference/tests.rs:135:5:
assertion `left == right` failed: {"call":11,"unresolved":true,"why":"the response terminal could not be committed"}
  left: Null
 right: true
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I10-spend** — Drop terminal spend. Files: `src/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web session_inspection_and_terminal_metadata_and_no_prompt_or_session_inference_key_in_records -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::session_inspection_and_terminal_metadata_and_no_prompt_or_session_inference_key_in_records' (586388) panicked at src/store/inference/tests.rs:166:5:
assertion `left == right` failed
  left: None
 right: Some("0.000000123456789012345678901234567890")
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I10-token_counts** — Drop terminal token_counts. Files: `src/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web session_inspection_and_terminal_metadata_and_no_prompt_or_session_inference_key_in_records -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::session_inspection_and_terminal_metadata_and_no_prompt_or_session_inference_key_in_records' (558091) panicked at src/store/inference/tests.rs:158:5:
assertion `left == right` failed
  left: (None, None, None)
 right: (Some(3), Some(5), Some(8))
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I11** — Include the composed prompt body in the intent model field. Files: `src/store/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web decrypted_records_never_contain_session_inference_key_or_prompt -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::decrypted_records_never_contain_session_inference_key_or_prompt' (645384) panicked at src/store/inference/tests.rs:507:9:
decrypted record contains prompt body
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test store::inference::tests::decrypted_records_never_contain_session_inference_key_or_prompt ... FAILED

```

Restored byte-identically; green exit: 0.

**I12-barrier** — Refuse the next inference request while a completion is unresolved. Files: `src/store/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web unresolved_is_unaccounted_never_resent_and_next_request_dispatches_after_reopen -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::unresolved_is_unaccounted_never_resent_and_next_request_dispatches_after_reopen' (673256) panicked at src/store/inference/tests.rs:327:5:
assertion `left == right` failed
  left: Null
 right: true
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I12-lock** — Hold the mint guard across completion fetch; both requests must have their own committed intents and fixture arrivals. Files: `src/inference.rs`. Exact command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=core /var/tmp/twr17-round3/wasm bash scripts/tracer.sh
```

Red exit: 1. Failing output:

```text
[FAILED] second completion finishes while the first response is withheld
[FAILED] both intents committed and both completions reached the fixture
```

Saved bytes restored and compared byte for byte. Green exit: 0.

**I13** — Describe an unreadable completion as failed. Files: `src/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web unresolved_is_unaccounted_never_resent_and_next_request_dispatches_after_reopen -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::unresolved_is_unaccounted_never_resent_and_next_request_dispatches_after_reopen' (702778) panicked at src/store/inference/tests.rs:318:5:
assertion `left == right` failed: {"call":11,"failed":true}
  left: Null
 right: true
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I14** — Automatically resend an unresolved completion. Files: `src/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web unresolved_is_unaccounted_never_resent_and_next_request_dispatches_after_reopen -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::unresolved_is_unaccounted_never_resent_and_next_request_dispatches_after_reopen' (730285) panicked at src/store/inference/tests.rs:332:5:
assertion `left == right` failed
  left: 4
 right: 3
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I15** — Clear the chosen route after a real 5xx response. Files: `src/store/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web every_composition_and_route_and_readable_error -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::every_composition_and_route_and_readable_error' (754437) panicked at src/store/inference/tests.rs:218:5:
assertion `left == right` failed
  left: 2
 right: 1
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I16** — Send account read and mint before the route probe. Files: `src/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web every_composition_and_route_and_readable_error -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::every_composition_and_route_and_readable_error' (777987) panicked at src/store/inference/tests.rs:219:5:
assertion `left == right` failed
  left: "/account"
 right: "/"
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I17** — Omit retention on a later completion only. Files: `src/store/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web every_composition_and_route_and_readable_error -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::every_composition_and_route_and_readable_error' (798933) panicked at src/store/inference/tests.rs:221:9:
assertion `left == right` failed
  left: Object {"only": Array [String("fixture-provider")]}
 right: Object {"only": Array [String("fixture-provider")], "zdr": Bool(true)}
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I18-maker** — Derive only from candidate maker. Files: `src/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web every_composition_and_route_and_readable_error -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::every_composition_and_route_and_readable_error' (833171) panicked at src/store/inference/tests.rs:221:9:
assertion `left == right` failed
  left: Object {"only": Array [String("fixture-maker")], "zdr": Bool(true)}
 right: Object {"only": Array [String("fixture-provider")], "zdr": Bool(true)}
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I18-slug** — Derive only from candidate slug. Files: `src/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web every_composition_and_route_and_readable_error -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'store::inference::tests::every_composition_and_route_and_readable_error' (818895) panicked at src/store/inference/tests.rs:221:9:
assertion `left == right` failed
  left: Object {"only": Array [String("fixture-model")], "zdr": Bool(true)}
 right: Object {"only": Array [String("fixture-provider")], "zdr": Bool(true)}
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I19** — Refuse inference under standing dispositions. Files: `src/dispatch/typed.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web disposition_matrix_reads_and_commands_in_core_store_and_replay -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'dispatch::typed_tests::disposition_matrix_reads_and_commands_in_core_store_and_replay' (843323) panicked at src/dispatch/typed_tests.rs:544:21:
assertion `left == right` failed: {"refused":"inference admission refused"}
  left: Null
 right: true
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Restored byte-identically; green exit: 0.

**I20** — Let an inference intent clear the standing restriction. Files: `src/store/inference.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web disposition_matrix_reads_and_commands_in_core_store_and_replay -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'dispatch::typed_tests::disposition_matrix_reads_and_commands_in_core_store_and_replay' (875266) panicked at src/dispatch/typed_tests.rs:547:53:
no entry found for key
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test dispatch::typed_tests::disposition_matrix_reads_and_commands_in_core_store_and_replay ... FAILED

```

Restored byte-identically; green exit: 0.

**I21** — Delete the per-build search site's call to add aggregator needles, leaving its independent control intact. Files: `tracer/src/main.rs`. Exact command:

```sh
env -u TAU_TRACER_SETUP_CASE -u TAU_TRACER_SEED_CASE -u TAU_TRACER_HOLD_CASE -u TAU_TRACER_MODE_CASE -u TAU_TRACER_INFERENCE -u TAU_TRACER_INFERENCE_PHASE -u TAU_TRACER_INFERENCE_END /var/tmp/twr17-round3/wasm bash scripts/tracer.sh
```

Red exit: 1. Failing output:

```text
[FAILED] per-build search includes every aggregator needle
[FAILED] per-build search includes every aggregator needle
== summary (125 cases)
```

Saved bytes restored and compared byte for byte. The green is the final full gate recorded below.

**I22-export** — Compile the fixture-origin switch into the served build. Files: `src/harness/inference.rs`. Exact command:

```sh
/var/tmp/twr17-round2/check-served
```

Red exit: 1. Failing assertion:

```text
FAIL: test-only parts found:
  dist/served/pkg/tau_web.js: test switch: test_inference_origin
  dist/served/pkg/tau_web_bg.wasm: test switch: test_inference_origin
```

Restored byte-identically; green exit: 0.

**I22-needles** — Drop the new check-absence needles. Files: `tracer/src/checks.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tracer absence_detects_each_planted_inference_needle -- --nocapture
```

Red exit: 101. Failing assertion:

```text
thread 'checks::tests::absence_detects_each_planted_inference_needle' (892001) panicked at tracer/src/checks.rs:341:22:
planted inference needle escaped check-absence: ()
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test checks::tests::absence_detects_each_planted_inference_needle ... FAILED

```

Restored byte-identically; green exit: 0.

**I23** — Sweep and send another revoke even when a revoke intent exists. Files: `src/store/inference.rs`. Exact command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=cutoff /var/tmp/twr17-round2/wasm bash scripts/tracer.sh
```

Red exit: 1. Failing assertion:

```text
[FAILED] exactly one revoke was sent, with no sweep retry
```

Restored byte-identically; green exit: 0.

**I24** — Follow completion redirects automatically. Files: `src/harness/inference.rs`. Exact command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=core /var/tmp/twr17-round2/wasm bash scripts/tracer.sh
```

Red exit: 1. Failing assertion:

```text
[FAILED] redirect target received nothing
```

Restored byte-identically; green exit: 0.

The late-response metadata regression was also run before and after its fix. A completion
arrives after session end with the session inference key as its reported provider and the
inference account credential as its request id. The terminal must contain redaction markers
and no response body is handed back. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web late_completion_metadata_redacts_the_request_credential_after_holdings_clear
```

Before the request-token scan, exit 101:

```text
assertion `left == right` failed: late metadata must not journal a cleared session inference key
  left: Some("fixture-session-private-value")
 right: Some("<redacted>")
```

With the request's transient credential included in the boundary, exit 0. All host mutation
variants above were rerun red and green after this addition, with byte-identical restoration.

The following reruns and I25–I32 use rooted tools. `/var/tmp/twr17-round3/host` contains:

```sh
#!/usr/bin/env bash
export TMPDIR=/var/tmp
exec nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 "$@"
```

`/var/tmp/twr17-round3/wasm` contains:

```sh
#!/usr/bin/env bash
export TMPDIR=/var/tmp
export PATH=/var/tmp/rev-twr17/wbg/bin:$PATH
export CC_wasm32_unknown_unknown=/var/tmp/twr17-round3-tools/clang/bin/clang
export AR_wasm32_unknown_unknown=/var/tmp/twr17-round3-tools/llvm/bin/llvm-ar
export CHROME=/var/tmp/twr17-round3-tools/chromium/bin/chromium
exec nix shell nixpkgs#gcc -c env RUSTUP_TOOLCHAIN=1.97.1 CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-Clinker-features=-lld "$@"
```

GCC, Chromium 154, clang and llvm-ar are retained by the named Nix out-links. The
wasm-bindgen executable is a regular installed binary at version 0.2.127. Each browser
command rebuilds both directories. No two cargo or tracer processes run together.
The final full gate and final host suite supply the restored green for every earlier mutation.

An initial full I21 attempt exited 1 after 115 passing cases with an OPFS `NotFoundError`
during the unlock sweep, before reaching the planted control. It is excluded from I21's red
evidence. The dump now retries its whole snapshot after an atomic move, discards the partial
snapshot, bounds retries at ten and propagates unrelated errors. I32 checks all three behaviours.
The completed I21 rerun reached 125 cases and failed only the two independent per-build controls.

**I2-redo** — Insert a session inference key into terminal metadata after the decoded-value scan. Files: `src/store/inference.rs`. Exact command:

```sh
/var/tmp/twr17-round3/host test --locked -p tau-web decrypted_records_never -- --nocapture
```

Red exit: 101. Failing output:

```text
decrypted record contains session inference key
```

Saved bytes restored and compared byte for byte. Green exit: 0.

**I6-redo** — Skip the end step's snapshot revokes. Files: `src/harness/inference.rs`. Exact command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_END=lock /var/tmp/twr17-round3/wasm bash scripts/tracer.sh
```

Red exit: 1. Failing output:

```text
[FAILED] the tracer uses the ended session's key and the fixture refuses it
```

Saved bytes restored and compared byte for byte. Green exit: 0.

**I23-redo** — Select an identifier again despite an existing revoke intent. Files: `src/store/inference.rs`. Exact command:

```sh
/var/tmp/twr17-round3/host test --locked -p tau-web session_end_sweep_skips -- --nocapture
```

Red exit: 101. Failing output:

```text
assertion failed: reopen(&s).inference_sweep().is_empty()
```

Saved bytes restored and compared byte for byte. Green exit: 0.

**I25** — Remove the decoded terminal metadata scan. Files: `src/store/inference.rs`. Exact command:

```sh
/var/tmp/twr17-round3/host test --locked -p tau-web escaped_ -- --nocapture
```

Red exit: 101. Failing output:

```text
assertion `left == right` failed
  left: Some("fixture-account-private-value")
 right: Some("<redacted>")
assertion `left == right` failed
  left: Some("fixture-session-private-value")
 right: Some("<redacted>")
```

Saved bytes restored and compared byte for byte. Green exit: 0.

The `escaped_` filter ran three regressions: the escaped session inference key in `provider`,
the escaped inference account credential in `id`, and both after session end. All three
failed with the scan removed and passed after restoration.

**I26** — Propagate the body-redaction refusal before committing the terminal. Files: `src/store/inference.rs`. Exact command:

```sh
/var/tmp/twr17-round3/host test --locked -p tau-web redaction_refusal_still -- --nocapture
```

Red exit: 101. Failing output:

```text
called `Result::unwrap()` on an `Err` value: "redaction marker cannot exclude held credentials"
```

Saved bytes restored and compared byte for byte. Green exit: 0.

**I27** — Include current-worker minted identifiers in the unlock sweep. Files: `src/store/inference.rs`. Exact command:

```sh
/var/tmp/twr17-round3/host test --locked -p tau-web delayed_unlock_sweep -- --nocapture
```

Red exit: 101. Failing output:

```text
assertion `left == right` failed
  left: ["fixture-key-id", "current-worker-key-id"]
 right: ["fixture-key-id"]
```

Saved bytes restored and compared byte for byte. Green exit: 0.

**I28** — Drop the late-mint revoke from finish. Files: `src/store/inference.rs`. Exact command:

```sh
/var/tmp/twr17-round3/host test --locked -p tau-web mint_finishing_during_session_end -- --nocapture
```

Red exit: 101. Failing output:

```text
late mint owes an immediate revoke
```

Saved bytes restored and compared byte for byte. Green exit: 0.

**I29** — Revoke only keys that installed a row-2 holding at session end. Files: `src/store/inference.rs`. Exact command:

```sh
env TAU_TRACER_INFERENCE=1 /var/tmp/twr17-round3/wasm bash scripts/tracer.sh
```

Red exit: 1. Failing output:

```text
[FAILED] identifier-only key is refused immediately after end, before unlock
```

Saved bytes restored and compared byte for byte. Green exit: 0.

**I30** — Freeze the fixture clock at process start. Files: `tracer/src/aggregator.rs`. Exact command:

```sh
/var/tmp/twr17-round3/host test --locked -p tracer fixture_clock_advances -- --nocapture
```

Red exit: 101. Failing output:

```text
assertion failed: state.now() >= state.now + 600
```

Saved bytes restored and compared byte for byte. Green exit: 0.

**I31** — Require acceptance before reload unlock even when a revoke terminal committed. Files: `tracer/src/inference_cases.rs`. Exact command:

```sh
/var/tmp/twr17-round3/host test --locked -p tracer reload_checks_all_three -- --nocapture
```

Red exit: 101. Failing output:

```text
[FAILED] reload key status before unlock matches its recorded revoke
assertion failed: case.failures.is_empty()
```

Saved bytes restored and compared byte for byte. Green exit: 0.

**I32** — Remove the OPFS dump's atomic-move retry. Files: `tracer/src/main.rs`. Exact command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=core /var/tmp/twr17-round3/wasm bash scripts/tracer.sh
```

Red exit: 1. Failing output:

```text
[FAILED] OPFS dump retries a move and discards the partial snapshot
[FAILED] OPFS dump bounds move retries and preserves unrelated errors
```

Saved bytes restored and compared byte for byte. Green exit: 0.

**I33** — Remove both post-commit session-end checks from the box-plane command path.
File: `src/harness/run.rs`. The tracer-only `test_hold_move` suspends the real OPFS move
while the intent append owns the writer. The case begins end-sessions with the revoke
response withheld, then releases the move and checks the sshd and replayed state.

The round-four commands use `/var/tmp/twr17-round4/host`:

```sh
#!/usr/bin/env bash
export TMPDIR=/var/tmp
exec systemd-run --user --scope -p MemoryMax=16G -p MemorySwapMax=0 nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 "$@"
```

And `/var/tmp/twr17-round4/wasm`:

```sh
#!/usr/bin/env bash
export TMPDIR=/var/tmp
export PATH=/var/tmp/rev-twr17/wbg/bin:$PATH
export CC_wasm32_unknown_unknown=/var/tmp/twr17-tools/clang/bin/clang
export AR_wasm32_unknown_unknown=/var/tmp/twr17-tools/llvm/bin/llvm-ar
export CHROME=/var/tmp/twr17-tools/chromium/bin/chromium
exec systemd-run --user --scope -p MemoryMax=16G -p MemorySwapMax=0 nix shell nixpkgs#gcc -c env RUSTUP_TOOLCHAIN=1.97.1 CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-Clinker-features=-lld "$@"
```

The Nix out-links `/var/tmp/twr17-tools/{gcc,clang,llvm,chromium}` retain the tools;
wasm-bindgen is the installed 0.2.127 binary. Every process runs in the foreground.
Exact red and restored-green command:

```sh
TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=dispatch /var/tmp/twr17-round4/wasm bash scripts/tracer.sh
```

Red, exit 1:

```text
== session end during box-plane intent commit prevents exec
   [FAILED] committed command reports unresolved after end begins
   [FAILED] sshd receives no exec after the held intent commits
   [FAILED] unlock recovers the committed command as unresolved
```

The saved source bytes were restored and compared byte for byte. Green, exit 0:

```text
== session end during box-plane intent commit prevents exec
   [ok] committed command reports unresolved after end begins
   [ok] sshd receives no exec after the held intent commits
   [ok] unlock recovers the committed command as unresolved
== summary (5 cases)
   PASS session end during box-plane intent commit prevents exec
TRACER PASS
```

Three focused host regressions were also run red and restored green with the round-four
`host test --locked <selector> -- --nocapture` command. Each red exited 101; each green exited 0:

| Selector | Removed behavior | Red evidence |
|---|---|---|
| `empty_completion_text` | empty decoded terminal text omission | independent reader: `record 11: inference text missing` |
| `reload_checks_all_three` | allow refusal after a logged revoke whose terminal was cut off | recorded revoke, `sent=true, status=402`: expected accepted observation, got refusal |
| `post_terminal_failures_report_finished` | report post-terminal failures as separate refusals | `Result::unwrap()` on `Err("second session inference key")` |

The empty-text regression commits both an empty provider and an empty request id, retaining
the other nonempty field and passing the complete independent reader. The post-terminal
regression covers both an existing row-2 holding and a late-revoke create failure; both mint
terminals survive replay, and the latter key remains in the next unlock's sweep.

**I34** — Remove the session-end check immediately before the job-read `exec` in
`read_job_record`. File: `src/harness/run.rs`. The collection case suspends its first read
after channel opening, begins session end while the store writer is held, then releases it.
A second mutation removes the immediate `stop_all` call from `src/harness/inference.rs`;
the held-request variant checks the wait is stopped before end-sessions acquires that writer.

The round-five `host` and `wasm` wrappers under `/var/tmp/twr17-round5.zgH4I7PG/` have exactly
the round-four wrapper contents above. Exact command for both red and restored-green runs:

```sh
TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=dispatch /var/tmp/twr17-round5.zgH4I7PG/wasm bash scripts/tracer.sh
```

Read-check mutation red, exit 1:

```text
== session end before collection read prevents exec
   [FAILED] unread calls report not_read with session end as the reason
   [FAILED] sshd receives no read exec after session end begins
```

Immediate-stop mutation red, exit 1:

```text
== session end stops held read before acquiring writer
   [FAILED] held wait is stopped while end-sessions still awaits the writer
```

Each saved source file was restored and compared byte for byte before its green run. Both
greens exited 0; the final focused run printed:

```text
== session end before collection read prevents exec
   [ok] unread calls report not_read with session end as the reason
   [ok] sshd receives no read exec after session end begins
   [ok] session end appends no job evidence and settles no command
== session end stops held read before acquiring writer
   [ok] held wait is stopped while end-sessions still awaits the writer
   [ok] unread calls report not_read with session end as the reason
   [ok] sshd receives no read exec after session end begins
   [ok] session end appends no job evidence and settles no command
== summary (7 cases)
TRACER PASS
```

**I35** — Restore the post-mint `has_key(...).await?` path, discarding the committed mint
report. File: `src/inference.rs`. Exact red and restored-green command:

```sh
/var/tmp/twr17-round5.zgH4I7PG/host test --locked infer_preserves_committed_mint_report -- --nocapture
```

Red, exit 101:

```text
assertion `left == right` failed: {"refused":"sessions ended"}
  left: Null
 right: true
test store::inference::tests::infer_preserves_committed_mint_report_when_sessions_end_in_flight ... FAILED
```

The saved source file was restored and compared byte for byte. Green, exit 0:

```text
test store::inference::tests::infer_preserves_committed_mint_report_when_sessions_end_in_flight ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 204 filtered out
```

This test goes through `inference::infer` and the fake transport. Session end occurs inside
the mint exchange, after the intent commits and before its response returns. When late-revoke
preparation fails, the report preserves the mint call id, `finished:true`, and the refusal
saying no revoke was recorded and leaving the key to the next unlock's sweep or its expiry.
When the late revoke succeeds but the subsequent session-key lookup fails, the report still
preserves that committed mint's call id and finished status. Replay retains both mint terminals;
no completion is sent.

**I36** — Restore the finished-only condition after the mint's session-key lookup fails.
File: `src/inference.rs`. The round-six `host` and `wasm` wrappers under
`/var/tmp/twr17-round6.7cnd2U0i/` have the round-four contents above. Exact red and
restored-green command:

```sh
/var/tmp/twr17-round6.7cnd2U0i/host test --locked infer_preserves_unresolved_mint_report -- --nocapture
```

Red, exit 101, for both the lost-response and post-append legs:

```text
assertion `left == right` failed: after_append=false: {"refused":"sessions ended"}
  left: Null
 right: true
assertion `left == right` failed: after_append=true: {"refused":"sessions ended"}
  left: Null
 right: true
test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 208 filtered out
```

The saved source bytes were restored and compared byte for byte. Green, exit 0:

```text
test store::inference::tests::infer_preserves_unresolved_mint_report_when_sessions_end_after_append ... ok
test store::inference::tests::infer_preserves_unresolved_mint_report_when_sessions_end_after_send ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 208 filtered out
```

Both tests go through `inference::infer` and assert call 9, `unresolved: true`, the session-end
refusal and the unresolved mint on replay. The lost leg sent `/keys`; the append leg sent
nothing after its committed mint. Neither sent a completion or revoke.

**I37 — superseded by I44 and I45.** This is historical evidence for the removed
sent-read-keeps-its-error rule; its test names and expected reasons are no longer current.
Relabel every read error as session end whenever the flag is set, ignoring whether
its `exec` was sent. File: `src/harness/job_read.rs`; remove `!self.sent.get() &&` from the
session-end condition. Exact red and restored-green command:

```sh
/var/tmp/twr17-round6.7cnd2U0i/host test --locked sent_read_error_survives_session_end -- --nocapture
```

Red, exit 101:

```text
assertion `left == right` failed
  left: String("sessions ended before record was read")
 right: "job record read: missing exit status"
assertion `left == right` failed: {"call":9,"job":"fixture-job","not_read":true,"why":"sessions ended before record was read"}
  left: Null
 right: true
test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 208 filtered out
```

The saved source bytes were restored and compared byte for byte. Green, exit 0:

```text
test harness::job_read::tests::sent_read_error_survives_session_end_in_held_report ... ok
test harness::job_read::tests::sent_read_error_survives_session_end_in_collection_report ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 208 filtered out
```

The transport in `run.rs` compiles only on wasm32. These host tests exercise the shared
reporting function used by both read paths: mark the read sent, set the session-end flag,
then report its own read error. At that time collection retained `failed: true` and held
reads retained `not_read: true`, both with the original error. A separate host test checks both unsent
shapes name session end. The full browser gate also retains both pre-exec session-end cases.

**I38 — superseded by I44, I45 and I51.** This is historical evidence for the removed
sent-read-keeps-its-error rule. The current sent-read reason is session end, with send history
preserved and collection reads cancelled. Discard the tracked send state at the job-read reporting sites in
`src/harness/run.rs`: replace each `progress.failure(...)` with
`super::job_read::Read::default().failure(...)`. This covers both held-read error branches
and the collection error branch. The two new browser cases wait for sshd to receive the
read `exec` before calling `end_sessions()`.

The wrappers in `/var/tmp/twr17-k-fixes.I4mWTYPE/` supplied the environment for I38, I39 and
that round's final gates; the current final gates use the I40–I53 wrappers. `host` contains:

```sh
#!/usr/bin/env bash
export TMPDIR=/var/tmp
exec nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 "$@"
```

`wasm` contains:

```sh
#!/usr/bin/env bash
export TMPDIR=/var/tmp
export PATH=/var/tmp/rev-twr17/wbg/bin:$PATH
export CC_wasm32_unknown_unknown=/var/tmp/twr17-tools/clang/bin/clang
export AR_wasm32_unknown_unknown=/var/tmp/twr17-tools/llvm/bin/llvm-ar
export CHROME=/var/tmp/twr17-tools/chromium/bin/chromium
exec nix shell nixpkgs#gcc -c env RUSTUP_TOOLCHAIN=1.97.1 CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-Clinker-features=-lld "$@"
```

The tools have persistent roots, and the commands inherit a 16 GiB memory limit with no swap.
Exact red and restored-green command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=dispatch /var/tmp/twr17-k-fixes.I4mWTYPE/wasm bash scripts/tracer.sh
```

Red, exit 1. Both sent reads wrongly reported `not_read: true` with
`why: "sessions ended before record was read"`; the existing pre-exec cases still passed:

```text
== summary (9 cases)
   PASS session end before collection read prevents exec
   PASS session end stops held read before acquiring writer
   FAIL session end preserves a sent held read's stop reason: sent read retains its own outcome and reason after session end
   FAIL session end preserves a sent collection read's error: sent read retains its own outcome and reason after session end
FAIL: tracer cases failed: session end preserves a sent held read's stop reason, session end preserves a sent collection read's error
```

The saved source bytes were restored and compared byte for byte. Green, exit 0:

```text
== summary (9 cases)
   PASS session end preserves a sent held read's stop reason
   PASS session end preserves a sent collection read's error
TRACER PASS
```

Under that superseded rule the held read retained `not_read: true` with
`why: "stopped while reading record"`, and collection retained `failed: true`, its job
identity and its own wrapper-status/read-file error after a malformed fixture exit record was
supplied following session end. Both cases checked that no further exec, job evidence or
terminal appeared.

**I39** — Restore the bare top-up refusal after an account read in `src/inference.rs`,
discarding the read's call id and unresolved state. Exact red and restored-green command:

```sh
/var/tmp/twr17-k-fixes.I4mWTYPE/host test --locked infer_preserves_unresolved_account_read_report -- --nocapture
```

Red, exit 101. Both tests reported:

```text
assertion `left == right` failed: {"refused":"account read 7: automatic top-up must read off"}
  left: Null
 right: 7
test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 210 filtered out
```

The saved source bytes were restored and compared byte for byte. Green, exit 0:

```text
test store::inference::tests::infer_preserves_unresolved_account_read_report_after_lost_response ... ok
test store::inference::tests::infer_preserves_unresolved_account_read_report_when_sessions_end_after_append ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 210 filtered out
```

Both tests call `inference::infer`, check call 7, `unresolved: true` and the refusal
`no mint is sent without a recorded top-up-off read`, and replay the unresolved account
read. The lost-response test sends `/account`; the session-end test ends sessions during
its durable append and sends no account read. Neither prepares or sends a mint. The
finished top-up-on regression also checks that its refusal keeps the call id and finished
status.

### Session-end follow-up evidence (I40–I53)

These checks ran on 2026-10-24. I40–I52 add 18 red/green command pairs; I53 runs
controls against the production behavior at `8dbfcee` and the restored fix. Every command
ran in the foreground, unpiped, with stdout/stderr redirected to its named log and the exit
status inspected. Before each green, the saved source bytes were restored and compared
byte for byte (`RESTORE BYTES MATCH`). Each browser command was preceded by
`/var/tmp/twr17-session-end-20261024/wasm scripts/build-web.sh tracer`, exit 0, on both trees.
The final full gate supplies an additional green for every case with all selectors unset.

The wrappers used below are `/var/tmp/twr17-session-end-20261024/host`:

```sh
#!/usr/bin/env bash
export TMPDIR=/var/tmp
exec nix shell nixpkgs#gcc -c env RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 "$@"
```

and `/var/tmp/twr17-session-end-20261024/wasm`:

```sh
#!/usr/bin/env bash
export TMPDIR=/var/tmp
export PATH=/var/tmp/rev-twr17/wbg/bin:$PATH
export CC_wasm32_unknown_unknown=/var/tmp/twr17-tools/clang/bin/clang
export AR_wasm32_unknown_unknown=/var/tmp/twr17-tools/llvm/bin/llvm-ar
export CHROME=/var/tmp/twr17-tools/chromium/bin/chromium
exec nix shell nixpkgs#gcc -c env RUSTUP_TOOLCHAIN=1.97.1 CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-Clinker-features=-lld "$@"
```

**I40** — Remove the post-route probe fence. Host starts with no chosen route and ends inside route(); the browser queues its cold route read behind the writer and holds revocation open. Files: `src/inference.rs`.

Exact red and restored-green command:

```sh
/var/tmp/twr17-session-end-20261024/host test --locked cold_probe_refuses -- --nocapture
```

Red, exit 101, `I40-red-0.log`:

```text
thread 'store::inference::tests::cold_probe_refuses_when_route_await_ends_sessions' (2562253) panicked at src/store/inference/tests.rs:1448:5:
assertion `left == right` failed
  left: Ok(())
 right: Err("sessions ended")
test store::inference::tests::cold_probe_refuses_when_route_await_ends_sessions ... FAILED
```

Restored green, exit 0, `I40-green-0.log`:

```text
test store::inference::tests::cold_probe_refuses_when_route_await_ends_sessions ... ok
```

Exact red and restored-green command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=session-end TAU_TRACER_SESSION_END='fences a cold probe' /var/tmp/twr17-session-end-20261024/wasm cargo run --locked -p tracer -- run dist/served dist/tracer
```

Red, exit 1, `I40-red-1.log`:

```text
   FAIL session end fences a cold probe queued ahead of the end writer: only the revoke probe is sent after ending; revoke itself is sent
FAIL: tracer cases failed: session end fences a cold probe queued ahead of the end writer
```

Restored green, exit 0, `I40-green-1.log`:

```text
   PASS session end fences a cold probe queued ahead of the end writer
TRACER PASS
```

**I41** — Remove the 2xx condition from the account-read predicate, leaving the top-up-off body check. The refusal loses its call id and HTTP status when prepare refuses the mint. Files: `src/inference.rs`.

Exact red and restored-green command:

```sh
/var/tmp/twr17-session-end-20261024/host test --locked non_success_account_read_keeps -- --nocapture
```

Red, exit 101, `I41-red-0.log`:

```text
thread 'store::inference::tests::non_success_account_read_keeps_call_status_and_prepares_no_mint' (2641720) panicked at src/store/inference/tests.rs:1508:5:
assertion `left == right` failed: {"refused":"mint has no top-up-off read"}
  left: Null
 right: 7
test store::inference::tests::non_success_account_read_keeps_call_status_and_prepares_no_mint ... FAILED
```

Restored green, exit 0, `I41-green-0.log`:

```text
test store::inference::tests::non_success_account_read_keeps_call_status_and_prepares_no_mint ... ok
```

**I42** — Remove both connection-admission end fences. The host checks the store directly; the browser queues admission behind the end snapshot. I46 separately isolates the journal fence. Files: `src/store.rs`, `src/lib.rs`.

Exact red and restored-green command:

```sh
/var/tmp/twr17-session-end-20261024/host test --locked connection_admission_after_end -- --nocapture
```

Red, exit 101, `I42-red-0.log`:

```text
thread 'store::inference::tests::connection_admission_after_end_records_no_refusal_live_or_replayed' (3373146) panicked at src/store/inference/tests.rs:1535:5:
assertion failed: matches!(block_on(store.connection_session("fixture-other")),
test store::inference::tests::connection_admission_after_end_records_no_refusal_live_or_replayed ... FAILED
```

Restored green, exit 0, `I42-green-0.log`:

```text
test store::inference::tests::connection_admission_after_end_records_no_refusal_live_or_replayed ... ok
```

Exact red and restored-green command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=session-end TAU_TRACER_SESSION_END='fences unbound writer behind' /var/tmp/twr17-session-end-20261024/wasm cargo run --locked -p tracer -- run dist/served dist/tracer
```

Red, exit 1, `I42-red-1.log`:

```text
   FAIL session end fences unbound writer behind end snapshot: session-end refusal replaces admission or collected answer; no connection or signature refusal is committed
FAIL: tracer cases failed: session end fences unbound writer behind end snapshot
```

Restored green, exit 0, `I42-green-1.log`:

```text
   PASS session end fences unbound writer behind end snapshot
TRACER PASS
```

**I43** — Remove both signature end fences for a lowering form on an unpinned installation. The host checks the store directly; the browser queues the check behind the end snapshot. I47 separately isolates the journal fence. Files: `src/store.rs`, `src/lib.rs`.

Exact red and restored-green command:

```sh
/var/tmp/twr17-session-end-20261024/host test --locked signature_check_after_end -- --nocapture
```

Red, exit 101, `I43-red-0.log`:

```text
thread 'store::inference::tests::signature_check_after_end_records_no_refusal_live_or_replayed' (2786490) panicked at src/store/inference/tests.rs:1552:5:
assertion failed: matches!(block_on(store.check_signature("fixture-other",
test store::inference::tests::signature_check_after_end_records_no_refusal_live_or_replayed ... FAILED
```

Restored green, exit 0, `I43-green-0.log`:

```text
test store::inference::tests::signature_check_after_end_records_no_refusal_live_or_replayed ... ok
```

Exact red and restored-green command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=session-end TAU_TRACER_SESSION_END='fences signature writer behind' /var/tmp/twr17-session-end-20261024/wasm cargo run --locked -p tracer -- run dist/served dist/tracer
```

Red, exit 1, `I43-red-1.log`:

```text
   FAIL session end fences signature writer behind end snapshot: session-end refusal replaces admission or collected answer; no connection or signature refusal is committed
FAIL: tracer cases failed: session end fences signature writer behind end snapshot
```

Restored green, exit 0, `I43-green-1.log`:

```text
   PASS session end fences signature writer behind end snapshot
TRACER PASS
```

**I44** — Restore the sent-read-keeps-its-own-error branch. Both host report shapes and both sent browser reads must instead name session end. This replaces I37 and the reason part of I38. Files: `src/harness/job_read.rs`.

Exact red and restored-green command:

```sh
/var/tmp/twr17-session-end-20261024/host test --locked sent_read_names_session_end -- --nocapture
```

Red, exit 101, `I44-red-0.log`:

```text
thread 'harness::job_read::tests::sent_read_names_session_end_in_collection_report' (2862190) panicked at src/harness/job_read.rs:66:9:
assertion `left == right` failed
  left: String("job record read: missing exit status")
 right: "sessions ended while reading record"
thread 'harness::job_read::tests::sent_read_names_session_end_in_held_report' (2862191) panicked at src/harness/job_read.rs:66:9:
assertion `left == right` failed
  left: String("job record read: missing exit status")
 right: "sessions ended while reading record"
test harness::job_read::tests::sent_read_names_session_end_in_held_report ... FAILED
test harness::job_read::tests::sent_read_names_session_end_in_collection_report ... FAILED
```

Restored green, exit 0, `I44-green-0.log`:

```text
test harness::job_read::tests::unsent_read_names_session_end_in_collection_and_held_reports ... ok
test harness::job_read::tests::sent_read_names_session_end_in_collection_report ... ok
test harness::job_read::tests::sent_read_names_session_end_in_held_report ... ok
```

Exact red and restored-green command:

```sh
env -u TAU_TRACER_SESSION_END TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=sent-reads /var/tmp/twr17-session-end-20261024/wasm cargo run --locked -p tracer -- run dist/served dist/tracer
```

Red, exit 1, `I44-red-1.log`:

```text
   FAIL session end cancels a sent held read: sent read names session end and preserves its send history
   FAIL session end cancels a sent collection read: sent read names session end and preserves its send history
FAIL: tracer cases failed: session end cancels a sent held read, session end cancels a sent collection read
```

Restored green, exit 0, `I44-green-1.log`:

```text
   PASS session end cancels a sent held read
   PASS session end cancels a sent collection read
TRACER PASS
```

**I45** — Omit mark_sent after successfully queuing exec. Both sent-read browser shapes then claim the read was unsent. This replaces the send-history part of I37/I38. Files: `src/harness/run.rs`.

Exact red and restored-green command:

```sh
env -u TAU_TRACER_SESSION_END TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=sent-reads /var/tmp/twr17-session-end-20261024/wasm cargo run --locked -p tracer -- run dist/served dist/tracer
```

Red, exit 1, `I45-red-0.log`:

```text
   FAIL session end cancels a sent held read: sent read names session end and preserves its send history
   FAIL session end cancels a sent collection read: sent read names session end and preserves its send history
FAIL: tracer cases failed: session end cancels a sent held read, session end cancels a sent collection read
```

Restored green, exit 0, `I45-green-0.log`:

```text
   PASS session end cancels a sent held read
   PASS session end cancels a sent collection read
TRACER PASS
```

**I46** — Remove only StoreJournal::connection_session's ENDING fence. Queue approved unbound admission and bound collectable-call admission ahead of the end snapshot but run them after ENDING, while the store flag is still unset. Files: `src/lib.rs`.

Exact red and restored-green command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=session-end TAU_TRACER_SESSION_END='fences unbound writer ahead,fences collection writer ahead' /var/tmp/twr17-session-end-20261024/wasm cargo run --locked -p tracer -- run dist/served dist/tracer
```

Red, exit 1, `I46-red-0.log`:

```text
   FAIL session end fences unbound writer ahead of end snapshot: session-end refusal replaces admission or collected answer; no connection or signature refusal is committed
   FAIL session end fences collection writer ahead of end snapshot: session-end refusal replaces admission or collected answer
FAIL: tracer cases failed: session end fences unbound writer ahead of end snapshot, session end fences collection writer ahead of end snapshot
```

Restored green, exit 0, `I46-green-0.log`:

```text
   PASS session end fences unbound writer ahead of end snapshot
   PASS session end fences collection writer ahead of end snapshot
TRACER PASS
```

**I47** — Remove only StoreJournal::check_signature's ENDING fence. Queue a lowering form on an unpinned installation ahead of the end snapshot but run it after ENDING, while the store flag is still unset. Files: `src/lib.rs`.

Exact red and restored-green command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=session-end TAU_TRACER_SESSION_END='fences signature writer ahead' /var/tmp/twr17-session-end-20261024/wasm cargo run --locked -p tracer -- run dist/served dist/tracer
```

Red, exit 1, `I47-red-0.log`:

```text
   FAIL session end fences signature writer ahead of end snapshot: session-end refusal replaces admission or collected answer; no connection or signature refusal is committed
FAIL: tracer cases failed: session end fences signature writer ahead of end snapshot
```

Restored green, exit 0, `I47-green-0.log`:

```text
   PASS session end fences signature writer ahead of end snapshot
TRACER PASS
```

**I48** — Remove the final completion-body fence. Exercise finish ahead of the end snapshot and a body already built before the last writer wait; both terminal records remain committed. Files: `src/harness/inference.rs`.

Exact red and restored-green command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=session-end TAU_TRACER_SESSION_END='withholds completion body' /var/tmp/twr17-session-end-20261024/wasm cargo run --locked -p tracer -- run dist/served dist/tracer
```

Red, exit 1, `I48-red-0.log`:

```text
   FAIL session end withholds completion body at finish_writer: body absent with session-end refusal and finished call metadata
   FAIL session end withholds completion body at response_writer: body absent with session-end refusal and finished call metadata
FAIL: tracer cases failed: session end withholds completion body at finish_writer, session end withholds completion body at response_writer
```

Restored green, exit 0, `I48-green-0.log`:

```text
   PASS session end withholds completion body at finish_writer
   PASS session end withholds completion body at response_writer
TRACER PASS
```

**I49** — Disable registered-socket close on Stop firing and on already stopped registration. Observe every first-key-exchange and rekey stall, suspended held/collection evidence appends, all three rekey-stalled evidence appends, and a suspended command intent before releasing its append. Files: `src/harness/wait.rs`.

Exact red and restored-green command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=session-end TAU_TRACER_SESSION_END='at kex,-rekey,append with rekey,completes begun held,completes begun collection' /var/tmp/twr17-session-end-20261024/wasm cargo run --locked -p tracer -- run dist/served dist/tracer
```

Red, exit 1, `I49-red-0.log`:

```text
   FAIL session end closes command at kex: relay observes browser socket close during end step; every dialed sshd observes connection end
   FAIL session end closes command at auth-rekey: relay observes browser socket close during end step; every dialed sshd observes connection end
   FAIL session end closes command at connected-rekey: relay observes browser socket close during end step; every dialed sshd observes connection end
   FAIL session end closes held at kex: relay observes browser socket close during end step; every dialed sshd observes connection end
   FAIL session end closes held at auth-rekey: relay observes browser socket close during end step; every dialed sshd observes connection end
   FAIL session end closes held at connected-rekey: relay observes browser socket close during end step; every dialed sshd observes connection end
   FAIL session end closes collection at kex: relay observes browser socket close during end step; every dialed sshd observes connection end
   FAIL session end closes collection at auth-rekey: relay observes browser socket close during end step; every dialed sshd observes connection end
   FAIL session end closes collection at connected-rekey: relay observes browser socket close during end step; every dialed sshd observes connection end
   FAIL session end closes command during begun evidence append with rekey stalled: relay observes browser socket close during end step; every dialed sshd observes connection end
   FAIL session end closes held during begun evidence append with rekey stalled: relay observes browser socket close during end step; every dialed sshd observes connection end
   FAIL session end closes collection during begun evidence append with rekey stalled: relay observes browser socket close during end step; every dialed sshd observes connection end
   FAIL session end completes begun held evidence append: relay observes browser socket close during end step; every dialed sshd observes connection end
   FAIL session end completes begun collection evidence append: relay observes browser socket close during end step; every dialed sshd observes connection end
FAIL: tracer cases failed: session end closes command at kex, session end closes command at auth-rekey, session end closes command at connected-rekey, session end closes held at kex, session end closes held at auth-rekey, session end closes held at connected-rekey, session end closes collection at kex, session end closes collection at auth-rekey, session end closes collection at connected-rekey, session end closes command during begun evidence append with rekey stalled, session end closes held during begun evidence append with rekey stalled, session end closes collection during begun evidence append with rekey stalled, session end completes begun held evidence append, session end completes begun collection evidence append
```

Restored green, exit 0, `I49-green-0.log`:

```text
   PASS session end closes command at kex
   PASS session end closes command at auth-rekey
   PASS session end closes command at connected-rekey
   PASS session end closes held at kex
   PASS session end closes held at auth-rekey
   PASS session end closes held at connected-rekey
   PASS session end closes collection at kex
   PASS session end closes collection at auth-rekey
   PASS session end closes collection at connected-rekey
   PASS session end closes command during begun evidence append with rekey stalled
   PASS session end closes held during begun evidence append with rekey stalled
   PASS session end closes collection during begun evidence append with rekey stalled
   PASS session end completes begun held evidence append
   PASS session end completes begun collection evidence append
TRACER PASS
```

Exact red and restored-green command:

```sh
env -u TAU_TRACER_SESSION_END TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=command-intent /var/tmp/twr17-session-end-20261024/wasm cargo run --locked -p tracer -- run dist/served dist/tracer
```

Red, exit 1, `I49-red-1.log`:

```text
   FAIL session end during box-plane intent commit prevents exec: relay observes browser socket close during end step; every dialed sshd observes connection end
FAIL: tracer cases failed: session end during box-plane intent commit prevents exec
```

Restored green, exit 0, `I49-green-1.log`:

```text
   PASS session end during box-plane intent commit prevents exec
TRACER PASS
```

**I50** — Remove run_command's stop wrappers around connect, channel opening and exec_record, retaining socket close and the evidence fence. Observe each relay/SSH handshake hold and a sent command; the report must name session end and preserve transmission history. Files: `src/harness/run.rs`.

Exact red and restored-green command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=session-end TAU_TRACER_SESSION_END='closes command at challenge,closes command at verdict,closes command at identification,closes command at auth,running command' /var/tmp/twr17-session-end-20261024/wasm cargo run --locked -p tracer -- run dist/served dist/tracer
```

Red, exit 1, `I50-red-0.log`:

```text
   FAIL session end closes command at challenge: command stopped before intent reports session-end journal refusal
   FAIL session end closes command at verdict: command stopped before intent reports session-end journal refusal
   FAIL session end closes command at identification: command stopped before intent reports session-end journal refusal
   FAIL session end closes command at auth: command stopped before intent reports session-end journal refusal
   FAIL session end closes command at auth-rekey: command stopped before intent reports session-end journal refusal
   FAIL session end closes a running command without DISCONNECT and preserves unresolved replay: sent command reports unresolved with session end and its send history
FAIL: tracer cases failed: session end closes command at challenge, session end closes command at verdict, session end closes command at identification, session end closes command at auth, session end closes command at auth-rekey, session end closes a running command without DISCONNECT and preserves unresolved replay
```

Restored green, exit 0, `I50-green-0.log`:

```text
   PASS session end closes command at challenge
   PASS session end closes command at verdict
   PASS session end closes command at identification
   PASS session end closes command at auth
   PASS session end closes command at auth-rekey
   PASS session end closes a running command without DISCONNECT and preserves unresolved replay
TRACER PASS
```

**I51** — Remove collection's stop wrapper around channel opening/read and unregister its socket before the loop. A sent collection read no longer closes or answers during the held end step. The held-read case remains a control in the same command. Files: `src/harness/run.rs`.

Exact red and restored-green command:

```sh
env -u TAU_TRACER_SESSION_END TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=sent-reads /var/tmp/twr17-session-end-20261024/wasm cargo run --locked -p tracer -- run dist/served dist/tracer
```

Red, exit 1, `I51-red-0.log`:

```text
== session end cancels a sent held read
   [ok] sshd received the read exec while the detached command is still alive
== session end cancels a sent collection read
   [ok] sshd received the read exec while the detached command is still alive
   [FAILED] relay observes browser socket close during end step
   [FAILED] every dialed sshd observes connection end
   sent read reported: {"read_wait_expired":true}
FAIL: the run stopped after 4 cases: sent read report has no calls; cases failed:
```

Restored green, exit 0, `I51-green-0.log`:

```text
   PASS session end cancels a sent held read
   PASS session end cancels a sent collection read
TRACER PASS
```

**I52** — Use the unconditional command job_evidence append instead of job_evidence_unless_stopped, retaining the tracer hold point. Its evidence acquisition follows the end snapshot in the writer queue. Files: `src/harness/run.rs`.

Exact red and restored-green command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=session-end TAU_TRACER_SESSION_END='fences queued command evidence' /var/tmp/twr17-session-end-20261024/wasm cargo run --locked -p tracer -- run dist/served dist/tracer
```

Red, exit 1, `I52-red-0.log`:

```text
   FAIL session end fences queued command evidence append: begun append completes whole; queued append commits nothing; uncommitted job record is reported as unresolved evidence; uncommitted evidence leaves command unresolved after unlock
FAIL: tracer cases failed: session end fences queued command evidence append
```

Restored green, exit 0, `I52-green-0.log`:

```text
   PASS session end fences queued command evidence append
TRACER PASS
```

**I53 — baseline controls.** Restore the `8dbfcee` production bodies in
`src/inference.rs`, `src/store.rs`, `src/lib.rs`, `src/harness/job_read.rs`,
`src/harness/run.rs`, `src/harness/wait.rs` and `src/harness/inference.rs`. Retain only
tracer hold points, the tracer cold-cache helper and the probe argument arity needed to run
the same cases. No session-end production fix remains. After these controls, restore and
compare all seven saved files byte for byte and run the identical commands again.
The authentication and command evidence controls have no rekey or pending data.

Exact baseline and restored command:

```sh
/var/tmp/twr17-session-end-20261024/host test --locked readable_completion_after_session_end_commits_terminal_without_handback -- --nocapture
```

Baseline green, exit 0, `I53-baseline-0.log`:

```text
test store::inference::tests::readable_completion_after_session_end_commits_terminal_without_handback ... ok
```

Restored green, exit 0, `I53-green-0.log`:

```text
test store::inference::tests::readable_completion_after_session_end_commits_terminal_without_handback ... ok
```

Exact baseline and restored command:

```sh
/var/tmp/twr17-session-end-20261024/host test --locked non_success_account_read_sends_no_mint_control -- --nocapture
```

Baseline green, exit 0, `I53-baseline-1.log`:

```text
test store::inference::tests::non_success_account_read_sends_no_mint_control ... ok
```

Restored green, exit 0, `I53-green-1.log`:

```text
test store::inference::tests::non_success_account_read_sends_no_mint_control ... ok
```

Exact baseline and restored command:

```sh
/var/tmp/twr17-session-end-20261024/host test --locked revoke_probe_still_sends -- --nocapture
```

Baseline green, exit 0, `I53-baseline-2.log`:

```text
test store::inference::tests::revoke_probe_still_sends_when_route_await_ends_sessions ... ok
```

Restored green, exit 0, `I53-green-2.log`:

```text
test store::inference::tests::revoke_probe_still_sends_when_route_await_ends_sessions ... ok
```

Exact baseline and restored command:

```sh
env TAU_TRACER_INFERENCE=1 TAU_TRACER_INFERENCE_PHASE=session-end TAU_TRACER_SESSION_END='=session end closes held at challenge,=session end closes held at verdict,=session end closes held at identification,=session end closes held at auth,=session end closes collection at challenge,=session end closes collection at verdict,=session end closes collection at identification,=session end closes collection at auth,=session end completes begun command evidence append,=session end fences bound writer ahead of end snapshot,=revoke cold probe control during session end' /var/tmp/twr17-session-end-20261024/wasm cargo run --locked -p tracer -- run dist/served dist/tracer
```

Baseline green, exit 0, `I53-baseline-3.log`:

```text
   PASS revoke cold probe control during session end
   PASS session end closes held at challenge
   PASS session end closes held at verdict
   PASS session end closes held at identification
   PASS session end closes held at auth
   PASS session end closes collection at challenge
   PASS session end closes collection at verdict
   PASS session end closes collection at identification
   PASS session end closes collection at auth
   PASS session end fences bound writer ahead of end snapshot
   PASS session end completes begun command evidence append
TRACER PASS
```

Restored green, exit 0, `I53-green-3.log`:

```text
   PASS revoke cold probe control during session end
   PASS session end closes held at challenge
   PASS session end closes held at verdict
   PASS session end closes held at identification
   PASS session end closes held at auth
   PASS session end closes collection at challenge
   PASS session end closes collection at verdict
   PASS session end closes collection at identification
   PASS session end closes collection at auth
   PASS session end fences bound writer ahead of end snapshot
   PASS session end completes begun command evidence append
TRACER PASS
```

### Procured inference final verification

The final tree passed on 2026-10-24 with Rust 1.97.1, wasm-bindgen 0.2.127 and rooted
Chromium 154. Every command ran in the foreground, unpiped, with stdout/stderr redirected to
its log under `/var/tmp/twr17-session-end-20261024/` and its exit status inspected. The host
and wasm wrappers are defined in I40–I53 above. The source hashes were unchanged throughout
all twelve commands and are retained in `source-digests.json` beside those logs.

| Gate | Exact command | Exit |
|---|---|---|
| Format | `/var/tmp/twr17-session-end-20261024/host fmt --check` | 0 |
| Host clippy | `/var/tmp/twr17-session-end-20261024/host clippy --locked --all-targets -- -D warnings` | 0 |
| Host tests, pin and bundle checks | `/var/tmp/twr17-session-end-20261024/host test --locked` | 0 |
| Disk check | `python3 spec/prototypes/spec-checks/check-install-disks.py` | 0 |
| Disk baseline negative control | `python3 spec/prototypes/spec-checks/check-install-disks.py --baseline` | 1, required nonzero |
| Served wasm clippy | `/var/tmp/twr17-session-end-20261024/wasm cargo clippy --locked -p tau-web --target wasm32-unknown-unknown --all-targets -- -D warnings` | 0 |
| Tracer wasm clippy | `/var/tmp/twr17-session-end-20261024/wasm cargo clippy --locked -p tau-web --target wasm32-unknown-unknown --all-targets --features tracer -- -D warnings` | 0 |
| Dependency boundary | `/var/tmp/twr17-session-end-20261024/wasm bash scripts/check-adr-0024.sh` | 0 |
| Served build | `/var/tmp/twr17-session-end-20261024/wasm bash scripts/build-web.sh served` | 0 |
| Served absence | `/var/tmp/twr17-session-end-20261024/host run --locked -p tracer -- check-absence dist/served` | 0 |
| Served CSP | `/var/tmp/twr17-session-end-20261024/host run --locked -p tracer -- check-csp dist/served` | 0 |
| Full browser gate, rebuilding both directories | `env -u TAU_TRACER_HOLD_CASE -u TAU_TRACER_INFERENCE -u TAU_TRACER_INFERENCE_END -u TAU_TRACER_INFERENCE_PHASE -u TAU_TRACER_MODE_CASE -u TAU_TRACER_SEED_CASE -u TAU_TRACER_SESSION_END -u TAU_TRACER_SETUP_CASE /var/tmp/twr17-session-end-20261024/wasm bash scripts/tracer.sh` | 0 |

The host suite passed 218 library, 4 bundle, 69 tracer and 3 doc tests. Absence inspected
5 served files against 245 needles. The full run, with every `TAU_TRACER_*` selector unset,
printed `== summary (171 cases)` and `TRACER PASS`, exiting 0. It includes the 41 additional
session-end cases and the rewritten sent-read cases. All companion comparison tests passed;
the witness files were not edited.

`spec/bundle/cors-probe.sh`: **withheld by the no-live-vendor fence**. No live-account check
is claimed. The existing issue-tracker bytes were preserved; twr-ggw.83 and twr-ggw.84 were
left as filed.

The final README consistency command was:

```sh
python3 /var/tmp/twr17-session-end-20261024/check-readme.py
```

It exited 0, matching both documented browser counts and the final summary to the 171 printed
PASS lines, the host totals, 245 absence needles and all 18 red/green command pairs. It also
checked the final source hashes, restored production bytes, preserved issue-tracker bytes,
the clean specification worktree and the required branch.

**Initial README consistency control (E10).** Exact command:

```sh
python3 /var/tmp/twr17-round6.7cnd2U0i/check-readme.py
```

The checker contains:

```python
from pathlib import Path
import re
log=Path('/var/tmp/twr17-round6.7cnd2U0i/final-tracer.log').read_text()
counts=re.findall(r'^== summary \((\d+) cases\)$',log,re.M)
assert len(counts)==1 and '\nTRACER PASS\n' in log, 'full gate has no passing summary'
count=int(counts[0])
readme=Path('README.md').read_text()
documented=[int(n) for n in re.findall(r'(?:The full run defines|unset and runs all) (\d+) cases',readme)]
assert len(documented)==2 and all(n==count for n in documented), f'documented counts {documented} differ from {count}'
stale = 'the browser case ' + 'currently fails'
assert stale not in readme, 'stale progress wording remains'
print(f'README matches the {count}-case passing full gate and contains no stale session-end claim')
```

Restoring the old documented counts produced exit 1:

```text
AssertionError: documented counts [126, 126] differ from 128
```

Restoring the stale session-end progress claim separately produced exit 1:

```text
AssertionError: stale progress wording remains
```

Each control restored and compared the README bytes exactly. Restored checker exit: 0.

### Session goals and tools mutation evidence (G1–G44)

The original G1–G22 commands ran in the foreground, unpiped, redirecting stdout/stderr to
`/var/tmp/tau-ggw14-implementation/G<n>-red.log` and then `G<n>-green.log`. Each production
file was saved before its mutation, restored in a `finally` block, and compared byte for byte
before the identical command ran green. G10 was rerun with the job first so its typed host
outcome explicitly distinguishes held from job-unavailable. Every pair went red and green.

The browser command file `/var/tmp/tau-ggw14-implementation/browser` contains exactly:

```sh
#!/usr/bin/env bash
set -euo pipefail
export TMPDIR=/var/tmp
cd /home/user/p/tau-web-rust
bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh bash scripts/build-web.sh tracer
exec bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh env -u TAU_TRACER_HOLD_CASE -u TAU_TRACER_INFERENCE -u TAU_TRACER_INFERENCE_END -u TAU_TRACER_INFERENCE_PHASE -u TAU_TRACER_MODE_CASE -u TAU_TRACER_SEED_CASE -u TAU_TRACER_SESSION_END -u TAU_TRACER_SETUP_CASE TAU_TRACER_GOALS=1 cargo run --locked -p tracer -- run dist/served dist/tracer
```

It uses the provided web environment, whose exact contents are:

```sh
#!/usr/bin/env bash
# The web job's tool environment, rooted under /var/tmp/tau-web-manager/ggw14/tools (nix out-links + CI's pinned wasm-bindgen 0.2.127).
T=/var/tmp/tau-web-manager/ggw14/tools
export TMPDIR=${TMPDIR:-/var/tmp}
export WB=$T/wbg CLANG=$T/clang LLVM=$T/llvm CHR=$T/chromium
exec nix shell nixpkgs#gcc -c sh -c 'PATH="$WB/bin:$PATH" CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-Clinker-features=-lld CC_wasm32_unknown_unknown=$CLANG/bin/clang AR_wasm32_unknown_unknown=$LLVM/bin/llvm-ar RUSTUP_TOOLCHAIN=1.97.1 CHROME=$CHR/bin/chromium "$@"' sh "$@"
```

G1–G3 and G12 cover record provenance and reuse; G4–G5 cover the four machine-naming tools;
G6 covers dispatch-level no-brief admission; G7–G8 and G19 cover untrusted typing and claimed
authority; G13–G18 independently plant brief/feed substitution, configuration and fetched
authority; G9 covers the credential absence claim; G10 and G20 cover model-tool holds; G11
covers the typed pre-approval barrier; G21–G22 cover both document session-end boundaries.
Held-result content is not asserted by G10 or G20. G9, G10, G19 and G20 were
rerun below with the current checks and the new scratch directory.

**G1 — omit goal session.** Files: `src/goals.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web goal_commits_session_source_once_and_replay_never_reuses_it -- --nocapture
```

Red exit 101. Failing assertion:

```text
called `Result::unwrap()` on an `Err` value: "its event is not one this version reads"
```

Restored bytes identical; same command green exit 0.

**G2 — omit goal source.** Files: `src/goals.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web goal_commits_session_source_once_and_replay_never_reuses_it -- --nocapture
```

Red exit 101. Failing assertion:

```text
called `Result::unwrap()` on an `Err` value: "its event is not one this version reads"
```

Restored bytes identical; same command green exit 0.

**G3 — reuse historical goal in a fresh session.** Files: `src/store/goals.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web goal_commits_session_source_once_and_replay_never_reuses_it -- --nocapture
```

Red exit 101. Failing assertion:

```text
assertion failed: reopened.goal(&fresh).is_none()
```

Restored bytes identical; same command green exit 0.

**G4 — add fifth tool.** Files: `src/goals.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web scripted_turns_use_inference_redaction_fixed_tools_and_untrusted_content -- --nocapture
```

Red exit 101. Failing assertion:

```text
assertion `left == right` failed
```

Restored bytes identical; same command green exit 0.

**G5 — remove required machine.** Files: `src/goals.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web scripted_turns_use_inference_redaction_fixed_tools_and_untrusted_content -- --nocapture
```

Red exit 101. Failing assertion:

```text
assertion failed: body["tools"].as_array().unwrap().iter().all(|t|
```

Restored bytes identical; same command green exit 0.

**G6 — remove acting-tool no-brief gate.** Files: `src/store/goals.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web all_acting_tools_require_no_brief_acceptance_and_a_bound_machine -- --nocapture
```

Red exit 101. Failing assertion:

```text
called `Result::unwrap_err()` on an `Ok` value: ()
```

Restored bytes identical; same command green exit 0.

**G7 — remove document untrusted typing.** Files: `src/goals.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web scripted_turns_use_inference_redaction_fixed_tools_and_untrusted_content -- --nocapture
```

Red exit 101. Failing assertion:

```text
assertion `left == right` failed
```

Restored bytes identical; same command green exit 0.

**G8 — remove tool-output untrusted typing.** Files: `src/goals.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web scripted_turns_use_inference_redaction_fixed_tools_and_untrusted_content -- --nocapture
```

Red exit 101. Failing assertion:

```text
assertion `left == right` failed
```

Restored bytes identical; same command green exit 0.

**G9 — compose held account credential into context after its boundary.** Files: `src/store/inference.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web scripted_turns_use_inference_redaction_fixed_tools_and_untrusted_content -- --nocapture
```

Red exit 101. Failing assertion:

```text
assertion `left == right` failed
```

Restored bytes identical; same command green exit 0. This round's logs are
`/var/tmp/tau-ggw14-round2-20261025/G9-{red,green}.log`.

**G10 — remove job admission hold (rerun with job-only production admission).** Files: `src/goals.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web new_model_jobs_keep_the_command_hold -- --nocapture
```

Red exit 101. Failing assertion:

```text
expected held tool, got JobUnavailable("twr-i6k.5")
```

Restored bytes identical; same command green exit 0. This round's logs are
`/var/tmp/tau-ggw14-round2-20261025/G10-{red,green}.log`.

**G11 — remove typed pre-approval barrier.** Files: `src/store/goals.rs`. Exact command:

```sh
nix shell 'nixpkgs#gcc' -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web lost_create_reaches_model_typed_barrier_before_approval -- --nocapture
```

Red exit 101. Failing assertion:

```text
called `Result::unwrap_err()` on an `Ok` value: Request { target: Entry("fixture"), operation: Create, session: "session-5", requester: Session, facts: Facts { arguments: {}, cost_bound: 0, bundle_commit: "d029ebd9f632696bb027a22559d774d165685947" }, approved: None }
```

Restored bytes identical; same command green exit 0.

**G12 — prefill a fresh goal from history.** Files: `www/boot.js`. Exact command:

```sh
env -u TAU_TRACER_GOAL_CASE /var/tmp/tau-ggw14-implementation/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] fresh bindings have no goal and no prefilled goal input
```

Restored bytes identical; same command green exit 0.

**G13 — accept a runtime brief substitute.** Files: `src/harness/goals.rs`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=card /var/tmp/tau-ggw14-implementation/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] goal refuses runtime brief substitute/configure
```

Restored bytes identical; same command green exit 0.

**G14 — accept a runtime feed-list substitute.** Files: `src/harness/goals.rs`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=card /var/tmp/tau-ggw14-implementation/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] goal refuses runtime feeds substitute/configure
```

Restored bytes identical; same command green exit 0.

**G15 — persist runtime brief configuration.** Files: `www/worker.js`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=card /var/tmp/tau-ggw14-implementation/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] page ignores runtime brief configuration
```

Restored bytes identical; same command green exit 0.

**G16 — persist runtime feed-list configuration.** Files: `www/worker.js`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=card /var/tmp/tau-ggw14-implementation/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] page ignores runtime feed_list configuration
```

Restored bytes identical; same command green exit 0.

**G17 — fetched brief text waives no-brief acceptance.** Files: `src/harness/goals.rs`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=card /var/tmp/tau-ggw14-implementation/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] each acting tool refuses without no-brief acceptance
```

Restored bytes identical; same command green exit 0.

**G18 — fetched feed text waives no-brief acceptance.** Files: `src/harness/goals.rs`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=card /var/tmp/tau-ggw14-implementation/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] each acting tool refuses without no-brief acceptance
```

Restored bytes identical; same command green exit 0.

**G19 — tool output grants authority to the typed tool.** Files: `src/harness/goals.rs`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=context /var/tmp/tau-ggw14-round2-20261025/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] claimed authority grants no typed approval
```

Restored bytes identical; same command green exit 0. This round's logs are
`/var/tmp/tau-ggw14-round2-20261025/G19-{red,green}.log`.

**G20 — remove the shared command hold from exec and jobs (rerun).** Files: `src/dispatch/typed.rs`. Exact command (with the scratch path expanded):

```sh
env TAU_TRACER_GOAL_CASE=hold "$ROUND3/browser"
```

Red exit 1. Failing assertions:

```text
[FAILED] each held request reads its holding job exactly once and never launches or records the requested work
```

Restored bytes identical; same command green exit 0.

**G21 — remove both document post-append/pre-send end checks.** Files: `src/harness/goals.rs`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=document_end /var/tmp/tau-ggw14-implementation/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] no document GET occurs after session end begins during source append
```

Restored bytes identical; same command green exit 0.

**G22 — do not abort an active document request.** Files: `src/harness/goals.rs`. Exact command:

```sh
env -u TAU_TRACER_GOAL_CASE /var/tmp/tau-ggw14-implementation/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] end aborts the document fetch and its loopback connection closes
```

Restored bytes identical; same command green exit 0.

### Session goals and tools follow-up mutation evidence

The following controls ran in the foreground, unpiped. Each production file was saved,
restored in `finally`, and compared byte for byte before the identical command ran green.
Logs, saved bytes and exact exits are in `/var/tmp/tau-ggw14-round2-20261025/`, named
`G<n>-red.log`, `G<n>-green.log` and `G<n>-saved`; the index is `mutations.json`.
The four `a`–`d` controls each independently plant `brief`, `briefs`, `feeds` and `feed_list`,
respectively. The tool controls cover both the call object and its arguments.
G10 is also the job-only admission control for the removed test-only exec path.

The browser command file `/var/tmp/tau-ggw14-round2-20261025/browser` contains exactly:

```sh
#!/usr/bin/env bash
set -euo pipefail
export TMPDIR=/var/tmp
cd /home/user/p/tau-web-rust
bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh bash scripts/build-web.sh tracer
exec bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh env -u TAU_TRACER_HOLD_CASE -u TAU_TRACER_INFERENCE -u TAU_TRACER_INFERENCE_END -u TAU_TRACER_INFERENCE_PHASE -u TAU_TRACER_MODE_CASE -u TAU_TRACER_SEED_CASE -u TAU_TRACER_SESSION_END -u TAU_TRACER_SETUP_CASE TAU_TRACER_GOALS=1 cargo run --locked -p tracer -- run dist/served dist/tracer
```

One preliminary G28 planting attempted to parse the plaintext key-preparation message as a
goal context and stopped at the tracer's 120-second evaluation timeout. It is retained in
`G28-initial-timeout.log` and counts as no evidence. The corrected planting then exposed a
weak check: body and file scans failed, but the SSH scan stayed green because launch bytes
are octal operands. That incomplete control is `G28-initial-incomplete-control.log`.
The SSH scan was strengthened to include octal forms of every needle. G36 proves that scan
against a real composed launch, and the final G28 below fails all three scans. No timed-out
or incomplete control is claimed as a successful pair.

**G23 — stop after dispatch refusal: host hold and typed barrier delivery (rerun).** Files: `src/goals.rs`. Exact command (with the scratch path expanded):

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web held_and_barrier_refused_calls_reach_the_next_turn_then_done -- --nocapture
```

Red exit 101. Failing assertion:

```text
assertion `left == right` failed: dispatch refusal must reach another turn
```

Restored bytes identical; same command green exit 0.

**G24 — stop after dispatch refusal: scripted exec, jobs and typed barrier delivery (rerun).** Files: `src/goals.rs`. Exact command (with the scratch path expanded):

```sh
env TAU_TRACER_GOAL_CASE=barrier "$ROUND3/browser"
```

Red exit 1. Failing assertions:

```text
[FAILED] dispatch result reaches the next turn as that call's untrusted tool output before done
[FAILED] lost create's barrier refuses model create without a record or contact
[FAILED] claimed authority leaves the destructive stop standing
```

Restored bytes identical; same command green exit 0.

**G25 — disable decoded-value scanning: escaped session and account credentials.** Files: `src/redaction.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web escaped_tool_credentials_are_refused_before_dispatch_and_never_enter_history -- --nocapture
```

Red exit 101. Failing assertion:

```text
decoded credential must never be dispatched
```

Restored bytes identical; same command green exit 0.

**G26 — disable decoded-value scanning: escaped minted session key in browser exec.** Files: `src/redaction.rs`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=credential /var/tmp/tau-ggw14-round2-20261025/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] escaped key sends no SSH exec and records no intent
```

Restored bytes identical; same command green exit 0.

**G27 — remove pending-document acceptance and start guards (rerun).** Files: `src/harness/goals.rs`. Exact command (with the scratch path expanded):

```sh
env TAU_TRACER_GOAL_CASE=document_pending "$ROUND3/browser"
```

Red exit 1. Failing assertions:

```text
[FAILED] pending fetch refuses acceptance without a record or inference send
[FAILED] settled fetch permits acceptance
```

Restored bytes identical; same command green exit 0.

**G28 — plant a held account credential in goal context after the request boundary.** Files: `src/store/inference.rs`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=context /var/tmp/tau-ggw14-round2-20261025/browser
```

Red exit 1. Failing assertions:

```text
[FAILED] model context contains no held credential in any needle encoding
[FAILED] every received SSH command excludes every held credential
[FAILED] machine job files exclude every held credential
```

Restored bytes identical; same command green exit 0.

**G29a — admit runtime brief on the tool path.** Files: `src/goals.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web tool_refuses_every_runtime_brief_feed_member -- --nocapture
```

Red exit 101. Failing assertion:

```text
tool must refuse runtime brief in call
```

Restored bytes identical; same command green exit 0.

**G29b — admit runtime briefs on the tool path.** Files: `src/goals.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web tool_refuses_every_runtime_brief_feed_member -- --nocapture
```

Red exit 101. Failing assertion:

```text
tool must refuse runtime briefs in call
```

Restored bytes identical; same command green exit 0.

**G29c — admit runtime feeds on the tool path.** Files: `src/goals.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web tool_refuses_every_runtime_brief_feed_member -- --nocapture
```

Red exit 101. Failing assertion:

```text
tool must refuse runtime feeds in call
```

Restored bytes identical; same command green exit 0.

**G29d — admit runtime feed_list on the tool path.** Files: `src/goals.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web tool_refuses_every_runtime_brief_feed_member -- --nocapture
```

Red exit 101. Failing assertion:

```text
tool must refuse runtime feed_list in call
```

Restored bytes identical; same command green exit 0.

**G30a — admit runtime brief on the inference path.** Files: `src/inference.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web inference_refuses_every_runtime_brief_feed_member -- --nocapture
```

Red exit 101. Failing assertion:

```text
inference must refuse runtime brief
```

Restored bytes identical; same command green exit 0.

**G30b — admit runtime briefs on the inference path.** Files: `src/inference.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web inference_refuses_every_runtime_brief_feed_member -- --nocapture
```

Red exit 101. Failing assertion:

```text
inference must refuse runtime briefs
```

Restored bytes identical; same command green exit 0.

**G30c — admit runtime feeds on the inference path.** Files: `src/inference.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web inference_refuses_every_runtime_brief_feed_member -- --nocapture
```

Red exit 101. Failing assertion:

```text
inference must refuse runtime feeds
```

Restored bytes identical; same command green exit 0.

**G30d — admit runtime feed_list on the inference path.** Files: `src/inference.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web inference_refuses_every_runtime_brief_feed_member -- --nocapture
```

Red exit 101. Failing assertion:

```text
inference must refuse runtime feed_list
```

Restored bytes identical; same command green exit 0.

**G31a — admit runtime brief on the goal path.** Files: `src/harness/goals.rs`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=card /var/tmp/tau-ggw14-round2-20261025/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] goal refuses runtime brief substitute/configure
```

Restored bytes identical; same command green exit 0.

**G31b — admit runtime briefs on the goal path.** Files: `src/harness/goals.rs`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=card /var/tmp/tau-ggw14-round2-20261025/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] goal refuses runtime briefs substitute/configure
```

Restored bytes identical; same command green exit 0.

**G31c — admit runtime feeds on the goal path.** Files: `src/harness/goals.rs`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=card /var/tmp/tau-ggw14-round2-20261025/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] goal refuses runtime feeds substitute/configure
```

Restored bytes identical; same command green exit 0.

**G31d — admit runtime feed_list on the goal path.** Files: `src/harness/goals.rs`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=card /var/tmp/tau-ggw14-round2-20261025/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] goal refuses runtime feed_list substitute/configure
```

Restored bytes identical; same command green exit 0.

**G32a — admit runtime brief on the page path.** Files: `www/worker.js`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=card /var/tmp/tau-ggw14-round2-20261025/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] page ignores runtime brief configuration
```

Restored bytes identical; same command green exit 0.

**G32b — admit runtime briefs on the page path.** Files: `www/worker.js`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=card /var/tmp/tau-ggw14-round2-20261025/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] page ignores runtime briefs configuration
```

Restored bytes identical; same command green exit 0.

**G32c — admit runtime feeds on the page path.** Files: `www/worker.js`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=card /var/tmp/tau-ggw14-round2-20261025/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] page ignores runtime feeds configuration
```

Restored bytes identical; same command green exit 0.

**G32d — admit runtime feed_list on the page path.** Files: `www/worker.js`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=card /var/tmp/tau-ggw14-round2-20261025/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] page ignores runtime feed_list configuration
```

Restored bytes identical; same command green exit 0.

**G33 — remove the goal record shape guard.** Files: `src/store.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web goal_replay_refuses_positional_array -- --nocapture
```

Red exit 101. Failing assertion:

```text
malformed goal must refuse unlock
```

Restored bytes identical; same command green exit 0.

**G34 — clear mode acceptance when the hostile command finishes.** Files: `src/store.rs`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=context /var/tmp/tau-ggw14-round2-20261025/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] claimed authority leaves mode_acceptances unchanged
```

Restored bytes identical; same command green exit 0.

**G35 — continue past bound done.** Files: `src/goals.rs`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=context /var/tmp/tau-ggw14-round2-20261025/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] done ends the loop at two completions
```

Restored bytes identical; same command green exit 0.

**G36 — omit octal credential needles for received SSH bytes.** Files: `tracer/src/goal_cases.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tracer received_launch_scan_finds_context_hex_inside_printf_octal -- --nocapture
```

Red exit 101. Failing assertion:

```text
scan must detect the credential in received launch bytes
```

Restored bytes identical; same command green exit 0.

### Session goals and tools mutation evidence (G37–G44)

The original round-three controls ran in the foreground, unpiped, with output redirected to
logs. Their saved bytes,
`G<n>-red.log`, `G<n>-green.log` and `mutations.json` are under
`/var/tmp/tau-ggw14-round3-20261025-evidence/`. Each source was restored and compared byte
for byte before the same command ran green. G40–G41 below retain those commands and use
the canonical scratch path:

```sh
ROUND3=$(realpath /var/tmp/tau-ggw14-round3-20261025-evidence)
```

`$ROUND3/browser` contains the exact browser command file printed in the follow-up evidence
above: build the tracer directory through the provided web environment, then run the
loopback tracer with `TAU_TRACER_GOALS=1` and the named focused selector. Every other
selector is unset in that command file.

The first G41 control stayed green because the fixture's dial-spacing refusal stopped the
second dispatch before it could add a read. That run is retained as
`G41-initial-masked.log` and counts as no successful mutation pair. The hold case now removes
fixture dial spacing around each loop and restores it even when the loop returns an error.
The corrected G41 below fails the exact read count for every held request. G40 and G41
repeat only held or refused dispatches. G20, G23, G24 and G27 were rerun with their changed
checks; their entries above now give this round's commands and failures.

G37–G39 and G42–G44 below show round-four reruns under
`/var/tmp/tau-ggw14-round4-M79FdJCU/`. G40–G41 retain their round-three evidence.
After fixing the response scan, the lossy escaped-call case no longer isolates admission.
G42 now primes the inference key and directly checks original credential-bearing calls at
admission, independently of the response scan. The escaped valid-UTF-8 and lossy-UTF-8
loop cases remain and now also require refusal before dispatch. G44 covers the expanded
README grammar examples. Every rerun went red and restored green.

**G37 — forward the entire error-turn report: host outcome.** Files: `src/goals.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web finished_error_turn_reports_only_safe_metadata -- --nocapture
```

Red exit 101. Failing assertion:

```text
outcome contains only safe metadata: {"body":"{\"choices\":[{\"message\":{\"tool_calls\":[{\"untrusted\":\"response text\"}]}}]}","call":13,"finished":true,"status":500}
```

Restored bytes identical; same command green exit 0. Logs and saved bytes:
`/var/tmp/tau-ggw14-round4-M79FdJCU/G37-red.log`, `/var/tmp/tau-ggw14-round4-M79FdJCU/G37-green.log` and
`/var/tmp/tau-ggw14-round4-M79FdJCU/G37-source.bin`.

**G38 — forward the entire error-turn report: page messages.** Files: `src/goals.rs`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=outcome /var/tmp/tau-ggw14-round4-M79FdJCU/browser
```

Red exit 1. Failing assertions:

```text
[FAILED] no page message carries a response body
[FAILED] terminal page outcome contains only safe metadata
[FAILED] finished refused turn is labelled by its refusal before its status
```

Restored bytes identical; same command green exit 0. Logs and saved bytes:
`/var/tmp/tau-ggw14-round4-M79FdJCU/G38-red.log`, `/var/tmp/tau-ggw14-round4-M79FdJCU/G38-green.log` and
`/var/tmp/tau-ggw14-round4-M79FdJCU/G38-source.bin`.

**G39 — restore the unresolved page label for a finished error turn.** Files: `www/boot.js`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=outcome /var/tmp/tau-ggw14-round4-M79FdJCU/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] finished non-2xx turn is labelled by its finished status
```

Restored bytes identical; same command green exit 0. Logs and saved bytes:
`/var/tmp/tau-ggw14-round4-M79FdJCU/G39-red.log`, `/var/tmp/tau-ggw14-round4-M79FdJCU/G39-green.log` and
`/var/tmp/tau-ggw14-round4-M79FdJCU/G39-source.bin`.

**G40 — dispatch held or refused calls twice: host counter.** Files: `src/goals.rs`. Exact command (with the scratch path expanded):

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web held_and_barrier_refused_calls_reach_the_next_turn_then_done -- --nocapture
```

Red exit 101. Failing assertion:

```text
assertion `left == right` failed: each scripted call dispatches exactly once
```

Restored bytes identical; same command green exit 0.

**G41 — dispatch held or refused calls twice: exact browser read count.** Files: `src/goals.rs`. Exact command (with the scratch path expanded):

```sh
env TAU_TRACER_GOAL_CASE=hold "$ROUND3/browser"
```

Red exit 1. Failing assertions:

```text
[FAILED] each held request reads its holding job exactly once and never launches or records the requested work
```

Restored bytes identical; same command green exit 0.

**G42 — remove the independent admission credential scan.** Files: `src/store/goals.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web admission_scan_refuses_original_tool_credentials -- --nocapture
```

Red exit 101. Failing assertion:

```text
assertion `left == right` failed: admission must independently refuse a credential-bearing call
  left: Ok(())
 right: Err("tool credential boundary")
```

Restored bytes identical; same command green exit 0. Logs and saved bytes:
`/var/tmp/tau-ggw14-round4-M79FdJCU/G42-red.log`, `/var/tmp/tau-ggw14-round4-M79FdJCU/G42-green.log` and
`/var/tmp/tau-ggw14-round4-M79FdJCU/G42-source.bin`.

**G43 — restore the permissive document URL predicate at replay.** Files: `src/goals.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web goal_replay_refuses_invalid_source_and_document_url -- --nocapture
```

Red exit 101. Failing assertion:

```text
malformed goal must refuse unlock
```

Restored bytes identical; same command green exit 0. Logs and saved bytes:
`/var/tmp/tau-ggw14-round4-M79FdJCU/G43-red.log`, `/var/tmp/tau-ggw14-round4-M79FdJCU/G43-green.log` and
`/var/tmp/tau-ggw14-round4-M79FdJCU/G43-source.bin`.

**G44 — make the independent reader accept every HTTPS authority.** Files: `tracer/src/reader.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tracer goal_document_url_requires_a_valid_host_and_port -- --nocapture
```

Red exit 101. Failing assertion:

```text
assertion `left == right` failed: reader grammar: https://127.0.0.1:invalid/document: Ok(())
  left: true
 right: false
```

Restored bytes identical; same command green exit 0. Logs and saved bytes:
`/var/tmp/tau-ggw14-round4-M79FdJCU/G44-red.log`, `/var/tmp/tau-ggw14-round4-M79FdJCU/G44-green.log` and
`/var/tmp/tau-ggw14-round4-M79FdJCU/G44-source.bin`.

### Session goals and tools round-four mutation evidence (G45–G48)

Each command ran in the foreground, unpiped, with output redirected to the named scratch
log; its exit was printed immediately afterwards. Every source was restored from its saved
bytes and compared byte for byte before the same command ran green. The per-pair JSON
files under `/var/tmp/tau-ggw14-round4-M79FdJCU/` record commands, exits, durations and
source hashes. The `browser` command there builds the tracer directory through the supplied
web environment and runs the loopback tracer with `TAU_TRACER_GOALS=1`; the named outcome
selector remains set and all other selector families are explicitly unset. The browser
request fence stays active. An initial G45 control restored strict JSON parsing alone and
stayed green (exit 0), because the equality guard independently refused the call. Its logs,
source and result are retained as `G45-initial-masked-red.log`,
`G45-initial-masked-source.bin` and `G45-initial-masked-json` in the same scratch directory;
it is not counted as a successful pair. The corrected G45 below also restores the old skip
of comparison when the original body has no parseable calls. It fails the launch assertion;
the check additionally requires no tool dispatch, no intent and withheld history.

**G45 — restore strict UTF-8 parsing and the original skipping behavior.** Files: `src/store/inference.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web literal_lossy_utf8_tool_credentials_are_refused_before_dispatch -- --nocapture
```

Red exit 101. Failing assertion:

```text
decoded credential must never be dispatched
```

Restored bytes identical; same command green exit 0. Logs and saved bytes:
`/var/tmp/tau-ggw14-round4-M79FdJCU/G45-red.log`, `/var/tmp/tau-ggw14-round4-M79FdJCU/G45-green.log` and
`/var/tmp/tau-ggw14-round4-M79FdJCU/G45-source.bin`.

**G46 — restore finished-status precedence over a refusal.** Files: `www/boot.js`. Exact command:

```sh
env TAU_TRACER_GOAL_CASE=outcome /var/tmp/tau-ggw14-round4-M79FdJCU/browser
```

Red exit 1. Failing assertion:

```text
[FAILED] finished refused turn is labelled by its refusal before its status
```

Restored bytes identical; same command green exit 0. Logs and saved bytes:
`/var/tmp/tau-ggw14-round4-M79FdJCU/G46-red.log`, `/var/tmp/tau-ggw14-round4-M79FdJCU/G46-green.log` and
`/var/tmp/tau-ggw14-round4-M79FdJCU/G46-source.bin`.

**G47 — allow a port above 65535 in the harness predicate.** Files: `src/goals.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tracer goal_document_url_requires_a_valid_host_and_port -- --nocapture
```

Red exit 101. Failing assertion:

```text
reader rejects harness-admitted URL https://127.0.0.1:65536/document
```

Restored bytes identical; same command green exit 0. Logs and saved bytes:
`/var/tmp/tau-ggw14-round4-M79FdJCU/G47-red.log`, `/var/tmp/tau-ggw14-round4-M79FdJCU/G47-green.log` and
`/var/tmp/tau-ggw14-round4-M79FdJCU/G47-source.bin`.

G48 covers both a quoted credential whose removal repairs malformed JSON and a two-backslash
credential occurring in the wire encoding of one decoded character. Neither case may launch,
record an intent or retain the altered call in history.

**G48 — remove the comparison of original and released tool calls.** Files: `src/store/inference.rs`. Exact command:

```sh
nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked -p tau-web tool_calls_altered_by_byte_boundary_are_refused_whole -- --nocapture
```

Red exit 101. Failing assertion:

```text
a byte-altered call must never be dispatched
```

Restored bytes identical; same command green exit 0. Logs and saved bytes:
`/var/tmp/tau-ggw14-round4-M79FdJCU/G48-red.log`, `/var/tmp/tau-ggw14-round4-M79FdJCU/G48-green.log` and
`/var/tmp/tau-ggw14-round4-M79FdJCU/G48-source.bin`.

### Session goals and tools round-three verification

The round-three final implementation passed on 2026-10-25 with Rust 1.97.1,
wasm-bindgen 0.2.127 and Chromium 154. Every command ran in the foreground, unpiped,
with stdout/stderr redirected to its named log under
`/var/tmp/tau-ggw14-round3-20261025-evidence/`; its exit was echoed immediately afterwards.
`gates.json` records each exact command, exit and elapsed time.

| Gate | Exact command | Exit |
|---|---|---:|
| Host format | `nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 fmt --check` | 0 |
| Host clippy | `nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 clippy --locked --all-targets -- -D warnings` | 0 |
| Host tests, pin and bundle | `nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked` | 0 |
| Disk check | `python3 spec/prototypes/spec-checks/check-install-disks.py` | 0 |
| Disk baseline negative control | `python3 spec/prototypes/spec-checks/check-install-disks.py --baseline` | 1 (required nonzero) |
| Served wasm clippy | `bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh cargo clippy --locked -p tau-web --target wasm32-unknown-unknown --all-targets -- -D warnings` | 0 |
| Tracer wasm clippy | `bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh cargo clippy --locked -p tau-web --target wasm32-unknown-unknown --all-targets --features tracer -- -D warnings` | 0 |
| Dependency boundary | `bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh bash scripts/check-adr-0024.sh` | 0 |
| Served build | `bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh bash scripts/build-web.sh served` | 0 |
| Served absence | `bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh cargo run --locked -p tracer -- check-absence dist/served` | 0 |
| Served CSP | `bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh cargo run --locked -p tracer -- check-csp dist/served` | 0 |
| Full browser gate | `bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh env -u TAU_TRACER_HOLD_CASE -u TAU_TRACER_INFERENCE -u TAU_TRACER_INFERENCE_END -u TAU_TRACER_INFERENCE_PHASE -u TAU_TRACER_MODE_CASE -u TAU_TRACER_SEED_CASE -u TAU_TRACER_SESSION_END -u TAU_TRACER_SETUP_CASE -u TAU_TRACER_GOALS -u TAU_TRACER_GOAL_CASE bash scripts/tracer.sh` | 0 |

The host suite passed 237 library tests, 4 bundle tests, 72 tracer tests and 3 doc tests.
Both companion comparisons passed; the pinned specification and its witness files remain
unchanged. Served absence checked 5 files against 248 needles. The full browser gate,
with all ten `TAU_TRACER_*` selectors explicitly unset, printed `== summary (183 cases)`,
183 PASS lines and `TRACER PASS`, exit 0, in 1199.6 seconds.
No final gate timed out. The browser request fence remained active in both builds.
`spec/bundle/cors-probe.sh` was **withheld by the no-live-vendor fence**.

G37–G44 each passed red/restored-green. G20, G23, G24 and G27 were rerun and their entries
updated: twelve pairs this round, all saved sources restored byte for byte. The initially
masked G41 control is described above and is not counted as a successful pair.

Files changed this round; all earlier work remains in place:

- `README.md`
- `src/goals.rs`
- `src/store/goals.rs`
- `tracer/src/goal_cases.rs`
- `tracer/src/reader.rs`
- `www/boot.js`

`src/harness/goals.rs` and `src/dispatch/typed.rs` were changed only for controls and restored
byte for byte. No dependency, session worker, approval act, new send path, commit, amend,
push, pull request or tracker write was added. The protected session-end passages, stops,
5000 ms bound and existing session-end report texts remain unchanged. No BLOCK was encountered.

This round's implementation readings for the closing comment are:

- Outcomes carry only the safe typed metadata members and fixed refusal text described above;
  successful bound completion reports only `done: true`. Finished error turns display their
  status and end without dispatch.
- A 2xx body that does not parse, has zero tool calls or has more than one ends the loop
  before dispatch, alongside the already documented invalid-call cases.
- At round three both credential scans remained, with the admission scan covering escaped
  credentials recovered from invalid UTF-8. Round four supersedes that reading: the response
  scan now inspects original lossy completion text before any replacement.
- Document entry and replay use the conservative HTTPS DNS/IPv4 and decimal-port grammar
  above, also checked by the independent reader. Excluded forms include empty hosts,
  malformed ports, user information, IPv6, encoded internationalized labels, trailing dots
  and alternative numeric hosts.

The previous implementation readings remain in the goals section. Final consistency command:

```sh
python3 /var/tmp/tau-ggw14-round3-20261025-evidence/consistency.py
```

It exits 0 only when protected text, tracker bytes, branch, pin, witness bytes, twelve
mutation pairs, all gate exits and both case-count sites agree with the recorded evidence.

### Session goals and tools final verification (round four)

The final implementation passed on 2026-10-25 with Rust 1.97.1, wasm-bindgen 0.2.127 and
Chromium 154. All commands ran after the last source edit and formatting, in the foreground,
unpiped, with stdout/stderr redirected to `gate-<name>.log` under
`/var/tmp/tau-ggw14-round4-M79FdJCU/`; each exit was echoed immediately afterwards.
`gates.json` records every exact command, exit and elapsed time. `final-source.json` records
the source hashes checked after the gates. An earlier sequence was stopped after its active
host test command finished, before the final boundary refinement; its format, clippy and
host-test logs are retained as `pre-final-*.log` and are superseded by the runs below.

| Gate | Exact command | Exit |
|---|---|---:|
| Host format | `nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 fmt --check` | 0 |
| Host clippy | `nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 clippy --locked --all-targets -- -D warnings` | 0 |
| Host tests, pin and bundle | `nix shell nixpkgs#gcc -c env TMPDIR=/var/tmp RUSTFLAGS=-Clinker-features=-lld cargo +1.97.1 test --locked` | 0 |
| Disk check | `python3 spec/prototypes/spec-checks/check-install-disks.py` | 0 |
| Disk baseline negative control | `python3 spec/prototypes/spec-checks/check-install-disks.py --baseline` | 1 (required nonzero) |
| Served wasm clippy | `bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh cargo clippy --locked -p tau-web --target wasm32-unknown-unknown --all-targets -- -D warnings` | 0 |
| Tracer wasm clippy | `bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh cargo clippy --locked -p tau-web --target wasm32-unknown-unknown --all-targets --features tracer -- -D warnings` | 0 |
| Dependency boundary | `bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh bash scripts/check-adr-0024.sh` | 0 |
| Served build | `bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh bash scripts/build-web.sh served` | 0 |
| Served absence | `bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh cargo run --locked -p tracer -- check-absence dist/served` | 0 |
| Served CSP | `bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh cargo run --locked -p tracer -- check-csp dist/served` | 0 |
| Full browser gate | `bash /var/tmp/tau-web-manager/ggw14/tools/web-env.sh env -u TAU_TRACER_HOLD_CASE -u TAU_TRACER_INFERENCE -u TAU_TRACER_INFERENCE_END -u TAU_TRACER_INFERENCE_PHASE -u TAU_TRACER_MODE_CASE -u TAU_TRACER_SEED_CASE -u TAU_TRACER_SESSION_END -u TAU_TRACER_SETUP_CASE -u TAU_TRACER_GOALS -u TAU_TRACER_GOAL_CASE bash scripts/tracer.sh` | 0 |

The host suite passed 240 library tests, 4 bundle tests, 72 tracer tests and 3 doc tests.
Both companion comparisons passed with the pinned specification and witness files unedited.
The full browser gate explicitly unset all ten `TAU_TRACER_*` selectors and printed
`== summary (184 cases)`, 184 PASS lines and `TRACER PASS`, exit 0, in
1162.07 seconds. No final gate timed out. The request fence stayed
active in both builds. `spec/bundle/cors-probe.sh` was **withheld by the no-live-vendor fence**.

G45–G48 passed red/restored-green, as did the rerun G37–G39 and G42–G44: ten successful
pairs this round. Every saved source matches the final bytes. The initial masked G45 is
recorded separately above and is excluded. The response scan covers literal and escaped
credentials in lossy completion text, including transient request credentials after holdings
clear. The byte-comparison check additionally covers escaping and malformed-JSON repair.
The reader checks the README grammar independently and rejects the harness port mutant.

Files changed this round, preserving all earlier work:

- `README.md`
- `src/goals.rs`
- `src/harness/goals.rs`
- `src/store/goals.rs`
- `src/store/inference.rs`
- `tracer/src/aggregator.rs`
- `tracer/src/goal_cases.rs`
- `tracer/src/reader.rs`
- `www/boot.js`

This round's new implementation readings for the closing comment are:

- Original completion text is decoded lossily before the response scan, exactly as in the
  loop. Original and released tool-call values must agree, including the absence of a
  parseable original call; redaction never creates executable marker text. Both credential
  scans remain, and refusal withholds the whole call from later history.
- An unresolved outcome is labelled only as unresolved. Otherwise refusal takes precedence
  over finished status; finished outcomes without refusal use their status, and an outcome
  without these members uses the neutral `Goal loop ended.` label.

The existing document URL grammar has the same accepted set after removal of the dead `0x`
test. Acceptance guards the pending fetch; the loop-start guard is defence in depth, and its
admission errors retain their actual reason. The send-path coverage table remains accurate:
no new send path, dependency, switch, approval act or session worker was added. The protected
session-end sentences, stops, report texts and 5000 ms bound remain unchanged. No branch
switch, commit, amend, push, pull request or tracker write occurred. No BLOCK was encountered.

Final consistency command:

```sh
python3 /var/tmp/tau-ggw14-round4-M79FdJCU/consistency.py
```

It checks protected text, tracker bytes, branch, pin and witness cleanliness, the nine changed
files, final source hashes, ten mutation pairs, all gate exits and both 184-case count sites.


### Surviving hidden sessions and scan consumers

`STA-23` says "An ordinary visibility-only hide MUST NOT end or pause an unlocked session, clear its runtime authority, or invalidate its approvals."
It also says "Before further ordinary sends or actionable result publication after a processed suspension or interruption, the surviving worker MUST validate its current authority, bindings, holds, connection state and scan readiness."
And "A begun durable append MUST finish whole rather than be cancelled partway."

The page distinguishes ordinary hide, processed freeze/resume and full end. Ordinary hide
keeps the worker, exclusive Web Lock, Store mutex owner, bindings, context and approvals.
Processed freeze invalidates pending ordinary continuations and clock continuity, closes safe
transports and preserves unresolved effects. A return never retransmits a possibly sent operation.
A revalidated new operation uses the same surviving session. Only a retained demonstrably unsent
mint intent can continue unchanged under its original call and limits; it never creates another attempt.

`ARC-31a` says "Ordinary hide alone neither invalidates established continuous clock evidence nor pauses time."
It also says "A fresh observation MUST NOT change the recorded origin or expiry, reset consumption, or revive an ended session."

The shared clock consumer uses exact rational outward intervals and both independent wall/monotonic
discrepancy checks, with strict admission before original expiry. Usage is summed as exact decimal
text, including precision finer than hundredths. Expiry or established cap exhaustion ends only the
affected session. Safe late accounting and revocation do not authorize further actions. A narrow
journaled authenticated time read can repair clock validity while ordinary authority is withheld.
The page shows original requested expiry, observed consumption, unknown clock validity and actual
session end separately. Production minting remains refused: the consumed pin has no reviewed real
issuer profile. Confirmed fixture tuples and time sources establish only synthetic consumer evidence;
the per-session chooser and its own admission evidence remain twr-ggw.83's work.

`SEC-5` says "Unscanned bytes MUST be withheld; matches become visible redaction markers naming the secret, never silent omissions."
It also says "For row 23, retained or reloaded scan material is the same independent random key and encrypted reference already recorded, never seed-derived, regenerated on hide or replaced by machine-reported bytes."

The read-only loader authenticates identified required references in the prescribed encrypted
representation and retains unavailable material as an unarmed barrier. It never discovers authority
from a file or machine output. The byte consumer compares the prescribed keyed digest over every
raw window before decoding, retaining cross-chunk windows and protecting nested legacy hex copies,
normal tool output, collection, historical/uncommitted reports and transcript-only release. Existing
held-credential protection remains in the same boundary. Reload does no encryption or lifetime write.
Lock/end clear working copies without retiring encrypted references.

Host cases live in `clock::tests`, `inference_limits::tests`, `store::lifecycle_tests` and
`store::scan::tests`. Browser cases in `tracer/src/lifecycle_cases.rs` exercise real page lifecycle
messages, hidden scheduled model/tool work, the same original reference after reload, the retained
writer, clock repair and stale-result refusal. Existing session-end, seed, goal, delivery and job
cases retain full-end and uncertainty coverage. These are desktop loopback fixtures, not physical
Android scheduling or live-issuer evidence; no background survival duration is promised.

The synthetic scan producer runs only in isolated fixture stores. Its encrypted bytes supply no
production enrollment, reservation, causal replay, counted-encryption or lifetime-event evidence.
Named marker insertion into legacy job evidence supplies no intrinsic custody or completed protected
finalization. twr-ggw.23 retains that protocol and atomic page/cache release; these cases claim no
CNF-95(g) or complete persistent-protocol acceptance. Entry/funding, real profile admission and
physical-device evidence remain separately owned.


`STG-20` says "An approval **stands** from its record until its reset is dispatched, a matching withdrawal is recorded, or the session it was rendered for ends; several approvals for an entry stand independently."
It also says "A withdrawal whose append fails is not recorded (`STA-3`), so the approval still stands."

The dedicated standing-approval consumer journals the original reset identity, entry, rendering
session and facts. It requires a newer dispatched activation, the immediately preceding durable
confirming read, the same binding and the normal typed barrier. Hide changes none of those facts.
The page offers withdrawal for each standing approval separately; ended-session approvals remain
visible as no longer usable, without a withdrawal offer. A processed freeze invalidates an old
reset continuation, and a possibly sent reset has no automatic retry. A begun append remains whole.
The lifecycle fixtures supply explicitly synthetic dedicated adapter facts and exercise this same
consumer and typed dispatch boundary. No dedicated vendor adapter or stage-3 admission is supplied;
there is no dedicated approval path for the stage-1 vendor. The existing comparison partition and
its dedicated qualifications remain unchanged. No fixture reset establishes a physical disk wipe.

The final inference send also compares the current scan-reference revision with the revision
that protected the actual request body, after acquiring the Store owner. Arming or reloading a
reference while a request waits cannot approve bytes scanned under an earlier reference set.
A fresh operation scans those same bytes with the now-armed material. Empty placeholder route
validation and the narrow clock read carry no scanned payload and retain their separate current
authority checks. Browser cases exercise this last send boundary, an unchanged original mint
through actual time verification, and dedicated approvals across actual app Lock and worker restart.
