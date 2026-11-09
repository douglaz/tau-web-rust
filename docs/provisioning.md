# Bounded browser provisioning

The served page can approve one fixed or custom LNVPS offer, create that machine once,
request its initial Lightning invoice, and hand its published host-key pin to the existing
configuration runner. This is a PoC integration, with `coverage.complete` still false.
Local fixture success does not establish production CORS, stock, reachability or a live checkpoint.

Complete the local-store and seed-backup ceremony, then enter the dedicated, already verified
provider HTTPS origin and account's 64-hex private key. Entry fields clear on transfer; the admitted origin is shown again without credentials. Only the dedicated
worker validates and holds the usable key; Lock, reload and worker loss require re-entry.
Resume is bound to the saved public account identity. This operator-supplied account deliberately
departs from ADR-0042: role-5 derivation, verification automation and vendor-account recovery
are deferred.

Fetch offers and images, explicitly choose a fixed or custom offer and unencrypted Arch image,
and review the normalized provider origin alongside the exact current configuration and charge.
Changing the configured origin before approval discards the previous selection; approval carries
the reviewed origin as well as the exact displayed terms. Custom resources use the documented JSON
fields, with memory/disk in bytes; every requested range is checked against the fetched offer.
Hourly credit plans and encrypted images are unsupported. Approve the charge, class and maintained
access, and supply the existing v1 relay URL. Approval re-fetches the offer and price; a change
requires another review and approval. Approval carries the displayed configuration snapshot;
missing or stale consent cannot approve a newer selection still waiting for its page report.
Approval reserves the machine and relay identities durably.
An existing enrolled machine or outstanding purchase prevents a new purchase.

Create / Refresh registers only the derived SSH public half, refreshes the selected catalogue,
image and custom quote as applicable, then saves a pre-order inventory and create intent before
sending the approved order. Changed terms pause before create and require explicit approval of
the displayed replacement terms. This approval retains the same procurement, machine, account,
relay, class, access and registered SSH-key identities; reload preserves the pending review.
Once create is possibly sent, approval cannot change those terms or clear its uncertainty.
The comparison is bounded and supplies no atomic price or stock guarantee.
The encrypted intent is committed before sending.
Once an operation may have been sent, neither a timeout nor a reload enables its retry. A lost
registration response pauses: the documented SSH-key list has no public-key material with which
to prove a match. A lost create response uses list/detail evidence, the before inventory, key id,
image, template/resources, region, charge and creation time. Zero, multiple, incomplete or
conflicting candidates preserve uncertainty. Image association compares stable identity and
configuration, excluding the provider's changing popularity statistic. Refresh can discover
delayed evidence. Advertised CPU architecture/manufacturer constraints and required feature sets
must be evidenced by the returned template; a reported host architecture must also agree with the
image. Missing required proof, contradictory CPU data or changed advertised limits pause.
Offers must include the documented limits object; a missing object is incomplete evidence and
is refused before selection or approval, including during journal replay. An empty object means
uncapped. Transfer allowances compare presence as well as value: an approved unmetered offer cannot acquire
a numeric allowance, and malformed or null allowances refuse admission. Custom association retains every inherited performance cap and its uncapped semantics; an explicit
selected network speed overrides only the network cap. Missing or conflicting caps also refuse
reconciliation, later readiness and journal replay.
Creation-time evidence permits the documented 60-second authentication clock skew and the bounded
60-second action, including its journal and dispatch work: provider creation must be within 60
seconds before to 120 seconds after the saved local intent instant. This supplements before-inventory, registered-key and full-configuration
evidence; it never establishes association by time alone. Associated VM and payment identities
remain immutable; bounded reconciliation
does not establish continuous or account-wide duplicate discovery.

Creation returns a VM, without an invoice. The page first reads that VM's payment history.
It then reads the same VM's authenticated status and nonmutating one-period Lightning quote,
which supplies the actual payment amount, currency, period seconds, tax and processing fee.
Review that displayed quote before using the explicit initial-invoice button. A fixed or custom
plan may be priced in EUR/USD; the Lightning quote supplies its BTC payment terms without a local
exchange-rate or calendar-duration calculation. The quote and its VM identity are durable.
Before issuance the page reads history first and freshly compares the current quote against the
displayed saved terms. The click carries that exact displayed quote snapshot; missing or stale
approval is refused, including if a concurrent Refresh updated the saved quote before its report
reached the page. Missing, changed or unavailable terms send no invoice; changed terms are
saved for fresh review and a later explicit click. Refresh can update a quote before issuance.
This bounded comparison supplies no atomic pricing guarantee.
Only that explicit button may issue one invoice for the first approved period. The saved quote
and invoice intent precede the request. Once issuance is possibly sent, the quote is immutable;
lost responses reconcile history against it without requoting or reissuing. A single existing
paid or unpaid payment is reused only if a saved or authenticated one-period quote establishes
its exact VM, amount, currency, period and fees. Foreign, upgrade, conflicting, unproved or
ambiguous evidence pauses. Expired invoices remain paused with the same identities.
Pay externally using the displayed invoice; amount, currency, expiry, tax and processing fee
come from the authenticated payment. The displayed automatic-renewal state is the provider's
report, including unknown; this integration does not change it.

Refresh observes payment and running state. Empty or unusable published keys pause. The supported
key family is Ed25519, preferred by the current SSH client; the public key's wire encoding and
curve point are checked, its SHA-256 fingerprint is derived locally and compared with the
publication. Multiple distinct Ed25519 keys pause rather than guess. The saved provenance names
the Purchase-bound provider origin, VM, creation evidence and published keys. Handoff records the same
machine identity, validated allocated IPv4 with CIDR removed, port 22, user `arch`, whole-script
`sudo -n`, relay, class and access approvals. Target/pin conflicts refuse replacement.
The pin is retrieved from the provider's hypervisor scan, not attested. It trusts the provider
and anyone able to answer on the machine's address inside that provider's network at scan time.
This bounded flow selects one supported published key; full family/history qualification under
CHN-R7 is deferred, alongside vendor-account recovery and renewal-policy mutation.

Enroll the displayed relay public key separately with the relay operator. Provider SSH-key
registration does not enroll a relay pass. Configure inference and Start session for the handed-off machine, enter the goal and
verification commands, accept it, propose the installation declaration, approve its requirements
card and Resume. The existing task, verification and detached-job collection path remains in use.
Only successful verification completes a task. Procurement and task state are separate; task
Stop task cannot erase an uncertain create or stop remote effects or billing. Handoff reload
replays the target without ordering. Lock retires the execution and clears working keys; an
unended configuration session retains its machine. Unlock restores that original session and
collects any recorded job before further inference. Selected End stops future session-authorized
browser work after its durable append; already accepted remote work may continue.

## Protocol and bounds

The worker uses HTTPS fetch to the operator-entered origin, CORS mode, omitted credentials,
no cache and refused redirects. Entry admits only `https://host[:port]` with a DNS host or IP
literal and at most a root slash. It normalizes host spelling, removes the root slash and default
port 443, and refuses userinfo (even empty), query/fragment delimiters, non-root paths, escapes,
backslashes, whitespace/control repair, malformed IP literals and invalid ports before configuration
changes or provider contact. No origin probe is made. The provider must serve the existing API at
its origin root without redirects; IPv6 origin syntax does not add IPv6 machine targets.
Approval saves the reviewed origin in the Purchase. Every subsequent provider read or mutation,
including catalogue refresh and published-key provenance, uses that bound origin. Editing the
entry, key re-entry, reload, Resume and reapproval cannot redirect it. Missing or explicitly invalid stored origins are refused.
There is no proxy.
NIP-98 events bind the exact URL, method and SHA-256 of each transmitted body. A fresh random
nonce makes same-second reads distinct. Private key, header, event and signature protection is
separate from inference structural admission. Account-key scan protection is memory-only and rebuilt
on re-entry. Only request scan fingerprints are encrypted and committed before request dispatch,
and restored on journal replay. No private-key scan metadata is persisted. A failed append sends no request. Request material remains protected after a lost response and worker loss;
no key, authorization, signed event or signature bytes are retained in those records.
Retained request fingerprints share the existing finite scan-work budget; exhaustion pauses
publication rather than releasing incompletely protected values, and reload does not discard them.
Signature custody includes the decoded 64-byte
signature so base64 and uppercase/mixed hexadecimal aliases are protected too. Both credential families protect new response,
publication and journal boundaries; unsafe identity/evidence is refused rather than repaired.
Operator-authored purchase authority is checked with decoding-aware admission before approval or
identity allocation, including active and retained inference credentials and required scan material.
The exact serialized entry is checked again before encryption. Diagnostics are fixed strings.
Provider credential entry and reads refuse while a command response is pending, preserving the
existing response protection reservation until publication completes.

The consumed success envelope is `{data: ...}`. Routes are:

| Operation | Route |
|---|---|
| Offers, images | `GET /api/v1/vm/templates`, `GET /api/v1/image` |
| Custom quote | `POST /api/v1/vm/custom-template/price` |
| Public SSH key | `POST /api/v1/ssh-key`, read-only `GET /api/v1/ssh-key` after uncertainty |
| Create | `POST /api/v1/vm` or `POST /api/v1/vm/custom-template` |
| Inventory/status | `GET /api/v1/vm`, `GET /api/v1/vm/{id}` |
| Payment evidence | `GET /api/v1/vm/{id}/payments?limit=100&offset=0`, `GET /api/v1/payment/{id}` |
| Initial billing quote (read-only) | `GET /api/v1/vm/{id}/renew/quote?method=lightning&intervals=1` |
| Initial invoice only | `GET /api/v1/vm/{id}/renew?method=lightning&intervals=1` |

Only `GET /api/v1/vm/{id}/payments?limit=100&offset=0` consumes a payment-row array inside
the single response envelope: `{"data":[...]}`. Nested pagination objects are refused, including
`{data: VmPayment[], total, limit, offset}`. The existing array type and 128-entry bound apply
first; 129 or more rows receive the generic provider-response refusal. Fewer than 100 rows
form a complete first page; 100–128 rows pause with "Payment history incomplete; Refresh without
issuing another invoice." and cannot issue an invoice. Completeness does not establish suitability:
two or more rows remain ambiguous, and row identity and payment checks still apply.

Vendor documentation describes `PaginatedResponse<VmPayment>`, but LNVPS source at `10266e58`
and `8352f114` returns `ApiResult<Vec<ApiVmPayment>>` through `ApiData::ok`, with no total.
The upstream VM payments route is deprecated in favor of `/api/v1/subscriptions/{id}/payments`;
this PoC keeps the VM route. No other route or response-envelope rule changes.

LNVPS `10266e58` and `8352f114` assign the VM's `subscription_id` at creation, while vendor
documentation says `null/omitted if never paid`. The page does not treat that field as billing
evidence. Any payment-history row follows the existing suitability rules, a saved invoice intent
prevents reissuance, and a present, non-null `expires` on the VM status read at the invoice click
prevents initial issuance even with empty history.

LNVPS `10266e58` returns nanosecond payment timestamps in the invoice reply and whole seconds
in later reads. The page compares `created` and `expires` to the whole UTC second, dropping
fractions, while payment id and invoice data remain exact.

The page does not invent a payment-type field: VM linkage, creation, exact saved quote amount/currency/period/fees,
`is_upgrade` and Lightning data establish suitability. Plan-price units are millisats for BTC and
cents for EUR/USD. The authenticated Lightning quote supplies BTC millisats and the seconds for
one approved billing interval; the page assumes no day/month/year length and reconstructs no FX.
Unknown or inconsistent terms pause. Quotes create no invoice, payment or charge.

Each exchange has a 15-second timeout and 256-KiB body cap. Each explicit action has a 60-second
and 16-request bound, measured with a monotonic clock independent of wall-clock corrections.
The exchange timer uses the smaller of 15 seconds and the action's remaining
time, cancelling pending headers or body reads and releasing the store for explicit recovery.
A possibly sent mutation stays uncertain after cancellation; a late response cannot authorize it.
Arrays are limited to 128 entries; create reconciliation permits at most
eight account VMs before pausing. Explicit actions have a one-second pace floor; readiness and
payment never busy-poll or call the mutating invoice route as a poll. Freeze aborts waits and
invalidates continuations. Late results cannot revive ended authority. Unknown state stays paused.

## Local checks

Build `dist/tracer` and the native `tracer` fixture first. With a Chrome executable on `CHROME`
and OpenSSL on PATH, run `node scripts/check-provisioning.mjs fixed` (or use
`nix shell nixpkgs#openssl -c node scripts/check-provisioning.mjs fixed`). Other scenario names are
listed at the top of that script. Native protocol/state tests use `cargo test --locked provisioning`.

The browser checks serve the ordinary page and dedicated worker over loopback HTTPS, keeping
the page CSP unchanged and applying it to the worker response too. A second HTTPS port serves
the documented provider schemas. An independent verifier checks BIP-340 signatures, event ids,
URL/method/body binding, freshness, nonce uniqueness, Origin, CORS preflight and omitted cookies.
The checks separately report application fetch dispatches per durable mutation intent, every raw
HTTP transmission, exact signed transport replay rejections and accepted mutation effects.
Registration, fixed/custom create and initial invoice each permit at most one application dispatch
per intent, including after uncertainty and reload. A browser may retransmit identical signed
bytes after a lost response. The local verifier compares the complete accepted authorization,
method, exact URL and body, then rejects its reused event id before another effect. Other
authorization or schema failures remain failures. Dispatch sensitivity controls include a second
invocation with identical signed bytes, which still counts as two application dispatches.
This bounded fixture flow depends on the provider's documented one-use event-id rule; it makes
no claim about deployed replay protection or universal at-most-once transport. A replay refusal
leaves the original outcome unknown and its saved intent retained for read-only reconciliation.
Passwords are empty before DOM/durable scans. Decoded journal inspection checks for credential
occurrences without exporting entries or secrets.

Each run creates a fresh isolated profile and self-signed certificate below `target/`, pins only
that certificate's SPKI for that browser process, and removes exactly its own temporary directory.
No system trust is changed. Only the `tracer` build exports `test_procurement_origin`, which accepts
loopback HTTPS origins for older controls. Origin-entry scenarios omit that hook, enter the
field through the ordinary page and observe an independent second loopback stub for wrong-origin
non-contact. The fixture retains actual browser fetch and the provider adapter. Release absence checks reject the hook and test hold markers. The ordinary
`served` build has none of those capabilities or fixture credentials.

The local relay fixture maps only the documentation address `192.0.2.10:22` to its own ephemeral
loopback sshd. It separately enrolls the public relay key, checks the actual host pin and executes
the existing sudo-wrapped runner in its own scratch directory. A fixture-only sudo shim models
the approved elevation without changing the product's emitted bytes. No external VM is contacted.
