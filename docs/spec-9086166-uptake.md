# Specification uptake at 9086166

This inventory compares `66762f1a63f43977f4ef407c194a73e1ae71458a` with
`9086166b0ee62387da6440da059f5b89f01a0d8d`. Ownership was checked against the
implementation's committed `.beads/issues.jsonl` at
`4e637238cb5de42ef57fa348e39e34bf46042449`, including descriptions, comments and
reference-only neighbors. Tracker records and historical comments remain unchanged.
The earlier [66762f1 inventory](spec-66762f1-uptake.md) remains a dated record.

## Normative effects and implemented boundary

[Protected browser evidence v1 §3a](../spec/docs/design/protected-evidence-v1.md#3a-protected-operation-evidence),
[STA-24](../spec/03-state-and-recovery.md) and
[STG-21a](../spec/06-first-stage.md) distinguish absent, retained and received-present
withheld vendor identities. Canonically withheld order identities confirm nothing and
settle nothing. Genuine comparisons occur before omission. Qualifying earlier durable
receipts and associations create permanent cross-entry unavailable-identity risk in the
global VendorMachine literal namespace. A new order for another entry refuses before
intent/send, with the exact earlier risk record numbers. Disposition, ended references,
restart and independent same-entry adoption erase none of those risks.

Association admission checks approved entry, target kind, allocation reservation,
admitted mappings and retained qualifying identity evidence. Exact admitted duplicates
append nothing; legacy duplicate events remain readable no-ops. Known cross-entry literal
conflict refuses with `identity_conflict`. Otherwise unavailable targets and unknown aliases
are quarantined, with all applicable earlier risk records. Quarantine remains inspectable,
supplies no operational mapping and never serves as an order settlement constituent.
Both retained constituent orders work across replay; an association never rewrites an
older receipt's historical settled vector. Wrong provenance, validation or correlation
gains no authority through protection. Separately required receipts remain recordable.

This ticket implements those shared Dispatch/Store predicates, closed raw and stored
legacy/protected-v1 arms, truthful relations, custody and whole-fact validation,
transactional preview/append/replace, authenticated prefix replay, diagnostics and scoped
input clearing. From the first risk, new VendorMachine associations require the protected
arm. AllocationIndex storage remains legacy and reservation-checked. Failed append changes
no live state; landed-then-error latches the old writer and fresh replay applies the landed
evidence once. Diagnostics have `committed:false` and no journal number or historical
settled vector. Clearing recoverable input aliases asserts no physical-memory erasure.

[§4](../spec/docs/design/protected-evidence-v1.md#4-intrinsic-substitution-facts-and-names)
also governs the read-only helpers: additional display omissions preserve historical
relations, admission/reason, alias checks, number and settlement. Copied custody names may
be withheld while keeping their association identities. Complete merged tables reindex
unavailable-name and whole-fact markers from association arrays. Unavailable names are not
restored or recursively expanded; contradictory retained names refuse. Durable custody
and canonical intent/setup/approval records remain unchanged. These helpers do not
implement the complete enclosing-object finalizer, origin propagation, scan-reference
protocol or atomic browser/cache release. Full CNF-95(g) remains outstanding.

The listing predicate in STG-21a requires a complete authenticated listing, exact recorded
account/image/key/resource correspondence, one qualifying matching candidate, retained
usable identity and proved ownership admission. Withholding cannot remove a matching
candidate from the count or make retained evidence for another entry unassociated.
Same-entry adoption establishes its own identity, never reconstructs an erased receipt.
Concrete listing/adoption and adapter demonstrations remain separately owned. Shared
fixtures do not complete CNF-112 or demonstrate cleanup, billing cessation, destruction,
ended secret duties, real issuer enforcement or device behavior.

## Companion comparison

The runtime file is `docs/design/dispatch-witnesses-v8.json`, schema 8, namespace
`TauWeb.Dispatch`. The bound is still three events over eight distinct alphabet members,
filtered to distinct request call ids. Enumeration membership is recomputed and checked,
including complete coverage and unchanged rescue-first/reboot-second routing.

| Partition | Named traces | Enumerated traces | Behavioral coverage here / remaining owner |
|---|---:|---:|---|
| stage1 | 52 | 286 | Production Store/Dispatch, this uptake; existing shared core owner twr-ggw.8 |
| dedicated | 54 | 184 | Complete vocabulary/shape validation; production behavior remains twr-i6k.3 |
| reboot | 12 | 0 | Complete vocabulary/shape validation; production behavior remains twr-i6k.11 |
| Total | 118 | 470 | Partition union; no full three-owner behavioral claim |

Schema 8 adds `returned_withheld`, `associate_evidence`, `quarantined`,
`identity_exclusions`, typed `identity_exclusion` refusals and the `identityExclusion`
guard/pair. Every routed step requires its event-specific outcome, including on admitted
controls. Unknown, absent and inapplicable members fail before comparison. Structural
mutations are parser-contract controls, distinct from deliberate semantic defects.

All 110 earlier named traces and their pairs remain, including both admitted
`orderAssociation` traces differing at steps 2 and 3. The eight new named trace objects all
run in stage1: the excluded-order refused/admitted pair, the shared
`quarantine_has_no_target` / `retained_quarantine_conflict` object,
`withheld_association_excludes`, `failed_quarantine_append_changes_nothing`,
`unavailable_receipt_never_settles`, `unavailable_uncorrelated_creates_no_risk`, and
`unavailable_risk_survives_disposition`. The identityExclusion admitted side differs at
step 4. Fourteen stage1 guard pairs are required. These are comparisons of harness
knowledge and grant no external-state, concurrency or device evidence.

The driver explicitly maps zero-based abstract durable occurrences to production journal
numbers. Initial setup associations are constituent occurrences of the setup approval;
the setup shell, seed ceremony and fixture prerequisites add no abstract records. Extra
associations, authenticated starting calls/dispositions, appended requests, observations,
receipts and association evidence advance the ordinal. Concrete support records for one
abstract read do not multiply it. Refusals, failed appends and duplicate mappings do not
advance it. Replay retains the same mapping. Independent small-journal regressions cover
reads, failed/no-append neighbors and starting calls/dispositions before later risk.
Inference remains the existing core-only comparison; this does not widen dedicated or
reboot behavior.

## Adopted procured-session contract, still to implement

The source is [ARC-31a](../spec/01-architecture.md), with lifecycle consequences in
[STA-23](../spec/03-state-and-recovery.md), credential custody in
[SEC-5](../spec/04-security-model.md), protected mint acceptance in
[Protected browser evidence v1 §3](../spec/docs/design/protected-evidence-v1.md#mint-acceptance-extension),
and demonstrations in [CNF-95(g)](../spec/07-conformance.md).

The cap uses integer hundredths of the evidenced account unit, exactly 0.01–100.00;
lifetime uses whole minutes 1–1440. Offered defaults are 0.10 and 15 minutes. Supported
choices intersect the pinned profile's evidenced envelope. Decimal validation is exact,
with no floating-point rounding, clamping or implicit currency conversion; observed spend
may have finer precision. Explicit confirmation binds choice generation, session,
account-credential journal generation, profile, amount/unit and lifetime. A durable mint
intent consumes one attempt even after loss, refusal, withholding or a fenced send.
Changes require fresh confirmation before intent; afterward they cannot replace the attempt.

Lifetime begins at the original issuer-time lower bound after confirmation and the recorded
top-up-off read. Original expiry is fixed by checked addition and never renewed by delay,
hide, funding, refresh or reply. The profile supplies authenticated fresh timestamp interval
`[a,b]`, monotonic endpoints `m0,m1` and exact finite rational clock rates. At `m >= m1`,
`L=floor(a+r_min*(m-m1))`, `U=ceil(b+r_max*(m-m0))`; admission requires `U < expiry`.
Supported absolute expiry is 1–253402300799 whole Unix UTC seconds. Both discrepancy
baselines matter: wall versus monotonic elapsed since the latest issuer anchor and since
the last valid paired reading, with disagreement greater than five seconds in either
direction making validity uncertain. There is no separate five-second interval-width or
observation-age limit. Suspension defeating continuity requires revalidation. A fresh
observation can establish remaining eligibility of the same key/expiry, never a renewal
or revived ended session.

Issuer acceptance independently reports the same identifier's cap/unit/expiry with dated
profile semantics and response/readback provenance (fixed profile unit only where evidenced).
The issuer must enforce one nonresetting aggregate cap across concurrent, settled and
in-flight charges; the profile must evidence expiry's admission/in-flight consequences.
Lost replies are unaccounted spend, never zero or refunded. Account-balance refusal differs
from cap exhaustion. At expiry/exhaustion/end, ordinary authority ceases at the next
execution opportunity; late evidence remains accounting/cleanup only. No local reservation,
remote cancellation promise, deadline scheduling promise or second credential tier is added.

New protected mint terminals are version 2, with immutable `requested`, independent
accepted facts, per-field provenance and `acceptance:absent|exact|different|unverifiable`.
Whole-fact slots are status, key_id and the three accepted fields. A withheld accepted
field supplies no usable authority even with historical `exact`; retained identifiers
remain usable only for the existing cleanup path after acceptance refusal. Requested and
observed expiry stay distinct, including discrepancies. Version-1 mint terminals remain
readable without invented acceptance or promotion. Other protected terminal kinds stay v1.

The new [synthetic profile](../spec/bundle/inference-profile-fixture-v1.md) is dated test-only
prose. It supplies no production origin/endpoint or real issuer evidence. Production
minting under the adopted contract requires a separately reviewed real pinned profile.
This uptake implements none of this session-limit, clock, confirmation, issuer-acceptance
or hide/Lock feature and claims no CNF-69 completion. twr-ggw.83 remains open/needs-triage
with its historical decision request; the adopted contract resolves specification policy,
not implementation readiness. The separately retained twr-ggw.89 assignment owns ordinary
hide versus explicit Lock. That record is absent in this clone and is neither imported nor
created. twr-ggw.23 retains protected terminal/finalizer integration. Account entry/funding
and live acceptance remain .84/.51's; existing funding qualifications are preserved.

## Open citation inventory and remaining owners

All identifiers below name committed open records in this clone, except the explicitly
absent .89 above. Citations include description and comment references. No record's
status, labels, dependencies, description or comments are changed by this inventory.

| Committed record | Affected citations / comments | Exact remaining work |
|---|---|---|
| twr-ggw | STG-21, STA-24, CNF-95; comments 38/85 | Stage-1 scenario and completion across all owners |
| twr-ggw.20 | ARC-43, STA-24; comments 43/88 | Concrete delivery findings/read evidence; protected publisher integration through .23 |
| twr-ggw.21 | STA-24, CNF-29/104/110; comments 44/89 | Fixture create/payment, sibling cards and shared exclusion at actual dispatch |
| twr-ggw.23 | SEC-5, ARC-43, CNF-95; comments 45/130 | Complete protected finalizer, intrinsic substitution, scan references/fenced keys, actual sinks and atomic browser/cache release; remaining CNF-95(g) |
| twr-ggw.25 | SEC-5, CNF-95, STA-24 | Re-arm/paste, immediate cards, one-act post-reinstall reads; no reference-duty discharge |
| twr-ggw.28 | SEC-5, CNF-95, STA-24; comment 47 | Restore labels, reference re-arm and release, through .25/.23 |
| twr-ggw.29 | STA-24, STA-23; no new comment | Replace migrations, held state and confirmed key removal; no synthetic target from unavailable identity |
| twr-ggw.31 | SEC-5, STA-24, STG-21a/CNF-112; comment 92 | Deterministic abandonment, truthful billing/identity/cleanup uncertainty; .40 supplies stop/deletion predicates |
| twr-ggw.32 | STA-24, STG-21, SEC-12; comment 48 | Concrete signed authenticated listing/reads, predicate evidence and vendor-TLS invoices |
| twr-ggw.36 | STG-21a, ARC-43, STA-24 | Service findings and independent survival reads; no vendor restart confirmation from job evidence |
| twr-ggw.40 | SEC-5, STA-24, STG-21a, CNF-95 | Stop/renewal/deletion adapters and full predicate/duty evidence; no unavailable wire literal |
| twr-ggw.41 | STA-24, STG-21a/CNF-112; comments 53/95/126 | Verified HTTP order, exact listing adoption/ownership filter and invoices; comment 53's undecided T50 is historical |
| twr-ggw.43 | SEC-5, CNF-23/109, ARC-43; comments 75/96 | Published-key pin admission and existing pins comparison; operation evidence grants no pin |
| twr-ggw.45 | STA-24, STG-20, ARC-22; comments 13/54/74/97 | Reinstall publication predicates, installation advance/retirement and first contact; retain twr-qso recovery dependency |
| twr-ggw.48 | SEC-5, ARC-22; comments 57/99 | LNVPS scan-ahead/role-5 carried-key recovery, still pending T44; no guessed identity or discharge |
| twr-ggw.49 | SEC-5, STA-24, CNF-95/112 and admission inventory; comment 129 | Record new shared evidence and missing feature/live evidence separately; full admission remains here |
| twr-ggw.51 | CNF-69, STG-10/12/21; comments 58/100 | Real account/device/live creation, placement and re-entry checks; no fixture or issuer enforcement credit |
| twr-ggw.52 | SEC-5, CNF-95, STG-21; comment 59 | Phone recovery/completion ledger, with revised protected obligations and unchanged service evidence |
| twr-ggw.66 | SEC-5, STA-24/23 | Operator disposition/late evidence/refusal display; projection integration preserves useful calls and uncertainty |
| twr-ggw.67 | ARC-43, STA-24; comments 60/70/79 | Tool refusal results, attributed protected copies and exact risk/call references |
| twr-ggw.83 | ARC-31a, CNF-69; no comments | Implement adopted exact limits/confirmation/clock/profile/acceptance contract; metadata reconciliation remains separate |
| twr-ggw.84 | ARC-31a, SEC-5, CNF-69/70; no comments | Account entry/funding under existing qualification; account-credit change renews no session |
| twr-ggw.87 | ARC-43, STA-24; no comments | Operator approval of exact typed-operation facts, separate from disposition and mapping evidence |
| twr-i6k | Dispatch v7 references; comments 64/102/131 | Current consumer is v8/schema8; stage split persists; dated v6 references are historical |
| twr-i6k.2 | SEC-5, STA-24; comments 14/103 | Robot tunnel/registration/rescue/reset predicates, immediate durable activation read; no mutation-receipt exception |
| twr-i6k.3 | Dispatch v7/schema7, STA-24/ARC-43; comment 15's v2 | Full dedicated 54/184 production comparison and integrated rescue/blocked-append evidence; keep all new schema members even empty |
| twr-i6k.10 | STA-24/23, STG-20 | Approval/withdrawal and refusal, distinct from disposition, with protected display integration |
| twr-i6k.11 | Dispatch v7/schema7, ARC-43/STA-24 | Full reboot 12/0 production comparison, boot-change collection and pending delivery-check hold |

Reference-only and downstream neighbors retain their assignments:

- twr-ede (comments 36/83/127), .33 (49/93/128) and .34 cite ARC-43: checklist
  implementation/promotion and concrete reads stay theirs. The unchanged checklist bytes
  supply no new acceptance. .24 (46/78), .50 and .73 (73/80) retain re-entry/service duties.
- .18 retains selection/provenance/trust layers; .22 (90) retains set and binding behavior;
  .26 retains publisher enrollment/hosting and .27 (91) recovery-sheet custody. .38 retains
  the minimum, .47 (56/98) role-5 derivation/deletion and .46 (55) the T44 pin. No new
  placement, protocol or role-5 implementation is supplied here.
- .54 (18/31) and .76 retain worker/Lock and landed-append duties; .70 (101) and .75 retain
  job observation deduplication and incomplete-read truth. .85 retains cold-probe timing
  repair with .89 coordination. .86 and .88 retain goal eligibility/outcome duties.
- Dedicated .5 retains install/artifact and harness-job requirements; .6 (65/104) missing
  metadata recovery; .7 (66/105) physical milestone; .8 (106) installation identity;
  .9 confirmed root relabel/key removal. Protected evidence does not replace those checks.
- twr-g1h (37/84), twr-qso, twr-x3k and twr-ni0 retain external vendor-identity,
  recovery-decision, funded-account/phone and LNVPS-funds prerequisites. .77/.78/.79/.80/
  .81/.82, relay .55/.56, hosting twr-ew2, tunnel .1, brief promotion .4/twr-68d and
  external twr-oa6 have no newly changed substantive contract here; their qualifications
  and independent evidence remain. Closed records remain historical.

## Unchanged source bytes and compiled status

The following SHA-256 values were recomputed from both exact Git objects and matched.
Witnesses and credential vectors are runtime test inputs, never compiled bundle inputs.

| Source path | SHA-256 at both pins |
|---|---|
| `bundle/artifact-alpine.toml` | `2f45d068fc4010f01da24cfc9b8f1f12200905b64d087fc60d78acfa0b40fe0b` |
| `bundle/inference.toml` | `81fed0b31b23d039e51034c7b9eb2b3ab373d0000fe6d38bddb8309a254e6e7c` |
| `bundle/lockdown.toml` | `3d3bc22140b79b5a558c530ee53b46533ff608356ec4a1343cbc63d481d34453` |
| `bundle/timing.toml` | `dddb94f5be8f27dfec08785efbb8237488067b8b790926aa9bc1a80f4c831c7c` |
| `docs/briefs/01-install.md` | `283816b3506cc299529f893b0581bc3b888ea974d1066060db3e65c4a92d581d` |
| `docs/tenants/ad-hoc/profile.md` | `2da388b67b2053cf87eb42cb53bc1fe3f15ff53231ed8716bcf91d77d81f30eb` |
| `docs/tenants/btc-policy/profile.md` | `6693c4a3474780a878e19c2050e9954844f9678e94ed1e2e2feed93053783657` |
| `docs/tenants/lnrent/profile.md` | `fc3f07bcc0af33dcb588920731f02a688676a9331508eb1edacfb96de8b95210` |
| `docs/design/allocation-witnesses-v2.json` | `e1d18a76bf5c9c6821cff866e5cad0fd44469a05270ccdc2f2e75b6a5f4fcbe3` |
| `docs/design/declaration-witnesses-v1.json` | `35f6e0f7082980b678004360805d647804de0f599d67f07d13a4bf276a19b2d8` |
| `docs/design/pins-witnesses-v5.json` | `875a8391966df8309ac225cb1119a7a215b1f89119773a703fadb3a518afaa2f` |
| `docs/design/relay-witnesses-v1.json` | `95d2fbcb11ac92c4fbb3c1f44bcc756cf480c4ecdb4f30baccc7122d84a72b9a` |
| `docs/design/credential-vectors-v1.json` | `c0e0d19358b40d27fc1572493fdfdcb90f6cfe100a1d68aaa92f35587df635df` |

The four TOMLs are compiled unchanged. All three tenant profile sources are unchanged and
compiled as profiles, including the ad-hoc profile used by stage1; source inclusion does
not implement a tenant's later-stage flows. The sole install brief remains draft and is
not promoted or compiled. `bundle/inference-profile-fixture-v1.md` is prose, skipped by
build.rs's TOML-only bundle loader, and supplies no executable production profile.

Five existing formal-marker blocks are byte-identical: the receipt mapping in
`03-state-and-recovery.md`, the credential role table, the delivery declaration table,
and the syntax illustrations in `CONTEXT.md` and the specification README. The last two
are illustrations, not additional normative rendered tables. No existing region changed.

## Complete fifteen-path delta

Computed with `git -C spec diff --no-renames --name-status` between the two exact pins:

```text
M	01-architecture.md
M	03-state-and-recovery.md
M	04-security-model.md
M	06-first-stage.md
M	07-conformance.md
M	CONTEXT.md
A	bundle/inference-profile-fixture-v1.md
D	docs/design/dispatch-witnesses-v7.json
A	docs/design/dispatch-witnesses-v8.json
M	docs/design/protected-evidence-v1.md
M	docs/design/witness-file-v1.md
M	tools/check-controls.sh
M	tools/formal/TauWeb/Dispatch.lean
M	tools/formal/Witnesses.lean
M	tools/test_pins_control_diagnostics.py
```

The numbered requirements carry the identity/admission and procured-session changes above;
CONTEXT and witness-file-v1 name v8 and its expanded grammar. Protected-evidence-v1 carries
the canonical receipt/association construction, custody/projection and mint-v2 contracts.
Dispatch.lean and Witnesses.lean carry the amended companion and schema-8 emission.
check-controls.sh updates dispatch controls and retains parser/diagnostic coverage;
test_pins_control_diagnostics.py updates those specification diagnostic checks. These are
specification artifacts, not implementation or external-state acceptance. No specification
source or witness outcome is edited by this uptake.
