# Specification uptake at 66762f1

This inventory compares specification `d029ebd9f632696bb027a22559d774d165685947` with
`66762f1a63f43977f4ef407c194a73e1ae71458a`, and reads the committed implementation tracker
at `abbb914da6a592f70fa3b0cfeb76741670381e77`, including descriptions, comments and named
file/version references. Historical comments retain their original revision. This is an
uptake inventory, not a stage-completion record.

## Contract changes and remaining ownership

| Group | Actual source change and new meaning | Uptake and remaining owner |
|---|---|---|
| V: operation evidence (#26) | STA-5 retry classes; STA-24/ARC-43 distinct read and exact-call receipt authority; STG-21 exact account/email verification; new STG-21a order/list/key/stop/restart/renewal/reinstall/deletion predicates; ARC-22/SEC-5 destruction duties; TRU-E1/ADR-0042 source-derived transfer/purge races and later un-delete gap; new CNF-112 and revised CNF-23/29/53/95/104. | .39 implements shared approved binding, durable receipt/extra association, replay and stage1 comparison only. .21 owns create workflow; .32/.40/.41/.43/.45/.48 own concrete adapters and evidence. .36/.50/.73 retain delivery/service evidence; .23/.25 retain secret duties. T50 is specification-complete, not adapter/live-complete. |
| K: fixed checklist (#24) | bundle/lockdown.toml and ADR-0051 settle checks, question/rendering and concrete listener/outbound/unit/enablement/linger/boot reads; ARC-43 exits and missing binaries become findings, held/refused reads prove nothing. OPN-14/T42 keep implementation and fresh-image work open. Declaration inbound includes local sockets; outbound uses fixed CIDR/any form, rejects DNS; default credentials other than none wait for a measurable read. | .33/.34/.36/.50/.73 and twr-ede keep implementation/read/fresh-image ownership. Parsing a compiled bundle alone is not checklist uptake. |
| R: relay discovery/recovery (#25) | CHN-19/SEC-8/TRU-A2 introduce compiled publisher key and public starting set, signed high-water retention, timestamp/id ordering, withdrawal/expiry/future distinctions, byte-exact /v2/ challenge/AUTH URL binding, no fallback or implicit identity migration. STA-14/16/17/22a/22b and credential companion add payload v4 locators/discovery, explicit v3 direct-URL conversion; holder key remains distinct. | .26 and external relay/deployment owners; .27/.28/.29 recovery. bundle/relay-discovery.toml has no selected usable values yet. Historical /v1/ relay companion and allocation projections do not certify discovery, /v2/ or complete-sheet merging. |
| H: publisher hosting (#27, 03fce70) | CHN-11 selects k3s pod, process-local TLS via L4 passthrough/dedicated public port and no logging proxy/sidecar/history. ARC-41/CHN-16/16a qualify equal-view claims by eligible target/source. Independent workload egress is mandatory; precisely declared private resolver TCP/53 is outside the second wall if connector-usable, never a tunnel permission. CNF-25/58/81/87 and new CNF-113 require truthful unavailable coverage and bound artifact/configuration/deployment/live records. | .26 already records these obligations against merged relay 49309df54dea3841f3cb1a37527f8d4ec9b5f1ab. .49/.51 and external deployment retain admission/live duties. Required missing deployment/live evidence stays pending; no relay/cluster change here. |
| P: package policy (#29) | ARC-25a/CNF-67/ADR-0002 select release stock signature policy, required repository-package signatures and permitted unsigned local files under effective optional policy. Raw literal filter is bounded; free shell can bypass and harmless matches can be refused. No new recurrent package inventory/policy delivery read is owed. | src/modes.rs already matches LF splitting, ASCII-whitespace comment handling, case-sensitive maximal word tokens, directive/equals suffix, six lowering tokens and first-match form. src/harness/run.rs checks after binding/before contact; Store::append repeats under writer before hold/intent; check_signature commits one target/form refusal and uses failure latch. No matcher edit here. .79/.80/.18/.49/.51 retain disclosure, controls and native accounting. |
| L: lifecycle (#30) | STA-23/ARC-2/31a, SEC-5 row 23, STG-10/12/20 and CNF-7/29/40/69/82/86/95/102 distinguish scheduled hidden continuation, processed freeze, irreversible end and actual loss. Original approvals/writer/bindings/context/scan references persist; expiry/cap never renew; stale sends/results must be fenced. | A1 remains outstanding under existing .89, whose saved assignment is in implementation metadata commit dedda25cdcee5ce60e8dcacda92dcd3b4a946ad2. Its metadata has not landed in this clone; no duplicate issue or edge is created. www/boot.js still locks on ordinary hide. .83/.84/.85/.49/.51 coordination remains; old green hide cases do not demonstrate A1. |
| E: occurrence custody and protected browser evidence (#31/#32) | ARC-43/SEC-5 and CNF-16/94/95 distinguish carried occurrences from demonstrated permitted structural/cryptographic provenance, protect whole representations/junctions, and refuse unsafe required facts before effects. New protected-evidence-v1 defines jobs/reports/name associations, intrinsic substitution facts, atomic repair batches, immutable runtime closures, encrypted scan blobs and counted attempt fences. Credential format/STA-23/CNF-82 explicitly add fresh version-2 local envelopes/AAD and protected legacy-read-only eligibility. | All are prerequisites for separately reviewed .23 uptake and its consumers, not implemented here. This change preserves the existing v1 journal envelope/record bytes; it does not claim the newly specified fenced-key protocol, protected reports, atomic page batches or scan custody conformance. No rejected placement draft is restored. |
| Recovery backlog (#28, bc135c7) | Specification tracker adds a decision-gap issue only; no normative recovery behavior changes. | twr-qso and .44/.45 remain blocked on the third-rung decision. |

The P comparison is source inspection only. It does not establish native signature behavior,
stock effective policy, current CORS, deployed family reachability, physical phone behavior
or any live vendor result. No live probe or external operation was run for this uptake.

## Dispatch witness reconciliation

The actual v7 file retains all 97 old named traces and all 470 bounded traces and adds 13
named receipt traces (110 total). With the existing rescue-first/reboot-second partition:

| Owner | Named | Enumerated | Compared here |
|---|---:|---:|---|
| shared stage1, .8/.39 | 44 | 286 | Starts, every outcome and complete knowledge at every step |
| dedicated, twr-i6k.3 | 54 | 184 | Remains that ticket's comparison |
| reboot, twr-i6k.11 | 12 | 0 | Remains that ticket's comparison |

Schema 7 adds orderAssociation, receipt_binding (explicit null or closed binding), receive
and receipts; the operation mapping is order/create, stop/destroy, restart/reset. Both
unsafe admitted order traces are run against production and differ at receipt settlement,
including after replay. Repeated theorem declarations are separate traces, including the
eleven wrong-context/source receipts and failed append in lnvps_receipt_refusals. No receipt
is a generic read or deletion record. Stop means vendor-observed stopped; restart means
vendor task result; order means its returned/associated id. Delivery, pin, billing, host
creation and secret duties remain independent.

## Open citation reconciliation

Every row below is a cited change or inspected neighboring/reference-only candidate from
the committed tracker. Group letters give its new meaning above; the issue itself retains
its implementation/evidence assignment unless another owner is named. Except .39's shared
core, this change supplies documentation/metadata reconciliation only. No statuses, labels or dependency edges change. Current predicate/schema citations are corrected
to the already adopted rules; all other acceptance obligations remain with their owners. Historical pin references remain dated.

| Open record | Inspected touched citations | Disposition / retained owner |
|---|---|---|
| `twr-ede` | `ARC-43`, `OPN-14`, `d029ebd` | K: specification checklist now exists; implementation, fresh-image and integrated evidence still open. |
| `twr-et9` | `CNF-67` | P: stock repository/local policy and bounded literal refusal replace universal unsigned refusal; external artifact choice remains. |
| `twr-ew2` | `STG-21` | STG-21 account predicate changes no HTTPS-host/header assignment; protected runtime addressing is E/.23. |
| `twr-g1h` | `SEC-5`, `STA-17`, `STG-21` | V/E/R: deletion lifetime and locator/format references change; role 5, scan bound and carried-key prerequisites remain unimplemented. |
| `twr-ggw` | `STG-21` | V/K/L/E/R/H/P: required row adds 112 and publisher-hosting row 113; all integrated completion remains pending. |
| `twr-ggw.16` | `STG-12` | L: convergence now distinguishes surviving suspension from actual loss; .89 supplies lifecycle behavior. |
| `twr-ggw.18` | `ARC-43`, `CHN-13`, `SEC-6` | K/R/P: concrete checked reads and discovery parties affect provenance/disclosure; session selection remains here. |
| `twr-ggw.20` | `ARC-43`, `CNF-103`, `CNF-52` | K: consume fixed listener/outbound reads and truthful exit findings from .34/.36; receipt authority is no delivery observation. |
| `twr-ggw.21` | `CNF-104`, `CNF-110`, `CNF-29`, `STA-24` | V: shared receipt/association prerequisite here does not implement fixture create/payment or inventory adoption. |
| `twr-ggw.22` | `CNF-7`, `STA-17` | L/R: hidden predecessor retains binding; Replace references typed locators; set membership rules remain. |
| `twr-ggw.23` | `ARC-43`, `CNF-110`, `CNF-16`, `CNF-40`, `CNF-94`, `CNF-95`, `SEC-5`, `SEC-6`, `STA-20`, `STA-24`, `STG-10` | E/V/L: occurrence custody and protected representations require separate implementation; deletion duties and same scan reference persist. No placement uptake here. |
| `twr-ggw.24` | `CNF-40`, `STA-20` | K/E/L: re-entry uses fixed reads and protected reports; ordinary hide is not a successor session. |
| `twr-ggw.25` | `ARC-43`, `CNF-95`, `SEC-5`, `STA-20`, `STA-24` | E/V/L: occurrence-aware re-arm/protected evidence and deletion lifetime; no receipt grants a scan reference or paste authority. |
| `twr-ggw.26` | `ARC-41`, `CHN-11`, `CHN-15`, `CHN-16`, `CHN-16a`, `CHN-19`, `CNF-113`, `CNF-16`, `CNF-4`, `CNF-81`, `CNF-87`, `SEC-8`, `STA-17`, `STG-18` | R/H: existing criterion already names 49309df, /v2/, discovery and deployment/live binding; retain every pending admission blocker. |
| `twr-ggw.27` | `CHN-R7`, `CNF-109`, `STA-16`, `STA-17`, `STA-22a`, `STA-22b`, `STA-23` | R/E: payload v4 typed locators/high-water events, explicit v3 conversion and protected-sheet representations; no scan material export. |
| `twr-ggw.28` | `ARC-43`, `CHN-R7`, `CNF-109`, `CNF-95`, `SEC-5`, `STA-16`, `STA-17`, `STA-20`, `STA-24` | R/E/V: merge discovery monotonically, preserve direct locator identity, protected reports/re-arm, retain duties without deletion evidence. |
| `twr-ggw.29` | `CNF-110`, `CNF-40`, `CNF-86`, `STA-17`, `STA-20`, `STA-22b`, `STA-23`, `STA-24`, `STG-20` | R/L/E/V: preserve locator/pass continuity and protected custody; hide retains live authority, genuine end/recovery and deletion stay separate. |
| `twr-ggw.31` | `ARC-22`, `CNF-110`, `STA-24` | V: stop plus renewal-off leaves existing/billed until distinct durable combined deletion evidence; T50 specification gap is closed. |
| `twr-ggw.32` | `CNF-104`, `CNF-110`, `STA-24`, `STG-10`, `STG-21` | V: exact verified account/email, repeat-safe reads, invoice/renewal predicates and replay; full adapter remains here. |
| `twr-ggw.33` | `CNF-4`, `OPN-14` | K: pin now carries checklist and questions; its own gates/evidence and .34 implementation are not closed by this record. |
| `twr-ggw.34` | `ARC-43`, `CNF-103`, `CNF-110`, `CNF-40`, `OPN-14`, `STA-20`, `STA-24` | K: compile/render fixed checks and implement concrete read grammar, fixed outbound form, exit semantics and proposal restrictions. |
| `twr-ggw.36` | `ARC-43`, `CNF-110`, `CNF-40`, `CNF-53`, `CNF-94`, `OPN-14`, `SEC-6`, `STA-20`, `STA-24`, `T50` | V/K: restart receipt confirms vendor task only; independent boot/service evidence and pending delivery hold remain here; T50-open wording corrected. |
| `twr-ggw.38` | `ARC-43`, `CNF-94`, `CNF-95`, `SEC-5`, `STA-24` | E: same minimum byte length; no new syntax/entropy/classification rule. Occurrence-aware custody belongs to .23/.25. |
| `twr-ggw.39` | `CNF-4`, `STA-24`, `STG-21a`, `d029ebd` | V: shared receipt/association implementation and schema-7 stage1 comparison; whole-pin inventory only for other groups. |
| `twr-ggw.40` | `ARC-22`, `ARC-34`, `ARC-43`, `CNF-110`, `CNF-29`, `CNF-32`, `CNF-4`, `CNF-95`, `SEC-5`, `SEC-6`, `STA-24`, `STA-5`, `T50` | V: exact stop receipt, authoritative subscription-bound renewal false and distinct combined deletion record; concrete adapter and duty consequences remain here. |
| `twr-ggw.41` | `CNF-104`, `CNF-110`, `CNF-29`, `STA-24`, `STG-21` | V: verified-account ordering, complete exact-match inventory reconciliation and invoice remain here; shared order receipt alone is no readiness/payment claim. |
| `twr-ggw.43` | `ARC-43`, `CHN-R7`, `CNF-109`, `CNF-23`, `SEC-5`, `STA-16`, `TRU-E1` | V: admitted installed pin after empty history does not confirm reinstall; receipts never grant pins. Existing publication predicates remain. |
| `twr-ggw.44` | `CNF-4` | No third-rung decision was adopted: #28 adds only specification backlog. Retain twr-qso blocker. |
| `twr-ggw.45` | `ARC-22`, `CHN-R7`, `CNF-109`, `CNF-110`, `CNF-29`, `STA-24`, `STG-20` | V/L: reinstall requires prior complete publication and complete disjoint successor; timeout/2xx/pin alone do not settle. Recovery decision still open. |
| `twr-ggw.46` | `CNF-4`, `STA-22a` | R/E: recovery payload and key-birth additions do not supply T44 role 5 or numeric discovery decisions. |
| `twr-ggw.47` | `CNF-17`, `CNF-94`, `SEC-5`, `STA-22a` | V/E: deletion/format references do not create role-5 derivation or vectors; existing assignment remains. |
| `twr-ggw.48` | `ARC-22`, `CNF-94`, `SEC-5`, `STA-17` | V/R/E: inventory/account reads, deletion risk and locator/protected recovery changes; scan-ahead and carried-key contract remain downstream. |
| `twr-ggw.49` | `CNF-102`, `CNF-104`, `CNF-109`, `CNF-110`, `CNF-16`, `CNF-17`, `CNF-23`, `CNF-29`, `CNF-4`, `CNF-40`, `CNF-52`, `CNF-67`, `CNF-69`, `CNF-7`, `CNF-70`, `CNF-81`, `CNF-82`, `CNF-86`, `CNF-87`, `CNF-94`, `SEC-5`, `STA-20`, `STA-24`, `STG-21` | V/K/R/H/P/L/E: admission must link actual amended evidence; add 112 and conditional 113; fixture passes grant no deployment/live/device credit. |
| `twr-ggw.50` | `ARC-43`, `CNF-53`, `OPN-14` | K/V: fixed service reads and independent restart survival; no job observation may clear vendor restart. |
| `twr-ggw.51` | `CNF-103`, `CNF-25`, `CNF-53`, `CNF-69`, `CNF-70`, `STG-10`, `STG-12`, `STG-21` | V/K/H/P/L: fresh-image/native/physical-device/live records remain separately required; receipt fixtures and old hide tests grant none. |
| `twr-ggw.52` | `CNF-110`, `CNF-53`, `CNF-94`, `CNF-95`, `STA-17`, `STG-21` | V/K/R/E/L: recovery payload, custody, device continuation and completion records stay here; no pin-only acceptance. |
| `twr-ggw.54` | `STA-23` | L/E: STA-23 grows continuation and creation-fence contracts; worker-policy/header assignment itself is unchanged. |
| `twr-ggw.55` | `CHN-15`, `CNF-87` | R: external wire source now 49309df and /v2/ has distinct frame duties; historical WIR-8 question and old v1 evidence remain scoped. |
| `twr-ggw.66` | `ARC-22`, `CNF-110`, `CNF-29`, `CNF-40`, `SEC-5`, `STA-20`, `STA-23`, `STA-24`, `STG-20` | V/L/E: receipt provenance must be shown distinctly from unknown disposition; hidden approvals and protected display remain their respective owners. |
| `twr-ggw.67` | `ARC-43`, `CNF-29`, `CNF-40`, `STA-20`, `STA-24` | V/E: barrier tool result includes unchanged uncertainty and protected representation; no inference of receipt authority from tool text. |
| `twr-ggw.70` | `STA-20` | E: browser job-copy representation is added; raw job and unchanged-observation dedup semantics are not changed. |
| `twr-ggw.73` | `ARC-43`, `CNF-53`, `OPN-14`, `d029ebd` | K/V: fixed read inputs now exist; running-at-delivery boot anchor and every-unit re-entry rule remain as decided at d029ebd. |
| `twr-ggw.75` | `CNF-29`, `STA-20` | E/L: protected job copy and surviving collection do not turn a failed read into evidence that the call failed. |
| `twr-ggw.76` | `STA-23` | E/L: whole append/landed-error and seed-ceremony full Lock remain; ordinary hide and fresh fenced creation belong to .89/.23. |
| `twr-ggw.78` | `CNF-7`, `SEC-5`, `STA-22b` | R: pass-locator paragraph changes neither machine identity nor tombstone binding rule; retain separate fix. |
| `twr-ggw.79` | `ARC-25a`, `CNF-67` | P: native stock unsigned-repository refusal and permitted local-file rows need recorded versions/policy and real transactions. |
| `twr-ggw.80` | `ARC-25a`, `CNF-67` | P: exact literal matcher is already present; disclosure, systematic bypass/over-refusal and native evidence remain owned separately. |
| `twr-ggw.81` | `STA-16` | K/P: checklist and package-policy changes do not discharge per-installation unpinned acceptance after reinstall. |
| `twr-ggw.83` | `ARC-31a`, `CNF-69` | L: continuity cannot renew limits; numeric units/clock/issuer/in-flight contract remains its prerequisite decision. |
| `twr-ggw.84` | `ARC-31a`, `CNF-69`, `CNF-70`, `SEC-5`, `STA-16`, `STG-10`, `STG-18` | L/E: funding cannot renew a session; custody/protected results do not authorize concurrent funding. Entry/funding design remains pending. |
| `twr-ggw.86` | `CNF-102`, `STG-21` | L: hidden goal-loop checks add no independence-bound exemption; profile goal refusal still belongs here. |
| `twr-ggw.87` | `ARC-43`, `STA-24` | V/L: typed approval includes receipt context; visibility supplies no approval and no stale-session authority. |
| `twr-ggw.88` | `CNF-29` | L: continuity/uncertain effects must not fabricate failed/successful goal outcomes; precedence assignment remains. |
| `twr-i6k.10` | `CNF-110`, `CNF-86`, `STA-23`, `STA-24`, `STG-20` | L: standing approval survives ordinary hide, genuine session end remains distinct from withdrawal. |
| `twr-i6k.11` | `ARC-43`, `CNF-110`, `CNF-40`, `CNF-53`, `STA-20`, `STA-24`, `d029ebd`, `dispatch-witnesses-v6` | V/K/E: v7/schema7 reboot partition remains 12/0; receipts do not replace dedicated reboot evidence, pending check or protected job copy. |
| `twr-i6k.2` | `CNF-29`, `SEC-5`, `STA-24`, `STA-5`, `STG-20` | V: Robot stays read-confirmed; receipt mutation exception supplies it no authority or retry. |
| `twr-i6k.3` | `ARC-43`, `CNF-109`, `CNF-110`, `CNF-86`, `STA-20`, `STA-24`, `STG-20`, `d029ebd`, `dispatch-witnesses-v6` | V/E/L: v7/schema7 dedicated partition stays 54/184; empty receipts member and binding null remain required; raw rescue predicates and gates remain. |
| `twr-i6k.4` | `CNF-4` | No promoted brief added; CNF-4 route-probe source changes supply no promotion or pin-ticket closure. |
| `twr-i6k.5` | `ARC-25a`, `CNF-67`, `CNF-86`, `STA-20`, `STA-24`, `STG-20` | P/E: harness-owned commands have separate nonlowering duty; protected job evidence does not replace artifact pin or same-boot checks. |
| `twr-i6k.6` | `STA-17`, `STA-22b` | R/E: typed relay recovery and protected sheet additions do not admit guessed indices or change no-metadata Robot rescue ownership. |
| `twr-i6k.7` | `CNF-82`, `CNF-86`, `STG-12` | L/E: physical suspension/loss and protected-store requirements remain dedicated live milestone evidence; no execution here. |
| `twr-i6k.8` | `CNF-86`, `STA-17`, `STG-20` | L: hide preserves approval lifetime; installation dispatch boundary and zero-based ordinal remain unchanged. |
| `twr-i6k.9` | `ARC-43`, `CNF-110`, `CNF-40`, `CNF-86`, `STA-17`, `STA-20`, `STA-24`, `STA-6`, `STG-20` | R/E: pass/metadata representation and protected relabel records change no requirement for confirmed root relabel before key removal. |
| `twr-ni0` | `STG-21` | STG-21 account/evidence changes do not supply funds; external payment remains unauthorized here. |
| `twr-oa6` | `STG-18` | STG-18 relay reference now pinned; disposable Robot server and credentials remain external. |
| `twr-qso` | `ARC-22` | #28 creates specification issue tw-ae7 for the existing recovery decision gap; no normative third rung is selected. |
| `twr-x3k` | `ARC-31a`, `STG-21` | L/V: physical scheduled continuation/loss and unchanged key limits require separate device/funded-account evidence. |

Additional alias/comment and non-seed checks:

- twr-i6k comment 102 names v6; its current consumer reference is updated to v7 without changing the dedicated-stage split. twr-i6k.3 comment 15 names v2 historically; its current criterion uses v7/schema7. twr-i6k.11 also uses v7/schema7. All require the new receipts member even when empty and receipt_binding even when null.
- twr-ggw.31/.36/.40 and .41 comment 53 refer to undefined T50 predicates. Current wording points to STG-21a/CNF-112, while the original comments remain dated history. twr-ggw.39's preparation description is retained as the reason for the behavioral uptake, followed by the current implementation boundary.
- twr-ede comments 36/83 and twr-ggw.20/.51/.52 mention the once missing checklist; the specification now supplies it, while implementation/fresh-image evidence stays pending. .33's target is carried, but its separate closure/gates are not performed here.
- twr-ggw.56's historical WIR-8/844e834 question remains a /v1/ reference, not evidence for /v2/. twr-7m5's deployment/pass external dependency remains pending under .26's effective publisher admission; twr-ggw.85 retains cold-probe timing/assertion repair and .89 coordination. No readiness is inferred from these references.
- twr-i6k.1's pinned-tunnel contract, twr-ggw.77's recurring-cost ownership, .82's unpinned distribution qualification and twr-68d's brief promotion have no substantive changed cited rule in this delta. They receive no rewrite. Closed records are historical evidence, not reopened or silently credited at the new pin.
- T44/SEC-5 row 22 still supply no implemented vendor role or numeric scan bound. #28's specification issue is tw-ae7. Existing allocation/pins/declaration/relay witness bounds remain unchanged; commentary/source links or declaration rendering changes do not supply new implementation comparison credit.

## Complete changed-path inventory

Generated with `git -C spec diff --name-status d029ebd9f632696bb027a22559d774d165685947 66762f1a63f43977f4ef407c194a73e1ae71458a`.
All 44 paths are listed, including removed v6 and added v7, without rename normalization:

```text
M	.beads/issues.jsonl
M	00-overview.md
M	01-architecture.md
M	02-channel.md
M	03-state-and-recovery.md
M	04-security-model.md
M	05-trust.md
M	06-first-stage.md
M	07-conformance.md
M	08-open-questions.md
M	CONTEXT.md
M	TASKS.md
M	bundle/README.md
M	bundle/cors-probe.sh
A	bundle/lockdown.toml
M	bundle/timing.toml
M	docs/adr/0002-cloud-plane-and-box-plane.md
M	docs/adr/0003-the-ai-runs-only-in-the-browser.md
M	docs/adr/0009-one-device-concurrent-sessions-batched-approval.md
M	docs/adr/0019-the-publisher-operates-the-default-relay.md
M	docs/adr/0022-durable-state-is-an-append-only-journal.md
M	docs/adr/0023-a-tenants-runtime-obligations-belong-to-its-machines.md
M	docs/adr/0025-relay-access-is-bought-not-granted.md
M	docs/adr/0031-the-specification-and-the-implementation-are-separate-repositories.md
M	docs/adr/0032-the-formal-companion-follows-provisiond-spec.md
M	docs/adr/0041-secret-scan-rearms-from-machine-reports.md
M	docs/adr/0042-the-vendor-identity-is-derived-per-machine.md
A	docs/adr/0051-the-lockdown-checklists-fixed-checks-and-reads.md
M	docs/design/credential-format-v1.md
M	docs/design/delivery-declaration-v1.md
D	docs/design/dispatch-witnesses-v6.json
A	docs/design/dispatch-witnesses-v7.json
A	docs/design/protected-evidence-v1.md
A	docs/design/relay-discovery-inputs.md
M	docs/design/relay-protocol-v1.md
M	docs/design/witness-file-v1.md
M	executive-summary.md
M	tools/check-controls.sh
M	tools/coverage-baseline.json
M	tools/formal/TauWeb/Allocation.lean
M	tools/formal/TauWeb/Dispatch.lean
M	tools/formal/TauWeb/Relay.lean
M	tools/formal/TauWeb/Render.lean
M	tools/formal/Witnesses.lean
```

Numbered prose, glossary and ADR edits carry the groups above. bundle/lockdown.toml and
ADR-0051 are K; bundle/timing.toml adds the placeholder 10s discovery fetch bound (R).
bundle/cors-probe.sh adds VM POST/account PATCH preflight shapes and preserves case-sensitive
method tokens, independently checking OPTIONS/GET headers; it is source-inspected here and
remains CI's later live gate. bundle/README and relay-discovery-inputs document still-unselected
publisher inputs. credential-format-v1 and protected-evidence-v1 carry R/E; delivery-declaration
carries K. The moved relay-protocol document and several OVR/CHN/ADR paragraphs only update
external source links; canonical selected relay source is 49309df, while dated subordinate
v1 commentary/timing links retain ba316fc. No new guarantee follows from that link update.

Dispatch.lean/Witnesses.lean implement receipt predicates, retention, schema7 emission and
new declarations; Render.lean adds the mapping table and checklist rendering. Allocation.lean
and Relay.lean change scope commentary only, not the allocation or historical relay witnesses.
check-controls.sh uses v7 as the source for obsolete-schema controls and adds a receipt-mapping
drift control. coverage-baseline.json changes uncovered budget 74 to 71 for specification
coverage, not executable implementation coverage. TASKS marks T50 complete and narrows T42's
remaining work; specification .beads changes retain that history and add the third-rung gap.
Additional specification backlog entries tw-hwl, tw-l1l, tw-nj8 and tw-sfu ask about definitive allocation failure, successor/session routes and installation/no-pin boundaries; tw-yuo asks about the arch-to-root route. They choose no behavior and authorize no successor allocation in this change.
The executive summary and lifecycle ADR addenda explain L; ADR-0041 explains E; ADR-0031's
later addendum explicitly distinguishes the protected representation extension from the earlier
occurrence amendment. None of those specification records establishes implementation acceptance.
