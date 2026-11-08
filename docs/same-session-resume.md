# Same-session recovery in the PoC

This behavior was reviewed against specification b6d1252 (4d991cde plus ADR-0072).
The compiled specification remains pinned to 9086166b. This branch claims no specification
conformance; `coverage.complete` remains false. Local fixture results establish no physical-phone,
live-service or remote-CI acceptance. Selected CI checks have not yet been proven to run remotely;
the owner must dispatch the workflow on the eventual commit’s ref or open a pull request.

Start session shows the model and machine and durably records inference approval plus public
endpoint/model in Exposure before granting authority. A bare bind grants nothing. After Lock,
reload or worker loss, the replacement starts locked. Unlock validates the entire journal before
restoring the original session, immutable binding, goal, approvals, task and consumed budgets.
Missing keys or connection readiness withhold execution while the dormant session keeps its machine.
Key re-entry restores custody without approving a new session. Endpoint validation remains;
re-entry must match the admitted model name, which does not prove actual model weights. Automatic
inference also requires the admitted endpoint; an explicit Resume may use an edited endpoint
without End. This prevents one restored session from silently using another public configuration.
Collection and evidence settlement do not require inference configuration.

Eligible running, waiting and verifying tasks wake after unlock, revalidation and needed key
resupply. A pending job is collected by its original identity first. Committed terminal evidence
settles without another launch. Possibly sent effects retain existing reconciliation holds.
Missing inference credentials consume no new Request and need not prevent permitted collection
or evidence settlement. An interrupted model response remains uncertain and counted; a later
eligible turn consumes another Request. Genuine approval, budget, evidence and verification
pauses retain their explicit controls. Completed and stopped tasks remain history.

Ordinary visibility-only hide preserves eligible authority. Switching apps or device-screen lock
may leave data-key, seed, account and machine authority unlocked in memory indefinitely. Permitted
work, including approved destructive actions such as disk wipe, may run unseen. End is the kill
switch; Lock pauses; dormant sessions retain their machines. An already approved destructive
action may run after reload/kill without a new tap. Already accepted remote work may continue
after End; the phone may freeze or discard the page. This disclosure appears before admission
and beside Lock, without another acknowledgement ceremony.

Processed Lock/pagehide retire the execution, close transports and clear working secrets after
a begun append finishes whole. The page clears visible secrets immediately and visibly waits in
locking state. Its short explanatory timer never terminates a worker. A successor must acquire
the existing exclusive store Web Lock after retirement acknowledgement and termination; a
second tab waits while the first owns it. Freeze retains ownership, invalidates old continuations
and requires revalidation. Execution identity, lifecycle generation, original session/binding
and task revision fence stale sends, mutations and actionable publication.
An approval or Resume already received retains its originating generation while waiting for
the writer. Retirement before admission consumes neither the pending decision nor a Request;
a fresh current control remains usable. A begun append still finishes whole. A worker waiting
for the exclusive lock accepts retirement, cancels its queued acquisition and acknowledges
without opening the store, so its page can terminate it without leaving an orphan writer.

Selected End is available for an unlocked dormant session without an inference key or connection.
During suspension the protected page exposes only the minimal session/binding controls needed
for End; a queued control must still belong to the current execution generation before append.
It appends before permanently fencing only that session, retiring its pending approvals and
releasing its binding. Failed or uncertain writes release nothing and stop dependent work until
replay resolves what committed. End survives reopen, is idempotent and never revives an identity.
It does not promise remote cancellation or billing cessation. Stop task stops local orchestration
without implicitly ending the session, erasing uncertain effects or stopping billing.

## Bounded specification differences

- **D1:** Only session journal format 2 is readable/writable: the closed
  `{"journal_version":2,"event":...}` wrapper is inside every encrypted record, including seed.
  Raw pre-End records, mixed suffixes, earlier/unknown versions, malformed and duplicate-member
  wrappers are refused without append or authority projection. ADR-0072 supersedes 4d991cde’s
  ended-history reading. Refusal distinguishes earlier format, unknown version and decoding
  failure, says bytes are unchanged and warns that clearing site data permanently deletes the
  store including its seed. There is no migration, reset control, import or snapshot support.
- **D2:** The BYO disclosure implements the STA-23 subset, omitting only the paid-key-at-rest
  clause. BYO keys remain memory-only and retirement clears them. Paid-key recovery is deferred.
- **D3:** The existing writable local-envelope-v1 deviation remains for fresh stores. Journal
  format 2 does not relabel an old key or change outer serialization, AAD, nonce or chain bytes.
  No canonical key/encryption migration is implemented.
- **D4:** BYO inference has no intent/terminal pair. The existing Request is the journaled request;
  no inference attempt identifiers, second correlation schema or prompt checkpoints are added.
- **D5:** Existing prompt construction gains the original goal/source, bound machine, approved
  facts, protected outcomes, budgets and uncertainty. There are no bundle briefs or generic
  context-restoration subsystem. Outgoing facts project machine names and approved entry/access
  data without journal-only seed/allocation associations; canonical encrypted records retain them.

Focused native `poc_session_` tests cover refusal, restoration, dormant exclusivity, admission
scanning, scoped End and held/failed/lost append acknowledgements. Real-page cases
`resume-lock`, `resume-reload` and `resume-loss` use loopback inference, relay and SSH to preserve
session/task/job identities and prove one launch plus distinct verification. `resume-stale-fetch`,
`resume-freeze`, `resume-approval`, `resume-append`, `resume-end` and `resume-configuration` exercise stale work, genuine
approval pause, writer exclusion, visible append waiting and durable End. Existing credential,
origin, host-pin, journal and protected-result regressions remain required.
`resume-approval` also covers received approval/rejection and queued Resume across revalidation;
`resume-append` retires the waiting second tab before it can acquire the writer. The native
`poc_request_restores_useful_facts_without_seed_allocation_associations` test checks the actual
serialized request, useful context and preserved canonical associations.

The browser harness retains its 15-second measured-operation and queued-lifecycle limits
and one aggregate 180-second invocation watchdog. The same browser and store carry the
main-worker history into the real-page replay checks.
The provisioning fixture's final authenticated journal scan allows 90 seconds, raised once
from 45 seconds after scanning 149 credential forms took 47 seconds and passed every check.
Its ordinary control waits and overall watchdog retain their existing limits; the scan still
checks every credential form and requires an authenticated result with no matches.
