# Inference credit in the PoC

After recording the local seed backup, the primary inference path is browser-held credit.
Choose 100–5,000 sat (default 1,000) and press **Get an invoice**. The worker creates an account,
commits its credit id and Default key together in the existing encrypted journal, and only then
reads a fresh balance and requests an invoice. Both account values enter the shared credential
filter after that commit, and again during every replay before the store becomes writable.
No later record, page projection, prompt, command or evidence may carry those values. Secret
holders, event fields and decoded/serialized temporary buffers clear on drop, best effort in a
browser. Fixture procured inference retains its separate account record and protocol.

This credit is kept only in this browser's encrypted store. If the store is lost, the credit is
lost. There is no export, migration or reset-store control. The earlier statement that an account
credential never enters the browser or a test does not apply to this path. The session key is
memory-only, used only by harness code, registered with the filter on receipt, and never journaled
or sent to the page. The Default key is never used for inference.

A saved invoice displays its amount, **Open in wallet**, **Copy**, minutes left and **Check now**.
The wallet link uses its saved `lightning:` invoice, never a checkout URL. Invoices are paid
externally under ARC-30/ADR-0014. The page holds no wallet, spends nothing, never enables
automatic top-up and makes no NWC connection.

While visible and unlocked, pending credit invoices are read every five seconds until their
expiry plus 60 seconds. Unlock and visibility return re-read the saved invoice even outside
that automatic window. Manual checks remain available. Elapsed time never establishes unpaid.
Only a matching `Expired` status, numeric zero `amount_paid`, and a successful fresh balance
not above that invoice's baseline jointly permit **New invoice**. Earlier invoice history stays.
A balance above baseline on matching `Expired` is treated as paid. `Settled` before or after expiry
reads the balance; failure shows “Payment seen; balance not read yet.” and is retried. A successful
positive balance read is required before Start. Other failures, unknown statuses, identity
mismatches, `New` after expiry or malformed/nonzero paid amounts remain “Payment status unknown.”
and withhold a new invoice. A persistently unresolved invoice needs manual greenfield handling,
marking it abandoned while retaining the account; this page provides no clearing control.
`New` before expiry is pending only after a successful fresh balance read; a failed read is
unknown. Once a paid or expired-unpaid outcome is established, later failed reads or credit
consumption cannot erase that resolution or block further funding. Each refresh still reads
the current balance; failure withholds balance-dependent controls without rewriting history.

Balance is service-reported USD, represented as a finite binary float and rounded down to cents
for display. It establishes no exchange rate, local accounting or cap enforcement. A lost account
creation answer leaves no local account and can be retried; the unobserved account has no funds.
A lost invoice answer can be retried on the same account because no payable invoice was displayed.
An uncertain store append holds further credit dispatch until replay. Mutation presses serialize;
Lock, End and lifecycle generations fence stale sends, appends and actionable answers. A begun
append finishes whole. Every exchange has a 15-second timeout and a 256-KiB response bound.
Required refreshes and eligible automatic key work wait for an in-flight credit operation;
duplicate mutation presses report the existing operation rather than starting another.

Enter the goal before **Start session <machine>**. Start confirms this disclosure:

> Inference uses a key capped at 0.25 USD of your credit and valid 24 hours (requested limits, per key). A new key with the same limits is made after each Unlock or New key press, so a session can use more than 0.25 USD in total; your credit balance is the overall limit.

The credit-backed Exposure records the original session and public endpoint/model atomically.
The worker commits a mint name before requesting a key, checks the returned 0.25 cap, null reset
period and expiry within 60 seconds, then commits the issuer id and limits. Names are `k` followed
by 24 lowercase hexadecimal characters drawn from 96 random bits: exactly 25 characters. Each
new mint uses fresh randomness and the store refuses a repeated name. Before a new mint it lists
keys including disabled ones, matches earlier committed names for that session and best-effort
deletes their issuer ids, including keys whose mint answers were lost. Returned unusable and late
keys are deleted best effort. End cannot be undone by cleanup failure.

Lock, reload and worker loss clear session keys. Eligible interrupted work or Resume restores the
account automatically and mints when inference is next needed, retaining the same session,
binding, approvals, task budgets and job ids. Recorded work is collected first; no missing key
permits another launch of a possibly sent command. Ordinary hide/return preserves a held key and
never mints. Genuine approval and verification pauses remain explicit. **New key** requests fresh
limits after earlier-name cleanup. **Use your own inference endpoint instead** keeps the separate
memory-only typed-key path and its key re-entry behavior.
A failed mint withholds future inference with a retryable reason. It leaves recorded-job
collection, authorized command continuation and independent verification eligible, preserving
their task revisions and job identities. The next inference boundary pauses without consuming
a Request; explicit Resume or New key can retry. Existing approval and evidence pauses stay.
An unsubmitted goal draft survives ordinary renders and hide/return. Successful Start consumes
that draft, and Lock clears unsubmitted drafts; the original session's durable goal remains.

An internally recognized insufficient-credit refusal reads the balance first: below the request
minimum it says “Inference credit used up.” Otherwise refusal is neutral and New key remains.
An expired-key refusal says “This session's inference key expired.” Other 401/402/403/429 responses
say “The credit service refused this request.” Service error text, including account prefixes,
is never displayed. Add credit retains the same account.

## Deployment defaults

At boot the page reads `poc-defaults.json` from the same origin and directory as `index.html`.
The exact accepted object is:

```json
{
  "provider_origin": "https://provider.example",
  "relay_url": "wss://relay.example/",
  "chat_endpoint": "https://credit.example/v1/chat/completions",
  "model": "example-model",
  "topup_sat": 1000
}
```

All five fields are required and no additional field is accepted. The complete object validates
against the consuming fields' URL grammars before any field changes: literal `https://` provider
origin with no non-root path, `wss://` relay with a trailing slash and no dot segments, and a valid
HTTPS chat endpoint. Browser URL repair does not make a malformed spelling admissible.
Missing or invalid data retains every fallback (provider
`https://api.lnvps.net`, empty relay/chat/model fields, and 1,000 sat), with a Details notice.
The read is bounded to three seconds and 16 KiB and does not delay store opening. Public fields
stay editable; late defaults cannot overwrite edited fields or a reviewed selection. No fresh
class answer is preselected. Origin/price and relay remain subject to review and explicit
approval. The file is ignored, never committed and never copied into `dist/served`; deployment
supplies it beside the deployed page and records it in its deployment hash manifest. No example
file lives under `www/`. The page CSP is unchanged.

## Accepted specification departures

This lite path deliberately departs from **ARC-31a, ADR-0028, CNF-69, CNF-70 and STA-16**:

1. There is no reviewed pinned protocol profile. Service-reported USD uses binary floats and
   rounding down for display, rather than exact-decimal account units.
2. The fixed 0.25 USD cap and 24-hour lifetime are disclosed before and confirmed by Start.
   Limits are not editable and there is no choice-generation record. Returned limits are checked,
   but there is no issuer-clock contract, local expiry enforcement beyond the issuer's,
   aggregate accounting or in-flight accounting.
3. Account creation and top-up have no journaled SEC-12 intent. Mint records retain only
   non-secret names, issuer ids and limit metadata.
4. Fresh minting after Unlock or New key in the same session departs from the one-mint and
   no-replay-remint rules. Every key has a new 0.25 allowance and 24-hour expiry, so the account
   balance alone bounds session total. Earlier keys are revoked best effort; returned expiry
   is accepted within 60 seconds of the requested value.
5. End/re-mint revocation is best effort. CNF-69 refusal-after-close is not established when
   revocation fails; expiry still bounds that key.
6. No recorded top-up-off read required by CNF-70 is made. The page creates its account and
   never calls NWC endpoints.
7. A session key can request a payable invoice, differing from ADR-0028's earlier reading that
   it cannot attach funding. Service documentation requires the account credential to connect
   NWC; use of a session key for that was not tested and is not tested here.
8. The account credential is not exported in the recovery sheet (STA-16). Losing the store loses
   its credit, as the page explicitly says.
9. The retention tier is not requested, as before, because the configured inference has no
   zero-retention endpoint.

The ADR-0042 provider-account departure remains unchanged. Fixture results establish no live
service or phone readiness, and this branch claims no specification conformance.

The PoC claims none of the spec's cap and expiry guarantees for this path. This path replaces the deferral of in-app inference funding and minting for this path only.
