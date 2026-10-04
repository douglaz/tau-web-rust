# tau-web-rust

The implementation of the tau-web harness: a client-side AI harness that runs in a phone
browser and provisions real infrastructure on its operator's behalf. Rust, compiled to
WebAssembly, following the configuration the specification records.

**The specification lives in [`douglaz/tau-web-spec`](https://github.com/douglaz/tau-web-spec)
and is vendored here at `spec/`, pinned to an exact commit** (spec ADR-0031). The build refuses
to run if the checked-out tree does not match the pin, and every release records the spec commit
it was built from. What the build compiles in from the pin:

- `spec/bundle/` — the artifact pin and accepted signers, the inference target, the named
  timings, and the CORS probe;
- `spec/docs/tenants/` — the tenant profiles;
- the briefs promoted out of draft (none yet).

`spec/bundle/cors-probe.sh` and `spec/prototypes/spec-checks/` run from the pinned tree as this
repository's CI gate. The probe is spec `CNF-4`, "The CORS probe runs on every push (`ARC-34`),
and its failure fails the build"; the disk checks are evidence for spec `CNF-85` and for nothing
else. Until this pin both were labelled `CNF-1`–`CNF-4`, which the specification's own task list
records as a mislabel to correct here.

Start reading at [`spec/00-overview.md`](./spec/00-overview.md). What to build first is
[`spec/06-first-stage.md`](./spec/06-first-stage.md); what it must demonstrate is the
first-stage row of [`spec/07-conformance.md`](./spec/07-conformance.md).

No harness code yet: `src/lib.rs` holds the pinned inputs and nothing else.

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
| | `cargo test --locked` | runs `build.rs`, so the gates above run here, and the `[session]` fixtures (`CNF-88`'s build fixtures) |

Both jobs check out the submodule; `spec-checks` takes the full history, which
`check-install-disks.py --baseline` reads to reconstruct the pre-fix brief.

`CNF-3` in its general form — "The test suite fails when a test is deliberately broken" — was
verified by hand on 2026-09-21, against a temporary pin filling the inference slugs: the one
test was broken deliberately, `cargo test` went red naming it, the restored test went green.
The three further breaks `CNF-3` names are the companion comparison's (ADR-0032), and wait on
the test that reads a witness file, which does not exist here yet.
