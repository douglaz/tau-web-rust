# AGENTS.md

This is the `poc/integration` branch. It builds a small proof of concept on top of the existing
implementation of the harness that the specification at `spec/` describes (spec ADR-0031).

## Milestone

The milestone is a recording of the phone creating a machine, installing a requested service,
losing the browser session, and resuming the same setup successfully. The work reaches it through
four checkpoints, taken in order:

1. Real inference configures a disposable, already running machine from the served page. The
   operator supplies their own inference endpoint and key. The page resolves a real target and a
   trusted host pin and connects through the actual relay. The model chooses the commands, and the
   page installs and verifies a small service.
2. An interruption doesn't lose that task. The interruption can be an app switch, a network loss, a
   reload or a lost worker. On unlock and Resume, the page collects the recorded job and never runs
   it twice. If an outcome can't be established, the task stays paused with a concrete reason.
3. Fresh provisioning. The page shows one real plan for approval, orders it once, shows the invoice,
   waits for readiness and persists the published host keys. It then continues into the
   configuration path from checkpoint 1.
4. The complete flow runs on a phone, with one interruption.

A task outlives the browser session. A lost response never automatically turns into a second
creation of the machine or a second run of the command. When the model says it is done, the page
runs verification, and only the verification establishes success. PoC readiness is recorded
separately from specification conformance, and this branch claims no conformance. A question that
the specification doesn't answer becomes an open PoC decision. It blocks work only when it blocks a
checkpoint.

## Checks per edit

Each edit gets a few minutes of checks, not the exhaustive suite. Run every check unpiped, because a
pipe reports the pipeline's status rather than the check's.

- `cargo fmt --check`
- `cargo clippy --locked --all-targets -- -D warnings`
- `cargo clippy --locked -p tau-web --target wasm32-unknown-unknown --all-targets -- -D warnings`,
  once with `--features tracer` and once without
- `cargo test --locked <filter>` for the behaviour you changed, with the tests for that change added
  in the same edit
- `scripts/check-adr-0024.sh`
- `scripts/build-web.sh served`, then `cargo run --locked -p tracer -- check-absence dist/served`
  and `cargo run --locked -p tracer -- check-csp dist/served`
- the browser smoke, `CHROME=<chrome> scripts/tracer.sh targeted TAU_TRACER_HOLD_CASE=drop`, plus
  `node scripts/check-poc-page.mjs` for each of first-key, rotation, publication, progress,
  interruption, aggregate, resolver, configuration, wire, first-key-checks, reload-key,
  reload-control, reload-progress, keyless-collection, metadata-key and mismatched-terminal

The wasm32 steps need three tools: the wasm32 target, the wasm-bindgen CLI at the version in
`Cargo.lock`, and a clang that targets wasm32 so it can compile ring (`README.md`, "Building and
checking it locally"). The full `cargo test --locked` and the full `scripts/tracer.sh` run at
checkpoints, through CI's manual dispatch, and not on every edit. Never bypass host-key verification
to make a check pass.

## Agent skills

### Issue tracker

Beads (`br`), local-first in `.beads/`, committed with the code. See `docs/agents/issue-tracker.md`.

### Triage labels

The five default roles as `br` labels. See `docs/agents/triage-labels.md`.

### Domain docs

The specification's, at `spec/CONTEXT.md` and `spec/docs/adr/`. See `docs/agents/domain.md`.
