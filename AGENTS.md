# AGENTS.md

The implementation of the harness the specification at `spec/` describes (spec ADR-0031). The
specification is the source of truth: what to build and what it must demonstrate are its
`06-first-stage.md` and `07-conformance.md`. A question it does not answer goes back to the
specification repository, not into code here.

## Gates

`cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings` and
`cargo test --locked`, as CI runs them (`.github/workflows/ci.yml`), before you report done. Run
them unpiped: a pipe reports the pipeline's status, not the gate's. `cargo test` runs `build.rs`,
so the pin and bundle gates run with it.

The `web` job's gates run the same way: `cargo clippy --locked -p tau-web --target
wasm32-unknown-unknown --all-targets -- -D warnings`, with and without `--features tracer`;
`scripts/check-adr-0024.sh`; `scripts/build-web.sh served`, then `cargo run --locked -p tracer --
check-absence dist/served` and `cargo run --locked -p tracer -- check-csp dist/served`; and
`CHROME=<chrome> scripts/tracer.sh`. They need the wasm32 target, the wasm-bindgen CLI at
`Cargo.lock`'s version and a wasm32 clang for ring (`README.md`, "Building and checking it
locally").

## Agent skills

### Issue tracker

Beads (`br`), local-first in `.beads/`, committed with the code. See `docs/agents/issue-tracker.md`.

### Triage labels

The five default roles as `br` labels. See `docs/agents/triage-labels.md`.

### Domain docs

The specification's, at `spec/CONTEXT.md` and `spec/docs/adr/`. See `docs/agents/domain.md`.
