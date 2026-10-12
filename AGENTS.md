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

## Agent skills

### Issue tracker

Beads (`br`), local-first in `.beads/`, committed with the code. See `docs/agents/issue-tracker.md`.

### Triage labels

The five default roles as `br` labels. See `docs/agents/triage-labels.md`.

### Domain docs

The specification's, at `spec/CONTEXT.md` and `spec/docs/adr/`. See `docs/agents/domain.md`.
