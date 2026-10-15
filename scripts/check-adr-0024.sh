#!/usr/bin/env bash
# ADR-0024's build check: "Anything pulling Tokio's `net` or `rt-multi-thread` fails this
# target … Worth a build check rather than a comment." Reads the wasm32 build's resolved
# dependency graph, for the served and the tracer feature sets, and refuses tokio `net` or
# `rt-multi-thread`, any russh feature but `ring` (so no `flate2`, `rsa` or `aws-lc-rs`), and any
# of those crates pulled by another path. Host-only dependencies of the tracer are not in it.
set -euo pipefail
cd "$(dirname "$0")/.."

status=0
for features in "" tracer; do
  label="wasm32 graph${features:+ with --features $features}"
  tree=$(cargo tree --locked -p tau-web --target wasm32-unknown-unknown -e normal,features --features "$features")
  # A graph without russh on ring and tokio is the wrong graph, and would pass on nothing.
  for needed in 'russh feature "ring"' 'tokio feature "sync"'; do
    if ! grep -qF "$needed" <<<"$tree"; then
      echo "$label: no $needed, so this is not the harness's graph" >&2
      status=1
    fi
  done
  found=$(grep -oE 'tokio feature "(net|rt-multi-thread)"|russh feature "[^"]+"|(^|[ ─])(aws-lc-rs|aws-lc-sys|flate2|rsa) v[0-9][^ ]*' <<<"$tree" \
    | sed 's/^[ ─]*//' | grep -vxF 'russh feature "ring"' | sort -u || true)
  if [ -n "$found" ]; then
    echo "$label refuses what ADR-0024 keeps out:" >&2
    echo "  ${found//$'\n'/$'\n'  }" >&2
    status=1
  else
    echo "$label: russh on ring alone, tokio without net or rt-multi-thread"
  fi
done
exit "$status"
