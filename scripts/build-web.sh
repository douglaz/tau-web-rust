#!/usr/bin/env bash
# Builds a web directory: the page, its script, the worker script and the wasm module.
#
#   scripts/build-web.sh served   # -> dist/served: the served build (ARC-32), release, no test-only part
#   scripts/build-web.sh tracer   # -> dist/tracer: the same with the `tracer` feature, for the tracer only
#
# Needs cargo with the wasm32-unknown-unknown target, the wasm-bindgen CLI at the version
# Cargo.lock pins, and a clang that targets wasm32 for ring's C code, given as
# CC_wasm32_unknown_unknown and AR_wasm32_unknown_unknown.
set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-}" in
  served) features=() ;;
  tracer) features=(--features tracer) ;;
  *) echo "usage: scripts/build-web.sh served|tracer" >&2; exit 2 ;;
esac
out="dist/$1"

# The CLI must equal the wasm-bindgen crate exactly, or the glue it writes does not match.
locked=$(sed -n '/^name = "wasm-bindgen"$/{n;s/^version = "\(.*\)"$/\1/p;}' Cargo.lock)
cli=$(wasm-bindgen --version | cut -d' ' -f2)
if [ "$cli" != "$locked" ]; then
  echo "wasm-bindgen CLI is $cli, Cargo.lock pins the crate at $locked" >&2
  exit 1
fi

cargo build --locked --release -p tau-web --target wasm32-unknown-unknown "${features[@]}"
rm -rf "$out"
mkdir -p "$out"
wasm-bindgen --target web --no-typescript --out-dir "$out/pkg" \
  "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/tau_web.wasm"
cp www/index.html www/boot.js www/worker.js "$out/"
echo "built $out"
