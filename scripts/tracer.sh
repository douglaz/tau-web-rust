#!/usr/bin/env bash
# The tracer (twr-ggw.2): builds the served and the tracer web directories, then starts the
# fixtures on ephemeral ports, serves both builds over HTTPS, drives headless Chrome and asserts
# every case. CHROME names the Chrome or Chromium binary; without it the tracer fails.
set -euo pipefail
cd "$(dirname "$0")/.."
scripts/build-web.sh served
scripts/build-web.sh tracer
cargo run --locked -p tracer -- run dist/served dist/tracer
