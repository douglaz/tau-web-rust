#!/usr/bin/env bash
# Release web preparation; Python owns locks, staging, child exits and timing.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 scripts/web_preparation.py "$@"
