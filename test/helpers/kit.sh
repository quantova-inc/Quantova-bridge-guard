#!/bin/sh
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export BRIDGEGUARD_HWM_DIR="${BRIDGEGUARD_HWM_DIR:-${TMPDIR:-/tmp}/bridgeguard-test-hwm}"
cd "$ROOT/kit" && exec python3 -m bridgeguard "$@"
