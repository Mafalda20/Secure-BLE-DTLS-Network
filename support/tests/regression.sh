#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

role="${1:-}"
if [[ "$role" == "sink" ]]; then
    cmake -S "$root_dir/sync" -B "$root_dir/sync/build"
    cmake --build "$root_dir/sync/build" -j2
elif [[ "$role" == "node" ]]; then
    cmake -S "$root_dir/node" -B "$root_dir/node/build"
    cmake --build "$root_dir/node/build" -j2
else
    echo "Uso: $0 sink|node" >&2
    exit 2
fi
"$root_dir/support/tests/certificate-test.sh" "$role"

echo "REGRESSION_RESULT=PASS"
