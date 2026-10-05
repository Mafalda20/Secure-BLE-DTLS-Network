#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "Uso: $0 NOME_DO_NODE [PARENT_PREFERIDO]" >&2
    exit 2
fi

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$root_dir/node/build/sic_node" "$@"
