#!/bin/bash
# Run every scenario in order against the lab target. `make attack` calls this.
set -euo pipefail
cd "$(dirname "$0")"
. ./lib.sh
guard_target  # fail fast before any scenario runs

for s in scenarios/[0-9]*.sh; do
    echo "=== $s ==="
    bash "$s"
done
echo "=== all scenarios done; watch http://127.0.0.1:8000 ==="
