#!/bin/bash
# T1595 Scanning: a burst of 404s → web_scan (>=20/60s); the scanner User-Agent also raises a
# web_attack "Scanner user-agent" alert.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./lib.sh
guard_target
for i in $(seq 1 25); do
    curl -s -o /dev/null -A "gobuster/3.6" "http://$TARGET/admin/panel_$i"
done
echo "sent 25 requests to missing paths"
