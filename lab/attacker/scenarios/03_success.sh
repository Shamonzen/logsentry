#!/bin/bash
# T1078 Valid Accounts: wrong passwords, then the real one → success_after_failures
# (a success for an IP that just had >=5 failures). The lab password comes from the environment
# (compose passes LAB_PASSWORD from .env); it is never baked into this script.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./lib.sh
guard_target
: "${LAB_PASSWORD:?set LAB_PASSWORD (compose passes it from .env)}"
# -t 1 so the five failures are logged before the success, in one window.
printf '%s\n' wrong1 wrong2 wrong3 wrong4 wrong5 "$LAB_PASSWORD" > /tmp/creds.txt
hydra -l labuser -P /tmp/creds.txt -t 1 "ssh://$TARGET" || true
