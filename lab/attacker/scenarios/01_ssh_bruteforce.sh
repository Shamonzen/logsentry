#!/bin/bash
# T1110.001 Password Guessing: one user, many passwords, fast → ssh_bruteforce (>=10 fails/60s).
set -euo pipefail
cd "$(dirname "$0")/.."
. ./lib.sh
guard_target
# -t 4 keeps it under sshd's MaxStartups; 15 wrong passwords > the 10-in-60s threshold.
hydra -l labuser -P wordlists/passwords.txt -t 4 "ssh://$TARGET" || true
