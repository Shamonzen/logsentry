#!/bin/bash
# T1110 Brute Force: a burst of POSTs to a login page → web_login_bruteforce (>=10 in 60 s).
# The lab target serves static files only, so each POST gets an error; the rule counts attempts.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./lib.sh
guard_target
for i in $(seq 1 12); do
    curl -s -o /dev/null -X POST -d "log=admin&pwd=guess$i" "http://$TARGET/wp-login.php"
done
echo "sent 12 login attempts"
