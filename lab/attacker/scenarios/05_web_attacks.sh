#!/bin/bash
# T1190 Exploit Public-Facing Application: path traversal, SQLi and XSS in the URL → web_attack.
# URLs are percent-encoded as a real client would send them; the rule decodes them and matches.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./lib.sh
guard_target
req() { curl -s -o /dev/null --path-as-is "$1"; }
req "http://$TARGET/../../../../etc/passwd"                 # traversal
req "http://$TARGET/item?id=1%27+OR+%271%27%3D%271"         # SQLi: id=1' OR '1'='1
req "http://$TARGET/search?q=%3Cscript%3Ealert(1)%3C/script%3E"  # XSS: <script>alert(1)</script>
echo "sent 3 web attack requests"
