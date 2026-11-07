#!/usr/bin/env bash
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/vpngw-vpn-boot-guard.py"
unshare --net -- env BOOT_GUARD_SCRIPT="$script" bash -euo pipefail -c '
 temp="$(mktemp -d)"
 trap "rm -rf \"$temp\"" EXIT
 printf "%s\n" '\''{"id":"client-test","host":"10.99.8.17","lan":"lablan","vpn":"wg123456789ab","mac":"12:34:56:78:9a:bc","confirmed":true}'\'' > "$temp/client-test.json"
 chmod 600 "$temp/client-test.json"
 python3 "$BOOT_GUARD_SCRIPT" check --directory "$temp"
 python3 "$BOOT_GUARD_SCRIPT" install --directory "$temp"
 python3 "$BOOT_GUARD_SCRIPT" install --directory "$temp"
 nft list table inet vpngw_boot_client_test | grep "oifname !="
 nft list table inet vpngw_boot_client_test | grep "ether saddr"
 echo "BOOT_GUARD_ISOLATED_INSTALL_AND_RESTART_PASS"
'
