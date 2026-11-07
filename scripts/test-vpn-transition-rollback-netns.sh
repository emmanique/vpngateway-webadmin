#!/usr/bin/env bash
# Isolated transition and rollback fixture; NEVER changes host networking.
set -euo pipefail
[[ $(id -u) -eq 0 ]] || exit 1
unshare --net -- /bin/bash -euo pipefail -c '
ip link set lo up
ip link add lan-test type dummy
ip link add wan-test type dummy
ip link add wg123456789ab type dummy
for nic in lan-test wan-test wg123456789ab; do ip link set "$nic" up; done
ip addr add 10.77.8.1/24 dev lan-test
ip addr add 198.18.7.2/24 dev wan-test
ip route replace default dev wan-test
client=10.77.8.42
table=21775
baseline=$(ip route get 9.9.9.9 from "$client" iif lan-test)
case "$baseline" in *"dev wan-test"*) ;; *) printf "No DIRECT baseline: %s\n" "$baseline"; exit 1;; esac
echo "BASELINE_DIRECT: $baseline"
# Stage fail-closed before transitioning: guard drops all incorrect WAN egress.
nft -f - <<\NFT
table inet gw_transition {
 chain forward_guard {
  type filter hook forward priority -150; policy accept;
  iifname "lan-test" ip saddr 10.77.8.42 udp dport 53 counter drop
  iifname "lan-test" ip saddr 10.77.8.42 tcp dport 53 counter drop
  iifname "lan-test" ip saddr 10.77.8.42 oifname != "wg123456789ab" counter drop
 }
 chain input_guard {
  type filter hook input priority -150; policy accept;
  iifname "lan-test" ip saddr 10.77.8.42 udp dport 53 counter drop
  iifname "lan-test" ip saddr 10.77.8.42 tcp dport 53 counter drop
 }
}
NFT
ip route replace unreachable default metric 42700 table "$table"
ip route replace default dev wg123456789ab metric 10 table "$table"
ip rule add pref 1220 iif lan-test from "$client"/32 lookup "$table"
vpn=$(ip route get 9.9.9.9 from "$client" iif lan-test)
case "$vpn" in *"dev wg123456789ab"*) echo "TRANSITION_TO_VPN: PASS";; *) echo "Transition failed: $vpn"; exit 1;; esac
# Fail the VPN, then ensure routing CANNOT fall through to the DIRECT default.
ip link delete wg123456789ab
if leaked=$(ip route get 9.9.9.9 from "$client" iif lan-test 2>&1); then
 echo "FAIL: VPN fallback reached DIRECT: $leaked"; exit 1
fi
echo "VPN_FAILURE_FAIL_CLOSED: PASS"
# Simulate watchdog restoring original policy in its own privileged context.
ip rule del pref 1220 iif lan-test from "$client"/32 lookup "$table"
ip route flush table "$table"
nft delete table inet gw_transition
restored=$(ip route get 9.9.9.9 from "$client" iif lan-test)
case "$restored" in *"dev wan-test"*) ;; *) echo "FAIL: DIRECT restoration: $restored"; exit 1;; esac
[[ -z $(ip rule show | grep "lookup $table" || true) ]] || { echo "FAIL: dangling rule"; exit 1; }
! nft list table inet gw_transition >/dev/null 2>&1 || { echo "FAIL: dangling firewall"; exit 1; }
echo "ROLLBACK_RESTORED_DIRECT_AND_REMOVED_GUARDS: PASS"
# Confirmed-VPN policy: no rollback to DIRECT on tunnel failure.
ip link add wg123456789ab type dummy
ip link set wg123456789ab up
ip route replace unreachable default metric 42700 table "$table"
ip route replace default dev wg123456789ab metric 10 table "$table"
ip rule add pref 1220 iif lan-test from "$client"/32 lookup "$table"
confirmed=$(ip route get 9.9.9.9 from "$client" iif lan-test)
case "$confirmed" in *"dev wg123456789ab"*) ;; *) echo "FAIL: confirmed tunnel routing"; exit 1;; esac
ip link delete wg123456789ab
if escaped=$(ip route get 9.9.9.9 from "$client" iif lan-test 2>&1); then
 echo "FAIL: confirmed VPN leaked after tunnel failure: $escaped"; exit 1
fi
ip rule show | grep -q "lookup $table" || { echo "FAIL: confirmed policy vanished"; exit 1; }
echo "CONFIRMED_VPN_FAILURE_REMAINS_BLOCKED: PASS"
echo "RESULT: isolated transition rollback and confirmed fail-closed PASS"
'
