#!/usr/bin/env bash
# A throwaway *network namespace* test. Never touches host interfaces.
set -euo pipefail
[[ $(id -u) -eq 0 ]] || { echo "Requires root"; exit 1; }
unshare --net -- /bin/bash -euo pipefail -c '
 ip link set lo up
 ip link add gwlablan type dummy
 ip link add gwlabwan type dummy
 ip link add wg123456789ab type dummy
 for dev in gwlablan gwlabwan wg123456789ab; do ip link set "$dev" up; done
 ip address add 10.66.4.1/24 dev gwlablan
 ip address add 198.18.0.2/24 dev gwlabwan
 ip route replace default dev gwlabwan
 table=21775
 ip route replace unreachable default metric 42700 table "$table"
 ip route replace default dev wg123456789ab metric 10 table "$table"
 ip rule add pref 1220 iif gwlablan from 10.66.4.17/32 lookup "$table"
 before=$(ip -4 route get 1.1.1.1 from 10.66.4.17 iif gwlablan)
 printf "TUNNEL_UP: %s\n" "$before"
 case "$before" in *"dev wg123456789ab"*) ;; *) echo "FAIL: not WireGuard-only"; exit 1;; esac
 nft -f - <<'NFT'
table inet gwlab_guards {
 chain client_forward {
   type filter hook forward priority -150; policy accept;
   iifname "gwlablan" ip saddr 10.66.4.17 udp dport 53 counter drop
   iifname "gwlablan" ip saddr 10.66.4.17 tcp dport 53 counter drop
   iifname "gwlablan" ip saddr 10.66.4.17 oifname != "wg123456789ab" counter drop
 }
 chain client_input {
   type filter hook input priority -150; policy accept;
   iifname "gwlablan" ip saddr 10.66.4.17 udp dport 53 counter drop
   iifname "gwlablan" ip saddr 10.66.4.17 tcp dport 53 counter drop
 }
}
NFT
 nft list table inet gwlab_guards | grep -Fq "oifname !="
 echo "DNS_AND_EGRESS_FIREWALL_LOADED: true (isolated namespace)"
 ip link delete wg123456789ab
 if after=$(ip -4 route get 1.1.1.1 from 10.66.4.17 iif gwlablan 2>&1); then
   printf "FAIL: fell through on missing VPN: %s\n" "$after"; exit 1
 else
   printf "TUNNEL_DOWN: %s\n" "$after"
 fi
 original=$(ip -4 route get 1.1.1.1)
 printf "HOST_NAMESPACE_DEFAULT_UNCHANGED: %s\n" "$original"
 printf "RESULT: isolated route fail-closed PASS\n"
'
