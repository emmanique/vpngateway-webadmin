#!/usr/bin/env bash
set -euo pipefail
# Temporary per-host trial, valid only for live topology. No changes to DIRECT policy.
host="${1:?client_ipv4}" lan="${2:?lan_interface}" vpn="${3:?vpn_interface}" dns="${4:?vpn_dns}" mgmt="${5:?gateway_management_ip}" mac="${6:?verified_client_mac}" table="${7:?table_id}" priority="${8:?rule_priority}"
rollback=/usr/local/libexec/vpngw-vpn-trial-revert.sh
[[ $(id -u) == 0 && -x "$rollback" ]] || exit 1
[[ "$lan" =~ ^[a-zA-Z0-9_.-]{1,15}$ && "$vpn" =~ ^wg[a-f0-9]{11}$ && "$mac" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || exit 1
[[ "$table" =~ ^[0-9]{5}$ && "$priority" =~ ^[0-9]{5}$ ]] || exit 1
ip -4 address show dev "$lan" | grep -q "$mgmt/" || { echo "MANAGEMENT_IP_MISMATCH"; exit 1; }
ip -4 neigh show "$host" dev "$lan" | grep -qi "lladdr $mac " || { echo "CLIENT_MAC_UNVERIFIED"; exit 1; }
ip link show dev "$vpn" >/dev/null
wg show "$vpn" latest-handshakes | awk -v now="$(date +%s)" '($NF+0>0 && now-$NF<300){found=1}END{exit !found}' || { echo "STALE_VPN_HANDSHAKE"; exit 1; }
[[ -z $(ip -4 rule show | awk -v p="$priority:" '$1==p') ]] || { echo "RULE_COLLISION"; exit 1; }
[[ -z $(ip -4 route show table "$table" 2>/dev/null) ]] || { echo "ROUTE_TABLE_COLLISION"; exit 1; }
! nft list table inet vpngw_trial_guard >/dev/null 2>&1 || exit 1
! nft list table ip vpngw_trial_nat >/dev/null 2>&1 || exit 1
# Arm independent timer before any system network changes.
systemd-run --quiet --unit=vpngw-vpn-trial-revert2 --on-active=180s "$rollback" "$host" "$lan" "$table" "$priority"
systemctl is-active --quiet vpngw-vpn-trial-revert2.timer || { echo "ROLLBACK_TIMER_NOT_ARMED"; exit 1; }
trap '"$rollback" "$host" "$lan" "$table" "$priority"' ERR
# Scope all packet guards to source IP or verified MAC, not globally to the LAN.
nft -f - <<NFT
table inet vpngw_trial_guard {
 chain forward_guard {
  type filter hook forward priority -150; policy accept;
  iifname "$lan" ether saddr $mac meta nfproto ipv6 counter drop
  iifname "$lan" ip saddr $host udp dport 53 ip daddr != $dns counter drop
  iifname "$lan" ip saddr $host tcp dport 53 ip daddr != $dns counter drop
  iifname "$lan" ip saddr $host oifname != "$vpn" counter drop
 }
 chain input_guard {
  type filter hook input priority -150; policy accept;
  iifname "$lan" ether saddr $mac meta nfproto ipv6 counter drop
  iifname "$lan" ip saddr $host udp dport 53 counter drop
  iifname "$lan" ip saddr $host tcp dport 53 counter drop
 }
}
table ip vpngw_trial_nat {
 chain dns_redirect {
  type nat hook prerouting priority -101; policy accept;
  iifname "$lan" ip saddr $host udp dport 53 counter dnat to $dns
  iifname "$lan" ip saddr $host tcp dport 53 counter dnat to $dns
 }
 chain vpn_masquerade {
  type nat hook postrouting priority 110; policy accept;
  ip saddr $host oifname "$vpn" counter masquerade
 }
}
NFT
ip -4 route replace unreachable default metric 42700 table "$table"
ip -4 route replace default dev "$vpn" metric 10 table "$table"
# Existing Docker policy is preserved. These two matches precede its DIRECT jump.
nft insert rule ip filter DOCKER-USER iifname "$lan" oifname "$vpn" ip saddr "$host" counter accept comment "vpngw_trial_outgoing"
nft insert rule ip filter DOCKER-USER iifname "$vpn" oifname "$lan" ip daddr "$host" ct state established,related counter accept comment "vpngw_trial_incoming"
ip -4 rule add pref "$priority" iif "$lan" from "$host/32" lookup "$table"
ip -4 route get 1.1.1.1 from "$host" iif "$lan" | grep -q "dev $vpn" || { echo "VPN_POLICY_ROUTE_FAILED"; exit 1; }
trap - ERR
echo "TRIAL_ACTIVE expires_in=180s host=$host vpn=$vpn timer=vpngw-vpn-trial-revert2.timer"
