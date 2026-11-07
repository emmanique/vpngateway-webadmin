#!/usr/bin/env bash
set -euo pipefail
# No real host interfaces visible: never run packet tests in the production namespace.
unshare --net -- bash -euo pipefail -c '
if ip link show wlp2s0 >/dev/null 2>&1; then exit 90; fi
ip link set lo up
ip link add testlan type veth peer name testpeer
ip link set testlan up
clientns="vpngwlab$$"
trap "ip netns del \$clientns 2>/dev/null || true" EXIT
ip netns add "$clientns"
ip link set testpeer netns "$clientns"
ip -n "$clientns" link set lo up
ip -n "$clientns" link set testpeer up
ip -4 addr add 192.168.1.221/24 dev testlan
ip -n "$clientns" -4 addr add 192.168.1.249/24 dev testpeer
ip -6 addr add fd01::1/64 dev testlan
ip -n "$clientns" -6 addr add fd01::249/64 dev testpeer
nft -f - <<NFT
table inet leak_lab {
 chain input { type filter hook input priority -205; policy accept;
  iifname "testlan" ip6 saddr fd01::249 counter drop
  iifname "testlan" ip saddr 192.168.1.249 udp dport 53 counter drop
  iifname "testlan" ip saddr 192.168.1.249 tcp dport 53 counter drop
 }
}
NFT
# Positive baseline: IPv4 ICMP to local gateway must work.
ip netns exec "$clientns" ping -c 1 -W 1 -I testpeer 192.168.1.221 >/dev/null
# Wait until IPv6 DAD completes before exercising the firewall rule.
sleep 2
# IPv6 packet is denied by firewall; no reply.
if ip netns exec "$clientns" ping -6 -c 1 -W 1 -I testpeer fd01::1 >/dev/null 2>&1; then exit 91; fi
# Send both UDP and TCP DNS probe packets to the forbidden local resolver.
ip netns exec "$clientns" python3 - <<PY
import socket
q=bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
u.bind(("192.168.1.249",0))
u.sendto(q,("192.168.1.221",53))
t=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
t.bind(("192.168.1.249",0));t.settimeout(0.5)
try:t.connect(("192.168.1.221",53))
except OSError:pass
PY
# Check that each of the three DENY rules actually matched a packet.
nft -j list chain inet leak_lab input | python3 -c "import json,sys; d=json.load(sys.stdin); rules=[x[\"rule\"] for x in d[\"nftables\"] if \"rule\" in x]; counts=[next((e[\"counter\"][\"packets\"] for e in r[\"expr\"] if \"counter\" in e),0) for r in rules]; assert len(counts)==3 and all(n>0 for n in counts), counts; print(\"DENY_RULE_PACKET_COUNTS\",counts)"
echo VPN_LEAK_NETNS_IPV6_AND_DNS_DENIED_PASS
'
