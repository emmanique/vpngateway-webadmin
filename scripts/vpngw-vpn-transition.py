#!/usr/bin/env python3
"""Render strictly per-host fail-closed VPN firewall rules; no commands executed."""
from __future__ import annotations
import hashlib
import ipaddress
import re

IFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")

def render(profile: str, host: str, lan: str, vpn: str, management_ip: str,
           vpn_dns: str, client_mac: str) -> dict:
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", profile):
        raise ValueError("Invalid profile")
    for name in (lan, vpn):
        if not IFACE.fullmatch(name):
            raise ValueError("Invalid interface")
    if lan == vpn or not vpn.startswith("wg"):
        raise ValueError("Invalid VPN interface")
    client = ipaddress.IPv4Address(host)
    mgmt = ipaddress.IPv4Address(management_ip)
    dns = ipaddress.IPv4Address(vpn_dns)
    if not client.is_private or client == mgmt or dns in (client, mgmt):
        raise ValueError("Unsafe client or DNS address")
    mac = client_mac.lower()
    if not MAC.fullmatch(mac) or mac == "00:00:00:00:00:00":
        raise ValueError("Verified client MAC required")
    ident = hashlib.sha256((profile + ":" + host).encode()).hexdigest()[:12]
    guard, nat = "vpngw_vpn_" + ident, "vpngw_vnat_" + ident
    nft = f'''table inet {guard} {{
 chain forward_guard {{
  type filter hook forward priority -150; policy accept;
  iifname "{lan}" ether saddr {mac} meta nfproto ipv6 counter drop
  iifname "{lan}" ip saddr {client} udp dport 53 ip daddr != {dns} counter drop
  iifname "{lan}" ip saddr {client} tcp dport 53 ip daddr != {dns} counter drop
  iifname "{lan}" ip saddr {client} oifname != "{vpn}" counter drop
 }}
 chain input_guard {{
  type filter hook input priority -150; policy accept;
  iifname "{lan}" ether saddr {mac} meta nfproto ipv6 counter drop
  iifname "{lan}" ip saddr {client} udp dport 53 counter drop
  iifname "{lan}" ip saddr {client} tcp dport 53 counter drop
 }}
}}
table ip {nat} {{
 chain dns_redirect {{
  type nat hook prerouting priority -101; policy accept;
  iifname "{lan}" ip saddr {client} ip daddr {mgmt} udp dport 53 counter dnat to {dns}
  iifname "{lan}" ip saddr {client} ip daddr {mgmt} tcp dport 53 counter dnat to {dns}
 }}
 chain vpn_masquerade {{
  type nat hook postrouting priority 110; policy accept;
  ip saddr {client} oifname "{vpn}" counter masquerade
 }}
}}
'''
    return {"guard_table": guard, "nat_table": nat, "nft": nft,
            "host": str(client), "lan": lan, "vpn": vpn, "dns": str(dns),
            "mac": mac, "applied": False,
            "note": "Rendered only. Requires atomic activation, per-host Docker FORWARD accept and independent rollback."}
