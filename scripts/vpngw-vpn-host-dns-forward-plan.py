#!/usr/bin/env python3
"""Read-only per-host DNS forwarding and reverse-path nft fixture.

Use only after host kill switch and source-specific DNS routing are active.
"""
import hashlib
import ipaddress
import re

def render(policy,host,lan,bridge,worker,client_mac):
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}",policy):
        raise ValueError("Invalid policy")
    h=ipaddress.IPv4Address(host)
    w=ipaddress.IPv4Address(worker)
    if not h.is_private or not w.is_private or h==w:
        raise ValueError("Invalid host/worker")
    if not all(re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}",x) for x in (lan,bridge)):
        raise ValueError("Invalid interface")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}",client_mac,re.I):
        raise ValueError("Invalid MAC")
    table="vpngw_host_dns_"+policy.replace("-","_")
    # Filter runs before Docker forwarding: allow only DNS to the dedicated worker.
    # The forward return path is conntrack ESTABLISHED/RELATED and pinned to the
    # expected worker bridge. Neither rule can authorize internet bypass.
    nft=f'''table inet {table} {{
 chain forward {{
  type filter hook forward priority -210; policy accept;
  iifname "{lan}" ether saddr {client_mac} ip saddr {h} oifname "{bridge}" ip daddr {w} meta l4proto {{ tcp, udp }} th dport 53 counter accept
  iifname "{bridge}" oifname "{lan}" ip saddr {w} ip daddr {h} ct state established,related counter accept
 }}
}}
'''
    return {"policy":policy,"host":str(h),"worker":str(w),
      "nft":nft,"applied":False,"ready":False,"table":table,
      "blockers":["Docker FORWARD path still requires verification",
                  "Kill switch, host-specific route and guarded NAT not applied",
                  "No real DNS traffic confirmation"]}
