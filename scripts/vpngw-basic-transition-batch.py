#!/usr/bin/env python3
"""Render nft transaction for one existing host policy, no side effects."""
import ipaddress
import re
import sys
def batch(policy_id, plan, target):
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}",policy_id):
        raise ValueError("Invalid policy ID")
    if target not in ("direct", "blocked"):
        raise ValueError("Unsupported transition")
    import hashlib
    chain="GW_"+hashlib.sha256(policy_id.encode()).hexdigest()[:16].upper()
    host=str(ipaddress.IPv4Address(plan["host"]))
    mac=str(plan["registered_mac"]).lower()
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}",mac):
        raise ValueError("Missing registered MAC")
    lan,wan=plan["lan"],plan["wan"]
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}",x) for x in (lan,wan)):
        raise ValueError("Invalid interface")
    lines=[f"flush chain ip filter {chain}",
           f'add rule ip filter {chain} iifname "{lan}" ip saddr {host} ether saddr != {mac} drop comment "vpngw_identity_guard"']
    if target=="blocked":
        lines.extend([f'add rule ip filter {chain} iifname "{lan}" ip saddr {host} counter drop',
                      f'add rule ip filter {chain} ip daddr {host} counter drop'])
    else:
        lines.extend([f'add rule ip filter {chain} iifname "{lan}" oifname "{wan}" ip saddr {host} ct state new,established,related counter accept',
                      f'add rule ip filter {chain} iifname "{wan}" oifname "{lan}" ip daddr {host} ct state established,related counter accept'])
    return "\n".join(lines)+"\n"
if __name__=="__main__":
    import json
    print(batch(sys.argv[1],json.load(sys.stdin),sys.argv[2]),end="")
