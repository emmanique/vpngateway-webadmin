#!/usr/bin/env python3
"""Atomic DIRECT firewall + NAT restoration from a verified old plan.

Only run while the per-host fail-closed guard exists and is verified.
"""
import hashlib
import ipaddress
import re

def render(policy,plan):
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}",policy):
        raise ValueError("Invalid policy")
    if plan.get("destination")!="direct" or plan.get("shared") is not True:
        raise ValueError("Expected verified shared-interface DIRECT plan")
    host=str(ipaddress.IPv4Address(plan["host"]))
    lan=plan["lan"];wan=plan["wan"]
    if not all(re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}",v) for v in (lan,wan)):
        raise ValueError("Invalid interface")
    name="GW_"+hashlib.sha256(policy.encode()).hexdigest()[:16].upper()
    nat="vpngw_"+name.lower()
    return f'''flush chain ip filter {name}
add rule ip filter {name} iifname "{lan}" oifname "{wan}" ip saddr {host} ct state new,established,related counter accept
add rule ip filter {name} iifname "{wan}" oifname "{lan}" ip daddr {host} ct state established,related counter accept
flush chain ip {nat} postrouting
add rule ip {nat} postrouting ip saddr {host} oifname "{wan}" counter masquerade
'''
