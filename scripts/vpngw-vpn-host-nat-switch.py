#!/usr/bin/env python3
"""Offline atomic NAT switch for one verified host. No commands executed."""
import hashlib
import ipaddress
import re

def render(policy,host,wan,tunnel,nat_listing):
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}",policy):
        raise ValueError("Invalid policy")
    host=str(ipaddress.IPv4Address(host))
    if not all(re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}",x) for x in (wan,tunnel)):
        raise ValueError("Invalid interface")
    table="vpngw_gw_"+hashlib.sha256(policy.encode()).hexdigest()[:16]
    if not re.search(r"table ip "+table+r"\s*\{",nat_listing):
        raise ValueError("Legacy NAT table mismatch")
    if not all(token in nat_listing for token in ("chain postrouting",host,'oifname "'+wan+'"',"masquerade","chain no_redirect")):
        raise ValueError("DIRECT NAT snapshot not verified")
    # A single nftables batch replaces the original MASQUERADE rule.
    # The existing no_redirect chain is preserved.
    apply=f'''flush chain ip {table} postrouting
add rule ip {table} postrouting ip saddr {host} oifname "{tunnel}" counter masquerade
'''
    restore=f'''flush chain ip {table} postrouting
add rule ip {table} postrouting ip saddr {host} oifname "{wan}" counter masquerade
'''
    return {"policy":policy,"table":table,"apply":apply,"restore":restore,
            "applied":False,"ready":False,
            "preconditions":["independent host fail-closed guard active",
              "rollback armed","host source route points to tunnel",
              "Docker DNS reply forwarding verified"],
            "rollback":"restore DIRECT NAT only under host guard before removing VPN route"}
