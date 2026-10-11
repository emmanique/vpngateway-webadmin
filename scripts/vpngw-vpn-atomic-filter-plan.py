#!/usr/bin/env python3
"""Offline nftables atomic batch to convert existing per-host DIRECT chain to VPN.

The per-policy DOCKER-USER jumps remain in place; a single nft transaction
replaces only the referenced chain's body. It is intentionally not executed.
"""
import hashlib
import ipaddress
import re

def render(policy,host,lan,vpn,worker,chain_listing,docker_listing,bridge=None):
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}",policy):
        raise ValueError("invalid policy")
    host=str(ipaddress.IPv4Address(host))
    worker=str(ipaddress.IPv4Address(worker))
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}",lan) or not re.fullmatch(r"(?:tun[a-f0-9]{10}|wg[a-f0-9]{11})",vpn):
        raise ValueError("invalid interface")
    if bridge is not None and not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}",bridge):
        raise ValueError("invalid worker bridge")
    chain="GW_"+hashlib.sha256(policy.encode()).hexdigest()[:16].upper()
    if not re.search(r"chain "+chain+r"\s*\{",chain_listing) or "accept" not in chain_listing:
        raise ValueError("original DIRECT chain not verified")
    lines=[line for line in docker_listing.splitlines() if "jump "+chain in line]
    if len(lines)!=2 or not all(host in line for line in lines):
        raise ValueError("existing per-policy Docker jump not verified")
    dns_reply=(f'add rule ip filter {chain} iifname "{bridge}" oifname "{lan}" ip saddr {worker} ip daddr {host} meta l4proto {{ tcp, udp }} ct state established,related counter accept\n'
               if bridge else '')
    batch=f'''flush chain ip filter {chain}
add rule ip filter {chain} iifname "{lan}" ip saddr {host} ip daddr {worker} meta l4proto {{ tcp, udp }} th dport 53 counter accept
{dns_reply}add rule ip filter {chain} iifname "{lan}" ip saddr {host} oifname "{vpn}" ct state new,established,related counter accept
add rule ip filter {chain} iifname "{vpn}" ip daddr {host} ct state established,related counter accept
add rule ip filter {chain} iifname "{lan}" ip saddr {host} counter drop
'''
    return {"policy":policy,"host":host,"chain":chain,"batch":batch,
            "network_changes":False,"applied":False,
            "preconditions":["independent fail-closed host guard installed",
                             "host VPN routing policy active and checked",
                             "legacy per-host DIRECT NAT removed only after guard",
                             "Docker DNS worker reverse path verified"],
            "rollback_requires":"restore exact DIRECT chain under guard before removing VPN policy"}
