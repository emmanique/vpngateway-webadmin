#!/usr/bin/env python3
"""Generate the existing host-chain VPN filter replacement as one nft batch."""
import hashlib
import ipaddress
import re

def generate(policy_id, host_ip, mac, lan, vpn, central_dns=None):
    if not isinstance(policy_id,str) or not re.fullmatch(r'[a-z][a-z0-9-]{1,31}',policy_id):
        raise ValueError('Invalid policy id')
    host=str(ipaddress.IPv4Address(host_ip))
    if not isinstance(mac,str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',mac):
        raise ValueError('Invalid MAC')
    if not all(isinstance(x,str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',x) for x in (lan,vpn)):
        raise ValueError('Invalid interface')
    chain='GW_'+hashlib.sha256(policy_id.encode()).hexdigest()[:16].upper()
    mac=mac.lower()
    central_rules = ""
    if central_dns is not None:
        if not isinstance(central_dns, dict):
            raise ValueError("Invalid central DNS mapping")
        bridge = central_dns.get("bridge_interface")
        pihole = ipaddress.IPv4Address(central_dns.get("pihole_ipv4"))
        if (not isinstance(bridge, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", bridge)
                or bridge in (lan, vpn) or not pihole.is_private or pihole.is_loopback):
            raise ValueError("Invalid central DNS target")
        central_rules = (
            f'add rule ip filter {chain} iifname "{lan}" oifname "{bridge}" ip saddr {host} ip daddr {pihole} udp dport 53 counter accept\\n'
            f'add rule ip filter {chain} iifname "{lan}" oifname "{bridge}" ip saddr {host} ip daddr {pihole} tcp dport 53 counter accept\\n'
            f'add rule ip filter {chain} iifname "{bridge}" oifname "{lan}" ip saddr {pihole} ip daddr {host} ct state established,related counter accept\\n'
        ).replace("\\n", "\n")
    return f'''flush chain ip filter {chain}
add rule ip filter {chain} iifname "{lan}" ether saddr {mac} ip saddr != {host} drop comment "vpngw_ip_rebind_guard"
add rule ip filter {chain} iifname "{lan}" ip saddr {host} ether saddr != {mac} drop comment "vpngw_identity_guard"
{central_rules}add rule ip filter {chain} iifname "{lan}" oifname "{vpn}" ip saddr {host} ct state new,established,related counter accept
add rule ip filter {chain} iifname "{vpn}" oifname "{lan}" ip daddr {host} counter accept
'''
