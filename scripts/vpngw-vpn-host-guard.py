#!/usr/bin/env python3
"""Generate a fail-closed, host-scoped nft guard. No kernel changes.
Requires an independent, verified per-host route and NAT before activation.
"""
import hashlib
import ipaddress
import re
import sys
import json

def _iface(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", value):
        raise ValueError("Invalid interface")
    return value

def render(policy_id, host_ip, mac, lan, vpn, dns_ipv4=None, central_dns=None):
    if not isinstance(policy_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", policy_id):
        raise ValueError("Invalid policy ID")
    host = str(ipaddress.IPv4Address(host_ip))
    if not ipaddress.IPv4Address(host).is_private:
        raise ValueError("Invalid private client address")
    if not isinstance(mac, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
        raise ValueError("Invalid MAC")
    mac = mac.lower()
    lan, vpn = _iface(lan), _iface(vpn)
    if lan == vpn:
        raise ValueError("VPN must use a separate network interface")
    dns = str(ipaddress.IPv4Address(dns_ipv4)) if dns_ipv4 else None
    import importlib.util
    spec = importlib.util.spec_from_file_location("vpngw_management_access",
        __import__("pathlib").Path(__file__).with_name("vpngw_management_access.py"))
    mgmt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mgmt)
    management_match = mgmt.match(host, mac, lan)
    management_rule = ('        ' + management_match + ' counter accept\n') if management_match else ''
    central_rules = ""
    if central_dns is not None:
        if dns_ipv4 is not None or not isinstance(central_dns, dict):
            raise ValueError("Central DNS cannot coexist with provider DNS redirect")
        bridge = _iface(central_dns.get("bridge_interface"))
        pihole_ip = ipaddress.IPv4Address(central_dns.get("pihole_ipv4"))
        if bridge in (lan, vpn) or not pihole_ip.is_private or pihole_ip.is_loopback:
            raise ValueError("Invalid central DNS bridge/IP")
        dns = str(pihole_ip)
        central_rules = (f'        iifname "{lan}" ether saddr {mac} ip saddr {host} oifname "{bridge}" ip daddr {dns} udp dport 53 counter accept\n'
                         f'        iifname "{lan}" ether saddr {mac} ip saddr {host} oifname "{bridge}" ip daddr {dns} tcp dport 53 counter accept\n'
                         f'        iifname "{bridge}" oifname "{lan}" ip saddr {dns} ip daddr {host} ct state established,related counter accept\n')
    dns_nat = (f"""    chain dns_redirect {{
        type nat hook prerouting priority dstnat - 5; policy accept;
        iifname "{lan}" ip saddr {host} ether saddr {mac} udp dport 53 dnat ip to {dns}
        iifname "{lan}" ip saddr {host} ether saddr {mac} tcp dport 53 dnat ip to {dns}
    }}
""" if dns else "")
    name = "vpngw_vpn_" + hashlib.sha256(policy_id.encode()).hexdigest()[:12]
    # MAC-based IPv6 filtering protects the same client even if its IPv6
    # address changes. VPN IPv4 is allowed only to the selected tunnel.
    return f'''table inet {name} {{
    chain forward_guard {{
        type filter hook forward priority -150; policy accept;
        iifname "{lan}" ether saddr {mac} meta nfproto ipv6 counter drop
        iifname "{lan}" ip saddr {host} ether saddr != {mac} counter drop
        iifname "{lan}" ether saddr {mac} ip saddr != {host} counter drop
{management_rule}{central_rules}        iifname "{lan}" ether saddr {mac} udp dport 53 oifname != "{vpn}" counter drop
        iifname "{lan}" ether saddr {mac} tcp dport 53 oifname != "{vpn}" counter drop
        # Standard DoT/DoQ may bypass provider DNS and central filtering.
        # Deny port 853 independently of the chosen VPN interface.
        iifname "{lan}" ether saddr {mac} tcp dport 853 counter drop
        iifname "{lan}" ether saddr {mac} udp dport 853 counter drop
        iifname "{lan}" ip saddr {host} oifname != "{vpn}" counter drop
        iifname "{vpn}" ip daddr {host} counter accept
    }}
    chain local_dns_guard {{
        type filter hook input priority -250; policy accept;
        iifname "{lan}" ether saddr {mac} udp dport 53 counter drop
        iifname "{lan}" ether saddr {mac} tcp dport 53 counter drop
    }}
    chain vpn_srcnat {{
        type nat hook postrouting priority srcnat + 20; policy accept;
        ip saddr {host} oifname "{vpn}" counter masquerade
    }}
{dns_nat}}}
'''

if __name__ == "__main__":
    data = json.load(sys.stdin)
    print(render(data["policy_id"], data["host_ip"], data["mac"], data["lan"], data["vpn"]), end="")
