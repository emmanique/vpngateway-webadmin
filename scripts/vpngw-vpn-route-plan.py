#!/usr/bin/env python3
"""Read-only design and strict preflight of per-client VPN routing.

NEVER executes shell commands. A plan is not an installed firewall.
"""
from __future__ import annotations
import ipaddress
import hashlib
import re


def render_lab_nft(plan: dict) -> str:
    """Render a standalone nftables syntax-test fixture, never execute it."""
    if plan.get("status") != "proposal_only" or plan.get("applied") is not False:
        raise ValueError("Expected a non-applied route plan")
    host = str(ipaddress.IPv4Address(plan["host"]))
    lan = plan["interfaces"]["lan"]
    vpn = plan["interfaces"]["vpn"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", lan) or not re.fullmatch(r"(?:wg[a-f0-9]{11}|tun[a-f0-9]{10})", vpn):
        raise ValueError("Invalid interface")
    return f'''table inet vpngw_syntax_lab {{
    chain forwarded_guard {{
        type filter hook forward priority -150; policy accept;
        iifname "{lan}" ip saddr {host} udp dport 53 counter drop
        iifname "{lan}" ip saddr {host} tcp dport 53 counter drop
        iifname "{lan}" ip saddr {host} oifname != "{vpn}" counter drop
    }}
    chain local_dns_guard {{
        type filter hook input priority -150; policy accept;
        iifname "{lan}" ip saddr {host} udp dport 53 counter drop
        iifname "{lan}" ip saddr {host} tcp dport 53 counter drop
    }}
}}
'''


def build_plan(host_ip: str, gateway_ip: str, lan_iface: str, vpn_iface: str,
               vpn_profile: str, host_route: str, handshake: bool,
               ipv6_default: bool, dns_isolated: bool) -> dict:
    host = ipaddress.ip_address(host_ip)
    gateway = ipaddress.ip_address(gateway_ip)
    if host.version != 4 or gateway.version != 4 or not host.is_private or host == gateway:
        raise ValueError("Cliente/gateway IPv4 inválidos")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", lan_iface):
        raise ValueError("Interface LAN inválida")
    if not re.fullmatch(r"(?:wg[a-f0-9]{11}|tun[a-f0-9]{10})", vpn_iface):
        raise ValueError("Interface VPN inválida")
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", vpn_profile):
        raise ValueError("Perfil VPN inválido")
    table_id = 20000 + (int(hashlib.sha256((vpn_profile + ":" + str(host)).encode()).hexdigest()[:8], 16) % 20000)
    # Distinct host-scoped priorities. Collision protection is enforced by the live audit.
    priority = 10000 + (int(hashlib.sha256((vpn_profile + ":" + str(host)).encode()).hexdigest()[:8], 16) % 10000)
    blockers = []
    if host_route != "direct":
        blockers.append("Apenas a transição DIRECT para VPN é contemplada")
    if not handshake:
        blockers.append("WireGuard sem handshake recente")
    if ipv6_default:
        blockers.append("Rota IPv6 predefinida detectada no gateway")
    if not dns_isolated:
        blockers.append("DNS por túnel não isolado: deve ser bloqueado até existir resolução verificada")
    blockers.append("Transição atómica das regras DIRECT/VPN por validar em laboratório")
    blockers.append("Reversão independente e recuperação após reboot por validar")
    # Using 'iif' restricts policy routing to forwarded client traffic;
    # host originated management packets never match this rule.
    return {
        "status": "proposal_only", "applied": False, "ready": False,
        "host": str(host), "profile": vpn_profile,
        "interfaces": {"lan": lan_iface, "vpn": vpn_iface},
        "routing": {
            "table_id": table_id,
            "priority": priority,
            "policy_rule": f"ip rule add pref {priority} iif {lan_iface} from {host}/32 lookup {table_id}",
            "vpn_default": f"ip route replace default dev {vpn_iface} table {table_id}",
            "unreachable_fallback": f"ip route replace unreachable default metric 42700 table {table_id}",
            "note": "Unexecuted proposal. Route table IDs must be checked for collisions before installation. Main default route unchanged."
        },
        "firewall": {
            "family": "inet",
            "client_forward": f"iifname {lan_iface} ip saddr {host} oifname != {vpn_iface} drop",
            "vpn_return": f"iifname {vpn_iface} ip daddr {host} ct state established,related accept",
            "dns_guard": f"both input and forward hooks: iifname {lan_iface} ip saddr {host} udp dport 53 drop; tcp dport 53 drop",
            "ipv6_guard": "REQUIRES VERIFIED HOST MAC OR IPV6 SOURCE ADDRESS; do not drop IPv6 for all LAN clients",
            "policy": "Block any unexpected egress. No fallback to main table."
        },
        "transition": [
            "Save and verify current DIRECT state, topology and remote management",
            "Arm independent 180-second restore of previous DIRECT policy",
            "Install independent VPN-only forwarding guard before touching DIRECT",
            "Install isolated route table with terminal unreachable fallback",
            "Switch per-host policy route and remove obsolete DIRECT accepts atomically",
            "Test VPN exit, blocked direct exit, DNS and IPv6, then confirm or restore"
        ],
        "blockers": blockers,
        "scope": "Forwarded packets via gateway only; same-Wi-Fi L2 bypass not prevented"
    }
