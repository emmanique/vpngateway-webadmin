"""Official Proton VPN manual NAT-PMP contract for WireGuard and OpenVPN.

Reference: https://protonvpn.com/support/port-forwarding-manual-setup
Both transports use the same NAT-PMP gateway/lease loop. OpenVPN needs a
+pmp authentication suffix; WG requires a P2P server and NAT-PMP enabled
when generating its configuration. Those requirements cannot be inferred
from tunnel connectivity alone.
"""
from __future__ import annotations

import re

GATEWAY = "10.2.0.1"
LEASE_SECONDS = 60
RENEW_SECONDS = 45
MIN_FIXED_NATPMP_VERSION = 20230423


def is_openvpn_pmp_username(username: str) -> bool:
    """Only inspect local credential syntax; never return or log the username."""
    if not isinstance(username, str) or not username or len(username) > 256:
        return False
    # +pmp can be combined with Proton's other username suffixes (+f2).
    return "pmp" in username.split("+")[1:]


def provider_readiness(*, protocol: str, p2p_confirmed: bool,
                       openvpn_pmp_authorized: bool = False,
                       wireguard_natpmp_enabled: bool = False,
                       moderate_nat_enabled: bool = False):
    if protocol not in ("wireguard", "openvpn"):
        return {"ready": False, "reason": "unsupported_vpn_protocol"}
    if moderate_nat_enabled:
        return {"ready": False, "reason": "moderate_nat_incompatible"}
    if not p2p_confirmed:
        return {"ready": False, "reason": "p2p_server_not_confirmed"}
    if protocol == "openvpn" and not openvpn_pmp_authorized:
        return {"ready": False, "reason": "openvpn_pmp_suffix_missing"}
    if protocol == "wireguard" and not wireguard_natpmp_enabled:
        return {"ready": False, "reason": "wireguard_natpmp_option_unconfirmed"}
    return {"ready": True, "reason": "configuration_ready_not_live_mapping"}


def mapping_command(protocol: str, *, public_hint: int = 1,
                    lifetime: int = LEASE_SECONDS):
    if protocol not in ("udp", "tcp"):
        raise ValueError("Invalid mapping transport")
    if type(public_hint) is not int or not 1 <= public_hint <= 65535:
        raise ValueError("Invalid external hint")
    if type(lifetime) is not int or not 30 <= lifetime <= 3600:
        raise ValueError("Invalid lease")
    # Proton's documented request: natpmpc -a 1 0 udp 60 -g 10.2.0.1.
    # NAT-PMP's protocol-local private port is 0, NOT the final LAN app port.
    # The gateway DNAT can separately target the application on 6881.
    return ["/usr/bin/natpmpc", "-a", str(public_hint), "0", protocol,
            str(lifetime), "-g", GATEWAY]


def natpmp_binary_version_acceptable(version: str) -> bool:
    if not isinstance(version, str):
        return False
    numbers = [int(v) for v in re.findall(r"(?<!\d)(20\d{6})(?!\d)", version)]
    return bool(numbers and max(numbers) >= MIN_FIXED_NATPMP_VERSION)
