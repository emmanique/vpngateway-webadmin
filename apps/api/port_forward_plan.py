"""Deterministic desired-state planner for per-host UPnP / port forwarding.

No firewall mutation is performed here: the privileged reconciler must apply the
plan atomically and verify the resulting dataplane before reporting success.
"""
from __future__ import annotations

from ipaddress import ip_address
from typing import Mapping


PORT = 6881
PROTOCOLS = ("tcp", "udp")


class PortForwardPlanError(ValueError):
    pass


def _valid_ipv4(value: str) -> str:
    try:
        ip = ip_address(value)
    except ValueError as exc:
        raise PortForwardPlanError("Invalid host IPv4") from exc
    if ip.version != 4 or not ip.is_private or ip.is_multicast or ip.is_loopback or ip.is_unspecified:
        raise PortForwardPlanError("Host must have a private LAN IPv4")
    return str(ip)


def build_port_forward_plan(
    policies: Mapping[str, dict],
    *,
    vpn_external_ports: Mapping[str, Mapping[str, int]] | None = None,
) -> dict:
    """Produce a policy- and protocol-specific desired state.

    UPnP is available per eligible host, subject to the actual selected route.
    The privileged static port-forward is exclusive to one selected host.
    External VPN ports must be *discovered*, never synthesized as 6881.
    A discovery of just UDP must not be misreported as TCP+UDP forwarding.
    """
    vpn_external_ports = vpn_external_ports or {}
    selected = [(pid, p) for pid, p in policies.items() if p.get("port_forward_enabled")]
    if len(selected) > 1:
        raise PortForwardPlanError("Only one host may own port forwarding")
    upnp = []
    for pid, p in policies.items():
        destination = p.get("destination", "blocked")
        if destination == "blocked":
            continue
        upnp.append({
            "policy_id": pid,
            "host_ip": _valid_ipv4(p["host_ip"]),
            "route": destination,
            "enabled": bool(p.get("upnp_enabled", True)),
        })
    if not selected:
        return {"upnp": upnp, "forwarding": None, "remove_stale_forwarding": True}

    pid, policy = selected[0]
    host_ip = _valid_ipv4(policy["host_ip"])
    route = policy.get("destination", "blocked")
    if route == "blocked":
        return {"upnp": upnp, "forwarding": None, "remove_stale_forwarding": True,
                "status": "blocked"}
    if route == "direct":
        mappings = [{"protocol": protocol, "internal_port": PORT, "external_port": PORT}
                    for protocol in PROTOCOLS]
        return {"upnp": upnp, "forwarding": {"policy_id": pid, "host_ip": host_ip,
                "route": "direct", "mappings": mappings}, "remove_stale_forwarding": True}

    discovered = vpn_external_ports.get(route, {})
    mappings = []
    for protocol in PROTOCOLS:
        port = discovered.get(protocol)
        if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
            mappings.append({"protocol": protocol, "internal_port": port, "external_port": port})
    # libtorrent uses the same listening port for TCP and UDP. Never
    # advertise partial provider discovery as a usable forwarding plan.
    if len(mappings) != len(PROTOCOLS):
        return {"upnp": upnp, "forwarding": None,
                "remove_stale_forwarding": True,
                "status": "vpn_tcp_udp_mapping_incomplete"}
    # Distinct provider port numbers cannot be configured as one listener.
    if len({mapping["internal_port"] for mapping in mappings}) > 1:
        return {"upnp": upnp, "forwarding": None,
                "remove_stale_forwarding": True,
                "status": "vpn_ports_conflict"}
    return {"upnp": upnp,
            "forwarding": ({"policy_id": pid, "host_ip": host_ip, "route": route,
                            "mappings": mappings} if mappings else None),
            "remove_stale_forwarding": True,
            "status": "discovered" if mappings else "upnp_only"}
