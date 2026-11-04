#!/usr/bin/env python3
"""Privileged, host-scoped DNAT reconciler for managed port 6881.

A selected reservation is not evidence of a working forwarding path.
Only use this behind the authenticated policy-agent socket, and only
after inspecting the locally confirmed, persistent host route.
No blanket FORWARD ACCEPT or WAN fallback is ever installed.
"""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess

TABLE = "vpngw_port_forward"
PORT = 6881
PROTOCOLS = ("tcp", "udp")
NAME = re.compile(r"^[a-zA-Z0-9_.-]{1,15}$")


class ForwardingError(ValueError):
    pass


def _host(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ForwardingError("Invalid forwarding host") from exc
    if address.version != 4 or not address.is_private or address.is_loopback or address.is_unspecified:
        raise ForwardingError("Forwarding host must be private LAN IPv4")
    return str(address)


def _interface(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ForwardingError("Invalid ingress interface")
    return value


def _port(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ForwardingError("Invalid discovered external port")
    return value


def normalise_mapping(selection: dict | None, confirmed: dict | None):
    """Reject plans that do not match the kernel-confirmed host route."""
    if not selection:
        return None
    if not confirmed or confirmed.get("status") != "active" or not confirmed.get("applied"):
        raise ForwardingError("Host policy is not confirmed active")
    state = confirmed.get("plan") or {}
    if selection.get("host_ip") != state.get("host"):
        raise ForwardingError("Host does not match persistent policy")
    host = _host(selection["host_ip"])
    route = selection.get("route")
    if route in (None, "blocked") or route != state.get("destination"):
        raise ForwardingError("Route is blocked or inconsistent with active policy")
    if not state.get("registered_mac"):
        raise ForwardingError("Registered host identity required")
    if route == "direct":
        ingress = _interface(state.get("wan"))
    else:
        runtime = confirmed.get("vpn_runtime") or {}
        ingress = _interface(runtime.get("interface"))
        if runtime.get("interface") != selection.get("vpn_interface"):
            raise ForwardingError("VPN interface not confirmed")
        if not selection.get("vpn_connected", False):
            raise ForwardingError("VPN not connected: do not expose inbound port")
    addresses = selection.get("ingress_ipv4") or []
    if not isinstance(addresses, list) or not addresses:
        raise ForwardingError("Ingress IPv4 not verified")
    ipv4 = []
    for item in addresses:
        try:
            parsed = ipaddress.ip_address(item)
        except ValueError as exc:
            raise ForwardingError("Invalid ingress IP") from exc
        if parsed.version != 4 or parsed.is_unspecified or parsed.is_multicast:
            raise ForwardingError("Invalid ingress IP")
        ipv4.append(str(parsed))
    mappings = selection.get("mappings") or []
    if not isinstance(mappings, list) or len(mappings) != len(PROTOCOLS):
        raise ForwardingError("Both TCP and UDP mappings must be verified")
    seen = set()
    normalized = []
    for item in mappings:
        protocol = item.get("protocol")
        if protocol not in PROTOCOLS or protocol in seen:
            raise ForwardingError("Invalid or duplicate protocol mapping")
        seen.add(protocol)
        external = _port(item.get("external_port"))
        if route == "direct" and external != PORT:
            raise ForwardingError("Direct route must use port 6881")
        internal = _port(item.get("internal_port"))
        if route == "direct" and internal != PORT:
            raise ForwardingError("Direct route must retain local port 6881")
        if route != "direct" and internal != external:
            raise ForwardingError("VPN requires internal port to match provider port")
        normalized.append({"protocol": protocol, "external_port": external,
                           "internal_port": internal})
    # Libtorrent uses one listen port for TCP and UDP; unequal provider ports
    # cannot safely be applied to a single container runtime.
    if route != "direct" and len({p["internal_port"] for p in normalized}) > 1:
        raise ForwardingError("Provider TCP/UDP ports differ; single libtorrent port unavailable")
    return {"host": host, "interface": ingress, "addresses": sorted(set(ipv4)),
            "mappings": normalized, "route": route}


def nft_script(selection: dict | None, confirmed: dict | None, *, table_exists=False):
    """Render a single atomic nft batch; empty plan removes only owned table."""
    lines = [f"delete table ip {TABLE}"] if table_exists else []
    normalized = normalise_mapping(selection, confirmed) if selection else None
    if not normalized:
        return "\n".join(lines) + ("\n" if lines else ""), None
    lines.extend([
        f"add table ip {TABLE}",
        f"add chain ip {TABLE} prerouting {{ type nat hook prerouting priority -105; policy accept; }}",
    ])
    for address in normalized["addresses"]:
        for mapping in normalized["mappings"]:
            protocol = mapping["protocol"]
            port = mapping["external_port"]
            lines.append(f'add rule ip {TABLE} prerouting iifname "{normalized["interface"]}" '
                         f"ip daddr {address} {protocol} dport {port} "
                         f'dnat to {normalized["host"]}:{mapping["internal_port"]}')
    return "\n".join(lines) + "\n", normalized


def apply(nft_path: str, selection: dict | None, confirmed: dict | None, *,
          runner=subprocess.run):
    """Never change unrelated nftables tables. Success means ruleset verified, not WAN reachability."""
    observed = runner([nft_path, "list", "table", "ip", TABLE],
                      capture_output=True, text=True, timeout=8)
    exists = observed.returncode == 0
    if not exists and observed.returncode not in (1,):
        raise ForwardingError("Cannot inspect owned nftables table")
    batch, normalized = nft_script(selection, confirmed, table_exists=exists)
    if not batch:
        return {"applied": False, "removed": True, "route": None}
    runner([nft_path, "-c", "-f", "-"], input=batch, text=True,
           capture_output=True, check=True, timeout=8)
    runner([nft_path, "-f", "-"], input=batch, text=True,
           capture_output=True, check=True, timeout=8)
    check = runner([nft_path, "list", "table", "ip", TABLE],
                   capture_output=True, text=True, timeout=8)
    if normalized and (check.returncode or not all("dnat to " + normalized["host"] + ":" + str(mapping["internal_port"]) in check.stdout
                             for mapping in normalized["mappings"])):
        raise ForwardingError("DNAT rules were not verified")
    if not normalized and check.returncode == 0:
        raise ForwardingError("Stale forwarding table remains")
    return {"applied": bool(normalized), "removed": not bool(normalized),
            "route": normalized["route"] if normalized else None,
            "protocols": [x["protocol"] for x in normalized["mappings"]] if normalized else [],
            "path_tested": False}
