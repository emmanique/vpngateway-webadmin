"""Conservative upstream IGD (miniupnpc) command planner for DIRECT port 6881.

This module will apply mappings only through explicit calls after matching the upstream IGD.
The privileged executor must bind SSDP discovery to the verified WAN interface,
prove that the discovered IGD matches the kernel default gateway, and check
ownership before attempting deletion. A private WAN address is not a public
reachability guarantee.
"""
from __future__ import annotations

from ipaddress import ip_address, ip_interface, ip_network
import re
import subprocess
from urllib.parse import urlsplit

INTERFACE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
PORT = "6881"


class IGDPreflightError(ValueError):
    pass


def _ipv4(value):
    try:
        obj = ip_address(value)
    except ValueError as exc:
        raise IGDPreflightError("Invalid IPv4") from exc
    if obj.version != 4 or obj.is_multicast or obj.is_loopback or obj.is_unspecified:
        raise IGDPreflightError("Unsupported IPv4")
    return str(obj)


def parse_igd_inventory(output: str, *, expected_gateway: str, expected_local: str) -> dict:
    """Parse upnpc -l; reject a different IGD and any existing foreign mapping."""
    if not isinstance(output, str) or len(output) > 65536:
        raise IGDPreflightError("Invalid IGD inventory")
    gateway = _ipv4(expected_gateway)
    local = _ipv4(expected_local)
    urls = re.findall(r"^\s*Found valid IGD\s*:\s*(https?://\S+)\s*$", output, flags=re.M)
    if len(urls) != 1:
        raise IGDPreflightError("Expected exactly one validated IGD")
    parsed = urlsplit(urls[0])
    if parsed.scheme != "http" or parsed.hostname != gateway or parsed.username or parsed.password:
        raise IGDPreflightError("IGD endpoint is not the upstream IPv4 gateway")
    descriptions = re.findall(r"^\s*desc:\s*(https?://\S+)\s*$", output, flags=re.M)
    roots = [url for url in descriptions if (
        urlsplit(url).scheme == "http" and urlsplit(url).hostname == gateway)]
    if len(roots) != 1:
        raise IGDPreflightError("Expected exactly one upstream root-description URL")
    lan = re.findall(r"^\s*Local LAN ip address\s*:\s*(\S+)\s*$", output, flags=re.M)
    if lan != [local]:
        raise IGDPreflightError("IGD sees an unexpected gateway source address")
    mappings = {}
    for line in output.splitlines():
        match = re.match(
            r"^\s*\d+\s+(TCP|UDP)\s+(\d+)->([0-9.]+):(\d+)\s+'([^']*)'",
            line, flags=re.I)
        if not match:
            continue
        protocol, external, internal_address, internal, description = match.groups()
        if int(external) != 6881:
            continue
        if protocol.upper() in mappings:
            raise IGDPreflightError("Multiple mappings for the same protocol and port")
        mappings[protocol.upper()] = {
            "external_port": 6881,
            "internal_ip": _ipv4(internal_address),
            "internal_port": int(internal),
            "description": description,
        }
    return {"gateway": gateway, "local": local, "control_url": urls[0],
            "url": roots[0], "mappings": mappings}


def owned_or_free(inventory: dict, *, owner: str) -> dict:
    """Do not overwrite a port already mapped by another service or host."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", owner):
        raise IGDPreflightError("Invalid host identifier")
    tag = "VPNGW-" + owner
    occupied = inventory.get("mappings") or {}
    missing = []
    owned = []
    for protocol in ("TCP", "UDP"):
        record = occupied.get(protocol)
        if not record:
            missing.append(protocol)
            continue
        if (record.get("internal_ip") != inventory["local"]
                or record.get("internal_port") != 6881
                or record.get("description") != tag):
            raise IGDPreflightError("Foreign 6881 mapping must not be replaced or deleted")
        owned.append(protocol)
    return {"tag": tag, "missing": missing, "owned": owned}


def build_direct_upstream_plan(
    *, interface: str, local_ipv4: str, default_gateway: str,
    route_interface: str, discovered_igd_ipv4: str | None,
    host_route: str, selected: bool, lease_seconds: int = 120,
):
    """Return exact commands only after cross-checking the observed IGD."""
    if not selected or host_route != "direct":
        return {"available": False, "reason": "not_selected_direct_host", "commands": []}
    if not isinstance(interface, str) or not INTERFACE.fullmatch(interface) or route_interface != interface:
        raise IGDPreflightError("WAN interface and route do not agree")
    local = _ipv4(local_ipv4)
    gateway = _ipv4(default_gateway)
    if not discovered_igd_ipv4:
        return {"available": False, "reason": "igd_not_confirmed", "commands": []}
    igd = _ipv4(discovered_igd_ipv4)
    if gateway != igd:
        raise IGDPreflightError("Discovered IGD is not the selected upstream gateway")
    if not ip_address(local).is_private:
        raise IGDPreflightError("UPnP upstream mapping expects a private gateway WAN IP")
    if not 30 <= lease_seconds <= 3600:
        raise IGDPreflightError("Unsupported lease lifetime")
    # The local IPv4 must be the address bound to the physical WAN interface
    # (not the final host and never the WireGuard tunnel address).
    commands = [
        ["/usr/bin/upnpc", "-m", interface, "-a", local, PORT, PORT,
         protocol.upper(), str(lease_seconds)]
        for protocol in ("tcp", "udp")
    ]
    return {"available": True, "reason": "preflight_only",
            "gateway": gateway, "local": local, "interface": interface,
            "commands": commands, "external_port": 6881,
            "forward_to_host_port": 6881, "verified": False,
            "delete_requires_ownership_check": True}


def run_verified_upnpc(*, interface: str, local_ipv4: str, gateway: str,
                       route_interface: str, host_route: str, selected: bool,
                       owner: str, mode: str, runner=subprocess.run):
    """Bounded executor; only touches mappings tagged as belonging to owner.

    This is an explicit opt-in operation, not called automatically by the API.
    The caller must provide kernel-observed route and local interface addresses.
    """
    if mode not in ("apply", "revoke"):
        raise IGDPreflightError("Unsupported operation")
    if mode == "apply":
        candidate = build_direct_upstream_plan(interface=interface, local_ipv4=local_ipv4,
                      default_gateway=gateway, route_interface=route_interface,
                      discovered_igd_ipv4=gateway, host_route=host_route, selected=selected)
        if not candidate["available"]:
            return candidate
    elif host_route != "direct" or route_interface != interface:
        raise IGDPreflightError("Cannot revoke on unverified DIRECT interface")
    listing = runner(["/usr/bin/upnpc", "-m", interface, "-l"], capture_output=True,
                     text=True, timeout=12)
    if listing.returncode:
        return {"available": False, "reason": "igd_discovery_failed"}
    observed = parse_igd_inventory(listing.stdout, expected_gateway=gateway,
                                   expected_local=local_ipv4)
    access = owned_or_free(observed, owner=owner)
    commands = []
    if mode == "apply":
        # Renew both leases on every reconciliation. Only adding missing
        # protocols would let already-owned 120-second leases expire between
        # checks, creating an avoidable inbound outage.
        for protocol in ("TCP", "UDP"):
            commands.append(["/usr/bin/upnpc", "-u", observed["url"], "-e", access["tag"],
                             "-a", local_ipv4, PORT, PORT, protocol, "120"])
    else:
        for protocol in access["owned"]:
            commands.append(["/usr/bin/upnpc", "-u", observed["url"], "-d", PORT, protocol])
    executed = []
    for argv in commands:
        result = runner(argv, capture_output=True, text=True, timeout=12)
        if result.returncode:
            raise IGDPreflightError("Upstream IGD rejected " + mode + " for " + argv[-2])
        executed.append(argv)
    refreshed = runner(["/usr/bin/upnpc", "-u", observed["url"], "-l"],
                       capture_output=True, text=True, timeout=12)
    if refreshed.returncode:
        raise IGDPreflightError("Cannot verify resulting upstream IGD inventory")
    final = parse_igd_inventory(refreshed.stdout, expected_gateway=gateway,
                                expected_local=local_ipv4)
    verified = owned_or_free(final, owner=owner)
    if mode == "apply" and verified["missing"]:
        raise IGDPreflightError("Upstream mappings missing after command")
    if mode == "revoke" and verified["owned"]:
        raise IGDPreflightError("Upstream mappings remain after revocation")
    return {"available": True, "mode": mode,
            "mapping_verified": True, "external_reachability_verified": False,
            "tcp_udp": verified["owned"], "changes": len(executed)}
