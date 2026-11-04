#!/usr/bin/env python3
"""Verified upstream IGD management for the exclusive DIRECT host.

This does NOT run a local miniupnpd server. It controls the existing physical
upstream router via miniupnpc, mapping 6881 TCP+UDP to the Gateway WAN IP.
The Gateway's separately verified DNAT forwards to the selected host.
Never use an upstream IGD for a VPN route or replace a foreign mapping.
"""
from __future__ import annotations
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import subprocess

IP = "/usr/sbin/ip"
UPNPC = Path("/usr/bin/upnpc")


def _load():
    path = Path(__file__).with_name("vpngw-upnpc-upstream.py")
    spec = importlib.util.spec_from_file_location("vpngw_upnpc_upstream_bound", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wan_context(state: dict, *, runner=subprocess.run) -> dict:
    plan = state.get("plan") or {}
    wan = plan.get("wan")
    gateway = plan.get("gateway")
    if (state.get("status") != "active" or
            plan.get("destination") != "direct" or
            not isinstance(wan, str) or
            not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", wan)):
        raise ValueError("UPnP requires a confirmed DIRECT host on a WAN")
    gateway = str(ipaddress.IPv4Address(gateway))
    routes = runner([IP, "-j", "-4", "route", "show", "default"],
                    capture_output=True, text=True, timeout=8, check=True)
    matching = [route for route in json.loads(routes.stdout)
                if route.get("dev") == wan and route.get("gateway") == gateway]
    if len(matching) != 1:
        raise ValueError("Confirmed WAN default route/gateway is unavailable")
    addresses = runner([IP, "-j", "-4", "address", "show", "dev", wan],
                       capture_output=True, text=True, timeout=8, check=True)
    interfaces = json.loads(addresses.stdout)
    if len(interfaces) != 1 or interfaces[0].get("ifname") != wan:
        raise ValueError("WAN interface is ambiguous")
    ips = [str(ipaddress.IPv4Address(item["local"]))
           for item in interfaces[0].get("addr_info", [])
           if item.get("family") == "inet" and item.get("scope") == "global"]
    if len(ips) != 1 or not ipaddress.IPv4Address(ips[0]).is_private:
        raise ValueError("UPnP requires exactly one private physical WAN IPv4")
    return {"interface": wan, "local_ipv4": ips[0], "gateway": gateway,
            "route_interface": wan, "host_route": "direct"}


def reconcile(*, owner: str, state: dict, mode: str,
              runner=subprocess.run, upnpc: Path = UPNPC) -> dict:
    """Return verified state; unsupported upstream IGD never opens a fallback."""
    if mode not in ("apply", "revoke"):
        raise ValueError("Invalid direct IGD operation")
    if not upnpc.is_file():
        return {"available": False, "mapping_verified": False,
                "reason": "miniupnpc_not_installed"}
    context = wan_context(state, runner=runner)
    return _load().run_verified_upnpc(
        **context, selected=mode == "apply", owner=owner, mode=mode,
        runner=runner)
