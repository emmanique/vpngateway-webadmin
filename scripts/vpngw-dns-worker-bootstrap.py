#!/usr/bin/env python3
"""Start opt-in policy DNS on the current verified Pi-hole Docker bridge.

Do not persist Docker bridge/IP addresses: they may change on container
recreation or reboot. This program does not change DNS, routing or nftables.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys

IFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")
CONTAINER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{1,100}\Z")
WORKER = "/usr/local/libexec/vpngw-dns-policy-upstream.py"


class BootstrapError(ValueError):
    pass


def discover(*, container: str, inspector=subprocess.run) -> dict:
    if not isinstance(container, str) or not CONTAINER.fullmatch(container):
        raise BootstrapError("Invalid Pi-hole container name")
    result = inspector(["/usr/bin/docker", "inspect", container],
                       capture_output=True, text=True, timeout=8, check=True)
    response = json.loads(result.stdout)
    if not isinstance(response, list) or len(response) != 1:
        raise BootstrapError("Ambiguous Pi-hole inspection")
    state = response[0].get("State") or {}
    networks = (response[0].get("NetworkSettings") or {}).get("Networks") or {}
    if not state.get("Running") or len(networks) != 1:
        raise BootstrapError("Pi-hole is not running on exactly one network")
    item = next(iter(networks.values()))
    network_id = item.get("NetworkID", "")
    if not re.fullmatch(r"[0-9a-f]{64}", network_id):
        raise BootstrapError("Invalid Docker network ID")
    bridge = "br-" + network_id[:12]
    if not IFACE.fullmatch(bridge):
        raise BootstrapError("Invalid Docker bridge")
    host = ipaddress.IPv4Address(item["Gateway"])
    peer = ipaddress.IPv4Address(item["IPAddress"])
    if (not host.is_private or not peer.is_private or host == peer
            or host.is_loopback or peer.is_loopback):
        raise BootstrapError("Unsafe Pi-hole bridge addresses")
    return {"bridge": bridge, "listener": str(host), "peer": str(peer)}


def verified_runtime(discovered: dict, *, runner=subprocess.run) -> dict:
    result = runner(["/usr/sbin/ip", "-j", "-4", "address", "show",
                     "dev", discovered["bridge"]],
                    capture_output=True, text=True, timeout=8, check=True)
    addresses = json.loads(result.stdout)
    if (not isinstance(addresses, list) or len(addresses) != 1
            or addresses[0].get("ifname") != discovered["bridge"]
            or not any(a.get("family") == "inet"
                       and a.get("local") == discovered["listener"]
                       for a in addresses[0].get("addr_info", []))):
        raise BootstrapError("Docker bridge listener address mismatch")
    result = runner(["/usr/sbin/ip", "-j", "-4", "route", "get",
                     discovered["peer"]],
                    capture_output=True, text=True, timeout=8, check=True)
    routes = json.loads(result.stdout)
    if (not isinstance(routes, list) or len(routes) != 1
            or routes[0].get("dev") != discovered["bridge"]):
        raise BootstrapError("Pi-hole routing does not use Docker bridge")
    return discovered


def main() -> int:
    container = os.environ.get("VPNGW_DNS_PIHOLE_CONTAINER", "")
    resolver = os.environ.get("VPNGW_DNS_DIRECT_RESOLVER", "")
    try:
        dns = ipaddress.IPv4Address(resolver)
        if not dns.is_global:
            raise BootstrapError("DIRECT DNS resolver must be public")
        observed = verified_runtime(discover(container=container))
        if not Path(WORKER).is_file() or Path(WORKER).is_symlink():
            raise BootstrapError("DNS policy worker unavailable")
    except (ValueError, KeyError, TypeError, subprocess.SubprocessError,
            OSError, json.JSONDecodeError) as exc:
        print("dns_worker_bootstrap_refused: " + str(exc), file=sys.stderr)
        return 1
    os.execv("/usr/bin/python3", [
        "/usr/bin/python3", WORKER,
        "--listen", observed["listener"],
        "--bridge-interface", observed["bridge"],
        "--pihole-source", observed["peer"],
        "--direct-resolver", str(dns),
        "--policy-dir", "/var/lib/vpngw-policy-agent",
    ])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
