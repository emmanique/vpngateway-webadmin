#!/usr/bin/env python3
"""Discover/renew a VPN provider NAT-PMP lease on a verified tunnel only.

Absence of an endpoint or mapping is a normal state: never silently fall back
to a WAN NAT-PMP gateway or invent an external port. TCP and UDP are independent.
"""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import os
from pathlib import Path
from contextlib import contextmanager

MAP_RE = re.compile(
    r"Mapped public port\s+(\d+)\s+protocol\s+(TCP|UDP)\s+to local port\s+(\d+)\s+lifetime\s+(\d+)",
    re.IGNORECASE,
)
PORT = 6881
LIFETIME = 120
PROTON_GATEWAY = "10.2.0.1"
PROTON_LIFETIME = 60
TEMP_ROUTE_MARKER = Path('/var/lib/vpngw-policy-agent/port-forward/temporary-route.json')


def parse_mapping(output: str, protocol: str, *, provider: str = "generic") -> dict | None:
    """Never trust the port alone: require matching protocol, local port, lease."""
    for match in MAP_RE.finditer(output):
        public, observed_proto, private, lifetime = match.groups()
        if (observed_proto.lower() == protocol and int(private) == (0 if provider == "proton" else PORT)
                and 1 <= int(public) <= 65535 and int(lifetime) >= 30):
            return {"protocol": protocol, "internal_port": PORT,
                    "external_port": int(public), "lifetime": int(lifetime)}
    return None


def route_uses_tunnel(gateway: str, interface: str, runner=subprocess.run) -> bool:
    try:
        candidate = ipaddress.ip_address(gateway)
        if candidate.version != 4 or not candidate.is_private:
            return False
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", interface):
            return False
        result = runner(["/usr/sbin/ip", "-j", "-4", "route", "get", gateway],
                        capture_output=True, text=True, timeout=4)
        if result.returncode:
            return False
        routes = json.loads(result.stdout)
        return bool(routes and all(x.get("dev") == interface for x in routes))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return False


def candidate_gateway(interface: str, runner=subprocess.run) -> str | None:
    """Read kernel route-gateway, not an address guessed from the VPN provider."""
    try:
        result = runner(["/usr/sbin/ip", "-j", "-4", "route", "show", "dev", interface],
                        capture_output=True, text=True, timeout=4)
        if result.returncode:
            return None
        routes = json.loads(result.stdout)
        candidates = []
        for route in routes:
            via = route.get("gateway")
            if via and route_uses_tunnel(via, interface, runner):
                candidates.append(via)
        return candidates[0] if len(set(candidates)) == 1 else None
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return None


def candidate_from_tunnel_address(interface: str, runner=subprocess.run) -> str | None:
    """Tentative .1 gateway for a /32 private VPN address; never trust it without a probe."""
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", interface):
        return None
    try:
        result = runner(["/usr/sbin/ip", "-j", "-4", "address", "show", "dev", interface],
                        capture_output=True, text=True, timeout=4)
        if result.returncode:
            return None
        interfaces = json.loads(result.stdout)
        info = [x for link in interfaces for x in link.get("addr_info", [])
                if x.get("family") == "inet"]
        # OpenVPN may expose a point-to-point peer address instead of a gateway.
        peers = []
        for item in info:
            if item.get("peer"):
                candidate = ipaddress.ip_interface(item["peer"]).ip
                if candidate.version == 4 and candidate.is_private:
                    peers.append(str(candidate))
        if len(set(peers)) == 1:
            return peers[0]
        single = [x for x in info if x.get("prefixlen") == 32]
        if len(single) != 1:
            return None
        address = ipaddress.ip_address(single[0]["local"])
        if not address.is_private or address.is_loopback:
            return None
        # A candidate is not a discovery result. NAT-PMP must confirm the actual mapping.
        subnet = ipaddress.ip_network(str(address) + "/24", strict=False)
        gateway = subnet.network_address + 1
        return str(gateway) if gateway != address else None
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        return None


def cleanup_stale_route(runner=subprocess.run, marker=TEMP_ROUTE_MARKER) -> bool:
    """Delete only our recorded proto-186 /32 tunnel route, never other routes."""
    if not marker.is_file() or marker.is_symlink():
        return False
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
        gateway = data.get("gateway")
        interface = data.get("interface")
        if not gateway or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", str(interface)):
            raise ValueError("Invalid route marker")
        address = ipaddress.ip_address(gateway)
        if address.version != 4 or not address.is_private:
            raise ValueError("Invalid route marker destination")
        observed = runner(["/usr/sbin/ip", "-j", "-4", "route", "show", "exact",
                           gateway + "/32"], capture_output=True, text=True, timeout=4)
        if observed.returncode:
            return False
        matches = [entry for entry in json.loads(observed.stdout)
                   if entry.get("dev") == interface
                   and str(entry.get("protocol")) == "186"
                   and entry.get("dst") in (gateway, gateway + "/32")]
        if matches:
            result = runner(["/usr/sbin/ip", "-4", "route", "del", gateway + "/32",
                             "dev", interface, "proto", "186"],
                            capture_output=True, text=True, timeout=4)
            if result.returncode == 0:
                marker.unlink(missing_ok=True)
                return True
            return False  # Retain marker for a subsequent cleanup attempt.
        marker.unlink(missing_ok=True)  # Route was already removed.
        return False
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        return False


@contextmanager
def scoped_gateway_route(gateway: str, interface: str, runner=subprocess.run):
    """Temporary /32 via verified VPN. Never replace a pre-existing host route."""
    if route_uses_tunnel(gateway, interface, runner):
        yield True
        return
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", interface):
        yield False
        return
    try:
        address = ipaddress.ip_address(gateway)
        if address.version != 4 or not address.is_private or address.is_loopback:
            yield False
            return
        existing = runner(["/usr/sbin/ip", "-j", "-4", "route", "show", "exact",
                           gateway + "/32"], capture_output=True, text=True, timeout=4)
        if existing.returncode or json.loads(existing.stdout):
            yield False
            return
        TEMP_ROUTE_MARKER.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        marker_fd = os.open(TEMP_ROUTE_MARKER, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(marker_fd, "w", encoding="utf-8") as stream:
            json.dump({"gateway": gateway, "interface": interface}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        added = runner(["/usr/sbin/ip", "-4", "route", "add", gateway + "/32",
                        "dev", interface, "proto", "186"],
                       capture_output=True, text=True, timeout=4)
        if added.returncode:
            TEMP_ROUTE_MARKER.unlink(missing_ok=True)
            yield False
            return
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        yield False
        return
    try:
        yield route_uses_tunnel(gateway, interface, runner)
    finally:
        # Restrict deletion to the exact route created by this controller.
        removed = runner(["/usr/sbin/ip", "-4", "route", "del", gateway + "/32",
                          "dev", interface, "proto", "186"],
                         capture_output=True, text=True, timeout=4)
        if removed.returncode == 0:
            TEMP_ROUTE_MARKER.unlink(missing_ok=True)
        # On failure retain the marker so boot/shutdown cleanup can retry.


PRIVATE_PROTON_NATPMP = Path("/usr/local/libexec/vpngw-natpmpc")


def proton_natpmp_executable(runner=subprocess.run, private_path=None) -> str | None:
    """Accept a private client only with a root-owned version and verified SHA."""
    try:
        binary = Path(private_path) if private_path is not None else PRIVATE_PROTON_NATPMP
        manifest = Path(str(binary) + ".sha256")
        version_file = Path(str(binary) + ".version")
        if binary.is_file() and manifest.is_file() and version_file.is_file():
            files = (binary, manifest, version_file)
            if all(not item.is_symlink() and item.stat().st_uid == 0 and
                   (item.stat().st_mode & 0o022) == 0 for item in files):
                if version_file.read_text(encoding="ascii").strip() == "20230423":
                    # SHA manifest is only trusted if it contains the exact expected file.
                    record = manifest.read_text(encoding="ascii").strip()
                    if re.fullmatch(r"[0-9a-f]{64}  " + re.escape(binary.name), record):
                        check = runner(["/usr/bin/sha256sum", "-c", manifest.name],
                                       cwd=str(binary.parent), capture_output=True,
                                       text=True, timeout=5)
                        if check.returncode == 0:
                            return str(binary)
        # If no verified private binary exists, only a modern OS package is safe.
        result = runner(["/usr/bin/dpkg-query", "-W", "-f=${Version}", "natpmpc"],
                        capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            match = re.match(r"^(20\d{6})(?=[+~.-]|$)", result.stdout.strip())
            if match and int(match.group(1)) >= 20230423:
                return "/usr/bin/natpmpc"
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        pass
    return None


def proton_binary_compatible(runner=subprocess.run) -> bool:
    """Fail closed on old/unknown Debian natpmpc binary package versions.

    Proton documents an output-parsing defect in the 20150609 series.
    The configured executor runs /usr/bin/natpmpc, so its Debian package
    version must be at least 20230423. Do not trust a different binary
    installed in /usr/local/bin or a shell alias.
    """
    return proton_natpmp_executable(runner) is not None


def discover(gateway: str, interface: str, runner=subprocess.run, preferred=None, *, provider="generic") -> dict:
    """Request a short-lived mapping only if gateway egress is proven VPN-scoped."""
    if provider == "proton" and gateway != PROTON_GATEWAY:
        return {"mappings": [], "status": "proton_gateway_mismatch"}
    if provider == "proton" and not proton_binary_compatible(runner):
        return {"mappings": [], "status": "proton_natpmpc_version_unsupported"}
    mappings = []
    preferred = preferred or {}
    with scoped_gateway_route(gateway, interface, runner) as safe:
        if not safe:
            return {"mappings": [], "status": "vpn_gateway_unverified"}
        for protocol in ("tcp", "udp"):
            try:
                requested = preferred.get(protocol, 0)
                if not isinstance(requested, int) or not 0 <= requested <= 65535:
                    requested = 0
                if provider == "proton":
                    import importlib.util
                    source = Path(__file__).with_name("vpngw-proton-natpmp.py")
                    spec = importlib.util.spec_from_file_location("vpngw_proton_natpmp", source)
                    contract = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(contract)
                    # Re-request using the exact official Proton NAT-PMP signature.
                    cmd = contract.mapping_command(protocol)  # Proton renews using -a 1 0 every 45 s
                    verified_binary = proton_natpmp_executable(runner)
                    if not verified_binary:
                        return {"mappings": [], "status": "proton_natpmpc_version_unsupported"}
                    cmd[0] = verified_binary
                else:
                    cmd = ["/usr/bin/natpmpc", "-g", gateway, "-a", str(requested),
                           str(PORT), protocol, str(LIFETIME)]
                proc = runner(cmd, capture_output=True, text=True, timeout=8)
                result = parse_mapping(proc.stdout, protocol, provider=provider) if proc.returncode == 0 else None
                if result:
                    mappings.append(result)
            except (OSError, ValueError, subprocess.SubprocessError):
                continue
    return {"mappings": mappings,
            "status": "mapped" if mappings else "no_provider_mapping",
            "gateway": gateway if mappings else None}

def revoke(gateway: str, interface: str, ports: dict, runner=subprocess.run, *, provider="generic") -> dict:
    """Explicitly release owned provider leases before host removal/switch."""
    if provider == "proton":
        # RFC 6886 §3.4: private port 0 with lifetime 0 deletes *all* mappings
        # for the protocol at this NAT-PMP client. The Proton lease was
        # created with private port 0; a selective revocation cannot be
        # guaranteed. Disable local DNAT and let its 60-second lease expire.
        # In particular, never issue -a <public> 0 <protocol> 0.
        return {"revoked": [], "unreachable": False,
                "expiry_only": True, "lease_remaining_max_seconds": PROTON_LIFETIME}
    revoked = []
    with scoped_gateway_route(gateway, interface, runner) as safe:
        if not safe:
            return {"revoked": [], "unreachable": True}
        for protocol in ("tcp", "udp"):
            public = ports.get(protocol)
            if not isinstance(public, int) or not 1 <= public <= 65535:
                continue
            try:
                cmd = ["/usr/bin/natpmpc", "-g", gateway, "-a",
                       str(public), str(PORT), protocol, "0"]
                proc = runner(cmd, capture_output=True, text=True, timeout=8)
                if proc.returncode == 0:
                    revoked.append(protocol)
            except (OSError, subprocess.SubprocessError):
                continue
    return {"revoked": revoked, "unreachable": False}

if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["--cleanup"]:
        cleanup_stale_route()
    else:
        raise SystemExit("Usage: vpngw-natpmp-discovery.py --cleanup")
