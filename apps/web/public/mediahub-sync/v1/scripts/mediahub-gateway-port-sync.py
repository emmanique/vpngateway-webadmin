#!/usr/bin/env python3
"""Opt-in MediaHub observation of the host-selected Gateway NAT-PMP port.

No fixed MediaHub IPv4 is stored. The right to change the libtorrent port
belongs to the host policy ID AND MAC selected in Gateway -> Edit host.
The port must be attested, current and identical for TCP and UDP.
Only publishes an authenticated observation; the Stremio reconciler owns
all .env updates and container recreations. A provider lease renewal is
observation-only and never recreates the container.

Configuration is deliberately opt-in; do not enable before Gateway's selected
host/reconciliation API and release have been validated.
"""
from __future__ import annotations

import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

MAC_RE = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
ID_RE = re.compile(r"[a-z][a-z0-9-]{1,31}\Z")
LOCK_PATH = Path("/run/lock/mediahub-gateway-port-sync.lock")
OBSERVATION = Path("/var/lib/stremio-webadmin/gateway-port-observation.json")


class PortSyncError(RuntimeError):
    pass


def select_port(snapshot: dict, *, expected_policy: str, expected_mac: str,
                local_addresses: set[str], now: float) -> int | None:
    """Return a verified port, or None when no authorised change is possible."""
    identity = snapshot.get("selected_host") or {}
    runtime = snapshot.get("runtime") or {}
    if (not ID_RE.fullmatch(expected_policy) or
        not MAC_RE.fullmatch(expected_mac.lower()) or
        identity.get("policy_id") != expected_policy or
        str(identity.get("registered_mac", "")).lower() != expected_mac.lower() or
        runtime.get("owner") != expected_policy or
        not snapshot.get("rules_applied") or
        not runtime.get("applied")):
        return None

    current_ip = identity.get("host_ip")
    try:
        ipaddress.IPv4Address(current_ip)
    except (ValueError, TypeError, ipaddress.AddressValueError):
        return None
    if current_ip not in local_addresses:
        return None

    route = identity.get("route")
    if route != runtime.get("route"):
        return None
    if route == "direct":
        if runtime.get("provider_lease"):
            return None
        ports = runtime.get("external_ports") or {}
        if ports.get("tcp") == 6881 and ports.get("udp") == 6881:
            return 6881
        return None
    if not runtime.get("provider_lease") or runtime.get("status") != "nat_rules_verified":
        return None
    issued = runtime.get("updated_at")
    expiry = runtime.get("lease_expires_at")
    # Do not recreate a container against an old or nearly expired provider
    # allocation. The Gateway renews every 45 seconds.
    if (type(issued) not in (float, int) or type(expiry) not in (float, int)
            or not issued <= now <= issued + 75 or expiry - now < 12):
        return None
    ports = runtime.get("external_ports") or {}
    tcp, udp = ports.get("tcp"), ports.get("udp")
    if (type(tcp) is int and type(udp) is int
            and 1 <= tcp <= 65535 and tcp == udp):
        return tcp
    return None


def local_ip_addresses(mac: str, runner=subprocess.run) -> set[str]:
    """Look up the current host IPv4 addresses by NIC MAC, not a fixed IP."""
    result = runner(["/usr/sbin/ip", "-j", "-4", "address", "show"],
                    capture_output=True, text=True, timeout=8, check=True)
    addresses = set()
    for link in json.loads(result.stdout):
        device = link.get("ifname")
        if not (isinstance(device, str) and
                re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", device)):
            continue
        # ip -j -4 address show omits the L2 MAC on real Linux hosts.
        # Resolve it from the separate ip -j link show response instead.
        metadata = runner(["/usr/sbin/ip", "-j", "link", "show", "dev", device],
                          capture_output=True, text=True, timeout=8, check=True)
        links = json.loads(metadata.stdout)
        if (not isinstance(links, list) or len(links) != 1
                or links[0].get("ifname") != device
                or str(links[0].get("address", "")).lower() != mac.lower()):
            continue
        for item in link.get("addr_info", []):
            if item.get("family") == "inet" and item.get("scope") == "global":
                addresses.add(str(ipaddress.IPv4Address(item["local"])))
    return addresses


def active_gateway(*, local_address: str, expected_mac: str,
                   probe: str = "1.1.1.1", runner=subprocess.run) -> tuple[str, str]:
    """Determine the routing gateway FROM this MediaHub host's current IPv4.

    This checks the egress NIC belonging to the registered MAC.
    The management Gateway is independently configured and TLS verified.
    The interface selected by the kernel must be the NIC with the
    registered MediaHub MAC.
    """
    try:
        src = str(ipaddress.IPv4Address(local_address))
        destination = str(ipaddress.IPv4Address(probe))
        result = runner(["/usr/sbin/ip", "-j", "-4", "route", "get",
                         destination, "from", src],
                        capture_output=True, text=True, check=True, timeout=8)
        rows = json.loads(result.stdout)
        if not isinstance(rows, list) or len(rows) != 1:
            raise PortSyncError("Ambiguous active default gateway")
        entry = rows[0]
        device = entry.get("dev")
        candidate = entry.get("gateway")
        if not (isinstance(device, str) and re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", device)
                and isinstance(candidate, str)):
            raise PortSyncError("No routed gateway found")
        gateway = ipaddress.IPv4Address(candidate)
        if not gateway.is_private or gateway.is_loopback or gateway.is_link_local:
            raise PortSyncError("Gateway is not a private LAN address")
        if entry.get("prefsrc") not in (None, src):
            raise PortSyncError("Unexpected route source address")
        nic = runner(["/usr/sbin/ip", "-j", "link", "show", "dev", device],
                     capture_output=True, text=True, check=True, timeout=8)
        devices = json.loads(nic.stdout)
        if (not isinstance(devices, list) or len(devices) != 1
                or devices[0].get("ifname") != device
                or str(devices[0].get("address", "")).lower() != expected_mac.lower()):
            raise PortSyncError("Gateway route does not use selected host interface")
        return str(gateway), device
    except (ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        raise PortSyncError("Could not verify host's active Gateway route") from exc


def gateway_endpoint(ip: str, *, port: int = 9443,
                     path: str = "/api/v1/port-forward/desired") -> str:
    """Construct the API address from an explicit approved Gateway LAN IPv4."""
    address = ipaddress.IPv4Address(ip)
    if (not address.is_private or address.is_link_local or address.is_loopback
            or not isinstance(port, int) or not 1 <= port <= 65535
            or path not in ("/gateway/api/v1/port-forward/desired",
                            "/api/v1/port-forward/desired")):
        raise PortSyncError("Unsafe gateway API endpoint")
    return f"https://{address}:{port}{path}"


def query_gateway(url: str, ca_file: Path, token_file: Path) -> dict:
    parsed = urlparse(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment or parsed.query
            or not parsed.path.endswith("/api/v1/port-forward/desired")):
        raise PortSyncError("HTTPS Gateway endpoint with verified CA is required")
    if not ca_file.is_file():
        raise PortSyncError("Gateway CA certificate is missing")
    if token_file.is_symlink() or not token_file.is_file():
        raise PortSyncError("Dedicated Gateway status token is missing")
    mode = token_file.stat().st_mode
    if mode & 0o077:
        raise PortSyncError("Gateway status token must be readable by owner only")
    token = token_file.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64,128}", token):
        raise PortSyncError("Invalid Gateway status token")
    ctx = ssl.create_default_context(cafile=str(ca_file))
    request = Request(url, headers={
        "Accept": "application/json",
        "Authorization": "Bearer " + token,
    })
    # Do not let HTTPS_PROXY or other ambient proxy environment bypass the
    # host's selected gateway path or turn a LAN request into an offsite call.
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ctx))
    with opener.open(request, timeout=8) as response:
        if response.status != 200:
            raise PortSyncError("Gateway status unavailable")
        data = response.read(65537)
    if len(data) > 65536:
        raise PortSyncError("Gateway response exceeds maximum length")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise PortSyncError("Invalid Gateway response")
    return result


def publish_observation(port: int | None, *, policy: str, mac: str,
                        host_ip: str, gateway: str, route: str | None,
                        issued: float | None, expiry: float | None) -> None:
    """Atomically communicate the verified allocation to Stremio's reconciler."""
    OBSERVATION.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    if OBSERVATION.is_symlink():
        raise PortSyncError("Refusing symlinked observer state")
    data = {
        "schema": 1, "port": port, "policy_id": policy,
        "registered_mac": mac, "host_ip": host_ip,
        "gateway": gateway, "route": route,
        "lease_issued_at": issued, "lease_expires_at": expiry,
        "observed_at": time.time(),
    }
    fd, name = tempfile.mkstemp(prefix=".gateway-port-", dir=OBSERVATION.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(data, out, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, OBSERVATION)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main() -> int:
    if os.environ.get("MEDIAHUB_PORT_SYNC_ENABLE") != "1":
        print("disabled")
        return 0
    policy = os.environ["MEDIAHUB_PORT_SYNC_POLICY_ID"]
    mac = os.environ["MEDIAHUB_PORT_SYNC_HOST_MAC"].lower()
    ca = Path(os.environ["MEDIAHUB_PORT_SYNC_CA_FILE"])
    token_file = Path(os.environ["MEDIAHUB_PORT_SYNC_TOKEN_FILE"])
    api_port = int(os.environ.get("MEDIAHUB_PORT_SYNC_API_PORT", "9443"))
    api_path = os.environ.get("MEDIAHUB_PORT_SYNC_API_PATH",
                              "/api/v1/port-forward/desired")
    probe = os.environ.get("MEDIAHUB_PORT_SYNC_ROUTE_PROBE", "1.1.1.1")
    selected_gateway = os.environ["MEDIAHUB_PORT_SYNC_GATEWAY_IP"]
    try:
        configured_ip = ipaddress.IPv4Address(selected_gateway)
    except ipaddress.AddressValueError as error:
        raise PortSyncError("Explicit VPN Gateway management LAN IPv4 required") from error
    if not configured_ip.is_private or configured_ip.is_loopback or configured_ip.is_link_local:
        raise PortSyncError("Unsafe configured VPN Gateway management IPv4")
    with LOCK_PATH.open("a+") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        ips = local_ip_addresses(mac)
        if len(ips) != 1:
            raise PortSyncError("Expected one current IPv4 for the registered host MAC")
        address = next(iter(ips))
        gateway, interface = active_gateway(local_address=address,
                                             expected_mac=mac, probe=probe)
        endpoint = gateway_endpoint(str(configured_ip), port=api_port, path=api_path)
        snapshot = query_gateway(endpoint, ca, token_file)
        port = select_port(snapshot, expected_policy=policy, expected_mac=mac,
                           local_addresses=ips, now=time.time())
        if port is None:
            publish_observation(None, policy=policy, mac=mac, host_ip=address,
                                gateway=str(configured_ip), route=None, issued=None, expiry=None)
            print(json.dumps({"result": "no_verified_port_change",
                              "gateway": str(configured_ip), "router": gateway, "interface": interface}))
            return 0
        # Avoid applying a stale lease after the host's gateway or its IP
        # changes while the remote HTTPS request was in flight.
        if (local_ip_addresses(mac) != ips or
            active_gateway(local_address=address, expected_mac=mac, probe=probe)
                != (gateway, interface)):
            raise PortSyncError("Host IP or gateway changed during reconciliation")
        runtime = snapshot.get("runtime") or {}
        publish_observation(port, policy=policy, mac=mac, host_ip=address,
                            gateway=str(configured_ip), route=(snapshot.get("selected_host") or {}).get("route"),
                            issued=runtime.get("updated_at"),
                            expiry=runtime.get("lease_expires_at"))
        print(json.dumps({"result": "port_observed", "port": port,
                          "host_policy": policy, "gateway": str(configured_ip),
                          "interface": interface, "stremio_unchanged": True}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PortSyncError, KeyError, OSError, ValueError, subprocess.SubprocessError,
            BlockingIOError) as exc:
        print("mediahub_port_sync_error: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
