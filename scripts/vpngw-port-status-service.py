#!/usr/bin/env python3
"""LAN-only read-only HTTPS endpoint for selected-host VPN forwarding status.

Runs on the Gateway Linux HOST (not in Docker), bound to the configured LAN
interface using SO_BINDTODEVICE. It is intentionally separate from the
privileged policy-agent socket and never performs network writes.

An independent MediaHub Linux host can query it without traversing Docker
DNAT, which would otherwise hit the MediaHub fail-closed forwarding rule.
"""
from __future__ import annotations

import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import socket
import stat
import ssl
import sys
import time
from urllib.request import Request, urlopen

URI = "/api/v1/port-forward/desired"
HOST_URI = "/api/v1/port-forward/authorized-host"
MAX_BYTES = 65536
TOKEN_FILE = Path("/etc/vpngw-port-status/token")
CERT_FILE = Path("/etc/vpngw-port-status/lan.crt")
KEY_FILE = Path("/etc/vpngw-port-status/lan.key")
UPSTREAM = "http://127.0.0.1:18080/api/v1/port-forward/desired"
BUNDLE_PREFIX = "/mediahub-sync/v1/"
BUNDLE_ROOT = Path("/usr/local/share/vpngw/mediahub-sync/v1")
BUNDLE_FILES = frozenset({
    "bootstrap.sh",
    "SHA256SUMS",
    "scripts/mediahub-gateway-port-sync.py",
    "deploy/systemd/mediahub-gateway-port-sync.service",
    "deploy/systemd/mediahub-gateway-port-sync.timer",
    "deploy/examples/mediahub-port-sync.conf.example",
    "installers/install-mediahub-gateway-port-sync-linux.sh",
})
MAX_BUNDLE_BYTES = 131072


def read_public_bundle(uri: str, root: Path = BUNDLE_ROOT) -> bytes | None:
    """Only serve an explicit list of root-owned, versioned public assets."""
    if not uri.startswith(BUNDLE_PREFIX):
        return None
    name = uri[len(BUNDLE_PREFIX):]
    if name not in BUNDLE_FILES:
        return None
    path = root / name
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o022 or info.st_size > MAX_BUNDLE_BYTES):
            return None
        data = path.read_bytes()
        if len(data) > MAX_BUNDLE_BYTES:
            return None
        return data
    except OSError:
        return None



def validate_binding(interface: str, address: str, port: int):
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", interface):
        raise ValueError("Invalid management LAN interface")
    local = ipaddress.IPv4Address(address)
    if not local.is_private or local.is_loopback or local.is_link_local or local.is_unspecified:
        raise ValueError("Management LAN IPv4 required")
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("Invalid status endpoint port")
    return interface, str(local), port


def read_token(path: Path = TOKEN_FILE) -> str:
    record = path.stat()
    if path.is_symlink() or not stat.S_ISREG(record.st_mode) or record.st_uid != 0 or (record.st_mode & 0o077):
        raise ValueError("Token must be a root-owned 0600 regular file")
    token = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64,128}", token):
        raise ValueError("Invalid status token")
    return token


def sanitized_observation(raw: dict, now: float) -> dict:
    """Never hand out a stale port or an unverified forwarding selection."""
    if not isinstance(raw, dict):
        raise ValueError("Invalid Gateway status")
    record = dict(raw)
    runtime = dict(record.get("runtime") or {})
    expiry = runtime.get("lease_expires_at")
    issued = runtime.get("updated_at")
    ready = bool(
        record.get("rules_applied") and runtime.get("applied")
        and type(issued) in (float, int)
        and 0 <= now - issued <= 75
        and (not runtime.get("provider_lease") or (
            type(expiry) in (float, int) and now < expiry
        ))
    )
    if not ready:
        record["rules_applied"] = False
        runtime["external_ports"] = {}
        runtime["lease_state"] = "unverified"
    record["runtime"] = runtime
    record["external_reachability_verified"] = False
    return record


def fetch_observation(now: float, upstream: str = UPSTREAM) -> dict:
    req = Request(upstream, headers={"Accept": "application/json"})
    with urlopen(req, timeout=5) as response:
        if response.status != 200:
            raise ValueError("Gateway API is unavailable")
        data = response.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("Gateway response is too large")
    return sanitized_observation(json.loads(data), now)


def authorized_lan_host(raw: dict, *, source_ip: str, interface: str,
                        neighbor_check=None) -> bool:
    """Return only this authorised host's status, never a privileged token.

    The trust boundary is a managed LAN with anti-spoofing at its access layer.
    IP/MAC are admission checks, NOT cryptographic device authentication.
    """
    host=raw.get("selected_host") or {}
    selected=host.get("host_ip")
    mac=str(host.get("registered_mac") or "").lower()
    policy=host.get("policy_id")
    forwarded=raw.get("forwarding") or {}
    if (not isinstance(selected,str) or source_ip!=selected
        or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}",mac)
        or not isinstance(policy,str) or forwarded.get("policy_id")!=policy
        or not raw.get("rules_applied")):
        return False
    if neighbor_check is None:
        neighbor_check=read_neighbor
    return neighbor_check(source_ip,interface)==mac


def read_neighbor(ip: str, interface: str) -> str | None:
    """Kernel neighbour MAC must agree with the Gateway's selected policy."""
    try:
        addr=ipaddress.IPv4Address(ip)
        if not addr.is_private or addr.is_loopback:
            return None
        result=subprocess.run(["/usr/sbin/ip","-j","neigh","show","to",ip,
                               "dev",interface],check=True,capture_output=True,
                              text=True,timeout=3)
        rows=json.loads(result.stdout)
        if len(rows)!=1 or "FAILED" in rows[0].get("state",[]):
            return None
        return str(rows[0].get("lladdr","")).lower()
    except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "VPNGW-PortStatus"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.startswith(BUNDLE_PREFIX):
            resource = read_public_bundle(self.path)
            if resource is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(resource)))
            self.end_headers()
            self.wfile.write(resource)
            return
        if self.path == HOST_URI:
            try:
                result=fetch_observation(time.time(),self.server.upstream_url)
                allowed=authorized_lan_host(
                    result,source_ip=self.client_address[0],
                    interface=self.server.lan_interface)
                if not allowed:
                    self.send_error(403,"Host not authorised for NAT forwarding")
                    return
                payload=json.dumps(result,separators=(",",":")).encode("utf-8")
            except (OSError,ValueError,TimeoutError,json.JSONDecodeError):
                self.send_error(503,"Gateway status unavailable")
                return
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.send_header("Cache-Control","no-store")
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("Content-Length",str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path != URI:
            self.send_error(404)
            return
        auth = self.headers.get("Authorization", "")
        token = self.server.access_token
        if not hmac.compare_digest(auth, "Bearer " + token):
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Bearer")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        try:
            result = fetch_observation(time.time(), self.server.upstream_url)
            payload = json.dumps(result, separators=(",", ":")).encode("utf-8")
        except (OSError, ValueError, TimeoutError, json.JSONDecodeError):
            self.send_error(503, "Gateway status unavailable")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        # Never print tokens or client-controlled request headers.
        return


class LanServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: str, port: int, interface: str, token: str):
        super().__init__((address, port), Handler, bind_and_activate=False)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                               interface.encode("ascii") + b"\x00")
        self.server_bind()
        self.server_activate()
        self.access_token = token
        self.lan_interface = interface
        self.upstream_url = UPSTREAM


def main():
    interface, address, port = validate_binding(
        os.environ["VPNGW_PORT_STATUS_LAN_INTERFACE"],
        os.environ["VPNGW_PORT_STATUS_LAN_IP"],
        int(os.environ.get("VPNGW_PORT_STATUS_PORT", "9443")),
    )
    token = read_token()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(CERT_FILE), str(KEY_FILE))
    with LanServer(address, port, interface, token) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.serve_forever(poll_interval=0.4)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        print("port_status_service_unavailable: " + str(error), file=sys.stderr)
        raise SystemExit(1)