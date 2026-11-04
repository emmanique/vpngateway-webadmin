#!/usr/bin/env python3
"""Fail-closed, route-aware Pi-hole upstream. Opt-in, not activated by installer.

Pi-hole must receive the real client IP and add EDNS Client Subnet /32 from that
address. It must be configured with ONLY this upstream and no upstream fallback.
No ECS data is sent to DNS providers.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import socket
import socketserver
import struct
import threading

MAX_DNS_PACKET = 4096
BIND_DEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
ID_PATTERN = re.compile(r"[a-z][a-z0-9-]{1,31}\Z")
IFACE_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")
SLOTS = threading.BoundedSemaphore(32)


class QueryRejected(ValueError):
    pass


def parse_and_strip_ecs(packet):
    """Return (verified IPv4 client, wire request sans ECS, original question)."""
    if len(packet) < 17 or len(packet) > MAX_DNS_PACKET:
        raise QueryRejected("Invalid packet size")
    ident, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", packet)
    if flags & 0xF800 or qd != 1 or an or ns or ar != 1:
        raise QueryRejected("Only standard single-question EDNS queries accepted")
    pos = 12
    while True:
        if pos >= len(packet):
            raise QueryRejected("Truncated query name")
        size = packet[pos]
        pos += 1
        if size == 0:
            break
        if size > 63 or pos + size > len(packet):
            raise QueryRejected("Compressed or invalid query name")
        pos += size
    if pos + 4 > len(packet):
        raise QueryRejected("Truncated question")
    pos += 4
    question_end = pos
    if pos + 11 > len(packet) or packet[pos] != 0:
        raise QueryRejected("Missing EDNS OPT")
    pos += 1
    rtype, udp_size, ttl, rdlength = struct.unpack_from("!HHIH", packet, pos)
    if rtype != 41 or udp_size < 512 or ttl & 0xff000000:
        raise QueryRejected("Malformed EDNS OPT")
    rdlen_offset = pos + 8
    pos += 10
    if pos + rdlength != len(packet):
        raise QueryRejected("Additional records or trailing bytes unsupported")
    keep = bytearray()
    ecs_ip = None
    finish = pos + rdlength
    while pos < finish:
        if pos + 4 > finish:
            raise QueryRejected("Truncated EDNS option")
        option, size = struct.unpack_from("!HH", packet, pos)
        start = pos
        pos += 4
        if pos + size > finish:
            raise QueryRejected("Invalid EDNS option size")
        data = packet[pos:pos + size]
        pos += size
        if option != 8:
            keep.extend(packet[start:pos])
            continue
        if ecs_ip is not None or len(data) != 8:
            raise QueryRejected("Duplicate or malformed ECS")
        family, prefix, scope = struct.unpack_from("!HBB", data)
        if family != 1 or prefix != 32 or scope != 0:
            raise QueryRejected("Untrusted ECS subnet")
        ecs_ip = str(ipaddress.IPv4Address(data[4:]))
    if ecs_ip is None:
        raise QueryRejected("Missing verified client identity")
    # Remove private client identity before sending the request over VPN.
    clean = (packet[:rdlen_offset] + struct.pack("!H", len(keep))
             + bytes(keep))
    return ecs_ip, clean, packet[12:question_end]


def servfail(packet, question):
    ident = packet[:2] if len(packet) >= 2 else b"\x00\x00"
    return ident + struct.pack("!HHHHH", 0x8182, 1, 0, 0, 0) + question


def trusted_policy(client, state_dir, direct_resolver=None):
    """Only confirmed host policies can select outbound interface/DNS."""
    root = Path(state_dir)
    if root.is_symlink() or not root.is_dir():
        raise QueryRejected("Policy state unavailable")
    matches = []
    for path in root.glob("*.json"):
        if path.is_symlink() or not ID_PATTERN.fullmatch(path.stem):
            continue
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
            plan = state.get("plan") or {}
            if plan.get("host") != client:
                continue
            if state.get("status") != "active" or state.get("vpn_pending"):
                raise QueryRejected("Unconfirmed or inactive policy")
            dest = plan.get("destination")
            if dest == "blocked":
                raise QueryRejected("Blocked host")
            if dest == "direct":
                iface = plan.get("wan")
                dns = direct_resolver
                # No implicit fallback for DIRECT either: explicit DNS required.
            elif isinstance(dest, str) and ID_PATTERN.fullmatch(dest):
                runtime = state.get("vpn_runtime") or {}
                iface, dns = runtime.get("interface"), runtime.get("dns_ipv4")
                if not iface or not dns:
                    raise QueryRejected("VPN resolver unavailable")
            else:
                raise QueryRejected("Invalid route")
            if not isinstance(iface, str) or not IFACE_PATTERN.fullmatch(iface):
                raise QueryRejected("Invalid egress interface")
            addr = ipaddress.IPv4Address(dns)
            if (addr.is_multicast or addr.is_loopback or addr.is_link_local or addr.is_unspecified
                    or (dest == "direct" and not addr.is_global)):
                raise QueryRejected("Untrusted DNS resolver")
            matches.append((iface, str(addr)))
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, KeyError):
            raise QueryRejected("Damaged policy state")
    if len(matches) != 1:
        raise QueryRejected("No unique confirmed host policy")
    return matches[0]


def query_via_interface(payload, dns_ip, interface, tcp=False, timeout=3):
    """Mandatory bind-to-device, never fall back to the host default route."""
    mode = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, mode) as upstream:
        upstream.setsockopt(socket.SOL_SOCKET, BIND_DEVICE, interface.encode("ascii") + b"\0")
        upstream.settimeout(timeout)
        upstream.connect((dns_ip, 53))
        if tcp:
            upstream.sendall(struct.pack("!H", len(payload)) + payload)
            def exact(n):
                chunks = []
                while n:
                    chunk = upstream.recv(n)
                    if not chunk:
                        raise OSError("Upstream DNS closed")
                    chunks.append(chunk)
                    n -= len(chunk)
                return b"".join(chunks)
            amount = struct.unpack("!H", exact(2))[0]
            if not 12 <= amount <= MAX_DNS_PACKET:
                raise OSError("Invalid upstream response length")
            answer = exact(amount)
        else:
            upstream.send(payload)
            answer = upstream.recv(MAX_DNS_PACKET)
    if len(answer) < 12 or answer[:2] != payload[:2] or not (answer[2] & 0x80):
        raise OSError("Unexpected upstream DNS response")
    return answer


def resolve(packet, policy_dir, direct_resolver=None):
    try:
        client, clean, question = parse_and_strip_ecs(packet)
    except QueryRejected:
        return b""  # Never forward unverified ECS or malformed queries.
    try:
        iface, resolver = trusted_policy(client, policy_dir, direct_resolver)
        result = query_via_interface(clean, resolver, iface)
        if result[2] & 0x02:  # TC bit: RFC-compliant TCP retry
            return query_via_interface(clean, resolver, iface, tcp=True)
        return result
    except (QueryRejected, OSError, ValueError, TypeError):
        return servfail(packet, question)


class DnsUDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class DnsTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UdpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        if self.client_address[0] != self.server.trusted_peer:
            return
        payload, sock = self.request
        if not SLOTS.acquire(blocking=False):
            return
        try:
            response = resolve(payload, self.server.policy_dir, self.server.direct_resolver)
            if response:
                sock.sendto(response, self.client_address)
        finally:
            SLOTS.release()


class TcpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        if self.client_address[0] != self.server.trusted_peer:
            return
        if not SLOTS.acquire(blocking=False):
            return
        try:
            self.request.settimeout(5)
            data = self.request.recv(2)
            if len(data) != 2:
                return
            length = struct.unpack("!H", data)[0]
            if not 12 <= length <= MAX_DNS_PACKET:
                return
            parts = bytearray()
            while len(parts) < length:
                block = self.request.recv(length - len(parts))
                if not block:
                    return
                parts.extend(block)
            result = resolve(bytes(parts), self.server.policy_dir, self.server.direct_resolver)
            if result:
                self.request.sendall(struct.pack("!H", len(result)) + result)
        finally:
            SLOTS.release()


def main():
    arg = argparse.ArgumentParser()
    arg.add_argument("--listen", required=True, help="Explicit trusted Docker bridge IPv4")
    arg.add_argument("--port", type=int, default=5355)
    arg.add_argument("--policy-dir", default="/var/lib/vpngw-policy-agent")
    arg.add_argument("--pihole-source", required=True, help="Trusted Pi-hole container IPv4")
    arg.add_argument("--bridge-interface", required=True, help="Docker bridge receiving Pi-hole packets")
    arg.add_argument("--direct-resolver", required=True, help="Explicit DNS for DIRECT host policies")
    opts = arg.parse_args()
    ip = ipaddress.IPv4Address(opts.listen)
    peer = ipaddress.IPv4Address(opts.pihole_source)
    if not ip.is_private or not peer.is_private or peer == ip or not (1024 <= opts.port <= 65535):
        raise SystemExit("Private listener address and unprivileged port required")
    direct = ipaddress.IPv4Address(opts.direct_resolver)
    if not direct.is_global:
        raise SystemExit("DIRECT resolver must be a public IPv4")
    if not IFACE_PATTERN.fullmatch(opts.bridge_interface):
        raise SystemExit("Invalid Docker bridge interface")
    addr = (str(ip), opts.port)
    # Bind listeners to Docker bridge ingress only, not the LAN/WAN.
    udp = DnsUDP(addr, UdpHandler, bind_and_activate=False)
    tcp = DnsTCP(addr, TcpHandler, bind_and_activate=False)
    for server in (udp, tcp):
        server.socket.setsockopt(socket.SOL_SOCKET, BIND_DEVICE,
                                 opts.bridge_interface.encode("ascii") + b"\0")
        server.server_bind()
        server.server_activate()
    udp.policy_dir = tcp.policy_dir = opts.policy_dir
    udp.direct_resolver = tcp.direct_resolver = str(direct)
    udp.trusted_peer = tcp.trusted_peer = str(peer)
    worker = threading.Thread(target=udp.serve_forever, daemon=True)
    worker.start()
    try:
        tcp.serve_forever()
    finally:
        udp.shutdown()
        tcp.server_close()
        udp.server_close()


if __name__ == "__main__":
    main()
