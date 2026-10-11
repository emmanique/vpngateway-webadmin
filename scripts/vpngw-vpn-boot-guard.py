#!/usr/bin/env python3
"""Independent per-client VPN fail-closed boot guard.

This only operates on pre-approved, root-owned configs. It NEVER installs
routes or accepts packets; it just establishes fail-closed hooks before
network forwarding services start.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess

STATE = Path("/etc/vpngw-policy-agent/persistent-vpn")
NFT = "/usr/sbin/nft"
NAME = re.compile(r"[a-z][a-z0-9-]{1,31}\Z")
IFACE = re.compile(r"[a-zA-Z0-9_.-]{1,15}\Z")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")

def validate(d: dict) -> dict:
    if not isinstance(d, dict) or set(d) != {"id", "host", "lan", "vpn", "mac", "confirmed"}:
        raise ValueError("Unexpected persistent VPN config fields")
    if not NAME.fullmatch(d["id"]) or d["confirmed"] is not True:
        raise ValueError("Only confirmed VPN policies are eligible")
    host = ipaddress.IPv4Address(d["host"])
    if not host.is_private:
        raise ValueError("VPN client must have private IPv4 address")
    if not IFACE.fullmatch(d["lan"]) or not re.fullmatch(r"(?:wg[a-f0-9]{11}|tun[a-f0-9]{10})", d["vpn"]):
        raise ValueError("Invalid interface name")
    if d["lan"] == d["vpn"] or not MAC.fullmatch(d["mac"]):
        raise ValueError("Client MAC missing or invalid")
    if d["mac"] == "00:00:00:00:00:00":
        raise ValueError("Client MAC invalid")
    return d

def guard_name(policy_id: str) -> str:
    if not NAME.fullmatch(policy_id):
        raise ValueError("Invalid policy ID")
    return "vpngw_boot_" + policy_id.replace("-", "_")

def render(d: dict) -> str:
    d = validate(d)
    lan, vpn, host, mac = d["lan"], d["vpn"], d["host"], d["mac"]
    table = guard_name(d["id"])
    # IPv6 identity is MAC-based because hosts may use temporary IPv6 source IPs.
    # DHCP, IPv4 DNS, direct fallback and LAN hairpin bypass are all denied
    # while the proper VPN rules are absent. DNS egress over VPN is possible.
    return f'''table inet {table} {{
 chain forwarding {{
  type filter hook forward priority -205; policy accept;
  iifname "{lan}" ether saddr {mac} meta nfproto ipv6 counter drop
  iifname "{lan}" ip saddr {host} oifname != "{vpn}" counter drop
 }}
 chain local_dns {{
  type filter hook input priority -205; policy accept;
  iifname "{lan}" ether saddr {mac} meta nfproto ipv6 counter drop
  iifname "{lan}" ip saddr {host} udp dport 53 counter drop
  iifname "{lan}" ip saddr {host} tcp dport 53 counter drop
 }}
}}
'''

def records(directory: Path):
    for file in sorted(directory.glob("*.json")):
        if not NAME.fullmatch(file.stem):
            raise ValueError("Unsafe policy file")
        if file.is_symlink():
            raise ValueError("Symlink not allowed")
        mode = file.stat()
        if mode.st_uid != 0 or mode.st_mode & 0o077:
            raise ValueError("Persistent policy must be root-owned and mode 0600")
        data = validate(json.loads(file.read_text(encoding="utf-8")))
        if data["id"] != file.stem:
            raise ValueError("Policy ID differs from filename")
        yield data

def reconcile(directory: Path = STATE) -> list[str]:
    installed = []
    if not directory.exists():
        return installed
    for data in records(directory):
        table = guard_name(data["id"])
        result = subprocess.run([NFT, "list", "table", "inet", table],
                                capture_output=True, text=True, timeout=8)
        if result.returncode == 0:
            # Guard must match expected config. Never silently accept stale guard.
            current = result.stdout
            if any(item not in current for item in (data["host"], data["vpn"], data["mac"], data["lan"], "oifname !=", "udp dport 53", "tcp dport 53", "meta nfproto ipv6")):
                raise ValueError("Existing boot guard does not match persisted policy")
        else:
            subprocess.run([NFT, "-f", "-"], input=render(data), capture_output=True,
                           text=True, check=True, timeout=8)
        installed.append(data["id"])
    return installed

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["check", "install"])
    parser.add_argument("--directory", type=Path, default=STATE)
    args = parser.parse_args()
    if args.action == "check":
        for data in records(args.directory) if args.directory.exists() else ():
            print(data["id"], "validated")
    else:
        print("installed:", ",".join(reconcile(args.directory)))

if __name__ == "__main__":
    main()
