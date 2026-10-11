#!/usr/bin/env python3
"""Pure recovery plan for a confirmed per-client VPN; no host changes."""
from __future__ import annotations
import hashlib
import ipaddress
import re

IFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")
VPN = re.compile(r"wg[a-f0-9]{11}\Z")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")

def validate(config: dict) -> dict:
    required = {"id", "host", "lan", "vpn", "mac", "confirmed"}
    if not required.issubset(config) or config.get("confirmed") is not True:
        raise ValueError("Unconfirmed VPN policy")
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", config["id"]):
        raise ValueError("Invalid client policy ID")
    host = ipaddress.IPv4Address(config["host"])
    if not host.is_private:
        raise ValueError("Client address must be private")
    if not IFACE.fullmatch(config["lan"]) or not VPN.fullmatch(config["vpn"]):
        raise ValueError("Invalid interface")
    if config["vpn"] == config["lan"] or not MAC.fullmatch(config["mac"]):
        raise ValueError("Invalid identity")
    return config

def build(config: dict, *, observed_lan: bool, observed_vpn: bool,
          guard_installed: bool, verified_mac: bool,
          vpn_handshake: bool) -> dict:
    c = validate(config)
    digest = hashlib.sha256((c["id"] + ":" + c["host"]).encode()).hexdigest()
    table = 20000 + int(digest[:8], 16) % 20000
    priority = 10000 + int(digest[8:16], 16) % 10000
    checks = {"boot_guard_active": guard_installed, "lan_available": observed_lan,
              "client_identity_verified": verified_mac, "vpn_interface_up": observed_vpn,
              "vpn_handshake_recent": vpn_handshake}
    cmds = [
        ["/usr/sbin/ip", "-4", "route", "replace", "unreachable", "default", "metric", "42700", "table", str(table)],
        ["/usr/sbin/ip", "-4", "route", "replace", "default", "dev", c["vpn"], "metric", "10", "table", str(table)],
        ["/usr/sbin/ip", "-4", "rule", "add", "pref", str(priority), "iif", c["lan"],
         "from", c["host"] + "/32", "lookup", str(table)],
    ]
    return {"policy_id": c["id"], "host": c["host"], "lan": c["lan"],
            "vpn": c["vpn"], "table": table, "priority": priority,
            "checks": checks, "ready": all(checks.values()),
            "commands": cmds, "applied": False,
            "safety": "Requires preinstalled boot guard and collision-free route table / priority. No main-table changes.",
            "missing": [key for key, ok in checks.items() if not ok]}
