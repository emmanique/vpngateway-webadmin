#!/usr/bin/env python3
"""Exact LAN management exception for VPN-assigned clients; no Internet bypass."""
import ipaddress
import json
import re
import subprocess
from pathlib import Path

STATE = Path("/var/lib/vpngw-policy-agent/management/proxy.json")
CONTAINER = "vpngateway-v001-staging-lan-https-1"


def target(*, cached_only=False):
    current = None
    probe = None if cached_only else subprocess.run(
        ["/usr/bin/docker", "inspect", CONTAINER],
        text=True, capture_output=True, timeout=6)
    if probe is not None and probe.returncode == 0 and probe.stdout.strip():
        try:
            info = json.loads(probe.stdout)[0]
            bindings = info["HostConfig"]["PortBindings"].get("443/tcp") or []
            networks = info["NetworkSettings"]["Networks"]
            if len(bindings) == 1 and len(networks) == 1:
                current = {"gateway": bindings[0]["HostIp"],
                           "port": int(bindings[0]["HostPort"]),
                           "proxy": next(iter(networks.values()))["IPAddress"]}
        except (ValueError, KeyError, IndexError, TypeError):
            current = None
    if current is None and STATE.exists():
        current = json.loads(STATE.read_text())
    if not current:
        raise ValueError("Management proxy not discovered")
    for field in ("gateway", "proxy"):
        address = ipaddress.IPv4Address(current[field])
        if not address.is_private or address.is_loopback or address.is_unspecified:
            raise ValueError("Invalid management " + field)
    if current["port"] != 443 or current["gateway"] == current["proxy"]:
        raise ValueError("Unexpected management HTTPS binding")
    if current and probe is not None and probe.returncode == 0 and probe.stdout.strip():
        STATE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        STATE.write_text(json.dumps(current, sort_keys=True))
        STATE.chmod(0o600)
    return current


def match(host, mac, lan):
    ipaddress.IPv4Address(host)
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise ValueError("Invalid host MAC")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", lan):
        raise ValueError("Invalid LAN")
    try:
        cfg = target(cached_only=True)
    except (ValueError, OSError, KeyError):
        return None
    return (f'iifname "{lan}" ether saddr {mac} ip saddr {host} '
            f'ip daddr {cfg["proxy"]} tcp dport 443')


def ensure(policy_id, host, mac, lan):
    cfg = target()
    clause = match(host, mac, lan)
    rule = subprocess.run(["/usr/sbin/ip", "-4", "rule", "show"], capture_output=True,
                          text=True, check=True, timeout=6).stdout
    signature = f"from {host} to {cfg['proxy']} iif {lan} lookup main"
    if not any(signature in row for row in rule.splitlines()):
        subprocess.run(["/usr/sbin/ip", "-4", "rule", "add", "pref", "9000",
                        "iif", lan, "from", host + "/32", "to",
                        cfg["proxy"] + "/32", "lookup", "main"],
                       check=True, timeout=6)
    route = subprocess.run(["/usr/sbin/ip", "-4", "route", "get", cfg["proxy"],
                            "from", host, "iif", lan], capture_output=True, text=True,
                           check=True, timeout=6).stdout
    if "dev br-" not in route and "dev docker0" not in route:
        raise ValueError("Management proxy is not routed through a Docker bridge")
    nft = "/usr/sbin/nft"
    listing = subprocess.run([nft, "list", "chain", "ip", "filter", "DOCKER-USER"],
                             capture_output=True, text=True, check=True, timeout=6).stdout
    marker = "vpngw_management_" + policy_id.replace("-", "_")
    if marker not in listing:
        batch = f'insert rule ip filter DOCKER-USER {clause} counter accept comment "{marker}"\n'
        for args in ([nft, "-c", "-f", "-"], [nft, "-f", "-"]):
            subprocess.run(args, input=batch, text=True, capture_output=True,
                           check=True, timeout=6)
    return cfg
