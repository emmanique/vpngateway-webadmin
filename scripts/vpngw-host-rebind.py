#!/usr/bin/env python3
"""Read-only, strict DHCP-renumbering preflight for a MAC-bound host policy.

A neighbor cache entry is only an observation. This preflight never grants
network access, edits a policy, or treats a stale ARP mapping as ownership.
"""
from __future__ import annotations
import ipaddress
import re

MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
IFACE = re.compile(r"[a-zA-Z0-9_.-]{1,15}\Z")
VALID_NUD = {"REACHABLE", "PERMANENT"}


class RebindError(ValueError):
    pass


def candidate_from_neighbors(plan: dict, neighbors: list[dict],
                             addresses: list[dict],
                             occupied: set[str]) -> dict:
    mac = str(plan.get("registered_mac") or "").lower()
    lan = plan.get("lan")
    if not MAC.fullmatch(mac) or not isinstance(lan, str) or not IFACE.fullmatch(lan):
        raise RebindError("Missing registered MAC or trusted LAN interface")
    try:
        old = ipaddress.IPv4Address(plan["host"])
    except (ValueError, KeyError, TypeError) as exc:
        raise RebindError("Invalid previous host address") from exc
    if not old.is_private or old.is_loopback:
        raise RebindError("Invalid previous private LAN address")
    subnets = set()
    for interface in addresses:
        if interface.get("ifname") != lan:
            continue
        for entry in interface.get("addr_info", []):
            if entry.get("family") == "inet":
                try:
                    subnets.add(ipaddress.ip_interface(
                        str(entry["local"]) + "/" + str(entry["prefixlen"])).network)
                except (KeyError, TypeError, ValueError):
                    continue
    if len(subnets) != 1 or old not in next(iter(subnets)):
        raise RebindError("Ambiguous or changed LAN subnet")
    subnet = next(iter(subnets))
    matches = []
    for record in neighbors:
        if (record.get("dev") != lan or
            str(record.get("lladdr", "")).lower() != mac):
            continue
        raw_state = record.get("state", "")
        states = {raw_state.upper()} if isinstance(raw_state, str) else {
            str(item).upper() for item in raw_state} if isinstance(raw_state, list) else set()
        if not (states & VALID_NUD):
            continue
        try:
            address = ipaddress.IPv4Address(record["dst"])
        except (KeyError, TypeError, ValueError):
            continue
        if (address not in subnet or address == subnet.network_address
                or address == subnet.broadcast_address):
            continue
        matches.append(str(address))
    matches = sorted(set(matches), key=lambda ip: int(ipaddress.IPv4Address(ip)))
    if len(matches) != 1:
        raise RebindError("MAC has no unique fresh IPv4 neighbor binding")
    new_ip = matches[0]
    if new_ip != str(old) and new_ip in occupied:
        raise RebindError("Target IPv4 is reserved by a different policy")
    return {"previous_ip": str(old), "candidate_ip": new_ip,
            "registered_mac": mac, "lan": lan,
            "changed": new_ip != str(old),
            "verified_neighbor": True,
            "cutover_performed": False}

# Persist quarantine in the existing root-only VPN boot-guard directory.
# Its boot-time reconciler runs before Docker/network forwarding is enabled.
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

QUARANTINE_ROOT = Path("/etc/vpngw-policy-agent/persistent-vpn/rebind-pending")
NFT = "/usr/sbin/nft"


def quarantine_name(pid: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", pid):
        raise RebindError("Invalid policy ID")
    return "vpngw_rebind_" + hashlib.sha256(pid.encode("ascii")).hexdigest()[:12]


def quarantine_script(pid: str, mac: str, lan: str, previous_ip: str,
                      candidate_ip: str) -> str:
    """Drop every forwarded packet AND local DNS from the selected MAC.

    This high-priority table remains in the kernel until the DB and policy
    agent have BOTH committed and independently verified the new identity.
    """
    if not MAC.fullmatch(mac) or not IFACE.fullmatch(lan):
        raise RebindError("Untrusted quarantine identity")
    previous = str(ipaddress.IPv4Address(previous_ip))
    candidate = str(ipaddress.IPv4Address(candidate_ip))
    if not all(ipaddress.IPv4Address(value).is_private for value in (previous, candidate)):
        raise RebindError("Only private LAN addresses can be quarantined")
    name = quarantine_name(pid)
    return f'''table inet {name} {{
 chain forward_lock {{
  type filter hook forward priority -310; policy accept;
  iifname "{lan}" ether saddr {mac} counter drop
  ip daddr {previous} counter drop
  ip daddr {candidate} counter drop
 }}
 chain local_lock {{
  type filter hook input priority -310; policy accept;
  iifname "{lan}" ether saddr {mac} counter drop
 }}
}}
'''


def _private_root(path: Path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o077):
        raise RebindError("Quarantine journal directory is not root-private")


def read_pending(pid: str, root: Path = QUARANTINE_ROOT) -> dict | None:
    path = root / (quarantine_name(pid) + ".json")
    if not path.exists():
        return None
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o077):
        raise RebindError("Untrusted quarantine journal")
    data = json.loads(path.read_text(encoding="utf-8"))
    if (data.get("pid") != pid or not MAC.fullmatch(data.get("mac", ""))
            or not IFACE.fullmatch(data.get("lan", ""))):
        raise RebindError("Malformed quarantine journal")
    for key in ("previous_ip", "candidate_ip"):
        if not ipaddress.IPv4Address(data[key]).is_private:
            raise RebindError("Invalid quarantine IPv4")
    return data


def write_pending(record: dict, root: Path = QUARANTINE_ROOT):
    pid = record["pid"]
    _private_root(root)
    if read_pending(pid, root) is not None:
        raise RebindError("A prior host rebind must be completed or recovered first")
    data = {
        "pid": pid, "mac": record["mac"], "lan": record["lan"],
        "previous_ip": record["previous_ip"],
        "candidate_ip": record["candidate_ip"],
        "route": record["route"],
    }
    quarantine_script(pid, data["mac"], data["lan"],
                      data["previous_ip"], data["candidate_ip"])
    target = root / (quarantine_name(pid) + ".json")
    fd, temp = tempfile.mkstemp(prefix=".rebind-", dir=root)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(data, out, sort_keys=True)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, target)
    finally:
        Path(temp).unlink(missing_ok=True)


def ensure_quarantine(record: dict, *, runner=subprocess.run, nft=NFT):
    name = quarantine_name(record["pid"])
    current = runner([nft, "list", "table", "inet", name],
                     capture_output=True, text=True, timeout=8)
    if current.returncode == 0:
        if (f'ether saddr {record["mac"]}' not in current.stdout
                or f'iifname "{record["lan"]}"' not in current.stdout
                or "forward_lock" not in current.stdout
                or "local_lock" not in current.stdout
                or current.stdout.count(" drop") < 4
                or "ip daddr " + record["previous_ip"] not in current.stdout
                or "ip daddr " + record["candidate_ip"] not in current.stdout):
            raise RebindError("An existing quarantine cannot be trusted")
        return
    script = quarantine_script(record["pid"], record["mac"], record["lan"],
                               record["previous_ip"], record["candidate_ip"])
    for args in ((nft, "-c", "-f", "-"), (nft, "-f", "-")):
        runner(args, input=script, capture_output=True, text=True,
               check=True, timeout=8)


def release_quarantine(pid: str, *, root: Path = QUARANTINE_ROOT,
                       runner=subprocess.run, nft=NFT):
    record = read_pending(pid, root)
    if record is None:
        raise RebindError("No verified pending rebind")
    name = quarantine_name(pid)
    # Remove the kernel lockdown BEFORE removing the journal: a crash
    # can only cause an extra lockdown at next boot, never a missing one.
    runner([nft, "delete", "table", "inet", name],
           capture_output=True, text=True, check=True, timeout=8)
    (root / (name + ".json")).unlink()
