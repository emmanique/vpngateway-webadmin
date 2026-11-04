#!/usr/bin/env python3
"""Reconcile the one privileged port-forward reservation with real host policy.

Executed only by authenticated vpngw-policy-agent under its existing lock.
A missing VPN mapping is a valid state, never a reason to route via physical WAN.
"""
from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
import tempfile

HERE = Path(__file__).resolve().parent
OWNER_FILE = "port-forward-owner.json"
ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")


def _module(filename, identifier):
    spec = importlib.util.spec_from_file_location(identifier, HERE / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


forward = _module("vpngw-port-forward.py", "vpngw_owned_forward")
natpmp = _module("vpngw-natpmp-discovery.py", "vpngw_natpmp_discovery")


def load_owner(base: Path) -> str | None:
    path = base / "port-forward" / OWNER_FILE
    if not path.is_file() or path.is_symlink():
        return None
    content = json.loads(path.read_text(encoding="utf-8"))
    owner = content.get("policy_id")
    if not isinstance(owner, str) or not ID_RE.fullmatch(owner):
        raise ValueError("Invalid saved forwarding owner")
    return owner


def save_owner(base: Path, owner: str | None, *, provider: str = 'generic', upnp_enabled: bool = False):
    path = base / 'port-forward' / OWNER_FILE
    if owner is None:
        path.unlink(missing_ok=True)
        return
    if not ID_RE.fullmatch(owner):
        raise ValueError("Invalid forwarding owner")
    if provider not in ('generic','proton'): raise ValueError('Unknown NAT-PMP provider')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, tmp = tempfile.mkstemp(dir=path.parent, prefix=".forward-owner-")
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump({"policy_id": owner, "provider": provider,
                       "upnp_enabled": bool(upnp_enabled)}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_owner_provider(base: Path) -> str:
    path = base / 'port-forward' / OWNER_FILE
    if not path.is_file() or path.is_symlink(): return 'generic'
    provider = json.loads(path.read_text(encoding='utf-8')).get('provider','generic')
    if provider not in ('generic','proton'): raise ValueError('Invalid NAT-PMP provider')
    return provider


def load_owner_upnp(base: Path) -> bool:
    """Legacy records without the flag remain securely opt-out."""
    path = base / "port-forward" / OWNER_FILE
    if not path.is_file() or path.is_symlink():
        return False
    settings = json.loads(path.read_text(encoding="utf-8"))
    if type(settings.get("upnp_enabled", False)) is not bool:
        raise ValueError("Invalid selected host UPnP flag")
    return settings.get("upnp_enabled", False)


def ingress_addresses(interface: str, runner=subprocess.run):
    if not forward.NAME.fullmatch(interface):
        raise ValueError("Invalid interface")
    proc = runner(["/usr/sbin/ip", "-j", "-4", "address", "show", "dev", interface],
                  capture_output=True, text=True, timeout=5)
    if proc.returncode:
        raise ValueError("Ingress interface cannot be inspected")
    interfaces = json.loads(proc.stdout)
    if len(interfaces) != 1 or interfaces[0].get("ifname") != interface:
        raise ValueError("Ingress interface not found")
    return [str(ipaddress.ip_address(a["local"])) for a in interfaces[0].get("addr_info", [])
            if a.get("family") == "inet" and a.get("scope") in ("global", "host")]


def observed_host_binding(host_ip: str, registered_mac: str, lan_interface: str,
                          runner=subprocess.run) -> bool:
    """Fail closed if the selected host's current IP/MAC pairing is not evidenced.

    A saved host IPv4 is a mutable locator. Never forward packets to an address
    that the kernel cannot associate with the registered physical identity.
    """
    if (not isinstance(lan_interface, str)
            or not forward.NAME.fullmatch(lan_interface)
            or not isinstance(registered_mac, str)
            or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", registered_mac.lower())):
        return False
    try:
        address = ipaddress.ip_address(host_ip)
        if address.version != 4 or address.is_loopback or address.is_unspecified:
            return False
        result = runner(["/usr/sbin/ip", "-j", "-4", "neigh", "show", "to",
                         str(address), "dev", lan_interface],
                        capture_output=True, text=True, timeout=5)
        if result.returncode:
            return False
        neighbors = json.loads(result.stdout)
        if len(neighbors) != 1:
            return False
        entry = neighbors[0]
        # iproute2 omits "dev" in JSON when the command is already
        # filtered with "dev IFACE"; reject only an explicit mismatch.
        if entry.get("dev", lan_interface) != lan_interface:
            return False
        states = entry.get("state", [])
        if isinstance(states, str):
            states = [states]
        if not isinstance(states, list) or not states:
            return False
        valid_states = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}
        if not all(isinstance(state, str) for state in states):
            return False
        if not set(state.upper() for state in states).issubset(valid_states):
            return False
        return (entry.get("dst") == str(address)
                and str(entry.get("lladdr", "")).lower() == registered_mac.lower())
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        return False


def reconcile(owner: str | None, *, base: Path, read_state,
              inspect_rules, identity_guard_ok, vpn_tunnel_status,
              nft_path="/usr/sbin/nft", runner=subprocess.run):
    """Return observation, not an external reachability guarantee."""
    if not owner:
        actual = forward.apply(nft_path, None, None, runner=runner)
        return {**actual, "status": "disabled", "owner": None}
    if not ID_RE.fullmatch(owner):
        raise ValueError("Invalid forwarding policy")
    saved = read_state(owner)
    if not saved or saved.get("status") != "active" or not saved.get("applied"):
        actual = forward.apply(nft_path, None, None, runner=runner)
        return {**actual, "status": "policy_unavailable", "owner": owner}
    plan = saved.get("plan") or {}
    mac = plan.get("registered_mac")
    if not mac or not inspect_rules(owner) or not identity_guard_ok(owner, mac):
        actual = forward.apply(nft_path, None, None, runner=runner)
        return {**actual, "status": "identity_or_policy_unverified", "owner": owner}
    if not observed_host_binding(plan.get("host", ""), mac, plan.get("lan", ""), runner):
        actual = forward.apply(nft_path, None, None, runner=runner)
        return {**actual, "status": "host_ip_mac_binding_changed_or_unverified",
                "owner": owner, "external_ports": {}}
    route = plan.get("destination")
    if route == "blocked":
        actual = forward.apply(nft_path, None, None, runner=runner)
        return {**actual, "status": "blocked", "owner": owner}
    if route == "direct":
        ingress = plan.get("wan")
        protocols = [{"protocol": proto, "internal_port": 6881, "external_port": 6881}
                     for proto in ("tcp", "udp")]
        connected = False
    else:
        tunnel = vpn_tunnel_status(route)
        ingress = tunnel.get("interface")
        if not tunnel.get("connected") or ingress != (saved.get("vpn_runtime") or {}).get("interface"):
            actual = forward.apply(nft_path, None, None, runner=runner)
            return {**actual, "status": "vpn_disconnected", "owner": owner}
        provider = load_owner_provider(base)
        if (provider == 'proton' and tunnel.get('protocol') == 'openvpn'
                and not tunnel.get('proton_pmp_authorized')):
            actual = forward.apply(nft_path, None, None, runner=runner)
            return {**actual, 'status': 'openvpn_proton_pmp_suffix_missing', 'owner': owner}
        gateway = natpmp.PROTON_GATEWAY if provider == 'proton' else natpmp.candidate_gateway(ingress, runner=runner)
        if not gateway:
            gateway = natpmp.candidate_from_tunnel_address(ingress, runner=runner)
        if not gateway:
            actual = forward.apply(nft_path, None, None, runner=runner)
            return {**actual, "status": "vpn_natpmp_gateway_unavailable", "owner": owner}
        try:
            previous = json.loads((base / "port-forward" / "runtime.json").read_text())
        except (OSError, ValueError):
            previous = {}
        preferred = (previous.get("external_ports") or {}) if (
            previous.get("owner") == owner and previous.get("route") == route
            and previous.get("gateway") == gateway) else {}
        discovery = natpmp.discover(gateway, ingress, runner=runner, preferred=preferred, provider=provider)
        protocols = discovery["mappings"]
        if not protocols:
            actual = forward.apply(nft_path, None, None, runner=runner)
            return {**actual, "status": discovery.get("status", "no_provider_mapping"),
                    "owner": owner, "upnp_fallback_active": False}
        # libtorrent requires a single listening port for BOTH TCP and UDP.
        # A partial NAT-PMP lease must not be published as operational, even
        # if the single mapped protocol is reachable from the provider.
        if (len(protocols) != 2
                or {p.get("protocol") for p in protocols} != {"tcp", "udp"}):
            actual = forward.apply(nft_path, None, None, runner=runner)
            return {**actual, "status": "vpn_tcp_udp_mapping_incomplete",
                    "owner": owner, "external_ports": {},
                    "upnp_fallback_active": False}
        if len({p["external_port"] for p in protocols}) != 1:
            actual = forward.apply(nft_path, None, None, runner=runner)
            return {**actual, "status": "vpn_tcp_udp_ports_conflict",
                    "owner": owner, "external_ports": {}}
        protocols = [{**p, "internal_port": p["external_port"]} for p in protocols]
        connected = True
    addresses = ingress_addresses(ingress, runner=runner)
    if not addresses:
        actual = forward.apply(nft_path, None, None, runner=runner)
        return {**actual, "status": "ingress_ipv4_unavailable", "owner": owner}
    selection = {"host_ip": plan["host"], "route": route,
                 "vpn_interface": ingress if route != "direct" else None,
                 "vpn_connected": connected, "ingress_ipv4": addresses,
                 "mappings": protocols}
    # Never publish a DNAT mapping before checking lease duration.
    # A provider rule might already exist, so failure also removes stale DNAT.
    lease_expiry = None
    if route != "direct":
        lease_seconds = [p.get("lifetime", 0) for p in protocols]
        if not lease_seconds or any(type(v) is not int or v <= 5 for v in lease_seconds):
            forward.apply(nft_path, None, None, runner=runner)
            raise ValueError("Provider NAT-PMP lease duration was not verified")
        lease_expiry = time.time() + min(lease_seconds) - 5
    applied = forward.apply(nft_path, selection, saved, runner=runner)
    return {**applied, "status": "nat_rules_verified" if applied["applied"] else "unmapped",
            "lease_expires_at": lease_expiry,
            "owner": owner, "provider_lease": route != "direct",
            "provider": load_owner_provider(base) if route != "direct" else "generic",
            "gateway": gateway if route != "direct" else None,
            "vpn_interface": ingress if route != "direct" else None,
            "external_ports": {p["protocol"]: p["external_port"] for p in protocols}}


def revoke_previous_lease(base: Path, owner: str, runner=subprocess.run,
                          *, previous_runtime: dict | None = None) -> dict:
    """Revoke a recorded owned lease, including across atomic state invalidation."""
    if previous_runtime is None:
        try:
            record = json.loads((base / "port-forward" / "runtime.json").read_text())
        except (OSError, ValueError):
            return {"revoked": [], "reason": "no_previous_lease"}
    else:
        record = previous_runtime
    if record.get("owner") != owner or not record.get("provider_lease"):
        return {"revoked": [], "reason": "no_vpn_lease"}
    gateway = record.get("gateway")
    interface = record.get("vpn_interface")
    if not gateway or not interface:
        return {"revoked": [], "reason": "missing_gateway_or_interface"}
    return natpmp.revoke(gateway, interface, record.get("external_ports") or {}, runner=runner,
                         provider=record.get("provider", "generic"))
