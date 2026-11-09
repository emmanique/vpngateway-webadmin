#!/usr/bin/env python3
"""Host-scoped nftables controller. Linux host only; never changes host routes or DNS."""
import argparse
import configparser
import tempfile
import hashlib
import hmac
import fcntl
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import re
import socketserver
import subprocess
import threading
import time

BASE = Path("/var/lib/vpngw-policy-agent")
SOCKET = "/run/vpngw-policy-agent/control.sock"
TOKEN = "/etc/vpngw-policy-agent/secret"
LOCK = threading.RLock()
DISCOVERY_LOCK = threading.Lock()
WG_RETRY_AFTER = {}  # monotonic backoff for unexpectedly lost WireGuard tunnels
NFT = "/usr/sbin/nft"
IP = "/usr/sbin/ip"
MAX_BYTES = 131072
_LOCK_FD = None
_LOCK_DEPTH = 0


@contextmanager
def file_lock():
    global _LOCK_FD, _LOCK_DEPTH
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if _LOCK_DEPTH == 0:
        _LOCK_FD = os.open(BASE / ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(_LOCK_FD, fcntl.LOCK_EX)
    _LOCK_DEPTH += 1
    try:
        yield
    finally:
        _LOCK_DEPTH -= 1
        if _LOCK_DEPTH == 0:
            fcntl.flock(_LOCK_FD, fcntl.LOCK_UN)
            os.close(_LOCK_FD)
            _LOCK_FD = None


def run(*argv, input_text=None):
    return subprocess.run(argv, input=input_text, text=True, capture_output=True,
                          check=True, timeout=12)


def ensure_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", value):
        raise ValueError("Identificador de política inválido")
    return value


def state_path(pid):
    return BASE / (ensure_id(pid) + ".json")


def chain_name(pid):
    return "GW_" + hashlib.sha256(pid.encode()).hexdigest()[:16].upper()


def topology():
    links = json.loads(run(IP, "-j", "-4", "addr", "show").stdout)
    routes = json.loads(run(IP, "-j", "-4", "route", "show", "default").stdout)
    return links, routes


def validate(ip_str, destination, config):
    host = ipaddress.ip_address(ip_str)
    if host.version != 4 or host.is_multicast or host.is_loopback or host.is_unspecified:
        raise ValueError("IPv4 de host inválido")
    if destination not in ("direct", "blocked"):
        raise ValueError("O dataplane VPN ainda não está disponível")
    if not isinstance(config, dict) or config.get("mode") not in ("shared", "routed", "multi_lan"):
        raise ValueError("WAN/LAN não configurada")
    assignments = config.get("interfaces", [])
    if not isinstance(assignments, list):
        raise ValueError("Interfaces inválidas")
    roles = {i["interface"]: i["role"] for i in assignments}
    if len(roles) != len(assignments):
        raise ValueError("Interfaces duplicadas")
    lan = [i for i, role in roles.items() if role == "lan"]
    wan = ([config.get("management_interface")] if config["mode"] == "shared"
           else [i for i, role in roles.items() if role == "wan"])
    if not lan or len(wan) != 1 or wan[0] not in roles:
        raise ValueError("Funções WAN/LAN inválidas")
    if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "1":
        raise ValueError("Encaminhamento IPv4 do anfitrião está desactivado")
    links, routes = topology()
    available = {x["ifname"]: x for x in links if x.get("operstate") == "UP"}
    if any(i not in available for i in lan + wan):
        raise ValueError("Interface configurada desligada")
    candidate = []
    protected = set()
    for interface in links:
        for addr in interface.get("addr_info", []):
            if addr.get("family") == "inet":
                protected.add(ipaddress.ip_address(addr["local"]))
    for interface in lan:
        for addr in available[interface].get("addr_info", []):
            if addr.get("family") == "inet":
                subnet = ipaddress.ip_interface(addr["local"] + "/" + str(addr["prefixlen"])).network
                if host in subnet:
                    candidate.append(interface)
    if len(set(candidate)) != 1:
        raise ValueError("Host não pertence unicamente a uma LAN activa")
    default_routes = [r for r in routes if r.get("dev") == wan[0] and r.get("gateway")]
    if len(default_routes) != 1 and destination == "direct":
        raise ValueError("Gateway WAN ausente ou ambíguo")
    gateways = {ipaddress.ip_address(r["gateway"]) for r in routes if r.get("gateway")}
    if host in protected | gateways:
        raise ValueError("Não é permitido aplicar políticas ao gateway ou router")
    return {"host": str(host), "lan": candidate[0], "wan": wan[0],
            "gateway": default_routes[0]["gateway"] if default_routes else None,
            "destination": destination, "shared": candidate[0] == wan[0]}


def identity_guard_ok(pid, mac):
    if not mac:
        return True
    listing = run(NFT, "list", "chain", "ip", "filter", chain_name(pid)).stdout
    return "ether saddr != " + mac.lower() in listing and "vpngw_identity_guard" in listing


def renumber_guard_ok(pid, mac, plan):
    """Confirm a MAC-specific DOCKER-USER jump and an IPv4-renumbering drop."""
    name = chain_name(pid)
    chain = run(NFT, "list", "chain", "ip", "filter", name).stdout
    parent = run(NFT, "list", "chain", "ip", "filter", "DOCKER-USER").stdout
    mac = mac.lower()
    host = plan["host"]
    return (any("vpngw_ip_rebind_guard" in line
                and "ether saddr " + mac in line
                and "ip saddr != " + host in line
                for line in chain.splitlines())
            and any("jump " + name in line and "ether saddr " + mac in line
                    for line in parent.splitlines()))


def _set_kernel_identity_guard(pid, mac, plan):
    """Atomically align identity, renumber guard and MAC jump for a host."""
    if not isinstance(mac, str) or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise ValueError("MAC inválido")
    host = str(ipaddress.IPv4Address(plan["host"]))
    lan = plan["lan"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", lan):
        raise ValueError("Interface LAN inválida")
    name = chain_name(pid)
    chain = run(NFT, "-a", "list", "chain", "ip", "filter", name).stdout
    parent = run(NFT, "-a", "list", "chain", "ip", "filter", "DOCKER-USER").stdout
    desired_identity = "ether saddr != " + mac
    desired_renumber = "ether saddr " + mac
    wanted_identity = any("vpngw_identity_guard" in line and desired_identity in line
                          for line in chain.splitlines())
    wanted_renumber = any("vpngw_ip_rebind_guard" in line
                          and desired_renumber in line and "ip saddr != " + host in line
                          for line in chain.splitlines())
    wanted_jump = any("jump " + name in line and desired_renumber in line
                      for line in parent.splitlines())
    batch = []
    if not wanted_identity:
        batch.append(f'insert rule ip filter {name} iifname "{lan}" ip saddr {host} '
                     f'ether saddr != {mac} drop comment "vpngw_identity_guard"')
    if not wanted_renumber:
        batch.append(f'insert rule ip filter {name} iifname "{lan}" ether saddr {mac} '
                     f'ip saddr != {host} drop comment "vpngw_ip_rebind_guard"')
    if not wanted_jump:
        batch.append(f'insert rule ip filter DOCKER-USER iifname "{lan}" '
                     f'ether saddr {mac} jump {name}')
    for line in chain.splitlines():
        if "# handle " not in line:
            continue
        owned = "vpngw_identity_guard" in line or "vpngw_ip_rebind_guard" in line
        valid = ((("vpngw_identity_guard" in line) and desired_identity in line)
                 or (("vpngw_ip_rebind_guard" in line) and desired_renumber in line
                     and "ip saddr != " + host in line))
        if owned and not valid:
            handle = line.split("# handle ")[-1].split()[0]
            batch.append(f"delete rule ip filter {name} handle {handle}")
    for line in parent.splitlines():
        if "# handle " in line and "jump " + name in line and "ether saddr " in line:
            if desired_renumber not in line:
                handle = line.split("# handle ")[-1].split()[0]
                batch.append(f"delete rule ip filter DOCKER-USER handle {handle}")
    if batch:
        script = "\n".join(batch) + "\n"
        run(NFT, "-c", "-f", "-", input_text=script)
        run(NFT, "-f", "-", input_text=script)
    if not identity_guard_ok(pid, mac) or not renumber_guard_ok(pid, mac, plan):
        raise ValueError("Protecção IP/MAC não confirmada após actualização")


def set_identity_guard(pid, mac):
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise ValueError("MAC inválido")
    state = read_state(pid)
    if not state or state.get("status") != "active":
        raise ValueError("Política activa inexistente")
    original = json.loads(json.dumps(state))
    plan = state["plan"]
    old_mac = plan.get("registered_mac")
    vpn = plan["destination"] not in ("direct", "blocked")
    module = None
    if vpn and mac != old_mac:
        import importlib.util
        source = Path(__file__).with_name("vpngw-vpn-transaction.py")
        spec = importlib.util.spec_from_file_location("vpngw_identity_transaction", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    def replace_vpn_guard(value):
        runtime = state["vpn_runtime"]
        text = module.guard_text(pid, plan["host"], value, plan["lan"],
                                 runtime["interface"], runtime.get("dns_ipv4"))
        module.replace_guard(text, pid)
    try:
        # Replace the VPN guard first. The old basic guard keeps the new host
        # blocked until all per-host rules agree on the newly observed MAC.
        if module is not None:
            replace_vpn_guard(mac)
        _set_kernel_identity_guard(pid, mac, plan)
        plan["registered_mac"] = mac
        save_state(pid, state)  # Also synchronizes the verified boot guard.
    except Exception:
        # Restore the complete previous identity after any partial update.
        if module is not None:
            replace_vpn_guard(old_mac)
        _set_kernel_identity_guard(pid, old_mac, original["plan"])
        save_state(pid, original)
        raise
    return {"status": "active", "registered_mac": mac, "guard_verified": True}


def inspect_rules(pid):
    name = chain_name(pid)
    if not exists_chain(name):
        return False
    try:
        chain = run(NFT, "list", "chain", "ip", "filter", name).stdout
        if not ("accept" in chain or "drop" in chain):
            return False
        state = read_state(pid)
        if state and state.get("plan", {}).get("destination") == "direct":
            nat = run(NFT, "list", "table", "ip", "vpngw_" + name.lower()).stdout
            if "masquerade" not in nat:
                return False
            if state["plan"].get("shared") and "icmp type redirect" not in nat:
                return False
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _counter_for_direction(rules, host, lan, vpn, direction):
    """Match rule semantics rather than positional counters or management accepts."""
    source = direction == "tx"
    expected = [
        ("meta", "iifname", lan if source else vpn),
        ("meta", "oifname", vpn if source else lan),
        ("payload", ("ip", "saddr") if source else ("ip", "daddr"), host),
    ]
    matched = []
    for item in rules.get("nftables", []):
        expr = item.get("rule", {}).get("expr", [])
        if not any("accept" in e for e in expr):
            continue
        checks = []
        for e in expr:
            match = e.get("match")
            if not match or match.get("op") != "==":
                continue
            left = match.get("left", {})
            if "meta" in left:
                checks.append(("meta", left["meta"].get("key"), match.get("right")))
            if "payload" in left:
                value = left["payload"]
                checks.append(("payload", (value.get("protocol"), value.get("field")), match.get("right")))
        if all(criterion in checks for criterion in expected):
            matched.extend(e["counter"] for e in expr if "counter" in e)
    return matched[0] if len(matched) == 1 else None


def read_counters(pid, state):
    """Count only identified forwarding paths; blocked traffic is a separate metric."""
    if state.get("status") not in ("pending", "active") or not inspect_rules(pid):
        return None
    plan = state.get("plan") or {}
    try:
        rules = json.loads(run(NFT, "-j", "list", "chain", "ip", "filter", chain_name(pid)).stdout)
        if plan.get("destination") == "blocked":
            matches = []
            for item in rules.get("nftables", []):
                expr = item.get("rule", {}).get("expr", [])
                if not any("drop" in e for e in expr):
                    continue
                checks = [e["match"] for e in expr if "match" in e]
                if any(m.get("op") == "==" and m.get("left", {}).get("payload") == {"protocol": "ip", "field": "saddr"} and m.get("right") == plan["host"] for m in checks):
                    matches.extend(e["counter"] for e in expr if "counter" in e)
            if len(matches) == 1:
                return {"dropped_bytes": int(matches[0]["bytes"]), "dropped_packets": int(matches[0]["packets"])}
            return None
        vpn = (state.get("vpn_runtime") or {}).get("interface") if plan.get("destination") not in ("direct", "blocked") else plan.get("wan")
        if not vpn:
            return None
        tx = _counter_for_direction(rules, plan["host"], plan["lan"], vpn, "tx")
        rx = _counter_for_direction(rules, plan["host"], plan["lan"], vpn, "rx")
        if tx is not None and rx is not None:
            return {"tx_bytes": int(tx["bytes"]), "rx_bytes": int(rx["bytes"]),
                    "tx_packets": int(tx["packets"]), "rx_packets": int(rx["packets"])}
    except (KeyError, ValueError, TypeError, OSError, subprocess.SubprocessError):
        pass
    return None


def exists_chain(name):
    return subprocess.run([NFT, "list", "chain", "ip", "filter", name],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def remove_rules(pid):
    name = chain_name(pid)
    if exists_chain(name):
        listing = run(NFT, "-a", "list", "chain", "ip", "filter", "DOCKER-USER").stdout
        for line in listing.splitlines():
            if "jump " + name in line and "# handle " in line:
                handle = line.split("# handle ")[-1].split()[0]
                run(NFT, "delete", "rule", "ip", "filter", "DOCKER-USER", "handle", handle)
        run(NFT, "flush", "chain", "ip", "filter", name)
        run(NFT, "delete", "chain", "ip", "filter", name)
    # Only touch the dedicated per-policy NAT table; never flush Docker or host NAT.
    subprocess.run([NFT, "delete", "table", "ip", "vpngw_" + name.lower()],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def ensure_blocked_management(pid, plan):
    """Restore exact host-to-WebAdmin HTTPS exemption on install/recovery.

    No general LAN or Internet ACCEPT is added: only the Docker HTTPS proxy
    destination, scoped to source MAC, IP and LAN interface.
    """
    if plan.get("destination") != "blocked":
        return
    mac = plan.get("registered_mac")
    if not mac:
        raise ValueError("Blocked management exemption requires a registered MAC")
    import importlib.util
    source = Path(__file__).with_name("vpngw_management_access.py")
    spec = importlib.util.spec_from_file_location("vpngw_blocked_management", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ensure(pid, plan["host"], mac, plan["lan"])


def install_rules(plan, pid):
    name = chain_name(pid)
    host = plan["host"]
    lan, wan = plan["lan"], plan["wan"]
    if not exists_chain(name):
        run(NFT, "add", "chain", "ip", "filter", name)
    # Jump at the head of Docker's user chain; no other Docker rules are changed.
    run(NFT, "insert", "rule", "ip", "filter", "DOCKER-USER",
        "ip", "saddr", host, "jump", name)
    run(NFT, "insert", "rule", "ip", "filter", "DOCKER-USER",
        "ip", "daddr", host, "jump", name)
    if plan.get("registered_mac"):
        # MAC-specific jump also catches DHCP renumbering: an unregistered
        # source IPv4 cannot silently escape this policy through DIRECT.
        run(NFT, "insert", "rule", "ip", "filter", "DOCKER-USER",
            "iifname", lan, "ether", "saddr", plan["registered_mac"],
            "jump", name)
        run(NFT, "insert", "rule", "ip", "filter", name,
            "iifname", lan, "ether", "saddr", plan["registered_mac"],
            "ip", "saddr", "!=", host, "drop",
            "comment", "vpngw_ip_rebind_guard")
        run(NFT, "insert", "rule", "ip", "filter", name,
            "iifname", lan, "ip", "saddr", host, "ether", "saddr",
            "!=", plan["registered_mac"], "drop",
            "comment", "vpngw_identity_guard")
    if plan["destination"] == "blocked":
        run(NFT, "add", "rule", "ip", "filter", name,
            "iifname", lan, "ip", "saddr", host, "counter", "drop")
        ensure_blocked_management(pid, plan)
        return
    run(NFT, "add", "rule", "ip", "filter", name,
        "iifname", lan, "oifname", wan, "ip", "saddr", host,
        "ct", "state", "new,established,related", "counter", "accept")
    run(NFT, "add", "rule", "ip", "filter", name,
        "iifname", wan, "oifname", lan, "ip", "daddr", host,
        "ct", "state", "established,related", "counter", "accept")
    nat = "vpngw_" + name.lower()
    run(NFT, "add", "table", "ip", nat)
    run(NFT, "add", "chain", "ip", nat, "postrouting",
        "{", "type", "nat", "hook", "postrouting", "priority", "110;", "policy", "accept;", "}")
    run(NFT, "add", "rule", "ip", nat, "postrouting",
        "ip", "saddr", host, "oifname", wan, "counter", "masquerade")
    if plan["shared"]:
        # Prevent per-client ICMP redirects, which could bypass this gateway.
        run(NFT, "add", "chain", "ip", nat, "no_redirect",
            "{", "type", "filter", "hook", "output", "priority", "-10;", "policy", "accept;", "}")
        run(NFT, "add", "rule", "ip", nat, "no_redirect",
            "ip", "daddr", host, "icmp", "type", "redirect", "counter", "drop")


def sync_boot_policy(pid, state, directory=None):
    """Keep early-boot guards aligned with confirmed runtime policies."""
    import importlib.util
    source = Path(__file__).with_name("vpngw-vpn-boot-guard.py")
    spec = importlib.util.spec_from_file_location("vpngw_boot_sync", source)
    boot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boot)
    pid = ensure_id(pid)
    directory = Path(directory) if directory is not None else boot.STATE
    table = boot.guard_name(pid)
    current = subprocess.run([NFT, "list", "table", "inet", table],
                             capture_output=True, text=True, timeout=8)
    def remove_live():
        if current.returncode == 0:
            run(NFT, "delete", "table", "inet", table)
    if state is None or (state.get("status") == "active" and
                         state.get("plan", {}).get("destination") in ("direct", "blocked")):
        remove_live()
        (directory / (pid + ".json")).unlink(missing_ok=True)
        return
    if state.get("status") != "active":
        return  # Preserve fail-closed protection when recovery fails.
    if state.get("vpn_pending"):
        remove_live()  # A reboot must still restore the last confirmed config.
        return
    plan = state["plan"]
    data = boot.validate({"id": pid, "host": plan["host"], "lan": plan["lan"],
                          "vpn": state["vpn_runtime"]["interface"],
                          "mac": plan["registered_mac"], "confirmed": True})
    live = run(NFT, "list", "table", "inet", "vpngw_vpn_" + hashlib.sha256(pid.encode()).hexdigest()[:12]).stdout
    if not all(value in live for value in (data["host"], data["lan"], data["vpn"], data["mac"], "drop")):
        raise ValueError("Cannot persist an unverified VPN host guard")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_uid != 0 or directory.stat().st_mode & 0o077:
        raise ValueError("Boot guard directory must be private and root-owned")
    target = directory / (pid + ".json")
    if target.is_symlink():
        raise ValueError("Boot guard symlink refused")
    fd, temporary = tempfile.mkstemp(prefix=".sync-", dir=directory)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(data, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        batch = ("delete table inet " + table + "\n" if current.returncode == 0 else "") + boot.render(data)
        run(NFT, "-c", "-f", "-", input_text=batch)
        run(NFT, "-f", "-", input_text=batch)
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)


def save_state(pid, data):
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = state_path(pid)
    temp = target.with_suffix(".tmp")
    temp.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(temp, 0o600)
    temp.replace(target)
    sync_boot_policy(pid, data)


def schedule_rollback(pid):
    unit = "vpngw-host-revert-" + pid
    run("/usr/bin/systemd-run", "--quiet", "--unit=" + unit,
        "--on-active=180s", "/usr/bin/python3", os.path.abspath(__file__), "rollback", pid)


def cancel_rollback(pid):
    subprocess.run(["/usr/bin/systemctl", "stop", "vpngw-host-revert-" + pid + ".timer"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def rollback(pid, force=False):
    with LOCK, file_lock():
        old = read_state(pid)
        if old and old.get("status") == "active" and not force:
            return {"status": "active", "applied": True}
        remove_rules(pid)
        if old:
            save_state(pid, {**old, "status": "reverted", "applied": False, "deadline": None})
        cancel_rollback(pid)
        return {"status": "reverted", "applied": False}


def read_state(pid):
    path = state_path(pid)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def wireguard_paused_path(profile_id):
    """Persist an explicit operator disconnect separately from tunnel health."""
    return BASE / ("wireguard-paused-" + ensure_id(profile_id))


def set_wireguard_paused(profile_id, paused):
    path = wireguard_paused_path(profile_id)
    if paused:
        BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write("operator-disconnect\n")
    else:
        path.unlink(missing_ok=True)


def wireguard_iface(profile_id):
    return "wg" + hashlib.sha256(ensure_id(profile_id).encode()).hexdigest()[:11]


def wireguard_status(profile_id):
    interface = wireguard_iface(profile_id)
    present = subprocess.run([IP, "link", "show", "dev", interface],
                             capture_output=True).returncode == 0
    if not present:
        return {"state": "disconnected", "interface": None, "handshake": False,
                "tunnel_active": False, "connected": False}
    try:
        latest = run("/usr/bin/wg", "show", interface, "latest-handshakes").stdout
        stamps = [int(line.split()[-1]) for line in latest.splitlines() if line.strip()]
        handshake_at = max(stamps) if stamps else 0
        connected = bool(handshake_at > 0 and time.time() - handshake_at < 180)
        transfers = run("/usr/bin/wg", "show", interface, "transfer").stdout
        received = sent = 0
        for line in transfers.splitlines():
            fields = line.split()
            if len(fields) == 3:
                received += int(fields[1])
                sent += int(fields[2])
        return {"state": "connected" if connected else "awaiting_handshake",
                "interface": interface, "handshake": connected,
                "tunnel_active": True, "connected": connected,
                "received_bytes": received, "sent_bytes": sent,
                "last_handshake_at": handshake_at if handshake_at > 0 else None,
                "transport": "UDP", "public_ipv4": None,
                "kill_switch_active": False}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"state": "error", "interface": interface, "handshake": False,
                "tunnel_active": False, "connected": False}


def wireguard_probe(profile_id):
    status = wireguard_status(profile_id)
    if not status.get("connected") or not status.get("interface"):
        raise ValueError("Túnel WireGuard sem handshake recente")
    result = subprocess.run(["/usr/bin/curl", "-4", "-fsS", "--noproxy", "*",
                             "--interface", status["interface"], "--connect-timeout", "4",
                             "--max-time", "10", "https://api.ipify.org"],
                            capture_output=True, text=True, timeout=12, check=True)
    public = result.stdout.strip()
    address = ipaddress.ip_address(public)
    if address.version != 4 or not address.is_global:
        raise ValueError("A resposta não contém um IPv4 público válido")
    return {"public_ipv4": public, "interface": status["interface"],
            "verified_at": int(time.time()), "route_changed": False}


def wireguard_disconnect(profile_id):
    interface = wireguard_iface(profile_id)
    # Persist intent BEFORE removing the interface so an agent crash cannot
    # inadvertently reconnect an intentionally stopped profile.
    set_wireguard_paused(profile_id, True)
    try:
        if wireguard_status(profile_id)["interface"]:
            run(IP, "link", "delete", "dev", interface)
    except Exception:
        set_wireguard_paused(profile_id, False)
        raise
    return wireguard_status(profile_id)


def wireguard_connect(profile_id, configuration):
    if not isinstance(configuration, str) or len(configuration) > 65536:
        raise ValueError("Configuração WireGuard inválida")
    if wireguard_status(profile_id)["interface"]:
        raise ValueError("Interface WireGuard já existente")
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    try:
        parser.read_string(configuration)
        if set(parser.sections()) != {"Interface", "Peer"}:
            raise ValueError("Configuração deve ter exactamente Interface e Peer")
        settings = dict(parser.items("Interface"))
        peer = dict(parser.items("Peer"))
        if set(settings) - {"PrivateKey", "Address", "DNS", "MTU", "ListenPort"}:
            raise ValueError("Opções WireGuard não suportadas")
        if set(peer) - {"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"}:
            raise ValueError("Opções Peer não suportadas")
        addresses = [ipaddress.ip_interface(x.strip()) for x in settings["Address"].split(",")]
        if not addresses or len(addresses) > 2 or any(a.network.prefixlen != a.max_prefixlen for a in addresses):
            raise ValueError("O endereço WireGuard deve ser /32 ou /128")
        for label in ("PrivateKey",):
            if not settings.get(label):
                raise ValueError("Chave privada em falta")
        for label in ("PublicKey", "AllowedIPs", "Endpoint"):
            if not peer.get(label):
                raise ValueError("Campo obrigatório WireGuard em falta")
        allowed = [ipaddress.ip_network(x.strip()) for x in peer["AllowedIPs"].split(",")]
        if not allowed:
            raise ValueError("AllowedIPs em falta")
        wg_lines = ["[Interface]", "PrivateKey = " + settings["PrivateKey"]]
        if settings.get("ListenPort"):
            port = int(settings["ListenPort"])
            if not 1 <= port <= 65535:
                raise ValueError("Porta inválida")
            wg_lines.append("ListenPort = " + str(port))
        wg_lines += ["[Peer]"]
        for key in ("PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"):
            if peer.get(key):
                wg_lines.append(key + " = " + peer[key])
        mtu = int(settings.get("MTU", 1420))
        if not 1280 <= mtu <= 1500:
            raise ValueError("MTU fora dos limites")
    except (configparser.Error, KeyError, ValueError, TypeError) as error:
        raise ValueError("Configuração WireGuard não aceite: " + str(error))
    interface = wireguard_iface(profile_id)
    run(IP, "link", "add", "dev", interface, "type", "wireguard")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", prefix="wg-", suffix=".conf",
                                         dir="/run/vpngw-policy-agent", delete=False) as stream:
            temporary = stream.name
            os.chmod(temporary, 0o600)
            stream.write("\n".join(wg_lines) + "\n")
        run("/usr/bin/wg", "setconf", interface, temporary)
        for address in addresses:
            run(IP, "address", "add", str(address), "dev", interface)
        run(IP, "link", "set", "dev", interface, "mtu", str(mtu), "up")
    except Exception:
        subprocess.run([IP, "link", "delete", "dev", interface],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise
    finally:
        if temporary:
            Path(temporary).unlink(missing_ok=True)
    # An explicit successful Connect clears the durable operator pause.
    set_wireguard_paused(profile_id, False)
    return wireguard_status(profile_id)


def vpn_route_plan(data):
    import importlib.util
    filename = Path(__file__).with_name("vpngw-vpn-route-plan.py")
    spec = importlib.util.spec_from_file_location("vpngw_vpn_route_plan", filename)
    if spec is None or spec.loader is None:
        raise ValueError("Módulo de planeamento VPN indisponível")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    profile = ensure_id(data.get("profile_id"))
    state = wireguard_status(profile)
    if not state.get("interface"):
        raise ValueError("Interface WireGuard ainda não está instalada")
    current = read_state(ensure_id(data.get("id")))
    if not current or not current.get("plan"):
        raise ValueError("Política do cliente não encontrada no agente")
    plan = current["plan"]
    # Re-derive and validate the live LAN/WAN topology instead of trusting
    # interface names saved when this policy was installed.
    validate_saved_plan(plan)
    links, routes = topology()
    lan = plan["lan"]
    wan = plan["wan"]
    if not any(link.get("ifname") == lan and link.get("operstate") == "UP" for link in links):
        raise ValueError("Interface LAN da política já não está activa")
    if not any(route.get("dev") == wan and route.get("gateway") == plan.get("gateway")
               for route in routes):
        raise ValueError("Saída WAN da política mudou; é necessária nova pré-validação")
    ipv6_route = subprocess.run([IP, "-6", "route", "show", "default"],
                                capture_output=True, text=True, timeout=5)
    return module.build_plan(host_ip=plan["host"], gateway_ip=plan["gateway"],
                             lan_iface=plan["lan"], vpn_iface=state["interface"],
                             vpn_profile=profile, host_route=plan["destination"],
                             handshake=bool(state.get("connected")),
                             ipv6_default=bool(ipv6_route.stdout.strip()),
                             dns_isolated=False)


def vpn_transition_audit(data):
    """Read-only host-side safety audit; cannot apply or remove rules."""
    plan = vpn_route_plan(data)
    pid = ensure_id(data.get("id"))
    existing = read_state(pid) or {}
    routing_table = str(plan["routing"]["table_id"])
    rule_output = run(IP, "-4", "rule", "show").stdout
    routes_probe = subprocess.run([IP, "-4", "route", "show", "table", routing_table],
                                  capture_output=True, text=True, timeout=5)
    if routes_probe.returncode not in (0, 2):
        raise ValueError("Não foi possível verificar a tabela VPN")
    if routes_probe.returncode == 2 and "FIB table does not exist" not in routes_probe.stderr:
        raise ValueError("Erro inesperado ao consultar tabela VPN: " + routes_probe.stderr.strip())
    table_routes = routes_probe.stdout
    priority = str(plan["routing"]["priority"])
    occupied_priority = any(line.strip().startswith(priority + ":") for line in rule_output.splitlines())
    occupied_table = bool(table_routes.strip())
    docker_ready = exists_chain("DOCKER-USER")
    direct_rules = inspect_rules(pid) if existing.get("status") == "active" else False
    findings = [
        {"check": "active_direct_policy", "ok": existing.get("status") == "active"
         and existing.get("plan", {}).get("destination") == "direct" and direct_rules},
        {"check": "docker_forwarding", "ok": docker_ready},
        {"check": "policy_priority_free", "ok": not occupied_priority},
        {"check": "route_table_free", "ok": not occupied_table},
        {"check": "wireguard_connected", "ok": not any("handshake" in b.lower() for b in plan["blockers"])},
        {"check": "dns_isolation", "ok": False},
        {"check": "client_ipv6_verified", "ok": False},
        {"check": "atomic_transition_installed", "ok": False},
        {"check": "restore_timer_implemented", "ok": False},
    ]
    return {"ready": False, "applied": False, "network_changes": False,
            "policy_id": pid, "profile_id": plan["profile"], "host": plan["host"],
            "interfaces": plan["interfaces"], "checks": findings,
            "blockers": [f["check"] for f in findings if not f["ok"]],
            "note": "Consulta sem alterações. Só permitir migração após validar todos os requisitos."}


def vpn_tunnel_status(profile):
    """Resolve the live tunnel from its profile, not a vendor or fixed interface."""
    wg = wireguard_status(profile)
    if wg.get("connected"):
        return wg
    process=subprocess.run(["/usr/bin/python3","/usr/local/libexec/vpngw-openvpn-agent.py"],
        input=json.dumps({"id":profile,"action":"openvpn_status"}),capture_output=True,text=True,timeout=12)
    if process.returncode:
        return wg
    try:
        data=json.loads(process.stdout)
        if not data.get("connected") or not data.get("interface_name"):
            return wg
        return {"connected":True,"interface":data["interface_name"],"protocol":"openvpn",
                "proton_pmp_authorized":bool(data.get("proton_pmp_authorized")),
                "dns_ipv4":data.get("dns_ipv4")}
    except (ValueError,KeyError,TypeError):
        return wg


def vpn_transition(pid, destination, dns_ipv4=None, arm_timeout=True, previous_provider=None):
    """Fail-closed VPN cutover for one policy; atomic nft filters and rollback."""
    import importlib.util
    source = Path(__file__).with_name("vpngw-vpn-transaction.py")
    spec = importlib.util.spec_from_file_location("vpngw_vpn_transaction", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    current = read_state(pid)
    if not current or current.get("status") != "active":
        raise ValueError("Política activa necessária")
    old = current["plan"]["destination"]
    if old == destination:
        return {"status": "active", "destination": old, "changed": False}
    if not current["plan"].get("registered_mac") or not identity_guard_ok(pid, current["plan"]["registered_mac"]):
        raise ValueError("Protecção MAC do host não confirmada")
    plan = current["plan"]
    validate_saved_plan(plan)
    old_vpn = old not in ("direct", "blocked")
    new_vpn = destination not in ("direct", "blocked")
    original = json.loads(json.dumps(current))
    original_plan = dict(plan)
    original_runtime = dict(current.get("vpn_runtime") or {})
    new_route = None
    old_route = None
    if old_vpn:
        old_route = module.resources(plan["host"], old, plan["lan"], original_runtime["interface"])
    if new_vpn:
        profile = ensure_id(destination)
        state = vpn_tunnel_status(profile)
        if not state.get("connected") or not state.get("interface"):
            raise ValueError("Túnel WireGuard sem handshake recente")
        dns = str(ipaddress.IPv4Address(dns_ipv4))
        interface = state["interface"]
    else:
        if destination not in ("direct", "blocked"):
            raise ValueError("Destino inválido")
    try:
        if new_vpn:
            new_route, new_filter = module.stage(pid, plan, destination, interface, dns, True)
            # The guard is already in force before any change to routing.
            module.apply_filter(new_filter)
            if old_route:
                module.remove_rule(old_route)
            module.ensure_rule(new_route)
            observed = module.observed(plan["host"], plan["lan"])
            if observed.returncode or ("dev " + interface) not in observed.stdout:
                raise ValueError("Rota VPN efectiva não confirmada")
            plan["destination"] = destination
            current["vpn_runtime"] = {"interface": interface, "dns_ipv4": dns,
                                      "table": new_route["table"], "priority": new_route["priority"]}
        else:
            if destination == "direct":
                module.ensure_direct_nat(pid, plan)
            basic = module.load("vpngw-basic-transition-batch")
            batch = basic.batch(pid, plan, destination)
            run(NFT, "-c", "-f", "-", input_text=batch)
            run(NFT, "-f", "-", input_text=batch)
            if old_route:
                module.remove_rule(old_route)
            module.remove_guard(pid)
            plan["destination"] = destination
            current.pop("vpn_runtime", None)
        # Roll back unconfirmed VPN cutovers after 180 seconds, independent of
        # the browser and API process. The old destination is persisted first.
        if new_vpn and arm_timeout:
            current["vpn_pending"] = {"previous": old,
                                      "previous_dns": original_runtime.get("dns_ipv4"),
                                      "previous_provider": previous_provider,
                                      "deadline": time.time() + 180}
        else:
            current.pop("vpn_pending", None)
        save_state(pid, current)
        if new_vpn and arm_timeout:
            subprocess.run(["/usr/bin/systemctl", "stop", "vpngw-vpn-revert-" + pid + ".timer"],
                           capture_output=True)
            run("/usr/bin/systemd-run", "--quiet", "--unit=vpngw-vpn-revert-" + pid,
                "--on-active=180s", "/usr/bin/python3",
                os.path.abspath(__file__), "vpn-revert", pid)
        else:
            subprocess.run(["/usr/bin/systemctl", "stop", "vpngw-vpn-revert-" + pid + ".timer"],
                           capture_output=True)
        if old_route:
            module.remove_table(old_route)
        return {"status": "active", "destination": destination, "changed": True,
                "fail_closed": new_vpn, "confirmation_required": bool(new_vpn and arm_timeout),
                "deadline": current.get("vpn_pending", {}).get("deadline")}
    except Exception:
        # Restore previous state. On repeated failure, retain VPN guard and
        # unreachable routing rather than opening the main Internet route.
        if new_route:
            module.remove_rule(new_route)
        if old_vpn:
            old_iface = original_runtime["interface"]
            old_dns = original_runtime["dns_ipv4"]
            r, f = module.stage(pid, original_plan, old, old_iface, old_dns,
                                bool(vpn_tunnel_status(old).get("connected")))
            module.apply_filter(f)
            module.ensure_rule(r)
        elif not old_vpn:
            basic = module.load("vpngw-basic-transition-batch")
            run(NFT, "-f", "-", input_text=basic.batch(pid, original_plan, old))
            module.remove_guard(pid)
        if new_route:
            module.remove_table(new_route)
        save_state(pid, original)
        raise


def confirm_vpn(pid):
    state = read_state(pid)
    pending = state.get("vpn_pending") if state else None
    if not pending or time.time() >= pending["deadline"]:
        raise ValueError("Transição VPN pendente inexistente ou expirada")
    plan = state["plan"]
    observed_profile = plan["destination"]
    runtime = state.get("vpn_runtime") or {}
    if not vpn_tunnel_status(observed_profile).get("connected"):
        raise ValueError("WireGuard sem handshake recente")
    import importlib.util
    path = Path(__file__).with_name("vpngw-vpn-transaction.py")
    spec=importlib.util.spec_from_file_location("vpngw_vpn_transaction",path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    route=module.observed(plan["host"],plan["lan"])
    if route.returncode or "dev " + runtime.get("interface","(none)") not in route.stdout:
        raise ValueError("Rota VPN não confirmada")
    cancel = subprocess.run(["/usr/bin/systemctl","stop","vpngw-vpn-revert-"+pid+".timer"],
                            capture_output=True)
    if cancel.returncode:
        raise ValueError("Não foi possível cancelar a reversão automática")
    state.pop("vpn_pending",None)
    save_state(pid,state)
    return {"status":"active","destination":observed_profile,"confirmed":True}


def revert_unconfirmed_vpn(pid):
    with LOCK, file_lock():
        state = read_state(pid)
        pending = state.get("vpn_pending") if state else None
        if not pending:
            return {"changed":False}
        previous = pending["previous"]
        previous_dns = pending.get("previous_dns")
        previous_provider = pending.get("previous_provider")
        if previous_provider not in ("generic", "proton"):
            previous_provider = "generic"
        # This function is also invoked by an unattended systemd rollback and
        # during boot recovery, NOT only through the API. Always withdraw old
        # inbound mappings before changing the effective route.
        suspend_owned_forwarding(pid)
        try:
            result = vpn_transition(pid, previous, previous_dns, arm_timeout=False)
        except Exception:
            # If previous route recovery fails, block and withdraw all ingress.
            result = vpn_transition(pid, "blocked", arm_timeout=False)
            previous_provider = "generic"
        module = _port_reconciler()
        if module.load_owner(BASE) == pid:
            module.save_owner(BASE, pid, provider=previous_provider,
                              upnp_enabled=module.load_owner_upnp(BASE))
        reconcile_forwarding_owner()
        return result


def transition_basic(pid, target):
    """Switch existing DIRECT/BLOCKED rules atomically; retain per-host NAT."""
    import importlib.util
    if target not in ("direct", "blocked"):
        raise ValueError("Transição VPN requer executor isolado")
    state = read_state(pid)
    if not state or state.get("status") != "active":
        raise ValueError("Política activa inexistente")
    old = state["plan"]["destination"]
    if old not in ("direct", "blocked"):
        raise ValueError("Origem incompatível")
    if old == target:
        return {"status": "active", "destination": target, "changed": False}
    plan = state["plan"]
    validate_saved_plan(plan)
    if not plan.get("registered_mac") or not identity_guard_ok(pid, plan["registered_mac"]):
        raise ValueError("Identidade do host não protegida")
    if target == "direct":
        # After reboot, a BLOCKED policy may have its filter restored before
        # the DIRECT NAT table. Recreate only this policy's isolated NAT.
        import importlib.util
        source_nat = Path(__file__).with_name("vpngw-vpn-transaction.py")
        nat_spec = importlib.util.spec_from_file_location("vpngw_nat_recovery", source_nat)
        nat_module = importlib.util.module_from_spec(nat_spec)
        nat_spec.loader.exec_module(nat_module)
        nat_module.ensure_direct_nat(pid, plan)
        nat_name = "vpngw_" + chain_name(pid).lower()
        nat_output = run(NFT, "list", "table", "ip", nat_name).stdout
        if "masquerade" not in nat_output or (plan.get("shared") and "icmp type redirect" not in nat_output):
            raise ValueError("NAT DIRECT indisponível; alteração recusada")
    source = Path(__file__).with_name("vpngw-basic-transition-batch.py")
    spec = importlib.util.spec_from_file_location("vpngw_basic_transition", source)
    if spec is None or spec.loader is None:
        raise ValueError("Executor nft indisponível")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    new_batch = module.batch(pid, plan, target)
    old_batch = module.batch(pid, plan, old)
    run(NFT, "-c", "-f", "-", input_text=new_batch)
    run(NFT, "-f", "-", input_text=new_batch)
    try:
        observed = run(NFT, "list", "chain", "ip", "filter", chain_name(pid)).stdout
        if not identity_guard_ok(pid, plan["registered_mac"]):
            raise ValueError("Protecção MAC ausente")
        if target == "blocked" and not (len([line for line in observed.splitlines() if "counter packets" in line and " drop" in line]) >= 2 and " accept" not in observed):
            raise ValueError("Bloqueio não confirmado")
        if target == "direct" and not ("accept" in observed and "masquerade" in run(
                NFT, "list", "table", "ip", "vpngw_" + chain_name(pid).lower()).stdout):
            raise ValueError("DIRECT não confirmado")
        state["plan"]["destination"] = target
        save_state(pid, state)
    except Exception:
        # Conservative rollback; if recovery fails, drop host traffic rather than leak.
        try:
            run(NFT, "-f", "-", input_text=old_batch)
        except Exception:
            run(NFT, "-f", "-", input_text=module.batch(pid, plan, "blocked"))
        raise
    return {"status": "active", "destination": target, "changed": True}


def _port_reconciler():
    import importlib.util
    source = Path(__file__).with_name("vpngw-port-reconcile.py")
    spec = importlib.util.spec_from_file_location("vpngw_port_reconcile", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _direct_igd_reconcile(owner, mode):
    """Manage only owned upstream DIRECT mappings through verified miniupnpc."""
    state = read_state(owner)
    if not state or (state.get("plan") or {}).get("destination") != "direct":
        return {"available": False, "mapping_verified": False,
                "reason": "not_direct"}
    import importlib.util
    source = Path(__file__).with_name("vpngw-direct-upnp.py")
    spec = importlib.util.spec_from_file_location("vpngw_direct_upnp", source)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper.reconcile(owner=owner, state=state, mode=mode)


def reconcile_forwarding_owner():
    module = _port_reconciler()
    owner = None
    try:
        owner = module.load_owner(BASE)
        if owner:
            selected_state = read_state(owner) or {}
            selected_plan = selected_state.get("plan") or {}
            selected_mac = selected_plan.get("registered_mac")
            if selected_state.get("status") == "active" and selected_mac:
                # Upgrade active legacy rules before attesting any inbound
                # mapping; otherwise the same NIC could escape after DHCP.
                _set_kernel_identity_guard(owner, selected_mac, selected_plan)
        result = module.reconcile(owner, base=BASE, read_state=read_state,
                inspect_rules=inspect_rules, identity_guard_ok=identity_guard_ok,
                vpn_tunnel_status=vpn_tunnel_status, nft_path=NFT)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # Never leave the previous mapped-port observation marked as active
        # after a failed renewal or a malformed/missing provider lease.
        try:
            module.forward.apply(NFT, None, None)
            status = "reconcile_failed_rules_removed"
        except (OSError, ValueError, subprocess.SubprocessError):
            status = "reconcile_failed_cleanup_unverified"
        result = {"applied": False, "owner": owner, "status": status,
                  "external_ports": {}, "provider_lease": False}
    # Only selected DIRECT policy with verified internal DNAT may request
    # an upstream IGD mapping. A failure never turns into WAN fallback.
    if owner and module.load_owner_upnp(BASE):
        state = read_state(owner) or {}
        if (state.get("plan") or {}).get("destination") == "direct":
            try:
                mode = "apply" if result.get("applied") and result.get("route") == "direct" else "revoke"
                result["upnp"] = _direct_igd_reconcile(owner, mode)
            except (OSError, ValueError, KeyError, TypeError,
                    subprocess.SubprocessError) as exc:
                result["upnp"] = {"mapping_verified": False,
                                  "reason": "upstream_igd_unavailable",
                                  "detail": str(exc)[:180]}
    # Operator-visible last observation is not a guarantee of upstream reachability.
    record = {"updated_at": time.time(), **result}
    path = BASE / "port-forward" / "runtime.json"
    temp = BASE / "port-forward" / ".runtime.tmp"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp.write_text(json.dumps(record), encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)
    return record


def suspend_owned_forwarding(policy_id):
    """Remove and mark old DNAT invalid before any route switch."""
    module = _port_reconciler()
    if module.load_owner(BASE) == policy_id:
        # Capture the old provider lease BEFORE replacing the observed state;
        # otherwise generic providers could never revoke their old mapping.
        state_path = BASE / "port-forward" / "runtime.json"
        try:
            previous_runtime = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            previous_runtime = {}
        # Invalidate FIRST: a concurrent MediaHub poll must not act on a port
        # that belongs to the previous VPN route or to DIRECT.
        state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        stamp = state_path.with_name(".runtime.suspended")
        stamp.write_text(json.dumps({"updated_at": time.time(), "owner": policy_id,
            "status": "route_transition_suspended", "applied": False,
            "external_ports": {}, "provider_lease": False}), encoding="utf-8")
        os.chmod(stamp, 0o600)
        os.replace(stamp, state_path)
        module.forward.apply(NFT, None, None)
        if module.load_owner_upnp(BASE):
            try:
                _direct_igd_reconcile(policy_id, "revoke")
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                # Even if the physical router is unreachable, our internal
                # DNAT is already removed. Router leases expire separately.
                pass
        module.revoke_previous_lease(BASE, policy_id,
                                     previous_runtime=previous_runtime)


def host_rebind_preflight(pid):
    """Observe MAC/IP while the caller holds the policy transaction lock."""
    state = read_state(pid)
    if not state or state.get("status") != "active" or state.get("vpn_pending"):
        raise ValueError("A reatribuição exige uma política activa e confirmada")
    plan = state.get("plan") or {}
    lan = plan.get("lan")
    if not isinstance(lan, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", lan):
        raise ValueError("Interface LAN inválida")
    import importlib.util
    source = Path(__file__).with_name("vpngw-host-rebind.py")
    spec = importlib.util.spec_from_file_location("vpngw_rebind_preflight", source)
    preflight = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preflight)
    neighbors = json.loads(run(IP, "-j", "-4", "neigh", "show",
                               "dev", lan).stdout)
    addresses = json.loads(run(IP, "-j", "-4", "address", "show",
                               "dev", lan).stdout)
    occupied = set()
    for other_path in BASE.glob("*.json"):
        if other_path.stem == pid:
            continue
        other = json.loads(other_path.read_text(encoding="utf-8"))
        # Reserve even draft/error policy addresses; changing IP may
        # never silently capture another host's persisted identity.
        address = (other.get("plan") or {}).get("host")
        if address:
            occupied.add(address)
    return preflight.candidate_from_neighbors(
        plan, neighbors, addresses, occupied)


def dispatch(data):
    action = data.get("action")
    pid = ensure_id(data.get("id"))
    if action == "lan_discover":
        # Single global discovery; do not contend with policy transaction lock.
        if not DISCOVERY_LOCK.acquire(blocking=False):
            raise ValueError("LAN discovery already running")
        try:
            interfaces=data.get("interfaces")
            if not isinstance(interfaces,list) or not 1<=len(interfaces)<=4:
                raise ValueError("LAN interfaces missing")
            results=[]
            for interface in interfaces:
                if not isinstance(interface,str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}",interface):
                    raise ValueError("Invalid LAN interface")
                proc=subprocess.run(["/usr/bin/python3",
                    str(Path(__file__).with_name("lan-discovery.py")),
                    "--lan-interface",interface],capture_output=True,text=True,timeout=55)
                if proc.returncode:
                    raise ValueError("LAN scan failed: "+proc.stderr[-200:])
                results.append(json.loads(proc.stdout))
            return {"networks":results,"completed":True}
        finally:
            DISCOVERY_LOCK.release()
    with LOCK, file_lock():
        if action == "port_reconcile":
            module = _port_reconciler()
            selected = data.get("selected")
            if type(selected) is not bool:
                raise ValueError("Selected must be boolean")
            current = module.load_owner(BASE)
            if selected and current not in (None, pid):
                raise ValueError("Forwarding is reserved by another host")
            if not selected and current not in (None, pid):
                return {"applied": False, "owner": current, "unchanged": True}
            upnp_requested = data.get("upnp_enabled", False)
            if type(upnp_requested) is not bool:
                raise ValueError("UPnP selection must be boolean")
            upnp_revocation = None
            if current == pid and module.load_owner_upnp(BASE) and (
                    not selected or not upnp_requested):
                # Remove locally owned DNAT before revoking physical IGD.
                module.forward.apply(NFT, None, None)
                try:
                    upnp_revocation = _direct_igd_reconcile(pid, "revoke")
                except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                    upnp_revocation = {"mapping_verified": False,
                                       "reason": "revoke_unverified_router_lease_expires"}
            revocation = module.revoke_previous_lease(BASE, pid) if not selected and current == pid else None
            module.save_owner(BASE, pid if selected else None,
                              provider=data.get("provider", "generic"),
                              upnp_enabled=upnp_requested if selected else False)
            result = reconcile_forwarding_owner()
            if revocation is not None:
                result["lease_revocation"] = revocation
            if upnp_revocation is not None:
                result["upnp_revocation"] = upnp_revocation
            return result
        if action == "host_rebind_preflight":
            return host_rebind_preflight(pid)
        if action == "host_rebind_pending":
            import importlib.util
            source = Path(__file__).with_name("vpngw-host-rebind.py")
            spec = importlib.util.spec_from_file_location("vpngw_rebind_pending", source)
            pending_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(pending_module)
            pending = pending_module.read_pending(pid)
            return {"pending": pending is not None,
                    "previous_ip": pending["previous_ip"] if pending else None,
                    "candidate_ip": pending["candidate_ip"] if pending else None,
                    "mac": pending["mac"] if pending else None}
        if action in ("host_rebind_prepare", "host_rebind_commit"):
            # Both phases are exclusive across API workers and independent of
            # container lifecycle. Kernel is quarantined until SQLite commits.
            import importlib.util
            source = Path(__file__).with_name("vpngw-host-rebind-transaction.py")
            spec = importlib.util.spec_from_file_location("vpngw_rebind_transaction", source)
            rebind = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(rebind)
            mac = data.get("mac")
            new_ip = data.get("new_ip")
            if not isinstance(mac, str) or not re.fullmatch(
                    r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac.lower()):
                raise ValueError("MAC de reatribuição inválido")
            if not isinstance(new_ip, str):
                raise ValueError("IPv4 de reatribuição inválido")
            from types import SimpleNamespace
            runtime = SimpleNamespace(**globals())
            if action == "host_rebind_prepare":
                old_ip = data.get("old_ip")
                if not isinstance(old_ip, str):
                    raise ValueError("IPv4 anterior inválido")
                return rebind.prepare(runtime, pid,
                                      old_ip=old_ip, new_ip=new_ip, mac=mac.lower())
            return rebind.commit(runtime, pid,
                                 new_ip=new_ip, mac=mac.lower())
        if action == "port_owner":
            return {"owner": _port_reconciler().load_owner(BASE)}
        if action == "port_status":
            try:
                return json.loads((BASE / "port-forward" / "runtime.json").read_text())
            except (OSError, ValueError):
                return {"applied": False, "status": "not_verified"}
        if action in ("transition_basic", "vpn_transition"):
            previous_provider = _port_reconciler().load_owner_provider(BASE)
            previous_upnp = _port_reconciler().load_owner_upnp(BASE)
            suspend_owned_forwarding(pid)
            try:
                if action == "transition_basic":
                    result = transition_basic(pid, data.get("destination"))
                else:
                    result = vpn_transition(pid, data.get("destination"), data.get("dns_ipv4"),
                                            previous_provider=previous_provider)
                module = _port_reconciler()
                if module.load_owner(BASE) == pid:
                    # This applies to VPN->VPN, VPN->DIRECT/BLOCKED, DIRECT->VPN
                    # and DIRECT<->BLOCKED; never retain the old provider.
                    module.save_owner(BASE, pid, provider=data.get("provider", "generic"),
                                      upnp_enabled=previous_upnp)
                reconcile_forwarding_owner()
                return result
            except Exception:
                # The route transaction has its own rollback; only restore a
                # port once that effective route has been independently checked.
                module = _port_reconciler()
                if module.load_owner(BASE) == pid:
                    module.save_owner(BASE, pid, provider=previous_provider,
                                      upnp_enabled=previous_upnp)
                reconcile_forwarding_owner()
                raise
        if action == "vpn_confirm":
            return confirm_vpn(pid)
        if action == "vpn_revert":
            return revert_unconfirmed_vpn(pid)
        if action in ("openvpn_status","openvpn_import","openvpn_start","openvpn_stop","openvpn_probe","openvpn_backup_export","openvpn_backup_restore"):
            if not re.fullmatch(r"vpn-[a-z0-9][a-z0-9-]{1,27}", pid) or pid.endswith("-"):
                raise ValueError("Identificador OpenVPN inválido")
            payload={k:data.get(k) for k in ("id","action","configuration","username","password","files")}
            process=subprocess.run(["python3","/usr/local/libexec/vpngw-openvpn-agent.py"],
                                   input=json.dumps(payload),capture_output=True,text=True,timeout=25)
            if process.returncode:
                raise ValueError(process.stderr.strip() or "Falha do serviço OpenVPN")
            return json.loads(process.stdout)
        if action == "vpn_status":
            return wireguard_status(pid)
        if action == "vpn_probe":
            return wireguard_probe(pid)
        if action == "vpn_route_plan":
            return vpn_route_plan(data)
        if action == "vpn_transition_audit":
            return vpn_transition_audit(data)
        if action == "vpn_openvpn_preflight":
            import importlib.util
            source=Path(__file__).with_name("vpngw-vpn-route-plan.py")
            spec=importlib.util.spec_from_file_location("vpn_route_plan",source)
            module=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            profile=ensure_id(data.get("profile_id"))
            status_action="openvpn_status" if profile.startswith("vpn-") and subprocess.run(
                [IP,"link","show","dev","tun"+hashlib.sha256(profile.encode()).hexdigest()[:10]],
                capture_output=True,timeout=5).returncode == 0 else "vpn_status"
            if status_action == "openvpn_status":
                if not re.fullmatch(r"vpn-[a-z0-9][a-z0-9-]{1,27}",profile):
                    raise ValueError("Perfil OpenVPN inválido")
                helper=subprocess.run(["python3","/usr/local/libexec/vpngw-openvpn-agent.py"],
                    input=json.dumps({"id":profile,"action":"openvpn_status"}),
                    capture_output=True,text=True,timeout=20)
                if helper.returncode:
                    raise ValueError("Falha ao verificar interface OpenVPN")
                state=json.loads(helper.stdout)
            else:
                state=wireguard_status(profile)
            current=read_state(ensure_id(data.get("id")))
            if not current or current.get("status")!="active" or current.get("plan",{}).get("destination")!="direct":
                raise ValueError("A pré-validação exige política DIRECT activa")
            plan=current["plan"]
            validate_saved_plan(plan)
            interface=state.get("interface_name") or state.get("interface")
            if not interface:
                return {"ready":False,"reason":"VPN desligada","network_changes":False}
            proposal=module.build_plan(plan["host"],plan["gateway"],plan["lan"],interface,
                profile,"direct",bool(state.get("connected")),False,False)
            table=str(proposal["routing"]["table_id"])
            priority=str(proposal["routing"]["priority"])+":"
            rule_occupied=any(line.lstrip().startswith(priority) for line in run(IP,"-4","rule","show").stdout.splitlines())
            table_probe=subprocess.run([IP,"-4","route","show","table",table],capture_output=True,text=True,timeout=5)
            if table_probe.returncode not in (0,2):
                raise ValueError("Falha ao consultar a tabela de encaminhamento")
            table_occupied=bool(table_probe.stdout.strip())
            return {"ready":False,"network_changes":False,"connected":bool(state.get("connected")),
                "interface":interface,"host":plan["host"],"route_table":int(table),
                "priority":proposal["routing"]["priority"],
                "policy_rule_available":not rule_occupied,
                "route_table_available":not table_occupied,
                "blockers":proposal["blockers"] +
                    (["Prioridade de encaminhamento ocupada"] if rule_occupied else []) +
                    (["Tabela de encaminhamento ocupada"] if table_occupied else [])}
        if action == "vpn_trial_status":
            state = read_state(pid) or {}
            plan = state.get("plan") or {}
            if not plan.get("host") or not plan.get("lan"):
                return {"active": False}
            rules = run(IP, "-4", "rule", "show").stdout
            pattern = re.compile(r"^\d+:\s+from " + re.escape(plan["host"]) + r"(?:/32)? iif " + re.escape(plan["lan"]) + r" lookup (\d+)\s*$")
            tables = [m.group(1) for line in rules.splitlines() if (m := pattern.match(line.strip()))]
            for table in tables:
                route = subprocess.run([IP, "-4", "route", "get", "1.1.1.1", "from", plan["host"], "iif", plan["lan"]], capture_output=True, text=True, timeout=5)
                iface = wireguard_iface(ensure_id(data.get("profile_id")))
                if route.returncode == 0 and re.search(r"\bdev " + re.escape(iface) + r"\b", route.stdout):
                    return {"active": True, "interface": iface, "host": plan["host"], "table": int(table), "temporary": True}
            return {"active": False}
        if action == "vpn_connect":
            result = wireguard_connect(pid, data.get("configuration"))
            # A deleted WG interface removes its kernel routes. Re-establish
            # host routes without exposing a DIRECT fallback after reconnect.
            import importlib.util
            source = Path(__file__).with_name("vpngw-vpn-transaction.py")
            spec = importlib.util.spec_from_file_location("vpngw_reconnect_routes", source)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for state_path in BASE.glob("*.json"):
                state = json.loads(state_path.read_text())
                if state.get("status") != "active" or state.get("plan", {}).get("destination") != pid:
                    continue
                runtime = state.get("vpn_runtime") or {}
                interface = wireguard_iface(pid)
                if runtime.get("interface") != interface or not runtime.get("dns_ipv4"):
                    raise ValueError("VPN religada, dados de recuperação incompletos; tráfego permanece bloqueado")
                route, filt = module.stage(state_path.stem, state["plan"], pid,
                                           interface, runtime["dns_ipv4"], True)
                module.apply_filter(filt)
                module.ensure_rule(route)
                if state["plan"].get("registered_mac"):
                    _set_kernel_identity_guard(
                        pid, state["plan"]["registered_mac"], state["plan"])
                probe = module.observed(state["plan"]["host"], state["plan"]["lan"])
                if probe.returncode or ("dev " + interface) not in probe.stdout:
                    raise ValueError("VPN religada, encaminhamento do host não recuperado")
            return result
        if action == "vpn_disconnect":
            return wireguard_disconnect(pid)
        if action == "identity_update":
            mac = str(data.get("registered_mac") or "").lower()
            if data.get("host_ip") != (read_state(pid) or {}).get("plan",{}).get("host"):
                raise ValueError("Identidade/IP incompatíveis")
            return set_identity_guard(pid, mac)
        if action == "diagnose_host":
            state = read_state(pid)
            if not state or not state.get("plan"):
                return {"status":"not_configured","route_verified":False,"firewall_verified":False}
            plan=state["plan"]
            ip=plan["host"]
            command=[IP,"-4","route","get","1.1.1.1","from",ip,"iif",plan["lan"]]
            route=subprocess.run(command,capture_output=True,text=True,timeout=5)
            runtime=state.get("vpn_runtime") or {}
            iface=runtime.get("interface")
            expected=plan.get("destination")
            observed=route.stdout.strip() if route.returncode==0 else route.stderr.strip()
            route_ok=(("dev "+iface) in observed if iface and expected not in ("direct","blocked")
                      else route.returncode!=0 if expected=="blocked"
                      else route.returncode==0 and "dev "+plan["wan"] in observed)
            guard_name="vpngw_"+chain_name(pid).lower()
            guard=subprocess.run([NFT,"list","table","inet", "vpngw_vpn_"+__import__("hashlib").sha256(pid.encode()).hexdigest()[:12]],capture_output=True,text=True)
            return {"status":state.get("status"),"expected":expected,"route_verified":route_ok,
                    "observed_route":observed,"firewall_verified":inspect_rules(pid),
                    "mac_guard_verified":identity_guard_ok(pid,plan.get("registered_mac") or "") if plan.get("registered_mac") else False,
                    "vpn_guard_present":guard.returncode==0 if iface else None,
                    "ipv6":"unsupported_blocked_by_policy","dns":"rules_configured_not_client_leak_proof"}
        if action == "maintenance_inventory":
            records=[]
            for state_file in sorted(BASE.glob('*.json')):
                identifier=state_file.stem
                if not re.fullmatch(r'[a-z][a-z0-9-]{1,31}', identifier):
                    raise ValueError('Estado desconhecido: '+identifier)
                state=read_state(identifier) or {}
                records.append({'id':identifier,'status':state.get('status','unknown'),
                                'applied':bool(state.get('applied')),'rules_present':bool(inspect_rules(identifier))})
            return {'policies':records}
        if action == "status":
            state = read_state(pid)
            expected = str(data.get("registered_mac") or "").lower()
            if state and expected and state.get("status") in ("active", "pending"):
                plan = state.get("plan") or {}
                try:
                    neigh = json.loads(run(IP, "-j", "neigh", "show", plan["host"], "dev", plan["lan"]).stdout)
                    observed = next((str(x.get("lladdr")).lower() for x in neigh if x.get("lladdr")), None)
                except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                    observed = None
                identity = ("unauthorized" if observed and observed != expected
                            else "authorized" if observed == expected and identity_guard_ok(pid,expected)
                            else "unverified")
                state = {**state, "authorization_status":identity, "observed_mac":observed,
                         "identity_guard_verified":identity_guard_ok(pid,expected)}

            if state and state["status"] in ("pending", "active") and not inspect_rules(pid):
                return {"status": "error", "applied": False, "reason": "Regras não encontradas"}
            if state and state.get("status") in ("pending", "active"):
                return {**state, "counters": read_counters(pid, state)}
            return state or {"status": "draft", "applied": False}
        if action == "preflight":
            return {"status": "validated", "plan": validate(data["host_ip"], data["destination"], data["network"])}
        if action == "purge_host":
            # Remove any owned DNAT before deleting a host's authoritative state.
            port_module = _port_reconciler()
            if port_module.load_owner(BASE) == pid:
                port_module.revoke_previous_lease(BASE, pid)
                port_module.save_owner(BASE, None)
                reconcile_forwarding_owner()
            # Called only after the API has fully revoked the host policy.
            state = read_state(pid)
            if state and state.get("status") in ("active", "pending"):
                raise ValueError("Host policy still active; purge refused")
            if inspect_rules(pid):
                raise ValueError("Host filter remains; purge refused")
            import importlib.util
            source = Path(__file__).with_name("vpngw-vpn-transaction.py")
            spec = importlib.util.spec_from_file_location("vpngw_purge", source)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.remove_guard(pid)
            cancel_rollback(pid)
            subprocess.run(["/usr/bin/systemctl", "stop", "vpngw-vpn-revert-" + pid + ".timer"],
                           capture_output=True)
            removed_state_file = BASE / (ensure_id(pid) + ".json")
            sync_boot_policy(pid, None)
            removed_state_file.unlink(missing_ok=True)
            if removed_state_file.exists() or inspect_rules(pid):
                raise ValueError("Host state not fully purged")
            return {"purged": True}
        if action == "rollback":
            suspend_owned_forwarding(pid)
            result = rollback(pid, force=True)
            reconcile_forwarding_owner()
            return result
        if action == "confirm":
            state = read_state(pid)
            if not state or state["status"] != "pending" or time.time() >= state["deadline"]:
                raise ValueError("Aplicação pendente inexistente ou expirada")
            if not inspect_rules(pid):
                raise ValueError("Regras de encaminhamento desaparecidas")
            cancel_rollback(pid)
            state["status"] = "active"
            state["deadline"] = None
            save_state(pid, state)
            return state
        if action != "apply":
            raise ValueError("Operação desconhecida")
        if not exists_chain("DOCKER-USER"):
            raise ValueError("Encaminhamento Docker não encontrado")
        state = read_state(pid)
        if state and state["status"] in ("active", "pending"):
            raise ValueError("Reverta primeiro a política activa")
        plan = validate(data["host_ip"], data["destination"], data["network"])
        mac = data.get("registered_mac")
        if mac:
            mac = str(mac).lower()
            if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                raise ValueError("MAC inválido")
        plan["registered_mac"] = mac
        deadline = time.time() + 180
        save_state(pid, {"status": "pending", "applied": False, "deadline": deadline, "plan": plan})
        try:
            schedule_rollback(pid)
            install_rules(plan, pid)
            if not inspect_rules(pid):
                raise ValueError("Não foi possível verificar as regras instaladas")
        except Exception:
            rollback(pid)
            raise
        result = {"status": "pending", "applied": True, "deadline": deadline, "plan": plan}
        save_state(pid, result)
        return result


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            raw = self.rfile.readline(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("Pedido demasiado grande")
            data = json.loads(raw)
            if not hmac.compare_digest(str(data.pop("token", "")), Path(TOKEN).read_text().strip()):
                raise ValueError("Sem autorização")
            result = {"ok": True, "result": dispatch(data)}
        except Exception as error:
            result = {"ok": False, "error": str(error)}
        self.wfile.write((json.dumps(result) + "\n").encode())


def reconcile_returned_vpn_routes():
    """Restore routes lost when a confirmed tunnel disappears and returns."""
    with LOCK, file_lock():
        for path in BASE.glob("*.json"):
            try:
                state = json.loads(path.read_text())
                plan = state.get("plan", {})
                target = plan.get("destination")
                runtime = state.get("vpn_runtime") or {}
                interface = runtime.get("interface")
                reason = str(state.get("reason") or "")
                retryable = (
                    state.get("status") == "error"
                    and reason in (
                        "Recuperação após reinício falhou: Interface WAN/LAN mudou desde a confirmação",
                        "Recuperação após reinício falhou: Docker forwarding indisponível",
                    )
                )
                if ((state.get("status") != "active" and not retryable)
                        or state.get("vpn_pending")
                        or not target or target in ("direct", "blocked") or not interface):
                    continue
                route = subprocess.run(
                    [IP, "-j", "-4", "route", "get", "1.1.1.1", "from", plan["host"], "iif", plan["lan"]],
                    capture_output=True, text=True, timeout=5)
                if (not retryable and route.returncode == 0 and any(
                        item.get("dev") == interface for item in json.loads(route.stdout))):
                    continue
                # Do not reconnect an intentionally stopped profile or remove its guard.
                observed = vpn_tunnel_status(target)
                if observed.get("connected") and observed.get("interface") == interface:
                    recover_active_policy(path.stem, state)
            except Exception:
                # A failed observation must never relax a client's existing guard.
                continue


def reconcile_missing_wireguard_profiles():
    """Reconnect assigned WireGuard profiles after unexpected interface loss.

    Never override an explicit Disconnect, a pending cutover or an OpenVPN
    profile; the host's unreachable route and nft guard remain installed.
    """
    root_name = os.environ.get("VPNGW_WG_PROFILE_DIR")
    if not root_name:
        return
    root = Path(root_name)
    if root.is_symlink() or not root.is_dir():
        return
    with LOCK, file_lock():
        targets = set()
        for path in BASE.glob("*.json"):
            try:
                state = json.loads(path.read_text())
                plan = state.get("plan") or {}
                profile = plan.get("destination")
                runtime = state.get("vpn_runtime") or {}
                if (state.get("status") != "active" or state.get("vpn_pending")
                        or not profile or profile in ("direct", "blocked")):
                    continue
                profile = ensure_id(profile)
                if (runtime.get("interface") != wireguard_iface(profile)
                        or wireguard_paused_path(profile).exists()):
                    continue
                targets.add(profile)
            except (OSError, ValueError, TypeError):
                continue
        for profile in sorted(targets):
            try:
                if wireguard_status(profile).get("interface"):
                    WG_RETRY_AFTER.pop(profile, None)
                    continue
                now = time.monotonic()
                if now < WG_RETRY_AFTER.get(profile, 0):
                    continue
                WG_RETRY_AFTER[profile] = now + 30
                config = root / (profile + ".conf")
                if (not config.is_file() or config.is_symlink()
                        or not 0 < config.stat().st_size <= 65536):
                    continue
                wireguard_connect(profile, config.read_text(encoding="utf-8"))
                # Route restoration is handled by the existing periodic
                # reconciler, after the recreated tunnel becomes observable.
            except (OSError, ValueError, subprocess.SubprocessError):
                continue


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    _next_reconcile = 0.0
    _next_port_reconcile = 0.0

    def service_actions(self):
        now = time.monotonic()
        if now >= self._next_reconcile:
            self._next_reconcile = now + 5
            reconcile_missing_wireguard_profiles()
            reconcile_returned_vpn_routes()
        if now >= self._next_port_reconcile:
            self._next_port_reconcile = now + 45
            def refresh_forward():
                with LOCK, file_lock():
                    try:
                        reconcile_forwarding_owner()
                    except (OSError, ValueError, subprocess.SubprocessError):
                        # Never install fallback rules on a failed VPN probe.
                        pass
            threading.Thread(target=refresh_forward, daemon=True,
                             name="vpngw-port-forward-reconcile").start()


def validate_saved_plan(plan):
    """Never reuse confirmed routes on boot if their interfaces/gateway changed."""
    host = ipaddress.ip_address(plan["host"])
    lan, wan = plan["lan"], plan["wan"]
    links, routes = topology()
    active = {i["ifname"]: i for i in links if i.get("operstate") == "UP"}
    if lan not in active or wan not in active:
        raise ValueError("Interface WAN/LAN mudou desde a confirmação")
    if not any(host in ipaddress.ip_interface(a["local"] + "/" + str(a["prefixlen"])).network
               for a in active[lan].get("addr_info", []) if a.get("family") == "inet"):
        raise ValueError("Host deixou de pertencer à LAN confirmada")
    if plan["destination"] == "direct":
        if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "1":
            raise ValueError("IPv4 forwarding desactivado após reinício")
        matching = [r for r in routes if r.get("dev") == wan and r.get("gateway") == plan.get("gateway")]
        if len(matching) != 1:
            raise ValueError("Gateway WAN alterado desde a confirmação")
    if not exists_chain("DOCKER-USER"):
        raise ValueError("Docker forwarding indisponível")


def complete_recovered_vpn_policy(pid, state):
    """Only restore an eligible error state after verified VPN route recovery."""
    if state.get("status") == "error":
        restored = {**state, "status": "active", "applied": True}
        restored.pop("reason", None)
        sync_boot_policy(pid, restored)
        save_state(pid, restored)
    else:
        sync_boot_policy(pid, state)


def recover_active_policy(pid, state):
    with LOCK, file_lock():
        try:
            validate_saved_plan(state["plan"])
            target = state["plan"]["destination"]
            if target not in ("direct", "blocked"):
                import importlib.util
                source = Path(__file__).with_name("vpngw-vpn-transaction.py")
                spec = importlib.util.spec_from_file_location("vpngw_vpn_transaction", source)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                runtime = state.get("vpn_runtime") or {}
                interface = runtime.get("interface")
                if not interface or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface) or not runtime.get("dns_ipv4"):
                    raise ValueError("Configuração de recuperação VPN incompleta")
                expected_wg = wireguard_iface(target)
                expected_ovpn = "tun" + hashlib.sha256(target.encode()).hexdigest()[:10]
                if interface not in (expected_wg, expected_ovpn):
                    raise ValueError("Interface VPN não corresponde ao perfil")
                # The route must remain unreachable when a tunnel is absent.
                observed_tunnel = vpn_tunnel_status(target)
                tunnel_present = bool(observed_tunnel.get("interface") == interface)
                if not exists_chain(chain_name(pid)):
                    bootstrap = {**state["plan"], "destination": "blocked"}
                    install_rules(bootstrap, pid)
                route, filt = module.stage(pid, state["plan"], target, interface,
                                           runtime["dns_ipv4"], tunnel_present)
                module.apply_filter(filt)
                module.ensure_rule(route)
                probe = module.observed(state["plan"]["host"], state["plan"]["lan"])
                if tunnel_present and (probe.returncode or "dev " + interface not in probe.stdout):
                    raise ValueError("Recuperação VPN sem rota efectiva")
                if not tunnel_present and probe.returncode == 0:
                    raise ValueError("VPN desligada mas rota DIRECT acessível")
                complete_recovered_vpn_policy(pid, state)
                return
            mac = state["plan"].get("registered_mac")
            if not inspect_rules(pid) or not identity_guard_ok(pid, mac):
                remove_rules(pid)
                install_rules(state["plan"], pid)
            if mac:
                _set_kernel_identity_guard(pid, mac, state["plan"])
            # A healthy blocked chain can survive an agent restart while the
            # management exception and its host route have disappeared.
            ensure_blocked_management(pid, state["plan"])
            if (not inspect_rules(pid) or not identity_guard_ok(pid, mac)
                    or (mac and not renumber_guard_ok(pid, mac, state["plan"]))):
                raise ValueError("Regras IP/MAC não confirmadas após reposição")
        except Exception as exc:
            # Never remove a surviving VPN guard on recovery failure.
            if state["plan"]["destination"] in ("direct", "blocked"):
                remove_rules(pid)
            save_state(pid, {**state, "status": "error", "applied": False,
                             "reason": "Recuperação após reinício falhou: " + str(exc)})


def restore_boot_vpn_profiles():
    """Reconnect only VPN profiles actually assigned to persistent host policies."""
    base = os.environ.get("VPNGW_WG_PROFILE_DIR")
    if not base:
        return
    root = Path(base)
    if root.is_symlink():
        return
    profiles = set()
    for path in BASE.glob("*.json"):
        try:
            state = json.loads(path.read_text())
            dest = state.get("plan", {}).get("destination")
            if state.get("status") == "active" and dest not in ("direct", "blocked"):
                profile = ensure_id(dest)
                if not wireguard_paused_path(profile).exists():
                    profiles.add(profile)
        except (ValueError, OSError):
            continue
    for profile in sorted(profiles):
        try:
            present = bool(vpn_tunnel_status(profile).get("interface"))
            if not present:
                configuration = root / (profile + ".conf")
                ovpn_configuration = Path("/etc/openvpn/client") / (profile + ".conf")
                if configuration.is_file() and not configuration.is_symlink() and configuration.stat().st_size <= 65536:
                    wireguard_connect(profile, configuration.read_text(encoding="utf-8"))
                elif ovpn_configuration.is_file() and not ovpn_configuration.is_symlink():
                    subprocess.run(["/usr/bin/systemctl","start","openvpn-client@"+profile+".service"],
                                   check=True,timeout=25)
                else:
                    continue
            # A tunnel service can reach "active" before the tun interface exists.
            # Reconcile after the interface appears, even if it was already started.
            for attempt in range(40):
                if vpn_tunnel_status(profile).get("interface"):
                    break
                time.sleep(0.5)
            for path in BASE.glob("*.json"):
                state=json.loads(path.read_text())
                if state.get("status") == "active" and state.get("plan",{}).get("destination") == profile:
                    recover_active_policy(path.stem,state)
        except Exception:
            # Existing host routing remains fail-closed on any tunnel failure.
            continue


def reconcile_management_loop(interval=60):
    """Reconcile blocked-client HTTPS on Docker proxy IP changes.

    A container recreate can change the Docker bridge destination without
    restarting the policy agent. Rules are exact; no general allowlist is used.
    """
    while True:
        time.sleep(interval)
        try:
            with LOCK, file_lock():
                for path in BASE.glob("*.json"):
                    record = json.loads(path.read_text())
                    if record.get("status") == "active":
                        ensure_blocked_management(path.stem, record.get("plan") or {})
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            print("blocked management reconcile failed: " + str(exc), flush=True)


def serve():
    directory = Path(SOCKET).parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.path.exists(SOCKET):
        os.unlink(SOCKET)
    # Crash recovery: pending policies must not outlive the agent restart.
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    for file in BASE.glob("*.json"):
        record = json.loads(file.read_text())
        if record.get("status") == "pending":
            rollback(file.stem)
        elif record.get("status") == "active":
            recover_active_policy(file.stem, record)
    # A pending VPN cutover must never become permanent merely due to reboot.
    for path in BASE.glob("*.json"):
        state=json.loads(path.read_text())
        if state.get("status")=="active" and state.get("vpn_pending"):
            revert_unconfirmed_vpn(path.stem)
    # A crashed NAT-PMP probe may have left a temporary /32 host route.
    # Remove only routes journalled by this controller before recovering policies.
    try:
        _port_reconciler().natpmp.cleanup_stale_route()
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    restore_boot_vpn_profiles()
    # Boot-time forwarding is rebuilt only from the saved owner and verified route.
    with LOCK, file_lock():
        try:
            reconcile_forwarding_owner()
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    threading.Thread(target=reconcile_management_loop, daemon=True).start()
    with Server(SOCKET, Handler) as server:
        os.chmod(SOCKET, 0o600)
        server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["serve", "rollback", "vpn-revert"])
    parser.add_argument("id", nargs="?")
    args = parser.parse_args()
    if args.action == "serve":
        serve()
    elif args.action == "vpn-revert":
        revert_unconfirmed_vpn(ensure_id(args.id))
    else:
        rollback(ensure_id(args.id))
