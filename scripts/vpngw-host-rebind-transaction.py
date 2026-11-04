#!/usr/bin/env python3
"""Two-phase selected-host IPv4 cutover, exclusively under policy-agent lock.

Phase 1: durable MAC+old/new-IP quarantine, withdrawal of incoming NAT,
replacement of per-host rules/routes, verified persistent agent state.
Phase 2: API commits SQLite and explicitly authorises release. No data-plane
access is permitted between phases, including after an unexpected reboot.
A failed cutover remains quarantined until recovered; it NEVER falls back
to the physical WAN merely because a provider tunnel is unavailable.
"""
from __future__ import annotations
import copy
import importlib.util
import ipaddress
from pathlib import Path


def _load(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = _load("vpngw-host-rebind.py", "vpngw_host_rebind_runtime")
transaction = _load("vpngw-vpn-transaction.py", "vpngw_vpn_transaction_rebind")


def _check_tuple(original: dict, *, old_ip: str, new_ip: str, mac: str):
    plan = original.get("plan") or {}
    if original.get("status") != "active" or original.get("vpn_pending"):
        raise ValueError("Only confirmed active policies may be rebound")
    if str(plan.get("registered_mac") or "").lower() != mac.lower():
        raise ValueError("Registered owner MAC changed")
    if plan.get("host") != old_ip:
        raise ValueError("Outdated original host IP")
    candidate = str(ipaddress.IPv4Address(new_ip))
    if not ipaddress.IPv4Address(candidate).is_private or candidate == old_ip:
        raise ValueError("Invalid new private host IP")
    return plan, candidate


def prepare(agent, pid: str, *, old_ip: str, new_ip: str, mac: str):
    """All kernel mutations are protected by a persistent drop-all quarantine."""
    pending = helper.read_pending(pid)
    resuming = pending is not None
    if resuming:
        if not (pending["previous_ip"] == old_ip and
                pending["candidate_ip"] == new_ip and pending["mac"] == mac.lower()):
            raise ValueError("Conflicting rebind journal; host remains quarantined")
        helper.ensure_quarantine(pending)
        state = agent.read_state(pid) or {}
        if state.get("plan", {}).get("host") == new_ip and state.get("status") == "active":
            return {"prepared": True, "new_ip": new_ip, "pending_commit": True}
        if state.get("plan", {}).get("host") != old_ip:
            raise ValueError("Incomplete rebind has unknown persistent state")
    original = agent.read_state(pid)
    if not isinstance(original, dict):
        raise ValueError("Missing confirmed host state")
    plan, new_ip = _check_tuple(original, old_ip=old_ip, new_ip=new_ip, mac=mac)
    agent.validate_saved_plan(plan)
    verified = agent.host_rebind_preflight(pid)
    if verified.get("previous_ip") != old_ip or verified.get("candidate_ip") != new_ip:
        raise ValueError("MAC/IP neighbor observation changed during the cutover")
    if verified.get("registered_mac") != mac.lower() or not verified.get("changed"):
        raise ValueError("Host ownership not freshly verified")
    # A resumed crash may have already removed the old host chain. The
    # independently verified quarantine remains the effective safety gate.
    if not resuming and (not agent.identity_guard_ok(pid, mac)
                         or not agent.renumber_guard_ok(pid, mac, plan)):
        raise ValueError("Pre-existing MAC fail-closed guards not verified")
    record = {"pid": pid, "mac": mac.lower(), "lan": plan["lan"],
              "previous_ip": old_ip, "candidate_ip": new_ip,
              "route": plan["destination"]}
    # Persist FIRST so an interruption before/within nft writes can be
    # quarantined by the early-boot unit after a power failure.
    if not resuming:
        helper.write_pending(record)
    helper.ensure_quarantine(record)
    agent.suspend_owned_forwarding(pid)
    target = plan["destination"]
    next_plan = {**plan, "host": new_ip}
    next_state = copy.deepcopy(original)
    next_state["plan"] = next_plan
    old_route = None
    new_route = None
    try:
        agent.remove_rules(pid)
        if target in ("direct", "blocked"):
            agent.install_rules(next_plan, pid)
        else:
            runtime = original.get("vpn_runtime") or {}
            iface = runtime.get("interface")
            dns = runtime.get("dns_ipv4")
            tunnel = agent.vpn_tunnel_status(target)
            if not iface or not dns or not tunnel.get("connected") or tunnel.get("interface") != iface:
                raise ValueError("VPN unavailable; the host remains quarantined")
            # Install a policy-specific BLOCKED base before staging the new
            # VPN route, guard and filter. Nothing opens while quarantine holds.
            agent.install_rules({**next_plan, "destination": "blocked"}, pid)
            old_route = transaction.resources(old_ip, target, plan["lan"], iface)
            new_route = transaction.resources(new_ip, target, plan["lan"], iface)
            if (old_route["priority"] == new_route["priority"]
                    or old_route["table"] == new_route["table"]):
                raise ValueError("VPN routing table or priority collision")
            # Never stage into a routing table or preference owned by another
            # host. A previous interrupted attempt may have installed only
            # this exact new-IP policy rule, but no foreign owner is accepted.
            rules = agent.run(agent.IP, "-4", "rule", "show").stdout.splitlines()
            import re
            for line in rules:
                pref = re.match(r"^\s*(\d+):", line)
                lookup = re.search(r"\blookup\s+(\d+)\b", line)
                uses_priority = bool(pref and int(pref.group(1)) == new_route["priority"])
                uses_table = bool(lookup and int(lookup.group(1)) == new_route["table"])
                if (uses_priority or uses_table) and not (
                        resuming and "from " + new_ip + "/32" in line
                        and "iif " + plan["lan"] in line
                        and uses_priority and uses_table):
                    raise ValueError("New VPN route collides with existing policy")
            table_state = transaction.argv_run(
                [agent.IP, "-4", "route", "show", "table", str(new_route["table"])],
                verify=False)
            if table_state.returncode not in (0, 2):
                raise ValueError("Cannot inspect proposed VPN route table")
            if table_state.returncode == 2 and (
                    "FIB table does not exist" not in table_state.stderr):
                raise ValueError("Unexpected VPN route table inspection error")
            if table_state.returncode == 0 and table_state.stdout.strip():
                # A previous journalled cutover may already have staged this
                # exact VPN route. A fresh attempt must not reuse any table.
                if not resuming or any(
                        "dev " + iface not in row and
                        not row.strip().startswith("unreachable default")
                        for row in table_state.stdout.splitlines()):
                    raise ValueError("Proposed VPN route table is occupied")
            staged, filt = transaction.stage(pid, next_plan, target, iface, dns, True)
            transaction.apply_filter(filt)
            transaction.ensure_rule(staged)
            observed = transaction.observed(new_ip, plan["lan"])
            if observed.returncode or ("dev " + iface) not in observed.stdout:
                raise ValueError("New host VPN route was not verified")
            transaction.remove_rule(old_route)
            remaining = agent.run(agent.IP, "-4", "rule", "show").stdout
            if any("from " + old_ip + "/32" in line
                   and "lookup " + str(old_route["table"]) in line
                   for line in remaining.splitlines()):
                raise ValueError("Old host VPN route remains active")
        # save_state also validates/updates the per-MAC persistent boot guard.
        agent.save_state(pid, next_state)
        agent._set_kernel_identity_guard(pid, mac.lower(), next_plan)
        if old_route:
            transaction.remove_table(old_route)
        if not agent.inspect_rules(pid) or not agent.renumber_guard_ok(pid, mac, next_plan):
            raise ValueError("Rebound policy guard failed verification")
        return {"prepared": True, "new_ip": new_ip, "pending_commit": True,
                "fail_closed": True}
    except Exception:
        # Deliberately retain the journal AND quarantine. Replaying the old
        # source IP would be unsafe once DHCP has assigned it elsewhere.
        raise


def commit(agent, pid: str, *, new_ip: str, mac: str):
    """Called ONLY after the API persisted its SQLite policy IP."""
    pending = helper.read_pending(pid)
    if (not pending or pending["candidate_ip"] != new_ip
            or pending["mac"] != mac.lower()):
        raise ValueError("No matching pending, authenticated host rebind")
    helper.ensure_quarantine(pending)
    state = agent.read_state(pid) or {}
    plan = state.get("plan") or {}
    if (state.get("status") != "active" or state.get("vpn_pending")
            or plan.get("host") != new_ip
            or plan.get("registered_mac") != mac.lower()
            or plan.get("lan") != pending["lan"]):
        raise ValueError("Persistent policy is not ready to be committed")
    observed = agent.host_rebind_preflight(pid)
    if (observed.get("candidate_ip") != new_ip
            or observed.get("registered_mac") != mac.lower()
            or not observed.get("verified_neighbor")):
        raise ValueError("Host MAC/IP binding is no longer confirmed")
    if (not agent.inspect_rules(pid) or not agent.identity_guard_ok(pid, mac)
            or not agent.renumber_guard_ok(pid, mac, plan)):
        raise ValueError("MAC identity, forwarding and policy rules not verified")
    route = plan["destination"]
    if route not in ("direct", "blocked"):
        runtime = state.get("vpn_runtime") or {}
        iface = runtime.get("interface")
        tunnel = agent.vpn_tunnel_status(route)
        if not iface or not tunnel.get("connected") or tunnel.get("interface") != iface:
            raise ValueError("VPN disconnected; quarantine must remain active")
        probe = transaction.observed(new_ip, plan["lan"])
        if probe.returncode or "dev " + iface not in probe.stdout:
            raise ValueError("VPN route not confirmed")
    elif route == "blocked":
        rules = agent.run(agent.NFT, "list", "chain", "ip", "filter",
                          agent.chain_name(pid)).stdout
        if not any("ip saddr " + new_ip in line and "drop" in line
                   for line in rules.splitlines()):
            raise ValueError("BLOCKED policy has no verified drop rule")
    else:
        observed_route = agent.run(agent.IP, "-4", "route", "get", "1.1.1.1",
                                   "from", new_ip, "iif", plan["lan"]).stdout
        if "dev " + plan["wan"] not in observed_route:
            raise ValueError("Direct route not verified")
    # The OS route and persisted rules were checked with the quarantine on.
    helper.release_quarantine(pid)
    agent.reconcile_forwarding_owner()
    return {"committed": True, "host_ip": new_ip, "fail_closed": route != "direct"}
