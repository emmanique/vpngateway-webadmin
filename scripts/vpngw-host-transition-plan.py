#!/usr/bin/env python3
"""Pure host-scoped bidirectional transition planner. Does not change networking."""
import ipaddress
import json
import re

def plan_transition(host, current, target, profiles, active_hosts):
    ipaddress.IPv4Address(host)
    if not isinstance(profiles,dict):
        raise ValueError("Invalid profile registry")
    if not isinstance(active_hosts,list) or any(not isinstance(x,dict) for x in active_hosts):
        raise ValueError("Invalid policy registry")
    endpoints = {"direct","blocked"} | set(profiles)
    if current not in endpoints or target not in endpoints:
        raise ValueError("Unknown destination")
    for profile in profiles:
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}",profile):
            raise ValueError("Invalid profile ID")
    matching = [p for p in active_hosts if p.get("host_ip") == host]
    if len(matching) != 1:
        raise ValueError("Host policy must exist exactly once")
    if matching[0].get("destination") != current:
        raise ValueError("Saved host assignment changed; reload before transition")
    if not matching[0].get("registered_mac"):
        raise ValueError("Host has no registered MAC")
    vpn_source = current not in ("direct","blocked")
    vpn_target = target not in ("direct","blocked")
    blockers=[]
    if vpn_target:
        profile=profiles[target]
        if not profile.get("enabled") or profile.get("status")=="not_configured":
            blockers.append("vpn_profile_not_configured")
        blockers.extend(("vpn_egress_unverified","isolated_dns_unverified",
                         "host_ipv4_ipv6_killswitch_unverified","persistent_restore_unverified"))
    elif target == "direct":
        blockers.append("target_direct_guard_transaction_unverified")
    else:
        blockers.append("target_block_guard_transaction_unverified")
    if current != target:
        blockers.append("atomic_host_ruleset_swap_unverified")
        blockers.append("rollback_after_reboot_unverified")
    other_users=[p["host_ip"] for p in active_hosts
                 if p.get("host_ip") != host and p.get("destination")==current and vpn_source]
    transition_type = ("noop" if current == target else
                       "vpn_to_vpn" if vpn_source and vpn_target else
                       "vpn_to_direct" if vpn_source and target == "direct" else
                       "vpn_to_blocked" if vpn_source else
                       "direct_to_vpn" if current == "direct" and vpn_target else
                       "blocked_to_vpn" if current == "blocked" and vpn_target else
                       "direct_to_blocked" if current == "direct" else
                       "blocked_to_direct")
    return {"host":host,"from":current,"to":target,"transition_type":transition_type,"ready":current==target,
            "network_changes":False,"blockers":[] if current==target else blockers,
            "workflow":[
              "reload_persistent_assignments_and_topology",
              "lock_only_target_host_and_verify_registered_mac",
              "arm_failure_safe_and_boot_restore",
              "stage_destination_firewall_dns_and_routes_with_default_drop",
              "verify_destination_before_switch",
              "atomic_host_only_cutover",
              "verify_no_leak_then_commit_or_restore_safe_previous_state",
              "remove_unused_host_resources_without_disconnecting_shared_vpn"
            ] if current!=target else [],
            "shared_vpn_users_preserved":other_users}
