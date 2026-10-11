#!/usr/bin/env python3
"""DEV-only dry-run planner: never changes nftables, routes or systemd."""
import argparse
import ipaddress
import json
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("network_topology", Path(__file__).with_name("network-topology.py"))
topology_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(topology_module)

def plan(hosts, interface=None, topology=None):
    if topology is not None:
        candidates=[i for i in topology["interfaces"] if i.get("address") and
                    (i.get("interface")==interface if interface else i.get("default_route"))]
        if len(candidates)!=1:
            raise ValueError("invalid_lan_interface" if interface else "ambiguous_default_route")
        interface=candidates[0]
    else:
        interface, topology = topology_module.selected_network(interface)
    network = ipaddress.ip_network(interface["network"])
    reserved = {interface["address"]} | {r["gateway"] for r in topology["default_routes"] if r.get("gateway")}
    result = []
    seen = set()
    for raw in hosts:
        try:
            address = ipaddress.ip_address(raw)
            ip = str(address)
            if address.version != 4 or address not in network or address == network.network_address or address == network.broadcast_address:
                raise ValueError("outside_allowed_lan")
            if ip in reserved:
                raise ValueError("reserved_host")
            if ip in seen:
                raise ValueError("duplicate_host")
            seen.add(ip)
            result.append({"host_ip": ip, "eligible": True, "mode": "dry_run",
                           "action": "no_changes", "fail_closed_required": True})
        except ValueError as exc:
            result.append({"host_ip": raw, "eligible": False, "reason": str(exc),
                           "action": "no_changes"})
    return {"mode": "dry_run", "network": str(network), "hosts": result,
            "changes_applied": False}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("hosts", nargs="+")
    parser.add_argument("--interface", default=None)
    args = parser.parse_args()
    print(json.dumps(plan(args.hosts, args.interface), indent=2))
