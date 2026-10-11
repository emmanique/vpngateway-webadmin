#!/usr/bin/env python3
"""DEV LAN discovery: bounded ICMP probes; no route/firewall/DHCP changes."""
import concurrent.futures
import ipaddress
import json
import subprocess
import time
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("network_topology", Path(__file__).with_name("network-topology.py"))
topology_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(topology_module)
MAX_PROBES = 1024
MAX_WORKERS = 24

def probe(ip):
    try:
        p = subprocess.run(["/usr/bin/ping", "-n", "-c", "1", "-W", "1", ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return ip if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None

def discover(lan_interface):
    interface, topology = topology_module.selected_network(lan_interface)
    network = ipaddress.ip_network(interface["network"])
    if network.num_addresses > MAX_PROBES + 2:
        raise ValueError("network_too_large_for_safe_scan")
    excluded = {interface["address"]} | {r["gateway"] for r in topology["default_routes"] if r.get("gateway")}
    ips = [str(ip) for ip in network.hosts() if str(ip) not in excluded]
    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        found = sorted(filter(None, pool.map(probe, ips)), key=lambda s: ipaddress.ip_address(s))
    return {"network": str(network), "method": "bounded_icmp", "probes": len(ips),
            "responded": found, "complete": False, "elapsed_seconds": round(time.monotonic()-start, 2),
            "note": "Non-response does not imply offline. MAC/name not verified."}

if __name__ == "__main__":
    import argparse
    ap=argparse.ArgumentParser()
    ap.add_argument("--lan-interface",required=True)
    args=ap.parse_args()
    print(json.dumps(discover(args.lan_interface), ensure_ascii=False))
