#!/usr/bin/env python3
"""Read-only, installation-independent IPv4 topology discovery."""
import ipaddress
import json
import subprocess
from pathlib import Path

def ip_json(*args):
    result = subprocess.run(["/usr/sbin/ip", "-j", *args], capture_output=True,
                            text=True, check=True, timeout=5)
    return json.loads(result.stdout)

def detect():
    routes = ip_json("-4", "route", "show", "default")
    defaults = [{"interface": r.get("dev"), "gateway": r.get("gateway"),
                 "metric": r.get("metric", 0)} for r in routes if r.get("dev")]
    interfaces = []
    link_details = {i["ifname"]: i for i in ip_json("-d", "link", "show")}
    for link in ip_json("-4", "address", "show"):
        ifname = link.get("ifname")
        if ifname == "lo":
            continue
        sysnet = Path("/sys/class/net") / ifname
        details = link_details.get(ifname, {})
        driver_kind = (details.get("linkinfo") or {}).get("info_kind")
        ethernet_like = details.get("link_type") == "ether" and (
            (sysnet / "device").exists() or driver_kind in ("virtio", "macvlan") or (driver_kind == "veth" and ifname.startswith(("eth", "ens", "enp", "eno"))))
        kind = "wifi" if (sysnet / "wireless").exists() or ifname.startswith("wl") else ("vlan" if driver_kind == "vlan" else ("ethernet" if ethernet_like else "virtual"))
        addresses = [a for a in link.get("addr_info", []) if a.get("family") == "inet" and a.get("scope") == "global"]
        if not addresses:
            interfaces.append({"interface": ifname, "address": None, "network": None, "prefixlen": None, "operstate": link.get("operstate", "UNKNOWN"), "kind": kind, "default_route": any(r["interface"] == ifname for r in defaults)})
        for entry in addresses:
            if entry.get("family") != "inet" or entry.get("scope") != "global":
                continue
            address = ipaddress.ip_interface(f'{entry["local"]}/{entry["prefixlen"]}')
            interfaces.append({"interface": ifname, "address": str(address.ip),
                               "network": str(address.network), "prefixlen": address.network.prefixlen,
                               "operstate": link.get("operstate", "UNKNOWN"), "kind": kind,
                               "default_route": any(r["interface"] == ifname for r in defaults)})
    return {"interfaces": interfaces, "default_routes": defaults, "source": "kernel_iproute2"}

def selected_network(interface=None):
    topology = detect()
    if interface is not None:
        matches = [x for x in topology['interfaces'] if x['interface'] == interface
                   and x['address'] and x['operstate'] == 'UP']
        if len(matches) != 1:
            raise ValueError('invalid_lan_interface')
        return matches[0], topology
    preferred = [x for x in topology["interfaces"] if x["default_route"]]
    if len(preferred) != 1:
        raise ValueError("ambiguous_default_route")
    return preferred[0], topology

if __name__ == "__main__":
    print(json.dumps(detect()))
