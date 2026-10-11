#!/usr/bin/env python3
"""Read-only dynamic policy dataplane planner. Does not change host networking."""
import argparse
import ipaddress
import json


def plan(host_ip, destination, config, topology):
    host = ipaddress.ip_address(host_ip)
    if host.version != 4 or host.is_multicast or host.is_loopback or host.is_unspecified:
        raise ValueError("Host IPv4 invalido")
    if destination not in ("direct", "blocked"):
        raise ValueError("VPN requer dataplane e fail-closed verificados")
    if not config:
        raise ValueError("WAN/LAN nao configurada")
    roles = {i["interface"]: i["role"] for i in config["interfaces"]}
    management = config["management_interface"]
    lan = [name for name, role in roles.items() if role == "lan"]
    wan = [management] if config["mode"] == "shared" else [
        name for name, role in roles.items() if role == "wan"]
    live = {i["interface"]: i for i in topology["interfaces"] if i["operstate"] == "UP"}
    if not lan or len(wan) != 1 or any(i not in live for i in lan + wan):
        raise ValueError("Interfaces LAN/WAN invalidas ou inactivas")
    networks = [ipaddress.ip_network(live[i]["network"], strict=False) for i in lan]
    inbound = [i for i in lan if host in ipaddress.ip_network(live[i]["network"], strict=False)]
    if len(inbound) != 1:
        raise ValueError("Host tem de pertencer exactamente a uma LAN")
    gateway_candidates = [r["gateway"] for r in topology["default_routes"]
                          if r["interface"] == wan[0] and r.get("gateway")]
    if destination == "direct" and len(gateway_candidates) != 1:
        raise ValueError("Gateway WAN ambiguo ou ausente")
    protected = {ipaddress.ip_address(g) for g in gateway_candidates}
    for i in topology["interfaces"]:
        if i.get("address"):
            try:
                protected.add(ipaddress.ip_interface(i["address"]).ip)
            except ValueError:
                pass
    if host in protected:
        raise ValueError("Nao se pode aplicar politica ao gateway ou ao router")
    return {
        "host": str(host), "destination": destination, "lan": inbound[0],
        "wan": wan[0], "gateway": gateway_candidates[0] if gateway_candidates else None,
        "shared_interface": inbound[0] == wan[0], "ready_for_live_application": False,
        "requires": ["agente privilegiado isolado", "rollback systemd independente",
                     "confirmacao de cliente externo", "teste DNS e NAT"],
        "network_changed": False,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", required=True)
    p.add_argument("--destination", choices=("direct", "blocked"), required=True)
    p.add_argument("--config", required=True, help="JSON de configuracao WAN/LAN guardada")
    p.add_argument("--topology", required=True, help="JSON de topologia observada")
    args = p.parse_args()
    with open(args.config, encoding="utf-8") as f:
        config = json.load(f)
    with open(args.topology, encoding="utf-8") as f:
        topology = json.load(f)
    print(json.dumps(plan(args.host, args.destination, config, topology), indent=2))


if __name__ == "__main__":
    main()
