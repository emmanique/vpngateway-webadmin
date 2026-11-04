#!/usr/bin/env python3
"""Read-only DNS cutover gate. Explicitly refuses switching incomplete setup."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess


def call(*args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=10)
    if p.returncode:
        raise ValueError((p.stderr or "command failed")[:150])
    return p.stdout


def report(container, state_dir):
    findings = []
    def check(name, success, explanation):
        findings.append({"check": name, "pass": bool(success), "details": explanation})
    try:
        inspection = json.loads(call("docker","inspect",container))[0]
        network = inspection.get("NetworkSettings",{}).get("Networks",{})
        n = [(entry.get("IPAddress"),entry.get("Gateway"))
             for entry in network.values() if entry.get("IPAddress") and entry.get("Gateway")]
        container_ip, bridge_ip = n[0] if len(n)==1 else (None,None)
        env = inspection.get("Config",{}).get("Env",[])
        upstreams = [item.split("=",1)[1] for item in env if item.startswith("FTLCONF_dns_upstreams=")]
        extra = [item.split("=",1)[1] for item in env if item.startswith("FTLCONF_misc_dnsmasq_lines=")]
        check("pihole_container_running",inspection.get("State",{}).get("Running",False),
              "Container running, checked via Docker")
        check("single_container_network",bool(container_ip and bridge_ip),
              "Docker addresses discovered dynamically")
        check("exclusive_policy_upstream",
              len(upstreams)==1 and bool(re.fullmatch(r"[^,\s;#]+#5355",upstreams[0])),
              "Pi-hole must only target a verified host policy-worker on port 5355")
        check("client_edns_origin",
              bool(extra and "add-subnet=32" in extra[0] and "strip-subnet" in extra[0]),
              "Pi-hole must strip caller ECS and inject source-client /32")
        if bridge_ip:
            try:
                route=json.loads(call("ip","-j","-4","route","get",bridge_ip))
                check("bridge_route",bool(route and route[0].get("dev")),
                      "The gateway can reach its Docker bridge")
            except (ValueError, KeyError):
                check("bridge_route",False,"No verified bridge route")
    except (ValueError,IndexError,KeyError,OSError):
        check("pihole_container_running",False,"Cannot inspect Pi-hole")
        check("single_container_network",False,"No single verified Docker bridge")
        check("exclusive_policy_upstream",False,"Cannot confirm Pi-hole upstream")
        check("client_edns_origin",False,"Cannot confirm trusted ECS")
        container_ip=None
        bridge_ip=None
    folder=Path(state_dir)
    entries=list(folder.glob("*.json")) if folder.is_dir() and not folder.is_symlink() else []
    active=0
    for entry in entries:
        try:
            state=json.loads(entry.read_text())
            if state.get("status")=="active" and not state.get("vpn_pending"):
                active+=1
        except (ValueError,OSError):
            continue
    check("confirmed_host_policies",active>0,
          "Only explicitly confirmed policies may be included")
    check("host_dns_worker_service",False,
          "Opt-in DNS worker not deployed through an audited systemd unit")
    check("atomic_pihole_cutover",False,
          "Packet path and per-host exceptions not yet applied/verified")
    check("real_client_ip_verified",False,
          "Test that Pi-hole receives real LAN client IP rather than Docker proxy")
    check("dns_fail_closed_live",False,
          "No live DNS egress and VPN-outage capture evidence")
    return {"safe_to_switch":all(x["pass"] for x in findings),
            "read_only":True,"container_ipv4":container_ip,"host_bridge_ipv4":bridge_ip,
            "confirmed_policies":active,"checks":findings}


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--container",required=True)
    parser.add_argument("--state-dir",default="/var/lib/vpngw-policy-agent")
    options=parser.parse_args()
    result=report(options.container,options.state_dir)
    print(json.dumps(result,indent=2))
    raise SystemExit(0 if result["safe_to_switch"] else 2)
