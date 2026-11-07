#!/usr/bin/env python3
"""Observe live QA DNS by short simultaneous packet captures; NO network edits.

Capture only for the duration of two explicitly named synthetic DNS questions.
PCAP is held in a private temporary directory and deleted on exit. Never
use this to assert that Pi-hole filtering is enabled for live VPN clients.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import tempfile
import time


def run(args, timeout=12, check=True):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"Exit {p.returncode}: {args[0]}: {p.stderr[-280:]}")
    return p


def inspect_clients(state_dir, policy_ids, lan_dns):
    states={}
    for pid in policy_ids:
        p=state_dir/(pid+".json")
        if p.is_symlink():raise ValueError("Policy symlink not allowed")
        state=json.loads(p.read_text())
        plan=state.get("plan") or {}
        runtime=state.get("vpn_runtime") or {}
        if state.get("status")!="active" or state.get("vpn_pending"):
            raise ValueError("VPN host policy must be confirmed active")
        if not runtime.get("interface") or not runtime.get("dns_ipv4"):
            raise ValueError("Expected VPN tunnel and provider DNS")
        states[pid]={
            "ip":str(ipaddress.IPv4Address(plan["host"])),
            "lan":plan["lan"],
            "vpn":runtime["interface"],
            "resolver":str(ipaddress.IPv4Address(runtime["dns_ipv4"])),
        }
    return states


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--policy-id",action="append",required=True)
    parser.add_argument("--key",required=True)
    parser.add_argument("--lan-dns",required=True)
    parser.add_argument("--state-dir",default="/var/lib/vpngw-policy-agent")
    parser.add_argument("--pihole-container",default="vpngateway-v001-staging-pihole-1")
    options=parser.parse_args()
    if os.geteuid()!=0:raise PermissionError("Capture requires root")
    policies=inspect_clients(Path(options.state_dir),options.policy_id,options.lan_dns)
    source=next(iter(policies.values()))["lan"]
    if any(p["lan"]!=source for p in policies.values()):
        raise ValueError("This short audit requires QA clients on one known LAN")
    def verify_interface(name):
        run(["ip","-4","link","show","dev",name])
        return name
    interfaces=[verify_interface(source)]
    interfaces.extend(verify_interface(p["vpn"]) for p in policies.values())
    networks=json.loads(run(["docker","inspect",options.pihole_container]).stdout)[0]["NetworkSettings"]["Networks"]
    if len(networks)!=1:raise ValueError("Ambiguous Pi-hole Docker bridge")
    network_id=next(iter(networks.values()))["NetworkID"]
    pihole_bridge=verify_interface("br-"+network_id[:12])
    interfaces.append(pihole_bridge)
    default=json.loads(run(["ip","-j","-4","route","show","default"]).stdout)
    wan=next((entry.get("dev") for entry in default if entry.get("dev")),None)
    if not wan:raise ValueError("No default WAN found for leak observation")
    interfaces.append(verify_interface(wan))
    interfaces=list(dict.fromkeys(interfaces))
    labels={pid:"vpngwqa-"+secrets.token_hex(5)+"-"+pid+".example.org"
            for pid in policies}
    captures=[]
    with tempfile.TemporaryDirectory(prefix="vpngw-dns-audit-") as folder:
        try:
            for interface in interfaces:
                target=Path(folder)/(interface+".pcap")
                process=subprocess.Popen([
                    "tcpdump","--immediate-mode","-i",interface,"-nn","-U",
                    "-w",str(target),"udp port 53 or tcp port 53"],
                    stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
                captures.append((interface,target,process))
            time.sleep(1.0)
            for _,_,p in captures:
                if p.poll() is not None:
                    raise RuntimeError("DNS capture terminated unexpectedly")
            for pid,state in policies.items():
                host=state["ip"]
                query=labels[pid]
                response=run([
                    "ssh","-o","BatchMode=yes","-o","ConnectTimeout=4",
                    "-o","StrictHostKeyChecking=yes","-i",options.key,
                    "root@"+host,"dig","@"+options.lan_dns,query,
                    "A","+time=4","+tries=1","+noall","+comments"],timeout=13,check=False)
                if response.returncode!=0 or "timed out" in response.stdout.lower():
                    raise RuntimeError("QA DNS request failed for "+pid)
                print("CLIENT_DNS_PROBE",pid,host,
                      "response_received="+str("status:" in response.stdout),flush=True)
            time.sleep(1)
        finally:
            for _,_,process in captures:
                if process.poll() is None:process.send_signal(signal.SIGINT)
            for _,_,process in captures:
                try:process.wait(timeout=6)
                except subprocess.TimeoutExpired:process.kill()
        evidence={}
        for iface,pfile,proc in captures:
            output=run(["tcpdump","-nn","-r",str(pfile)],timeout=8,check=False).stdout
            matched={pid:[line for line in output.splitlines()
                          if labels[pid] in line] for pid in policies}
            evidence[iface]=matched
            print("DNS_TEST_QUERIES",iface,{pid:len(lines) for pid,lines in matched.items()},flush=True)
        for pid,state in policies.items():
            host=state["ip"]
            if not evidence[source][pid]:
                raise RuntimeError("No originating DNS packets seen on QA LAN for "+pid)
            if not evidence[state["vpn"]][pid]:
                raise RuntimeError("No provider DNS query seen in assigned VPN for "+pid)
            if any(evidence[other["vpn"]][pid] for other_pid,other in policies.items()
                   if other_pid!=pid):
                raise RuntimeError("DNS query crossed into another VPN interface")
            if evidence[wan][pid]:
                raise RuntimeError("Live QA DNS test query was visible on WAN")
        pihole_hits=sum(len(v) for v in evidence[pihole_bridge].values())
        print("LIVE_QA_PROVIDER_DNS_ROUTING_CONFIRMED: PASS",flush=True)
        print("LIVE_QA_NO_TEST_DOMAIN_WAN_LEAK_OBSERVED: PASS",flush=True)
        print("PIHOLE_TEST_DOMAIN_BRIDGE_QUERY_COUNT:",pihole_hits,flush=True)
        if pihole_hits==0:
            print("CENTRAL_PIHOLE_FILTERING_NOT_ACTIVE_FOR_LIVE_VPN_CLIENTS",flush=True)
        # No PCAP or query-specific personal data is retained.

if __name__=="__main__":
    main()
