#!/usr/bin/env python3
"""QA-only: short real-client DNS redirection with independent systemd rollback.

A separate ephemeral Pi-hole shares the existing Docker bridge but never the
production Pi-hole volume, listener, Compose service or DNS upstream.
No WAN/LAN reconfiguration and no changes to VPN tunnel profiles.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
PIHOLE_IMAGE="pihole/pihole@sha256:5b9c8cf51de7d6d3f2240dbe72baf5f06e1fd39cb4d77a99fab4fa13e23bd1be"

def run(*args,check=True,timeout=40):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(str(args[:3])+": "+p.stderr[-320:]+p.stdout[-140:])
    return p

def load(name):
    src=ROOT/"scripts"/(name+".py")
    spec=importlib.util.spec_from_file_location(name.replace("-","_"),src)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m

def ssh(key,ip,command,timeout=15):
    return run("ssh","-o","BatchMode=yes","-o","ConnectTimeout=4",
               "-o","StrictHostKeyChecking=yes","-i",key,"root@"+ip,
               command,timeout=timeout)

def wait_ready(name):
    for _ in range(40):
        status=run("docker","exec",name,"pihole","status",check=False)
        if status.returncode==0 and "enabled" in status.stdout.lower():
            return
        time.sleep(1)
    raise RuntimeError("Pilot Pi-hole failed health")

def main():
    argsparse=argparse.ArgumentParser()
    argsparse.add_argument("--policies",nargs="+",required=True)
    argsparse.add_argument("--ssh-key",required=True)
    argsparse.add_argument("--lan-dns",required=True)
    argsparse.add_argument("--live-container",default="vpngateway-v001-staging-pihole-1")
    argsparse.add_argument("--seconds",type=int,default=120)
    opts=argsparse.parse_args()
    if os.geteuid()!=0:raise PermissionError("root required")
    tool=load("vpngw-dns-qa-cutover")
    policies=[]
    for policy in opts.policies:
        state=tool.state_for(policy)
        host=state["plan"]["host"]
        if not ssh(opts.ssh_key,host,"hostname").stdout.strip():
            raise RuntimeError("QA client SSH not available: "+host)
        policies.append((policy,state))
    existing=json.loads(run("docker","inspect",opts.live_container).stdout)[0]
    existing_network=existing["NetworkSettings"]["Networks"]
    if len(existing_network)!=1:
        raise RuntimeError("Ambiguous existing staging Docker network")
    network=next(iter(existing_network))
    gateway=existing_network[network]["Gateway"]
    netinfo=json.loads(run("docker","network","inspect",network).stdout)[0]
    bridge="br-"+netinfo["Id"][:12]
    if not gateway or len(bridge)>15:
        raise RuntimeError("Invalid Docker bridge")
    tag=secrets.token_hex(3)
    qa="vpngw-qa-real-pihole-"+tag
    worker=None
    created=False
    armed=set()
    capture=[]
    rollback_pending=False
    try:
        with tempfile.TemporaryDirectory(prefix="vpngw-real-dns-qa-") as tempdir:
            tmp=Path(tempdir)
            run("docker","cp",opts.live_container+":/etc/pihole/gravity.db",str(tmp/"gravity.db"))
            # Docker cp creates a root-owned copy on the host. The Pi-hole
            # FTL daemon runs under an unprivileged UID and must be able to
            # read AND update the disposable gravity DB for the QA deny test.
            # No permissions on the production Pi-hole volume are changed.
            owner=run("docker","exec",opts.live_container,"id","-u","pihole").stdout.strip()
            group=run("docker","exec",opts.live_container,"id","-g","pihole").stdout.strip()
            if not (owner.isdigit() and group.isdigit()):
                raise RuntimeError("Cannot verify Pi-hole service identity")
            os.chown(tmp/"gravity.db",int(owner),int(group))
            os.chmod(tmp/"gravity.db",0o640)
            created=True
            run("docker","run","-d","--network",network,"--name",qa,
                "-v",str(tmp/"gravity.db")+":/etc/pihole/gravity.db:rw",
                "--cap-drop","NET_ADMIN","--cap-drop","SYS_ADMIN",
                "-e","FTLCONF_dns_listeningMode=ALL",
                "-e","FTLCONF_dns_upstreams="+gateway+"#5355",
                "-e","FTLCONF_misc_dnsmasq_lines=strip-subnet;add-subnet=32,128",
                "-e","FTLCONF_dns_cache_size=0",
                "-e","FTLCONF_dns_queryLogging=true",
                "-e","FTLCONF_webserver_api_password=",
                PIHOLE_IMAGE,timeout=45)
            pihole=json.loads(run("docker","inspect",qa).stdout)[0]
            ip=pihole["NetworkSettings"]["Networks"][network]["IPAddress"]
            worker=subprocess.Popen([sys.executable,str(ROOT/"scripts/vpngw-dns-policy-upstream.py"),
                "--listen",gateway,"--bridge-interface",bridge,"--pihole-source",ip,
                "--direct-resolver","1.1.1.1","--policy-dir","/var/lib/vpngw-policy-agent"],
                stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
            wait_ready(qa)
            if worker.poll() is not None:
                raise RuntimeError("Host worker unavailable: "+worker.stderr.read()[-300:])
            run("docker","exec",qa,"pihole","deny","qa-blocked.example.org")
            print("QA_CONTAINER_AND_POLICY_WORKER_READY",qa,ip,bridge,flush=True)
            for policy,state in policies:
                host=state["plan"]["host"]
                runtime=state["vpn_runtime"]
                print("QA_CLIENT_START",policy,host,runtime["interface"],flush=True)
                wan=state["plan"]["wan"]
                devices=[state["plan"]["lan"],bridge,runtime["interface"],wan]
                # Packet captures contain no VPN credentials. No host rules
                # are altered to capture traffic.
                traces=[]
                for iface in dict.fromkeys(devices):
                    path=tmp/("qa-"+policy+"-"+iface+".pcap")
                    query_filter=("udp port 53 or tcp port 53 or udp port 5355 or tcp port 5355")
                    proc=subprocess.Popen(["tcpdump","-i",iface,"-nn","-U",
                                           "-w",str(path),query_filter],
                                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    traces.append((iface,path,proc))
                    capture.append(proc)
                time.sleep(0.5)
                try:
                    applied=tool.apply(policy,ip,bridge,qa,opts.seconds)
                    armed.add(policy)
                    print("QA_CUTOVER",applied,flush=True)
                    # An unrelated direct/VPN route must remain available;
                    # the DNS-specific /32 is confined to this host's table.
                    query=ssh(opts.ssh_key,host,
                        "dig @"+opts.lan_dns+" www.example.org A +time=4 +tries=1 +short")
                    answer=query.stdout.strip()
                    print("QA_DNS_ANSWER",policy,answer[:180],flush=True)
                    if not answer or "connection timed out" in query.stderr.lower():
                        raise RuntimeError("Pi-hole DNS query failed on QA client")
                    blocked=ssh(opts.ssh_key,host,
                        "dig @"+opts.lan_dns+" qa-blocked.example.org A +time=4 +tries=1 +short")
                    print("QA_PIHOLE_BLOCK",policy,blocked.stdout.strip(),flush=True)
                    if "0.0.0.0" not in blocked.stdout:
                        raise RuntimeError("Central Pi-hole deny test not confirmed")
                    log=run("docker","exec",qa,"sh","-c",
                            "tail -200 /var/log/pihole/pihole.log").stdout
                    if host not in log:
                        raise RuntimeError("Original QA LAN source IP not observed by Pi-hole")
                    pub=ssh(opts.ssh_key,host,"curl -4 -fsS --max-time 8 https://api.ipify.org",timeout=13).stdout.strip()
                    if not pub:
                        raise RuntimeError("QA VPN Internet connectivity lost")
                    print("QA_PIHOLE_CLIENT_IDENTITY_AND_VPN_EGRESS_PASS",policy,pub,flush=True)
                finally:
                    result=tool.rollback(policy)
                    print("QA_CLIENT_RESTORE",result,flush=True)
                    if not result.get("restored"):
                        raise RuntimeError("Expected DNS policy was not restored; timer remains armed")
                    armed.discard(policy)
                    run("systemctl","stop","vpngw-dns-qa-revert-"+policy+".timer",check=False)
                    for iface,path,proc in traces:
                        if proc.poll() is None:
                            proc.send_signal(signal.SIGINT)
                            proc.wait(timeout=5)
                    capture=[p for p in capture if p.poll() is None]
                    # Store only counts/evidence, not private payloads.
                    for iface,path,_ in traces:
                        if path.is_file():
                            data=run("tcpdump","-nn","-r",str(path),check=False).stdout
                            lines=[line for line in data.splitlines() if "53:" in line or ".53 " in line]
                            print("QA_DNS_PCAP",policy,iface,"packets",len(data.splitlines()),flush=True)
                    restored=run("/usr/sbin/nft","list","table","inet",tool.names(policy)[0]).stdout
                    if "dnat ip to "+runtime["dns_ipv4"] not in restored:
                        raise RuntimeError("Original provider DNS guard not restored")
            print("REAL_CLIENT_DNS_PILOT_COMPLETE_AND_ROLLED_BACK",flush=True)
    finally:
        for pid in list(armed):
            try:
                outcome=tool.rollback(pid)
                print("EMERGENCY_ROLLBACK",pid,outcome,flush=True)
                if not outcome.get("restored"):
                    rollback_pending=True
            except Exception as error:
                rollback_pending=True
                print("ERROR: independent systemd rollback remains armed:",error,flush=True)
        for proc in capture:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:proc.wait(timeout=4)
                except subprocess.TimeoutExpired:proc.kill()
        if rollback_pending:
            # Never remove the endpoint while a host may still be DNATed to it.
            # Preserve resources for the independent systemd rollback timer.
            print("QA_PILOT_ROLLBACK_PENDING_ENDPOINT_PRESERVED",flush=True)
        else:
            if worker is not None:
                worker.terminate()
                try:worker.wait(timeout=4)
                except subprocess.TimeoutExpired:worker.kill()
            if created:
                run("docker","rm","-f",qa,check=False)
            print("QA_PILOT_RESOURCES_CLEANED",flush=True)


if __name__=="__main__":
    main()
