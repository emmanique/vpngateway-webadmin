#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Completely isolated kernel network; never modify the ASUS or its VPNs.
unshare --net -- python3 - <<'PY'
import hashlib
import importlib.util
from pathlib import Path
import subprocess

def run(*cmd, data=None):
    p=subprocess.run(cmd,input=data,text=True,capture_output=True)
    if p.returncode:
        raise RuntimeError(f"{cmd[:3]}: {p.stderr.strip()[:180]}")
    return p.stdout

def load(name):
    src=Path("scripts")/(name+".py")
    spec=importlib.util.spec_from_file_location(name.replace("-","_"),src)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    return mod

host="192.168.33.22"
mac="02:ee:dd:cc:bb:aa"
central={"pihole_ipv4":"172.19.9.2","bridge_interface":"brdns0"}
pid="dns-qa"
g=load("vpngw-vpn-host-guard").render(pid,host,mac,"lan0","wgqa0",central_dns=central)
run("nft","-c","-f","-",data=g)
print("DNS_CENTRAL_NFT_GUARD_SYNTAX: PASS")

chain="GW_"+hashlib.sha256(pid.encode()).hexdigest()[:16].upper()
run("nft","-f","-",data=f"add table ip filter\nadd chain ip filter {chain}\n")
f=load("vpngw-vpn-filter-batch").generate(pid,host,mac,"lan0","wgqa0",central_dns=central)
run("nft","-c","-f","-",data=f)
print("DNS_CENTRAL_LEGACY_FILTER_SYNTAX: PASS")

for iface in ("lan0","brdns0","wgqa0","wan0"):
    run("ip","link","add",iface,"type","dummy")
    run("ip","link","set",iface,"up")
run("ip","-4","addr","add","192.168.33.1/24","dev","lan0")
run("ip","-4","addr","add","172.19.9.1/24","dev","brdns0")
run("ip","-4","addr","add","10.2.0.2/32","dev","wgqa0")
run("ip","-4","addr","add","198.18.20.2/24","dev","wan0")
run("ip","-4","route","add","default","via","198.18.20.1","dev","wan0")

route=load("vpngw-vpn-route-commands").generate(host,"vpn-test","lan0","wgqa0")
table=str(route["table"])
for item in route["stage"]:
    run(*item)
run("ip","-4","route","replace","172.19.9.2/32","dev","brdns0",
    "scope","link","table",table)
run(*route["cutover"][0])
by_vpn=run("ip","-4","route","get","1.1.1.1","from",host,"iif","lan0")
by_pihole=run("ip","-4","route","get","172.19.9.2","from",host,"iif","lan0")
assert "dev wgqa0" in by_vpn,by_vpn
assert "dev brdns0" in by_pihole,by_pihole
print("DNS_CENTRAL_SPLIT_ROUTES_VPN_AND_PIHOLE: PASS")

run("ip","link","delete","wgqa0")
lost=subprocess.run(["ip","-4","route","get","1.1.1.1","from",host,"iif","lan0"],
                    capture_output=True,text=True)
assert lost.returncode!=0,lost.stdout
print("DNS_CENTRAL_NO_DIRECT_FALLBACK_ON_TUNNEL_LOSS: PASS")
PY
