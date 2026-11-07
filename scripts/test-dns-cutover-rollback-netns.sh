#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Kernel namespaces only: never touch host routes, host nftables, or running QA.
unshare --net -- python3 - <<'PY'
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch


def load(filename):
    path=Path("scripts")/filename
    spec=importlib.util.spec_from_file_location(filename.replace(".py","").replace("-","_"),path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(*cmd, data=None):
    result=subprocess.run(cmd,input=data,text=True,capture_output=True)
    if result.returncode:
        raise RuntimeError(f"{cmd[:3]} rc={result.returncode}: {result.stderr[:250]}")
    return result.stdout


agent=load("vpngw-dns-qa-cutover.py")
routes=load("vpngw-vpn-route-commands.py")
guard=load("vpngw-vpn-host-guard.py")
boot=load("vpngw-vpn-boot-guard.py")
policy="dns-pilot"
host="192.168.37.30"
mac="02:aa:bb:cc:dd:ee"
bridge="brdns0"
pihole="172.19.9.2"
vpn="wg123456789ab"
lan="lan0"
for iface in (lan,bridge,vpn,"wan0"):
    run("ip","link","add",iface,"type","dummy")
    run("ip","link","set",iface,"up")
for iface,cidr in ((lan,"192.168.37.1/24"),(bridge,"172.19.9.1/24"),
                   (vpn,"10.2.0.2/32"),("wan0","198.18.29.2/24")):
    run("ip","addr","add",cidr,"dev",iface)
run("ip","route","add","default","via","198.18.29.1","dev","wan0")

plan=routes.generate(host,"vpn-qa",lan,vpn)
for cmd in plan["stage"]:
    run(*cmd)
for cmd in plan["cutover"]:
    run(*cmd)
table=plan["table"]
state={"status":"active","plan":{
    "host":host,"lan":lan,"wan":"wan0",
    "registered_mac":mac,"destination":"vpn-qa"},
    "vpn_runtime":{"interface":vpn,"dns_ipv4":"10.2.0.1",
                   "table":table,"priority":plan["priority"]}}
run("nft","-f","-",data="add table ip filter\n")
run("nft","-f","-",data="add chain ip filter GW_"+hashlib.sha256(policy.encode()).hexdigest()[:16].upper()+"\n")
run("nft","-f","-",data=guard.render(policy,host,mac,lan,vpn,dns_ipv4="10.2.0.1"))
run("nft","-f","-",data=boot.render({"id":policy,"host":host,"lan":lan,"vpn":vpn,"mac":mac,"confirmed":True}))

with tempfile.TemporaryDirectory(prefix="vpngw-dns-ns-") as location:
    root=Path(location)
    state_dir=root/"policy"
    state_dir.mkdir()
    (state_dir/(policy+".json")).write_text(json.dumps(state))
    journal_dir=state_dir/"dns-qa-journals"
    original_run=agent.run
    armed=[]
    def simulated_run(*command,**kwargs):
        if command[0]=="/usr/bin/systemd-run":
            armed.append(tuple(command))
            return subprocess.CompletedProcess(command,0,stdout="",stderr="")
        return original_run(*command,**kwargs)
    with patch.object(agent,"POLICY_DIR",state_dir),\
         patch.object(agent,"JOURNAL_DIR",journal_dir),\
         patch.object(agent,"port_preflight",return_value="172.19.9.1"),\
         patch.object(agent,"run",side_effect=simulated_run):
        result=agent.apply(policy,pihole,bridge,"isolated-pihole",120)
        assert result["active"] and armed,"Rollback timer was not armed"
        nft=run("nft","list","table","inet",agent.names(policy)[0])
        assert "dnat ip to "+pihole in nft,nft
        boot_active=run("nft","list","table","inet",boot.guard_name(policy))
        assert "ip daddr "+pihole in boot_active and bridge in boot_active,boot_active
        route=run("ip","route","get",pihole,"from",host,"iif",lan)
        assert "dev "+bridge in route,route
        route=run("ip","route","get","1.1.1.1","from",host,"iif",lan)
        assert "dev "+vpn in route,route
        print("REAL_KERNEL_DNS_CUTOVER_ROUTE_AND_NFT_PASS",flush=True)

        # Destroy ONLY the simulated tunnel interface in the isolated netns.
        run("ip","link","delete",vpn)
        lost=subprocess.run(["ip","route","get","1.1.1.1",
                             "from",host,"iif",lan],capture_output=True,text=True)
        assert lost.returncode != 0, "Host fell back to global WAN routing"
        print("REAL_KERNEL_VPN_LINK_LOSS_FAIL_CLOSED_PASS",flush=True)
        recovered=agent.rollback(policy)
        assert recovered["restored"], recovered
        nft=run("nft","list","table","inet",agent.names(policy)[0])
        assert "dnat ip to 10.2.0.1" in nft and pihole not in nft
        boot_restored=run("nft","list","table","inet",boot.guard_name(policy))
        assert pihole not in boot_restored,boot_restored
        remaining=run("ip","route","show","table",str(table))
        assert pihole not in remaining
        lost=subprocess.run(["ip","route","get","1.1.1.1",
                             "from",host,"iif",lan],capture_output=True,text=True)
        assert lost.returncode != 0, "Rollback exposed DIRECT WAN when tunnel absent"
        assert not agent.journal_path(policy).exists()
        print("REAL_KERNEL_DNS_ROLLBACK_AFTER_TUNNEL_LOSS_FAIL_CLOSED_PASS",flush=True)
PY
