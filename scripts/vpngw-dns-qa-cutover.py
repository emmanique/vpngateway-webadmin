#!/usr/bin/env python3
"""Short, per-policy DNS pilot; independent systemd rollback. DEV/QA only.

No changes to the global WAN route, Docker networks or public repository.
All operations require root, verified policy and exclusive Pi-hole upstream.
"""
import argparse
import fcntl
from contextlib import contextmanager
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import threading

POLICY_DIR = Path("/var/lib/vpngw-policy-agent")
JOURNAL_DIR = Path("/var/lib/vpngw-policy-agent/dns-qa-journals")
IP = "/usr/sbin/ip"
NFT = "/usr/sbin/nft"
IFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")
ID = re.compile(r"[a-z][a-z0-9-]{1,31}\Z")
_THREAD_LOCK = threading.RLock()
_REENTRY = threading.local()


@contextmanager
def agent_policy_lock():
    """Use the same kernel lock as the live policy agent.

    Reentrant in this process so an apply failure can call rollback while
    holding the policy lock. The OS-level lock prevents concurrent updates
    from the main agent or another QA cutover process.
    """
    with _THREAD_LOCK:
        depth = getattr(_REENTRY, "depth", 0)
        if not depth:
            POLICY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd=os.open(POLICY_DIR/".lock", os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            _REENTRY.fd=fd
        _REENTRY.depth=depth+1
        try:
            yield
        finally:
            _REENTRY.depth-=1
            if _REENTRY.depth==0:
                fd=_REENTRY.fd
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
                del _REENTRY.fd


def run(*args, input_text=None, check=True, timeout=12):
    proc=subprocess.run(args,input=input_text,capture_output=True,text=True,timeout=timeout)
    if proc.returncode and check:
        raise RuntimeError("Command failed: "+str(args[:3])+" "+proc.stderr[:240])
    return proc


def load(name):
    path=Path(__file__).with_name(name+".py")
    spec=importlib.util.spec_from_file_location(name.replace("-","_"),path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def state_for(pid):
    if not ID.fullmatch(pid):
        raise ValueError("Invalid policy identifier")
    file=POLICY_DIR/(pid+".json")
    if file.is_symlink():
        raise ValueError("Symlink state refused")
    state=json.loads(file.read_text())
    plan=state.get("plan") or {}
    runtime=state.get("vpn_runtime") or {}
    if (state.get("status")!="active" or state.get("vpn_pending")
            or plan.get("destination") in ("direct","blocked",None)
            or not plan.get("registered_mac")
            or not runtime.get("interface") or not runtime.get("dns_ipv4")):
        raise ValueError("Confirmed VPN client policy required")
    return state


def names(pid):
    digest=hashlib.sha256(pid.encode()).hexdigest()
    return "vpngw_vpn_"+digest[:12],"GW_"+digest[:16].upper()


def port_preflight(container, pihole, bridge):
    ins=json.loads(run("docker","inspect",container).stdout)[0]
    network=ins.get("NetworkSettings",{}).get("Networks") or {}
    ips=[s.get("IPAddress") for s in network.values() if s.get("IPAddress")]
    if len(ips)!=1 or ips[0]!=pihole or not ins.get("State",{}).get("Running"):
        raise ValueError("Dedicated Pi-hole container mismatch")
    env=dict(x.split("=",1) for x in ins["Config"]["Env"] if "=" in x)
    routes=json.loads(run(IP,"-j","-4","route","get",pihole).stdout)
    if not routes or routes[0].get("dev")!=bridge:
        raise ValueError("Pi-hole not reachable through expected bridge")
    gateway=routes[0].get("prefsrc") or routes[0].get("src")
    # Kernel chooses source address of Docker bridge; not a LAN/WAN address.
    if not gateway:
        raise ValueError("Docker bridge gateway not verified")
    if env.get("FTLCONF_dns_upstreams")!=gateway+"#5355":
        raise ValueError("Pi-hole upstream must be exclusively the policy worker")
    opts=env.get("FTLCONF_misc_dnsmasq_lines","").split(";")
    if not {"strip-subnet","add-subnet=32,128"}.issubset(set(opts)):
        raise ValueError("Pi-hole must strip untrusted ECS and attach actual client /32")
    if env.get("FTLCONF_dns_cache_size")!="0":
        raise ValueError("Disable cache to enforce VPN outage fail closed")
    if env.get("FTLCONF_dns_listeningMode")!="ALL":
        raise ValueError("Pi-hole must accept routed client DNS queries")
    # Fail BEFORE modifying any client if the policy worker is not listening.
    import socket
    with socket.create_connection((gateway,5355),timeout=2):
        pass
    return gateway


def render_batch(pid, state, central=None):
    plan=state["plan"]
    runtime=state["vpn_runtime"]
    if not IFACE.fullmatch(plan["lan"]) or not IFACE.fullmatch(runtime["interface"]):
        raise ValueError("Invalid interfaces")
    ip=plan["host"]
    lan=plan["lan"]
    vpn=runtime["interface"]
    mac=plan["registered_mac"]
    dns=None if central is not None else runtime["dns_ipv4"]
    guard=load("vpngw-vpn-host-guard").render(
        pid,ip,mac,lan,vpn,dns_ipv4=dns,central_dns=central)
    filt=load("vpngw-vpn-filter-batch").generate(
        pid,ip,mac,lan,vpn,central_dns=central)
    table,_=names(pid)
    exists=run(NFT,"list","table","inet",table,check=False).returncode==0
    # Boot guard runs before the regular host guard (-205 vs -150).
    # Unless its drop is atomically amended for Pi-hole DNS, no client
    # packet can ever reach Docker, regardless of later accept rules.
    boot=load("vpngw-vpn-boot-guard")
    record={"id":pid,"host":ip,"lan":lan,"vpn":vpn,
            "mac":mac,"confirmed":True}
    boot.validate(record)
    boot_table=boot.guard_name(pid)
    if run(NFT,"list","table","inet",boot_table,check=False).returncode:
        raise ValueError("Mandatory early-boot fail-closed guard missing")
    boot_text=boot.render(record,central_dns=central)
    # Both guards and Docker-specific host allow rules change in a single
    # nft atomic batch. The provider DNS boot guard is restored on rollback.
    boot_batch="delete table inet "+boot_table+"\n"+boot_text+"\n"
    return (boot_batch + ("delete table inet "+table+"\n" if exists else "")
            +guard+"\n"+filt)


def journal_path(pid):
    if not ID.fullmatch(pid):
        raise ValueError("Invalid policy identifier")
    return JOURNAL_DIR/(pid+".json")


def save_journal(pid, data):
    JOURNAL_DIR.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(JOURNAL_DIR,0o700)
    file=journal_path(pid)
    fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w") as stream:
        json.dump(data,stream)
        stream.flush()
        os.fsync(stream.fileno())


def update_journal(pid, status):
    path=journal_path(pid)
    state=json.loads(path.read_text())
    state["status"]=status
    temp=path.with_suffix(".tmp")
    fd=os.open(temp,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w") as stream:
        json.dump(state,stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp,path)


def strip_stale_boot_exception(pid, journal):
    """Remove ONLY the prior pilot's DNS allow rule after a host policy change.

    A new VPN/DIRECT policy may have replaced other rules in the boot chain.
    Do not recreate the old boot guard or overwrite that newer policy.
    """
    boot_name=load("vpngw-vpn-boot-guard").guard_name(pid)
    observed=run(NFT,"-a","list","chain","inet",boot_name,"forwarding",check=False)
    if observed.returncode:
        return False
    old=journal["policy"]["plan"]
    markers=(
        "ip daddr "+journal["pihole"],
        'oifname "'+journal["bridge"]+'"',
        "ether saddr "+old["registered_mac"].lower(),
        "th dport 53",
    )
    candidates=[]
    for line in observed.stdout.splitlines():
        if all(item in line for item in markers):
            match=re.search(r"# handle (\d+)",line)
            if not match:
                raise ValueError("DNS exception exists without deletable handle")
            candidates.append(match.group(1))
    if len(candidates)>1:
        raise ValueError("Ambiguous stale DNS exception")
    if candidates:
        run(NFT,"delete","rule","inet",boot_name,"forwarding","handle",candidates[0])
    return bool(candidates)


def recover_pending():
    """Boot recovery: replay durable QA rollback journals, never mutate WAN."""
    if JOURNAL_DIR.is_symlink():
        raise ValueError("Unsafe DNS recovery journal directory")
    if not JOURNAL_DIR.exists():
        return {"recovered":[]}
    if not JOURNAL_DIR.is_dir():
        raise ValueError("Invalid DNS recovery journal directory")
    recovered=[]
    for file in sorted(JOURNAL_DIR.iterdir()):
        if (not file.name.endswith(".json") or file.is_symlink()
                or not file.is_file() or not ID.fullmatch(file.stem)):
            raise ValueError("Unexpected DNS recovery journal entry")
        if file.stat().st_uid!=0 or file.stat().st_mode & 0o077:
            raise ValueError("Unsafe DNS recovery journal permissions")
        result=rollback(file.stem)
        recovered.append({"policy":file.stem,**result})
    return {"recovered":recovered}


def rollback(pid):
    with agent_policy_lock():
        return _rollback_locked(pid)


def _rollback_locked(pid):
    path=journal_path(pid)
    if not path.is_file() or path.is_symlink():
        return {"already_reverted":True}
    journal=json.loads(path.read_text())
    if journal.get("status") not in ("prepared","armed","active","error"):
        raise ValueError("Invalid DNS journal status")
    before=journal["policy"]
    if (before.get("plan",{}).get("host")!=journal["host"]
            or journal["table"]!=before.get("vpn_runtime",{}).get("table")):
        raise ValueError("Journal policy integrity failure")
    # A policy may have been deliberately changed during the QA window.
    # Never overwrite that newer live policy with a stale journal snapshot.
    try:
        current=state_for(pid)
        changed=(current.get("plan")!=before.get("plan")
                 or current.get("vpn_runtime")!=before.get("vpn_runtime"))
    except (OSError, ValueError, KeyError):
        changed=True
    if not changed:
        batch=render_batch(pid,before)
        run(NFT,"-c","-f","-",input_text=batch)
        run(NFT,"-f","-",input_text=batch)
    else:
        strip_stale_boot_exception(pid,journal)
    # The provider DNS guard is restored BEFORE removing the bridge route
    # for an unchanged policy. In the changed-policy case do not edit nft.
    route=journal["pihole"]+"/32"
    table=str(journal["table"])
    observed=json.loads(run(IP,"-j","-4","route","show","table",table).stdout)
    for entry in observed:
        if (entry.get("dst") in (route,journal["pihole"])
                and entry.get("dev")==journal["bridge"]):
            run(IP,"-4","route","del",route,"table",table)
            break
    path.unlink()
    return {"restored":not changed,"policy":pid,
            "newer_policy_preserved":changed}


def apply(pid, pihole, bridge, container, seconds=120):
    with agent_policy_lock():
        return _apply_locked(pid, pihole, bridge, container, seconds)


def _apply_locked(pid, pihole, bridge, container, seconds=120):
    if os.geteuid()!=0:
        raise PermissionError("root required")
    if not 60<=seconds<=240:
        raise ValueError("Invalid rollback deadline")
    ipaddress.IPv4Address(pihole)
    if not IFACE.fullmatch(bridge):
        raise ValueError("Invalid bridge")
    state=state_for(pid)
    plan=state["plan"]
    runtime=state["vpn_runtime"]
    if journal_path(pid).exists():
        raise ValueError("Unresolved previous pilot rollback journal")
    port_preflight(container,pihole,bridge)
    table=runtime["table"]
    route=run(IP,"-4","route","get","1.1.1.1","from",plan["host"],
              "iif",plan["lan"]).stdout
    if "dev "+runtime["interface"] not in route:
        raise ValueError("Host is not using its assigned VPN")
    old_guard,_=names(pid)
    if run(NFT,"list","table","inet",old_guard,check=False).returncode:
        raise ValueError("Original fail-closed guard missing")
    central={"pihole_ipv4":pihole,"bridge_interface":bridge}
    batch=render_batch(pid,state,central)
    run(NFT,"-c","-f","-",input_text=batch)
    default=render_batch(pid,state)
    run(NFT,"-c","-f","-",input_text=default)
    # First create a durable journal, then independently arm systemd revert,
    # THEN mutate only this client's policy table and nftables batch.
    save_journal(pid,{"status":"prepared","policy":state,"host":plan["host"],
                      "bridge":bridge,"pihole":pihole,"table":table,
                      "at":time.time()})
    timer="vpngw-dns-qa-revert-"+pid
    try:
        run("/usr/bin/systemd-run","--quiet","--unit="+timer,
            "--on-active="+str(seconds)+"s","/usr/bin/python3",
            os.path.abspath(__file__),"rollback","--policy-id",pid,timeout=12)
        update_journal(pid,"armed")
        # Installing only one host-specific /32 avoids changing default route.
        run(IP,"-4","route","replace",pihole+"/32","dev",bridge,
            "scope","link","table",str(table))
        lookup=run(IP,"-4","route","get",pihole,"from",plan["host"],
                   "iif",plan["lan"]).stdout
        if "dev "+bridge not in lookup:
            raise ValueError("Selected host cannot route to Pi-hole bridge")
        run(NFT,"-f","-",input_text=batch)
        update_journal(pid,"active")
        return {"active":True,"policy":pid,"host":plan["host"],
                "pihole":pihole,"expires_after_seconds":seconds}
    except BaseException:
        try:
            rollback(pid)
        except Exception:
            # Journal remains for independent timer, preserve fail-closed
            # guard until the independent rollback is completed.
            pass
        raise


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("action",choices=["apply","rollback","recover"])
    parser.add_argument("--policy-id")
    parser.add_argument("--pihole")
    parser.add_argument("--bridge")
    parser.add_argument("--container")
    parser.add_argument("--seconds",type=int,default=120)
    args=parser.parse_args()
    if args.action=="recover":
        if args.policy_id:
            parser.error("recover does not accept a policy")
        result=recover_pending()
    elif args.action=="rollback":
        if not args.policy_id:
            parser.error("rollback requires --policy-id")
        result=rollback(args.policy_id)
    else:
        if not args.policy_id:
            parser.error("apply requires --policy-id")
        if not all((args.pihole,args.bridge,args.container)):
            parser.error("apply requires --pihole --bridge --container")
        result=apply(args.policy_id,args.pihole,args.bridge,args.container,args.seconds)
    print(json.dumps(result))


if __name__=="__main__":
    main()
