#!/usr/bin/env python3
"""Strict rollback completion: only remove an identified per-host guard after DIRECT restored.

Not integrated into automatic watchdog until cutover has been tested end-to-end.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

SOURCE=Path(__file__).with_name("vpngw-vpn-rollback-journal.py")
spec=importlib.util.spec_from_file_location("rollback_journal",SOURCE)
journal=importlib.util.module_from_spec(spec);spec.loader.exec_module(journal)

def verify(record,state,cmd):
    journal.validate(record)
    pid=record["policy_id"]
    if record.get("state")!="revert_required" or record.get("routing_restored") is not True:
        raise ValueError("DIRECT route has not been restored and recorded")
    plan=state.get("plan",{})
    if state.get("status")!="active" or plan.get("destination")!="direct" or record["snapshot"].get("host")!=plan.get("host"):
        raise ValueError("DIRECT policy not verified")
    name="GW_"+hashlib.sha256(pid.encode()).hexdigest()[:16].upper()
    host=plan["host"]
    lan=plan["lan"]
    guard=record.get("guard_table")
    if not isinstance(guard,str) or not re.fullmatch(r"vpngw_host_[a-z0-9_]{1,36}",guard):
        raise ValueError("Unexpected guard table")
    if guard!="vpngw_host_"+pid.replace("-","_"):
        raise ValueError("Guard ownership mismatch")
    direct=cmd("nft","list","chain","ip","filter",name)
    nat=cmd("nft","list","table","ip","vpngw_"+name.lower())
    user=cmd("nft","list","chain","ip","filter","DOCKER-USER")
    direct_nat=re.search(r"ip saddr "+re.escape(host)+r"\s+oifname \""+re.escape(plan["wan"])+r"\"[^\n]*masquerade",nat)
    if "accept" not in direct or not direct_nat or user.count("jump "+name)!=2:
        raise RuntimeError("DIRECT firewall or NAT cannot be verified")
    rule=cmd("ip","-4","rule","show")
    if any(line.lstrip().startswith(str(record["vpn_priority"])+":") for line in rule.splitlines()):
        raise RuntimeError("VPN host route still present")
    route=cmd("ip","-4","route","get","1.1.1.1","from",host,"iif",lan)
    if "dev "+plan["wan"] not in route or "table "+str(record["vpn_table"]) in route:
        raise RuntimeError("DIRECT routing not restored")
    actual=cmd("nft","list","table","inet",guard)
    if host not in actual or record["vpn_interface"] not in actual or "drop" not in actual:
        raise RuntimeError("Not the expected per-host kill switch")
    return guard

def finalize(record,state,cmd,save):
    guard=verify(record,state,cmd)
    cmd("nft","delete","table","inet",guard)
    # Confirm guard gone before declaring complete; rollback remains pending if this fails.
    try:
        cmd("nft","list","table","inet",guard)
    except subprocess.CalledProcessError:
        save({**record,"state":"reverted","guard_preserved":False,"routing_restored":True})
        return {"policy":record["policy_id"],"direct_restored":True,"guard_removed":True}
    raise RuntimeError("Guard remained installed; rollback not completed")
