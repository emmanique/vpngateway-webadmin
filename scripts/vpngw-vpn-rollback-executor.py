#!/usr/bin/env python3
"""Independent fail-closed rollback executor for a *future* VPN cutover.

Not wired into the running policy agent. Can inspect journals in dry-run;
requires verified rollback journal and explicit --execute to mutate.
"""
import argparse
import hashlib
import ipaddress
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import time

SOURCE=Path(__file__).with_name("vpngw-vpn-rollback-journal.py")
spec=importlib.util.spec_from_file_location("vpngw_rollback_journal",SOURCE)
journal=importlib.util.module_from_spec(spec)
spec.loader.exec_module(journal)
ROOT=Path("/var/lib/vpngw-vpn-transactions")
BATCH_SOURCE=Path(__file__).with_name("vpngw-vpn-direct-restore-batch.py")
batch_spec=importlib.util.spec_from_file_location("vpngw_direct_restore_batch",BATCH_SOURCE)
restore_batch=importlib.util.module_from_spec(batch_spec)
batch_spec.loader.exec_module(restore_batch)

FINALIZER=Path(__file__).with_name("vpngw-vpn-rollback-finalize.py")
final_spec=importlib.util.spec_from_file_location("vpngw_rollback_finalize",FINALIZER)
finalizer=importlib.util.module_from_spec(final_spec)
final_spec.loader.exec_module(finalizer)


DEMOTE_SOURCE=Path(__file__).with_name("vpngw-vpn-boot-demote.py")
demote_spec=importlib.util.spec_from_file_location("vpngw_boot_demote",DEMOTE_SOURCE)
boot_demote=importlib.util.module_from_spec(demote_spec)
demote_spec.loader.exec_module(boot_demote)


def complete_boot_cleanup(record, state, command, directory=None):
    """Idempotent final stage; never claim completion while boot policy remains."""
    kwargs={} if directory is None else {"directory":directory}
    return boot_demote.demote(record,state,command,**kwargs)


def commands_for(record, legacy_state):
    record=journal.validate(record)
    snap=record["snapshot"]
    plan=legacy_state.get("plan",{})
    if legacy_state.get("status")!="active" or plan.get("destination")!="direct":
        raise ValueError("Original DIRECT policy not active")
    if snap["host"]!=plan.get("host") or snap["policy"]!=record["policy_id"]:
        raise ValueError("Saved DIRECT plan mismatch")
    host=plan["host"]
    if not re.fullmatch(r"192\.168\.1\.\d{1,3}",host):
        raise ValueError("Unexpected host address")
    table=record.get("vpn_table")
    priority=record.get("vpn_priority")
    iface=record.get("vpn_interface")
    if not isinstance(table,int) or not 20000<=table<40000:
        raise ValueError("Invalid VPN table")
    if not isinstance(priority,int) or not 10000<=priority<20000:
        raise ValueError("Invalid VPN rule priority")
    if not isinstance(iface,str) or not re.fullmatch(r"(?:tun[a-f0-9]{10}|wg[a-f0-9]{11})",iface):
        raise ValueError("Invalid tunnel")
    # Keep the per-client kill switch in place. Deleting it is deliberately
    # forbidden here until DIRECT restore and route audit are implemented.
    return [
        ["ip","-4","rule","del","pref",str(priority),"iif",plan["lan"],
         "from",host+"/32","lookup",str(table)],
        ["ip","-4","route","flush","table",str(table)]
    ]

def inspect(policy):
    if not journal.ID.fullmatch(policy):raise ValueError("Invalid policy")
    record=journal.read(ROOT/(policy+".json"))
    saved=Path("/var/lib/vpngw-policy-agent")/(policy+".json")
    state=json.loads(saved.read_text())
    cmds=commands_for(record,state)
    return record,cmds

def verify_rollback_prerequisites(record, legacy_state, command):
    """Reject incomplete restoration before any route can fall through to main."""
    commands=commands_for(record,legacy_state)
    policy=record["policy_id"]
    plan=legacy_state["plan"]
    host=plan["host"]
    lan=plan["lan"]
    priority=record["vpn_priority"]
    table=record["vpn_table"]
    name="GW_"+hashlib.sha256(policy.encode()).hexdigest()[:16].upper()
    direct=command("nft","list","chain","ip","filter",name)
    nat=command("nft","list","table","ip","vpngw_"+name.lower())
    jump=command("nft","list","chain","ip","filter","DOCKER-USER")
    if not all(s in direct for s in ("accept",'iifname "'+lan+'"','oifname "'+plan["wan"]+'"')):
        raise RuntimeError("DIRECT forwarding not verified")
    if not re.search(r"ip saddr "+re.escape(host)+r"\s+oifname \""+re.escape(plan["wan"])+r"\"[^\n]*masquerade",nat):
        raise RuntimeError("DIRECT NAT interface not verified")
    if jump.count("jump "+name)!=2:
        raise RuntimeError("DIRECT chain jump not installed")
    # The dedicated host VPN guard must remain installed through the route change.
    guard_table=record.get("guard_table")
    if not isinstance(guard_table,str) or not re.fullmatch(r"vpngw_host_[a-z0-9_]{1,36}",guard_table):
        raise RuntimeError("Verified per-host guard not recorded")
    guard=command("nft","list","table","inet",guard_table)
    if not all(s in guard for s in (host,record["vpn_interface"],"counter")) or "drop" not in guard:
        raise RuntimeError("Fail-closed guard absent")
    rules=command("ip","-4","rule","show")
    expected=re.compile(r"^"+str(priority)+r":\s+from "+re.escape(host)+r"(?:/32)? iif "+re.escape(lan)+r" lookup "+str(table)+r"\s*$")
    matches=sum(bool(expected.match(line.strip())) for line in rules.splitlines())
    if record.get("routing_restored") is True:
        if matches!=0:
            raise RuntimeError("Journal says route restored but VPN rule still exists")
        return []
    if matches!=1:
        raise RuntimeError("VPN host rule not uniquely identified")
    return commands

def restore_direct_firewall_under_guard(record, legacy_state, command):
    """Atomically restore both DIRECT filter and NAT, but only under a verified guard."""
    rec=journal.validate(record)
    plan=legacy_state.get("plan",{})
    if legacy_state.get("status")!="active" or plan.get("destination")!="direct":
        raise RuntimeError("Original DIRECT policy not active")
    if rec["snapshot"].get("host")!=plan.get("host"):
        raise RuntimeError("Original host mismatch")
    guard=rec.get("guard_table")
    if guard!="vpngw_host_"+rec["policy_id"].replace("-","_"):
        raise RuntimeError("Guard ownership mismatch")
    current=command("nft","list","table","inet",guard)
    if not all(x in current for x in (plan["host"],rec["vpn_interface"],"drop")):
        raise RuntimeError("Fail-closed guard missing")
    batch=restore_batch.render(rec["policy_id"],plan)
    # One atomic nft batch prevents a partial DIRECT filter / NAT restoration.
    command("nft","-f","-",input_text=batch)
    return True

def execute_rollback(record, legacy_state, command, persist_result):
    if record["state"] not in ("revert_required","guarded","vpn_pending"):
        raise RuntimeError("Journal state does not authorize rollback")
    commands=verify_rollback_prerequisites(record,legacy_state,command)
    # DIRECT chain and NAT are already verified and remain effective.
    # Preserve guard throughout the removal; do not remove it automatically.
    for cmd in commands:
        command(*cmd)
    host=legacy_state["plan"]["host"]
    lan=legacy_state["plan"]["lan"]
    route=command("ip","-4","route","get","1.1.1.1","from",host,"iif",lan)
    if "dev "+legacy_state["plan"]["wan"] not in route or "table "+str(record["vpn_table"]) in route:
        raise RuntimeError("DIRECT egress restoration not verified; guard retained")
    # Keep the guard until client access is explicitly re-authorized.
    # Route restoration alone is not proof that forwarding is permitted.
    persist_result({**record,"state":"revert_required",
                    "routing_restored":True,"guard_preserved":True})
    return {"policy":record["policy_id"],"direct_route_restored":True,
            "direct_connectivity_restored":False,
            "guard_preserved":True,"vpn_rule_removed":True}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("policy")
    parser.add_argument("--execute",action="store_true")
    args=parser.parse_args()
    record,commands=inspect(args.policy)
    if not args.execute:
        print(json.dumps({"policy":args.policy,"dry_run":True,"commands":commands,
                          "guard_preserved":True,"direct_restored":False}))
        return
    saved=json.loads((Path("/var/lib/vpngw-policy-agent")/(args.policy+".json")).read_text())
    def command(*parts, input_text=None):
        return subprocess.run(parts,input=input_text,capture_output=True,text=True,timeout=8,check=True).stdout
    persist=lambda updated:journal.persist(ROOT/(args.policy+".json"),updated)
    if record.get("state")=="reverted":
        cleanup=complete_boot_cleanup(record,saved,command)
        print(json.dumps({"policy":args.policy,"direct_restored":True,"guard_removed":True,**cleanup}))
        return
    if record.get("routing_restored") is True:
        result=finalizer.finalize(record,saved,command,persist)
    else:
        restore_direct_firewall_under_guard(record,saved,command)
        result=execute_rollback(record,saved,command,persist)
        if result["direct_route_restored"]:
            updated=journal.read(ROOT/(args.policy+".json"))
            result=finalizer.finalize(updated,saved,command,persist)
    if result.get("direct_restored") is True and result.get("guard_removed") is True:
        finalized=journal.read(ROOT/(args.policy+".json"))
        cleanup=complete_boot_cleanup(finalized,saved,command)
        result={**result,**cleanup}
    print(json.dumps(result))

if __name__=="__main__":main()
