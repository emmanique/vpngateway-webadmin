#!/usr/bin/env python3
"""Read-only strict validation of legacy DIRECT forwarding before cutover."""
import re

def audit(pid, chain, docker_user, nat, state):
    name="GW_"+__import__("hashlib").sha256(pid.encode()).hexdigest()[:16].upper()
    jumps=re.findall(r"\bjump "+re.escape(name)+r"\b[^\n]*# handle (\d+)\b",docker_user)
    if len(jumps)!=2 or len(set(jumps))!=2:
        raise ValueError("Expected exactly two unique legacy DIRECT jump handles")
    if not state or state.get("status")!="active" or state.get("plan",{}).get("destination")!="direct":
        raise ValueError("DIRECT policy not active")
    plan=state["plan"]
    host=plan["host"]
    if not re.search(r"\b"+re.escape(host)+r"\b",docker_user):
        raise ValueError("No matching DIRECT host in jump list")
    if not all(x in chain for x in ('iifname "'+plan["lan"]+'"','oifname "'+plan["wan"]+'"',"accept")):
        raise ValueError("Legacy forward chain cannot be verified")
    if not all(x in nat for x in (host,'oifname "'+plan["wan"]+'"',"masquerade")):
        raise ValueError("Legacy source NAT cannot be verified")
    return {"status":"snapshot_validated","host":host,"policy":pid,
            "jump_handles":[int(h) for h in jumps],
            "chain":name,"active":True,"network_changes":False,
            "blockers":["No atomic DIRECT-to-VPN switch implemented",
                        "No independent timed rollback installed"]}
