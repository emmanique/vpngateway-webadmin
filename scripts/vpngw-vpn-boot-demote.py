#!/usr/bin/env python3
"""Remove a policy's persisted boot guard only after verified DIRECT rollback."""
import json
import os
from pathlib import Path

DEFAULT=Path("/etc/vpngw-policy-agent/persistent-vpn")

def demote(record,original,command,directory=DEFAULT):
    policy=record["policy_id"]
    if record.get("state")!="reverted" or record.get("routing_restored") is not True:
        raise ValueError("DIRECT rollback not finalized")
    if record.get("guard_preserved") is not False:
        raise ValueError("Host firewall guard not removed")
    expected="vpngw_host_"+policy.replace("-","_")
    if record.get("guard_table")!=expected:
        raise ValueError("Unexpected guard")
    plan=original.get("plan",{})
    if original.get("status")!="active" or plan.get("destination")!="direct":
        raise ValueError("Original DIRECT state missing")
    target=Path(directory)/(policy+".json")
    if target.is_symlink():raise ValueError("Symlink rejected")
    if not target.exists():return {"policy":policy,"boot_config_removed":False,"already_absent":True}
    info=target.stat()
    if info.st_uid!=0 or info.st_mode & 0o077:raise ValueError("Boot config has unsafe permissions")
    data=json.loads(target.read_text())
    if data.get("id")!=policy or data.get("host")!=plan.get("host") or data.get("vpn")!=record.get("vpn_interface"):
        raise ValueError("Boot config differs from transaction")
    # Never remove persistence until active DIRECT forwarding and absence of
    # both the migration guard and the boot-time guard are verified.
    for table in (expected,"vpngw_boot_"+policy.replace("-","_")):
        try:command("nft","list","table","inet",table)
        except Exception:pass
        else:raise RuntimeError("Active guard remains: "+table)
    name="GW_"+__import__("hashlib").sha256(policy.encode()).hexdigest()[:16].upper()
    chain=command("nft","list","chain","ip","filter",name)
    nat=command("nft","list","table","ip","vpngw_"+name.lower())
    if "accept" not in chain or 'oifname "'+plan["wan"]+'"' not in nat:
        raise RuntimeError("DIRECT not verified before demotion")
    target.unlink()
    directory_fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(directory_fd)
    finally:os.close(directory_fd)
    return {"policy":policy,"boot_config_removed":True}
