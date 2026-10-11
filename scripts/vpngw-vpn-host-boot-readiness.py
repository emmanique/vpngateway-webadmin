#!/usr/bin/env python3
"""Read-only boot persistence safety gate for an upcoming per-host VPN cutover."""
import importlib.util
import json
from pathlib import Path

BASE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("boot", BASE/"vpngw-vpn-boot-guard.py")
boot=importlib.util.module_from_spec(spec);spec.loader.exec_module(boot)

def audit(policy,host,lan,vpn,mac,directory=boot.STATE):
    path=Path(directory)/(policy+".json")
    result={"policy":policy,"boot_guard_ready":False,"cutover_enabled":False,"network_changes":False}
    if not path.is_file() or path.is_symlink():
        result["reason"]="No verified early-boot guard configuration"
        return result
    try:
        record=boot.validate(json.loads(path.read_text()))
        stat=path.stat()
        if stat.st_uid!=0 or stat.st_mode & 0o077:
            raise ValueError("Guard configuration ownership or permissions unsafe")
        if (record["id"],record["host"],record["lan"],record["vpn"],record["mac"].lower()) != (policy,host,lan,vpn,mac.lower()):
            raise ValueError("Persisted boot guard differs from requested cutover")
    except (ValueError,KeyError,TypeError, OSError, json.JSONDecodeError) as exc:
        result["reason"]=str(exc)
        return result
    result["boot_guard_ready"]=True
    result["reason"]="Verified on-disk early-boot fail-closed guard"
    return result
