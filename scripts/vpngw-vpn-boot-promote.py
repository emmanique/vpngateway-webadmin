#!/usr/bin/env python3
"""Fail-closed promotion of staged boot guard; only after active guard and armed journal."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time

BASE=Path(__file__).resolve().parent
def load(name):
 spec=importlib.util.spec_from_file_location(name.replace("-","_"),BASE/name)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
boot=load("vpngw-vpn-boot-guard.py")
journal=load("vpngw-vpn-rollback-journal.py")
STAGE=Path("/var/lib/vpngw-vpn-boot-staging")
ACTIVE=boot.STATE

def promote(policy, command, stage_dir=STAGE, active_dir=ACTIVE, journal_dir=Path("/var/lib/vpngw-vpn-transactions")):
    if not boot.NAME.fullmatch(policy):raise ValueError("Invalid policy")
    candidate=stage_dir/(policy+".json")
    if candidate.is_symlink() or not candidate.is_file():raise ValueError("Staged guard unavailable")
    state=boot.validate(json.loads(candidate.read_text()))
    if state["id"]!=policy:raise ValueError("Stage ownership mismatch")
    metadata=candidate.stat()
    if metadata.st_uid!=0 or metadata.st_mode & 0o077:raise ValueError("Unsafe candidate permissions")
    txn=journal.read(journal_dir/(policy+".json"))
    if txn["state"]!="guarded" or txn["deadline"]<=time.time() or txn.get("guard_table")!="vpngw_host_"+policy.replace("-","_"):
        raise ValueError("Guard must be installed and journaled before promotion")
    if txn["snapshot"].get("host")!=state["host"] or txn.get("vpn_interface")!=state["vpn"]:
        raise ValueError("Journal does not identify this host and tunnel")
    table=command("nft","list","table","inet",txn["guard_table"])
    if not all(key in table for key in (state["host"],state["lan"],state["vpn"],state["mac"],"drop")):
        raise RuntimeError("Installed fail-closed guard not verified")
    if active_dir.is_symlink() or not active_dir.is_dir():raise ValueError("Active guard directory unavailable")
    if active_dir.stat().st_uid!=0 or active_dir.stat().st_mode & 0o077:
        raise ValueError("Active guard directory is not private")
    target=active_dir/(policy+".json")
    if target.exists() or target.is_symlink():raise ValueError("Active guard already exists")
    fd,tmp=tempfile.mkstemp(prefix=".promoting-",dir=active_dir)
    try:
        with os.fdopen(fd,"w") as stream:
            os.fchmod(stream.fileno(),0o600)
            json.dump(state,stream,sort_keys=True)
            stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,target)
        directory=os.open(active_dir,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    return {"policy":policy,"boot_guard_active":True,"network_changes":False}
