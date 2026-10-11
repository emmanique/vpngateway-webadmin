#!/usr/bin/env python3
"""Durable, restrictive VPN migration rollback journal; no firewall mutation.

This module manages independent rollback deadlines. A separate verified
executor must be provided before enabling cutovers.
"""
import json
import math
import os
from pathlib import Path
import re
import tempfile
import time

ID=re.compile(r"[a-z][a-z0-9-]{1,31}\Z")
ALLOWED=("prepared","guarded","vpn_pending","confirmed","revert_required","reverted")

def validate(record):
    if not isinstance(record,dict) or not ID.fullmatch(record.get("policy_id","")):
        raise ValueError("Invalid policy")
    if record.get("state") not in ALLOWED: raise ValueError("Invalid rollback state")
    if type(record.get("deadline")) not in (int,float) or not math.isfinite(record["deadline"]) or record["deadline"]<=0:
        raise ValueError("Invalid rollback deadline")
    if not isinstance(record.get("snapshot"),dict):raise ValueError("Missing snapshot")
    snapshot=record["snapshot"]
    if snapshot.get("status")!="snapshot_validated" or snapshot.get("policy")!=record["policy_id"]:
        raise ValueError("Unverified DIRECT snapshot")
    handles=snapshot.get("jump_handles")
    if not isinstance(handles,list) or len(handles)!=2 or any(type(h) is not int or h<=0 for h in handles) or len(set(handles))!=2:
        raise ValueError("DIRECT snapshot incomplete")
    return record

def prepare(policy_id,snapshot,now=None,seconds=180):
    if not isinstance(seconds,int) or not 30<=seconds<=300:
        raise ValueError("Unsafe rollback deadline")
    if not ID.fullmatch(policy_id):raise ValueError("Invalid policy")
    created=time.time() if now is None else now
    result={"schema":1,"policy_id":policy_id,"snapshot":snapshot,
            "deadline":created+seconds,"state":"prepared","created_at":created}
    return validate(result)

def next_state(record, event, now=None):
    rec=validate(record)
    actual=time.time() if now is None else now
    if type(actual) not in (int,float) or not math.isfinite(actual):
        raise ValueError("Invalid transition time")
    allowed={
        ("prepared","guard_installed"):"guarded",
        ("guarded","vpn_route_installed"):"vpn_pending",
        ("vpn_pending","verified"):"confirmed",
        ("prepared","fail"):"revert_required",
        ("guarded","fail"):"revert_required",
        ("vpn_pending","fail"):"revert_required",
        ("revert_required","direct_verified"):"reverted",
    }
    if rec["state"] in ("prepared","guarded","vpn_pending") and actual>=rec["deadline"]:
        event="fail"
    state=allowed.get((rec["state"],event))
    if not state:raise ValueError("Unsafe or impossible state transition")
    if state=="confirmed" and actual>=rec["deadline"]:
        raise ValueError("Rollback deadline elapsed")
    return {**rec,"state":state}

def persist(path, record):
    validate(record)
    target=Path(path)
    if target.is_symlink():raise ValueError("Refusing symlink journal")
    if not target.parent.is_dir():raise ValueError("Journal directory absent")
    fd,tmp=tempfile.mkstemp(prefix=".vpngw-journal-",dir=target.parent)
    try:
        with os.fdopen(fd,"w") as output:
            os.fchmod(output.fileno(),0o600)
            json.dump(record,output,sort_keys=True)
            output.flush();os.fsync(output.fileno())
        os.replace(tmp,target)
        directory=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def read(path):
    return validate(json.loads(Path(path).read_text()))
