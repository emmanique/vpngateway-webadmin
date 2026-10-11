#!/usr/bin/env python3
"""Independent transaction deadline watchdog. No host changes without a journal."""
import fcntl
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

BASE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("journal",BASE/"vpngw-vpn-rollback-journal.py")
journal=importlib.util.module_from_spec(spec);spec.loader.exec_module(journal)
ROOT=Path("/var/lib/vpngw-vpn-transactions")
ACTIVE={"prepared","guarded","vpn_pending","revert_required"}

def candidates(directory,now):
    pending=[]
    for path in sorted(Path(directory).glob("*.json")):
        if not journal.ID.fullmatch(path.stem):
            raise ValueError("Unexpected journal filename")
        record=journal.read(path)
        if record["policy_id"]!=path.stem:
            raise ValueError("Journal filename/identity mismatch")
        needs_cleanup=(record["state"]=="reverted" and (Path("/etc/vpngw-policy-agent/persistent-vpn")/(record["policy_id"]+".json")).exists())
        if needs_cleanup or (record["state"] in ACTIVE and (record["deadline"]<=now or record["state"]=="revert_required")):
            pending.append((path,record))
    return pending

def scan(directory=ROOT,now=None,executor=None):
    now=time.time() if now is None else now
    # A corrupt journal must never suppress rollback processing for other hosts.
    # Fail loudly for the corrupt identity while continuing independent transactions.
    tasks=[]
    results=[]
    for path in sorted(Path(directory).glob("*.json")):
        try:
            if not journal.ID.fullmatch(path.stem):
                raise ValueError("Unexpected journal filename")
            record=journal.read(path)
            if record["policy_id"]!=path.stem:
                raise ValueError("Journal filename/identity mismatch")
            needs_cleanup=(record["state"]=="reverted" and
                (Path("/etc/vpngw-policy-agent/persistent-vpn")/(record["policy_id"]+".json")).exists())
            if needs_cleanup or (record["state"] in ACTIVE and
                (record["deadline"]<=now or record["state"]=="revert_required")):
                tasks.append((path,record))
        except Exception as exc:
            results.append({"policy":path.stem,"status":"rollback_failed",
                            "error":"Invalid rollback journal: "+str(exc)})
    for path,record in tasks:
        if executor is None:
            # Never claim recovery if an executor has not been supplied.
            results.append({"policy":record["policy_id"],"status":"rollback_required_not_executed"})
            continue
        try:
            outcome=executor(record["policy_id"])
            # An invoked executor is not proof of a completed rollback.
            if not isinstance(outcome,dict) or outcome.get("direct_restored") is not True or outcome.get("guard_removed") is not True or not (outcome.get("boot_config_removed") is True or outcome.get("already_absent") is True):
                raise RuntimeError("Executor did not confirm complete DIRECT restoration")
            updated=journal.read(path)
            if updated.get("state")!="reverted":
                raise RuntimeError("Rollback journal was not durably finalized")
            results.append({"policy":record["policy_id"],"status":"rollback_verified"})
        except Exception as exc:
            results.append({"policy":record["policy_id"],"status":"rollback_failed","error":str(exc)})
    return results

def invoke_executor(policy):
    response=subprocess.run(
        ["/usr/bin/python3","/usr/local/libexec/vpngw-vpn-rollback-executor.py",policy,"--execute"],
        capture_output=True,text=True,timeout=30,check=True)
    return json.loads(response.stdout)


def main():
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    with open("/run/vpngw-vpn-rollback-watchdog.lock","w") as handle:
        fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        results=scan(executor=invoke_executor)
    print(json.dumps(results))
    return 2 if any(x["status"] in ("rollback_failed","rollback_required_not_executed") for x in results) else 0

if __name__=="__main__":sys.exit(main())
