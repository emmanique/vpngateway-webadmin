#!/usr/bin/env python3
"""Create non-active, root-owned boot guard candidates; never install active guards.

The active boot directory is ONLY populated during a guarded VPN cutover.
Putting a DIRECT host there prematurely would block its traffic on next boot.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import tempfile

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("boot",HERE/"vpngw-vpn-boot-guard.py")
boot=importlib.util.module_from_spec(spec);spec.loader.exec_module(boot)
STAGE=Path("/var/lib/vpngw-vpn-boot-staging")

def stage(data,directory=STAGE):
    data=boot.validate(data)
    target=Path(directory)
    if target.is_symlink(): raise ValueError("Staging directory must not be a symlink")
    target.mkdir(mode=0o700,parents=True,exist_ok=True)
    if target.stat().st_uid!=0 or target.stat().st_mode & 0o077:
        raise ValueError("Staging directory needs root ownership and private permissions")
    destination=target/(data["id"]+".json")
    if destination.is_symlink():raise ValueError("Refusing symlink")
    fd,tmp=tempfile.mkstemp(prefix=".pending-",dir=target)
    try:
        with os.fdopen(fd,"w") as out:
            os.fchmod(out.fileno(),0o600)
            json.dump(data,out,sort_keys=True)
            out.flush();os.fsync(out.fileno())
        os.replace(tmp,destination)
        dirfd=os.open(target,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    return destination

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("policy")
    parser.add_argument("host")
    parser.add_argument("lan")
    parser.add_argument("vpn")
    parser.add_argument("mac")
    args=parser.parse_args()
    path=stage({"id":args.policy,"host":args.host,"lan":args.lan,
                "vpn":args.vpn,"mac":args.mac,"confirmed":True})
    print(json.dumps({"staged":str(path),"active":False,"network_changes":False}))
if __name__=="__main__":main()
