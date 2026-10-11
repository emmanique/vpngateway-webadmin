#!/usr/bin/env python3
"""Read-only verification against root-side issued challenge (not browser supplied).

Proof acceptance is intentionally separate from production cutover authorization.
"""
import importlib.util
import json
from pathlib import Path

BASE=Path(__file__).resolve().parent
def module(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),BASE/name)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj
challenge=module('vpngw-vpn-client-challenge.py')
binding=module('vpngw-vpn-client-proof-binding.py')

def verify_stored(*,policy,transaction_id,host,envelope,secret,directory,now=None):
    if not isinstance(policy,str) or not challenge.SAFE.fullmatch(policy) or not isinstance(transaction_id,str) or not challenge.SAFE.fullmatch(transaction_id) or not challenge.valid_host(host):
        return {'authenticated':False,'error':'unauthorized_identity'}
    directory=Path(directory)
    if not directory.is_dir() or directory.is_symlink():
        return {'authenticated':False,'error':'challenge_store_unavailable'}
    entry=directory/(policy+'-'+transaction_id+'.json')
    try:
        if entry.is_symlink() or not entry.is_file():
            raise ValueError('challenge_missing')
        issued=json.loads(entry.read_text())
    except (OSError,ValueError,json.JSONDecodeError):
        return {'authenticated':False,'error':'challenge_unavailable'}
    return binding.verify(issued=issued,envelope=envelope,policy=policy,
                          transaction_id=transaction_id,host=host,secret=secret,now=now)
