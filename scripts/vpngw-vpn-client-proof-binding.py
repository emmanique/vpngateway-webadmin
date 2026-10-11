#!/usr/bin/env python3
"""Pure challenge/proof transaction binder: read-only, fail-closed and IPv4-only."""
import importlib.util
from pathlib import Path
ROOT=Path(__file__).resolve().parent
def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),ROOT/name)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
challenge=load('vpngw-vpn-client-challenge.py')
proof=load('vpngw-vpn-client-proof-envelope.py')
def verify(*,issued,envelope,policy,transaction_id,host,secret,now=None):
    if not challenge.validate(issued,policy=policy,transaction_id=transaction_id,host=host,now=now):
        return {'authenticated':False,'error':'challenge_invalid_or_expired','cutover_enabled':False}
    result=proof.verify(envelope,policy=policy,host=issued['host'],
                        transaction_id=transaction_id,expected_nonce=issued['nonce'],
                        secret=secret,now=now)
    return {'authenticated':result.get('authenticated') is True,
            'error':result.get('error'),'cutover_enabled':False,'network_changes':False}
