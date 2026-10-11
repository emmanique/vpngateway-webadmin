#!/usr/bin/env python3
"""Durable single-use challenge consumption after HMAC validation.

The caller supplies a trusted secret. Does not provision keys or change routes.
"""
import importlib.util
import json
import os
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('proof_envelope',ROOT/'vpngw-vpn-client-proof-envelope.py')
envelope_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(envelope_module)
SAFE=re.compile(r'[a-z][a-z0-9-]{1,31}\Z')

def consume(envelope, *, policy, host, transaction_id, nonce, secret, directory, now=None):
    if not SAFE.fullmatch(policy) or not SAFE.fullmatch(transaction_id):
        return {'authenticated':False,'error':'invalid_transaction_identity'}
    result=envelope_module.verify(envelope,policy=policy,host=host,
                    transaction_id=transaction_id,expected_nonce=nonce,secret=secret,now=now)
    if result.get('authenticated') is not True:
        return result
    directory=Path(directory)
    if not directory.is_dir() or directory.is_symlink():
        return {'authenticated':False,'error':'challenge_directory_unavailable'}
    import hashlib
    name=hashlib.sha256((policy+'\0'+transaction_id+'\0'+nonce).encode()).hexdigest()+'.json'
    target=directory/name
    payload=json.dumps({'policy':policy,'host':host,'transaction_id':transaction_id,
                        'nonce_hash':hashlib.sha256(nonce.encode()).hexdigest()})
    try:
        fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    except FileExistsError:
        return {'authenticated':False,'error':'challenge_already_consumed'}
    try:
        with os.fdopen(fd,'w') as output:
            output.write(payload)
            output.flush();os.fsync(output.fileno())
        dirfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
    except Exception:
        # Fail closed; retain marker to prevent accepting duplicate proof.
        raise
    return {'authenticated':True,'challenge_consumed':True,
            'network_changes':False}
