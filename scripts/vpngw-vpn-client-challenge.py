#!/usr/bin/env python3
"""Root-side, durable issuance of unpredictable client probe challenges.

Only a future authenticated device collector may receive challenges. This module
has no WebAdmin endpoint, does not distribute secrets, and never modifies routes.
"""
import json
import os
from pathlib import Path
import re
import secrets
import time
import ipaddress

SAFE=re.compile(r'[a-z][a-z0-9-]{1,31}\Z')
def valid_host(host):
    try:
        address=ipaddress.IPv4Address(host)
        return address.is_private and not (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified)
    except (ValueError,TypeError):
        return False

def issue(policy, transaction_id, directory, *, host, now=None):
    if not isinstance(policy,str) or not SAFE.fullmatch(policy) or not isinstance(transaction_id,str) or not SAFE.fullmatch(transaction_id) or not valid_host(host):
        raise ValueError('Unapproved client or transaction')
    directory=Path(directory)
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError('Challenge store unavailable')
    timestamp=time.time() if now is None else now
    nonce=secrets.token_hex(32)
    record={'policy':policy,'host':host,'transaction_id':transaction_id,
            'nonce':nonce,'issued_at':timestamp,'expires_at':timestamp+30}
    # Exclusive creation means an existing trial cannot silently receive a new nonce.
    target=directory/(policy+'-'+transaction_id+'.json')
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(record,f)
            f.flush();os.fsync(f.fileno())
        dirfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
    except Exception:
        # Retain failed marker to fail closed; never overwrite a partially persisted trial.
        raise
    return dict(record,network_changes=False,cutover_enabled=False)

def validate(record, *, policy, transaction_id, host, now=None):
    timestamp=time.time() if now is None else now
    return (isinstance(record,dict) and isinstance(policy,str) and bool(SAFE.fullmatch(policy)) and valid_host(host) and
            record.get('policy')==policy and record.get('host')==host and
            record.get('transaction_id')==transaction_id and
            isinstance(record.get('nonce'),str) and
            bool(re.fullmatch('[0-9a-f]{64}',record['nonce'])) and
            type(record.get('issued_at')) in (int,float) and
            type(record.get('expires_at')) in (int,float) and
            record['issued_at']<=timestamp<record['expires_at'] and
            record['expires_at']-record['issued_at']==30)
