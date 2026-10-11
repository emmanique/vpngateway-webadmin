#!/usr/bin/env python3
"""Verify a per-transaction client proof envelope. No client key is provisioned here.

HMAC keys must be distributed out of band and never accepted from the WebAdmin browser.
This verifier is independent from route mutation and cutover authorization.
"""
import hashlib
import hmac
import json
import re
import time

HEX=re.compile(r'[0-9a-f]{64}\Z')
FIELDS=('policy','host','transaction_id','nonce','observed_at','public_ipv4',
        'dns_through_vpn','direct_fallback_blocked')

def canonical(proof):
    return json.dumps({key:proof[key] for key in FIELDS},
                      separators=(',',':'),sort_keys=True,allow_nan=False).encode()

def verify(envelope, *, policy, host, transaction_id, expected_nonce,
           secret, now=None):
    now=time.time() if now is None else now
    if not isinstance(envelope,dict) or not isinstance(envelope.get('proof'),dict):
        return {'authenticated':False,'error':'missing_envelope'}
    proof=envelope['proof']
    if not isinstance(secret,bytes) or len(secret)<32:
        return {'authenticated':False,'error':'key_unavailable'}
    if (proof.get('policy'),proof.get('host'),proof.get('transaction_id'),
        proof.get('nonce'))!=(policy,host,transaction_id,expected_nonce):
        return {'authenticated':False,'error':'identity_or_challenge_mismatch'}
    timestamp=proof.get('observed_at')
    if type(timestamp) not in (int,float) or not 0<=now-timestamp<=30:
        return {'authenticated':False,'error':'stale_proof'}
    digest=envelope.get('hmac_sha256')
    if not isinstance(digest,str) or not HEX.fullmatch(digest):
        return {'authenticated':False,'error':'invalid_signature'}
    try:
        expected=hmac.new(secret,canonical(proof),hashlib.sha256).hexdigest()
    except (KeyError,ValueError,TypeError):
        return {'authenticated':False,'error':'invalid_payload'}
    if not hmac.compare_digest(digest,expected):
        return {'authenticated':False,'error':'signature_mismatch'}
    return {'authenticated':True,'proof':proof,'network_changes':False}
