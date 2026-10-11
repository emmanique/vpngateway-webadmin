#!/usr/bin/env python3
"""Pure, fail-closed verification of client-observed cutover proof.

This module does not apply network changes or authorize a production cutover.
"""
import ipaddress
import math
import time

def verify(proof, *, policy, vpn_interface, expected_public_ip=None, now=None):
    errors=[]
    now=time.time() if now is None else now
    if not isinstance(proof,dict):
        return {"verified":False,"errors":["missing_proof"]}
    if proof.get("policy")!=policy:errors.append("policy_mismatch")
    if proof.get("interface")!=vpn_interface:errors.append("interface_mismatch")
    stamp=proof.get("observed_at")
    if type(stamp) not in (int,float) or not math.isfinite(stamp) or not 0 <= now-stamp <= 30:
        errors.append("stale_or_future_proof")
    if expected_public_ip is None:
        errors.append("missing_expected_vpn_egress")
    ip=proof.get("public_ipv4")
    try:
        parsed=ipaddress.IPv4Address(ip)
        if not parsed.is_global: errors.append("non_public_egress")
        if expected_public_ip is not None and str(parsed)!=str(expected_public_ip):
            errors.append("egress_mismatch")
    except (ValueError,TypeError,ipaddress.AddressValueError):
        errors.append("invalid_public_ipv4")
    if proof.get("observation_source")!="verified_client_probe":
        errors.append("untrusted_observation_source")
    for name in ("dns_through_vpn","direct_fallback_blocked",
                 "watchdog_armed","rollback_journal_durable"):
        if proof.get(name) is not True:errors.append("missing_"+name)
    return {"verified":not errors,"errors":errors}
