#!/usr/bin/env python3
"""Offline IPv4 DHCP host-binding planner. No firewall, IP or policy mutations.

MAC alone is not cryptographic identity: caller must verify LAN neighbor/lease
ownership, uniqueness and authentication before production application.
"""
import ipaddress
import re

MAC=re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z',re.I)
ID=re.compile(r'[a-z][a-z0-9-]{1,31}\Z')

def normal_ip(value):
    addr=ipaddress.IPv4Address(value)
    if not addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        raise ValueError('Unsupported client IPv4')
    return str(addr)

def plan(*,policy_id,profile_id,configured_ip,configured_mac,observed_ip,observed_mac,
         ownership_confirmed=False,identity_authenticated=False,ip_conflict=False):
    if not isinstance(policy_id,str) or not ID.fullmatch(policy_id) or not isinstance(profile_id,str) or not ID.fullmatch(profile_id):
        raise ValueError('Invalid policy or VPN profile')
    if not isinstance(configured_mac,str) or not MAC.fullmatch(configured_mac) or configured_mac.lower() in ('00:00:00:00:00:00','ff:ff:ff:ff:ff:ff'):
        raise ValueError('Client MAC must come from registered host')
    old_ip=normal_ip(configured_ip)
    new_ip=normal_ip(observed_ip)
    identity_matches=isinstance(observed_mac,str) and configured_mac.lower()==observed_mac.lower()
    safe=(identity_matches and ownership_confirmed is True and identity_authenticated is True and ip_conflict is False)
    changed=old_ip!=new_ip
    return {'policy':policy_id,'profile':profile_id,'previous_ipv4':old_ip,'observed_ipv4':new_ip,
            'ip_changed':changed,'mac_matches':identity_matches,'identity_verified':safe,
            'status':'no_change' if safe and not changed else 'rebind_proposal' if safe else 'blocked',
            'actions':(['revoke_old_ip_ownership_and_rules','install_new_ip_guard_before_egress',
                       'replace_per_host_routes_nat_dns_atomically','verify_client_then_commit']
                       if safe and changed else []),
            'blockers':([reason for reason,failed in (
                ('mac_mismatch',not identity_matches),
                ('lease_or_neighbor_unverified',ownership_confirmed is not True),
                ('client_authentication_missing',identity_authenticated is not True),
                ('ip_conflict',ip_conflict is not False)) if failed]),
            'applied':False,'cutover_enabled':False,'network_changes':False}
