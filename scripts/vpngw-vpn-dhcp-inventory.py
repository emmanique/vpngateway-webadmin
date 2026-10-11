#!/usr/bin/env python3
"""Read-only DHCP movement candidates from configured policies and observed LAN neighbors.

Neighbor cache is unauthenticated and incomplete. No result authorizes cutover.
"""
import ipaddress
import re
MAC=re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z',re.I)

def inspect(policies,neighbors):
    by_mac={}
    by_ip={}
    for n in neighbors:
        if not isinstance(n,dict):
            continue
        mac=n.get('mac')
        try:
            ip=str(ipaddress.IPv4Address(n.get('ip')))
        except (ValueError,TypeError):
            continue
        if not isinstance(mac,str) or not MAC.fullmatch(mac):
            continue
        mac=mac.lower()
        if 'FAILED' in n.get('state',[]) or 'INCOMPLETE' in n.get('state',[]):
            continue
        by_mac.setdefault(mac,set()).add(ip)
        by_ip.setdefault(ip,set()).add(mac)
    results=[]
    for policy in policies:
        if not isinstance(policy,dict):
            continue
        pid=policy.get('id')
        mac=policy.get('registered_mac')
        old=policy.get('host_ip')
        if not isinstance(pid,str) or not pid or not isinstance(mac,str) or not MAC.fullmatch(mac):
            results.append({'policy':pid,'status':'identity_not_registered','network_changes':False,'cutover_enabled':False})
            continue
        ips=sorted(by_mac.get(mac.lower(),[]),key=lambda x:int(ipaddress.IPv4Address(x)))
        candidates=[ip for ip in ips if ip!=old]
        conflict=any(len(by_ip[ip])!=1 for ip in ips)
        results.append({'policy':pid,'route':policy.get('destination'),'previous_ipv4':old,
                        'registered_mac':mac.lower(),'candidate_ipv4':candidates,
                        'status':('ambiguous' if conflict or len(ips)>1 else
                                  'dhcp_change_observed' if len(candidates)==1 else
                                  'unchanged_observed' if ips else 'not_observed'),
                        'ownership_confirmed':False,'identity_authenticated':False,
                        'network_changes':False,'cutover_enabled':False})
    return results
