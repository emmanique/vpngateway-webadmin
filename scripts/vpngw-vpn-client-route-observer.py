#!/usr/bin/env python3
"""Read-only, generic IPv4 kernel route observation; never proves client traffic."""
import argparse
import ipaddress
import json
import re
import subprocess

def check(policy,host,tunnel,table,lan,wan=None,runner=subprocess.run):
    if not re.fullmatch(r'[a-z][a-z0-9-]{1,31}',policy):
        raise ValueError('Invalid policy identifier')
    ipaddress.IPv4Address(host)
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}',lan) or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}',tunnel):
        raise ValueError('Invalid network interface')
    if type(table) is not int or table<1 or table>4294967295:
        raise ValueError('Invalid routing table')
    wan=lan if wan is None else wan
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}',wan):
        raise ValueError('Invalid WAN interface')
    response=runner(['ip','-4','route','get','1.1.1.1','from',host,'iif',lan],
                    capture_output=True,text=True,timeout=6)
    output=response.stdout if response.returncode==0 else ''
    uses_vpn=bool(re.search(r'\bdev '+re.escape(tunnel)+r'\b',output) and
                  re.search(r'\btable '+str(table)+r'\b',output))
    direct=bool(re.search(r'\bdev '+re.escape(wan)+r'\b',output)) and not uses_vpn
    return {'policy':policy,'host':host,'kernel_vpn_route':uses_vpn,
            'kernel_direct_route':direct,'route_lookup_ok':response.returncode==0,
            'client_egress_verified':False,'dns_leak_verified':False,
            'cutover_enabled':False,'network_changes':False}
if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for name in ('policy','host','tunnel','table','lan'):parser.add_argument(name)
    parser.add_argument('--wan')
    a=parser.parse_args()
    print(json.dumps(check(a.policy,a.host,a.tunnel,int(a.table),a.lan,a.wan)))
