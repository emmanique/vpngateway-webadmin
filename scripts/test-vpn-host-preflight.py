#!/usr/bin/env python3
"""Offline regression of VPN host identity, DNS/IPv6 guards and per-profile routes."""
from pathlib import Path
import importlib.util
import subprocess
root=Path(__file__).resolve().parent
def load(filename, name):
    spec=importlib.util.spec_from_file_location(name,root/filename)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
guard=load('vpngw-vpn-host-guard.py','guard')
routes=load('vpngw-vpn-route-commands.py','routes')
for lan in ('wlp2s0','enp1s0'):
    first=guard.render('test2','192.168.1.229','bc:25:11:5b:59:e1',lan,'wg14f16bf1cd9')
    assert 'meta nfproto ipv6 counter drop' in first
    assert 'udp dport 53 oifname != "wg14f16bf1cd9"' in first
    assert 'tcp dport 53 oifname != "wg14f16bf1cd9"' in first
    assert first.count('type filter hook')==2
    assert 'type filter hook forward priority -150; policy accept;' in first
    assert 'iifname "wg14f16bf1cd9" ip daddr 192.168.1.229 counter accept' in first
    assert 'ct state != established' not in first
    check=subprocess.run(['/usr/sbin/nft','-c','-f','-'],input=first,text=True,capture_output=True)
    assert check.returncode==0,check.stderr
    for profile in ('vpn-wireguard-pt','vpn-second'):
        route=routes.generate('192.168.1.229',profile,lan,'wg14f16bf1cd9')
        assert route['stage'][0][4]=='unreachable'
        assert route['cutover'][0][2]=='rule'
        assert route['host']=='192.168.1.229'
a=routes.generate('192.168.1.229','vpn-wireguard-pt','wlp2s0','wg14f16bf1cd9')
b=routes.generate('192.168.1.229','vpn-second','wlp2s0','wg14f16bf1cd9')
assert (a['table'],a['priority']) != (b['table'],b['priority'])
for bad in ('bad mac','ff:ff:ff:ff:ff'):
    try:guard.render('test2','192.168.1.229',bad,'wlp2s0','wg14f16bf1cd9')
    except ValueError:pass
    else:raise AssertionError('Invalid MAC accepted')
print('PASS: 2 physical layouts, 2 VPN profiles, DNS/IPv6 guard, fail-closed route proposal, invalid MAC; no live changes')
