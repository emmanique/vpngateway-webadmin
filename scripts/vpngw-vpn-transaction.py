#!/usr/bin/env python3
"""Host-scoped VPN cutover helpers; called under policy-agent exclusive lock."""
import hashlib
import importlib.util
import ipaddress
import subprocess
from pathlib import Path

def load(name):
    path=Path(__file__).with_name(name+'.py')
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def argv_run(args, input_text=None, verify=True):
    p=subprocess.run(args,input=input_text,text=True,capture_output=True,timeout=12)
    if verify and p.returncode:
        raise ValueError('Kernel command failed: '+str(args[:3])+': '+p.stderr.strip()[:180])
    return p

def resources(host, profile, lan, vpn):
    return load('vpngw-vpn-route-commands').generate(host,profile,lan,vpn)

def guard_text(pid, host, mac, lan, vpn, dns):
    return load('vpngw-vpn-host-guard').render(pid,host,mac,lan,vpn,dns)

def filter_text(pid, host, mac, lan, vpn):
    return load('vpngw-vpn-filter-batch').generate(pid,host,mac,lan,vpn)

def table_name(pid):
    return 'vpngw_vpn_'+hashlib.sha256(pid.encode()).hexdigest()[:12]

def ensure_direct_nat(pid, plan):
    """Restore per-host DIRECT NAT after reboot without opening VPN guards."""
    name='vpngw_gw_'+hashlib.sha256(pid.encode()).hexdigest()[:16]
    exists=argv_run(['/usr/sbin/nft','list','table','ip',name],verify=False)
    if exists.returncode==0:
        if 'masquerade' not in exists.stdout:
            raise ValueError('Existing DIRECT NAT incomplete')
        return
    import ipaddress
    import re
    host=str(ipaddress.IPv4Address(plan['host']))
    wan=plan['wan']
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',wan):
        raise ValueError('Invalid WAN')
    extra=(f"""    chain no_redirect {{
        type filter hook output priority -10; policy accept;
        ip daddr {host} icmp type redirect counter drop
    }}
""" if plan.get('shared') else '')
    script=f"""table ip {name} {{
    chain postrouting {{
        type nat hook postrouting priority 110; policy accept;
        ip saddr {host} oifname "{wan}" counter masquerade
    }}
{extra}}}
"""
    argv_run(['/usr/sbin/nft','-c','-f','-'],script)
    argv_run(['/usr/sbin/nft','-f','-'],script)


def ensure_route_table(r, interface_up):
    for cmd in r['stage'][:1]:
        argv_run(['/usr/sbin/'+cmd[0]]+cmd[1:])
    if interface_up:
        argv_run(['/usr/sbin/'+r['stage'][1][0]]+r['stage'][1][1:])

def ensure_rule(r):
    cmd=['/usr/sbin/'+r['cutover'][0][0]]+r['cutover'][0][1:]
    rules=argv_run(['/usr/sbin/ip','-4','rule','show']).stdout
    entry=str(r['priority'])+':'
    existing=[line for line in rules.splitlines() if line.strip().startswith(entry)]
    if existing:
        if len(existing)!=1 or r['host'] not in existing[0] or 'lookup '+str(r['table']) not in existing[0]:
            raise ValueError('Policy routing priority collision')
        return
    argv_run(cmd)

def remove_rule(r):
    argv_run(['/usr/sbin/'+r['revoke'][0][0]]+r['revoke'][0][1:],verify=False)

def remove_table(r):
    argv_run(['/usr/sbin/ip','-4','route','flush','table',str(r['table'])],verify=False)

def replace_guard(text, pid):
    name=table_name(pid)
    exists=argv_run(['/usr/sbin/nft','list','table','inet',name],verify=False).returncode==0
    batch=('delete table inet '+name+'\n' if exists else '')+text
    argv_run(['/usr/sbin/nft','-c','-f','-'],batch)
    argv_run(['/usr/sbin/nft','-f','-'],batch)

def remove_guard(pid):
    argv_run(['/usr/sbin/nft','delete','table','inet',table_name(pid)],verify=False)

def stage(pid, plan, profile, vpn, dns, connected):
    r=resources(plan['host'],profile,plan['lan'],vpn)
    guard=guard_text(pid,plan['host'],plan['registered_mac'],plan['lan'],vpn,dns)
    filt=filter_text(pid,plan['host'],plan['registered_mac'],plan['lan'],vpn)
    argv_run(['/usr/sbin/nft','-c','-f','-'],filt)
    # This table is installed first: no DIRECT egress while changes are staged.
    replace_guard(guard,pid)
    ensure_route_table(r,connected)
    return r,filt

def apply_filter(filt):
    argv_run(['/usr/sbin/nft','-f','-'],filt)

def observed(host, lan):
    return argv_run(['/usr/sbin/ip','-4','route','get','1.1.1.1','from',host,'iif',lan],verify=False)
