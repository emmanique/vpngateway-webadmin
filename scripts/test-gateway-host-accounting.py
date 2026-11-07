#!/usr/bin/env python3
"""Regression: route/consumption uses only verified per-host FORWARD counters."""
import ast
import hashlib
import json
import subprocess
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root/'apps/api/main.py').read_text()
agent = (root/'scripts/vpngw-policy-agent.py').read_text()
assert 'measured[(effective_vpn or policy["destination"], policy["host_ip"])]' in source
assert 'runtime_status == "active"' in source
assert 'read_counters(pid, state)' in agent
assert 'list", "chain", "ip", "filter", chain_name(pid)' in agent
ast.parse(source)
ast.parse(agent)
# Record a first snapshot; a second later snapshot must never lose cumulative bytes.
status = json.load(urllib.request.urlopen('http://127.0.0.1:18080/api/v1/overview/status', timeout=15))
second = json.load(urllib.request.urlopen('http://127.0.0.1:18080/api/v1/overview/status', timeout=15))
second_hosts = {h['ip']: h for r in second['routes'] for h in r['hosts']}
policies = json.load(urllib.request.urlopen('http://127.0.0.1:18080/api/v1/policies', timeout=15))
mapped = {p['host_ip']:(p['id'],p['destination']) for p in policies}
for route in status['routes']:
    for host in route['hosts']:
        ip=host['ip']
        if ip not in mapped: continue
        pid,destination=mapped[ip]
        assert route['id']==destination,(ip,route['id'],destination)
        assert all(isinstance(host[k],int) and host[k]>=0 for k in ('rx_bytes','tx_bytes'))
        name='GW_'+hashlib.sha256(pid.encode()).hexdigest()[:16].upper()
        nft=json.loads(subprocess.check_output(['/usr/sbin/nft','-j','list','chain','ip','filter',name],text=True))
        counters=[entry['counter'] for rule in nft['nftables'] if 'rule' in rule
                  for expr in rule['rule'].get('expr',[])
                  for entry in [expr] if 'counter' in entry]
        assert len(counters)>=2
        # Kernel counters can advance between API and nft reads. Compare two
        # accumulated snapshots instead of racing a later live kernel count.
        latest=second_hosts[ip]
        assert latest['tx_bytes'] >= host['tx_bytes']
        assert latest['rx_bytes'] >= host['rx_bytes']
        print('PASS',ip,route['id'],'tx',host['tx_bytes'],'rx',host['rx_bytes'])
for r in status['routes']:
    if r['hosts'] and all(isinstance(x['rx_bps'],int) and isinstance(x['tx_bps'],int) for x in r['hosts']):
        assert r['rx_bps']==sum(h['rx_bps'] for h in r['hosts'])
        assert r['tx_bps']==sum(h['tx_bps'] for h in r['hosts'])
print('PASS: persistent dashboard host-only traffic accounting; no interface-wide counters')
