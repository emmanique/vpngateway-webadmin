#!/usr/bin/env python3
"""Passive host discovery for isolated WebAdmin; no probes or network changes."""
import importlib.util
import ipaddress
import json
import subprocess
import os
from datetime import datetime, timezone
from pathlib import Path

base = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('topology', base / 'network-topology.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
topology = module.detect()
allowed = {i['interface']: ipaddress.ip_network(i['network']) for i in topology['interfaces'] if i['address'] and i['operstate'] == 'UP' and i['interface'] != 'docker0' and not i['interface'].startswith(('br-', 'veth'))}
excluded = {i['address'] for i in topology['interfaces'] if i['address']} | {r['gateway'] for r in topology['default_routes'] if r.get('gateway')}
entries = json.loads(subprocess.check_output(['/usr/sbin/ip', '-j', 'neigh', 'show'], timeout=5))
hosts = []
for item in entries:
    ip = item.get('dst', '')
    dev = item.get('dev')
    state = item.get('state', [])
    try:
        address = ipaddress.ip_address(ip)
        if address.version != 4 or dev not in allowed or address not in allowed[dev] or ip in excluded or not item.get('lladdr') or any(s in state for s in ('FAILED','INCOMPLETE')):
            continue
    except ValueError:
        continue
    hosts.append({'ip': ip, 'mac': item['lladdr'].lower(), 'name': None, 'name_source': None, 'interface': dev, 'state': state})
result = {'observed_at': datetime.now(timezone.utc).isoformat(), 'topology': topology, 'neighbors': sorted(hosts, key=lambda h: ipaddress.ip_address(h['ip']))}
target = Path(os.environ.get('VPNGW_DISCOVERY_OUTPUT', '/var/lib/vpngw/shared/discovery.json'))
target.parent.mkdir(parents=True, exist_ok=True)
tmp = target.with_suffix('.tmp')
tmp.write_text(json.dumps(result), encoding='utf-8')
tmp.chmod(0o644)
tmp.replace(target)
print('snapshot hosts:', len(hosts))
