#!/usr/bin/env python3
"""Read-only smoke test for live operational pages."""
import json
import os
import urllib.request

base = os.environ.get('VPNGW_TEST_BASE_URL', 'http://127.0.0.1:18080/api/v1').rstrip('/')
def get(path):
    with urllib.request.urlopen(base + path, timeout=15) as response:
        assert response.status == 200
        return json.load(response)
metrics = get('/monitoring/hosts')
assert metrics['scope'] == 'managed-host-forward-only'
assert all(isinstance(h['ip'], str) and isinstance(h['route'], str) for h in metrics['hosts'])
assert {h['ip'] for h in metrics['hosts']} == {p['host_ip'] for p in get('/policies')}
print('PASS monitoring contains managed hosts exclusively')
logs = get('/logs/vpn')
assert isinstance(logs['events'], list) and len(logs['events']) <= 100
assert all(set(e) == {'at', 'profile', 'event', 'detail'} for e in logs['events'])
print('PASS logs recent VPN events')
system = get('/system/health')
assert system['webadmin'] == 'operational' and system['database'] == 'accessible'
assert system['profiles'] == len(get('/connections'))
assert system['policies'] == len(get('/policies'))
assert isinstance(system['disk_total_bytes'], int) and system['disk_total_bytes'] > 0
assert 0 <= system['disk_used_bytes'] <= system['disk_total_bytes']
print('PASS application, storage, policy and VPN module status')
