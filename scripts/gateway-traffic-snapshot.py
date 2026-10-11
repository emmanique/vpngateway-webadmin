#!/usr/bin/env python3
"""Read-only gateway nftables forwarding byte counters; never counts host interface totals.

Run only on the actual forwarding gateway. Explicit per-host accounting rules must
already exist and be verified; missing rules mean no measurement, not zero traffic.
"""
import json
import re
import subprocess
from datetime import datetime, timezone

# Accept only dedicated accounting rules marked with a fixed comment; never
# infer per-host bytes from aggregate interface or NAT counters.
result = subprocess.run(['/usr/sbin/nft', '-j', 'list', 'ruleset'], capture_output=True, text=True, timeout=8, check=True)
ruleset = json.loads(result.stdout)
seen = {}
for item in ruleset.get('nftables', []):
    rule = item.get('rule')
    if not rule or rule.get('family') not in ('ip', 'inet'):
        continue
    comment = rule.get('comment', '')
    match = re.fullmatch(r'vpngw-account:(direct|vpn-[a-z0-9-]+):(192\.168\.1\.\d{1,3}):(rx|tx)', comment)
    if not match:
        continue
    route, host, direction = match.groups()
    # Only dedicated FORWARD accounting rules with counter expressions.
    if rule.get('chain') not in ('forward', 'FORWARD', 'vpngw_forward_account'):
        continue
    counters = [entry['counter'] for entry in rule.get('expr', []) if 'counter' in entry]
    if len(counters) != 1 or not isinstance(counters[0].get('bytes'), int):
        continue
    key = (route, host)
    seen.setdefault(key, {})[direction] = counters[0]['bytes']
hosts = [{'route': route, 'ip': ip, 'rx_bytes': value['rx'], 'tx_bytes': value['tx']}
         for (route, ip), value in seen.items() if 'rx' in value and 'tx' in value]
print(json.dumps({'observed_at': datetime.now(timezone.utc).isoformat(), 'source': 'gateway_nft_forward_accounting', 'hosts': hosts}))
