#!/usr/bin/env python3
"""Read-only functional smoke tests against isolated Docker staging."""
import json
from urllib.request import urlopen
from urllib.error import HTTPError
base='http://127.0.0.1:18080'
for path in ('/','/api/v1/connections','/api/v1/policies','/api/v1/gateway/live','/api/v1/dns/config'):
    with urlopen(base+path, timeout=8) as res:
        assert res.status==200, path
        content=res.read()
        if path=='/':
            assert b'/assets/' in content
        elif path.endswith('/gateway/live'):
            data=json.loads(content)
            assert data['scope']=='container',data
            assert data['read_only'] is True
        print('PASS',path)

try:
    urlopen(base+'/api/v1/network/topology', timeout=8)
except HTTPError as err:
    assert err.code==503
    print('EXPECTED 503 /api/v1/network/topology (isolated namespace)')
else:
    print('PASS /api/v1/network/topology')
