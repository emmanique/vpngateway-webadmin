#!/usr/bin/env python3
"""Functional API contract test in isolated staging; no host network mutation."""
import json
import urllib.request
import urllib.error
import uuid
import os
import ssl
BASE=os.environ.get('VPNGW_TEST_BASE_URL', '').rstrip('/')
if not BASE.startswith('https://'):
    raise SystemExit('Configure VPNGW_TEST_BASE_URL=https://IP_DA_LAN/api/v1')
CONTEXT=ssl._create_unverified_context()
def call(path,method='GET',payload=None):
    req=urllib.request.Request(BASE+path,method=method,headers={'Content-Type':'application/json','Origin':os.environ.get('VPNGW_TEST_ORIGIN',BASE.split('/api/v1')[0]),'Sec-Fetch-Site':'same-origin'},data=json.dumps(payload).encode() if payload is not None else None)
    try:
        with urllib.request.urlopen(req,timeout=8,context=CONTEXT) as response:
            raw=response.read()
            return response.status,json.loads(raw) if raw else None
    except urllib.error.HTTPError as err:
        return err.code,err.read().decode()
def check(condition,label):
    assert condition,label
    print('PASS',label)
status,live=call('/gateway/live')
check(status==200 and live['scope']=='container' and live['read_only'],'scope isolation and read-only status')
status,config=call('/dns/config')
check(status==200 and config['applied'] is False,'DNS draft not applied')
key='smoke-'+uuid.uuid4().hex[:10]
profile={'id':key,'name':'Functional Test','provider':'Synthetic','protocol':'wireguard','enabled':False}
status,item=call('/connections','POST',profile)
check(status==201 and item['status']=='not_configured','connection creation')
status,_=call('/connections','POST',profile)
check(status==409,'duplicate connection rejected')
status,items=call('/connections')
check(status==200 and any(c['id']==key for c in items),'connection persisted/read-back')
status,_=call('/policies','POST',{'id':key,'host_ip':'10.77.88.99','destination':key,'failure_mode':'direct'})
check(status==422,'unsafe direct fallback rejected')
status,_=call('/policies','POST',{'id':key,'host_ip':'invalid','destination':'direct','failure_mode':'block'})
check(status==422,'invalid host IP rejected')
status,_=call('/connections/'+key,'DELETE')
check(status==204,'synthetic connection cleaned')
print('RESULT 8 functional API checks passed; browser and dataplane remain separately tested')
