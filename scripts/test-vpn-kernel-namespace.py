#!/usr/bin/env python3
"""Destructive networking test, ONLY run with unshare --net!"""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile

def run(*args):
    p=subprocess.run(args,text=True,capture_output=True)
    if p.returncode:
        raise RuntimeError(str(args)+': '+p.stderr)
    return p.stdout
assert Path('/proc/self/ns/net').stat().st_ino != Path('/proc/1/ns/net').stat().st_ino, 'ISOLATED netns REQUIRED'
host='192.0.2.29'
profile='vpn-wireguard-pt'
wg='wg'+hashlib.sha256(profile.encode()).hexdigest()[:11]
chain='GW_'+hashlib.sha256(b'test2').hexdigest()[:16].upper()
run('ip','link','add','lanmock','type','veth','peer','name','lanpeer')
run('ip','link','set','lanpeer','up')
for nic,addr in [('lanmock','192.0.2.1/24'),(wg,'10.2.0.2/32')]:
    if nic == wg:
        run('ip','link','add',nic,'type','dummy')
    run('ip','addr','add',addr,'dev',nic)
    run('ip','link','set',nic,'up')
run('ip','route','add','default','via','192.0.2.254','dev','lanmock')
run('nft','add','table','ip','filter')
run('nft','add','chain','ip','filter','DOCKER-USER')
run('nft','add','chain','ip','filter',chain)
run('nft','add','rule','ip','filter',chain,'iifname','lanmock','ip','saddr',host,'ether','saddr','!=','02:00:00:00:00:29','drop','comment','vpngw_identity_guard')
root=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('policy_agent',root/'vpngw-policy-agent.py')
agent=importlib.util.module_from_spec(spec);spec.loader.exec_module(agent)
with tempfile.TemporaryDirectory() as tmp:
    agent.BASE=Path(tmp)
    agent.wireguard_status=lambda pid: {'interface':wg,'connected':True} if pid==profile else {'interface':None,'connected':False}
    state={'status':'active','applied':True,'deadline':None,'plan':{'host':host,'lan':'lanmock','wan':'lanmock','gateway':'192.0.2.254','destination':'direct','shared':True,'registered_mac':'02:00:00:00:00:29'}}
    agent.save_state('test2',state)
    v=agent.vpn_transition('test2',profile,'10.2.0.1',arm_timeout=False)
    print('DIRECT_TO_VPN',v,flush=True)
    assert v['destination']==profile
    assert 'dev '+wg in run('ip','route','get','1.1.1.1','from',host,'iif','lanmock')
    run('ip','link','delete',wg)
    probe=subprocess.run(['ip','route','get','1.1.1.1','from',host,'iif','lanmock'],capture_output=True)
    assert probe.returncode!=0,'VPN DOWN EXPOSED DIRECT'
    print('FAIL_CLOSED',probe.returncode,flush=True)
    agent.wireguard_status=lambda pid: {'interface':None,'connected':False}
    v=agent.vpn_transition('test2','direct')
    assert v['destination']=='direct'
    assert 'dev lanmock' in run('ip','route','get','1.1.1.1','from',host,'iif','lanmock')
    print('VPN_TO_DIRECT',v,flush=True)
    second='vpn-second'
    second_iface='wg'+hashlib.sha256(second.encode()).hexdigest()[:11]
    for nic in (wg,second_iface):
        run('ip','link','add',nic,'type','dummy')
        run('ip','addr','add','10.2.0.3/32' if nic==second_iface else '10.2.0.2/32','dev',nic)
        run('ip','link','set',nic,'up')
    agent.wireguard_status=lambda pid: {'interface': ('wg'+hashlib.sha256(pid.encode()).hexdigest()[:11]),'connected':True}
    assert agent.vpn_transition('test2',profile,'10.2.0.1',arm_timeout=False)['destination']==profile
    swapped=agent.vpn_transition('test2',second,'10.2.0.1',arm_timeout=False)
    assert swapped['destination']==second
    assert 'dev '+second_iface in run('ip','route','get','1.1.1.1','from',host,'iif','lanmock')
    print('VPN_A_TO_VPN_B',swapped,flush=True)
    blocked=agent.vpn_transition('test2','blocked')
    assert blocked['destination']=='blocked'
    print('VPN_TO_BLOCKED',blocked,flush=True)
    # The block policy must also be able to move to a VPN without DIRECT.
    again=agent.vpn_transition('test2',profile,'10.2.0.1',arm_timeout=False)
    assert again['destination']==profile
    print('BLOCKED_TO_VPN',again,flush=True)
    assert agent.vpn_transition('test2','blocked')['destination']=='blocked'
    # Mock only systemd, leaving nft/ip running in this isolated namespace.
    system_run=subprocess.run
    events=[]
    def without_host_timer(argv,*args,**kwargs):
        if argv[0] in ('/usr/bin/systemd-run','/usr/bin/systemctl'):
            events.append(argv)
            return subprocess.CompletedProcess(argv,0,'','')
        return system_run(argv,*args,**kwargs)
    subprocess.run=without_host_timer
    try:
        pending=agent.vpn_transition('test2',profile,'10.2.0.1')
        assert pending['confirmation_required'] and pending['deadline']
        assert any(x[0]=='/usr/bin/systemd-run' for x in events)
        confirmed=agent.confirm_vpn('test2')
        assert confirmed['confirmed']
        assert not agent.read_state('test2').get('vpn_pending')
        print('TIMED_CONFIRMATION',confirmed,flush=True)
        agent.recover_active_policy('test2',agent.read_state('test2'))
        assert 'dev '+wg in run('ip','route','get','1.1.1.1','from',host,'iif','lanmock')
        run('ip','link','delete',wg)
        agent.wireguard_status=lambda pid: {'interface':None,'connected':False}
        agent.recover_active_policy('test2',agent.read_state('test2'))
        down=subprocess.run(['ip','route','get','1.1.1.1','from',host,'iif','lanmock'],capture_output=True)
        assert down.returncode!=0,'boot restore allowed unsafe direct fallback'
        print('BOOT_RECOVERY_FAIL_CLOSED',down.returncode,flush=True)
    finally:
        subprocess.run=system_run
print('PASS: isolated DIRECT/VPN, BLOCKED/VPN, VPN A/VPN B, outage fail-closed, timed confirmation, reboot recovery')
