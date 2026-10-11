#!/usr/bin/env python3
"""Per-host routing proposal; no shell execution and no kernel mutation."""
import hashlib
import ipaddress
import re
def _iface(value):
    if not isinstance(value,str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}",value):
        raise ValueError("Invalid interface")
    return value
def generate(host_ip, profile_id, lan, vpn):
    host=str(ipaddress.IPv4Address(host_ip))
    if not ipaddress.IPv4Address(host).is_private:
        raise ValueError("Invalid client address")
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}",profile_id):
        raise ValueError("Invalid VPN ID")
    lan,vpn=_iface(lan),_iface(vpn)
    if lan==vpn:
        raise ValueError("VPN must differ from LAN")
    key=int(hashlib.sha256((profile_id+":"+host).encode()).hexdigest()[:8],16)
    table=20000+key%20000
    priority=10000+key%10000
    return {"host":host,"vpn":vpn,"lan":lan,"table":table,"priority":priority,
        "stage":[["ip","-4","route","replace","unreachable","default","metric","42700","table",str(table)],
                 ["ip","-4","route","replace","default","dev",vpn,"metric","100","table",str(table)]],
        "cutover":[["ip","-4","rule","add","pref",str(priority),"iif",lan,"from",host+"/32","lookup",str(table)]],
        "fail_closed_test":["ip","-4","route","get","1.1.1.1","from",host,"iif",lan],
        "revoke":[["ip","-4","rule","del","pref",str(priority),"iif",lan,"from",host+"/32","lookup",str(table)]]}
