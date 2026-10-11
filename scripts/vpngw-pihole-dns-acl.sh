#!/bin/sh
set -eu
# Determine the management/LAN interface and subnet from the active network.
# No server-specific IP or CIDR is allowed in the nftables policy.
DNS_PORT="${VPNGW_DNS_PORT:-53}"
LAN_INTERFACE="${VPNGW_LAN_INTERFACE:-}"
python3 - "$LAN_INTERFACE" "$DNS_PORT" <<'PY'
import ipaddress
import json
import re
import subprocess
import sys
interface,port=sys.argv[1:]
if not port.isdecimal() or not 1 <= int(port) <= 65535:
    raise SystemExit("Invalid DNS port")
def ip(*args):
    result=subprocess.run(["/usr/sbin/ip","-j",*args],check=True,text=True,
                          capture_output=True,timeout=5)
    return json.loads(result.stdout)
if not interface:
    default=ip("-4","route","show","default")
    candidates={r["dev"] for r in default if "dev" in r}
    if len(candidates)!=1:
        raise SystemExit("Ambiguous LAN interface; set VPNGW_LAN_INTERFACE")
    interface=candidates.pop()
if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}",interface):
    raise SystemExit("Invalid LAN interface")
entries=ip("-4","addr","show","dev",interface)
addresses=[(info["local"],info["prefixlen"]) for d in entries for info in d.get("addr_info",[])
           if info.get("family")=="inet" and info.get("scope")=="global"]
if len(addresses)!=1:
    raise SystemExit("LAN must have exactly one IPv4 address")
address,prefix=addresses[0]
network=ipaddress.IPv4Network(f"{address}/{prefix}",strict=False)
if network.prefixlen==32:
    raise SystemExit("LAN CIDR unavailable")
name="vpngw_pihole_dns"
script=f"""table inet {name} {{
 chain local_input {{
  type filter hook input priority -10; policy accept;
  ip daddr {address} meta l4proto {{ tcp, udp }} th dport {port} ip saddr != {network} drop
 }}
 chain ingress {{
  type filter hook forward priority -10; policy accept;
  ct direction original meta l4proto {{ tcp, udp }} ct original ip daddr {address} ct original proto-dst {port} ip saddr != {network} drop
 }}
}}
"""
nft="/usr/sbin/nft"
subprocess.run([nft,"-c","-f","-"],input=script,text=True,check=True,timeout=6)
present=subprocess.run([nft,"list","table","inet",name],capture_output=True,timeout=6).returncode==0
batch=(f"delete table inet {name}\n" if present else "")+script
subprocess.run([nft,"-c","-f","-"],input=batch,text=True,check=True,timeout=6)
subprocess.run([nft,"-f","-"],input=batch,text=True,check=True,timeout=6)
print(f"DNS ACL {address} {network} via {interface}")
PY
