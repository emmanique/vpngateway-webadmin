#!/usr/bin/env python3
"""Generate Pi-hole DNS ACL from current configured LAN interfaces and kernel topology."""
import ipaddress
import json
import subprocess
import sys
import urllib.request

BASE = "http://127.0.0.1:18080/api/v1/network/"
def get(path):
    with urllib.request.urlopen(BASE + path, timeout=5) as reply:
        return json.load(reply)
def main():
    config, topo = get("config"), get("topology")
    draft = config.get("draft") or {}
    lan_names = {v["interface"] for v in draft.get("interfaces", []) if v.get("role") in ("lan", "clients", "client")}
    actual = [i for i in topo.get("interfaces", []) if i.get("interface") in lan_names]
    if not actual or len(actual) != len(lan_names):
        raise ValueError("LAN interfaces missing from current topology")
    sources = set()
    destinations = set()
    for entry in actual:
        cidr = ipaddress.ip_network(entry["network"], strict=False)
        address = ipaddress.ip_address(entry["address"])
        if address not in cidr or address.version != 4:
            raise ValueError("Invalid LAN address / CIDR")
        sources.add(str(cidr))
        destinations.add(str(address))
    if not sources or not destinations:
        raise ValueError("No verified LAN CIDRs")
    nets = ", ".join(sorted(sources))
    rules = ['table inet vpngw_pihole_dns {',
             ' chain local_input {',
             '  type filter hook input priority -10; policy accept;']
    for dest in sorted(destinations):
        rules.append(f'  ip daddr {dest} meta l4proto {{ tcp, udp }} th dport 53 ip saddr != {{ {nets} }} drop')
    rules += [' }', ' chain ingress {',
              '  type filter hook forward priority -10; policy accept;']
    for dest in sorted(destinations):
        rules.append(f'  ct direction original meta l4proto {{ tcp, udp }} ct original ip daddr {dest} ct original proto-dst 53 ip saddr != {{ {nets} }} drop')
    rules += [' }', '}']
    script = "\n".join(rules)+"\n"
    # Validate generated ruleset in a separate network namespace: never destroy
    # the existing ACL before the new rules are known to be syntactically sound.
    check = subprocess.run(["nft", "-c", "-f", "-"], input=script, text=True,
                           capture_output=True, timeout=8)
    if check.returncode:
        raise RuntimeError(check.stderr.strip())
    print(script)
if __name__ == "__main__":
    try: main()
    except Exception as error:
        print(f"DNS ACL generation failed: {error}", file=sys.stderr)
        sys.exit(2)
