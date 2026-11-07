#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
unshare --net -- bash -euo pipefail -c '
ip link set lo up
ip link add lan0 type dummy
ip link add wan0 type dummy
ip link add wg123456789ab type dummy
for d in lan0 wan0 wg123456789ab; do ip link set "$d" up; done
ip addr add 10.50.1.1/24 dev lan0
ip addr add 198.18.4.2/24 dev wan0
ip route add default dev wan0
python3 - <<\PY
import importlib.util, subprocess
path="scripts/vpngw-vpn-recovery-plan.py"
spec=importlib.util.spec_from_file_location("recovery",path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
config={"id":"example-host","host":"10.50.1.22","lan":"lan0","vpn":"wg123456789ab","mac":"12:34:56:78:9a:bc","confirmed":True}
plan=module.build(config,observed_lan=True,observed_vpn=True,guard_installed=True,verified_mac=True,vpn_handshake=True)
assert plan["ready"]
for cmd in plan["commands"]: subprocess.run(cmd,check=True)
route=subprocess.run(["ip","-4","route","get","1.1.1.1","from","10.50.1.22","iif","lan0"],capture_output=True,text=True,check=True)
assert "dev wg123456789ab" in route.stdout,route.stdout
subprocess.run(["ip","link","delete","wg123456789ab"],check=True)
fail=subprocess.run(["ip","-4","route","get","1.1.1.1","from","10.50.1.22","iif","lan0"],capture_output=True,text=True)
assert fail.returncode!=0,fail.stdout
print("RECOVERY_PLAN_FAIL_CLOSED_WHEN_VPN_DISAPPEARS: PASS")
subprocess.run(["ip","link","add","wg123456789ab","type","dummy"],check=True)
subprocess.run(["ip","link","set","wg123456789ab","up"],check=True)
# Equivalent to a boot-style reconstruction after tunnel recreation.
subprocess.run(plan["commands"][0],check=True)
subprocess.run(plan["commands"][1],check=True)
restored=subprocess.run(["ip","-4","route","get","1.1.1.1","from","10.50.1.22","iif","lan0"],capture_output=True,text=True,check=True)
assert "dev wg123456789ab" in restored.stdout,restored.stdout
print("RECOVERY_PLAN_ROUTE_REBUILT_AFTER_VPN_RETURN: PASS")
PY
'
