#!/usr/bin/env python3
"""Read-only regression tests for configured host route transition planner."""
import importlib.util
from pathlib import Path

module_path = Path(__file__).with_name("vpngw-host-transition-plan.py")
spec = importlib.util.spec_from_file_location("vpngw_transition_plan",module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

profiles={"vpn-a":{"enabled":True,"status":"connected"},
          "vpn-b":{"enabled":True,"status":"connected"}}
destinations=("direct","blocked","vpn-a","vpn-b")
count=0
for old in destinations:
    registry=[{"host_ip":"198.51.100.229","destination":old,"registered_mac":"02:00:00:00:00:29"},
              {"host_ip":"198.51.100.228","destination":"direct","registered_mac":"02:00:00:00:00:29"},
              {"host_ip":"198.51.100.230","destination":"vpn-a"}]
    for new in destinations:
        result=module.plan_transition("198.51.100.229",old,new,profiles,registry)
        assert result["from"]==old and result["to"]==new
        assert result["ready"]==(old==new)
        assert result["network_changes"] is False
        assert result["transition_type"]
        assert registry[1]["destination"]=="direct"
        assert registry[2]["destination"]=="vpn-a"
        assert result["shared_vpn_users_preserved"] == (["198.51.100.230"] if old=="vpn-a" else [])
        count+=1
try:
    module.plan_transition("198.51.100.229","direct","vpn-a",profiles,
                           [{"host_ip":"198.51.100.229","destination":"blocked","registered_mac":"02:00:00:00:00:29"}])
except ValueError:
    pass
else:
    raise AssertionError("stale state incorrectly accepted")
assert "vpn_profile_not_configured" in module.plan_transition(
    "198.51.100.229","direct","vpn-a",
    {"vpn-a":{"enabled":False,"status":"not_configured"}},
    [{"host_ip":"198.51.100.229","destination":"direct","registered_mac":"02:00:00:00:00:29"}])["blockers"]
print(f"PASS: {count} directed transitions, stale-state refusal, VPN eligibility and isolation")
