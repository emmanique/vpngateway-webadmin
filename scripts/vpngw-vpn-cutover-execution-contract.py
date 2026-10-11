#!/usr/bin/env python3
"""Pure transaction execution contract; intentionally cannot mutate host networking."""
from dataclasses import dataclass
@dataclass(frozen=True)
class Step:
    name:str
    prerequisite:str
    compensating_action:str
STEPS=(
 Step("snapshot","verified_direct","abort"),
 Step("arm_watchdog","snapshot_durable","cancel_watchdog"),
 Step("install_boot_guard","watchdog_armed","demote_only_after_direct_verified"),
 Step("install_fail_closed","boot_guard_installed","keep_until_direct_verified"),
 Step("install_routes","fail_closed_installed","remove_vpn_policy"),
 Step("atomic_filter_and_nat","routes_verified","restore_direct_under_guard"),
 Step("verify_live_egress","filter_and_nat_switched","rollback_if_unverified"),
 Step("commit","live_egress_and_dns_ipv4_verified","persist_and_disarm"),
)
def validate_evidence(evidence):
    if not isinstance(evidence,dict):return {"ready":False,"missing":["evidence"]}
    required=("verified_direct","snapshot_durable","watchdog_armed",
              "boot_guard_installed","fail_closed_installed","routes_verified",
              "filter_and_nat_switched","live_egress_and_dns_ipv4_verified")
    missing=[name for name in required if evidence.get(name) is not True]
    return {"ready":False,"missing":missing,
            "execute_enabled":False,
            "reason":"No production executor or end-to-end client proof installed"}
def ordered_steps():
    return [step.__dict__ for step in STEPS]
