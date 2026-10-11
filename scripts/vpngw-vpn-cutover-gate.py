#!/usr/bin/env python3
"""Pure cutover eligibility gate. An audit is NOT permission to modify network state."""
def evaluate(report):
    checks=report.get("checks")
    if not isinstance(checks,dict) or not checks:
        return {"eligible_for_trial":False,"reasons":["missing_integrated_checks"]}
    failed=[key for key,value in checks.items() if value is not True]
    staged=report.get("boot_guard",{}).get("staged_candidate_valid") is True
    reasons=["failed:"+key for key in failed]
    if not staged:reasons.append("boot_guard_not_staged")
    if report.get("integrated_preflight") is not True:reasons.append("integrated_preflight_not_passed")
    # Prevent a caller treating a staging audit as authorization.
    reasons.extend(["executor_not_wired","live_egress_and_rollback_not_verified"])
    return {"eligible_for_trial":False,"reasons":reasons}
