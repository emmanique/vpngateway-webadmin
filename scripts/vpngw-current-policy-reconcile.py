#!/usr/bin/env python3
"""Reconcile current assignments, without resurrecting deprecated fixed VPNs."""
import json
import sys
import urllib.request

BASE = "http://127.0.0.1:18080/api/v1/"
def get(path):
    with urllib.request.urlopen(BASE + path, timeout=5) as response:
        result = json.load(response)
    if not isinstance(result, list if path in ("policies", "connections") else dict):
        raise ValueError("Invalid control-plane response")
    return result

def main():
    try:
        policies = get("policies")
        connections = get("connections")
        overview = get("overview/status")
        by_id = {p["id"]: p for p in connections}
        by_host = {h["ip"]: (route["id"], h) for route in overview.get("routes", []) for h in route.get("hosts", [])}
        failures = []
        report = []
        for policy in policies:
            ip, target = policy["host_ip"], policy["destination"]
            route, state = by_host.get(ip, (None, {}))
            identity = state.get("authorization_status")
            if target in ("direct", "blocked"):
                okay = route == target and (identity != "unauthorized") and state.get("status") not in ("error", "reverted")
            else:
                profile = by_id.get(target)
                # A VPN must be attributed to the host and verified in the dataplane,
                # never inferred merely from a connected tunnel.
                vpn_route = next((r for r in overview["routes"] if r["id"] == target), {})
                okay = bool(profile and route == target and vpn_route.get("tunnel_active")
                            and vpn_route.get("available") and state.get("status") in ("vpn_trial", "gateway_measured", "active")
                            and identity != "unauthorized")
            report.append({"ip": ip, "target": target, "observed_route": route,
                           "identity": identity, "verified": bool(okay)})
            if not okay:
                failures.append(ip)
        print(json.dumps({"policies_checked": len(report), "hosts": report,
                          "result": "verified" if not failures else "requires_reconciliation",
                          "unverified_hosts": failures}, ensure_ascii=False))
        return 0 if not failures else 2
    except Exception as exc:
        print(json.dumps({"result": "unavailable", "detail": str(exc)}, ensure_ascii=False))
        return 2

if __name__ == "__main__":
    sys.exit(main())
