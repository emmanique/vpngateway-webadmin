#!/bin/bash
# Reconcile the boot data-plane after WAN/Wi-Fi returns, without dropping existing sessions.
set -euo pipefail
exec 9>/run/vpngw-network-recovered.lock
flock -n 9 || exit 0
log(){ logger -t vpngw-network-recovered "$*"; echo "$*"; }
step(){ log "starting $1"; shift; if "$@"; then log "OK"; else log "FAIL: recovery step failed; host protections preserved"; return 1; fi; }
log "WAN reconnect: full per-profile routing/DNS reconciliation"
# Inspect the current default route on each attempt, never a fixed gateway/interface.
for attempt in 1 2 3 4 5; do
  if python3 - <<'PY_ROUTE'
import json, subprocess, sys
try:
    routes=json.loads(subprocess.check_output(["ip","-j","-4","route","show","default"],timeout=3))
    routes=[r for r in routes if r.get("dev") and r.get("gateway")]
    routes.sort(key=lambda r:int(r.get("metric",0)))
    if not routes or (len(routes)>1 and int(routes[0].get("metric",0))==int(routes[1].get("metric",0))):
        sys.exit(1)
    route=routes[0]
    result=subprocess.run(["ping","-c","1","-W","2","-I",route["dev"],route["gateway"]],
                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
    sys.exit(result.returncode)
except (OSError,ValueError,KeyError,subprocess.SubprocessError):
    sys.exit(1)
PY_ROUTE
  then break; fi
  if [ "$attempt" -eq 5 ]; then log "No verified WAN gateway; preserve protections"; exit 2; fi
  sleep 3
done
# Reconcile the saved assignments on every run; no hard-coded host or VPN.
# A missing API or unverified VPN remains an error rather than triggering
# an unrelated legacy tunnel/service.
# Wait for the policy agent and saved VPN profiles to recover after Docker.
# A missing service must never trigger unsafe fallback to the main route.
for attempt in $(seq 1 20); do
  if python3 /usr/local/libexec/vpngw-current-policy-reconcile.py; then
    log "Current policy reconciliation verified"
    exit 0
  fi
  [ "$attempt" -eq 20 ] && break
  sleep 3
done
log "FAIL: policies not fully recovered; existing fail-closed guards retained"
exit 1
