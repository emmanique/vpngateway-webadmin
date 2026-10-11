#!/usr/bin/env bash
# Rebuild/recreate WebAdmin with every production Linux compose overlay intact.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export VPNGW_SHARED_DIR="${VPNGW_SHARED_DIR:-/var/lib/vpngw/shared}"
if [[ -z "${VPNGW_LAN_IPV4:-}" ]]; then
  VPNGW_LAN_IPV4="$(ip -4 -j route get 1.1.1.1 | python3 -c 'import json,sys;print(json.load(sys.stdin)[0].get("prefsrc", ""))')"
fi
[[ -n "$VPNGW_LAN_IPV4" ]] || { echo 'VPNGW_LAN_IPV4 não disponível' >&2; exit 1; }
export VPNGW_LAN_IPV4
files=(-f deploy/compose.1.0.0.yml -f deploy/compose.linux-policy-agent.yml -f deploy/compose.linux-discovery.yml -f deploy/compose.lan-https.yml -f deploy/compose.pihole-lan-dns.yml)
docker compose --env-file deploy/.env "${files[@]}" config --quiet
docker compose --env-file deploy/.env "${files[@]}" build webadmin
docker compose --env-file deploy/.env "${files[@]}" up -d --no-deps --force-recreate webadmin
