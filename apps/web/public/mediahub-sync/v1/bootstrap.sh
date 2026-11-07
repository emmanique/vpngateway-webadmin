#!/usr/bin/env bash
# MediaHub Linux host bootstrap served by the active VPN Gateway via HTTPS.
# Download, checksum verification, optional host-level installation.
# No docker exec, no API write operation, no systemd automatic activation.
set -Eeuo pipefail
umask 077
MODE="${1:---verify-only}"
[[ "$MODE" == "--verify-only" || "$MODE" == "--install" ]] || {
  echo "Usage: $0 [--verify-only|--install]" >&2; exit 2;
}
[[ "${EUID}" -eq 0 ]] || { echo "Run as root on the MediaHub Linux HOST" >&2; exit 1; }
CA="${MEDIAHUB_PORT_SYNC_CA_FILE:-/etc/mediahub/gateway-ca.pem}"
[[ -f "$CA" && ! -L "$CA" ]] || { echo "Trusted Gateway CA absent: $CA" >&2; exit 1; }
for bin in ip python3 curl sha256sum; do
  command -v "$bin" >/dev/null || { echo "Missing $bin" >&2; exit 1; }
done
# The HTTPS service hostname/IP is not the default-router address.
# Explicit Gateway LAN IP is required; no silent use of the WAN router.
GW="${MEDIAHUB_PORT_SYNC_GATEWAY_IP:-}"
WEB_PORT="${MEDIAHUB_PORT_SYNC_BOOTSTRAP_PORT:-443}"
python3 - "$GW" "$WEB_PORT" <<'PY_GATEWAY'
import ipaddress,sys
try:
    ip=ipaddress.IPv4Address(sys.argv[1])
    port=int(sys.argv[2])
except (ValueError,IndexError) as e:
    raise SystemExit("Set MEDIAHUB_PORT_SYNC_GATEWAY_IP to the VPN Gateway LAN IPv4") from e
if not ip.is_private or ip.is_loopback or ip.is_link_local or not (1<=port<=65535):
    raise SystemExit("Unsafe VPN Gateway LAN endpoint")
PY_GATEWAY
BASE="https://${GW}:${WEB_PORT}/mediahub-sync/v1"
# The current kernel route to the management IP must be stable during download.
route_identity() {
  ip -j -4 route get "$GW" | python3 -c '
import json,sys,ipaddress
rows=json.load(sys.stdin)
if len(rows)!=1: raise SystemExit("Missing route to VPN Gateway")
r=rows[0]
dev=r.get("dev","")
src=r.get("prefsrc") or r.get("src","")
if not dev or not src: raise SystemExit("No source IPv4 for Gateway route")
ipaddress.IPv4Address(src)
print(dev+"|"+src+"|"+str(r.get("gateway","")))'
}
ROUTE_BEFORE="$(route_identity)"
TEMP="$(mktemp -d /tmp/mediahub-port-sync.XXXXXXXX)"
trap 'rm -rf "$TEMP"' EXIT
fetch() {
  curl --silent --show-error --fail --proto '=https' --tlsv1.2 \
    --connect-timeout 5 --max-time 25 --cacert "$CA" --noproxy '*' \
    "$BASE/$1" -o "$TEMP/$1"
}
fetch "SHA256SUMS"
while IFS= read -r line; do
  [[ "$line" =~ ^[0-9a-f]{64}\ \ [a-zA-Z0-9_./-]+$ ]] || {
    echo "Unsafe bundle manifest" >&2; exit 4;
  }
  name="${line#*  }"
  case "$name" in
    scripts/mediahub-gateway-port-sync.py|\
    deploy/systemd/mediahub-gateway-port-sync.service|\
    deploy/systemd/mediahub-gateway-port-sync.timer|\
    deploy/examples/mediahub-port-sync.conf.example|\
    installers/install-mediahub-gateway-port-sync-linux.sh) ;;
    *) echo "Unexpected bundle asset $name" >&2; exit 4 ;;
  esac
  mkdir -p "$TEMP/$(dirname "$name")"
  fetch "$name"
done < "$TEMP/SHA256SUMS"
[[ "$(route_identity)" == "$ROUTE_BEFORE" ]] || { echo "Route to VPN Gateway changed; abort" >&2; exit 5; }
(cd "$TEMP" && sha256sum --check --strict SHA256SUMS)
echo "Verified MediaHub port-sync bundle from configured VPN Gateway: $GW:$WEB_PORT"
if [[ "$MODE" == "--install" ]]; then
  export MEDIAHUB_PORT_SYNC_GATEWAY_IP="$GW"
  bash "$TEMP/installers/install-mediahub-gateway-port-sync-linux.sh"
  echo "Service installed but NOT enabled. Configure /etc/mediahub/port-sync.conf."
else
  echo "Verification only. Rerun with --install to place files on this Linux host."
fi
