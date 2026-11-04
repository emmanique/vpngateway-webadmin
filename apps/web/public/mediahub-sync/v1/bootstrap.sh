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
# Never use IP literals from the script itself: resolve the current host's
# actual default route. Re-check after downloads to avoid mid-flight switches.
get_gateway() {
  ip -j -4 route get 1.1.1.1 | python3 -c '
import json,sys,ipaddress
rows=json.load(sys.stdin)
if len(rows)!=1: raise SystemExit(2)
gateway=ipaddress.ip_address(rows[0].get("gateway",""))
if gateway.version!=4 or not gateway.is_private or gateway.is_loopback: raise SystemExit(3)
print(gateway)'
}
GW="$(get_gateway)"
BASE="https://${GW}:9443/mediahub-sync/v1"
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
[[ "$(get_gateway)" == "$GW" ]] || { echo "Default Gateway changed; abort" >&2; exit 5; }
(cd "$TEMP" && sha256sum --check --strict SHA256SUMS)
echo "Verified MediaHub port-sync bundle from current gateway: $GW"
if [[ "$MODE" == "--install" ]]; then
  bash "$TEMP/installers/install-mediahub-gateway-port-sync-linux.sh"
  echo "Service installed but NOT enabled. Configure /etc/mediahub/port-sync.conf."
else
  echo "Verification only. Rerun with --install to place files on this Linux host."
fi
