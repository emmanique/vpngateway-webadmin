#!/usr/bin/env bash
# Install host-side read-only status service; no automatic start or activation.
set -Eeuo pipefail
[[ "$EUID" -eq 0 ]] || { echo "Root required" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v openssl >/dev/null || { echo "openssl required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "Python required" >&2; exit 1; }
python3 -m py_compile "$ROOT/scripts/vpngw-port-status-service.py"
install -d -m 0700 /etc/vpngw-port-status
install -d -m 0755 /usr/local/libexec
install -m 0755 "$ROOT/scripts/vpngw-port-status-service.py" /usr/local/libexec/vpngw-port-status-service.py
install -m 0644 "$ROOT/deploy/systemd/vpngw-port-status.service" /etc/systemd/system/vpngw-port-status.service
if [[ ! -e /etc/vpngw-port-status/env ]]; then
  install -m 0600 "$ROOT/deploy/vpngw-port-status.env.example" /etc/vpngw-port-status/env
fi
if [[ ! -e /etc/vpngw-port-status/token ]]; then
  openssl rand -hex 32 > /etc/vpngw-port-status/token
  chmod 0600 /etc/vpngw-port-status/token
fi
# Install only public, versioned MediaHub host-job assets for delivery via
# the same 9443 LAN TLS endpoint. Never expose credentials or private files.
BUNDLE_SRC="$ROOT/apps/web/public/mediahub-sync/v1"
BUNDLE_DST="/usr/local/share/vpngw/mediahub-sync/v1"
BUNDLE_FILES=(
  "scripts/mediahub-gateway-port-sync.py"
  "deploy/systemd/mediahub-gateway-port-sync.service"
  "deploy/systemd/mediahub-gateway-port-sync.timer"
  "deploy/examples/mediahub-port-sync.conf.example"
  "installers/install-mediahub-gateway-port-sync-linux.sh"
)
for entry in "${BUNDLE_FILES[@]}" bootstrap.sh; do
  [[ -f "$BUNDLE_SRC/$entry" && ! -L "$BUNDLE_SRC/$entry" ]] || {
    echo "Missing public bundle asset $entry" >&2; exit 1;
  }
done
install -d -m 0755 "$BUNDLE_DST"
for entry in "${BUNDLE_FILES[@]}" bootstrap.sh; do
  install -d -m 0755 "$BUNDLE_DST/$(dirname "$entry")"
  install -m 0644 "$BUNDLE_SRC/$entry" "$BUNDLE_DST/$entry"
done
(cd "$BUNDLE_DST" && sha256sum "${BUNDLE_FILES[@]}" > SHA256SUMS &&
  chmod 0644 SHA256SUMS && sha256sum --check --strict SHA256SUMS)
systemctl daemon-reload
echo "Status service and public distribution bundle installed, but NOT enabled or started."
echo "Configure /etc/vpngw-port-status/env with the actual management LAN."
echo "Place the current Gateway TLS server cert/key with a matching IP SAN in:"
echo "  /etc/vpngw-port-status/lan.crt (0644)"
echo "  /etc/vpngw-port-status/lan.key (0600)"
echo "Place its trusted CA/public cert and the dedicated access token securely on MediaHub."
echo "Once verified in QA: systemctl enable --now vpngw-port-status.service"
