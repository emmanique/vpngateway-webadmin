#!/usr/bin/env bash
# Install the external MediaHub watcher as an OS-level systemd service.
# Never runs inside Docker; NEVER enables the timer automatically.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Root required" >&2; exit 1; }
SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SOURCE_ROOT/scripts/mediahub-gateway-port-sync.py"
UNIT="$SOURCE_ROOT/deploy/systemd/mediahub-gateway-port-sync.service"
TIMER="$SOURCE_ROOT/deploy/systemd/mediahub-gateway-port-sync.timer"
CONFIG_EXAMPLE="$SOURCE_ROOT/deploy/examples/mediahub-port-sync.conf.example"
for f in "$SCRIPT" "$UNIT" "$TIMER" "$CONFIG_EXAMPLE"; do
  [[ -f "$f" && ! -L "$f" ]] || { echo "Missing or symlinked $f" >&2; exit 1; }
done
command -v docker >/dev/null || { echo "Docker missing" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "Python 3 required" >&2; exit 1; }
python3 -m py_compile "$SCRIPT"
install -d -m 0755 /usr/local/libexec /etc/systemd/system /etc/mediahub
install -m 0755 "$SCRIPT" /usr/local/libexec/mediahub-gateway-port-sync.py
install -m 0644 "$UNIT" /etc/systemd/system/mediahub-gateway-port-sync.service
install -m 0644 "$TIMER" /etc/systemd/system/mediahub-gateway-port-sync.timer
if [[ ! -e /etc/mediahub/port-sync.conf ]]; then
  install -m 0600 "$CONFIG_EXAMPLE" /etc/mediahub/port-sync.conf
fi
systemctl daemon-reload
echo "Installed OS-level files. Timer intentionally left DISABLED."
echo "Edit /etc/mediahub/port-sync.conf and install a trusted CA at MEDIAHUB_PORT_SYNC_CA_FILE."
echo "Gateway certificate MUST have an IP SAN matching the currently detected default gateway."
echo "To check the actual host route: ip -4 route get 1.1.1.1"
echo "For an operator test (after QA approval):"
echo "  systemctl start mediahub-gateway-port-sync.service"
echo "After end-to-end validation, enable monitoring explicitly:"
echo "  systemctl enable --now mediahub-gateway-port-sync.timer"
