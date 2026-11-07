#!/usr/bin/env bash
set -Eeuo pipefail
# Explicit DEV/QA opt-in. Never called by the regular/public installer.
[[ $EUID -eq 0 ]] || { echo 'Root required' >&2; exit 1; }
cd "$(dirname "$0")/.."
install -d -o root -g root -m 0755 /usr/local/libexec
for item in vpngw-dns-qa-cutover.py vpngw-vpn-host-guard.py vpngw-vpn-filter-batch.py vpngw-vpn-boot-guard.py; do
  test -f "scripts/$item" || { echo "Missing scripts/$item" >&2; exit 1; }
  install -o root -g root -m 0755 "scripts/$item" "/usr/local/libexec/$item"
done
install -o root -g root -m 0644 deploy/systemd/vpngw-dns-qa-recovery.service   /etc/systemd/system/vpngw-dns-qa-recovery.service
systemctl daemon-reload
# Process any pre-existing rollback journal before enabling future recovery.
python3 /usr/local/libexec/vpngw-dns-qa-cutover.py recover
systemctl enable --now vpngw-dns-qa-recovery.service
systemctl is-enabled vpngw-dns-qa-recovery.service
echo 'QA DNS boot recovery installed; no client DNS settings changed.'
