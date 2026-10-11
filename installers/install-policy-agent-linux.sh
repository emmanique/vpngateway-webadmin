#!/usr/bin/env bash
set -euo pipefail
if [[ "${EUID}" -ne 0 ]]; then
  echo "Requer root: sudo bash installers/install-policy-agent-linux.sh" >&2
  exit 1
fi
cd "$(dirname "$0")/.."
for utility in systemctl systemd-run nft ip openssl; do
  command -v "$utility" >/dev/null || { echo "Falta: $utility" >&2; exit 1; }
done
install -d -m 0700 /etc/vpngw-policy-agent
if [[ ! -s /etc/vpngw-policy-agent/secret ]]; then
  openssl rand -hex 32 > /etc/vpngw-policy-agent/secret
  chmod 0600 /etc/vpngw-policy-agent/secret
fi
install -d -m 0755 /usr/local/libexec
install -m 0755 scripts/vpngw-policy-agent.py /usr/local/libexec/vpngw-policy-agent.py
for script in vpngw-vpn-route-plan.py vpngw-vpn-transaction.py vpngw-openvpn-agent.py vpngw-basic-transition-batch.py vpngw-vpn-host-guard.py vpngw-vpn-route-commands.py vpngw-vpn-filter-batch.py network-topology.py lan-discovery.py host-discovery-snapshot.py; do
  install -m 0755 "scripts/$script" "/usr/local/libexec/$script"
done
install -m 0755 scripts/vpngw-vpn-boot-guard.py /usr/local/libexec/vpngw-vpn-boot-guard.py
install -m 0644 deploy/systemd/vpngw-vpn-boot-guard.service /etc/systemd/system/vpngw-vpn-boot-guard.service
# Do not enable the boot guard until a complete, verified persistent VPN
# policy is committed. Enabling it prematurely could disrupt DIRECT clients.
install -m 0644 deploy/systemd/vpngw-policy-agent.service /etc/systemd/system/vpngw-policy-agent.service
systemctl daemon-reload
systemctl enable --now vpngw-policy-agent.service
systemctl is-active --quiet vpngw-policy-agent.service
echo "Agente instalado: sem palavra-passe adicional no WebAdmin. Apenas operações HTTPS da LAN de gestão são aceites."
echo "A comunicação interna mantém uma chave automática não apresentada ao utilizador."
