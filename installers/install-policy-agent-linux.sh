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
# The DIRECT upstream UPnP client is optional for basic routing. For Debian
# installations it is provisioned by default, but a blocked/offline package
# mirror must never disable the VPN kill-switch or break core provisioning.
if [[ "${VPNGW_INSTALL_MINIUPNPC:-1}" == "1" && ! -x /usr/bin/upnpc ]]; then
  if command -v apt-get >/dev/null; then
    if ! (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends miniupnpc); then
      echo "AVISO: miniupnpc não disponível. UPnP físico fica desactivado; NAT-PMP VPN não é afectado." >&2
    fi
  else
    echo "AVISO: distribuição sem apt-get. Instale miniupnpc para UPnP DIRECT." >&2
  fi
fi
install -d -m 0700 /etc/vpngw-policy-agent /etc/vpngw-policy-agent/persistent-vpn
if [[ ! -s /etc/vpngw-policy-agent/secret ]]; then
  openssl rand -hex 32 > /etc/vpngw-policy-agent/secret
  chmod 0600 /etc/vpngw-policy-agent/secret
fi
install -d -m 0755 /usr/local/libexec
install -m 0755 scripts/vpngw-policy-agent.py /usr/local/libexec/vpngw-policy-agent.py
for script in vpngw-host-rebind.py vpngw-host-rebind-transaction.py vpngw-direct-upnp.py vpngw-upnpc-upstream.py vpngw-port-forward.py vpngw-natpmp-discovery.py vpngw-proton-natpmp.py vpngw-port-reconcile.py vpngw-vpn-route-plan.py vpngw-vpn-transaction.py vpngw-openvpn-agent.py vpngw-basic-transition-batch.py vpngw-vpn-host-guard.py vpngw-vpn-route-commands.py vpngw-vpn-filter-batch.py network-topology.py lan-discovery.py host-discovery-snapshot.py; do
  install -m 0755 "scripts/$script" "/usr/local/libexec/$script"
done
# Provision the Proton-compatible NAT-PMP client with a pinned upstream
# source checksum. Failure does not break routing; port forwarding stays
# fail-closed until a verified client is available.
if [[ "${VPNGW_INSTALL_PROTON_NATPMP:-1}" == "1" ]]; then
  if ! bash installers/install-proton-natpmpc.sh; then
    echo "AVISO: Proton NAT-PMP não disponível; VPN routing mantém-se activo, mas a abertura de portas fica bloqueada." >&2
  fi
fi
install -m 0755 scripts/vpngw-vpn-boot-guard.py /usr/local/libexec/vpngw-vpn-boot-guard.py
install -m 0644 deploy/systemd/vpngw-vpn-boot-guard.service /etc/systemd/system/vpngw-vpn-boot-guard.service
# Empty directories install no guards; confirmed policies are persisted by the agent.
systemctl enable vpngw-vpn-boot-guard.service
install -m 0644 deploy/systemd/vpngw-policy-agent.service /etc/systemd/system/vpngw-policy-agent.service
# Recover failed OpenVPN processes without reimporting saved profiles.
install -d -m 0755 /etc/systemd/system/openvpn-client@.service.d
install -m 0644 deploy/systemd/openvpn-client-recovery.conf /etc/systemd/system/openvpn-client@.service.d/vpngw-recovery.conf
systemctl daemon-reload
systemctl enable --now vpngw-policy-agent.service
systemctl is-active --quiet vpngw-policy-agent.service
echo "Agente instalado: sem palavra-passe adicional no WebAdmin. Apenas operações HTTPS da LAN de gestão são aceites."
echo "A comunicação interna mantém uma chave automática não apresentada ao utilizador."
