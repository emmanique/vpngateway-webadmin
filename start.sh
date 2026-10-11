#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
PROJECT_ROOT="$PWD"
usage() { echo "Utilização: sudo ./start.sh [--check] [--lan-interface IFACE] [--lan-ip IPv4]"; }
CHECK=0
LAN_IFACE="${VPNGW_LAN_INTERFACE:-}"
LAN_IPV4="${VPNGW_LAN_IPV4:-}"
while (($#)); do
  case "$1" in
    --check) CHECK=1; shift ;;
    --lan-interface) LAN_IFACE="${2:?Indique a interface}"; shift 2 ;;
    --lan-ip) LAN_IPV4="${2:?Indique o IPv4}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ "$(uname -s)" == Linux ]] || { echo "Apenas Linux é suportado" >&2; exit 1; }
dependencies_ok() {
  local binary
  for binary in docker ip openssl nft systemctl python3 openvpn wg ping; do
    command -v "$binary" >/dev/null || return 1
  done
  docker compose version >/dev/null 2>&1
}
if ! dependencies_ok; then
  if ((CHECK)); then
    echo "Dependências em falta; --check não instala pacotes" >&2
    exit 1
  fi
  [[ "$EUID" -eq 0 ]] || { echo "Execute sudo ./start.sh para instalar dependências" >&2; exit 1; }
  command -v apt-get >/dev/null || { echo "Instalação automática de dependências suportada em Debian/Ubuntu. Noutras distribuições instale Docker Compose v2, OpenVPN, WireGuard, nftables, iproute2, ping e Python 3." >&2; exit 1; }
  echo "A instalar dependências Linux em falta..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y docker.io iproute2 nftables openssl python3 openvpn wireguard-tools iputils-ping curl
  if ! docker compose version >/dev/null 2>&1; then
    apt-get install -y docker-compose-v2 || apt-get install -y docker-compose-plugin
  fi
  dependencies_ok || { echo "Falhou a instalação das dependências" >&2; exit 1; }
fi
if ((!CHECK)); then
  [[ "$EUID" -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
  systemctl enable --now docker.service
fi
if [[ -z "$LAN_IFACE" ]]; then
  LAN_IFACE="$(ip -4 -j route show default | python3 -c 'import json,sys; a={r.get("dev") for r in json.load(sys.stdin) if r.get("dev")}; print(next(iter(a)) if len(a)==1 else "")')"
fi
[[ -n "$LAN_IFACE" ]] || { echo "Interface LAN ambígua; indique --lan-interface" >&2; exit 1; }
[[ "$LAN_IFACE" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || { echo "Interface inválida" >&2; exit 1; }
if [[ -z "$LAN_IPV4" ]]; then
  LAN_IPV4="$(ip -4 -j addr show dev "$LAN_IFACE" | python3 -c 'import json,sys; a=[i["local"] for d in json.load(sys.stdin) for i in d.get("addr_info",[]) if i.get("family")=="inet" and i.get("scope")=="global"]; print(a[0] if len(a)==1 else "")')"
fi
python3 - "$LAN_IPV4" <<'PY'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1])
if ip.version!=4 or not ip.is_private or ip.is_loopback or ip.is_link_local:
    raise SystemExit("O endereço de gestão tem de ser IPv4 privado da LAN")
PY
ip -4 -j addr show dev "$LAN_IFACE" | python3 -c 'import json,sys; wanted=sys.argv[1]; active={i["local"] for x in json.load(sys.stdin) for i in x.get("addr_info",[]) if i.get("family")=="inet"}; sys.exit(0 if wanted in active else 1)' "$LAN_IPV4" || { echo "O IPv4 indicado não pertence à interface LAN seleccionada" >&2; exit 1; }
echo "Gateway VPN Multi: LAN $LAN_IFACE / $LAN_IPV4"
files=(-f deploy/compose.1.0.0.yml -f deploy/compose.linux-policy-agent.yml -f deploy/compose.linux-discovery.yml -f deploy/compose.lan-https.yml -f deploy/compose.pihole-lan-dns.yml)
export VPNGW_SHARED_DIR=/var/lib/vpngw/shared
if ((CHECK)); then
  VPNGW_LAN_IPV4="$LAN_IPV4" PIHOLE_WEBPASSWORD=check-only docker compose --env-file deploy/.env.example "${files[@]}" config --quiet
  bash -n installers/install-policy-agent-linux.sh
  echo "Pré-verificação aprovada; nenhuma alteração aplicada."
  exit 0
fi
[[ "$EUID" -eq 0 ]] || { echo "Execute com sudo para instalar os serviços de sistema" >&2; exit 1; }
umask 077
if [[ ! -f deploy/.env ]]; then
  password="$(openssl rand -hex 24)"
  printf 'PIHOLE_WEBPASSWORD=%s\n' "$password" > deploy/.env
  echo "Segredo administrativo gerado e guardado em deploy/.env (modo 0600)."
fi
chmod 0600 deploy/.env
if grep -Eq 'CHANGE_ME|^PIHOLE_WEBPASSWORD=$' deploy/.env; then
  echo "Segredo inválido em deploy/.env" >&2; exit 1
fi
install -d -m 0700 deploy/tls-local
if [[ ! -s deploy/tls-local/lan.crt || ! -s deploy/tls-local/lan.key ]]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
    -keyout deploy/tls-local/lan.key -out deploy/tls-local/lan.crt \
    -subj "/CN=$LAN_IPV4" -addext "subjectAltName=IP:$LAN_IPV4" >/dev/null 2>&1
  chmod 0600 deploy/tls-local/lan.key
  echo "Certificado TLS local criado; o navegador terá de confiar nele."
fi
bash installers/install-policy-agent-linux.sh
install -d -m 0755 "$VPNGW_SHARED_DIR"
cat > /etc/systemd/system/vpngw-discovery.service <<'UNIT'
[Unit]
Description=Gateway VPN Multi passive LAN discovery
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
Environment=VPNGW_DISCOVERY_OUTPUT=/var/lib/vpngw/shared/discovery.json
ExecStart=/usr/bin/python3 /usr/local/libexec/host-discovery-snapshot.py
UNIT
cat > /etc/systemd/system/vpngw-discovery.timer <<'UNIT'
[Unit]
Description=Gateway VPN Multi discovery refresh
[Timer]
OnBootSec=10s
OnUnitActiveSec=30s
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now vpngw-discovery.timer >/dev/null
systemctl start vpngw-discovery.service
install -d -m 0755 /etc/default
printf 'VPNGW_LAN_INTERFACE=%s\n' "$LAN_IFACE" > /etc/default/vpngw-pihole-dns-acl
chmod 0644 /etc/default/vpngw-pihole-dns-acl
install -m 0755 scripts/vpngw-pihole-dns-acl.sh /usr/local/sbin/vpngw-pihole-dns-acl
install -m 0644 deploy/systemd/vpngw-pihole-dns-acl.service /etc/systemd/system/vpngw-pihole-dns-acl.service
systemctl daemon-reload
VPNGW_LAN_IPV4="$LAN_IPV4" VPNGW_LAN_INTERFACE="$LAN_IFACE" PIHOLE_WEBPASSWORD="$(sed -n 's/^PIHOLE_WEBPASSWORD=//p' deploy/.env | head -1)" \
  docker compose --env-file deploy/.env "${files[@]}" config --quiet
# Apply the firewall before publishing DNS; if ACL validation fails, abort.
if [[ -x /usr/local/sbin/vpngw-pihole-dns-acl ]]; then
  VPNGW_LAN_INTERFACE="$LAN_IFACE" /usr/local/sbin/vpngw-pihole-dns-acl
else
  VPNGW_LAN_INTERFACE="$LAN_IFACE" sh scripts/vpngw-pihole-dns-acl.sh
fi
systemctl enable vpngw-pihole-dns-acl.service >/dev/null
export VPNGW_LAN_IPV4="$LAN_IPV4"
docker compose --env-file deploy/.env "${files[@]}" up -d --build
echo "WebAdmin: https://$LAN_IPV4/"
echo "Pi-hole DNS: $LAN_IPV4:53; administração: https://$LAN_IPV4:8443/"
