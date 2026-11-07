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
# Bind the observer to the explicitly authenticated Gateway used by bootstrap.
# Do not infer it from the LAN's default router.
if [[ -n "${MEDIAHUB_PORT_SYNC_GATEWAY_IP:-}" ]]; then
  python3 - "$MEDIAHUB_PORT_SYNC_GATEWAY_IP" <<'PY_GATEWAY_CONFIG'
import ipaddress,sys
from pathlib import Path
try:
    address=ipaddress.IPv4Address(sys.argv[1])
except ValueError as exc:
    raise SystemExit("Invalid explicit VPN Gateway LAN IPv4") from exc
if not address.is_private or address.is_loopback or address.is_link_local:
    raise SystemExit("VPN Gateway management IP must be private LAN")
config=Path("/etc/mediahub/port-sync.conf")
rows=config.read_text().splitlines()
key="MEDIAHUB_PORT_SYNC_GATEWAY_IP="
rows=[key+str(address) if row.startswith(key) else row for row in rows]
if not any(row.startswith(key) for row in rows):
    rows.append(key+str(address))
config.write_text("\n".join(rows)+"\n")
config.chmod(0o600)
PY_GATEWAY_CONFIG
fi
systemctl daemon-reload
# Gateway watcher is observation-only. The existing Stremio reconciler is the
# sole writer to .env and the sole authority to recreate the Docker container.
# Discover the *actual* Compose directory from Docker metadata, never from a
# fixed sample path or a guessed IP address.
COMPOSE_DIR="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' stremio-libtorrent-server 2>/dev/null || true)"
if [[ -n "$COMPOSE_DIR" && "$COMPOSE_DIR" == /* &&
      -f "$COMPOSE_DIR/compose.yaml" && -f "$COMPOSE_DIR/.env" &&
      -f "$COMPOSE_DIR/scripts/gateway-port-sync.py" &&
      -f "$COMPOSE_DIR/scripts/reconcile-host.py" ]]; then
  if ! grep -q 'def load_verified_observation(' "$COMPOSE_DIR/scripts/gateway-port-sync.py"; then
    echo "Stremio reconciler needs the Gateway observation consumer update; refusing unsafe activation." >&2
    exit 7
  fi
  python3 - "$COMPOSE_DIR" <<'PYCONFIG'
import json,os,re,stat,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve(strict=True)
if not root.is_dir():
    raise SystemExit("Invalid Compose root")
routes=json.loads(subprocess.run(["ip","-j","-4","route","get","1.1.1.1"],
                                 capture_output=True,text=True,check=True).stdout)
if len(routes)!=1 or not routes[0].get("gateway"):
    raise SystemExit("Default gateway unavailable")
nic=routes[0]["dev"]
links=json.loads(subprocess.run(["ip","-j","link","show","dev",nic],
                                capture_output=True,text=True,check=True).stdout)
if len(links)!=1 or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}",links[0]["address"].lower()):
    raise SystemExit("Registered host MAC not found")
mac=links[0]["address"].lower()
observer_conf=Path("/etc/mediahub/port-sync.conf")
if observer_conf.is_symlink() or not observer_conf.is_file():
    raise SystemExit("Unsafe watcher configuration")
watcher=dict(line.strip().split("=",1) for line in observer_conf.read_text().splitlines()
             if "=" in line and not line.lstrip().startswith("#"))
policy=watcher.get("MEDIAHUB_PORT_SYNC_POLICY_ID","stremio")
watcher["MEDIAHUB_PORT_SYNC_HOST_MAC"]=mac
if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}",policy):
    raise SystemExit("Invalid policy ID")
observer_conf.write_text("".join(f"{k}={v}\n" for k,v in watcher.items()))
observer_conf.chmod(0o600)
file=Path("/etc/stremio-webadmin/port-sync.conf")
file.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
gateway_ip=watcher.get("MEDIAHUB_PORT_SYNC_GATEWAY_IP","")
try:
    import ipaddress
    vpn_gateway=ipaddress.IPv4Address(gateway_ip)
    valid_gateway=(vpn_gateway.is_private and not vpn_gateway.is_loopback and not vpn_gateway.is_link_local)
except ValueError:
    valid_gateway=False
expected={"ENABLED":"0","SOURCE":"observation","POLICY_ID":policy,"HOST_MAC":mac}
if valid_gateway:
    expected["GATEWAY_IP"]=gateway_ip
if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}",expected["POLICY_ID"]):
    raise SystemExit("Invalid policy ID")
if file.exists():
    if file.is_symlink() or not stat.S_ISREG(file.stat().st_mode):
        raise SystemExit("Unsafe Stremio port-sync config")
    original=dict(line.strip().split("=",1) for line in file.read_text().splitlines()
                  if "=" in line and not line.lstrip().startswith("#"))
    for field in ("POLICY_ID","HOST_MAC","GATEWAY_IP"):
        if original.get(field) and original[field]!=expected[field]:
            raise SystemExit("Existing Stremio port-sync binding differs: "+field)
    original.update(expected)
    # Never activate until dedicated read-only credentials and CA pass QA.
    original["ENABLED"]="0"
    expected=original
file.write_text("".join(f"{k}={v}\n" for k,v in expected.items()))
file.chmod(0o600)
print("Existing Stremio reconciler detected:",root)
print("Stremio .env:",root/".env")
print("Port authority: Stremio gateway-port-sync.py (SOURCE=observation)")
PYCONFIG
else
  echo "Existing Stremio reconciler not detected. No .env or container changes." >&2
fi
echo "Installed observer and prepared Stremio config with ENABLED=0; both timers remain opt-in."
echo "Configure /etc/mediahub/port-sync.conf and install the trusted Gateway CA and dedicated status token."
echo "After validation: systemctl enable --now mediahub-gateway-port-sync.timer"
