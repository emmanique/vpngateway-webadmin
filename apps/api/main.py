from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from ipaddress import ip_address, ip_network
from typing import Literal
from threading import RLock, Lock
import sqlite3
import json
import os
import subprocess
import shutil
import socket
import hmac
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timezone
from contextlib import closing
from pathlib import Path

app = FastAPI(title="VPN Gateway Manager API", version="1.0.0")
_lock = RLock()
_discovery_lock = Lock()
_connections = {}
_policies = {}
_revision = 0
DB_PATH = os.environ.get("VPNGW_DB_PATH", "/data/gateway.sqlite3")

def _connect():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.execute("PRAGMA busy_timeout=10000")
    db.execute("CREATE TABLE IF NOT EXISTS connections (id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS policies (id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS vpn_events (event_id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id TEXT NOT NULL, observed_at TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS ix_vpn_events_profile ON vpn_events(profile_id,event_id)")
    db.execute("CREATE TABLE IF NOT EXISTS host_traffic_totals (route TEXT NOT NULL, ip TEXT NOT NULL, rx_total INTEGER NOT NULL DEFAULT 0, tx_total INTEGER NOT NULL DEFAULT 0, last_rx INTEGER NOT NULL DEFAULT 0, last_tx INTEGER NOT NULL DEFAULT 0, observed_at TEXT NOT NULL, PRIMARY KEY(route,ip))")
    return db

def _load():
    with closing(_connect()) as db, db:
        _connections.update((key, json.loads(payload)) for key, payload in db.execute("SELECT id,payload FROM connections"))
        _policies.update((key, json.loads(payload)) for key, payload in db.execute("SELECT id,payload FROM policies"))

def _save(table, key, entry=None):
    with closing(_connect()) as db, db:
        if entry is None:
            db.execute(f"DELETE FROM {table} WHERE id=?", (key,))
        else:
            db.execute(f"INSERT OR REPLACE INTO {table} (id,payload) VALUES (?,?)", (key, json.dumps(entry)))

_load()

class Connection(BaseModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,31}$")
    name: str = Field(min_length=2, max_length=80)
    provider: str = Field(min_length=2, max_length=80)
    protocol: Literal["wireguard", "openvpn"]
    enabled: bool = False

class Policy(BaseModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,31}$")
    host_ip: str
    destination: str = "direct"
    failure_mode: Literal["block", "direct"] = "block"
    registered_mac: str | None = None

@app.get("/health")
def health():
    return {"status": "ok", "service": "control-plane", "mode": "mixed"}

_traffic_previous = {}

def _gateway_traffic():
    """Optional snapshot of verified gateway FORWARD byte counters; fail closed."""
    path = os.environ.get("VPNGW_GATEWAY_TRAFFIC_SNAPSHOT")
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as stream:
            snapshot = json.load(stream)
        observed = datetime.fromisoformat(snapshot["observed_at"])
        if observed.tzinfo is None or not 0 <= (datetime.now(timezone.utc) - observed).total_seconds() <= 15:
            return {}
        if snapshot.get("source") != "gateway_nft_forward_accounting":
            return {}
        return {(item["route"], item["ip"]): (int(item["rx_bytes"]), int(item["tx_bytes"]), observed.timestamp())
                for item in snapshot["hosts"] if int(item["rx_bytes"]) >= 0 and int(item["tx_bytes"]) >= 0}
    except (OSError, ValueError, KeyError, TypeError):
        return {}

def _accumulate_host_traffic(route, ip, rx, tx):
    """Durable, monotonic host-only FORWARD counters across rule resets and reboots."""
    rx, tx = int(rx), int(tx)
    if min(rx, tx) < 0:
        raise ValueError("Invalid host counter")
    with closing(_connect()) as db, db:
        previous = db.execute(
            "SELECT rx_total,tx_total,last_rx,last_tx FROM host_traffic_totals WHERE route=? AND ip=?",
            (route, ip)).fetchone()
        if previous:
            total_rx, total_tx, old_rx, old_tx = previous
            total_rx += rx-old_rx if rx >= old_rx else rx
            total_tx += tx-old_tx if tx >= old_tx else tx
        else:
            total_rx, total_tx = rx, tx
        db.execute(
            "INSERT OR REPLACE INTO host_traffic_totals(route,ip,rx_total,tx_total,last_rx,last_tx,observed_at) VALUES(?,?,?,?,?,?,?)",
            (route,ip,total_rx,total_tx,rx,tx,datetime.now(timezone.utc).isoformat()))
        return total_rx,total_tx

@app.get("/api/v1/diagnostics/hosts")
def diagnostics_hosts():
    with _lock:
        entries=[dict(p) for p in _policies.values()]
    results=[]
    for entry in entries:
        try:
            result=_policy_agent_call("diagnose_host",entry["id"],entry)
            runtime=_policy_agent_call("status",entry["id"],entry)
            results.append({"ip":entry["host_ip"],"policy":entry["id"],
                "destination":entry["destination"],"registered_mac":entry.get("registered_mac"),
                "observed_mac":runtime.get("observed_mac"),
                "identity":runtime.get("authorization_status","unverified"),**result})
        except Exception as error:
            results.append({"ip":entry["host_ip"],"destination":entry["destination"],
                            "status":"unverified","error":str(error)})
    return {"hosts":results,"ipv6_supported":False}


@app.get("/api/v1/monitoring/hosts")
def monitoring_hosts():
    overview = overview_status()
    return {"observed_at": datetime.now(timezone.utc).isoformat(),
            "hosts": [{"ip": h["ip"], "route": r["id"], "rx_bytes": h.get("rx_bytes"),
                       "tx_bytes": h.get("tx_bytes"), "rx_bps": h.get("rx_bps"),
                       "tx_bps": h.get("tx_bps"), "status": h.get("status")}
                      for r in overview["routes"] for h in r["hosts"]],
            "scope": "managed-host-forward-only"}


@app.get("/api/v1/logs/vpn")
def vpn_logs():
    with closing(_connect()) as db:
        rows = db.execute("SELECT observed_at,profile_id,event,detail FROM vpn_events ORDER BY event_id DESC LIMIT 100").fetchall()
    return {"events": [{"at": row[0], "profile": row[1], "event": row[2], "detail": row[3]} for row in rows]}


from fastapi.responses import Response
import system_maintenance as maintenance

class BackupPassword(BaseModel):
    password: str

@app.post("/api/v1/system/backup")
def system_backup(data: BackupPassword, request: Request):
    _require_policy_admin(request)
    with _lock:
        openvpn = {}
        for ident, profile in _connections.items():
            if profile.get('protocol')=='openvpn':
                openvpn[ident] = _wireguard_agent_call(ident,'openvpn_backup_export')
        export = maintenance.encrypted_snapshot(DB_PATH, data.password, openvpn)
    return Response(content=json.dumps(export),media_type="application/json",headers={
        "Content-Disposition":"attachment; filename=gateway-vpn-encrypted.json",
        "Cache-Control":"no-store", "X-Content-Type-Options":"nosniff"})

class MaintenancePayload(BaseModel):
    confirmation: str
    backup: dict | None = None
    password: str | None = None
    interface_mapping: dict[str,str] = Field(default_factory=dict)

def _restore_mapping(restored, requested=None):
    rows=restored.get('network_config',[])
    if not rows:
        return restored, {}, [], [], ['Backup sem topologia de rede']
    draft=json.loads(rows[0]['payload'])
    topology=network_topology()
    current={i['interface']:i for i in topology['interfaces'] if i.get('kind') in ('ethernet','wifi','vlan') and i.get('operstate')=='UP'}
    origin={i['interface']:i for i in draft.get('interfaces',[])}
    existing=get_network_config().get('draft') or {}
    roles={i['interface']:i.get('role') for i in existing.get('interfaces',[])}
    mapping=dict(requested or {})
    errors=[]
    for src,dst in mapping.items():
        if src not in origin or dst not in current:
            errors.append('Mapeamento de interface inválido: '+src+' → '+dst)
        elif roles and roles.get(dst)!=origin[src].get('role'):
            errors.append('Papel WAN/LAN incompatível: '+src+' → '+dst)
    occupied=set(mapping.values())
    for src,info in origin.items():
        if src in mapping:continue
        role=info.get('role')
        candidates=[name for name in current if name not in occupied and (not roles or roles.get(name)==role)]
        if src in candidates:
            mapping[src]=src;occupied.add(src)
        elif len(candidates)==1 and len([x for x in origin if x not in mapping and origin[x].get('role')==role])==1:
            mapping[src]=candidates[0];occupied.add(candidates[0])
    if len(set(mapping.values()))!=len(mapping):errors.append('Duas interfaces de origem apontam para o mesmo destino')
    options={src:[n for n in current if not roles or roles.get(n)==info.get('role')] for src,info in origin.items()}
    pending=[src for src in origin if src not in mapping]
    if not pending and not errors:
        copy=json.loads(json.dumps(restored))
        remapped=json.loads(rows[0]['payload'])
        for item in remapped['interfaces']:item['interface']=mapping[item['interface']]
        remapped['management_interface']=mapping.get(remapped['management_interface'],remapped['management_interface'])
        copy['network_config'][0]['payload']=json.dumps(remapped,ensure_ascii=False)
        return copy,mapping,options,pending,errors
    return restored,mapping,options,pending,errors

def _restore_preflight(restored):
    """Fail closed on topology, interface roles, subnet and host-policy incompatibilities."""
    issues = []
    network_rows = restored.get('network_config', [])
    original = json.loads(network_rows[0]['payload']) if network_rows else None
    if not original:
        issues.append('Backup sem configuração de topologia WAN/LAN')
        return issues
    try:
        current = network_topology()
        actual = {i['interface']:i for i in current['interfaces'] if i.get('kind') in ('ethernet','wifi','vlan') and i.get('operstate') == 'UP'}
    except Exception:
        return ['Não foi possível verificar a topologia real das interfaces do servidor']
    names = {i['interface'] for i in original.get('interfaces',[])}
    if set(actual) != names:
        issues.append('Interfaces diferentes: backup=' + ', '.join(sorted(names)) + '; servidor=' + ', '.join(sorted(actual)))
    current_config = get_network_config().get('draft')
    if current_config:
        if original.get('mode') != current_config.get('mode'):
            issues.append('Topologia diferente: backup=' + str(original.get('mode')) + '; servidor=' + str(current_config.get('mode')))
        current_roles = {i['interface']: i.get('role') for i in current_config.get('interfaces',[])}
        for item in original.get('interfaces',[]):
            if current_roles.get(item['interface']) != item.get('role'):
                issues.append('Papel WAN/LAN diferente para ' + str(item['interface']))
        if original.get('management_interface') != current_config.get('management_interface'):
            issues.append('Interface de gestão diferente')
    for item in original.get('interfaces', []):
        name=item.get('interface')
        if name not in actual or item.get('role') != 'lan':
            continue
        if item.get('ipv4_address') and item.get('prefix_length') is not None:
            try:
                expected = ip_network(item['ipv4_address']+'/'+str(item['prefix_length']),strict=False)
                observed = actual[name].get('network')
                if not observed or ip_network(observed,strict=False)!=expected:
                    issues.append('CIDR LAN diferente em '+name+': backup='+str(expected)+'; servidor='+str(observed))
            except ValueError:
                issues.append('CIDR LAN inválido em '+name)
    subnets=[]
    for item in original.get('interfaces',[]):
        if item.get('role') != 'lan':
            continue
        name = item.get('interface')
        if name not in actual:
            issues.append('Interface LAN indisponível: ' + str(name))
            continue
        # DHCP/shared LAN: derive the CIDR from the host snapshot, never from a missing static draft.
        try:
            observed = actual[name].get('network')
            if not observed:
                issues.append('CIDR LAN não detectado em ' + str(name))
                continue
            observed_subnet = ip_network(observed, strict=False)
            if item.get('ipv4_address') and item.get('prefix_length') is not None:
                configured_subnet = ip_network(item['ipv4_address']+'/'+str(item['prefix_length']), strict=False)
                if configured_subnet != observed_subnet:
                    continue  # Already recorded as a CIDR mismatch above.
                subnets.append(configured_subnet)
            else:
                subnets.append(observed_subnet)
        except ValueError:
            issues.append('CIDR LAN inválido em ' + str(name))
    seen=set()
    for row in restored.get('policies',[]):
        policy=json.loads(row['payload']); host=policy.get('host_ip')
        try:
            addr=ip_address(host)
            if not any(addr in subnet for subnet in subnets):
                issues.append('Host fora das redes LAN do backup: '+str(host))
        except ValueError:
            issues.append('IP de host inválido: '+str(host))
        if host in seen:
            issues.append('Regras duplicadas para host '+str(host))
        seen.add(host)
        if not policy.get('registered_mac'):
            issues.append('Host sem identidade MAC validada: '+str(host))
    return issues

class RestorePreflight(BaseModel):
    backup: dict
    password: str
    interface_mapping: dict[str,str] = Field(default_factory=dict)

@app.post('/api/v1/system/restore/preflight')
def system_restore_preflight(data: RestorePreflight, request: Request):
    _require_policy_admin(request)
    restored, _, _ = maintenance.decrypt_backup(data.backup,data.password)
    adjusted,mapping,options,pending,errors = _restore_mapping(restored,data.interface_mapping)
    issues=errors + (['Mapeamento de interfaces por concluir'] if pending else [])
    if not issues:issues+=_restore_preflight(adjusted)
    with _lock:
        active=[p.get('host_ip',p.get('id','?')) for p in _policies.values() if p.get('status')=='active']
        if active:
            issues.append('Existem políticas activas para os hosts: '+', '.join(active)+'. Desactive/remova as políticas em Hosts e rotas antes do restauro.')
        for ident,item in _connections.items():
            action='vpn_status' if item.get('protocol')=='wireguard' else 'openvpn_status'
            try:
                state=_wireguard_agent_call(ident,action)
                if state.get('tunnel_active') or state.get('connected'):
                    issues.append('VPN activa: '+ident+'. Desligue o túnel antes do restauro.')
            except HTTPException:
                issues.append('Não foi possível verificar o estado VPN: '+ident)
    return {'compatible':not issues,'issues':issues,'mapping':mapping,'options':options,'pending':pending,'vpn_count':len(restored['connections']), 'host_count':len(restored['policies'])}

@app.post("/api/v1/system/restore")
def system_restore(data: MaintenancePayload, request: Request):
    _require_policy_admin(request)
    if data.confirmation != "RESTORE":
        raise HTTPException(422, "Confirmação RESTORE obrigatória")
    if data.backup is None or len(json.dumps(data.backup)) > maintenance.MAX_ENCRYPTED_BACKUP * 2:
        raise HTTPException(413, "Backup inexistente ou demasiado grande")
    restored, wgfiles, ovpn = maintenance.decrypt_backup(data.backup, data.password)
    restored, mapping, options, pending, errors = _restore_mapping(restored,data.interface_mapping)
    conflicts = errors + (['Mapeamento de interfaces por concluir'] if pending else [])
    if not conflicts: conflicts += _restore_preflight(restored)
    if conflicts:
        raise HTTPException(409, {'message':'Restauro bloqueado por incompatibilidade de topologia ou regras','issues':conflicts})
    with _lock:
        maintenance.safe_to_change(DB_PATH)
        if any(p.get("status")=="active" for p in _policies.values()):
            raise HTTPException(409, "Políticas activas impedem o restauro")
        # Never overwrite profile material while any managed tunnel is running.
        for item in _connections.values():
            status_action = 'vpn_status' if item.get('protocol')=='wireguard' else 'openvpn_status'
            state = _wireguard_agent_call(item['id'],status_action)
            if state.get('tunnel_active') or state.get('connected'):
                raise HTTPException(409,'Desligue todas as VPNs antes do restauro')
        # Strict replacement, including removal of profiles absent from the backup.
        incoming_ids = {row['id'] for row in restored['connections'] if json.loads(row['payload']).get('protocol') == 'openvpn'}
        old_ids = {ident for ident, profile in _connections.items() if profile.get('protocol') == 'openvpn'}
        all_ids = sorted(old_ids | incoming_ids)
        previous = {ident: _wireguard_agent_call(ident,'openvpn_backup_export') for ident in all_ids}
        completed = []
        try:
            for ident in all_ids:
                completed.append(ident)  # Include a partially failed replacement in rollback.
                _wireguard_agent_call(ident,'openvpn_backup_restore',files=ovpn.get(ident,{}))
            maintenance.restore_wireguard(DB_PATH,restored,wgfiles)
        except Exception:
            rollback_errors = []
            for ident in reversed(completed):
                try:
                    _wireguard_agent_call(ident,'openvpn_backup_restore',files=previous[ident])
                except Exception as error:
                    rollback_errors.append(ident + ': ' + str(error))
            if rollback_errors:
                raise HTTPException(500, 'Restauro falhou e rollback OpenVPN requer intervenção: ' + '; '.join(rollback_errors))
            raise
        _connections.clear();_policies.clear();_load()
    return {"restored":True,"requires_activation":True,"warning":"Configuração recuperada. Verifique interfaces, hosts e regras antes de aplicar."}

@app.post("/api/v1/system/defaults")
def system_defaults(data: MaintenancePayload, request: Request):
    """Replace all managed administrative and VPN material, never live routing state."""
    _require_policy_admin(request)
    if data.confirmation != "RESET":
        raise HTTPException(422, "Confirmação RESET obrigatória")
    global _revision
    with _lock:
        maintenance.safe_to_change(DB_PATH)
        # Verify actual dataplane state, not only the potentially stale DB status.
        for ident, entry in _policies.items():
            state = _policy_agent_call('status', ident, entry)
            if state.get('status') in ('active', 'pending', 'error') or state.get('applied'):
                raise HTTPException(409, 'Host com regras activas ou não verificáveis: ' + entry.get('host_ip', ident))
        for ident, profile in _connections.items():
            action = 'vpn_status' if profile.get('protocol') == 'wireguard' else 'openvpn_status'
            state = _wireguard_agent_call(ident, action)
            if state.get('tunnel_active') or state.get('connected'):
                raise HTTPException(409, 'VPN ainda activa: ' + ident)
        inventory=_policy_agent_call('maintenance_inventory','maintenance-audit',{})
        if inventory.get('policies'):
            raise HTTPException(409,'Estado residual no agente: '+', '.join(p['id'] for p in inventory['policies'])+'. Elimine as políticas pelos fluxos normais antes do reset.')
        if _policies:
            raise HTTPException(409,'Remova primeiro os hosts configurados.')
        # Prepare rollback copies before making any destructive change.
        vpn_ids = sorted(ident for ident, item in _connections.items() if item.get('protocol') == 'openvpn')
        old_openvpn = {ident: _wireguard_agent_call(ident, 'openvpn_backup_export') for ident in vpn_ids}
        # Preserve the management-LAN configuration so HTTPS administration and Restore stay authorised.
        baseline = maintenance.snapshot(DB_PATH)['data']
        cleared = {table: [] for table in maintenance.TABLES}
        cleared['network_config'] = baseline['network_config']
        changed = []
        try:
            for ident in vpn_ids:
                changed.append(ident)
                _wireguard_agent_call(ident, 'openvpn_backup_restore', files={})
            maintenance.restore_wireguard(DB_PATH, cleared, {})
        except Exception:
            failed=[]
            for ident in reversed(changed):
                try:
                    _wireguard_agent_call(ident, 'openvpn_backup_restore', files=old_openvpn[ident])
                except Exception:
                    failed.append(ident)
            if failed:
                raise HTTPException(500, 'Rollback de ficheiros OpenVPN incompleto: ' + ', '.join(failed))
            raise
        # Clear state of non-active policies only after backup and VPN reset succeeded.
        # Fail-closed host guards remain until explicitly purged by their API workflow.
        _connections.clear()
        _policies.clear()
        _revision += 1
    return {'reset': True, 'vpn_profiles': 0, 'host_policies': 0,
            'note': 'Perfis, regras e materiais VPN eliminados; LAN de gestão preservada para permitir o restauro.'}

@app.get("/api/v1/system/health")
def system_health():
    profiles = list_connections()
    overview = overview_status()
    stat = os.statvfs(os.path.dirname(DB_PATH))
    used = (stat.f_blocks - stat.f_bfree) * stat.f_frsize
    total = stat.f_blocks * stat.f_frsize
    return {"observed_at": datetime.now(timezone.utc).isoformat(),
            "webadmin": "operational", "profiles": len(profiles),
            "policies": len(list_policies()), "disk_total_bytes": total,
            "disk_used_bytes": used, "services": overview.get("services", {}),
            "database": "accessible", "scope": "application-read-only"}

@app.get("/api/v1/overview/status")
def overview_status():
    """Only measured metrics are reported; draft policies do not carry traffic."""
    # The independent VPN timeout service may have reverted a policy.
    list_policies()
    with _lock:
        policies = list(_policies.values())
        connections = list(_connections.values())
    measured = _gateway_traffic()
    routes = [{"id": "direct", "name": "Internet directa", "available": True,
               "active": False, "hosts": [], "rx_bps": None, "tx_bps": None,
               "measurement": "unavailable", "note": "Saída disponível; tráfego por rota não instrumentado"}]
    routes.append({"id": "blocked", "name": "BLOQUEADO", "available": False,
                   "active": False, "hosts": [], "rx_bps": None, "tx_bps": None,
                   "measurement": "unavailable", "note": "Política lógica; bloqueio ainda não aplicado"})
    interfaces_by_route = {}
    for conn in connections:
        vpn_state = {"tunnel_active": False, "connected": False, "state": "unavailable"}
        if conn.get("protocol") in ("wireguard", "openvpn"):
            try:
                vpn_state = _wireguard_agent_call(conn["id"], "vpn_status" if conn["protocol"] == "wireguard" else "openvpn_status")
                if conn["protocol"] == "openvpn":
                    vpn_state["interface"] = vpn_state.get("interface_name")
            except HTTPException:
                pass
        if vpn_state.get("interface"):
            interfaces_by_route[conn["id"]] = vpn_state["interface"]
        routes.append({"id": conn["id"], "name": conn["name"], "available": bool(vpn_state.get("connected")),
                       "active": bool(vpn_state.get("connected")), "tunnel_active": bool(vpn_state.get("tunnel_active")),
                       "vpn_state": vpn_state.get("state"), "hosts": [], "rx_bps": None, "tx_bps": None,
                       "measurement": "unavailable", "note": "Interface do túnel verificada; sem hosts associados" if vpn_state.get("connected") else "Túnel desligado ou ainda não estabelecido"})
    for policy in policies:
        effective_vpn = None
        for conn in connections:
            if conn.get("protocol") != "wireguard":
                continue
            try:
                observed_vpn = _wireguard_agent_call(conn["id"], "vpn_trial_status", policy_id=policy["id"])
                if observed_vpn.get("active"):
                    effective_vpn = conn["id"]
                    break
            except HTTPException:
                continue
        runtime_status = "draft"
        authorization_status = "unverified"
        try:
            runtime_state = _policy_agent_call("status", policy["id"], policy)
            authorization_status = runtime_state.get("authorization_status", "unverified")
            if runtime_state.get("status") in ("active", "pending", "reverted", "error"):
                runtime_status = runtime_state["status"]
            counters = runtime_state.get("counters")
            if runtime_status == "active" and policy["destination"] != "blocked" and counters and "rx_bytes" in counters and "tx_bytes" in counters:
                measured[(effective_vpn or policy["destination"], policy["host_ip"])] = (
                    int(counters["rx_bytes"]), int(counters["tx_bytes"]),
                    datetime.now(timezone.utc).timestamp())
        except HTTPException:
            pass
        for route in routes:
            if route["id"] == (effective_vpn or policy["destination"]):
                route["hosts"].append({"ip": policy["host_ip"], "status": "vpn_trial" if effective_vpn else runtime_status, "authorization_status": authorization_status,
                                       "rx_bps": None, "tx_bps": None,
                                       "rx_bytes": None, "tx_bytes": None})
    # Never count detected LAN devices or draft-only policies as active gateway clients.
    with _lock:
        for route in routes:
            for host in route["hosts"]:
                key = (route["id"], host["ip"])
                if key not in measured:
                    continue
                rx, tx, stamp = measured[key]
                prior = _traffic_previous.get(key)
                host["rx_bytes"], host["tx_bytes"] = _accumulate_host_traffic(route["id"],host["ip"],rx,tx)
                host["status"] = "gateway_measured"
                if prior and stamp > prior[2] and rx >= prior[0] and tx >= prior[1]:
                    elapsed = stamp - prior[2]
                    host["rx_bps"] = round((rx - prior[0]) * 8 / elapsed)
                    host["tx_bps"] = round((tx - prior[1]) * 8 / elapsed)
                _traffic_previous[key] = (rx, tx, stamp)
            samples = [h for h in route["hosts"] if h["status"] == "gateway_measured"]
            if samples:
                route["active"] = True
                if len(samples) == len(route["hosts"]) and all(h["rx_bps"] is not None and h["tx_bps"] is not None for h in samples):
                    route["rx_bps"] = sum(h["rx_bps"] for h in samples)
                    route["tx_bps"] = sum(h["tx_bps"] for h in samples)
                route["note"] = "Contadores do gateway; valores por host medidos, sem tráfego local do servidor"
    # Check the actual DNS listener, rather than displaying a static Pi-hole badge.
    pihole_dns = False
    try:
        with socket.create_connection(("pihole", 53), timeout=1):
            pihole_dns = True
    except OSError:
        pass
    wg_routes = [r for r in routes if r["id"] not in ("direct", "blocked", "unidentified-vpn")]
    connected_tunnels = sum(1 for r in wg_routes if r.get("tunnel_active") and r.get("available") and any(c["id"]==r["id"] and c.get("protocol")=="wireguard" for c in connections))
    all_tunnels = [{"id": r["id"], "name": r["name"], "protocol": next((c["protocol"] for c in connections if c["id"] == r["id"]), "unknown"),
                    "connected": bool(r.get("tunnel_active") and r.get("available")),
                    "interface": r.get("interface") or None}
                   for r in wg_routes]
    return {"services": {"pihole_dns": pihole_dns, "wireguard_connected": connected_tunnels,
                         "vpn_connected": sum(1 for t in all_tunnels if t["connected"]),
                         "vpn_tunnels": all_tunnels},
            "installed_version": app.version,
            "latest_version": os.environ.get("VPNGW_LATEST_VERSION") or None,
            "update_available": None, "routes": routes,
            "sample_interval_seconds": 5,
            "traffic_metrics_available": bool(measured),
            "note": "Valores não medidos são apresentados como indisponíveis, nunca como zero."}

@app.get("/api/v1/capabilities")
def capabilities():
    policies=list_policies()
    vpn=any(p["destination"] not in ("direct","blocked") and p.get("status")=="active" for p in policies)
    return {"gateway_mode":"per-host","explicit_proxy_mode":"not_required",
            "vpn_connections":"wireguard_openvpn","routing_policies":"persistent",
            "routing_active":any(p.get("status")=="active" for p in policies),
            "direct_host_ip":None,"vpn_routing_active":vpn}

@app.get("/api/v1/overview")
def overview():
    policies=list_policies()
    active=[p for p in policies if p.get("status")=="active"]
    direct=any(p["destination"]=="direct" for p in active)
    vpn=any(p["destination"] not in ("direct","blocked") for p in active)
    with _lock:
        return {"mode":"mixed","routing_active":bool(active),
                "connections":len(_connections),"policies":len(_policies),
                "revision":_revision,"direct_host_ip":None,
                "direct_active":direct,"vpn_routing_active":vpn,
                "message":"Estado efectivo das políticas por host"}


@app.get("/api/v1/connections")
def list_connections():
    # Do not confuse stored profile metadata with effective kernel tunnel state.
    with _lock:
        entries = [dict(item) for item in _connections.values()]
    inventory = {item["id"]: item for item in wireguard_profiles_status()["profiles"]}
    for entry in entries:
        if entry["protocol"] in ("wireguard", "openvpn"):
            observed = inventory.get(entry["id"], {})
            entry["configuration_stored"] = bool(observed.get("stored"))
            entry["configuration_valid"] = bool(observed.get("format_valid"))
            entry["tunnel_active"] = bool(observed.get("tunnel_active"))
            entry["connected"] = bool(observed.get("connected"))
            entry["runtime_status"] = observed.get("tunnel_state", "disconnected")
            entry["status"] = ("connected" if entry["connected"] else
                               "configured" if entry["configuration_valid"] else "not_configured")
    return entries


@app.put("/api/v1/connections/{connection_id}")
def update_connection(connection_id: str, data: Connection, request: Request):
    """Edit persistent profile metadata; never silently alter kernel VPN state."""
    _require_policy_admin(request)
    global _revision
    with _lock:
        old = _connections.get(connection_id)
        if not old:
            raise HTTPException(404, "Ligação VPN não encontrada")
        if data.id != connection_id or data.protocol != old["protocol"]:
            raise HTTPException(422, "ID e protocolo não podem ser alterados")
        if data.enabled != old["enabled"]:
            raise HTTPException(409, "Activação/desactivação do túnel exige operação própria")
        updated = {**old, "name": data.name, "provider": data.provider}
        _save("connections", connection_id, updated)
        _connections[connection_id] = updated
        _revision += 1
        return updated

@app.post("/api/v1/connections", status_code=201)
def create_connection(data: Connection):
    global _revision
    with _lock:
        if data.id in _connections:
            raise HTTPException(409, "Connection id already exists")
        entry = data.model_dump()
        entry["status"] = "not_configured"
        _save("connections", data.id, entry)
        _connections[data.id] = entry
        _revision += 1
        return entry

@app.delete("/api/v1/connections/{connection_id}", status_code=204)
def delete_connection(connection_id: str):
    """Never remove a VPN profile referenced by a host policy."""
    global _revision
    with _lock:
        if connection_id not in _connections:
            raise HTTPException(404, "Perfil VPN não encontrado")
        attached = sorted({p["host_ip"] for p in _policies.values() if p.get("destination") == connection_id})
        # Recheck live assignments at deletion time. A persistent host policy may
        # differ from the saved draft (e.g. Lenovo VPN vs legacy DIRECT).
        try:
            live_route = next((r for r in overview_status()["routes"] if r["id"] == connection_id), None)
            effective_hosts = {h["ip"] for h in (live_route or {}).get("hosts", [])}
        except Exception:
            raise HTTPException(503, "Não foi possível validar as associações efectivas. Eliminação bloqueada.")
        attached = sorted(set(attached) | effective_hosts)
        if attached:
            raise HTTPException(409, "Perfil associado a hosts: " + ", ".join(attached) + ". Remova primeiro as respectivas políticas em Hosts e rotas.")
        # The tunnel must be disconnected before its profile may be deleted.
        if _connections[connection_id].get("protocol") == "wireguard":
            try:
                state = _wireguard_agent_call(connection_id, "vpn_status")
            except Exception:
                raise HTTPException(503, "Estado da VPN não verificável. Eliminação bloqueada.")
            if state.get("tunnel_active"):
                raise HTTPException(409, "Desligue primeiro a VPN antes de eliminar o perfil.")
        if _connections[connection_id].get("protocol") == "openvpn":
            try:
                state = _wireguard_agent_call(connection_id, "openvpn_status")
            except Exception:
                raise HTTPException(503, "Estado OpenVPN não verificável. Eliminação bloqueada.")
            if state.get("tunnel_active") or state.get("connected"):
                raise HTTPException(409, "Desligue primeiro a ligação OpenVPN antes de eliminar.")
        if _connections[connection_id].get("enabled"):
            raise HTTPException(409, "Desactive o perfil antes de o eliminar")
        # WireGuard import is persistent on disk. Removing just the DB entry
        # would orphan private-key material and leave a misleading system state.
        # Stage deletion with a same-directory rename; restore on DB failure.
        staged = None
        if _connections[connection_id].get("protocol") == "wireguard":
            from pathlib import Path
            directory = Path("/data/wireguard-profiles")
            saved = directory / (connection_id + ".conf")
            if saved.is_symlink():
                raise HTTPException(409, "Configuração WireGuard suspeita; eliminação recusada")
            if saved.exists():
                staged = directory / ("." + connection_id + ".deleting")
                if staged.exists() or staged.is_symlink():
                    raise HTTPException(409, "Eliminação anterior por reconciliar")
                os.replace(saved, staged)
        # Stage OpenVPN managed files before removing metadata. A failed DB
        # update must restore the credentials, not orphan or lose them.
        openvpn_snapshot = None
        if _connections[connection_id].get("protocol") == "openvpn":
            openvpn_snapshot = _wireguard_agent_call(connection_id, "openvpn_backup_export")
            _wireguard_agent_call(connection_id, "openvpn_backup_restore", files={})
        try:
            _save("connections", connection_id)
        except Exception as error:
            if staged is not None:
                os.replace(staged, saved)
            if openvpn_snapshot is not None:
                try:
                    _wireguard_agent_call(connection_id, "openvpn_backup_restore", files=openvpn_snapshot)
                except Exception as rollback_error:
                    raise HTTPException(503, "Rollback OpenVPN incompleto; intervenção necessária") from rollback_error
            raise error
        del _connections[connection_id]
        _revision += 1
        if staged is not None:
            staged.unlink(missing_ok=True)


class HostIdentity(BaseModel):
    registered_mac: str = Field(pattern=r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")

@app.put("/api/v1/policies/{policy_id}/identity")
def register_host_identity(policy_id: str, data: HostIdentity, request: Request):
    """Save observed identity only; never change host addressing or packet routing."""
    _require_policy_admin(request)
    global _revision
    with _lock:
        previous=_policies.get(policy_id)
        if previous is None:raise HTTPException(404,"Política não encontrada")
        mac=data.registered_mac.lower()
        if any(x.get("registered_mac")==mac for key,x in _policies.items() if key!=policy_id):
            raise HTTPException(409,"MAC já registado")
        observed=network_neighbors()["hosts"]
        if not any(x.get("ip")==previous["host_ip"] and x.get("mac","").lower()==mac for x in observed):
            raise HTTPException(409,"Dispositivo não confirmado na LAN")
        if previous.get("status") == "active":
            applied = _policy_agent_call("identity_update", policy_id,
                                         {**previous, "registered_mac":mac})
            if not applied.get("guard_verified"):
                raise HTTPException(503, "Protecção MAC não confirmada")
        entry={**previous,"registered_mac":mac}
        try:
            _save("policies",policy_id,entry)
        except Exception:
            if previous.get("status") == "active" and previous.get("registered_mac"):
                _policy_agent_call("identity_update",policy_id,previous)
            raise
        _policies[policy_id]=entry
        _revision+=1
        return {"policy":policy_id,"registered_mac":mac,"network_changes":False}

@app.get("/api/v1/policies")
def list_policies():
    """Reflect verified effective agent assignments, including timed rollback."""
    global _revision
    with _lock:
        output = []
        for pid, entry in list(_policies.items()):
            item = dict(entry)
            try:
                live = _policy_agent_call("status", pid, item)
                assigned = (live.get("plan") or {}).get("destination")
                if (live.get("status") == "active" and
                    (assigned in ("direct", "blocked") or assigned in _connections)):
                    if item["destination"] != assigned:
                        item["destination"] = assigned
                        _save("policies", pid, item)
                        _policies[pid] = dict(item)
                        _revision += 1
                    pending = live.get("vpn_pending") or {}
                    if pending.get("deadline", 0) > datetime.now(timezone.utc).timestamp():
                        item["vpn_pending"] = True
                        item["vpn_deadline"] = pending["deadline"]
            except HTTPException:
                item["runtime_sync_unavailable"] = True
            output.append(item)
        return output

@app.post("/api/v1/policies", status_code=201)
def create_policy(data: Policy, request: Request):
    _require_policy_admin(request)
    global _revision
    with _lock:
        if data.id in _policies:
            raise HTTPException(409, "Policy id already exists")
        try:
            ip = ip_address(data.host_ip)
            if ip.version != 4 or ip.is_multicast or ip.is_unspecified or ip.is_loopback:
                raise ValueError("A valid unicast host IPv4 address is required")
            host_ip = str(ip)
        except ValueError as e:
            raise HTTPException(422, str(e))
        if data.destination not in ("direct", "blocked") and data.failure_mode == "direct":
            raise HTTPException(422, "Automatic direct fallback is not allowed for VPN-bound hosts")
        if data.destination != "direct" and any(h["host_ip"] == host_ip and h.get("service_active", False) for h in direct_hosts()["hosts"]):
            raise HTTPException(409, "Host has an active DIRECT systemd route; disable it before assigning VPN")
        if data.destination not in ("direct", "blocked"):
            _vpn_host_automation_ready(data.destination)
        if any(x["host_ip"] == host_ip for x in _policies.values()):
            raise HTTPException(409, "Host already has a policy")
        registered_mac = data.registered_mac.lower() if data.registered_mac else None
        if registered_mac:
            import re
            if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}",registered_mac):
                raise HTTPException(422,"MAC inválido")
            if any(p.get("registered_mac")==registered_mac for p in _policies.values()):
                raise HTTPException(409,"MAC associado a outra política")
            if not any(h.get("ip")==host_ip and h.get("mac","").lower()==registered_mac
                       for h in network_neighbors()["hosts"]):
                raise HTTPException(409,"MAC não corresponde ao dispositivo observado no IPv4 seleccionado")
        entry = {**data.model_dump(), "host_ip": host_ip, "registered_mac":registered_mac, "status": "draft"}
        if entry["destination"] == "direct":
            # Apply and confirm before persisting. Never leave a misleading draft
            # after a failed dataplane operation.
            try:
                _policy_agent_call("preflight", data.id, entry)
                _policy_agent_call("apply", data.id, entry)
                applied = _policy_agent_call("confirm", data.id, entry)
                if applied.get("status") != "active":
                    raise HTTPException(503, "Não foi possível confirmar a política DIRECT")
            except Exception:
                try:
                    _policy_agent_call("rollback", data.id, entry)
                except Exception:
                    raise HTTPException(503, "Falha ao configurar DIRECT; reversão não confirmada")
                raise
            entry["status"] = "active"
        try:
            _save("policies", data.id, entry)
        except Exception:
            if entry["destination"] == "direct":
                _policy_agent_call("rollback", data.id, entry)
            raise
        _policies[data.id] = entry
        _revision += 1
        return entry

@app.get("/api/v1/policies/{policy_id}/vpn-preflight")
def vpn_host_preflight(policy_id: str, profile_id: str):
    """Read-only host VPN route audit. Never installs rules or changes routes."""
    with _lock:
        policy = _policies.get(policy_id)
        profile = _connections.get(profile_id)
    if not policy:
        raise HTTPException(404, "Host não encontrado")
    if not profile:
        raise HTTPException(404, "Perfil VPN não encontrado")
    if profile.get("protocol") not in ("openvpn", "wireguard"):
        raise HTTPException(422, "Protocolo VPN inválido")
    if profile["protocol"] != "openvpn":
        # Existing WireGuard transition audit remains protocol-specific.
        return _wireguard_agent_call(profile_id, "vpn_transition_audit", policy_id=policy_id)
    return _wireguard_agent_call(profile_id, "vpn_openvpn_preflight", policy_id=policy_id)


@app.get("/api/v1/policies/{policy_id}/vpn-generic-preview")
def vpn_generic_preview(policy_id: str, profile_id: str):
    """Any configured IPv4 policy/profile pair, no hardcoded client/provider names.

    A preview does not indicate host-specific firewall/DNS readiness.
    """
    with _lock:
        policy=_policies.get(policy_id)
        profile=_connections.get(profile_id)
    if policy is None:
        raise HTTPException(404,"Política não encontrada")
    if profile is None or profile.get("protocol") not in ("openvpn","wireguard"):
        raise HTTPException(422,"Perfil VPN inválido")
    if policy.get("destination")!="direct":
        raise HTTPException(409,"Pré-teste de migração exige uma rota DIRECT actual")
    import ipaddress
    try:
        address=ipaddress.IPv4Address(policy.get("host_ip"))
        if address.is_multicast or address.is_loopback or address.is_unspecified:
            raise ValueError("Invalid host")
    except (ValueError,TypeError):
        raise HTTPException(422,"Endereço IPv4 do host inválido")
    return {"policy":policy_id,"host_ipv4":str(address),
            "route_name":policy.get("name") or policy_id,
            "current_route":policy.get("destination"),
            "vpn_id":profile_id,"vpn_name":profile.get("name") or profile_id,
            "vpn_protocol":profile.get("protocol"),
            "checks":{"host_configured":True,"vpn_profile_configured":True,
                      "host_specific_dns_guard":False,"live_client_egress":False,
                      "dns_ipv4_leak_test":False,"rollback_transaction":False},
            "cutover_enabled":False,"network_changes":False}


@app.get("/api/v1/policies/{policy_id}/transition-plan")
def host_transition_plan(policy_id: str, destination: str):
    """Read-only transition validation against live, persisted assignments."""
    import importlib.util
    with _lock:
        policy = dict(_policies[policy_id]) if policy_id in _policies else None
        profiles = {key: dict(value) for key, value in _connections.items()}
        active = [dict(value) for value in _policies.values()]
    if policy is None:
        raise HTTPException(404, "Política não encontrada")
    try:
        spec = importlib.util.spec_from_file_location("host_transition_plan", "/app/host_transition_plan.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        plan = module.plan_transition(policy["host_ip"], policy["destination"], destination, profiles, active)
    except (ValueError, KeyError, OSError) as error:
        raise HTTPException(422, str(error))
    return {**plan, "executor_available": False, "can_apply": False}


def _vpn_host_automation_ready(profile_id: str) -> None:
    """Reject unknown or unsupported profiles with a client error, not HTTP 500.

    Activation still requires the existing authenticated transition and
    kernel-level fail-closed verification; this only validates creation.
    """
    profile = _connections.get(profile_id)
    if profile is None:
        raise HTTPException(422, "Perfil VPN não encontrado")
    if profile.get("protocol") not in ("wireguard", "openvpn"):
        raise HTTPException(409, "Protocolo VPN não suportado")


def _vpn_profile_dns_ipv4(profile_id: str) -> str:
    """Resolve DNS from the profile already stored; never request reimport."""
    from pathlib import Path
    profile = _connections.get(profile_id)
    if not profile or profile.get("protocol") not in ("wireguard","openvpn"):
        raise HTTPException(422, "Perfil VPN não suportado")
    if profile.get("protocol") == "openvpn":
        status = _wireguard_agent_call(profile_id, "openvpn_status")
        dns = status.get("dns_ipv4")
        if not status.get("connected") or not dns:
            raise HTTPException(409,"OpenVPN sem túnel ligado e DNS IPv4 anunciado pelo fornecedor")
        return str(__import__("ipaddress").IPv4Address(dns))
    path = Path("/data/wireguard-profiles") / (profile_id + ".conf")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise HTTPException(409, "Configuração WireGuard inexistente ou inválida")
    import re
    match = re.search(r"^\s*DNS\s*=\s*(.+)$", path.read_text(encoding="utf-8"), re.I | re.M)
    if not match:
        raise HTTPException(409, "Perfil sem DNS configurado para a VPN")
    from ipaddress import IPv4Address
    candidates = [value.strip() for value in match.group(1).split(",")]
    try:
        ipv4 = [str(IPv4Address(value)) for value in candidates if ":" not in value]
    except ValueError:
        raise HTTPException(409, "Endereço DNS WireGuard inválido")
    if not ipv4 or ipv4[0] in ("0.0.0.0", "255.255.255.255"):
        raise HTTPException(409, "Perfil WireGuard sem DNS IPv4 utilizável")
    return ipv4[0]


@app.post("/api/v1/policies/{policy_id}/transition-vpn")
def apply_vpn_transition(policy_id: str, destination: str, request: Request):
    """Apply a timed host-scoped VPN transition with independent kernel rollback."""
    _require_policy_admin(request)
    global _revision
    with _lock:
        existing = _policies.get(policy_id)
        if not existing:
            raise HTTPException(404, "Host não encontrado")
        old = existing["destination"]
        if old == destination:
            return {"policy": existing, "changed": False}
        if old in ("direct", "blocked") and destination in ("direct", "blocked"):
            raise HTTPException(422, "Utilize a transição DIRECT/BLOQUEADO")
        if destination not in ("direct", "blocked") and destination not in _connections:
            raise HTTPException(422, "VPN não encontrada")
        if destination not in ("direct", "blocked"):
            profile = _connections[destination]
            if profile.get("protocol") not in ("wireguard","openvpn"):
                raise HTTPException(409, "Protocolo VPN não suportado")
            dns = _vpn_profile_dns_ipv4(destination)
        else:
            dns = None
        # The kernel MAC guard must already exist; also verify the host
        # identity against the current LAN discovery before switching.
        observed = [item for item in network_neighbors()["hosts"]
                    if item.get("ip") == existing["host_ip"] and item.get("mac")]
        if len(observed) != 1 or observed[0]["mac"].lower() != str(existing.get("registered_mac") or "").lower():
            raise HTTPException(409, "MAC actual do cliente não corresponde à política registada")
        try:
            runtime = _policy_agent_call("vpn_transition", policy_id,
                                         {**existing, "destination": destination, "dns_ipv4": dns})
            if runtime.get("status") != "active" or runtime.get("destination") != destination:
                raise HTTPException(503, "Rota VPN não confirmada no kernel")
            updated = {**existing, "destination": destination, "status": "active"}
            _save("policies", policy_id, updated)
        except Exception:
            try:
                _policy_agent_call("vpn_revert", policy_id, existing)
            except Exception:
                pass
            raise
        _policies[policy_id] = updated
        _revision += 1
        return {"policy": updated, "changed": True,
                "confirmation_required": runtime.get("confirmation_required", False),
                "deadline": runtime.get("deadline"),
                "fail_closed": runtime.get("fail_closed", False)}


@app.post("/api/v1/policies/{policy_id}/confirm-vpn")
def confirm_vpn_transition(policy_id: str, request: Request):
    _require_policy_admin(request)
    with _lock:
        current = _policies.get(policy_id)
        if not current:
            raise HTTPException(404, "Host não encontrado")
        return _policy_agent_call("vpn_confirm", policy_id, current)


@app.post("/api/v1/policies/{policy_id}/transition-basic")
def apply_basic_transition(policy_id: str, destination: str, request: Request):
    """Host-scoped DIRECT/BLOCKED transition; persistent DB follows verified firewall."""
    _require_policy_admin(request)
    if destination not in ("direct", "blocked"):
        raise HTTPException(422, "Transições VPN ainda não estão disponíveis")
    global _revision
    with _lock:
        entry = _policies.get(policy_id)
        if entry is None:
            raise HTTPException(404, "Política não encontrada")
        if entry["destination"] not in ("direct", "blocked"):
            raise HTTPException(409, "Origem VPN requer outro executor")
        previous = entry["destination"]
        if previous == destination:
            return entry
        try:
            state = _policy_agent_call("transition_basic", policy_id, {**entry, "destination": destination})
            if state.get("destination") != destination or state.get("status") != "active":
                raise HTTPException(503, "Alteração não confirmada pelo agente")
            updated = {**entry, "destination": destination, "status": "active"}
            _save("policies", policy_id, updated)
        except Exception:
            # Best-effort restore; no unverified success is reported.
            try:
                _policy_agent_call("transition_basic", policy_id, {**entry, "destination": previous})
            except Exception:
                pass
            raise
        _policies[policy_id] = updated
        _revision += 1
        return updated


@app.put("/api/v1/policies/{policy_id}")
def update_policy(policy_id: str, data: Policy):
    """Update the stored desired route; never touch dataplane networking."""
    global _revision
    with _lock:
        existing = _policies.get(policy_id)
        if existing is None:
            raise HTTPException(404, "Política não encontrada")
        if data.destination not in ("direct", "blocked"):
            _vpn_host_automation_ready(data.destination)
        _ensure_policy_not_active(policy_id, existing)
        if data.id != policy_id or data.host_ip != existing["host_ip"]:
            raise HTTPException(422, "O identificador e o IP do host não podem ser alterados")
        if data.destination not in ("direct", "blocked") and data.destination not in _connections:
            raise HTTPException(422, "Perfil VPN não encontrado")
        if data.destination not in ("direct", "blocked") and data.failure_mode != "block":
            raise HTTPException(422, "VPN exige fail-closed")
        if data.destination != "direct" and any(h["host_ip"] == existing["host_ip"] and h.get("service_active", False) for h in direct_hosts()["hosts"]):
            raise HTTPException(409, "Host com rota DIRECT activa; desactive-a antes de atribuir outra saída")
        entry = {**existing, "destination": data.destination, "failure_mode": "block", "status": "draft"}
        _save("policies", policy_id, entry)
        _policies[policy_id] = entry
        _revision += 1
        return entry


def _require_policy_admin(request: Request):
    """No extra password: allow changes only from management LAN over same-origin HTTPS."""
    source = request.headers.get("x-real-ip", "")
    origin = request.headers.get("origin", "")
    host = request.headers.get("host", "").split(":")[0]
    if request.headers.get("x-forwarded-proto") != "https" or origin != "https://" + host:
        raise HTTPException(403, "Operações de rede exigem HTTPS e origem local validada")
    if request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
        raise HTTPException(403, "Pedido de outra origem recusado")
    try:
        client = ip_address(source)
        config = get_network_config()["draft"]
        topology = network_topology()
        lan_names = {i["interface"] for i in config["interfaces"] if i["role"] == "lan"} if config else set()
        management = config["management_interface"] if config else None
        allowed = [ip_network(i["network"], strict=False) for i in topology["interfaces"]
                   if i["interface"] in lan_names and i.get("network") and i["operstate"] == "UP"]
        manager = [i["address"] for i in topology["interfaces"]
                   if i["interface"] == management and i.get("address")]
    except (ValueError, TypeError, KeyError):
        raise HTTPException(403, "Endereço de origem inválido")
    if not manager or host not in manager or not any(client in subnet for subnet in allowed):
        raise HTTPException(403, "Operação disponível apenas na LAN de gestão")


def _policy_agent_call(action, policy_id, entry):
    location = os.environ.get("VPNGW_POLICY_AGENT_SOCKET", "/run/vpngw-policy-agent/control.sock")
    secret = os.environ.get("VPNGW_POLICY_AGENT_SECRET", "/run/vpngw-policy-agent/secret")
    if not os.path.exists(location):
        raise HTTPException(503, "Agente de políticas indisponível")
    try:
        with open(secret, encoding="utf-8") as source:
            token = source.read().strip()
        payload = {"action": action, "id": policy_id, "token": token}
        if action == "status":
            payload["registered_mac"] = entry.get("registered_mac")
        if action == "identity_update":
            payload.update({"host_ip":entry["host_ip"], "registered_mac":entry["registered_mac"]})
        if action in ("transition_basic", "vpn_transition"):
            payload["destination"] = entry["destination"]
        if action == "vpn_transition":
            payload["dns_ipv4"] = entry.get("dns_ipv4")
        if action in ("apply", "preflight"):
            network_config = get_network_config()
            if action == "apply" and not network_config["applied"]:
                raise HTTPException(409, "Confirme primeiro a topologia actual em WAN/LAN")
            payload.update({"host_ip": entry["host_ip"],
                            "destination": entry["destination"],
                            "registered_mac":entry.get("registered_mac"),
                            "network": network_config["draft"]})
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(8)
            client.connect(location)
            client.sendall((json.dumps(payload) + "\n").encode())
            response = b""
            while not response.endswith(b"\n") and len(response) < 65536:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response += chunk
        result = json.loads(response)
    except (OSError, ValueError, TimeoutError) as error:
        raise HTTPException(503, "Falha de comunicação com agente: " + str(error))
    if not result.get("ok"):
        raise HTTPException(409, result.get("error", "Erro ao aplicar política"))
    return result["result"]


def _ensure_policy_not_active(policy_id, entry):
    location = os.environ.get("VPNGW_POLICY_AGENT_SOCKET", "/run/vpngw-policy-agent/control.sock")
    if os.path.exists(location):
        state = _policy_agent_call("status", policy_id, entry)
        if state.get("status") in ("pending", "active", "error"):
            raise HTTPException(409, "Reverta primeiro as regras existentes ou em erro deste host")


@app.get("/api/v1/policies/{policy_id}/runtime")
def policy_runtime(policy_id: str):
    with _lock:
        entry = _policies.get(policy_id)
        if not entry:
            raise HTTPException(404, "Política não encontrada")
    return _policy_agent_call("status", policy_id, entry)


@app.post("/api/v1/policies/{policy_id}/activate-restored")
def activate_restored_policy(policy_id: str, request: Request):
    """Bootstrap restored VPN draft fail-closed, then permit normal VPN cutover."""
    _require_policy_admin(request)
    global _revision
    with _lock:
        entry = _policies.get(policy_id)
        if entry is None:
            raise HTTPException(404, "Host não encontrado")
        if entry.get('status') != 'draft':
            raise HTTPException(409, 'A activação inicial exige uma política em rascunho')
        if entry.get('destination') not in _connections:
            raise HTTPException(409, 'Perfil VPN de destino inexistente')
        if not entry.get('registered_mac'):
            raise HTTPException(409, 'Identidade MAC obrigatória')
        observed = [host for host in network_neighbors()['hosts'] if host.get('ip') == entry['host_ip'] and host.get('mac')]
        if len(observed) != 1 or observed[0]['mac'].lower() != entry['registered_mac'].lower():
            raise HTTPException(409, 'MAC actual não coincide com o host associado')
        # The agent installs only DROP rules; VPN cutover is a separate confirmed operation.
        state = _policy_agent_call('apply', policy_id, {**entry, 'destination':'blocked'})
        if state.get('status') != 'pending' or not state.get('applied'):
            raise HTTPException(503, 'Não foi possível activar o bloqueio inicial')
        _policy_agent_call('confirm', policy_id, entry)
        updated = {**entry, 'destination':'blocked', 'status':'active'}
        _save('policies', policy_id, updated)
        _policies[policy_id] = updated
        _revision += 1
        return {'activated':True,'route':'blocked','desired_vpn':entry['destination'], 'note':'Host bloqueado; execute a transição VPN depois de ligar o túnel.'}

@app.post("/api/v1/policies/{policy_id}/apply")
def policy_apply(policy_id: str, request: Request):
    _require_policy_admin(request)
    with _lock:
        entry = _policies.get(policy_id)
        if not entry:
            raise HTTPException(404, "Política não encontrada")
        if entry["destination"] not in ("direct", "blocked"):
            raise HTTPException(409, "VPN ainda não dispõe de túnel validado")
        return _policy_agent_call("apply", policy_id, entry)


@app.post("/api/v1/policies/{policy_id}/confirm")
def policy_confirm(policy_id: str, request: Request):
    _require_policy_admin(request)
    with _lock:
        entry = _policies.get(policy_id)
        if not entry:
            raise HTTPException(404, "Política não encontrada")
        return _policy_agent_call("confirm", policy_id, entry)


@app.post("/api/v1/policies/{policy_id}/rollback")
def policy_rollback(policy_id: str, request: Request):
    _require_policy_admin(request)
    with _lock:
        entry = _policies.get(policy_id)
        if not entry:
            raise HTTPException(404, "Política não encontrada")
        return _policy_agent_call("rollback", policy_id, entry)


@app.get("/api/v1/policies/{policy_id}/preflight")
def policy_preflight(policy_id: str):
    """Read-only policy readiness using configured WAN/LAN roles, never fixed interface names."""
    with _lock:
        policy = _policies.get(policy_id)
        if policy is None:
            raise HTTPException(404, "Política não encontrada")
        policy = dict(policy)
        connection = _connections.get(policy["destination"])
    config = get_network_config()["draft"]
    topology = network_topology()
    errors = []
    if not config:
        errors.append("Configure e guarde WAN/LAN primeiro")
    roles = {item["interface"]: item["role"] for item in config["interfaces"]} if config else {}
    management = config["management_interface"] if config else None
    lan = [name for name, role in roles.items() if role == "lan"]
    wan = [name for name, role in roles.items() if role == "wan"]
    if config and config["mode"] == "shared":
        wan = [management]
    live = {item["interface"] for item in topology["interfaces"] if item["operstate"] == "UP"}
    if any(name not in live for name in set(lan + wan)):
        errors.append("Interface LAN/WAN configurada não está UP")
    if not lan or not wan:
        errors.append("Falta uma interface LAN ou uma saída WAN")
    gateways = [route for route in topology["default_routes"] if route["interface"] in wan and route.get("gateway")]
    if not gateways and policy["destination"] == "direct":
        errors.append("Gateway de saída não detectado na WAN configurada")
    try:
        host = ip_address(policy["host_ip"])
        networks = [ip_network(item["network"], strict=False) for item in topology["interfaces"]
                    if item["interface"] in lan and item.get("network")]
        if not any(host in network for network in networks):
            errors.append("O IP do host não pertence à rede LAN configurada")
    except ValueError:
        errors.append("Endereço IP ou rede LAN inválidos")
    if policy["destination"] not in ("direct", "blocked"):
        if connection is None:
            errors.append("Perfil VPN inexistente")
        else:
            if connection.get("protocol") != "wireguard":
                errors.append("O encaminhamento de OpenVPN ainda não está implementado")
            else:
                try:
                    tunnel = _wireguard_agent_call(connection["id"], "vpn_status")
                    if not tunnel.get("connected"):
                        errors.append("WireGuard sem handshake recente")
                    if not tunnel.get("tunnel_active"):
                        errors.append("Interface WireGuard não está activa")
                except HTTPException:
                    errors.append("Não foi possível verificar o estado WireGuard")
            if config and config.get("mode") == "shared":
                errors.append("LAN e router partilham a mesma interface: o gateway não controla desvios directos dos clientes para o router")
            errors.append("Falta implementar e testar encaminhamento exclusivo VPN com firewall fail-closed e reversão automática")
            errors.append("Falta validar isolamento DNS por VPN e bloqueio de fugas fora do túnel")
    if not get_network_config()["applied"]:
        errors.append("Confirme primeiro a topologia em WAN/LAN")
    elif policy["destination"] in ("direct", "blocked"):
        try:
            _policy_agent_call("preflight", policy_id, policy)
        except HTTPException as error:
            errors.append(str(error.detail))
    return {"policy_id": policy_id, "host_ip": policy["host_ip"],
            "destination": policy["destination"], "lan_interfaces": lan,
            "wan_interfaces": wan, "gateways": gateways,
            "ready": not errors, "applied": False, "errors": errors}


@app.delete("/api/v1/policies/{policy_id}", status_code=204)
def delete_policy(policy_id: str, request: Request):
    _require_policy_admin(request)
    global _revision
    with _lock:
        if policy_id not in _policies:
            raise HTTPException(404, "Unknown policy")
        entry = _policies[policy_id]
        if any(h["host_ip"] == entry["host_ip"] and h.get("service_active", False) for h in direct_hosts()["hosts"]):
            raise HTTPException(409, "Host DIRECT gerido por systemd: remoção automática não autorizada")
        if entry["destination"] in ("direct", "blocked"):
            _policy_agent_call("rollback", policy_id, entry)
            state = _policy_agent_call("status", policy_id, entry)
            if state.get("applied") or state.get("status") in ("active", "pending", "error"):
                raise HTTPException(503, "Não foi possível confirmar a remoção das regras")
        else:
            _ensure_policy_not_active(policy_id, entry)
        _policy_agent_call("purge_host", policy_id, entry)
        with closing(_connect()) as db, db:
            db.execute("DELETE FROM host_traffic_totals WHERE ip=?", (entry["host_ip"],))
        _save("policies", policy_id)
        del _policies[policy_id]
        _revision += 1


class DnsModuleDraft(BaseModel):
    enabled: bool = False
    upstream_ipv4: list[str] = Field(default_factory=list, max_length=8)
    block_on_vpn_failure: bool = True
    lan_only: bool = True


def _validate_dns_draft(data: DnsModuleDraft):
    if not data.lan_only:
        raise HTTPException(422, "DNS listening on WAN is forbidden")
    if not data.block_on_vpn_failure:
        raise HTTPException(422, "VPN DNS fail-open is forbidden")
    if data.enabled and not data.upstream_ipv4:
        raise HTTPException(422, "At least one external DNS resolver is required")
    normalized = []
    for value in data.upstream_ipv4:
        try:
            address = ip_address(value)
        except ValueError:
            raise HTTPException(422, "Invalid upstream DNS IPv4 address")
        if address.version != 4 or not address.is_global:
            raise HTTPException(422, "Upstream DNS must be a public unicast IPv4 address")
        if str(address) in normalized:
            raise HTTPException(422, "Duplicate upstream DNS address")
        normalized.append(str(address))
    return normalized


@app.get("/api/v1/dns/bindings")
def dns_bindings():
    """Read-only planned DNS/admin listeners on the actual management IPv4."""
    topology = network_topology()
    saved = get_network_config()["draft"]
    management = saved["management_interface"] if saved else None
    if not management:
        candidates = [i for i in topology["interfaces"] if i.get("kind") == "ethernet" and i.get("operstate") == "UP"]
        management = candidates[0]["interface"] if candidates else None
    addresses = [i["address"] for i in topology["interfaces"] if i["interface"] == management and i.get("address")]
    address = addresses[0] if len(addresses) == 1 else None
    return {"management_interface": management, "management_ipv4": address,
            "webadmin_port": 8080, "pihole_admin_port": 8081, "dns_port": 53,
            "pihole_admin_url": f"http://{address}:8081" if address else None,
            "dns_client_server": address, "applied": False,
            "ready": bool(address),
            "note": "Read-only target bindings; Pi-hole listeners are not configured."}


@app.get("/api/v1/dns/summary")
def dns_summary():
    """Read-only status of isolated Pi-hole; never changes host routing or DNS."""
    import urllib.request
    topology = network_topology()
    configured = get_network_config().get("draft") or {}
    management_iface = configured.get("management_interface")
    management_addresses = [i["address"] for i in topology["interfaces"]
                            if i.get("interface") == management_iface and i.get("address")]
    management_ip = management_addresses[0] if len(management_addresses) == 1 else None
    admin_port = int(os.environ.get("VPNGW_PIHOLE_HTTPS_PORT", "8443"))
    admin_url = f"https://{management_ip}:{admin_port}/admin/" if management_ip else None
    result = {"reachable": False, "dns_enabled": None, "version": None,
              "admin_url": admin_url,
              "scope": "isolated", "routing_managed_by": "Gateway VPN Multi",
              "host_dns_changed": False, "client_dns_changed": False}
    for path, field in (("/api/info/version", "version"), ("/api/dns/status", "dns_enabled")):
        try:
            with urllib.request.urlopen("http://pihole" + path, timeout=2) as response:
                payload = json.loads(response.read(65536))
            result["reachable"] = True
            if field == "version":
                result[field] = str(payload.get("version", {}).get("core", {}).get("local", {}).get("version") or "Indisponível")
            else:
                result[field] = payload.get("dns", {}).get("blocking") if isinstance(payload.get("dns"), dict) else None
        except Exception:
            continue
    return result


@app.get("/api/v1/dns/live-dashboard")
def dns_live_dashboard():
    """Read-only live Pi-hole statistics and effective VPN DNS route status."""
    stats = None
    try:
        with urllib.request.urlopen("http://pihole/api/stats/summary", timeout=3) as response:
            data = json.load(response)
        queries = data.get("queries") or {}
        gravity = data.get("gravity") or {}
        clients = data.get("clients") or {}
        stats = {"total": int(queries["total"]), "blocked": int(queries["blocked"]),
                 "percent_blocked": float(queries["percent_blocked"]),
                 "domains": int(gravity["domains_being_blocked"]),
                 "active_clients": int(clients.get("active", 0)),
                 "cached": int(queries.get("cached", 0))}
    except (OSError, ValueError, KeyError, TypeError):
        pass
    vpn_dns_reachable = False
    dns_worker=os.environ.get("VPNGW_VPN_DNS_WORKER")
    if dns_worker:
        try:
            host,port=dns_worker.rsplit(":",1)
            with socket.create_connection((host,int(port)),timeout=1):
                vpn_dns_reachable=True
        except (ValueError,OSError):
            pass
    return {"stats": stats, "primary_dns": bool(dns_summary()["reachable"]),
            "vpn_resolver_reachable": True if vpn_dns_reachable else None,
            "vpn_host_ip": None, "vpn_host_mode": None,
            "vpn_host_guard": False, "vpn_host_routed": False,
            "dns_sync": "configured_30min" if vpn_dns_reachable else "not_verifiable_from_webadmin",
            "admin_url": dns_summary().get("admin_url")}

@app.get("/api/v1/dns/admin-status")
def dns_admin_status():
    """Dockerized Pi-hole status: probe the DNS service, not host binaries."""
    summary = dns_summary()
    running = bool(summary["reachable"])
    return {"installed": running, "running": running,
            "admin_available": running and bool(summary.get("admin_url")),
            "admin_url": summary.get("admin_url") if running else None,
            "access": "Proxy HTTPS pela LAN de gestão",
            "note": "Serviço Pi-hole em contentor Docker; instalação no host não necessária."}


@app.get("/api/v1/dns/config")
def get_dns_config():
    with closing(_connect()) as db:
        db.execute("CREATE TABLE IF NOT EXISTS dns_config (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)")
        row = db.execute("SELECT payload FROM dns_config WHERE id=1").fetchone()
    return {"draft": json.loads(row[0]) if row else None, "applied": False,
            "installed": False, "note": "Saved settings only; no DNS service changes"}


@app.put("/api/v1/dns/config")
def save_dns_config(data: DnsModuleDraft):
    upstream = _validate_dns_draft(data)
    draft = {**data.model_dump(), "upstream_ipv4": upstream}
    with _lock, closing(_connect()) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS dns_config (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)")
        db.execute("INSERT OR REPLACE INTO dns_config(id,payload) VALUES(1,?)", (json.dumps(draft),))
    return {"draft": draft, "applied": False, "installed": False}


@app.get("/api/v1/dns/policy-preview")
def dns_policy_preview():
    """Read-only Pi-hole design preview; no resolver or firewall is configured."""
    with _lock:
        policies = list(_policies.values())
        connections = dict(_connections)
    clients = []
    for policy in policies:
        target = policy["destination"]
        is_direct = target == "direct"
        vpn = connections.get(target) if not is_direct else None
        clients.append({
            "client_ip": policy["host_ip"],
            "dns_service": "pihole_planned",
            "egress": "direct" if is_direct else "vpn",
            "connection_id": None if is_direct else target,
            "failure_mode": policy["failure_mode"],
            "vpn_configured": bool(vpn) if not is_direct else None,
            "dns_leak_protection_required": not is_direct,
            "enforcement": "not_implemented",
        })
    return {
        "module": "pihole", "installed": False, "applied": False,
        "listen_scope": "lan_only_planned", "wan_dns_allowed": False,
        "client_policy_isolation": "required_not_implemented",
        "upstream_dns": "not_configured",
        "clients": clients,
        "note": "Design preview only. DNS is not routed or filtered by this endpoint."
    }


@app.get("/api/v1/dns/isolation-plan")
def dns_isolation_plan():
    """Plan DNS isolation boundaries without executing firewall, Pi-hole or VPN changes."""
    with _lock:
        policies = sorted(_policies.values(), key=lambda x: x["host_ip"])
        connections = dict(_connections)
    groups = {}
    for entry in policies:
        destination = entry["destination"]
        group_id = "direct" if destination == "direct" else "vpn:" + destination
        group = groups.setdefault(group_id, {
            "id": group_id, "destination": destination,
            "clients": [], "resolver_isolation": "required",
            "upstream_route": "direct" if destination == "direct" else "vpn_only",
            "deny_non_vpn_dns": destination != "direct",
            "ready": False, "reasons": []
        })
        group["clients"].append(entry["host_ip"])
    for group in groups.values():
        group["reasons"].append("Pi-hole resolver and per-group DNS isolation not installed")
        if group["destination"] != "direct":
            if group["destination"] not in connections:
                group["reasons"].append("VPN configuration is missing")
            group["reasons"].append("VPN routing and DNS leak firewall protection not active")
    return {
        "applied": False, "safe_to_apply": False,
        "wan_listener_allowed": False, "groups": list(groups.values()),
        "requirements": ["LAN-only DNS listener", "Client-aware policy dispatch",
                         "Isolated resolver egress per destination", "Block VPN DNS fallback to DIRECT",
                         "Atomic firewall apply and rollback"],
        "note": "Read-only design plan. No DNS services, network routes or firewall rules changed."
    }


@app.get("/api/v1/routing/preview")
def routing_preview():
    """Read-only effective policy preview. Never changes OS routing."""
    direct_active = direct_host_status()["active"]
    with _lock:
        rows = []
        for entry in sorted(_policies.values(), key=lambda p: p["host_ip"]):
            vpn = _connections.get(entry["destination"])
            rows.append({
                "host_ip": entry["host_ip"],
                "destination": entry["destination"],
                "route_type": "direct" if vpn is None else "vpn",
                "vpn_protocol": vpn["protocol"] if vpn else None,
                "tunnel_ready": False if vpn else None,
                "effective_action": "direct" if vpn is None else "block_until_tunnel_ready",
                "applied": bool(entry.get("status") == "active"),
            })
        return {"mode": "mixed", "applied": any(r["applied"] for r in rows), "default_policy": "not_configured", "rules": rows}


@app.get("/api/v1/diagnostics/runtime")
def runtime_diagnostics():
    """Read-only diagnostics; does not create interfaces, routes or firewall rules."""
    def check_binary(binary):
        return shutil.which(binary) is not None
    def check_capability(bit):
        try:
            with open("/proc/self/status", encoding="utf-8") as stream:
                line = next(row for row in stream if row.startswith("CapEff:"))
            return bool(int(line.split()[1], 16) & (1 << bit))
        except (OSError, StopIteration, ValueError):
            return False
    return {
        "mode": "read_only",
        "network_changes_enabled": False,
        "tools": {"iproute2": check_binary("ip"), "wireguard": check_binary("wg"), "openvpn": check_binary("openvpn") or os.path.exists("/usr/sbin/openvpn"), "nftables": check_binary("nft") or os.path.exists("/usr/sbin/nft")},
        "capabilities": {"net_admin": check_capability(12), "sys_admin": check_capability(21)},
        "tun_device": os.path.exists("/dev/net/tun") or any(str(v.get("interface_name") or "").startswith("tun") and v.get("tunnel_active") for v in wireguard_profiles_status()["profiles"]),
        "isolation": "not_configured",
        "tunnels": [],
    }


@app.get("/api/v1/diagnostics/direct")
def direct_diagnostics():
    """Read-only IPv4 direct egress check from the DEV server itself."""
    target = "1.1.1.1"
    result = {"mode": "server_egress_only", "vpn_used": False, "client_forwarding_tested": False,
              "target": target, "route": None, "http_status": None, "reachable": False,
              "timestamp": datetime.now(timezone.utc).isoformat()}
    try:
        route = subprocess.run(["/usr/bin/ip", "-4", "route", "get", target],
                               capture_output=True, text=True, timeout=3, check=True)
        result["route"] = route.stdout.strip().splitlines()[0]
    except (OSError, subprocess.SubprocessError) as exc:
        result["error"] = type(exc).__name__
        return result
    try:
        request = urllib.request.Request("https://www.cloudflare.com/cdn-cgi/trace",
                                         headers={"User-Agent": "VPNGateway-DEV-DirectProbe/1"})
        with urllib.request.urlopen(request, timeout=6) as response:
            result["http_status"] = response.status
            payload = response.read(2048).decode("utf-8", errors="replace")
            result["reachable"] = response.status == 200
            result["public_ipv4"] = next((line[3:] for line in payload.splitlines()
                                          if line.startswith("ip=")), None)
            result["warp"] = next((line[5:] for line in payload.splitlines()
                                   if line.startswith("warp=")), None)
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        result["error"] = type(exc).__name__
    return result


@app.get("/api/v1/direct/status")
def direct_host_status():
    hosts=[p for p in list_policies() if p["destination"]=="direct"]
    return {"host_ip":None,"gateway_ip":None,"destination":"direct",
            "active":any(p.get("status")=="active" for p in hosts),
            "service_active":None,"firewall_rules_verified":None,
            "scope":"policy_host_set","hosts":[p["host_ip"] for p in hosts]}


@app.post("/api/v1/network/discover")
def discover_lan():
    """Explicit low-rate ICMP sweep, DEV LAN only."""
    if not _discovery_lock.acquire(blocking=False):
        raise HTTPException(409,"Descoberta LAN já em execução")
    try:
        allowed=_discovery_lan_networks(network_topology())
        location=os.environ.get("VPNGW_POLICY_AGENT_SOCKET","/run/vpngw-policy-agent/control.sock")
        secret=os.environ.get("VPNGW_POLICY_AGENT_SECRET","/run/vpngw-policy-agent/secret")
        with open(secret,encoding="utf-8") as f:
            token=f.read().strip()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(85)
            client.connect(location)
            client.sendall((json.dumps({"action":"lan_discover","id":"lan-discovery",
                       "interfaces":list(allowed),"token":token})+"\n").encode())
            answer=b""
            while not answer.endswith(b"\n") and len(answer)<131072:
                chunk=client.recv(4096)
                if not chunk:break
                answer+=chunk
        response=json.loads(answer)
        if not response.get("ok") or not response.get("result",{}).get("completed"):
            raise HTTPException(503,"Descoberta LAN não concluída")
        # Refresh host-side passive snapshot after the sweep, once only.
        # New ARP neighbors created by ping are now visible to WebAdmin via
        # the host snapshot timer. Return only scan-completed IPs with MACs
        # from the existing trusted-format snapshot, excluding other networks.
        scan=response["result"]["networks"]
        if {r["network"] for r in scan}!={str(n) for n in allowed.values()}:
            raise HTTPException(503,"Descoberta fora da LAN configurada")
        snapshot=network_neighbors()
        responded={ip for r in scan for ip in r["responded"]}
        hosts=[h for h in snapshot["hosts"] if h["ip"] in responded]
        return {"hosts":hosts,"lan_cidrs":{k:str(v) for k,v in allowed.items()},
                "complete":True,"network_changes":False}
    finally:
        _discovery_lock.release()


class InterfaceRole(BaseModel):
    interface: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,32}$")
    role: Literal["wan", "lan", "unused"]
    label: str = Field(default="", max_length=64)
    address_mode: Literal["static", "dhcp"] | None = None
    ipv4_address: str | None = None
    prefix_length: int | None = Field(default=None, ge=1, le=32)
    gateway_ipv4: str | None = None
    dns_ipv4: list[str] = Field(default_factory=list, max_length=4)

class NetworkDraft(BaseModel):
    mode: Literal["shared", "routed", "multi_lan"]
    interfaces: list[InterfaceRole] = Field(min_length=1, max_length=32)
    management_interface: str
    wan_webadmin_enabled: bool = False
    wan_webadmin_allowed_cidrs: list[str] = Field(default_factory=list, max_length=32)

@app.get("/api/v1/network/config")
def get_network_config():
    with closing(_connect()) as db:
        db.execute("CREATE TABLE IF NOT EXISTS network_config (id INTEGER PRIMARY KEY CHECK (id=1), payload TEXT NOT NULL)")
        row = db.execute("SELECT payload FROM network_config WHERE id=1").fetchone()
    draft = json.loads(row[0]) if row else None
    with closing(_connect()) as db:
        db.execute("CREATE TABLE IF NOT EXISTS network_applied (id INTEGER PRIMARY KEY CHECK (id=1), fingerprint TEXT NOT NULL)")
        applied_row = db.execute("SELECT fingerprint FROM network_applied WHERE id=1").fetchone()
    fingerprint = hashlib.sha256(json.dumps(draft, sort_keys=True).encode()).hexdigest() if draft else None
    return {"draft": draft, "applied": bool(applied_row and applied_row[0] == fingerprint)}

@app.put("/api/v1/network/config")
def save_network_config(data: NetworkDraft):
    topology = network_topology()
    available = {i["interface"] for i in topology["interfaces"] if i["operstate"] == "UP" and i.get("kind") in ("wifi", "ethernet", "vlan")}
    names = [i.interface for i in data.interfaces]
    if len(names) != len(set(names)) or set(names) != available:
        raise HTTPException(422, "Specify each detected IPv4 interface exactly once")
    if data.management_interface not in available:
        raise HTTPException(422, "Management interface must be available and UP")
    if next(i.role for i in data.interfaces if i.interface == data.management_interface) != "lan":
        raise HTTPException(422, "WebAdmin management interface must have LAN/client role")
    physical = {i["interface"] for i in topology["interfaces"] if i.get("kind") in ("ethernet", "wifi") and i.get("operstate") == "UP"}
    if data.mode == "routed" and len(physical) < 2:
        raise HTTPException(422, "WAN/LAN separadas exigem duas interfaces de rede físicas disponíveis")
    if data.mode == "multi_lan" and len(physical) < 3:
        raise HTTPException(422, "Multi-LAN exige pelo menos três interfaces físicas disponíveis")
    roles = [i.role for i in data.interfaces]
    if data.mode == "shared":
        if roles.count("lan") != 1 or roles.count("wan") != 0 or next(i.role for i in data.interfaces if i.interface == data.management_interface) != "lan":
            raise HTTPException(422, "Shared mode needs one LAN and no WAN")
    elif roles.count("wan") != 1 or roles.count("lan") < 1:
        raise HTTPException(422, "Routed mode needs one WAN and at least one LAN")
    if data.mode == "routed" and roles.count("lan") != 1:
        raise HTTPException(422, "Routed mode needs exactly one LAN")
    if data.mode == "multi_lan" and roles.count("lan") < 2:
        raise HTTPException(422, "Multi-LAN mode needs at least two LANs")
    if data.wan_webadmin_enabled and data.mode == "shared":
        raise HTTPException(422, "Separate WAN access authorization is not applicable to shared LAN mode")
    if data.wan_webadmin_enabled and not data.wan_webadmin_allowed_cidrs:
        raise HTTPException(422, "WAN WebAdmin authorization requires at least one allowed CIDR")
    if not data.wan_webadmin_enabled and data.wan_webadmin_allowed_cidrs:
        raise HTTPException(422, "Clear allowed CIDRs when WAN WebAdmin access is disabled")
    try:
        networks = [ip_network(value, strict=True) for value in data.wan_webadmin_allowed_cidrs]
    except ValueError:
        raise HTTPException(422, "Invalid WAN WebAdmin CIDR")
    if len(set(networks)) != len(networks):
        raise HTTPException(422, "Duplicate WAN WebAdmin CIDR")
    if data.wan_webadmin_enabled and any(network.prefixlen == 0 for network in networks):
        raise HTTPException(422, "WAN WebAdmin authorization cannot allow the entire Internet")
    # Validate installation intent without changing the running interfaces.
    configured_lans = []
    wan_config = None
    for item in data.interfaces:
        if item.role == "unused":
            continue
        if data.mode != "shared" and item.address_mode is None:
            raise HTTPException(422, f"Seleccione DHCP/estático para {item.interface}")
        mode = item.address_mode or ("static" if item.role == "lan" else "dhcp")
        if item.role == "lan" and data.mode != "shared" and mode != "static":
            raise HTTPException(422, f"A LAN {item.interface} exige IPv4 estático")
        if mode == "dhcp":
            if item.ipv4_address or item.prefix_length is not None or item.gateway_ipv4 or item.dns_ipv4:
                raise HTTPException(422, f"Limpe os campos IPv4 manuais em {item.interface} (DHCP)")
            continue
        if data.mode == "shared" and not item.ipv4_address and item.prefix_length is None:
            # Legacy running topology: keep adoption of the current network possible.
            continue
        if not item.ipv4_address or item.prefix_length is None:
            raise HTTPException(422, f"IP e prefixo estáticos obrigatórios em {item.interface}")
        try:
            address = ip_address(item.ipv4_address)
            segment = ip_network(f"{address}/{item.prefix_length}", strict=False)
            if address.version != 4 or not address.is_private or address in (segment.network_address, segment.broadcast_address):
                raise ValueError("Endereço IPv4 não utilizável")
            if item.role == "wan":
                if not item.gateway_ipv4:
                    raise ValueError("Gateway obrigatório na WAN estática")
                gateway = ip_address(item.gateway_ipv4)
                if gateway.version != 4 or gateway not in segment or gateway == address:
                    raise ValueError("Gateway WAN fora da sub-rede ou igual ao IP WAN")
            elif item.gateway_ipv4:
                raise ValueError("A LAN não deve definir gateway de saída")
            for server in item.dns_ipv4:
                if ip_address(server).version != 4:
                    raise ValueError("Apenas DNS IPv4")
        except ValueError as exc:
            raise HTTPException(422, f"{item.interface}: {exc}")
        if item.role == "lan":
            configured_lans.append(segment)
        elif item.role == "wan":
            wan_config = segment
    if any(left.overlaps(right) for index, left in enumerate(configured_lans)
           for right in configured_lans[index+1:]):
        raise HTTPException(422, "As sub-redes LAN não podem sobrepor-se")
    if wan_config and any(wan_config.overlaps(lan) for lan in configured_lans):
        raise HTTPException(422, "As sub-redes LAN e WAN não podem sobrepor-se")
    payload = data.model_dump()
    with _lock:
        for policy_id, entry in _policies.items():
            _ensure_policy_not_active(policy_id, entry)
    with closing(_connect()) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS network_config (id INTEGER PRIMARY KEY CHECK (id=1), payload TEXT NOT NULL)")
        db.execute("INSERT OR REPLACE INTO network_config(id,payload) VALUES(1,?)", (json.dumps(payload),))
        db.execute("CREATE TABLE IF NOT EXISTS network_applied (id INTEGER PRIMARY KEY CHECK (id=1), fingerprint TEXT NOT NULL)")
        db.execute("DELETE FROM network_applied WHERE id=1")
    return {"draft": payload, "applied": False, "message": "Draft saved only; no OS network changes"}

@app.get("/api/v1/network/flow-preview")
def network_flow_preview():
    """Single read-only topology contract for downstream VPN, DNS and firewall modules."""
    saved = get_network_config()
    draft = saved["draft"]
    if not draft:
        return {"ready": False, "applied": False, "reason": "Configure WAN/LAN primeiro",
                "network_changes": False, "interfaces": []}
    observed = network_topology()
    detected = {item["interface"]: item for item in observed["interfaces"]}
    interfaces = []
    for item in draft["interfaces"]:
        if item["role"] == "unused":
            continue
        current = detected.get(item["interface"]) or {}
        proposed_mode = item.get("address_mode") or ("static" if item["role"] == "lan" else "dhcp")
        interfaces.append({
            "interface": item["interface"], "role": item["role"], "address_mode": proposed_mode,
            "configured_address": item.get("ipv4_address"),
            "configured_prefix": item.get("prefix_length"),
            "configured_gateway": item.get("gateway_ipv4"),
            "configured_dns": item.get("dns_ipv4") or [],
            "observed_address": current.get("address"),
            "observed_prefix": current.get("prefixlen"),
            "observed_active": current.get("operstate") == "UP"
        })
    return {"mode": draft["mode"], "ready": bool(saved["applied"]),
            "applied": bool(saved["applied"]), "network_changes": False,
            "management_interface": draft["management_interface"],
            "interfaces": interfaces,
            "consumers": ["host_policy", "wireguard", "dns", "firewall", "routing"],
            "note": "Configuração pretendida separada da topologia observada. Nenhuma alteração ao sistema."}


@app.post("/api/v1/network/accept-current")
def accept_current_network(request: Request):
    """Confirm existing kernel WAN/LAN roles; never change an OS interface or route."""
    _require_policy_admin(request)
    saved = get_network_config()["draft"]
    if not saved:
        raise HTTPException(409, "Guarde primeiro uma configuração WAN/LAN")
    topology = network_topology()
    active = {i["interface"] for i in topology["interfaces"] if i["operstate"] == "UP"}
    roles = {i["interface"]: i["role"] for i in saved["interfaces"]}
    management = saved["management_interface"]
    outgoing = management if saved["mode"] == "shared" else next(
        (name for name, role in roles.items() if role == "wan"), None)
    if management not in active or outgoing not in active:
        raise HTTPException(409, "Interfaces de gestão ou de saída indisponíveis")
    targets = [r for r in topology["default_routes"]
               if r["interface"] == outgoing and r.get("gateway")]
    if len(targets) != 1:
        raise HTTPException(409, "Gateway da saída ausente ou ambíguo")
    # Adopting the *current* network must never certify a future static draft
    # which differs from the live kernel state.
    actual_interfaces = {item["interface"]: item for item in topology["interfaces"]}
    for item in saved["interfaces"]:
        if item["role"] == "unused" or not item.get("ipv4_address"):
            continue
        observed = actual_interfaces.get(item["interface"])
        if not observed or observed.get("address") != item["ipv4_address"] or observed.get("prefixlen") != item["prefix_length"]:
            raise HTTPException(409, "IP/prefixo proposto diferente da interface real. Guarde como rascunho; a aplicação de rede requer validação e reversão independente")
        if item["role"] == "wan" and item.get("address_mode") == "static" and item.get("gateway_ipv4") != targets[0]["gateway"]:
            raise HTTPException(409, "Gateway WAN estático proposto difere do gateway real")
    fingerprint = hashlib.sha256(json.dumps(saved, sort_keys=True).encode()).hexdigest()
    with closing(_connect()) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS network_applied (id INTEGER PRIMARY KEY CHECK (id=1), fingerprint TEXT NOT NULL)")
        db.execute("INSERT OR REPLACE INTO network_applied(id,fingerprint) VALUES (1,?)", (fingerprint,))
    return {"applied": True, "mode": "adopt-current", "gateway": targets[0]["gateway"],
            "outgoing_interface": outgoing,
            "note": "A topologia existente foi confirmada; nenhuma interface, rota ou firewall foi alterada"}


@app.get("/api/v1/network/route-preview")
def route_preview():
    config = get_network_config()["draft"]
    topology = network_topology()
    if not config:
        return {"ready": False, "reason": "Save a network draft first", "applied": False}
    wan = next((i["interface"] for i in config["interfaces"] if i["role"] == "wan"), None)
    management = config["management_interface"]
    current = topology["default_routes"]
    target = management if config["mode"] == "shared" else wan
    candidate = next((r for r in current if r["interface"] == target and r.get("gateway")), None)
    warnings = []
    if config["mode"] == "shared" and not candidate:
        warnings.append("Management LAN has no detected gateway; configure it before changing default route")
    elif not candidate:
        warnings.append("WAN has no detected gateway: configure and validate its upstream gateway before applying")
    if management == wan:
        warnings.append("Management cannot share WAN under the current LAN-only management policy")
    return {"ready": bool(candidate),
            "applied": False, "wan_interface": wan, "target_default_interface": target, "management_interface": management,
            "current_default_routes": current,
            "proposed_default_route": {"interface": target, "gateway": candidate["gateway"]} if candidate else None,
            "warnings": warnings,
            "note": "Read-only preview. No routes or interface states changed."}


def _host_discovery_snapshot():
    path = os.environ.get("VPNGW_HOST_DISCOVERY_SNAPSHOT")
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as source:
            snapshot = json.load(source)
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(snapshot["observed_at"])).total_seconds()
        if not 0 <= age <= 180:
            raise ValueError("stale snapshot")
        return snapshot
    except (OSError, ValueError, KeyError, TypeError):
        raise HTTPException(503, "Host discovery snapshot missing or stale")


@app.get("/api/v1/network/topology")
def network_topology():
    snapshot = _host_discovery_snapshot()
    if snapshot is not None:
        return snapshot["topology"]
    if os.environ.get("VPNGW_RUNTIME_SCOPE") == "container":
        raise HTTPException(503, "Snapshot de topologia do host indisponível")
    try:
        proc = subprocess.run(["/usr/bin/python3",
                               str(Path(__file__).with_name("network-topology.py"))],
                              capture_output=True, text=True, timeout=12, check=True)
        return json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise HTTPException(503, "Network topology unavailable")


def _discovery_lan_networks(topology):
    """Fail closed: only explicit LAN roles and CIDRs, never inferred VPN/WAN."""
    config=get_network_config()
    draft=config.get("draft") or {}
    if not config.get("applied"):
        raise HTTPException(409,"Configure e aplique a LAN antes da descoberta")
    mode=draft.get("mode")
    # Discover exactly the CIDRs of interfaces assigned the LAN/client role.
    # Never infer LAN from the management IP, default route, WAN or VPN.
    roles={item.get("interface") for item in draft.get("interfaces",[]) if item.get("role")=="lan"}
    physical={x["interface"]:x for x in topology.get("interfaces",[])
              if x.get("kind") in ("wifi","ethernet") and x.get("operstate")=="UP"}
    allowed={}
    for name in roles:
        if name in physical:
            try:
                net=ip_network(physical[name]["network"],strict=False)
                if net.version==4 and net.prefixlen<32:
                    allowed[name]=net
            except (ValueError,KeyError,TypeError):
                pass
    if not allowed:
        raise HTTPException(503,"CIDR da LAN não disponível")
    return allowed


@app.get("/api/v1/network/neighbors")
def network_neighbors():
    """Passive LAN neighbor cache; absence does not imply host is offline."""
    snapshot = _host_discovery_snapshot()
    topology = snapshot["topology"] if snapshot is not None else network_topology()
    allowed = _discovery_lan_networks(topology)
    assigned = {p["host_ip"] for p in _policies.values()}
    excluded = {i["address"] for i in topology["interfaces"] if i.get("address")} | {r.get("gateway") for r in topology["default_routes"]}
    if snapshot is not None:
        hosts=[]
        for host in snapshot["neighbors"]:
            try:
                ip=ip_address(host["ip"])
                if ip.version==4 and host.get("interface") in allowed and ip in allowed[host["interface"]] and str(ip) not in excluded:
                    hosts.append({**host,"has_policy":host["ip"] in assigned})
            except (ValueError,KeyError,TypeError):
                continue
        return {"source":"lan_cidr_passive_snapshot","complete":False,
                "lan_cidrs":{name:str(net) for name,net in allowed.items()},"hosts":hosts}
    try:
        proc = subprocess.run(["/usr/sbin/ip", "-j", "neigh", "show"],
                              capture_output=True, text=True, timeout=4, check=True)
        entries = json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise HTTPException(503, "Neighbor cache unavailable")
    hosts = {}
    for item in entries:
        try:
            address = ip_address(item["dst"])
            device = item.get("dev")
            if address.version != 4 or device not in allowed or address not in allowed[device]:
                continue
            if str(address) in {i["address"] for i in topology["interfaces"]} | {r.get("gateway") for r in topology["default_routes"]}:
                continue
            if not item.get("lladdr") or "FAILED" in item.get("state", []) or "INCOMPLETE" in item.get("state", []):
                continue
            ip = str(address)
            hosts[ip] = {"ip": ip, "mac": item["lladdr"].lower(),
                         "name": None, "name_source": None, "interface": device,
                         "state": item.get("state", []), "has_policy": ip in assigned}
        except (ValueError, KeyError, TypeError):
            continue
    return {"source": "lan_cidr_passive_neighbor_cache", "complete": False,
            "lan_cidrs":{name:str(net) for name,net in allowed.items()}, "hosts": sorted(hosts.values(), key=lambda h: tuple(map(int, h["ip"].split("."))))}


@app.get("/api/v1/network/dhcp-policy-observations")
def dhcp_policy_observations():
    """Passive DHCP/IP movement hints; never imply verified ownership or execute changes."""
    import re
    from ipaddress import IPv4Address
    valid_mac=re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z",re.I)
    with _lock:
        policies=[dict(value) for value in _policies.values()]
    observed=network_neighbors().get("hosts",[])
    by_mac={}
    for item in observed:
        try:
            mac=item.get("mac")
            ipv4=str(IPv4Address(item.get("ip")))
            if not isinstance(mac,str) or not valid_mac.fullmatch(mac):
                continue
            if {"FAILED","INCOMPLETE"} & set(item.get("state",[])):
                continue
            by_mac.setdefault(mac.lower(),set()).add(ipv4)
        except (ValueError,TypeError):
            continue
    report=[]
    for policy in policies:
        mac=policy.get("registered_mac")
        if not isinstance(mac,str) or not valid_mac.fullmatch(mac):
            report.append({"policy":policy.get("id"),"status":"identity_not_registered",
                           "cutover_enabled":False,"network_changes":False})
            continue
        ips=sorted(by_mac.get(mac.lower(),set()),key=lambda value:int(IPv4Address(value)))
        previous=policy.get("host_ip")
        candidates=[ip for ip in ips if ip!=previous]
        status=("ambiguous" if len(ips)>1 else
                "dhcp_change_observed" if len(candidates)==1 else
                "unchanged_observed" if ips else "not_observed")
        report.append({"policy":policy.get("id"),"route":policy.get("destination"),
                       "previous_ipv4":previous,"candidate_ipv4":candidates,
                       "status":status,"ownership_confirmed":False,
                       "identity_authenticated":False,"cutover_enabled":False,
                       "network_changes":False})
    return {"source":"passive_lan_neighbor_cache","complete":False,
            "automatic_rebinding_enabled":False,"policies":report}


@app.get("/api/v1/direct/hosts")
def direct_hosts():
    """Dynamic status of configured DIRECT host policies."""
    hosts=[]
    for policy in list_policies():
        if policy["destination"] != "direct":
            continue
        try:
            runtime=_policy_agent_call("diagnose_host",policy["id"],policy)
            verified=bool(runtime.get("route_verified") and runtime.get("firewall_verified"))
        except HTTPException:
            verified=False
        hosts.append({"host_ip":policy["host_ip"],"service_active":False,"active":verified,
                      "firewall_verified":verified,"verification":"policy_agent"})
    return {"hosts":hosts,"vpn_routing_active":any(
        p["destination"] not in ("direct","blocked") for p in list_policies()),
        "snapshot_timestamp":None}


class HostPlanRequest(BaseModel):
    hosts: list[str] = Field(min_length=1, max_length=20)
    interface: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_.:-]{1,32}$")

@app.post("/api/v1/hosts/plan")
def plan_hosts(data: HostPlanRequest):
    """Preview only; never installs routes or firewall rules."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "vpngw_host_plan", str(Path(__file__).with_name("multi-host-plan.py")))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        snapshot = _host_discovery_snapshot()
        if snapshot is None:
            raise HTTPException(503, "Snapshot LAN do gateway indisponível")
        preview = module.plan(data.hosts, data.interface, snapshot["topology"])
    except ValueError as exc:
        if str(exc) in ('ambiguous_default_route', 'invalid_lan_interface'):
            raise HTTPException(422, str(exc)) from exc
        raise
    existing = {entry["host_ip"] for entry in list_policies()}
    for item in preview["hosts"]:
        if item.get("eligible") and item["host_ip"] in existing:
            item.update(eligible=False, reason="existing_policy")
    return preview


class WireGuardImport(BaseModel):
    profile_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,31}$")
    configuration: str = Field(min_length=50, max_length=65536)


@app.post("/api/v1/wireguard/import")
def import_wireguard(data: WireGuardImport):
    """Store a WG profile without activating networking or exposing its secret."""
    import re
    import tempfile
    import stat
    import configparser
    if data.profile_id not in _connections:
        raise HTTPException(404, "Create the VPN profile first")
    if _connections[data.profile_id].get("protocol") != "wireguard":
        raise HTTPException(400, "Profile protocol must be WireGuard")
    state = _wireguard_agent_call(data.profile_id, "vpn_status")
    if state.get("tunnel_active"):
        raise HTTPException(409, "Desligue a VPN antes de substituir o ficheiro de configuração; o túnel activo ainda usa a configuração anterior.")
    if any(p.get("destination") == data.profile_id for p in _policies.values()):
        raise HTTPException(409, "Remova primeiro as associações de hosts antes de alterar a configuração WireGuard.")
    raw = data.configuration
    if "\x00" in raw or "\r" in raw:
        raise HTTPException(422, "Invalid configuration encoding")
    forbidden = re.compile(r"^\s*(PreUp|PostUp|PreDown|PostDown|SaveConfig)\s*=", re.I | re.M)
    if forbidden.search(raw):
        raise HTTPException(422, "Shell hooks and SaveConfig are not accepted")
    sections = re.findall(r"^\s*\[([^\]]+)\]\s*$", raw, re.M)
    if sections.count("Interface") != 1 or not sections.count("Peer") or any(s not in ("Interface", "Peer") for s in sections):
        raise HTTPException(422, "Expected one Interface and at least one Peer")
    interface = raw.split("[Interface]", 1)[-1].split("[Peer]", 1)[0]
    if not re.search(r"^\s*PrivateKey\s*=\s*[A-Za-z0-9+/]{43}=\s*$", interface, re.M):
        raise HTTPException(422, "Missing or invalid private key format")
    if not re.search(r"^\s*Address\s*=", interface, re.M):
        raise HTTPException(422, "Interface Address required")
    for peer in raw.split("[Peer]")[1:]:
        if not re.search(r"^\s*PublicKey\s*=\s*[A-Za-z0-9+/]{43}=\s*$", peer, re.M) or not re.search(r"^\s*AllowedIPs\s*=", peer, re.M):
            raise HTTPException(422, "Each peer requires PublicKey and AllowedIPs")
    directory = "/data/wireguard-profiles"
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    target = os.path.join(directory, data.profile_id + ".conf")
    fd, temporary = tempfile.mkstemp(prefix=".import-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(raw)
            if not raw.endswith("\n"):
                stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    _vpn_event(data.profile_id, "profile_imported", "Configuração WireGuard validada e guardada")
    return {"profile_id": data.profile_id, "stored": True, "activated": False,
            "peer_count": sections.count("Peer"), "secret_returned": False}

def _vpn_event(profile_id: str, event: str, detail: str):
    """Persist a bounded, fixed-vocabulary event without credentials or peer endpoints."""
    allowed = {"requested_connect", "connected", "awaiting_handshake", "disconnected",
               "connect_failed", "disconnect_failed", "profile_imported", "agent_unavailable"}
    if event not in allowed:
        raise ValueError("Unknown VPN event")
    with closing(_connect()) as db, db:
        db.execute("INSERT INTO vpn_events(profile_id,observed_at,event,detail) VALUES(?,?,?,?)",
                   (profile_id, datetime.now(timezone.utc).isoformat(), event, detail[:180]))
        db.execute("DELETE FROM vpn_events WHERE profile_id=? AND event_id NOT IN (SELECT event_id FROM vpn_events WHERE profile_id=? ORDER BY event_id DESC LIMIT 300)", (profile_id, profile_id))


@app.get("/api/v1/wireguard/{profile_id}/events")
def wireguard_profile_events(profile_id: str):
    with _lock:
        if profile_id not in _connections:
            raise HTTPException(404, "Perfil não encontrado")
    with closing(_connect()) as db:
        rows = db.execute("SELECT observed_at,event,detail FROM vpn_events WHERE profile_id=? ORDER BY event_id DESC LIMIT 100", (profile_id,)).fetchall()
    return {"profile_id": profile_id, "events": [{"at": at, "event": event, "detail": detail} for at,event,detail in rows]}


def _wireguard_agent_call(profile_id: str, action: str, configuration: str | None = None, policy_id: str | None = None, credentials: dict | None = None, files: dict | None = None):
    import socket
    location = os.environ.get("VPNGW_POLICY_AGENT_SOCKET", "/run/vpngw-policy-agent/control.sock")
    secret = os.environ.get("VPNGW_POLICY_AGENT_SECRET", "/run/vpngw-policy-agent-keys/secret")
    try:
        with open(secret, encoding="utf-8") as file:
            token = file.read().strip()
        payload = {"token": token, "id": policy_id or profile_id, "action": action}
        if policy_id is not None:
            payload["profile_id"] = profile_id
        if configuration is not None:
            payload["configuration"] = configuration
        if credentials is not None:
            payload["username"] = credentials.get("username")
            payload["password"] = credentials.get("password")
        if files is not None:
            payload["files"] = files
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(18)
            client.connect(location)
            client.sendall((json.dumps(payload) + "\n").encode())
            response = bytearray()
            while not response.endswith(b"\n") and len(response) < 131072:
                chunk = client.recv(8192)
                if not chunk:
                    break
                response.extend(chunk)
        result = json.loads(response)
    except (OSError, ValueError, TimeoutError) as exc:
        raise HTTPException(503, "Agente WireGuard indisponível: " + str(exc))
    if not result.get("ok"):
        raise HTTPException(409, str(result.get("error", "Operação WireGuard recusada")))
    return result["result"]


_vpn_probe_cache = {}


@app.get("/api/v1/wireguard/{profile_id}/transition-audit/{policy_id}")
def wireguard_transition_audit(profile_id: str, policy_id: str):
    """Read-only root agent audit. Never applies host routing."""
    with _lock:
        profile = _connections.get(profile_id)
        policy = _policies.get(policy_id)
    if not profile or profile.get("protocol") != "wireguard":
        raise HTTPException(404, "Perfil WireGuard não encontrado")
    if not policy:
        raise HTTPException(404, "Política de host não encontrada")
    return _wireguard_agent_call(profile_id, "vpn_transition_audit", policy_id=policy_id)


@app.get("/api/v1/wireguard/{profile_id}/host-plan/{policy_id}")
def wireguard_host_plan(profile_id: str, policy_id: str):
    """Never applies routing; read-only agent plan for an already-known host."""
    with _lock:
        profile = _connections.get(profile_id)
        policy = _policies.get(policy_id)
    if not profile or profile.get("protocol") != "wireguard":
        raise HTTPException(404, "Perfil WireGuard não encontrado")
    if not policy:
        raise HTTPException(404, "Host não encontrado")
    return _wireguard_agent_call(profile_id, "vpn_route_plan", policy_id=policy_id)


@app.get("/api/v1/wireguard/{profile_id}/routing-readiness")
def wireguard_routing_readiness(profile_id: str, host_ip: str):
    """Read-only safety gate: a working tunnel is not an effective client kill switch."""
    with _lock:
        profile = _connections.get(profile_id)
        matching = [p for p in _policies.values() if p["host_ip"] == host_ip]
    if not profile or profile.get("protocol") != "wireguard":
        raise HTTPException(404, "Perfil WireGuard não encontrado")
    try:
        host = ip_address(host_ip)
        if host.version != 4 or not host.is_private:
            raise ValueError()
    except ValueError:
        raise HTTPException(422, "Endereço IPv4 de cliente inválido")
    config = get_network_config().get("draft") or {}
    blockers = []
    facts = {"host_ip": host_ip, "profile_id": profile_id,
             "policy_destination": matching[0]["destination"] if matching else None,
             "vpn_connected": False, "shared_lan": config.get("mode") == "shared",
             "exclusive_routing_installed": False, "killswitch_verified": False,
             "dns_vpn_isolated": False}
    try:
        tunnel = _wireguard_agent_call(profile_id, "vpn_status")
        facts["vpn_connected"] = bool(tunnel.get("connected"))
    except HTTPException:
        pass
    if not facts["vpn_connected"]:
        blockers.append("Túnel WireGuard sem handshake recente")
    if facts["shared_lan"]:
        blockers.append("Cliente e router estão na mesma LAN: o ASUS não consegue bloquear o acesso directo do cliente ao router")
    if any(p["destination"] == "direct" for p in matching):
        blockers.append("A política DIRECT existente tem de ser substituída através de uma transição controlada")
    blockers.append("Encaminhamento exclusivo pelo túnel e kill switch fail-closed ainda não instalados nem testados")
    blockers.append("DNS através da VPN e prevenção de fugas ainda não testados")
    blockers.append("É necessário validar a reversão independente e ausência de bypass IPv6 no momento da aplicação")
    return {"ready": False, "network_changes": False, "facts": facts, "blockers": blockers}


@app.post("/api/v1/wireguard/{profile_id}/probe")
def wireguard_probe_profile(profile_id: str, request: Request):
    _require_policy_admin(request)
    with _lock:
        profile = _connections.get(profile_id)
        if not profile or profile.get("protocol") != "wireguard":
            raise HTTPException(404, "Perfil WireGuard não encontrado")
    result = _wireguard_agent_call(profile_id, "vpn_probe")
    with _lock:
        _vpn_probe_cache[profile_id] = result
    return result


@app.post("/api/v1/wireguard/{profile_id}/connect")
def wireguard_connect_profile(profile_id: str, request: Request):
    from pathlib import Path
    _require_policy_admin(request)
    with _lock:
        profile = _connections.get(profile_id)
        if not profile or profile["protocol"] != "wireguard":
            raise HTTPException(404, "Perfil WireGuard não encontrado")
    path = Path("/data/wireguard-profiles") / (profile_id + ".conf")
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 65536:
        raise HTTPException(409, "Importe primeiro um ficheiro WireGuard válido")
    _vpn_event(profile_id, "requested_connect", "Pedido de ligação recebido")
    try:
        result = _wireguard_agent_call(profile_id, "vpn_connect", path.read_text(encoding="utf-8"))
    except HTTPException as exc:
        _vpn_event(profile_id, "connect_failed", "Activação recusada; consulta o estado do perfil")
        raise
    _vpn_event(profile_id, "connected" if result.get("connected") else "awaiting_handshake",
               "Handshake confirmado" if result.get("connected") else "Interface iniciada, a aguardar handshake")
    return result


@app.post("/api/v1/wireguard/{profile_id}/disconnect")
def wireguard_disconnect_profile(profile_id: str, request: Request):
    _require_policy_admin(request)
    with _lock:
        profile = _connections.get(profile_id)
        if not profile or profile["protocol"] != "wireguard":
            raise HTTPException(404, "Perfil WireGuard não encontrado")
    # Allow a VPN to be switched off with attached hosts ONLY where a proven
    # fail-closed host policy will deny forwarding when the tunnel disappears.
    active = next((r for r in overview_status()["routes"] if r["id"] == profile_id), None)
    attached = [h["ip"] for h in (active or {}).get("hosts", [])]
    attached += [p["host_ip"] for p in _policies.values() if p.get("destination") == profile_id]
    attached = sorted(set(attached))
    if attached:
        # Only proceed when every managed host confirms an independent
        # fail-closed guard, regardless of client IP or provider.
        for ip in attached:
            policy = next((p for p in _policies.values() if p["host_ip"] == ip), None)
            if not policy:
                raise HTTPException(409, "Host sem política persistente: desligar recusado")
            runtime = _policy_agent_call("diagnose_host", policy["id"], policy)
            if not (runtime.get("route_verified") and runtime.get("firewall_verified")
                    and runtime.get("mac_guard_verified") and runtime.get("vpn_guard_present")):
                raise HTTPException(409, "Protecção fail-closed não confirmada para " + ip)
    try:
        result = _wireguard_agent_call(profile_id, "vpn_disconnect")
    except HTTPException:
        _vpn_event(profile_id, "disconnect_failed", "Falha ao desligar interface WireGuard")
        raise
    _vpn_event(profile_id, "disconnected", "Interface WireGuard desligada")
    return result


class OpenVPNImportRequest(BaseModel):
    profile_id: str
    configuration: str
    username: str
    password: str

@app.post("/api/v1/openvpn/import")
def openvpn_import(data: OpenVPNImportRequest, request: Request):
    _require_policy_admin(request)
    with _lock:
        profile=_connections.get(data.profile_id)
        if not profile or profile.get("protocol") != "openvpn":
            raise HTTPException(404, "Perfil OpenVPN não encontrado")
    if len(data.configuration)>120000:
        raise HTTPException(413,"Ficheiro demasiado grande")
    # Privileged helper validates the archive and strips unsafe OpenVPN directives.
    result = _wireguard_agent_call(data.profile_id,"openvpn_import",data.configuration,
                                  credentials={"username":data.username,"password":data.password})
    _vpn_event(data.profile_id, "profile_imported", "Configuração OpenVPN validada e guardada")
    return result

@app.post("/api/v1/openvpn/{profile_id}/{operation}")
def openvpn_change(profile_id: str, operation: str, request: Request):
    _require_policy_admin(request)
    if operation not in ("connect","disconnect","probe"):
        raise HTTPException(404,"Operação não encontrada")
    if operation == "probe":
        with _lock:
            conn = _connections.get(profile_id)
            if not conn or conn.get("protocol") != "openvpn":
                raise HTTPException(404, "Perfil OpenVPN não encontrado")
        probe = _wireguard_agent_call(profile_id, "openvpn_probe")
        with _lock:
            _vpn_probe_cache[profile_id] = probe
        _vpn_event(profile_id, "connected", "Saída pública OpenVPN verificada")
        return probe
    with _lock:
        profile=_connections.get(profile_id)
        if not profile or profile.get("protocol")!="openvpn":
            raise HTTPException(404,"Perfil OpenVPN não encontrado")
        if operation=="disconnect":
            attached=[p["host_ip"] for p in _policies.values() if p.get("destination")==profile_id]
            if attached:
                raise HTTPException(409,"Retire primeiro os hosts associados: "+", ".join(attached))
    if operation=="disconnect":
        route=next((r for r in overview_status()["routes"] if r["id"]==profile_id),None)
        if route and route.get("hosts"):
            raise HTTPException(409,"Hosts efectivos associados: desligar bloqueado")
    _vpn_event(profile_id, "requested_connect" if operation=="connect" else "disconnected",
               "Pedido OpenVPN recebido" if operation=="connect" else "Desligamento OpenVPN solicitado")
    try:
        result = _wireguard_agent_call(profile_id,"openvpn_start" if operation=="connect" else "openvpn_stop")
    except HTTPException:
        _vpn_event(profile_id, "connect_failed" if operation=="connect" else "disconnect_failed", "Falha no comando OpenVPN")
        raise
    if operation=="connect":
        _vpn_event(profile_id, "connected" if result.get("connected") else "awaiting_handshake",
                   "Túnel OpenVPN iniciado")
        if result.get("connected"):
            try:
                probe=_wireguard_agent_call(profile_id,"openvpn_probe")
                with _lock:
                    _vpn_probe_cache[profile_id]=probe
            except HTTPException:
                pass
    return result


@app.post("/api/v1/openvpn/{profile_id}/probe")
def openvpn_probe(profile_id: str, request: Request):
    _require_policy_admin(request)
    with _lock:
        conn=_connections.get(profile_id)
        if not conn or conn.get("protocol") != "openvpn":
            raise HTTPException(404,"Perfil OpenVPN não encontrado")
    probe=_wireguard_agent_call(profile_id,"openvpn_probe")
    with _lock:
        _vpn_probe_cache[profile_id]=probe
    _vpn_event(profile_id, "connected", "Saída pública OpenVPN verificada")
    return probe


@app.get("/api/v1/wireguard/profiles/status")
def wireguard_profiles_status():
    """Read-only, redacted local WireGuard profile inventory."""
    import re
    import base64
    from pathlib import Path
    root = Path("/data/wireguard-profiles")
    result = []
    with _lock:
        profiles = [(key, value.get("name", key)) for key, value in _connections.items() if value.get("protocol") == "wireguard"]
    for key, name in profiles:
        item = {"id": key, "name": name, "stored": False, "format_valid": False,
                "peer_count": 0, "address_present": False, "dns_present": False,
                "endpoint_present": False, "tunnel_active": False}
        path = root / (key + ".conf")
        try:
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536:
                content = path.read_text(encoding="utf-8")
                def field(label):
                    match = re.search(r"^\s*" + re.escape(label) + r"\s*=\s*(.+)$", content, re.M | re.I)
                    return match.group(1).strip() if match else ""
                item["stored"] = True
                item["peer_count"] = len(re.findall(r"^\s*\[Peer\]\s*$", content, re.M))
                item["address_present"] = bool(field("Address"))
                item["dns_present"] = bool(field("DNS"))
                item["endpoint_present"] = bool(field("Endpoint"))
                try:
                    valid_key = len(base64.b64decode(field("PrivateKey"), validate=True)) == 32
                except (ValueError, base64.binascii.Error):
                    valid_key = False
                item["format_valid"] = bool(valid_key and item["address_present"] and item["peer_count"] > 0 and field("PublicKey") and field("AllowedIPs"))
        except (OSError, UnicodeError):
            pass
        try:
            state = _wireguard_agent_call(key, "vpn_status")
            item["tunnel_active"] = bool(state.get("tunnel_active"))
            item["connected"] = bool(state.get("connected"))
            item["tunnel_state"] = state.get("state", "unknown")
            item["interface_name"] = state.get("interface")
            item["received_bytes"] = state.get("received_bytes")
            item["sent_bytes"] = state.get("sent_bytes")
            item["last_handshake_at"] = state.get("last_handshake_at")
            item["transport"] = state.get("transport")
            with _lock:
                probe = _vpn_probe_cache.get(key)
            if (state.get("connected") and probe and probe.get("interface") == state.get("interface")
                    and datetime.now(timezone.utc).timestamp() - probe.get("verified_at", 0) < 300):
                item["public_ipv4"] = probe.get("public_ipv4")
                item["public_ip_verified_at"] = probe.get("verified_at")
            else:
                item["public_ipv4"] = None
            item["kill_switch_active"] = bool(state.get("kill_switch_active"))
            with closing(_connect()) as db:
                recorded = db.execute("SELECT 1 FROM vpn_events WHERE profile_id=? LIMIT 1", (key,)).fetchone()
            if not recorded and state.get("connected"):
                _vpn_event(key, "connected", "Ligação WireGuard detectada ao iniciar monitorização")
        except HTTPException:
            item["tunnel_state"] = "unavailable"
            item["connected"] = False
        result.append(item)
    with _lock:
        openvpn_profiles=[(key,val.get("name",key)) for key,val in _connections.items() if val.get("protocol")=="openvpn"]
    for key,name in openvpn_profiles:
        try:
            state=_wireguard_agent_call(key,"openvpn_status")
            with _lock:
                cached=_vpn_probe_cache.get(key)
            verified=bool(cached and state.get("connected")
                          and cached.get("interface")==state.get("interface_name")
                          and datetime.now(timezone.utc).timestamp()-cached.get("verified_at",0)<300)
            result.append({"id":key,"name":name,"protocol":"openvpn",
                           "stored":bool(state.get("stored")),"format_valid":bool(state.get("stored") and state.get("credentials")),
                           "tunnel_active":bool(state.get("tunnel_active")),"connected":bool(state.get("connected")),
                           "tunnel_state":state.get("state"),"interface_name":state.get("interface_name"),
                           "received_bytes":None,"sent_bytes":None,
                           "public_ipv4":cached.get("public_ipv4") if verified else None,
                           "public_ip_verified_at":cached.get("verified_at") if verified else None,
                           "transport":state.get("transport"),"kill_switch_active":False})
        except HTTPException:
            result.append({"id":key,"name":name,"protocol":"openvpn","stored":False,"format_valid":False,
                           "tunnel_active":False,"connected":False,"tunnel_state":"unavailable"})
    return {"profiles": result, "network_changes": False}

@app.get('/api/v1/gateway/live')
def gateway_live():
    """Read-only state built from saved policies, never sample client IDs."""
    policies=list_policies()
    return {'version':'1.0.0',
            'scope':os.environ.get('VPNGW_RUNTIME_SCOPE','host'),
            'clients':{p['host_ip']:{'route':p['destination']} for p in policies},
            'wireguard':{'interface_present':any(p.get('protocol')=='wireguard' and p.get('connected')
                  for p in wireguard_profiles_status()['profiles'])},
            'kill_switch':{'loaded':all(p.get('failure_mode')=='block'
                  for p in policies if p['destination'] not in ('direct','blocked'))},
            'vpn_client_ready':any(p['destination'] not in ('direct','blocked') for p in policies),
            'read_only':True}
