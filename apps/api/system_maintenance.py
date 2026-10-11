"""Safe administrative configuration export, import and reset (not tunnel credentials)."""
import json
import os
import base64
import hashlib
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sqlite3
from datetime import datetime, timezone
from fastapi import HTTPException

TABLES = ("connections", "policies", "dns_config", "network_config")
MAX_BACKUP = 1024 * 1024

def snapshot(db_path):
    with sqlite3.connect(db_path) as db:
        result = {}
        for table in TABLES:
            present = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            result[table] = [dict(zip(("id", "payload"), row)) for row in db.execute(
                f"SELECT id,payload FROM {table}")] if present else []
    return {"format": "vpngw-admin-config", "schema": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "includes_vpn_secrets": False, "requires_profile_reimport": True, "data": result}

def validate(payload):
    if not isinstance(payload, dict) or payload.get("format") != "vpngw-admin-config" or payload.get("schema") != 1:
        raise HTTPException(422, "Formato de backup inválido")
    data = payload.get("data")
    if not isinstance(data, dict) or set(data) != set(TABLES):
        raise HTTPException(422, "Tabelas inválidas")
    for table, rows in data.items():
        if not isinstance(rows, list) or len(rows) > 1000:
            raise HTTPException(422, "Número de registos inválido")
        keys = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"id", "payload"}:
                raise HTTPException(422, "Registo inválido")
            key = row["id"]
            if not isinstance(key, (str, int)) or len(str(key)) > 80 or key in keys:
                raise HTTPException(422, "Identificador inválido ou duplicado")
            keys.add(key)
            if not isinstance(row["payload"], str) or len(row["payload"]) > 65536:
                raise HTTPException(422, "Conteúdo inválido")
            try:
                parsed = json.loads(row["payload"])
            except (ValueError, TypeError):
                raise HTTPException(422, "JSON de registo inválido")
            if not isinstance(parsed, dict):
                raise HTTPException(422, "Configuração inválida")
            # Preserve logical configuration, but never reapply live network state implicitly.
            if table == "policies" and parsed.get("status") == "active":
                parsed["status"] = "draft"
                row["payload"] = json.dumps(parsed, ensure_ascii=False)
            if table == "network_config" and parsed.get("applied"):
                parsed["applied"] = False
                row["payload"] = json.dumps(parsed, ensure_ascii=False)
            if table == "connections" and parsed.get("enabled"):
                parsed["enabled"] = False
                row["payload"] = json.dumps(parsed, ensure_ascii=False)
    destinations = {row["id"] for row in data["connections"]} | {"direct", "blocked"}
    for row in data["policies"]:
        if json.loads(row["payload"]).get("destination") not in destinations:
            raise HTTPException(422, "Regra com destino VPN inexistente")
    return data

def safe_to_change(db_path):
    with sqlite3.connect(db_path) as db:
        active = db.execute("SELECT count(*) FROM policies WHERE json_extract(payload, '$.status')='active'").fetchone()[0]
        if active:
            raise HTTPException(409, "Existem políticas activas. Remova-as de forma controlada antes do restauro ou reposição.")

def apply(db_path, data):
    with sqlite3.connect(db_path) as db:
        for table in TABLES:
            db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)" if table.endswith("_config") else f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
            db.execute(f"DELETE FROM {table}")
            for row in data[table]:
                db.execute(f"INSERT INTO {table}(id,payload) VALUES(?,?)", (row["id"], row["payload"]))


# Version 2 backups are authenticated and encrypted end-to-end. Never expose keys in plaintext responses.
PROFILE_ROOT = Path(os.environ.get("VPNGW_WIREGUARD_PROFILE_ROOT", "/data/wireguard-profiles"))
MAX_ENCRYPTED_BACKUP = 4 * 1024 * 1024

def _key(password, salt):
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise HTTPException(422, "Palavra-passe deve ter entre 12 e 256 caracteres")
    return hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1, dklen=32, maxmem=67108864)

def encrypted_snapshot(db_path, password, openvpn_export=None):
    inventory = snapshot(db_path)
    profiles = {}
    for row in inventory["data"]["connections"]:
        profile = json.loads(row["payload"])
        if profile.get("protocol") != "wireguard":
            continue
        ident = row["id"]
        if not isinstance(ident, str) or not __import__('re').fullmatch(r'[a-z][a-z0-9-]{1,31}', ident):
            raise HTTPException(422, "Identificador VPN inválido")
        path = PROFILE_ROOT / (ident + ".conf")
        if path.is_symlink():
            raise HTTPException(409, "Perfil WireGuard suspeito")
        if path.exists():
            if not path.is_file() or path.stat().st_size > 65536:
                raise HTTPException(409, "Ficheiro WireGuard inválido")
            profiles[ident] = base64.b64encode(path.read_bytes()).decode('ascii')
    payload = {"configuration":inventory,"wireguard":profiles,"openvpn":openvpn_export or {}}
    plain = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode()
    if len(plain) > MAX_ENCRYPTED_BACKUP:
        raise HTTPException(413, "Backup demasiado grande")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    cipher = AESGCM(_key(password,salt)).encrypt(nonce, plain, b'vpngw-encrypted-backup-v2')
    return {"format":"vpngw-encrypted-backup", "schema":2,"kdf":"scrypt-32768-8-1", "cipher":"AES-256-GCM",
            "salt":base64.b64encode(salt).decode(), "nonce":base64.b64encode(nonce).decode(),
            "ciphertext":base64.b64encode(cipher).decode()}

def decrypt_backup(backup, password):
    if not isinstance(backup,dict) or backup.get('format')!='vpngw-encrypted-backup' or backup.get('schema')!=2 or backup.get('kdf')!='scrypt-32768-8-1' or backup.get('cipher')!='AES-256-GCM':
        raise HTTPException(422, "Formato de backup cifrado inválido")
    try:
        salt=base64.b64decode(backup['salt'],validate=True)
        nonce=base64.b64decode(backup['nonce'],validate=True)
        ciphertext=base64.b64decode(backup['ciphertext'],validate=True)
        if len(salt)!=16 or len(nonce)!=12 or len(ciphertext)>MAX_ENCRYPTED_BACKUP+16:
            raise ValueError('Dimensões inválidas')
        plain=AESGCM(_key(password,salt)).decrypt(nonce,ciphertext,b'vpngw-encrypted-backup-v2')
        content=json.loads(plain)
        data=validate(content['configuration'])
        ids={r['id']:json.loads(r['payload']).get('protocol') for r in data['connections']}
        files=content['wireguard']
        if not isinstance(files,dict) or any(ids.get(k)!='wireguard' for k in files):
            raise ValueError('Perfis WireGuard inconsistentes')
        decoded={}
        for ident,value in files.items():
            raw=base64.b64decode(value,validate=True)
            if len(raw)>65536 or b'\x00' in raw or b'[Interface]' not in raw or b'[Peer]' not in raw:
                raise ValueError('Ficheiro WireGuard inválido')
            decoded[ident]=raw
        openvpn=content.get('openvpn',{})
        if not isinstance(openvpn,dict) or any(ids.get(k)!='openvpn' or not isinstance(v,dict) for k,v in openvpn.items()):
            raise ValueError('Perfis OpenVPN inconsistentes')
        return data,decoded,openvpn
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(422,"Palavra-passe incorrecta ou backup inválido/adulterado")

def restore_wireguard(db_path, data, profiles):
    # Stage regular files in the same filesystem, and keep old content until DB commit.
    import shutil
    import tempfile
    PROFILE_ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    if PROFILE_ROOT.is_symlink():
        raise HTTPException(409,'Directório WireGuard inválido')
    with tempfile.TemporaryDirectory(prefix='.restore-',dir=PROFILE_ROOT) as temp:
        staging=Path(temp)
        old={}
        existing=list(PROFILE_ROOT.glob('*.conf'))
        for path in existing:
            if path.is_symlink() or not path.is_file():
                raise HTTPException(409,'Ficheiro WireGuard suspeito')
            old[path.name]=path.read_bytes()
        previous=snapshot(db_path)['data']
        try:
            for ident,raw in profiles.items():
                p=staging/(ident+'.conf')
                p.write_bytes(raw)
                p.chmod(0o600)
            for path in existing:
                path.unlink()
            for staged in staging.iterdir():
                os.replace(staged,PROFILE_ROOT/staged.name)
            apply(db_path,data)
        except Exception:
            for path in PROFILE_ROOT.glob('*.conf'):
                path.unlink()
            for name,raw in old.items():
                path=PROFILE_ROOT/name
                path.write_bytes(raw)
                path.chmod(0o600)
            apply(db_path,previous)
            raise
