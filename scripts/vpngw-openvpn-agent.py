#!/usr/bin/env python3
"""Restricted OpenVPN profile manager. Never changes default route or host rules."""
import base64, hashlib, io, ipaddress, json, os, pathlib, re, subprocess, sys, zipfile
ROOT=pathlib.Path("/etc/openvpn/client")
ALLOWED={"client","proto","remote","server-poll-timeout","remote-random","resolv-retry","nobind","cipher","data-ciphers","data-ciphers-fallback","auth","auth-nocache","tun-mtu","mssfix","persist-key","persist-tun","reneg-sec","remote-cert-tls","ping","explicit-exit-notify","route-delay","verb","remote-random-hostname","tls-version-min","verify-x509-name","sndbuf","rcvbuf","connect-retry","connect-timeout"}
BLOCKED={"up","down","plugin","script-security","management","daemon","log","log-append","status","route-up","ipchange","learn-address","client-connect","client-disconnect","tls-verify","auth-user-pass-verify","dhcp-option","redirect-gateway","route","route-ipv6","ifconfig","ifconfig-ipv6","dev","dev-type","auth-user-pass","ca","cert","key","tls-auth","tls-crypt","tls-crypt-v2","setenv","setenv-safe","askpass","writepid","cd","chroot","user","group","persist-local-ip","mark","bind","local","remote-cert-ku","remote-cert-eku"}
def checkid(pid):
    if not isinstance(pid,str) or not re.fullmatch(r"vpn-[a-z0-9][a-z0-9-]{1,27}",pid) or pid.endswith("-"):
        raise ValueError("Identificador OpenVPN inválido")
    return pid
def run(*args):
    return subprocess.run(args, capture_output=True,text=True,timeout=18)
def configured_transport(pid):
    config=ROOT/(pid+".conf")
    if not config.is_file():
        return None
    protocols=set()
    for raw in config.read_text(encoding="utf-8").splitlines():
        parts=raw.strip().split()
        if not parts or parts[0].startswith(("#",";")):
            continue
        if parts[0]=="proto" and len(parts)>=2:
            protocols.add(parts[1].upper())
        if parts[0]=="remote" and len(parts)>=4:
            protocols.add(parts[3].upper())
    if not protocols:
        return "UDP"
    return "/".join(sorted(protocols))


def pushed_dns_ipv4(pid):
    """Read only the latest pushed DNS IPv4 from the unit journal; never expose PUSH_REPLY."""
    checkid(pid)
    log=subprocess.run(["/usr/bin/journalctl","-u","openvpn-client@"+pid+".service",
        "--no-pager","-n","150","-o","cat"],capture_output=True,text=True,timeout=8)
    if log.returncode:
        return None
    # Prefer latest push; refuse profiles without a provider-advertised IPv4 resolver.
    pushes=[line for line in log.stdout.splitlines() if "PUSH_REPLY," in line]
    if not pushes:
        return None
    match=re.search(r"(?:^|,)dhcp-option DNS (\d{1,3}(?:\.\d{1,3}){3})(?:,|')",pushes[-1])
    if not match:
        return None
    try:
        address=ipaddress.IPv4Address(match.group(1))
        return str(address) if not (address.is_multicast or address.is_unspecified or address.is_loopback) else None
    except ipaddress.AddressValueError:
        return None


def inspect(pid):
    checkid(pid)
    dev="tun"+hashlib.sha256(pid.encode()).hexdigest()[:10]
    active=run("systemctl","is-active","openvpn-client@"+pid+".service").stdout.strip()=="active"
    info=run("ip","-o","-4","addr","show","dev",dev) if active else None
    match=re.search(r"inet (\d+\.\d+\.\d+\.\d+)/",info.stdout) if info and info.returncode==0 else None
    addr=match.group(1) if match else None
    return {"id":pid,"stored":(ROOT/(pid+".conf")).is_file(),"credentials":(ROOT/(pid+".auth")).is_file(),"tunnel_active":active and bool(addr),"connected":active and bool(addr),"interface_name":dev if active else None,"assigned_ipv4":addr,"state":"connected" if active and addr else "connecting" if active else "disconnected","public_ipv4":None,"dns_ipv4":pushed_dns_ipv4(pid) if active else None,"transport":configured_transport(pid)}
def probe(pid):
    state=inspect(pid)
    if not state["connected"]:
        raise ValueError("Túnel OpenVPN não ligado")
    dev=state["interface_name"]
    result=subprocess.run(["/usr/bin/curl","-4","-fsS","--noproxy","*",
        "--interface",dev,"--connect-timeout","5","--max-time","12",
        "https://api.ipify.org"],capture_output=True,text=True,timeout=15)
    if result.returncode:
        raise ValueError("Falha no teste de saída pública pela VPN")
    address=ipaddress.ip_address(result.stdout.strip())
    if address.version!=4 or not address.is_global:
        raise ValueError("Endereço IP público inválido")
    return {"id":pid,"public_ipv4":str(address),"interface":dev,
            "verified_at":int(__import__("time").time()),"network_changes":False}

def import_config(pid, content_b64, username, password):
    checkid(pid)
    if not isinstance(content_b64,str) or len(content_b64)>120000: raise ValueError("Configuração demasiado grande")
    raw=base64.b64decode(content_b64,validate=True)
    if len(raw)>80000:raise ValueError("Configuração demasiado grande")
    attachments={}
    if raw.startswith(b"PK\x03\x04"):
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            files=z.infolist()
            if len(files)>8 or sum(f.file_size for f in files)>80000:raise ValueError("ZIP excede limites")
            for f in files:
                name=f.filename
                if f.is_dir() or "/" in name or "\\" in name or name not in {"openvpn.ovpn","ca.crt","client.crt","client.key"}:raise ValueError("Estrutura ZIP inválida")
                attachments[name]=z.read(f)
            raw=attachments.pop("openvpn.ovpn")
    if not raw or len(raw)>50000: raise ValueError("OVPN inválido")
    config=raw.decode("utf-8-sig")
    lines=[]
    block=None
    for rawline in config.splitlines():
        line=rawline.strip()
        if not line or line.startswith(("#",";")):continue
        if line.startswith("<") and line.endswith(">"):
            tag=line[1:-1].strip().lower()
            if tag.startswith("/"):
                if block!=tag[1:]:raise ValueError("Bloco não corresponde")
                lines.append(line);block=None
            else:
                if block or tag not in {"ca","cert","key","tls-crypt","tls-auth"}:raise ValueError("Bloco não permitido")
                block=tag;lines.append(line)
            continue
        if block:
            lines.append(rawline);continue
        parts=line.split()
        directive=parts[0].lower()
        if directive in BLOCKED:continue
        if directive not in ALLOWED:raise ValueError("Directiva OpenVPN não suportada: "+directive)
        if re.search(r'[\x00\r\n;|&<>\x60]',line):raise ValueError("Caracteres inválidos")
        lines.append(line)
    if block:raise ValueError("Bloco não terminado")
    if not any(line.startswith("remote ") for line in lines):raise ValueError("Falta servidor remoto")
    if not isinstance(username,str) or not isinstance(password,str) or not username or not password or len(username)>256 or len(password)>256 or "\n" in username+password or "\r" in username+password:raise ValueError("Credenciais OpenVPN necessárias")
    root=ROOT
    root.mkdir(parents=True,exist_ok=True)
    os.chmod(root,0o700)
    def atomic(name,data):
        dst=root/name
        tmp=root/(name+".tmp")
        with open(tmp,"wb") as f: f.write(data)
        os.chmod(tmp,0o600)
        os.replace(tmp,dst)
    for name,blob in attachments.items():
        if not name.endswith((".crt",".key")):raise ValueError("Anexo inválido")
        atomic(pid+"-"+name,blob)
        lines.append(name.split(".")[0].split("-")[0]+" "+str(root/(pid+"-"+name)) if name!="client.key" and name!="client.crt" else ("key" if name=="client.key" else "cert")+" "+str(root/(pid+"-"+name)))
    dev="tun"+hashlib.sha256(pid.encode()).hexdigest()[:10]
    lines+=["dev "+dev,"dev-type tun","route-nopull","auth-user-pass "+str(root/(pid+".auth")),"auth-nocache","script-security 1","verb 3"]
    atomic(pid+".auth",(username+"\n"+password+"\n").encode())
    atomic(pid+".conf",("\n".join(lines)+"\n").encode())
    return {"stored":True,"credentials":True,"interface":dev}
def export_backup(pid):
    """Export only the named managed profile files; never expose unrelated credentials."""
    result={}
    for path in ROOT.glob(pid+'*'):
        if not (path.name in (pid+'.conf',pid+'.auth') or re.fullmatch(re.escape(pid)+r'-[a-zA-Z0-9_.-]{1,48}\.(crt|key)',path.name)):
            continue
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 50000:
            raise ValueError('Ficheiro OpenVPN inválido')
        result[path.name]=base64.b64encode(path.read_bytes()).decode('ascii')
    if sum(len(v) for v in result.values())>80000:
        raise ValueError('Perfil OpenVPN demasiado grande')
    return result

def restore_backup(pid,files):
    if inspect(pid)['connected']:
        raise ValueError('Desligue OpenVPN antes do restauro')
    if not isinstance(files,dict) or len(files)>20:
        raise ValueError('Arquivos OpenVPN inválidos')
    allowed={pid+'.conf',pid+'.auth'}
    for name in files:
        if not isinstance(name,str) or not (name in allowed or re.fullmatch(re.escape(pid)+r'-[a-zA-Z0-9_.-]{1,48}\.(crt|key)',name)):
            raise ValueError('Ficheiro OpenVPN não permitido')
    decoded={}
    for name,content in files.items():
        blob=base64.b64decode(content,validate=True)
        if len(blob)>50000:
            raise ValueError('Ficheiro OpenVPN demasiado grande')
        decoded[name]=blob
    root=ROOT
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    existing=[root/name for name in export_backup(pid)]
    for name in decoded:
        path=root/name
        if path.is_symlink():raise ValueError('Symlink OpenVPN recusado')
    for path in existing:
        path.unlink()
    for name,blob in decoded.items():
        path=root/name
        if path.is_symlink():raise ValueError('Symlink OpenVPN recusado')
        temp=root/(name+'.restoring')
        with open(temp,'wb') as out:out.write(blob)
        os.chmod(temp,0o600)
        os.replace(temp,path)
    return {'stored':bool(decoded),'restored_files':len(decoded)}

def dispatch(payload):
    action=payload.get("action");pid=checkid(payload.get("id"))
    if action=="openvpn_status":return inspect(pid)
    if action=="openvpn_backup_export":return export_backup(pid)
    if action=="openvpn_backup_restore":return restore_backup(pid,payload.get("files"))
    if action=="openvpn_probe":return probe(pid)
    if action=="openvpn_import":
        if inspect(pid)["connected"]:raise ValueError("Desligue antes de substituir a configuração")
        return import_config(pid,payload.get("configuration",""),payload.get("username",""),payload.get("password",""))
    if action=="openvpn_start":
        state=inspect(pid)
        if not state["stored"] or not state["credentials"]:raise ValueError("Configuração e credenciais em falta")
        result=run("systemctl","start","openvpn-client@"+pid+".service")
        if result.returncode:raise ValueError("OpenVPN não iniciou; consultar journalctl")
        return inspect(pid)
    if action=="openvpn_stop":
        result=run("systemctl","stop","openvpn-client@"+pid+".service")
        if result.returncode:raise ValueError("Falha ao desligar OpenVPN")
        return inspect(pid)
    raise ValueError("Acção desconhecida")
if __name__=="__main__":
    try:print(json.dumps(dispatch(json.load(sys.stdin))))
    except Exception as exc:
        print(str(exc),file=sys.stderr);sys.exit(1)
