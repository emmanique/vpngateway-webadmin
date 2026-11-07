#!/usr/bin/env python3
"""Isolated REAL Pi-hole v6 -> ECS-aware gateway DNS -> per-route fake DNS.

Docker networks are INTERNAL, with NO published ports. No host VPN policy,
routing, Pi-hole stack, or nftables modifications. Tear down test objects on exit.
"""
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time

ROOT = Path(__file__).resolve().parents[1]
PYIMAGE = os.environ.get("VPNGW_DNS_QA_IMAGE", "vpngateway/webadmin:v2-qa-e925424")
PIHOLE_IMAGE = "pihole/pihole@sha256:5b9c8cf51de7d6d3f2240dbe72baf5f06e1fd39cb4d77a99fab4fa13e23bd1be"


def run(*args, check=True, timeout=45):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(str(args[:4]) + ": " + result.stderr[-500:] + " " + result.stdout[-250:])
    return result


def ip_of(name, network):
    data = json.loads(run("docker", "inspect", name).stdout)[0]
    return data["NetworkSettings"]["Networks"][network]["IPAddress"]


def bridge_of(network):
    data = json.loads(run("docker", "network", "inspect", network).stdout)[0]
    return data["IPAM"]["Config"][0]["Gateway"], "br-" + data["Id"][:12]


def wait_container(name, timeout=40):
    for _ in range(timeout):
        try:
            value=run("docker","inspect","--format","{{.State.Running}}",name,check=False).stdout.strip()
            if value=="true":
                return
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError(name + " not running")


FAKE_SERVER = r'''
import socket, struct, select, sys
ipv4=bytes(map(int,sys.argv[1].split(".")))
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(("0.0.0.0",53))
tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM);tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
tcp.bind(("0.0.0.0",53));tcp.listen(20)
def answer(packet):
    pos=12
    while pos<len(packet) and packet[pos]!=0:
        pos+=1+packet[pos]
    pos+=5
    return packet[:2]+b"\x81\x80"+struct.pack("!HHHH",1,1,0,0)+packet[12:pos]+b"\xc0\x0c\x00\x01\x00\x01"+struct.pack("!IH",0,4)+ipv4
while True:
    ready,_,_=select.select([udp,tcp],[],[],0.3)
    for server in ready:
        if server==udp:
            data,addr=udp.recvfrom(4096)
            udp.sendto(answer(data),addr)
        else:
            conn,_=tcp.accept()
            with conn:
                conn.settimeout(3)
                header=conn.recv(2)
                if len(header)==2:
                    n=struct.unpack("!H",header)[0]
                    msg=conn.recv(n)
                    out=answer(msg)
                    conn.sendall(struct.pack("!H",len(out))+out)
'''

QUERY_CLIENT = r'''
import socket,struct,sys
server,name=sys.argv[1:3]
q=b"".join(bytes([len(x)])+x.encode() for x in name.split("."))+b"\x00"
p=b"\x5a\xa5\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01"+q+b"\x00\x01\x00\x01"
p+=b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.settimeout(6)
sock.sendto(p,(server,53))
data,_=sock.recvfrom(4096)
rcode=data[3]&0xf
addresses=[]
pos=12
while pos<len(data) and data[pos]:
    pos+=data[pos]+1
pos+=5
for _ in range(struct.unpack_from("!H",data,6)[0]):
    if data[pos]&0xc0==0xc0:pos+=2
    else:
        while data[pos]:pos+=data[pos]+1
        pos+=1
    typ,cl,ttl,size=struct.unpack_from("!HHIH",data,pos);pos+=10
    if typ==1 and size==4:addresses.append(".".join(map(str,data[pos:pos+4])))
    pos+=size
print("RESULT",rcode,",".join(addresses),flush=True)
'''

def main():
    suffix=secrets.token_hex(3)
    networks=[f"vpngw_qa_dns_{suffix}",f"vpngw_qa_vpna_{suffix}",f"vpngw_qa_vpnb_{suffix}"]
    names=[f"vpngw-qa-pihole-{suffix}",f"vpngw-qa-a-{suffix}",
           f"vpngw-qa-b-{suffix}",f"vpngw-qa-res-a-{suffix}",f"vpngw-qa-res-b-{suffix}"]
    pi, ca, cb, ra, rb=names
    started=[]
    created=[]
    upstream=None
    capture=[]
    try:
        with tempfile.TemporaryDirectory(prefix="vpngw-dns-qa-") as temporary:
            temp=Path(temporary)
            (temp/"fake.py").write_text(FAKE_SERVER)
            (temp/"query.py").write_text(QUERY_CLIENT)
            # Internal-only networking cannot fetch blocklists at startup.
            # Reuse an isolated COPY when an existing Pi-hole is accessible,
            # otherwise bootstrap gravity in a separate disposable container
            # BEFORE test networks exist. QA client networks are always internal.
            source=os.environ.get("VPNGW_DNS_QA_GRAVITY_SOURCE",
                                  "vpngateway-v001-staging-pihole-1")
            copied=run("docker","cp",source+":/etc/pihole/gravity.db",
                       str(temp/"gravity.db"),check=False)
            if copied.returncode:
                bootstrap="vpngw-qa-seed-"+suffix
                started.append(bootstrap)
                run("docker","run","-d","--name",bootstrap,
                    "-e","FTLCONF_webserver_api_password=",
                    PIHOLE_IMAGE,timeout=40)
                for _ in range(90):
                    probe=run("docker","exec",bootstrap,"sh","-c",
                              "test -s /etc/pihole/gravity.db",check=False)
                    if probe.returncode==0:
                        break
                    time.sleep(1)
                else:
                    raise RuntimeError("Cannot bootstrap isolated gravity seed")
                run("docker","cp",bootstrap+":/etc/pihole/gravity.db",
                    str(temp/"gravity.db"))
                run("docker","rm","-f",bootstrap,check=False)
                started.remove(bootstrap)
            state=temp/"state";state.mkdir(mode=0o700)
            for network in networks:
                run("docker","network","create","--internal","--driver","bridge",network)
                created.append(network)
            gateway,bridge=bridge_of(networks[0])
            for network,name,reply in ((networks[1],ra,"198.18.0.10"),(networks[2],rb,"198.18.0.20")):
                run("docker","run","-d","--network",network,"--name",name,
                    "-v",str(temp/"fake.py")+":/fixture.py:ro","--entrypoint","python3",PYIMAGE,
                    "/fixture.py",reply,timeout=30)
                started.append(name)
            ip_a,ip_b=ip_of(ra,networks[1]),ip_of(rb,networks[2])
            _,iface_a=bridge_of(networks[1])
            _,iface_b=bridge_of(networks[2])
            for network in networks:
                info=json.loads(run("docker","network","inspect",network).stdout)[0]
                assert info["Internal"] is True, "QA Docker network must be isolated from WAN"
            for name in (ca,cb):
                run("docker","run","-d","--network",networks[0],"--name",name,
                    "-v",str(temp/"query.py")+":/query.py:ro","--entrypoint","sleep",PYIMAGE,"300",timeout=30)
                started.append(name)
            host_a,host_b=ip_of(ca,networks[0]),ip_of(cb,networks[0])
            for name,host,dest,iface,dns in ((ca,host_a,"vpn-qa-a",iface_a,ip_a),
                                             (cb,host_b,"vpn-qa-b",iface_b,ip_b)):
                (state/(name+".json")).write_text(json.dumps({
                    "status":"active","plan":{"host":host,"destination":dest},
                    "vpn_runtime":{"interface":iface,"dns_ipv4":dns}
                }))
            # Configures ONLY a private Docker-internal Pi-hole; does not touch
            # the production container or its persisted volume.
            started.append(pi)
            run("docker","run","-d","--network",networks[0],"--name",pi,
                "--cap-drop","NET_ADMIN","--cap-drop","SYS_ADMIN",
                "-v",str(temp/"gravity.db")+":/etc/pihole/gravity.db",
                "-e","FTLCONF_dns_listeningMode=ALL",
                "-e","FTLCONF_dns_upstreams="+gateway+"#5355",
                "-e","FTLCONF_misc_dnsmasq_lines=strip-subnet;add-subnet=32,128",
                "-e","FTLCONF_dns_cache_size=0",
                "-e","FTLCONF_dns_queryLogging=true",
                "-e","FTLCONF_webserver_api_password=",
                PIHOLE_IMAGE,timeout=40)
            pihole_ip=ip_of(pi,networks[0])
            upstream=subprocess.Popen([
                sys.executable,str(ROOT/"scripts/vpngw-dns-policy-upstream.py"),
                "--listen",gateway,"--bridge-interface",bridge,
                "--pihole-source",pihole_ip,"--direct-resolver","1.1.1.1",
                "--policy-dir",str(state)
            ],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
            time.sleep(2)
            if upstream.poll() is not None:
                raise RuntimeError("DNS policy worker exited: "+upstream.stderr.read()[-500:])
            for attempt in range(45):
                status=run("docker","exec",pi,"pihole","status",check=False)
                if status.returncode==0 and "enabled" in status.stdout.lower():
                    break
                time.sleep(1)
            else:
                raise RuntimeError("Isolated Pi-hole did not become ready")
            print("PIHOLE_V6_STARTED_ISOLATED: PASS",flush=True)
            wan_routes=json.loads(run("ip","-j","-4","route","show","default").stdout)
            wan_iface=next((row.get("dev") for row in wan_routes if row.get("dev")),None)
            if not shutil.which("tcpdump") or os.geteuid()!=0 or not wan_iface:
                raise RuntimeError("Packet capture (root, tcpdump, WAN interface) is mandatory")
            for ifname in (iface_a,iface_b,wan_iface,"any"):
                file=temp/("capture-"+ifname+".pcap")
                proc=subprocess.Popen(["tcpdump","--immediate-mode","-i",ifname,"-nn","-U",
                     "-w",str(file),"udp port 53 and (host "+ip_a+" or host "+ip_b+")"],
                     stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
                capture.append((ifname,file,proc))
            time.sleep(1.8)
            if any(proc.poll() is not None for _,_,proc in capture):
                raise RuntimeError("A packet capture ended before DNS traffic; pcap evidence unreliable")
            print("CLIENTS:",host_a,host_b,"RESOLVERS:",ip_a,ip_b,"PIHOLE:",pihole_ip,flush=True)
            # Native Pi-hole denylisting; this modifies only the isolated test Pi-hole.
            run("docker","exec",pi,"pihole","deny","qa-blocked.example.org")
            def resolve_from(name,domain):
                result=run("docker","exec",name,"python3","/query.py",pihole_ip,domain,check=False,timeout=15)
                if result.returncode:
                    raise RuntimeError("DNS request failed: "+result.stderr[-250:])
                return result.stdout.strip()
            a=resolve_from(ca,"qa-a-route.example.org")
            b=resolve_from(cb,"qa-b-route.example.org")
            print("DNS_A",a,"DNS_B",b,flush=True)
            if "198.18." not in a or "198.18." not in b:
                print("PIHOLE_QA_DNS_LOG", run("docker","exec",pi,"sh","-c","tail -36 /var/log/pihole/pihole.log",check=False).stdout[-2200:],flush=True)
                print("PIHOLE_QA_CONFIG", run("docker","exec",pi,"pihole-FTL","--config","dns.upstreams",check=False).stdout[-250:],flush=True)
            assert "198.18.0.10" in a and "198.18.0.20" not in a,(a,b)
            assert "198.18.0.20" in b and "198.18.0.10" not in b,(a,b)
            print("REAL_PIHOLE_ECS_PER_CLIENT_UPSTREAM_SPLIT: PASS",flush=True)
            blocked=resolve_from(ca,"qa-blocked.example.org")
            print("BLOCKED",blocked,flush=True)
            assert "198.18." not in blocked,blocked
            print("REAL_PIHOLE_BLOCKING_CENTRALIZED: PASS",flush=True)
            # Mark one host blocked, prove that even Pi-hole cannot accidentally
            # send blocked-client DNS to direct/default route.
            policy_file=state/(cb+".json")
            state_b=json.loads(policy_file.read_text())
            state_b["plan"]["destination"]="blocked"
            policy_file.write_text(json.dumps(state_b))
            denied=resolve_from(cb,"qa-b-route-afterblock.example.org")
            print("DENIED",denied,flush=True)
            assert "198.18." not in denied,denied
            print("REAL_PIHOLE_FAIL_CLOSED_BLOCKED_HOST: PASS",flush=True)
            # Simulate the assigned tunnel interface becoming unavailable.
            # Cache is disabled: Pi-hole must not return a stale success or
            # select a default-route DNS server when the policy iface is lost.
            policy_a=state/(ca+".json")
            original_a=json.loads(policy_a.read_text())
            unavailable=json.loads(policy_a.read_text())
            unavailable["vpn_runtime"]["interface"]="wgdoesnotexist0"
            policy_a.write_text(json.dumps(unavailable))
            try:
                vanished=resolve_from(ca,"qa-a-tunnel-loss.example.org")
                print("TUNNEL_ABSENT",vanished,flush=True)
                if "198.18." in vanished or not vanished.startswith("RESULT 2"):
                    raise RuntimeError("DNS failure must return SERVFAIL without fallback")
                print("REAL_PIHOLE_DNS_FAIL_CLOSED_WHEN_INTERFACE_UNAVAILABLE: PASS",flush=True)
            finally:
                policy_a.write_text(json.dumps(original_a))
            restored=resolve_from(ca,"qa-a-after-recovery.example.org")
            print("TUNNEL_RESTORED",restored,flush=True)
            if "198.18.0.10" not in restored:
                raise RuntimeError("Original assigned DNS interface was not recovered")
            print("REAL_PIHOLE_DNS_AFTER_TUNNEL_RESTORATION: PASS",flush=True)
            pihole_log=run("docker","exec",pi,"sh","-c",
                           "tail -130 /var/log/pihole/pihole.log",check=False).stdout
            assert host_a in pihole_log and host_b in pihole_log, "Real Pi-hole origin IP missing from query log"
            print("REAL_PIHOLE_ORIGINAL_CLIENT_IP_IN_LOG: PASS",flush=True)
            if capture:
                for _,_,proc in capture:
                    proc.send_signal(signal.SIGINT)
                for ifname,_,proc in capture:
                    proc.wait(timeout=6)
                    report=proc.stderr.read()[-550:]
                    print("PCAP_CAPTURE_STATS",ifname,report.replace("\n"," | "),flush=True)
                evidence={}
                for iface,file,_ in capture:
                    evidence[iface]=run("tcpdump","-nn","-r",str(file),
                                        check=False).stdout
                print("PCAP_INTERFACE_COUNTS",
                      {name:len(data.splitlines()) for name,data in evidence.items()},flush=True)
                print("PCAP_ANY_SAMPLE",evidence.get("any","")[:850],flush=True)
                assert ip_a in evidence[iface_a], "VPN-A DNS not seen on assigned interface"
                assert ip_b in evidence[iface_b], "VPN-B DNS not seen on assigned interface"
                assert ip_a not in evidence[iface_b], "VPN-A address leaked to VPN-B interface"
                assert ip_b not in evidence[iface_a], "VPN-B address leaked to VPN-A interface"
                assert not evidence[wan_iface].strip(), "Isolated QA resolver DNS seen on real WAN"
                print("PCAP_ROUTE_A_B_SEPARATED_AND_NO_WAN_EGRESS: PASS",flush=True)
    finally:
        for _,_,proc in capture:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:proc.wait(timeout=3)
                except subprocess.TimeoutExpired:proc.kill()
        if upstream is not None:
            upstream.terminate()
            try:upstream.wait(timeout=4)
            except subprocess.TimeoutExpired:upstream.kill()
        for name in reversed(started):
            run("docker","rm","-f",name,check=False)
        for name in reversed(created):
            run("docker","network","rm",name,check=False)

if __name__=="__main__":
    main()
