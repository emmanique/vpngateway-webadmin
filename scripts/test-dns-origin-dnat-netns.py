#!/usr/bin/env python3
"""Real DNS packet identity/anti-fallback with veths and nft DNAT in a netns.

Must only be run via unshare --net (not directly on the host). Creates two
nested child network namespaces for a simulated LAN host and Pi-hole resolver.
Does not create a Docker container or connect to an external interface.
"""
import importlib.util
import ipaddress
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]


def run(*args, input=None, check=True):
    p=subprocess.run(args,input=input,text=True,capture_output=True,timeout=10)
    if check and p.returncode:
        raise RuntimeError(f"{args[:4]} => {p.stderr[-260:]}")
    return p


def load(script):
    path=ROOT/"scripts"/script
    spec=importlib.util.spec_from_file_location(script.replace("-","_").replace(".py",""),path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

SERVER=r'''
import socket,struct,sys
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
u.bind(("172.18.0.2",53))
data,remote=u.recvfrom(4096)
print("PIHOLE_ORIGIN="+remote[0],flush=True)
print("PIHOLE_QUERY_ID="+data[:2].hex(),flush=True)
if remote[0] != "192.168.88.20":
 sys.exit(22)
u.sendto(data[:2]+b"\x81\x80"+data[4:],remote)
'''

CLIENT=r'''
import socket,struct,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(4)
s.bind(("192.168.88.20",0))
question=b"\x03www\x07example\x03org\x00\x00\x01\x00\x01"
request=struct.pack("!HHHHHH",0xAABB,0x0100,1,0,0,0)+question
s.sendto(request,("192.168.88.1",53))
response,source=s.recvfrom(4096)
assert response[:2]==request[:2],response.hex()
print("DNS_CLIENT_REPLY_FROM="+source[0],flush=True)
print("DNS_CLIENT_SUCCESS="+str(response[3]&15==0),flush=True)
'''

def main():
    if os.geteuid()!=0:
        raise SystemExit("Root required inside isolated netns")
    run("ip","-4","route","show")
    run("sysctl","-qw","net.ipv4.ip_forward=1")
    with tempfile.TemporaryDirectory() as folder:
        folder=Path(folder)
        server=folder/"dns-server.py"
        client=folder/"dns-client.py"
        server.write_text(SERVER);client.write_text(CLIENT)
        children=[]
        try:
            # Each child is a separate ephemeral network namespace.
            for _ in range(2):
                proc=subprocess.Popen(["unshare","--net","--","sleep","90"],
                                      stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                children.append(proc)
            time.sleep(0.4)
            if any(p.poll() is not None for p in children):
                raise RuntimeError("Cannot create child network namespaces")
            hostpid,dnspid=(p.pid for p in children)
            for iface,peer,pid in (("lan0","cli0",hostpid),("brdns0","dns0",dnspid)):
                run("ip","link","add",iface,"type","veth","peer","name",peer)
                run("ip","link","set",peer,"netns",str(pid))
                run("ip","link","set",iface,"up")
            run("ip","addr","add","192.168.88.1/24","dev","lan0")
            run("ip","addr","add","172.18.0.1/24","dev","brdns0")
            for pid,interface,cidr,route in (
                (hostpid,"cli0","192.168.88.20/24","192.168.88.1"),
                (dnspid,"dns0","172.18.0.2/24","172.18.0.1")):
                run("nsenter","-t",str(pid),"-n","ip","link","set","lo","up")
                run("nsenter","-t",str(pid),"-n","ip","addr","add",cidr,"dev",interface)
                run("nsenter","-t",str(pid),"-n","ip","link","set",interface,"up")
                run("nsenter","-t",str(pid),"-n","ip","route","add","default","via",route)
            run("nsenter","-t",str(hostpid),"-n","ip","link","set","cli0","address","02:aa:bb:cc:dd:ee")
            run("ip","link","add","wgqa0","type","dummy")
            run("ip","link","set","wgqa0","up")
            run("ip","route","add","unreachable","default","table","32444")
            run("ip","route","add","172.18.0.2/32","dev","brdns0","table","32444")
            run("ip","rule","add","pref","12444","from","192.168.88.20",
                "iif","lan0","table","32444")
            rules=load("vpngw-vpn-host-guard.py").render(
                "qa-dns-origin","192.168.88.20","02:aa:bb:cc:dd:ee","lan0","wgqa0",
                central_dns={"pihole_ipv4":"172.18.0.2","bridge_interface":"brdns0"})
            run("nft","-f","-",input=rules)
            gateway_probe=run("ip","route","get","172.18.0.2","from","192.168.88.20",
                              "iif","lan0").stdout
            assert "dev brdns0" in gateway_probe,gateway_probe
            serverproc=subprocess.Popen(
                ["nsenter","-t",str(dnspid),"-n","python3",str(server)],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            time.sleep(0.4)
            result=run("nsenter","-t",str(hostpid),"-n","python3",str(client))
            out,err=serverproc.communicate(timeout=4)
            if serverproc.returncode:
                raise RuntimeError("Source identity changed: "+out+" "+err)
            assert "PIHOLE_ORIGIN=192.168.88.20" in out,out
            assert "DNS_CLIENT_REPLY_FROM=192.168.88.1" in result.stdout,result.stdout
            print(out.strip(),flush=True)
            print(result.stdout.strip(),flush=True)
            print("REAL_NFT_DNAT_PRESERVED_ORIGINAL_LAN_CLIENT_IP: PASS",flush=True)
            # With the tunnel removed, DNS to the local Pi-hole continues,
            # but a new public destination cannot reach the host WAN.
            run("ip","link","del","wgqa0")
            lost=run("ip","route","get","1.1.1.1","from","192.168.88.20",
                     "iif","lan0",check=False)
            assert lost.returncode!=0,lost.stdout
            print("REAL_NFT_ORIGIN_TEST_NO_DIRECT_FALLBACK: PASS",flush=True)
        finally:
            for p in children:
                p.terminate()
                try:p.wait(timeout=2)
                except subprocess.TimeoutExpired:p.kill()


if __name__=="__main__":
    main()
