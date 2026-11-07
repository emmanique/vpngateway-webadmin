#!/usr/bin/env python3
"""Real TCP/UDP DNAT regression in isolated Linux network namespaces only.

Never execute on an actual gateway. Requires: sudo unshare --net -- python3 ...
"""
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
TEST_SERVER = r'''
import socket,select,time
tcp=socket.socket()
tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
tcp.bind(("192.168.88.199",6881))
tcp.listen(1)
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
udp.bind(("192.168.88.199",6881))
until=time.time()+20
while time.time()<until:
 ready,_,_=select.select([tcp,udp],[],[],0.5)
 for item in ready:
  if item is tcp:
   connection,_=tcp.accept()
   with connection:
    connection.recv(128)
    connection.sendall(b"TCP_PORT_FORWARD_OK")
  else:
   data,remote=udp.recvfrom(256)
   udp.sendto(b"UDP_PORT_FORWARD_OK",remote)
'''
TEST_CLIENT = r'''
import socket
s=socket.create_connection(("203.0.113.1",6881),timeout=4)
s.sendall(b"tcp")
assert s.recv(128)==b"TCP_PORT_FORWARD_OK"
s.close()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
u.settimeout(4)
u.sendto(b"udp",("203.0.113.1",6881))
assert u.recvfrom(128)[0]==b"UDP_PORT_FORWARD_OK"
print("DNAT_TCP_UDP_REAL_PACKETS: PASS",flush=True)
'''


def run(*args, check=True):
    p = subprocess.run(args, capture_output=True, text=True, timeout=12)
    if check and p.returncode:
        raise RuntimeError(" ".join(args[:4]) + ": " + p.stderr[-350:])
    return p


def main():
    if os.geteuid() != 0:
        raise SystemExit("Root needed inside isolated netns")
    if not os.environ.get("VPNGW_ISOLATED_NETNS") == "1":
        raise SystemExit("Set VPNGW_ISOLATED_NETNS=1 only inside unshare --net")
    script = ROOT / "scripts" / "vpngw-port-forward.py"
    spec = importlib.util.spec_from_file_location("vpngw_port_forward", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run("sysctl", "-qw", "net.ipv4.ip_forward=1")
    children = []
    try:
        for _ in range(2):
            children.append(subprocess.Popen(["unshare", "--net", "--", "sleep", "60"],
                                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
        time.sleep(0.5)
        if any(p.poll() is not None for p in children):
            raise RuntimeError("Cannot create isolated child namespaces")
        external, host = (p.pid for p in children)
        for gate_if, peer_if, target in (("wan0","ext0",external),("lan0","cli0",host)):
            run("ip", "link", "add", gate_if, "type", "veth", "peer", "name", peer_if)
            run("ip", "link", "set", peer_if, "netns", str(target))
            run("ip", "link", "set", gate_if, "up")
        run("ip", "address", "add", "203.0.113.1/24", "dev", "wan0")
        run("ip", "address", "add", "192.168.88.1/24", "dev", "lan0")
        for pid, iface, address, gateway in (
                (external,"ext0","203.0.113.2/24","203.0.113.1"),
                (host,"cli0","192.168.88.199/24","192.168.88.1")):
            run("nsenter","-t",str(pid),"-n","ip","link","set","lo","up")
            run("nsenter","-t",str(pid),"-n","ip","addr","add",address,"dev",iface)
            run("nsenter","-t",str(pid),"-n","ip","link","set",iface,"up")
            run("nsenter","-t",str(pid),"-n","ip","route","add","default","via",gateway)
        confirmed = {"status":"active","applied":True,
                     "plan":{"host":"192.168.88.199","wan":"wan0","destination":"direct",
                             "registered_mac":"02:11:22:33:44:55"}}
        selected = {"host_ip":"192.168.88.199","route":"direct",
                    "ingress_ipv4":["203.0.113.1"],
                    "mappings":[{"protocol":"tcp","internal_port":6881,"external_port":6881},
                                {"protocol":"udp","internal_port":6881,"external_port":6881}]}
        check = module.apply("/usr/sbin/nft", selected, confirmed)
        assert check["applied"] and set(check["protocols"])=={"tcp","udp"},check
        listener = subprocess.Popen(["nsenter","-t",str(host),"-n",sys.executable,"-c",TEST_SERVER],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(0.5)
        if listener.poll() is not None:
            raise RuntimeError("Host listener failed: " + listener.stderr.read())
        result = run("nsenter","-t",str(external),"-n",sys.executable,"-c",TEST_CLIENT)
        assert "DNAT_TCP_UDP_REAL_PACKETS: PASS" in result.stdout,result.stdout
        print(result.stdout.strip(),flush=True)
        module.apply("/usr/sbin/nft", None, None)
        assert run("nft","list","table","ip","vpngw_port_forward",check=False).returncode != 0
        denied = run("nsenter","-t",str(external),"-n",sys.executable,"-c",
                     'import socket; socket.create_connection(("203.0.113.1",6881),timeout=2)',
                     check=False)
        assert denied.returncode != 0,"DNAT remained accessible after deselection"
        print("PORT_FORWARD_REMOVAL_REAL_PACKETS: PASS",flush=True)
    finally:
        for process in children:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__=="__main__":
    main()
