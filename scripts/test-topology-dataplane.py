#!/usr/bin/env python3
"""Real packet tests in disposable network namespaces; never host networking.
Run: unshare --net -- python3 scripts/test-topology-dataplane.py MODE
MODE: shared, routed, multi_lan. Requires root, ip, nft, nsenter and unshare.
Uses production install_rules/remove_rules with a Docker-style FORWARD chain.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
    raise SystemExit("Refusing host network namespace; run with unshare --net")
mode = sys.argv[1] if len(sys.argv) == 2 else ""
if mode not in ("shared", "routed", "multi_lan"):
    raise SystemExit("Specify shared, routed or multi_lan")
spec = importlib.util.spec_from_file_location("agent", Path(__file__).with_name("vpngw-policy-agent.py"))
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
children = []


def run(ns, *args, check=True):
    prefix = ["nsenter", "-t", str(ns), "-n"] if ns else []
    return subprocess.run(prefix + list(args), check=check, text=True, capture_output=True, timeout=8)


def child():
    proc = subprocess.Popen(["unshare", "--net", "--", "sleep", "120"])
    children.append(proc)
    for _ in range(100):
        if os.readlink(f"/proc/{proc.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
            run(proc.pid, "ip", "link", "set", "lo", "up")
            return proc.pid
        time.sleep(0.01)
    raise RuntimeError("Namespace not ready")


def connect(a, an, b, bn, number):
    x, y = f"va{number}", f"vb{number}"
    run(None, "ip", "link", "add", x, "type", "veth", "peer", "name", y)
    if a:
        run(None, "ip", "link", "set", x, "netns", str(a))
    run(a, "ip", "link", "set", x, "name", an)
    if b:
        run(None, "ip", "link", "set", y, "netns", str(b))
    run(b, "ip", "link", "set", y, "name", bn)
    run(a, "ip", "link", "set", an, "up")
    run(b, "ip", "link", "set", bn, "up")


def addr(ns, dev, value):
    run(ns, "ip", "addr", "add", value, "dev", dev)


def ping(ns):
    return run(ns, "ping", "-c", "1", "-W", "1", "203.0.113.1", check=False).returncode == 0


try:
    run(None, "ip", "link", "set", "lo", "up")
    run(None, "sysctl", "-qw", "net.ipv4.ip_forward=1")
    upstream = child()
    addr(upstream, "lo", "203.0.113.1/32")
    clients = []
    if mode == "shared":
        switch, client = child(), child()
        run(switch, "ip", "link", "add", "br0", "type", "bridge")
        run(switch, "ip", "link", "set", "br0", "up")
        for index, (ns, port) in enumerate(((None, "pg"), (client, "pc"), (upstream, "pu"))):
            connect(ns, "eth0", switch, port, index)
            run(switch, "ip", "link", "set", port, "master", "br0")
        addr(None, "eth0", "10.50.0.1/24")
        addr(client, "eth0", "10.50.0.10/24")
        addr(upstream, "eth0", "10.50.0.254/24")
        run(client, "ip", "route", "add", "default", "via", "10.50.0.1")
        run(None, "ip", "route", "add", "default", "via", "10.50.0.254")
        clients.append((client, "10.50.0.10", "eth0"))
        wan = "eth0"
    else:
        connect(None, "wan0", upstream, "eth0", 0)
        addr(None, "wan0", "198.18.0.2/30")
        addr(upstream, "eth0", "198.18.0.1/30")
        run(None, "ip", "route", "add", "default", "via", "198.18.0.1")
        wan = "wan0"
        for index in range(1, 3 if mode == "multi_lan" else 2):
            client = child()
            lan = f"lan{index}"
            connect(None, lan, client, "eth0", index)
            addr(None, lan, f"10.50.{index}.1/24")
            addr(client, "eth0", f"10.50.{index}.10/24")
            run(client, "ip", "route", "add", "default", "via", f"10.50.{index}.1")
            clients.append((client, f"10.50.{index}.10", lan))
    run(None, "nft", "add", "table", "ip", "filter")
    run(None, "nft", "add", "chain", "ip", "filter", "FORWARD",
        "{ type filter hook forward priority 0; policy drop; }")
    run(None, "nft", "add", "chain", "ip", "filter", "DOCKER-USER")
    run(None, "nft", "add", "rule", "ip", "filter", "FORWARD", "jump", "DOCKER-USER")
    for index, (client, host, lan) in enumerate(clients):
        pid = f"test-client-{index}"
        mac = json.loads(run(client, "ip", "-j", "link", "show", "eth0").stdout)[0]["address"]
        plan = dict(host=host, lan=lan, wan=wan, destination="direct",
                    shared=mode == "shared", registered_mac=mac)
        assert not ping(client), "Unconfigured client unexpectedly forwarded"
        agent.install_rules(plan, pid)
        assert ping(client), "DIRECT did not forward"
        table = "vpngw_" + agent.chain_name(pid).lower()
        nat = json.loads(run(None, "nft", "-j", "list", "table", "ip", table).stdout)
        assert any(any("masquerade" in expr for expr in item.get("rule", {}).get("expr", []))
                   and any(expr.get("counter", {}).get("packets", 0) > 0
                           for expr in item.get("rule", {}).get("expr", []))
                   for item in nat["nftables"]), "NAT rule did not receive packets"
        agent.remove_rules(pid)
        agent.install_rules({**plan, "destination": "blocked"}, pid)
        assert not ping(client), "BLOCKED leaked"
        for previous, _, _ in clients[:index]:
            assert ping(previous), "Blocking one LAN disrupted another LAN"
        agent.remove_rules(pid)
        agent.install_rules({**plan, "registered_mac": "02:00:00:00:00:ff"}, pid)
        assert not ping(client), "MAC mismatch leaked"
        agent.remove_rules(pid)
        agent.install_rules(plan, pid)
        assert ping(client), "DIRECT did not recover"
        print(f"{mode}: client {index}: initial deny, DIRECT/NAT, BLOCKED, MAC mismatch, DIRECT recovery PASS", flush=True)
finally:
    for proc in children:
        proc.terminate()
    for proc in children:
        proc.wait(timeout=5)
