#!/usr/bin/env python3
"""Read-only host DNS route preparation; no host routing changes."""
import ipaddress
import re

def render(host,worker,bridge,tunnel,table,priority,lan,worker_route):
    host=str(ipaddress.IPv4Address(host))
    worker=str(ipaddress.IPv4Address(worker))
    if not all(re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}",v) for v in (bridge,tunnel,lan)):
        raise ValueError("Invalid interface")
    if not isinstance(table,int) or not 20000<=table<40000:
        raise ValueError("Invalid host routing table")
    if not isinstance(priority,int) or not 10000<=priority<20000:
        raise ValueError("Invalid priority")
    if not re.search(r"\bdev "+re.escape(bridge)+r"\b",worker_route):
        raise ValueError("Worker not reachable through expected Docker bridge")
    # Install the terminal unreachable route first, then local worker, then VPN.
    return {"host":host,"dns_worker":worker,"bridge":bridge,"table":table,
      "applied":False,
      "commands":[
       ["ip","-4","route","replace","unreachable","default","metric","42700","table",str(table)],
       ["ip","-4","route","replace",worker+"/32","dev",bridge,"scope","link","table",str(table)],
       ["ip","-4","route","replace","default","dev",tunnel,"metric","10","table",str(table)],
       ["ip","-4","rule","add","pref",str(priority),"from",host+"/32","iif",lan,"lookup",str(table)]],
      "required_before_execution":["host kill switch active","worker DNS isolation verified",
                                  "independent rollback journal armed","Docker forwarding and reply traffic validated"]}
