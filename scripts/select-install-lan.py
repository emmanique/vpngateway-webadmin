#!/usr/bin/env python3
"""Select management LAN conservatively; a default route does not identify LAN."""
import json
from pathlib import Path
import subprocess
import sys


def select_lan(links, physical):
    candidates = [
        link["ifname"] for link in links
        if link.get("ifname") in physical
        and any(addr.get("family") == "inet" and addr.get("scope") == "global"
                for addr in link.get("addr_info", []))
    ]
    if len(candidates) != 1:
        raise ValueError("Interface LAN ambígua; indique --lan-interface (não inferida pela rota WAN)")
    return candidates[0]


def main():
    links = json.loads(subprocess.check_output(
        ["ip", "-4", "-j", "addr", "show"], text=True, timeout=5))
    physical = {p.name for p in Path("/sys/class/net").iterdir()
                if (p / "device").exists()}
    try:
        print(select_lan(links, physical))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
