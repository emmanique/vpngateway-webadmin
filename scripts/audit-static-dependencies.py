#!/usr/bin/env python3
"""Fail production builds that depend on laboratory hosts, interfaces or VPN IDs."""
import argparse
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
PATTERNS={
    "private_ipv4":re.compile(r"(?<![\d.])(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2}(?![\d.])"),
    "legacy_profile":re.compile(r"vpn-(?:proton-openvpn|cyberghost-openvpn|proton-wire|dev-br|dev-pt)"),
    "legacy_host":re.compile(r"dev-client-[ab]|gwproxydev|gwdev-asus|gwproxy-dev|lenovo249|vm210"),
    "lab_interface":re.compile(r"\b(?:wlp2s0|ens19|wg211)\b"),
    "absolute_workspace":re.compile(r"/opt/vpngateway-dev/workspace/"),
}
EXTENSIONS={".py",".sh",".tsx",".ts",".yaml",".yml",".service",".conf"}
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("--strict",action="store_true",help="Exit nonzero for any production dependency")
parser.add_argument("--include-tests",action="store_true",help="Report synthetic fixtures separately")
args=parser.parse_args()
files=[ROOT/"start.sh"]
for folder in ("apps/api","apps/web/src","scripts","installers","deploy"):
    for p in (ROOT/folder).rglob("*"):
        if not p.is_file() or p.suffix not in EXTENSIONS: continue
        if any(part in {"tests","node_modules","__pycache__","dist"} for part in p.relative_to(ROOT).parts): continue
        if p.name.startswith(("test-","test_")) or p.name=="audit-static-dependencies.py":continue
        files.append(p)
if args.include_tests:
    files.extend(p for folder in ("apps/api/tests","tests") for p in (ROOT/folder).rglob("*")
                 if p.is_file() and p.suffix in EXTENSIONS)
    files.extend(p for p in (ROOT/"scripts").iterdir() if p.is_file()
                 and p.name.startswith(("test-","test_")) and p.suffix in EXTENSIONS)
issues=[]
for p in sorted(set(files)):
    if not p.exists():continue
    for n,line in enumerate(p.read_text(encoding="utf-8",errors="replace").splitlines(),1):
        for kind,regex in PATTERNS.items():
            if regex.search(line):
                issues.append((kind,str(p.relative_to(ROOT)),n))
for kind,path,number in issues:
    print(f"{kind}: {path}:{number}")
print(f"Audited {len(set(files))} files; {len(issues)} literal dependencies detected.")
if issues and args.strict:raise SystemExit(1)
