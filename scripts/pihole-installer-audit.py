#!/usr/bin/env python3
"""Fail-closed, read-only inspection of an upstream Pi-hole shell installer.

This does not authorize execution. It reports sensitive operations and their
relative order, so a changed upstream installer cannot silently inherit a
previous review.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


def audit(source):
    digest = hashlib.sha256(source.encode()).hexdigest()
    markers = {
        'disable_resolver_definition': r'^disable_resolved_stublistener\(\)\s*\{',
        'disable_resolver_call': r'^\s*disable_resolved_stublistener\s*$',
        'restart_ftl': r'^\s*restart_service\s+pihole-FTL\s*$',
        'set_dns_interface': r'^\s*setFTLConfigValue\s+"dns\.interface"',
        'resolver_dropin': r'90-pi-hole-disable-stub-listener\.conf',
        'resolver_restart': r'systemctl\s+reload-or-restart\s+systemd-resolved',
    }
    lines = source.splitlines()
    locations = {key: [i for i, line in enumerate(lines, 1)
                       if re.search(pattern, line)] for key, pattern in markers.items()}
    required = all(locations.values())
    first_start_precedes_interface = bool(required and
        locations['restart_ftl'][0] < locations['set_dns_interface'][0])
    resolver_mutation = bool(locations['disable_resolver_call'] and
                             locations['resolver_dropin'] and locations['resolver_restart'])
    return {
        'sha256': digest, 'line_count': len(lines), 'markers': locations,
        'first_ftl_start_precedes_interface_configuration': first_start_precedes_interface,
        'installer_modifies_systemd_resolved': resolver_mutation,
        'review_required': True,
        'safe_to_execute_on_gateway': False,
        'audit_complete': required,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('installer', type=Path, help='Local upstream installer to inspect; never execute')
    args = parser.parse_args()
    result = audit(args.installer.read_text(encoding='utf-8'))
    print(json.dumps(result, indent=2))
    return 0 if result['audit_complete'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
