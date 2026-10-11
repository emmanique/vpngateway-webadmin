#!/usr/bin/env python3
"""Read-only plan for guarded static-network changes (never schedules or applies)."""
import argparse
import ipaddress
import json
from pathlib import Path


def validate_config(interface, address, gateway, management_address):
    reasons = []
    try:
        candidate = ipaddress.ip_interface(address)
        gw = ipaddress.ip_address(gateway)
        management = ipaddress.ip_address(management_address)
        if candidate.version != 4 or gw.version != 4 or management.version != 4:
            reasons.append('ipv4_only')
        else:
            if gw not in candidate.network:
                reasons.append('gateway_outside_subnet')
            if candidate.ip in (candidate.network.network_address, candidate.network.broadcast_address):
                reasons.append('reserved_interface_address')
            if interface == 'eth0' and candidate.ip != management:
                reasons.append('management_ip_change_requires_external_recovery')
    except ValueError:
        reasons.append('invalid_ip_or_gateway')
    if not interface or '/' in interface or interface in ('.', '..'):
        reasons.append('invalid_interface')
    return reasons


def plan(interface, address, gateway, management_address=None):
    reasons = validate_config(interface, address, gateway, management_address) if management_address else ['management_address_required']
    return {
        'mode': 'read_only', 'apply_permitted': False,
        'candidate': {'interface': interface, 'address': address, 'gateway': gateway},
        'validation_errors': reasons,
        'rollback_requirements': [
            'capture byte-exact network files and active routes before change',
            'arm independent systemd rollback before applying changes',
            'prove rollback survives SSH/WebAdmin disconnection',
            'probe management from an external LAN host after applying',
            'cancel rollback only after external verification',
            'account for Proxmox-managed network file regeneration',
        ],
        'note': 'No network configuration, route, timer or service changed.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--address', required=True, help='Static IPv4 with prefix')
    parser.add_argument('--gateway', required=True)
    parser.add_argument('--management-ip', required=True)
    args = parser.parse_args()
    print(json.dumps(plan(args.interface, args.address, args.gateway, args.management_ip), indent=2))


if __name__ == '__main__':
    main()
