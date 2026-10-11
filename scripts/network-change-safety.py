#!/usr/bin/env python3
"""Read-only safety gate for applying static IPv4 changes on a PVE gateway.

This tool never changes interfaces, files, routes or services. Fail closed until
an external rollback mechanism and management reachability checks exist.
"""
import json
import pathlib
import subprocess


def evaluate(interfaces, routes, config_files, management='eth0'):
    reasons = []
    managed = [i for i in interfaces if i.get('interface') == management and i.get('address')]
    if len(managed) != 1:
        reasons.append('management_interface_not_unique')
    elif managed[0].get('operstate') != 'UP':
        reasons.append('management_interface_not_up')
    defaults = [r for r in routes if r.get('gateway')]
    if len(defaults) != 1:
        reasons.append('multiple_or_missing_default_routes')
    if any('autoconfigured by PVE' in content for content in config_files.values()):
        reasons.append('proxmox_managed_network_files')
    reasons.extend(['rollback_timer_not_armed', 'external_management_probe_not_verified'])
    return {'mode': 'read_only', 'apply_permitted': False,
            'management_interface': management, 'blocking_reasons': reasons,
            'network_files': sorted(config_files)}


def main():
    script = pathlib.Path(__file__).with_name('network-topology.py')
    p = subprocess.run(['/usr/bin/python3', str(script)], capture_output=True,
                       text=True, check=True, timeout=12)
    topology = json.loads(p.stdout)
    folder = pathlib.Path('/etc/systemd/network')
    configs = {str(path): path.read_text() for path in folder.glob('*.network')}
    print(json.dumps(evaluate(topology['interfaces'], topology['default_routes'], configs), indent=2))


if __name__ == '__main__':
    main()
