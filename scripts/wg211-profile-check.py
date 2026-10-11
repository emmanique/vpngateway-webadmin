#!/usr/bin/env python3
"""Read-only validation of WireGuard profile without leaking private data."""
import configparser
import ipaddress
import json
from pathlib import Path

p = Path('/opt/vpngateway-dev/shared/data/wireguard-profiles/proton.conf')
c = configparser.ConfigParser(interpolation=None, strict=True)
result = {'profile_found': p.is_file(), 'profile_safe_permissions': False, 'single_peer': False, 'address_valid': False, 'allowed_ips_full_tunnel': False, 'dns_addresses_valid': False, 'endpoint_present': False, 'no_execution_hooks': False, 'ready_for_handshake_test': False, 'network_changes': False}
if p.is_file() and not p.is_symlink() and p.stat().st_size < 65536:
    result['profile_safe_permissions'] = (p.stat().st_mode & 0o077) == 0
    try:
        c.read(p, encoding='utf-8')
        result['single_peer'] = c.sections() == ['Interface', 'Peer']
        interface = c['Interface']
        peer = c['Peer']
        result['no_execution_hooks'] = not any(k.lower() in ('preup','postup','predown','postdown','saveconfig') for k in interface)
        result['address_valid'] = bool([ipaddress.ip_interface(v.strip()) for v in interface.get('Address','').split(',') if v.strip()])
        dns = [v.strip() for v in interface.get('DNS','').split(',') if v.strip()]
        result['dns_addresses_valid'] = bool(dns) and all(ipaddress.ip_address(v) for v in dns) is not None
        allowed = {str(ipaddress.ip_network(v.strip(), strict=False)) for v in peer.get('AllowedIPs','').split(',') if v.strip()}
        result['allowed_ips_full_tunnel'] = '0.0.0.0/0' in allowed
        result['endpoint_present'] = bool(peer.get('Endpoint','').strip())
    except (ValueError, KeyError, configparser.Error):
        pass
result['ready_for_handshake_test'] = all(result[k] for k in ('profile_safe_permissions','single_peer','address_valid','allowed_ips_full_tunnel','dns_addresses_valid','endpoint_present','no_execution_hooks'))
print(json.dumps(result, indent=2))
