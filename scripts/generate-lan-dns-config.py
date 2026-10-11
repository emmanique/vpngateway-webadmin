#!/usr/bin/env python3
"""Generate LAN-bound Pi-hole Docker override and CIDR ACL, without applying changes.
Only consumes a verified *applied* network config; never trusts an unapplied UI draft.
"""
import argparse, ipaddress, json, pathlib, subprocess


def generate(config, interfaces, upstreams):
    if not config.get('applied'):
        raise ValueError('Network configuration has not been applied; refusing to derive DNS ACL from draft')
    roles = {x['interface']: x['role'] for x in config['interfaces']}
    lans = []
    for item in interfaces:
        if item['interface'] not in roles or roles[item['interface']] != 'lan':
            continue
        if item.get('kind') not in ('ethernet', 'wifi', 'vlan'):
            continue
        address = ipaddress.ip_interface(item['address'] + '/' + str(item['prefixlen']))
        if not address.ip.is_private or address.version != 4:
            raise ValueError('LAN interface must have a private IPv4 address')
        lans.append((str(address.ip), str(address.network)))
    if not lans:
        raise ValueError('No applied physical LAN IPv4 interface')
    if len(lans) != 1:
        raise ValueError('Multiple LAN interfaces need explicit per-interface DNS binding')
    if not upstreams:
        raise ValueError('No configured DIRECT WAN DNS upstream')
    valid_upstreams = [str(ipaddress.ip_address(x)) for x in upstreams]
    ip, cidr = lans[0]
    compose = {'services': {'pihole': {'ports': [f'{ip}:53:53/udp', f'{ip}:53:53/tcp'], 'environment': {'FTLCONF_dns_listeningMode': 'ALL', 'FTLCONF_dns_upstreams': ';'.join(valid_upstreams), 'FTLCONF_dhcp_active': 'false'}}}}
    nft = f'''table inet vpngw_pihole_dns {{
 chain local_input {{
  type filter hook input priority -10; policy accept;
  ip daddr {ip} meta l4proto {{ tcp, udp }} th dport 53 ip saddr != {cidr} drop
 }}
 chain ingress {{
  type filter hook forward priority -10; policy accept;
  ct direction original meta l4proto {{ tcp, udp }} ct original ip daddr {ip} ct original proto-dst 53 ip saddr != {cidr} drop
 }}
}}
'''
    return {'lan_ip': ip, 'lan_cidr': cidr, 'upstreams': valid_upstreams, 'compose': compose, 'nft': nft}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--applied-config', required=True)
    parser.add_argument('--interfaces', required=True)
    parser.add_argument('--upstream', action='append', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = generate(json.loads(pathlib.Path(args.applied_config).read_text()), json.loads(pathlib.Path(args.interfaces).read_text()), args.upstream)
    target = pathlib.Path(args.output)
    target.mkdir(parents=True, exist_ok=True)
    (target/'compose.pihole-lan-dns.generated.json').write_text(json.dumps(result['compose'], indent=2) + '\n')
    (target/'pihole-dns-acl.generated.nft').write_text(result['nft'])
    subprocess.run(['nft', '-c', '-f', str(target/'pihole-dns-acl.generated.nft')], check=True)
    print(json.dumps({key: result[key] for key in ('lan_ip', 'lan_cidr', 'upstreams')}))


if __name__ == '__main__':
    main()
