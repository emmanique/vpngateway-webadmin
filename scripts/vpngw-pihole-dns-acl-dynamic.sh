#!/bin/sh
set -eu
umask 077
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT HUP INT TERM
# Docker and the WebAdmin API may become ready after network-online.target.
# Retry the read-only generator before applying an nft transaction.
ready=0
for attempt in $(seq 1 20); do
    if python3 /usr/local/libexec/vpngw-pihole-dns-acl-dynamic.py > "$tmp"; then
        ready=1
        break
    fi
    sleep 3
done
if [ "$ready" -ne 1 ]; then
    echo "DNS ACL API unavailable after retries; no firewall changes applied" >&2
    exit 2
fi
# Single nftables transaction: replace old table without an unprotected interval.
if /usr/sbin/nft list table inet vpngw_pihole_dns >/dev/null 2>&1; then
    sed -i '1i delete table inet vpngw_pihole_dns' "$tmp"
fi
/usr/sbin/nft -c -f "$tmp"
/usr/sbin/nft -f "$tmp"
