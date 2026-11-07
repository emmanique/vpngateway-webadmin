# VPN Gateway Multi — DEV/QA evidence (2026-11-04)

**Scope:** gateway `192.168.1.231` (`routerqua`), Stremio `192.168.1.199`, QA client `192.168.1.229`. This is NOT a public release approval.

## Existing features verified, not reimplemented

- Both registered MAC-bound hosts route independently through Proton OpenVPN `vpn-protopen`; their host policy tables retain an explicit unreachable fallback.
- Selected Stremio host has the exclusive provider NAT-PMP lease, TCP/UDP port **54659** during this observation. Dynamic port changes are propagated to Stremio Compose by an external systemd timer on `.199`.
- Normal client DNS queries and explicit attempts to use public DNS (1.1.1.1/8.8.8.8) are redirected through the host's assigned Proton VPN.
- Pi-hole exists once in the active Compose stack, with LAN DNS ACL; the live Pi-hole **still has upstream 1.1.1.1**, not the central route-aware worker.

## Corrections completed

1. OpenVPN pushed IPv4 DNS discovery no longer depends on the last 150 journal records (replay warnings can bury the push).
2. OpenVPN `tun...` devices are supported in read-only recovery planning, besides WireGuard.
3. External MediaHub NAT-PMP listener reconciliation was installed and validated for an OpenVPN port change, without redundant recreates.
4. DNS policy worker now derives the current Docker bridge and Pi-hole IP on startup, with netlink permitted in its restricted systemd unit.
5. DNS QA cutover updates the early MAC-bound boot guard **atomically in the same nft batch** as the per-host DNS guard, allowing only TCP/UDP 53 from the identified host to the chosen Pi-hole on the expected Docker bridge. All other non-VPN forwarding remains blocked.
6. DNS QA rollback restores the provider DNS guards and removes the bridge-specific route; boot recovery reads durable QA journals. On policy changes it removes only the exact stale DNS exception rather than overwriting a newer host policy.
7. A dedicated opt-in `installers/install-dns-qa-recovery-linux.sh` deploys the boot recovery components. It is NOT included in standard/public installation.

## Test evidence

- **486 pytest tests passed; 77 subtests passed**, including the API suite. No test failures; warnings were emitted.
- `scripts/test-dns-cutover-rollback-netns.sh`: kernel DNS cutover, loss of tunnel route, and rollback while VPN interface is unavailable all passed.
- `scripts/test-dns-pihole-e2e.py` with an existing local WebAdmin QA image: isolated Pi-hole v6, two independent clients and simulated VPN interfaces, ECS source retention, Pi-hole blocking, blocked host SERVFAIL, tunnel loss/recovery, and **zero DNS packets on WAN** all passed.
- **Live pilot limited to `.229`**: disposable Pi-hole `172.18.0.6` and per-host policy cutover accepted DNS from source `192.168.1.229`, including forced 8.8.8.8/1.1.1.1 queries. The client's public egress stayed `79.127.131.204`, and the Stremio `.199` retained its own tunnel, route, and NAT-PMP mapping. Early boot guard counted 71 accepted packets to the temporary Pi-hole. Rollback was verified: provider DNS `10.96.0.1` restored, temporary exception removed, no pending timers or journals. Disposable container removed; dedicated worker reattached to the production Pi-hole as an opt-in, not serving regular client DNS.
- Pi-hole gravity DB needs the unprivileged Pi-hole FTL UID/GID on disposable copies. The initial live attempt failed because its read-only/root-owned copy could not be read, and before the boot guard exception was added clients could not reach Docker. Both failures were diagnosed, corrected, and retested.

## Functional acceptance update — 2026-11-04

Project owner confirms **APPROVED** for: (1) real OpenVPN outage and recovery; (2) client reboot and recovery; (3) external VPN port reachability. These are owner acceptance statements; raw test logs are not attached to this record. The earlier test-evidence section remains a historical snapshot.

## Release gates and owner sign-off

1. **GitHub Actions** jobs are not starting because GitHub reports failed account payments or a spending limit. This is an account-level billing issue, not a test failure; CI cannot be declared passing until corrected and rerun.
2. **Global production Pi-hole upstream switch** is intentionally not performed: only `.199` and `.229` have confirmed VPN policies; other LAN clients may need DNS. The route-aware worker fails closed for unknown clients. Establish explicit policy coverage and an approved direct/blocked/unknown-host DNS contract before switching a shared upstream.
3. **Live shared OpenVPN outage / recovery**: APPROVED by project owner (functional acceptance).
4. **Client reboot and recovery; independent Internet port reachability**: APPROVED by project owner (functional acceptance).

**Historical promotion decision (before owner sign-off):** keep on `develop` pending functional validation. **Current status:** owner accepted OpenVPN outage/recovery, client reboot/recovery and external port reachability. GitHub Actions billing remains an infrastructure limitation, and global Pi-hole DNS cutover remains opt-in and outside standard v1.0.3 release scope. Final publication requires source/package integrity checks.
