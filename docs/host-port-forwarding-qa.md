# Gateway VPN Multi — selected host port forwarding QA

Status: development candidate. No public release until full QA passes.

## Runtime route matrix

- DIRECT: the chosen host receives TCP/UDP 6881 DNAT from the current physical WAN. If UPnP is enabled, miniupnpc on the Gateway requests and renews a matching **owned** upstream router IGD mapping. Foreign mappings must never be replaced.
- WireGuard and OpenVPN: only VPN-provider NAT-PMP mapping is used. Both TCP and UDP must be confirmed with the **same** provider port. The port becomes the active libtorrent listen port. The physical WAN IGD is not used.
- BLOCKED or disconnected VPN: no inbound DNAT, no fallback to DIRECT. Revoke owned upstream/router/provider mapping where permitted.
- Host identity belongs to policy ID + registered MAC, never a fixed IPv4.

## IPv4 change

The authenticated HTTPS API POST /api/v1/policies/{policy_id}/rebind-ip?new_ip=X requests a two-phase privileged rebind. A unique fresh Linux neighbour mapping must match the registered MAC, LAN and allowed subnet. Before any kernel mutation, the privileged agent journals a MAC-specific quarantine that also drops inbound packets for both the previous and candidate IPv4.

Rebuild the host-specific nft rules and, for VPN, the policy routing; verify against the active interface. Only after the privileged prepare may SQLite commit the new IP; kernel release is a second, independently verified phase. Failure leaves the host quarantined. Early boot restores pending quarantines before networking resumes.

Optional automatic mode: set VPNGW_AUTO_REBIND=1 on the single-worker WebAdmin API. The observer checks every 30 seconds and requires two identical fresh observations. A matching pending crash journal may be resumed immediately. Do not enable in QA until the complete functional regression passes.

## Operational dependency

The Gateway Linux policy-agent installer deploys all root-side helpers and can provision Debian miniupnpc. Missing /usr/bin/upnpc is reported as unavailable, not as a successful mapping. This is an upstream **client**, not a locally advertised miniupnpd IGD server.

MediaHub DEV PR #13 deploys a separate host-side port watcher. It discovers the current Gateway using the host MAC/NIC and active route, queries the authenticated HTTPS port 9443 status, and recreates Stremio only when a fresh verified TCP+UDP port actually changes.

## Release gate — mandatory evidence

1. Install the exact candidate revision on router QA and check the authenticated port 9443 endpoint returns HTTP 200 (anonymous 401); old 1.0.2 returned 404 upstream.
2. Test single-owner exclusive selection; MAC conflicts, stale neighbour state, duplicate and changing IP, and manual rebind in DIRECT/BLOCKED/WG/OpenVPN.
3. Inspect nftables quarantine, per-host tables, IPv4 rules, SQLite, systemd and boot state after failures injected before and after commit.
4. Reboot between prepare and commit; verify fail-closed persistence and automatic journal recovery.
5. Switch VPN A -> VPN B -> DIRECT -> BLOCKED; verify old mappings revoked and no residual direct or VPN ingress.
6. Verify UPnP router next hop identity, owned 6881 TCP and UDP mapping, renewal, revocation, foreign mapping refusal and real reachability.
7. Verify both Proton WireGuard and OpenVPN provider NAT-PMP TCP+UDP mapping and renewal with no DNS, IPv6 or direct fallback.
8. Integrate the real MediaHub timer, Stremio container recreation/health, reboot persistence, and rollback.
9. Complete all GitHub Actions jobs and isolated Linux netns dataplane tests on the exact candidate commit before merging DEV or publishing packages.

A passing unit test is not equivalent to evidence from the physical router, provider VPN, reboot or external reachability.
