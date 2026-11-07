# V2 dataplane checkpoint — 2026-10-12

Scope: DEV develop only. This is a partial acceptance report, not a release approval.
The public repository, NetworkManager profiles and existing clean-install backup were not changed.

## Changes

- Reconciled local daebf03 and remote a1186460 with a merge, preserving both histories.
  Their tree hashes were identical (e2161bb8f8b0ad7d3206ba674765f415b6447424).
- Commit 42eaddd: installer no longer infers LAN from the default (WAN) route.
  Automatic selection requires exactly one addressed physical interface; ambiguous setups require --lan-interface.
- Installer explicitly restarts and verifies the DNS ACL service after installing its configuration.
- Added six LAN-selection regression tests.
- Added real-packet namespace tests using production install_rules/remove_rules.
  CI now exercises shared, routed and multi-LAN modes and the existing VPN route-loss recovery test.

## Observed ASUS and client results

Lab addresses below are evidence only, never production defaults.

| Check | Result | Evidence |
|---|---|---|
| Physical topology | PASS | LAN enx00e04c360d26 192.168.1.221/24; WAN wlp2s0 192.168.200.200/24; default via 192.168.200.1 |
| Initial unconfigured clients | Expected deny | Empty policies; FORWARD DROP; no per-client NAT; both clients fail external ping |
| DIRECT creation | PASS | API HTTP 201, active; qa-client-a (.228), qa-client-b (.229), observed MAC registered |
| DIRECT external access | PASS | Both clients: ping response and HTTPS 200 from example.com |
| Actual WAN/NAT | PASS | Capture on wlp2s0: controlled ICMP payloads 128/144 bytes from the two clients appear as source 192.168.200.200; both replies captured |
| DIRECT to BLOCKED | PASS | Both clients: external ping fails, HTTPS connection times out, Pi-hole DNS times out; SSH remains reachable |
| BLOCKED to DIRECT | PASS | Both clients: ping restored; Pi-hole UDP and TCP DNS return answers |
| Agent restart | PASS | Both clients retain ping/HTTPS 200; WebAdmin 200; no failed systemd units |
| Served diagram bundle | PASS (content only) | index-B7rmD5IS.js contains outbound LAN flow and management component |
| UI visual desktop/mobile | NOT RUN | Bundle content and successful build do not prove visual layout |
| Real provider VPN | BLOCKED | Connections API returns []; no WireGuard/OpenVPN profiles in this clean installation |
| Full reboot recovery | NOT RUN | Agent restart is not a substitute for reboot verification |

Final live state: both test policies remain DIRECT and active. Four application containers running.
No global permissive NAT rule was added: forwarding is installed per authorised client.

## Isolated verification

- Full regression suite: 195 tests, PASS (includes 13 topology tests and 6 new installer tests).
  Ran in a disposable container with repository mounted read-only and no network.
- TypeScript/Vite build and PT/EN checks: PASS; 239 UI labels, 143 legacy translations.
- Static dependency audit: 89 files, zero literal dependencies.
- Explicit-interface installer precheck and shell syntax: PASS.
- Shared, routed and two-client multi-LAN namespace tests: PASS.
  Each client exercises initial deny, DIRECT, NAT counter increment, BLOCKED, MAC mismatch and DIRECT recovery.
  Blocking the second LAN does not disrupt the first LAN.
  These tests use virtual links, not additional physical ASUS adapters.
- Existing VPN namespace test: PASS for route denial after tunnel disappearance and route reconstruction.
  The tunnel is simulated; this does not certify provider reconnection or DNS isolation.
- GitHub CI for 42eaddd: all four jobs succeeded, run 38281962204.
  The added dataplane job is validated separately by the subsequent commit's CI.

## Remaining acceptance work

1. Import test WireGuard and OpenVPN profiles through WebAdmin; validate both providers/protocols,
   failure/reconnect, VPN-to-VPN changes, deletion and restoration.
2. Capture DNS with active VPN policies, including explicit external DNS, DoT and DoH.
   Pi-hole resolution alone does not prove absence of DNS leaks.
3. Test MAC changes on physical clients. Namespace enforcement passed; live API reports verified guards.
4. Validate a controlled reboot with recovery access and no fail-open window.
   IPv6 forwarding currently reads zero, but end-to-end IPv6 bypass was not exercised.
5. Review legacy systemd remnants: vpngw-dns-worker-client249.service is disabled and has no reverse dependents,
   but remains installed and references a historical VPN. It was not deleted.
6. Finish installer/recovery ordering audit. The network-recovered checker is a legacy installed unit;
   its presence on this host does not establish clean-install reproducibility.
7. Complete desktop/mobile visual QA.
8. Repeat clean-install acceptance on supported Debian/Ubuntu after these changes.

No release or version bump was performed.
