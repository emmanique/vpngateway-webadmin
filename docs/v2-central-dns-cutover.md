# v2 — Central Pi-hole / route-aware upstream (DEV only)

Status: **experimental; not deployed; release gate open**.

## Required invariant

One Pi-hole instance is the filtering authority for both DIRECT and VPN
clients. Every permitted query to an external upstream must use the
confirmed client's assigned egress route, not the container's default route.

    LAN host (IP/MAC) -- TCP/UDP 53 --> nft policy/Docker bridge
      --> Pi-hole gravity + trusted client EDNS IPv4 /32
      --> single host DNS policy upstream (bridge:5355)
          DIRECT  -> explicit resolver through WAN
          VPN A   -> assigned OpenVPN tunnel/provider DNS
          VPN B   -> assigned WireGuard tunnel/provider DNS
          blocked/unknown/pending -> SERVFAIL; never DIRECT

The policy upstream strips ECS before contacting DNS providers, rejects
untrusted Pi-hole sources, and binds outbound sockets to the selected
interface (SO_BINDTODEVICE), with no default-route fallback.

## Opt-in DEV building blocks

- scripts/vpngw-dns-policy-upstream.py — UDP/TCP upstream, validated ECS,
  confirmed per-host policies, privileged interface binding, no DNS fallback.
  Requires arguments: --listen, --bridge-interface, --pihole-source,
  --direct-resolver, --policy-dir. Not installed or enabled.
- scripts/vpngw-vpn-host-guard.py — optional central_dns guard rendering
  while maintaining MAC, IPv6, DoT/DoQ and VPN egress controls.
- scripts/vpngw-vpn-filter-batch.py — optional Pi-hole bridge exceptions
  in the legacy host filter. Default behaviour remains unchanged.
- scripts/vpngw-dns-central-preflight.py — read-only checks, explicitly
  rejects cutover until full policy and network readiness are proven.

- scripts/test-dns-pihole-e2e.py — real Pi-hole v6 in private Docker networks,
  two distinct fake provider resolvers and synthetic clients. Confirms
  client IP visibility, centralized blocking, route isolation, blocked-host
  fail-closed, PCAP packets per resolver and no associated packets on the
  physical WAN. No LAN or VPN interface changes. Mandatory root packet capture.
  The test also changes the synthetic client to a non-existent VPN interface:
  Pi-hole must return SERVFAIL, then resume successful DNS after restoration.
- scripts/test-dns-cutover-rollback-netns.sh — executes the actual DNS
  transaction and rollback against nftables and iproute2 INSIDE a Linux
  network namespace. Simulates tunnel-device disappearance after cutover
  and proves rollback retains unreachable routing (no WAN fallback).
- scripts/audit-dns-live-readonly.py — diagnostic only. Captures a short
  window on LAN, each assigned VPN, Pi-hole Docker bridge and WAN, using
  unique synthetic DNS questions from the two explicitly selected QA
  clients. No changes to policy or routing; packet captures are deleted
  on exit. Execution through remote access was blocked; no real-client
  PCAP has yet been obtained.
- scripts/vpngw-dns-qa-cutover.py — experimental per-host DNS transaction,
  shared kernel lock with policy agent, durable rollback journal, systemd
  independent deadline, atomic nftables batch and routing-table /32.
  Explicitly not enabled by installer or used in production.
- scripts/test-dns-real-client-pilot.py — opt-in restricted QA harness for
  real LAN clients, with independent Pi-hole container and per-client
  transaction rollback. No successful authorized live pilot has occurred.
  Never run it without a reviewed safe execution path and authorization.

## Mandatory acceptance gates before activation

1. Discover/pin the live Docker bridge, Pi-hole container address and
   trusted source; reject network identity drift.
2. Ensure Pi-hole v6 has exactly one upstream — this worker on the Docker
   bridge — with no global/direct fallback. Configure trusted EDNS source
   via add-subnet=32,128 plus strip-subnet (Pi-hole misc.dnsmasq_lines).
3. Bypass Docker published-port source NAT for client DNS queries while
   preserving client IP. Prove true client identity in Pi-hole's query log.
4. Stage a Pi-hole /32 route in the individual host policy routing table,
   preserving unreachable default and every other client's table.
5. Atomically switch provider DNAT to Pi-hole DNAT, host nft guard and
   legacy filter exceptions. Include durable rollback journal/restore.
6. Verify real blocked-domain queries at the single Pi-hole; prove DNS
   egress from OpenVPN and WireGuard stays on each tunnel, with no DNS
   packets routed via the WAN directly or via the other tunnel.
7. Test BLOCKED, DIRECT, MAC mismatch, tunnel loss and automatic recovery,
   resolver outage, Pi-hole restart, DNS-over-TLS/QUIC 853, backup/restore,
   and cold boot. Cached responses must not bypass failed-tunnel policy.
8. DNS-over-HTTPS over 443 is not fully blockable by simple port filters;
   document specific enterprise endpoint controls and test them rather than
   asserting comprehensive DoH prevention.

**Do not enable a subset of the path:** this could break DNS or leak DNS
through the host default route. Never hard-code QA IPs in release artifacts.
The public repository and v1.0.2 are outside this work.

## Development validation

- Run the full Python unittest suite in the WebAdmin dependency image.
- Run packet parsing, real isolated UDP/TCP requests and nftables syntax
  checks inside a dedicated network namespace.
- The isolated real Pi-hole packet/PCAP regression has passed on the
  ASUS, with no WAN DNS traffic from the two synthetic upstreams.
- Unit tests verify timer-before-route ordering, failed nft apply rollback,
  no concurrent agent changes and preservation of newer policy revisions.
- Run the real-client QA transaction only when the remote environment
  permits it, capturing LAN, Docker bridge, both VPN tunnels and WAN
  simultaneously. This evidence has NOT been obtained. Until then,
  production cutover preflight must remain fail-closed.

## Further DEV acceptance evidence

Single-Pi-hole deployment is opt-in, not enabled in the actual gateway:

- deploy/compose.v2-central-dns.opt-in.yml overrides the **existing** Pi-hole
  service upstream, enables EDNS origin tagging and disables DNS cache.
- deploy/systemd/vpngw-dns-policy-upstream.service stages the route-aware
  worker, requiring an explicit environment file, but is NOT enabled.
- deploy/dns-policy-upstream.env.example has no embedded QA IP or credentials.
- The existing release installer and start.sh never load this override.
- Unknown or Docker-proxied DNS client origins must not be silently treated
  as DIRECT. Correct client identity is a prerequisite to switching the
  existing Pi-hole upstream to policy-aware DNS.

E2E evidence and constraints:

- scripts/test-dns-origin-dnat-netns.py runs genuine UDP DNS across veth
  namespaces and nftables prerouting DNAT. The simulated Pi-hole receives
  the original LAN IPv4 and returns via reverse NAT; tunnel loss does not
  produce a WAN fallback.
- scripts/test-dns-pihole-e2e.py tests real Pi-hole v6 in Docker-isolated
  networks, distinct VPN resolvers, gravity blocking, missing-interface
  SERVFAIL, successful recovery and packet capture with zero matching
  DNS packets on the host physical WAN.
- tests/test_dns_v2_backup_restore_persistence.py verifies encrypted backup
  roundtrip, profile restoration, no implicit policy/network activation,
  and rejection of tampered backups and incorrect passwords.
- TCP/UDP 853 (DoT/DoQ) are denied for VPN hosts. DoH over HTTPS/443 is NOT
  exhaustively blocked by the gateway DNS policy and remains a limitation.

Remaining live release gates:

1. Identify all DIRECT and VPN DNS consumers, preserving original LAN source
   at the SINGLE existing Pi-hole (including published-port Docker ingress).
2. Apply per-client DNS cutover on .228 and .229 with rollback watchdog.
3. Capture simultaneous LAN, Docker, OpenVPN, WireGuard and WAN traffic
   and prove zero WAN DNS leaks or cross-profile DNS.
4. Simulate real tunnel failure and recovery in both clients.
5. Verify controlled cold reboot, service ordering and restored host routes.
   Boot guard is enabled but did not run during the current boot because its
   precondition was not present at boot time.
6. Run a full backup/restore in an isolated deployment; encrypted roundtrip
   tests do not prove production restore.

Remote operation checks previously blocked the real-client DNS cutover and
live multi-interface capture. Do not bypass those access restrictions.
All new central DNS components remain DISABLED on the QA gateway. Public
v1.0.2 release is unchanged.
