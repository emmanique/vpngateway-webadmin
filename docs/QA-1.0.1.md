# Gateway VPN Multi 1.0.1 — QA closure

Date: 2026-10-12. QA host: 192.168.1.230 (Ubuntu 22.04). Managed test clients: .228 and .229.
Runtime tests used the corrected 1.0.0 candidate; 1.0.1 consolidates those fixes with aligned version metadata and the unversioned Compose entry point.

## Evidence
- Clean installation completed with exit code 0 after correcting npm ETIMEDOUT handling; WebAdmin/Pi-hole HTTP 200 and Pi-hole passwordless LAN access.
- WireGuard/Proton and OpenVPN/CyberGhost verified from both clients with public IP, HTTPS and UDP/TCP DNS.
- 75-second VPN-provider transport interruption: both clients lost HTTPS access (HTTP 000); both recovered without agent restart or profile reimport.
- 32 directed transitions across DIRECT, BLOCKED and both VPNs: runtime state, firewall, MAC guard and persistent boot records verified.
- Removal of a VPN with assigned hosts rejected; registration of an unobserved MAC rejected.
- Controlled host deletion removed runtime state and persistent boot guards.
- WireGuard profile deletion removed its logical profile; factory defaults removed OpenVPN material.
- Reset/restore while active rejected; incorrect backup password rejected.
- Authenticated encrypted backup restored both profiles and policies; legacyLAN1 remapped to ens18. Restored policies remained drafts until explicit fail-closed activation.
- Both VPNs and per-host protections recovered after reboot.
- Targeted captures verified client DNS/DoT/DoH traffic in the VPN interfaces; matching test requests were absent from physical direct egress. Two physical DNS queries belonged to gateway public-IP checks.

## DNS decision and boundaries
Keep DoH/DoT available inside the assigned VPN. They bypass Pi-hole filtering. Gateway control-plane DNS uses the system resolver. This is a targeted IPv4 test, not exhaustive proof for every DNS endpoint, browser or bypass attempt. IPv6 forwarding is unsupported and blocked for managed VPN clients.

## Corrections consolidated
Python/npm download retries and timeouts; included Nginx configuration; LAN HTTPS port 8443; passwordless Pi-hole; missing VPN transition guard; OpenVPN file write permissions/lifecycle cleanup; DIRECT host deletion; confirmed early-boot guards; actual profile-volume discovery for reboot recovery.

## Residual boundaries
The provider-outage test preserved LAN management and did not unplug the shared physical WAN/LAN interface. OpenVPN process-crash restart is outside this test. No IPv6 routing support. Backup secrets and provider credentials are excluded from this report and production source.

## Publication policy
main/develop aligned in DEV. Public distribution contains runtime files, README/screenshots and deployment packages, with no GitHub Actions or development QA documentation.
