# Gateway VPN Multi 1.0.2 — MAC identity regression

Date: 2026-10-12. Extends the QA evidence in QA-1.0.1.md.

A changed MAC previously updated the basic identity guard while leaving the VPN guard with the previous MAC. The correction replaces the VPN guard before the basic guard and persists the authorized identity for boot recovery. A partial failure restores the previous guards and state.

Validation: 176 regression tests passed. On QA host 192.168.1.230, real MAC changes were tested on client .229 (CyberGhost/OpenVPN) and .228 (Proton/WireGuard). Unauthorized identities produced HTTPS 000. Authorizing each observed MAC through the application API returned HTTP 200, updated both kernel guards and the persistent boot record, and restored HTTPS 200. Original identities were restored and verified with HTTPS 200.

The QA harness refreshed ARP and the passive discovery snapshot after each MAC change. DNS/DoH/DoT scope and provider-outage limitations remain as documented in QA-1.0.1.md. Physical Proxmox link speed was not verified by this test.
