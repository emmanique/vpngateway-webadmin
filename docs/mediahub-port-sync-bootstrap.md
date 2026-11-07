# MediaHub BT port — Gateway observation / Stremio reconciliation

## Architecture

Gateway (LAN-only HTTPS 9443, bearer token, certificate with gateway IP SAN)
→ bootstrap-installed root-owned observer timer on MediaHub
→ `/var/lib/stremio-webadmin/gateway-port-observation.json` (0600)
→ existing `stremio-webadmin-reconcile.timer`
→ existing `scripts/gateway-port-sync.py`
→ `STREMIOSRV_BT_LISTEN_PORT` in Stremio's actual Compose `.env`
→ `sh start.sh up -d --no-deps --force-recreate stremio-libtorrent-server` **only when the port changes**.

The observer is read-only with respect to Docker and the Compose environment. The Stremio
reconciler is the only writer to the environment and the only container recreator.
It retains the existing GPU/VAAPI verification, health checks and rollback.

## Installation

1. Ensure the target Stremio release implements `consume_observation()` in
   `scripts/gateway-port-sync.py` (required compatibility gate).
2. Install the verified Gateway TLS certificate into
   `/etc/mediahub/gateway-ca.pem` after independently verifying its fingerprint.
3. Execute from the **MediaHub Linux host**, as root:
   `curl -fsS --cacert /etc/mediahub/gateway-ca.pem https://<current-gateway>/mediahub-sync/v1/bootstrap.sh | bash -s -- --install`.
   The bootstrap uses the kernel-observed gateway for the verified bundle downloads.
4. Bootstrap discovers the Compose directory from the running Stremio container's
   `com.docker.compose.project.working_dir` label. It configures
   `/etc/stremio-webadmin/port-sync.conf` with `SOURCE=observation`
   and identifies the MediaHub NIC by its live MAC.
5. Provision the **dedicated status-only bearer token** from
   `/etc/vpngw-port-status/token` on the Gateway to
   `/etc/mediahub/gateway-port-sync.token` on MediaHub through an approved
   secure administrative channel. Never publish the token via bootstrap/HTTPS assets,
   Git, logs or application UI. Keep it root-owned and mode 0600.
6. Set `MEDIAHUB_PORT_SYNC_ENABLE=1` in `/etc/mediahub/port-sync.conf`,
   run `systemctl start mediahub-gateway-port-sync.service`, inspect the observation
   and logs, then `systemctl enable --now mediahub-gateway-port-sync.timer`.
   Leave `stremio-webadmin-reconcile.timer` enabled.

## Safeguards

- The Gateway provides the authenticated selected host (policy ID, MAC, current IP,
  route), verified NAT TCP and UDP port, and time-limited provider lease.
- The observer validates the current MediaHub NIC, gateway, host policy, fresh lease,
  and matching TCP/UDP port. No port is published on mismatch; it publishes null
  to invalidate the prior observation.
- The reconciler consumes only root-owned, 0600, regular observations younger than
  35 seconds, for the expected policy, MAC, current IP and gateway. It refuses an
  expired or short-lived lease.
- A missing or invalid observation results in **no configuration change**.
- The synchronizer never recreates Stremio on a simple lease renewal of the same port.
- Container recreation is delegated to Stremio's GPU-aware `start.sh`, and
  must pass Docker port binding and health checks; otherwise revert the `.env`
  and recreate the previous configuration.
- Do not enable a second port-writing systemd service. The Gateway-installed timer
  may only observe and publish port state.

## QA state (2026-11-07)

Gateway 192.168.1.231 selected host `stremio` 192.168.1.199, VPN `vpn-protwg`,
verified forwarding TCP/UDP 40819. Stremio Compose root
`/opt/stremio-server-webadmin`, `STREMIOSRV_BT_LISTEN_PORT=40819`, Docker healthy.

The bootstrap was executed with `--install` on 192.168.1.199. TLS trust was
verified and provisioned. The observer timer remains disabled because the dedicated
status token has not yet been securely provisioned. No automatic change was made
to `.env` or the running container.
