# MediaHub port observer — independent VPN Gateway endpoint

The MediaHub host may use an ordinary LAN router (e.g. 192.168.1.1)
and access a separate VPN Gateway (e.g. 192.168.1.231). They **must not**
be treated as the same device.

## Before the first bootstrap

The Gateway publishes five public versioned bundle resources at
`https://GATEWAY_LAN_IP/mediahub-sync/v1/` on its management HTTPS port
(default TCP 443). The separate read-only authenticated NAT forwarding status
service listens on TCP 9443 **only after the Gateway administrator explicitly
installs and configures it**.

At the MediaHub host, obtain the Gateway's **public TLS server certificate**
on a trusted channel. If downloaded initially without a trusted CA, verify its
SHA-256 fingerprint out-of-band against the Gateway console before trusting it.
Never copy the private TLS key or disable TLS verification in the observer.

For a self-signed management certificate, an administrator can extract the
public certificate and verify the fingerprint:

```bash
install -d -m 0700 /etc/mediahub
openssl s_client -connect 192.168.1.231:443 -servername 192.168.1.231 \
  -showcerts </dev/null 2>/dev/null |
  openssl x509 -out /tmp/vpngw-lan-public.crt
openssl x509 -in /tmp/vpngw-lan-public.crt -noout -fingerprint -sha256 -ext subjectAltName
# Compare the fingerprint independently against the Gateway operator's value.
install -m 0644 /tmp/vpngw-lan-public.crt /etc/mediahub/gateway-ca.pem
rm -f /tmp/vpngw-lan-public.crt
```

If the management TLS certificate is issued by an internal CA, install the
trusted CA certificate instead and verify the server's IP SAN.

## Bootstrap from MediaHub (verify, then install)

```bash
curl -fsS --cacert /etc/mediahub/gateway-ca.pem \
  https://192.168.1.231/mediahub-sync/v1/bootstrap.sh -o /tmp/mediahub-bootstrap.sh
bash -n /tmp/mediahub-bootstrap.sh
MEDIAHUB_PORT_SYNC_GATEWAY_IP=192.168.1.231 \
  MEDIAHUB_PORT_SYNC_CA_FILE=/etc/mediahub/gateway-ca.pem \
  bash /tmp/mediahub-bootstrap.sh --verify-only
MEDIAHUB_PORT_SYNC_GATEWAY_IP=192.168.1.231 \
  MEDIAHUB_PORT_SYNC_POLICY_ID=stremioserver \
  MEDIAHUB_PORT_SYNC_CA_FILE=/etc/mediahub/gateway-ca.pem \
  bash /tmp/mediahub-bootstrap.sh --install
```

Replace `stremioserver` with the policy ID actually assigned to this host
in the Gateway's Hosts and Routes screen. The installer writes the same
policy ID into both observer and reconciler configuration files.

The bootstrap uses port 443 for bundle delivery by default, enforces TLS
validation and SHA-256 manifest verification, and records the configured
Gateway IP in the observation configuration. It checks that the host route
to the chosen VPN Gateway remains stable throughout the download, without
requiring that the default-router IP equal the VPN Gateway IP.

The observer timer is **not enabled**. The installer sets the Stremio
reconciler integration to `SOURCE=observation` with `ENABLED=0`. It does not
copy secrets from the Gateway or modify the Stremio Docker container.

## Dedicated status service, separate from the public bootstrap

On the Gateway, `installers/install-port-status-linux.sh` installs the
read-only `vpngw-port-status.service` bound to the configured LAN interface
and IP on TCP 9443, with a dedicated bearer token and a TLS certificate
matching the Gateway LAN IP. It must be explicitly configured and enabled.
The default router's LAN address is not used as the observer API endpoint.

After verifying the status service with an unauthenticated HTTP 401, securely
provision a dedicated read-only status token to MediaHub as
`/etc/mediahub/gateway-port-sync.token` (owner root, mode 0600).
Verify an authenticated status request using the trusted CA before enabling
`mediahub-gateway-port-sync.timer`.

The observer is read-only and writes only the root-owned, mode 0600
`/var/lib/stremio-webadmin/gateway-port-observation.json`. The Stremio
reconciler separately owns .env updates, container recreation, health checks,
and rollback. Do not infer public TCP/UDP reachability from NAT rules alone.

## Open acceptance gate

A real Gateway port change, observer update, container recreation, rollback
injection and reboot persistence must be validated on the QA hosts. Installing
these files does not establish that acceptance.
