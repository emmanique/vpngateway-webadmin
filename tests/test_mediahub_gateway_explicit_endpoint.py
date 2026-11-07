"""Clean Gateway/MediaHub installations must not confuse router and VPN server."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1] / "apps/web/public/mediahub-sync/v1"
spec=importlib.util.spec_from_file_location("mediahub_observer_test",ROOT/"scripts/mediahub-gateway-port-sync.py")
observer=importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


class BootstrapContractTest(unittest.TestCase):
    def test_bootstrap_and_installer_keep_tls_and_independent_endpoint(self):
        script=(ROOT/"bootstrap.sh").read_text()
        self.assertIn('GW="${MEDIAHUB_PORT_SYNC_GATEWAY_IP:-}"',script)
        self.assertIn('WEB_PORT="${MEDIAHUB_PORT_SYNC_BOOTSTRAP_PORT:-443}"',script)
        self.assertIn('BASE="https://${GW}:${WEB_PORT}/mediahub-sync/v1"',script)
        self.assertIn('--cacert "$CA"',script)
        self.assertNotIn("--insecure",script)
        self.assertNotIn('--no-check-certificate',script)
        self.assertIn('ROUTE_BEFORE="$(route_identity)"',script)
        self.assertIn('export MEDIAHUB_PORT_SYNC_GATEWAY_IP="$GW"',script)
        installer=(ROOT/"installers/install-mediahub-gateway-port-sync-linux.sh").read_text()
        self.assertIn('def load_verified_observation(',installer)
        self.assertIn('"ENABLED":"0"',installer)
        self.assertIn('"SOURCE":"observation"',installer)
        self.assertIn('GATEWAY_IP',installer)

    def test_explicit_management_gateway_can_differ_from_default_router(self):
        with tempfile.TemporaryDirectory() as tmp:
            config={
                "MEDIAHUB_PORT_SYNC_ENABLE":"1",
                "MEDIAHUB_PORT_SYNC_POLICY_ID":"stremio",
                "MEDIAHUB_PORT_SYNC_HOST_MAC":"bc:24:11:53:5f:65",
                "MEDIAHUB_PORT_SYNC_GATEWAY_IP":"192.168.1.231",
                "MEDIAHUB_PORT_SYNC_CA_FILE":str(Path(tmp)/"ca.pem"),
                "MEDIAHUB_PORT_SYNC_TOKEN_FILE":str(Path(tmp)/"token"),
                "MEDIAHUB_PORT_SYNC_API_PORT":"9443"
            }
            snapshots={"selected_host":{"route":"vpn-protwg"},"runtime":{"updated_at":100.,"lease_expires_at":200.}}
            result=[]
            with patch.dict(os.environ,config), \
                patch.object(observer,"LOCK_PATH",Path(tmp)/"lock"), \
                patch.object(observer,"local_ip_addresses",return_value={"192.168.1.199"}), \
                patch.object(observer,"active_gateway",return_value=("192.168.1.1","ens18")) as router, \
                patch.object(observer,"query_gateway",return_value=snapshots) as api, \
                patch.object(observer,"select_port",return_value=40819), \
                patch.object(observer,"publish_observation",side_effect=lambda *a,**kw:result.append(kw)), \
                patch.object(observer.time,"time",return_value=130.):
                self.assertEqual(observer.main(),0)
            self.assertEqual(router.call_count,2)
            self.assertEqual(api.call_args.args[0],"https://192.168.1.231:9443/api/v1/port-forward/desired")
            self.assertEqual(result[0]["gateway"],"192.168.1.231")
            self.assertEqual(result[0]["host_ip"],"192.168.1.199")
            self.assertEqual(result[0]["expiry"],200.)

    def test_endpoint_rejects_unsafe_gateway_ip(self):
        for address in ("127.0.0.1","169.254.2.1","8.8.8.8"):
            with self.subTest(address=address):
                with self.assertRaises(observer.PortSyncError):
                    observer.gateway_endpoint(address,port=9443)
        self.assertEqual(observer.gateway_endpoint("192.168.1.231",port=9443),
                         "https://192.168.1.231:9443/api/v1/port-forward/desired")


if __name__=="__main__":
    unittest.main()
