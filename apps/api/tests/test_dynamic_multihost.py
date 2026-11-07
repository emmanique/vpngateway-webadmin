"""Host policies must never depend on fixed laboratory clients."""
import importlib
import os
import tempfile
import unittest
from unittest.mock import patch


class DynamicHostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.environ["VPNGW_DB_PATH"] = os.path.join(self.temp.name, "gateway.sqlite3")
        import main
        self.api = importlib.reload(main)

    def tearDown(self):
        self.temp.cleanup()

    def test_gateway_live_reflects_arbitrary_policies(self):
        policies = [
            {"id": "client-one", "host_ip": "10.77.0.10", "destination": "vpn-alpha", "failure_mode": "block"},
            {"id": "client-two", "host_ip": "10.77.0.11", "destination": "direct", "failure_mode": "block"},
        ]
        with patch.object(self.api, "list_policies", return_value=policies), patch.object(
            self.api, "wireguard_profiles_status", return_value={"profiles": []}
        ):
            live = self.api.gateway_live()
        self.assertEqual(set(live["clients"]), {"10.77.0.10", "10.77.0.11"})
        self.assertTrue(live["kill_switch"]["loaded"])
        self.assertTrue(live["vpn_client_ready"])
        self.assertNotIn("192.168.1.249", live["clients"])

    def test_empty_install_has_no_client_bindings(self):
        with patch.object(self.api, "list_policies", return_value=[]), patch.object(
            self.api, "wireguard_profiles_status", return_value={"profiles": []}
        ):
            self.assertEqual(self.api.gateway_live()["clients"], {})
            self.assertFalse(self.api.capabilities()["routing_active"])


if __name__ == "__main__":
    unittest.main()
