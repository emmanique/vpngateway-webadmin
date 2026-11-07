import importlib
import os
import tempfile
import unittest
from fastapi import HTTPException

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.environ["VPNGW_DB_PATH"] = os.path.join(self.temp.name, "test.sqlite3")
        import main
        self.api = importlib.reload(main)
        # Policy creation is a privileged operation; keep unit tests offline.
        self.api._require_policy_admin = lambda request: None
        self.api._vpn_host_automation_ready = lambda profile: True
        self.api._policy_agent_call = lambda action, policy, data=None: (
            {"status": "active"} if action == "confirm" else {"ok": True})
        real_create_policy = self.api.create_policy
        self.api.create_policy = lambda data: real_create_policy(data, None)
        self.api.network_topology = lambda: {"interfaces": [], "default_routes": []}

    def tearDown(self):
        self.temp.cleanup()

    def test_overview_reflects_saved_policy_runtime(self):
        from unittest.mock import patch
        for active in (True, False):
            with self.subTest(active=active), patch.object(self.api, "list_policies",
                 return_value=[{"host_ip":"10.77.0.10","destination":"direct","status":"active"}] if active else []):
                self.assertEqual(self.api.overview()["routing_active"], active)
                self.assertEqual(self.api.capabilities()["routing_active"], active)
                self.assertFalse(self.api.overview()["vpn_routing_active"])

    def test_direct_draft_and_preview(self):
        payload = {"id": "host-one", "host_ip": "192.168.1.91",
                   "destination": "direct", "failure_mode": "block"}
        self.assertEqual(self.api.create_policy(self.api.Policy(**payload))["id"], "host-one")
        preview = self.api.routing_preview()
        self.assertTrue(preview["rules"][0]["applied"])
        self.assertEqual(preview["rules"][0]["effective_action"], "direct")

    def test_reject_duplicate_ip(self):
        self.api.create_policy(self.api.Policy(id="host-one", host_ip="192.168.1.91"))
        with self.assertRaises(HTTPException) as raised:
            self.api.create_policy(self.api.Policy(id="host-two", host_ip="192.168.1.91"))
        self.assertEqual(raised.exception.status_code, 409)

    def test_vpn_fallback_blocked(self):
        self.api.create_connection(self.api.Connection(
            id="vpn-one", name="VPN One", provider="test", protocol="wireguard"))
        with self.assertRaises(HTTPException) as raised:
            self.api.create_policy(self.api.Policy(
                id="host-one", host_ip="192.168.1.91",
                destination="vpn-one", failure_mode="direct"))
        self.assertEqual(raised.exception.status_code, 422)

if __name__ == "__main__":
    unittest.main()
