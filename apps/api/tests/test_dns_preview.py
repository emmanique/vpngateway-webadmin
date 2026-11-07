import importlib
import os
import tempfile
import unittest

class DnsPreviewTests(unittest.TestCase):
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

    def test_empty_preview_is_not_applied(self):
        result = self.api.dns_policy_preview()
        self.assertFalse(result["installed"])
        self.assertFalse(result["applied"])
        self.assertFalse(result["wan_dns_allowed"])
        self.assertEqual(result["clients"], [])

    def test_direct_client_inherits_direct_egress(self):
        self.api.create_policy(self.api.Policy(id="client-a", host_ip="10.10.0.12"))
        client = self.api.dns_policy_preview()["clients"][0]
        self.assertEqual(client["egress"], "direct")
        self.assertEqual(client["enforcement"], "not_implemented")
        self.assertFalse(client["dns_leak_protection_required"])

    def test_vpn_client_requires_isolated_dns(self):
        self.api.create_connection(self.api.Connection(id="vpn-a", name="VPN Alpha", provider="test", protocol="wireguard"))
        self.api.create_policy(self.api.Policy(id="client-b", host_ip="10.10.0.13", destination="vpn-a"))
        client = self.api.dns_policy_preview()["clients"][0]
        self.assertEqual(client["connection_id"], "vpn-a")
        self.assertTrue(client["dns_leak_protection_required"])
        self.assertEqual(client["failure_mode"], "block")

    def test_isolation_groups_direct_and_vpn(self):
        self.api.create_connection(self.api.Connection(id="vpn-a", name="VPN Alpha", provider="test", protocol="wireguard"))
        self.api.create_policy(self.api.Policy(id="client-a", host_ip="10.10.0.12"))
        self.api.create_policy(self.api.Policy(id="client-b", host_ip="10.10.0.13", destination="vpn-a"))
        result = self.api.dns_isolation_plan()
        self.assertFalse(result["safe_to_apply"])
        self.assertFalse(result["wan_listener_allowed"])
        groups = {g["id"]: g for g in result["groups"]}
        self.assertEqual(groups["direct"]["clients"], ["10.10.0.12"])
        self.assertEqual(groups["vpn:vpn-a"]["clients"], ["10.10.0.13"])
        self.assertTrue(groups["vpn:vpn-a"]["deny_non_vpn_dns"])
        self.assertFalse(groups["direct"]["deny_non_vpn_dns"])

    def test_dns_draft_is_persistent_and_not_applied(self):
        data = self.api.DnsModuleDraft(enabled=True, upstream_ipv4=["1.1.1.1", "9.9.9.9"])
        saved = self.api.save_dns_config(data)
        self.assertFalse(saved["applied"])
        self.assertEqual(self.api.get_dns_config()["draft"]["upstream_ipv4"], ["1.1.1.1", "9.9.9.9"])

    def test_dns_draft_rejects_unsafe_options(self):
        from fastapi import HTTPException
        for data in [
            self.api.DnsModuleDraft(lan_only=False),
            self.api.DnsModuleDraft(block_on_vpn_failure=False),
            self.api.DnsModuleDraft(enabled=True),
            self.api.DnsModuleDraft(upstream_ipv4=["192.168.1.1"]),
            self.api.DnsModuleDraft(upstream_ipv4=["1.1.1.1", "1.1.1.1"]),
        ]:
            with self.subTest(data=data), self.assertRaises(HTTPException):
                self.api.save_dns_config(data)

    def test_admin_link_is_not_guessed(self):
        from unittest.mock import patch
        with patch.object(self.api.shutil, "which", return_value=None), patch.object(self.api.subprocess, "run") as run:
            run.return_value.returncode = 3
            run.return_value.stdout = "inactive\n"
            status = self.api.dns_admin_status()
        self.assertFalse(status["admin_available"])
        self.assertIsNone(status["admin_url"])

    def test_bindings_follow_management_interface(self):
        from unittest.mock import patch
        topology = {"interfaces": [{"interface":"eth0","kind":"ethernet","operstate":"UP","address":"10.42.5.10"}, {"interface":"eth1","kind":"ethernet","operstate":"UP","address":"172.16.5.10"}]}
        with patch.object(self.api,"network_topology",return_value=topology), patch.object(self.api,"get_network_config",return_value={"draft":{"management_interface":"eth1"}}):
            result=self.api.dns_bindings()
        self.assertEqual(result["management_ipv4"],"172.16.5.10")
        self.assertEqual(result["pihole_admin_url"],"http://172.16.5.10:8081")
        self.assertEqual(result["dns_port"],53)
        self.assertFalse(result["applied"])

if __name__ == "__main__":
    unittest.main()
