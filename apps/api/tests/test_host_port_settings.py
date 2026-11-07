"""Regression coverage for exclusive host 6881 settings and SQLite persistence."""
import importlib
import os
import tempfile
import unittest
from fastapi import HTTPException


class HostPortSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.environ["VPNGW_DB_PATH"] = os.path.join(self.temp.name, "gateway.sqlite3")
        import main
        self.api = importlib.reload(main)
        self.api._require_policy_admin = lambda request: None
        self.api._policies.update({
            "host-a": {"id": "host-a", "host_ip": "192.168.1.199", "destination": "direct",
                       "registered_mac": "aa:bb:cc:dd:ee:01"},
            "host-b": {"id": "host-b", "host_ip": "192.168.1.229", "destination": "direct",
                       "registered_mac": "aa:bb:cc:dd:ee:02"},
        })
        for pid, item in self.api._policies.items():
            self.api._save("policies", pid, item)

    def tearDown(self):
        self.temp.cleanup()

    def settings(self, policy, selected, upnp=True):
        return self.api.update_host_port_settings(policy,
            self.api.HostPortSettings(upnp_enabled=upnp, port_forward_enabled=selected),
            None)

    def test_upnp_reports_vpn_and_blocked_ineligible(self):
        self.api._policies["host-a"].update({
            "destination": "proton", "upnp_enabled": True,
            "status": "active", "registered_mac": "aa:bb:cc:dd:ee:ff",
        })
        self.api._policies["host-b"].update({
            "destination": "blocked", "upnp_enabled": True, "status": "active",
        })
        result = self.api.upnp_capability()
        self.assertFalse(result["igd_running"])
        self.assertFalse(result["igd_ready"])
        self.assertEqual(result["unsupported"]["host-a"], "vpn_provider_mapping_required")
        self.assertEqual(result["unsupported"]["host-b"], "blocked_route")
        self.assertEqual(result["eligible_direct"], [])

    def test_upnp_eligibility_requires_kernel_confirmed_mac_guard(self):
        self.api._policies["host-a"].update({
            "destination": "direct", "upnp_enabled": True, "status": "active",
            "registered_mac": "aa:bb:cc:dd:ee:ff",
        })
        self.api._policy_agent_call = lambda action, pid, data: {
            "status": "active", "applied": True,
            "plan": {"destination": "direct", "host": "192.168.1.199"},
            "identity_guard_verified": False,
        }
        result = self.api.upnp_capability()
        self.assertEqual(result["unsupported"]["host-a"], "kernel_policy_not_confirmed")
        self.assertEqual(result["eligible_direct"], [])

    def test_selected_host_mac_cannot_be_replaced_without_deselect(self):
        self.settings("host-a", True)
        with self.assertRaises(HTTPException) as caught:
            self.api.register_host_identity(
                "host-a",
                self.api.HostIdentity(registered_mac="aa:bb:cc:dd:ee:03"),
                None)
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(self.api._policies["host-a"]["registered_mac"], "aa:bb:cc:dd:ee:01")

    def test_forwarding_requires_stable_registered_mac(self):
        self.api._policies["host-a"]["registered_mac"] = None
        self.api._save("policies", "host-a", self.api._policies["host-a"])
        with self.assertRaises(HTTPException) as caught:
            self.settings("host-a", True)
        self.assertEqual(caught.exception.status_code, 409)
        self.assertFalse(self.api._policies["host-a"].get("port_forward_enabled", False))

    def test_owner_identity_is_stable_policy_id_and_mac(self):
        result = self.settings("host-a", True)
        self.assertEqual(result["host_identity"]["policy_id"], "host-a")
        self.assertEqual(result["host_identity"]["registered_mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(result["host_identity"]["current_ip"], "192.168.1.199")

    def test_first_host_reserves_second_is_rejected(self):
        result = self.settings("host-a", True)
        self.assertFalse(result["applied"])
        with self.assertRaises(HTTPException) as error:
            self.settings("host-b", True)
        self.assertEqual(error.exception.status_code, 409)
        self.assertFalse(self.api._policies["host-b"].get("port_forward_enabled", False))

    def test_deselect_allows_transfer_and_removes_desired_mapping(self):
        self.settings("host-a", True)
        self.settings("host-a", False)
        self.assertIsNone(self.api.port_forward_desired()["forwarding"])
        self.settings("host-b", True)
        self.assertEqual(self.api.port_forward_desired()["forwarding"]["policy_id"], "host-b")

    def test_flags_survive_database_reload(self):
        self.settings("host-a", True, upnp=False)
        restored = importlib.reload(self.api)
        self.assertTrue(restored._policies["host-a"]["port_forward_enabled"])
        self.assertFalse(restored._policies["host-a"]["upnp_enabled"])
        self.assertFalse(restored.port_forward_desired()["rules_applied"])

    def test_expired_proton_port_is_never_reported_as_active(self):
        import time
        profile = self.api._policies["host-a"]
        profile.update({"destination": "vpn-proton", "port_forward_enabled": True})
        now = time.time()
        self.api._policy_agent_call = lambda action, pid, data: {
            "status": "nat_rules_verified", "applied": True,
            "owner": "host-a", "route": "vpn-proton",
            "updated_at": now - 47, "provider_lease": True,
            "lease_expires_at": now - 2,
            "external_ports": {"tcp": 36131, "udp": 36131},
        }
        result = self.api.port_forward_desired()
        self.assertFalse(result["rules_applied"])
        self.assertEqual(result["runtime"]["external_ports"], {})
        self.assertEqual(result["runtime"]["lease_state"], "expired_or_unverified")

    def test_unexpired_proton_port_must_match_policy_and_agent(self):
        import time
        profile = self.api._policies["host-a"]
        profile.update({"destination": "vpn-proton", "port_forward_enabled": True})
        now = time.time()
        self.api._policy_agent_call = lambda action, pid, data: {
            "status": "nat_rules_verified", "applied": True,
            "owner": "host-a", "route": "vpn-proton",
            "updated_at": now - 4, "provider_lease": True,
            "lease_expires_at": now + 45,
            "external_ports": {"tcp": 36131, "udp": 36131},
        }
        result = self.api.port_forward_desired()
        self.assertTrue(result["rules_applied"])
        self.assertEqual(result["runtime"]["external_ports"]["udp"], 36131)

    def test_incomplete_but_unexpired_provider_lease_is_not_attested(self):
        import time
        profile = self.api._policies["host-a"]
        profile.update({"destination": "vpn-proton", "port_forward_enabled": True})
        now = time.time()
        self.api._policy_agent_call = lambda action, pid, data: {
            "status": "nat_rules_verified", "applied": True,
            "owner": "host-a", "route": "vpn-proton",
            "updated_at": now - 4, "provider_lease": True,
            "lease_expires_at": now + 45,
            "external_ports": {"udp": 36131},
        }
        self.assertFalse(self.api.port_forward_desired()["rules_applied"])

    def test_direct_attestation_requires_6881_tcp_and_udp(self):
        import time
        profile = self.api._policies["host-a"]
        profile["port_forward_enabled"] = True
        now = time.time()
        self.api._policy_agent_call = lambda action, pid, data: {
            "status": "nat_rules_verified", "applied": True,
            "owner": "host-a", "route": "direct",
            "updated_at": now - 3, "provider_lease": False,
            "external_ports": {"tcp": 6881, "udp": 6881},
        }
        self.assertTrue(self.api.port_forward_desired()["rules_applied"])
        self.api._policy_agent_call = lambda action, pid, data: {
            "status": "nat_rules_verified", "applied": True,
            "owner": "host-a", "route": "direct",
            "updated_at": now - 3, "provider_lease": False,
            "external_ports": {"tcp": 6881},
        }
        self.assertFalse(self.api.port_forward_desired()["rules_applied"])

    def test_rebind_ip_prepare_sqlite_commit_and_kernel_confirmation(self):
        actions = []
        def agent(action, owner, payload):
            actions.append(action)
            if action == "host_rebind_prepare":
                self.assertEqual(payload["old_ip"], "192.168.1.199")
                return {"prepared": True, "pending_commit": True}
            if action == "host_rebind_commit":
                return {"committed": True, "host_ip": "192.168.1.205"}
            raise AssertionError(action)
        self.api._policy_agent_call = agent
        result = self.api.rebind_host_ip("host-a", "192.168.1.205", None)
        self.assertTrue(result["committed"])
        self.assertEqual(actions, ["host_rebind_prepare", "host_rebind_commit"])
        self.assertEqual(self.api._policies["host-a"]["host_ip"], "192.168.1.205")
        with self.api._connect() as db:
            import json
            actual = json.loads(db.execute(
                "SELECT payload FROM policies WHERE id='host-a'").fetchone()[0])
        self.assertEqual(actual["host_ip"], "192.168.1.205")

    def test_rebind_rejects_host_collision_without_kernel_mutation(self):
        self.api._policy_agent_call = lambda *args: self.fail("Kernel must not be changed")
        with self.assertRaises(HTTPException) as caught:
            self.api.rebind_host_ip("host-a", "192.168.1.229", None)
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(self.api._policies["host-a"]["host_ip"], "192.168.1.199")

    def test_rebind_failed_confirmation_never_claims_success(self):
        def agent(action, owner, payload):
            if action == "host_rebind_prepare":
                return {"prepared": True}
            if action == "host_rebind_commit":
                return {"committed": False}
            raise AssertionError(action)
        self.api._policy_agent_call = agent
        with self.assertRaises(HTTPException) as caught:
            self.api.rebind_host_ip("host-a", "192.168.1.205", None)
        self.assertEqual(caught.exception.status_code, 503)

    def test_verified_upstream_igd_is_not_misreported_as_local_igd_server(self):
        import time
        profile = self.api._policies["host-a"]
        profile.update({"destination":"direct","port_forward_enabled":True,
                        "upnp_enabled":True,"status":"active"})
        now = time.time()
        def agent(action, pid, data):
            if action == "port_status":
                return {"status":"nat_rules_verified","applied":True,
                        "owner":"host-a","route":"direct",
                        "updated_at":now, "provider_lease":False,
                        "external_ports":{"tcp":6881,"udp":6881},
                        "upnp":{"mapping_verified":True}}
            return {"status":"active","applied":True,
                    "plan":{"destination":"direct","host":"192.168.1.199"},
                    "identity_guard_verified":True}
        self.api._policy_agent_call=agent
        snapshot=self.api.port_forward_desired()
        self.assertTrue(snapshot["upnp_available"])
        capability=self.api.upnp_capability()
        self.assertTrue(capability["upstream_igd_mapping_verified"])
        self.assertFalse(capability["igd_running"])
        self.assertFalse(capability["igd_ready"])

    def test_verified_provider_ports_reconcile_desired_and_effective_status(self):
        import time
        self.api._policies["host-a"].update({
            "destination": "vpn-protwg", "port_forward_enabled": True,
            "upnp_enabled": True, "status": "active"})
        now = time.time()
        def agent(action, pid, data):
            self.assertEqual(action, "port_status")
            return {"status": "nat_rules_verified", "applied": True,
                    "owner": "host-a", "route": "vpn-protwg",
                    "updated_at": now, "lease_expires_at": now + 50,
                    "provider_lease": True, "external_ports":
                    {"tcp": 33702, "udp": 33702}}
        self.api._policy_agent_call = agent
        result = self.api.port_forward_desired()
        self.assertTrue(result["rules_applied"])
        self.assertEqual(result["status"], "nat_rules_verified")
        self.assertEqual(result["forwarding"]["mappings"], [
            {"protocol": "tcp", "internal_port": 33702, "external_port": 33702},
            {"protocol": "udp", "internal_port": 33702, "external_port": 33702}])
        self.assertFalse(result["external_reachability_verified"])

    def test_expired_provider_lease_never_exposes_mapping(self):
        import time
        self.api._policies["host-a"].update({
            "destination": "vpn-protwg", "port_forward_enabled": True})
        now = time.time()
        self.api._policy_agent_call = lambda *args: {
            "status": "nat_rules_verified", "applied": True,
            "owner": "host-a", "route": "vpn-protwg",
            "updated_at": now-120, "lease_expires_at": now-5,
            "provider_lease": True, "external_ports":
            {"tcp": 33702, "udp": 33702}}
        result = self.api.port_forward_desired()
        self.assertFalse(result["rules_applied"])
        self.assertIsNone(result["forwarding"])
        self.assertEqual(result["runtime"]["external_ports"], {})

    def test_no_dangling_selection_on_delete(self):
        self.settings("host-a", True)
        self.api._save("policies", "host-a")
        del self.api._policies["host-a"]
        self.assertIsNone(self.api.port_forward_desired()["forwarding"])

if __name__ == "__main__":
    unittest.main()
