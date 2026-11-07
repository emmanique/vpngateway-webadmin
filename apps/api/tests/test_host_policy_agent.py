import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[3] / "scripts" / "vpngw-policy-agent.py"
spec = importlib.util.spec_from_file_location("agent", SRC)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

class TestHostPolicyAgent(unittest.TestCase):
    def setUp(self):
        self.config = {"mode": "shared", "management_interface": "wifi17",
                       "interfaces": [{"interface": "wifi17", "role": "lan"}]}
        self.links = [
            {"ifname": "wifi17", "operstate": "UP",
             "addr_info": [{"family": "inet", "local": "10.17.0.221", "prefixlen": 24}]},
            {"ifname": "lo", "operstate": "UNKNOWN",
             "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
        ]
        self.routes = [{"dev": "wifi17", "gateway": "10.17.0.1"}]

    def test_dynamic_shared_direct(self):
        with patch.object(agent, "topology", return_value=(self.links, self.routes)):
            result = agent.validate("10.17.0.249", "direct", self.config)
        self.assertEqual(result["lan"], "wifi17")
        self.assertEqual(result["wan"], "wifi17")
        self.assertTrue(result["shared"])

    def test_blocked(self):
        with patch.object(agent, "topology", return_value=(self.links, self.routes)):
            self.assertEqual(agent.validate("10.17.0.249", "blocked", self.config)["destination"], "blocked")

    def test_protect_router_and_management(self):
        with patch.object(agent, "topology", return_value=(self.links, self.routes)):
            for host in ("10.17.0.1", "10.17.0.221"):
                with self.subTest(host=host), self.assertRaises(ValueError):
                    agent.validate(host, "direct", self.config)

    def test_reject_non_lan_or_vpn(self):
        with patch.object(agent, "topology", return_value=(self.links, self.routes)):
            with self.assertRaises(ValueError):
                agent.validate("10.8.0.249", "direct", self.config)
            with self.assertRaises(ValueError):
                agent.validate("10.17.0.249", "wg0", self.config)

    def test_separate_ethernet_wan_lan_detected_from_roles(self):
        network = {"mode": "routed", "management_interface": "enp2s0",
                   "interfaces": [{"interface": "enp2s0", "role": "lan"},
                                  {"interface": "enp1s0", "role": "wan"}]}
        links = [
            {"ifname": "enp2s0", "operstate": "UP",
             "addr_info": [{"family": "inet", "local": "10.55.8.1", "prefixlen": 24}]},
            {"ifname": "enp1s0", "operstate": "UP",
             "addr_info": [{"family": "inet", "local": "172.20.1.10", "prefixlen": 24}]},
        ]
        routes = [{"dev": "enp1s0", "gateway": "172.20.1.1"}]
        with patch.object(agent, "topology", return_value=(links, routes)):
            plan = agent.validate("10.55.8.88", "direct", network)
        self.assertEqual(plan["lan"], "enp2s0")
        self.assertEqual(plan["wan"], "enp1s0")
        self.assertEqual(plan["gateway"], "172.20.1.1")
        self.assertFalse(plan["shared"])

    def test_reverse_ethernet_roles_follow_configuration(self):
        network = {"mode": "routed", "management_interface": "eth0",
                   "interfaces": [{"interface": "eth0", "role": "lan"},
                                  {"interface": "eth1", "role": "wan"}]}
        links = [
            {"ifname": "eth0", "operstate": "UP",
             "addr_info": [{"family": "inet", "local": "10.9.1.1", "prefixlen": 24}]},
            {"ifname": "eth1", "operstate": "UP",
             "addr_info": [{"family": "inet", "local": "198.18.2.8", "prefixlen": 24}]},
        ]
        with patch.object(agent, "topology", return_value=(links, [{"dev":"eth1","gateway":"198.18.2.1"}])):
            plan = agent.validate("10.9.1.100", "direct", network)
        self.assertEqual((plan["lan"], plan["wan"]), ("eth0", "eth1"))

    def test_refuse_wan_outage_in_separated_topology(self):
        network = {"mode": "routed", "management_interface": "eth0",
                   "interfaces": [{"interface":"eth0","role":"lan"},{"interface":"eth1","role":"wan"}]}
        links = [
            {"ifname":"eth0","operstate":"UP",
             "addr_info":[{"family":"inet","local":"10.3.4.1","prefixlen":24}]},
            {"ifname":"eth1","operstate":"DOWN",
             "addr_info":[{"family":"inet","local":"172.19.1.4","prefixlen":24}]},
        ]
        with patch.object(agent, "topology", return_value=(links, [{"dev":"eth1","gateway":"172.19.1.1"}])):
            with self.assertRaisesRegex(ValueError, "desligada"):
                agent.validate("10.3.4.80", "direct", network)

    def test_vpn_transition_audit_never_applies_rules(self):
        simulated = {
            "host": "10.17.0.249", "profile": "profile-home",
            "interfaces": {"lan": "wifi17", "vpn": "wg123456789ab"},
            "routing": {"table_id": 23456, "priority": 1220}, "blockers": []
        }
        original = {"status": "active", "plan": {"destination": "direct"}}
        class Output:
            stdout = ""
        with patch.object(agent, "vpn_route_plan", return_value=simulated), patch.object(
                agent, "read_state", return_value=original), patch.object(
                agent, "run", return_value=Output()), patch.object(
                agent, "exists_chain", return_value=True), patch.object(
                agent, "inspect_rules", return_value=True), patch.object(
                agent, "install_rules") as install, patch.object(
                agent, "remove_rules") as remove, patch.object(
                agent.subprocess, "run", return_value=__import__("subprocess").CompletedProcess([], 2, "", "Error: ipv4: FIB table does not exist.")):
            result = agent.vpn_transition_audit({"id": "test-host", "profile_id": "profile-home"})
        self.assertFalse(result["ready"])
        self.assertFalse(result["applied"])
        self.assertTrue(next(c for c in result["checks"] if c["check"] == "active_direct_policy")["ok"])
        self.assertIn("dns_isolation", result["blockers"])
        install.assert_not_called()
        remove.assert_not_called()

    def test_vpn_transition_audit_reports_route_collisions(self):
        simulated = {"host": "10.17.0.249", "profile": "profile-home",
                     "interfaces": {"lan": "wifi17", "vpn": "wg123456789ab"},
                     "routing": {"table_id": 23456, "priority": 1220}, "blockers": []}
        class Output:
            def __init__(self, stdout):
                self.stdout = stdout
        with patch.object(agent, "vpn_route_plan", return_value=simulated), patch.object(
                agent, "read_state", return_value={"status": "active", "plan": {"destination": "direct"}}), patch.object(
                agent, "run", return_value=Output("1220: from all lookup 23456")), patch.object(
                agent.subprocess, "run", return_value=__import__("subprocess").CompletedProcess([], 0, "default dev wg123456789ab", "")), patch.object(
                agent, "exists_chain", return_value=True), patch.object(
                agent, "inspect_rules", return_value=True):
            result = agent.vpn_transition_audit({"id": "test-host", "profile_id": "profile-home"})
        self.assertIn("policy_priority_free", result["blockers"])
        self.assertIn("route_table_free", result["blockers"])

    def test_install_rules_separate_host_scope(self):
        calls = []
        plan = {"host":"10.17.0.249", "lan":"wifi17", "wan":"wifi17",
                "destination":"direct", "shared":True}
        with patch.object(agent, "exists_chain", return_value=False), patch.object(
                agent, "run", side_effect=lambda *args, **kwargs: calls.append(args)):
            agent.install_rules(plan, "client-abc")
        self.assertTrue(any("DOCKER-USER" in call and "saddr" in call for call in calls))
        self.assertTrue(any("DOCKER-USER" in call and "daddr" in call for call in calls))
        self.assertTrue(any("masquerade" in call and "10.17.0.249" in call for call in calls))
        self.assertFalse(any("flush" in call or "default" in call for call in calls))

    def test_pending_apply_and_automatic_rollback(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(agent, "BASE", Path(directory)), patch.object(
                agent, "exists_chain", return_value=True), patch.object(
                agent, "validate", return_value={"host":"10.17.0.249","lan":"wifi17",
                    "wan":"wifi17","gateway":"10.17.0.1","destination":"direct",
                    "shared":True}), patch.object(agent, "schedule_rollback") as timer, patch.object(
                agent, "install_rules") as install, patch.object(
                agent, "inspect_rules", return_value=True), patch.object(
                agent, "remove_rules") as cleanup, patch.object(
                agent, "cancel_rollback"):
                pending = agent.dispatch({"action":"apply","id":"host-one",
                    "host_ip":"10.17.0.249","destination":"direct","network":self.config})
                self.assertEqual(pending["status"], "pending")
                timer.assert_called_once()
                install.assert_called_once()
                self.assertEqual(agent.rollback("host-one")["status"], "reverted")
                cleanup.assert_called_once()

    def test_confirm_prevents_auto_rollback(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(agent, "BASE", Path(directory)), patch.object(
                agent, "exists_chain", return_value=True), patch.object(
                agent, "validate", return_value={"host":"10.17.0.249","lan":"wifi17",
                    "wan":"wifi17","destination":"direct","shared":True}), patch.object(
                agent, "schedule_rollback"), patch.object(agent, "install_rules"), patch.object(
                agent, "inspect_rules", return_value=True), patch.object(
                agent, "remove_rules") as cleanup, patch.object(agent, "cancel_rollback"):
                agent.dispatch({"action":"apply","id":"host-one","host_ip":"10.17.0.249",
                    "destination":"direct","network":self.config})
                self.assertEqual(agent.dispatch({"action":"confirm","id":"host-one"})["status"],"active")
                self.assertEqual(agent.rollback("host-one")["status"],"active")
                cleanup.assert_not_called()
                self.assertEqual(agent.dispatch({"action":"rollback","id":"host-one"})["status"],"reverted")
                cleanup.assert_called_once()

if __name__ == "__main__":
    unittest.main()
