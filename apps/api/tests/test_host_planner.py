import importlib.util
import pathlib
import unittest
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).resolve().parents[3] / "scripts" / "multi-host-plan.py"
spec = importlib.util.spec_from_file_location("multi_host_plan", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class HostPlannerTests(unittest.TestCase):
    """Planner unit tests must not depend on the gateway's live routes."""
    def setUp(self):
        self.topology = {
            "interfaces": [{"interface": "eth0", "address": "192.168.1.201",
                            "network": "192.168.1.0/24", "default_route": True}],
            "default_routes": [{"interface": "eth0", "gateway": "192.168.1.1"}],
        }
        self.patcher = patch.object(module.topology_module, 'selected_network',
                                    return_value=(self.topology['interfaces'][0], self.topology))
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_explicit_interface_forwarded_to_topology(self):
        module.plan(['192.168.1.92'], interface='eth0')
        module.topology_module.selected_network.assert_called_with('eth0')

    def test_explicit_interface_rejects_invalid_choice(self):
        self.patcher.stop()
        with patch.object(module.topology_module, 'detect', return_value=self.topology):
            with self.assertRaisesRegex(ValueError, 'invalid_lan_interface'):
                module.plan(['192.168.1.92'], interface='eth99')
        self.patcher.start()

    def test_accepts_new_lan_host_without_changes(self):
        interface, topology = module.topology_module.selected_network()
        import ipaddress
        network = ipaddress.ip_network(interface["network"])
        candidate = str(next(ip for ip in network.hosts() if str(ip) not in {interface["address"]} | {r["gateway"] for r in topology["default_routes"] if r.get("gateway")}))
        output = module.plan([candidate])
        self.assertTrue(output["hosts"][0]["eligible"])
        self.assertFalse(output["changes_applied"])

    def test_rejects_reserved_and_duplicate(self):
        interface, topology = module.topology_module.selected_network()
        import ipaddress
        network = ipaddress.ip_network(interface["network"])
        candidate = str(next(ip for ip in network.hosts() if str(ip) not in
                             {interface["address"]} | {r["gateway"] for r in topology["default_routes"] if r.get("gateway")}))
        hosts = module.plan([interface["address"], candidate, candidate])["hosts"]
        self.assertFalse(hosts[0]["eligible"])
        self.assertTrue(hosts[1]["eligible"])
        self.assertEqual(hosts[2]["reason"], "duplicate_host")

    def test_rejects_outside_network(self):
        interface, topology = module.topology_module.selected_network()
        import ipaddress
        network = ipaddress.ip_network(interface["network"])
        outside = "203.0.113.2" if ipaddress.ip_address("203.0.113.2") not in network else "198.51.100.2"
        self.assertFalse(module.plan([outside])["hosts"][0]["eligible"])

if __name__ == "__main__":
    unittest.main()
