import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "policy-dataplane-plan.py"
spec = importlib.util.spec_from_file_location("planner", SCRIPT)
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)

class TestDynamicHostPolicy(unittest.TestCase):
    def setUp(self):
        self.config = {"mode": "shared", "management_interface": "wifi42",
                       "interfaces": [{"interface": "wifi42", "role": "lan"}]}
        self.topology = {"interfaces": [{"interface": "wifi42", "operstate": "UP",
                         "network": "10.42.5.0/24", "address": "10.42.5.10/24"}],
                         "default_routes": [{"interface": "wifi42", "gateway": "10.42.5.1"}]}

    def test_dynamic_interface(self):
        result = planner.plan("10.42.5.50", "direct", self.config, self.topology)
        self.assertEqual(result["lan"], "wifi42")
        self.assertEqual(result["wan"], "wifi42")
        self.assertEqual(result["gateway"], "10.42.5.1")
        self.assertFalse(result["network_changed"])
        self.assertFalse(result["ready_for_live_application"])

    def test_protected_addresses(self):
        for host in ("10.42.5.1", "10.42.5.10"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                planner.plan(host, "direct", self.config, self.topology)

    def test_outside_lan(self):
        with self.assertRaises(ValueError):
            planner.plan("10.42.8.50", "direct", self.config, self.topology)

    def test_blocked(self):
        self.assertEqual(planner.plan("10.42.5.50", "blocked", self.config, self.topology)["destination"], "blocked")

    def test_interface_down(self):
        self.topology["interfaces"][0]["operstate"] = "DOWN"
        with self.assertRaises(ValueError):
            planner.plan("10.42.5.50", "direct", self.config, self.topology)

if __name__ == "__main__":
    unittest.main()
