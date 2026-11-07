"""Current read-only WireGuard readiness must remain generic and fail closed."""
from pathlib import Path
import ast
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'apps' / 'api' / 'main.py'

class ReadinessAPIContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SOURCE.read_text()
        tree = ast.parse(source)
        cls.method = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'wireguard_routing_readiness')
        cls.text = ast.get_source_segment(source, cls.method)

    def test_read_only_get(self):
        decorators = [ast.unparse(d) for d in self.method.decorator_list]
        self.assertTrue(any('app.get' in d and 'routing-readiness' in d for d in decorators))
        self.assertIn('"network_changes": False', self.text)

    def test_no_hardcoded_lab_host_or_provider(self):
        for value in ('192.168.1.226', '192.168.1.227', 'vpn-proton-openvpn', 'vpn-cyberghost-openvpn'):
            self.assertNotIn(value, self.text)

    def test_kill_switch_and_dns_are_not_assumed(self):
        self.assertIn('"killswitch_verified": False', self.text)
        self.assertIn('"dns_vpn_isolated": False', self.text)
        self.assertIn('"exclusive_routing_installed": False', self.text)

    def test_readiness_never_changes_kernel_routes(self):
        self.assertIn('"ready": False', self.text)
        self.assertNotIn('_policy_agent_call("vpn_transition"', self.text)
        self.assertNotIn('vpn_trial_apply', self.text)
