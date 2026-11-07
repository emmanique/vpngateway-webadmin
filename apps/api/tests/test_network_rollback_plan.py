"""Guarded network-change planning regression tests."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[3] / 'scripts' / 'network-rollback-plan.py'
spec = importlib.util.spec_from_file_location('network_rollback_plan', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NetworkRollbackPlanTests(unittest.TestCase):
    def test_valid_management_config_still_does_not_apply(self):
        result = module.plan('eth0', '192.168.1.201/24', '192.168.1.1', '192.168.1.201')
        self.assertEqual(result['validation_errors'], [])
        self.assertFalse(result['apply_permitted'])
        self.assertIn('external', ' '.join(result['rollback_requirements']))

    def test_management_ip_change_is_blocked(self):
        result = module.plan('eth0', '192.168.1.202/24', '192.168.1.1', '192.168.1.201')
        self.assertIn('management_ip_change_requires_external_recovery', result['validation_errors'])

    def test_gateway_outside_subnet_is_blocked(self):
        result = module.plan('eth1', '192.168.200.254/24', '10.0.0.1', '192.168.1.201')
        self.assertIn('gateway_outside_subnet', result['validation_errors'])

    def test_ipv6_not_accepted(self):
        result = module.plan('eth1', '2001:db8::1/64', '2001:db8::2', '192.168.1.201')
        self.assertIn('ipv4_only', result['validation_errors'])

    def test_invalid_interface_not_accepted(self):
        result = module.plan('../eth0', '192.168.1.201/24', '192.168.1.1', '192.168.1.201')
        self.assertIn('invalid_interface', result['validation_errors'])


if __name__ == '__main__':
    unittest.main()
