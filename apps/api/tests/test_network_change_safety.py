"""Network apply gate must fail closed on the existing PVE topology."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[3] / 'scripts' / 'network-change-safety.py'
spec = importlib.util.spec_from_file_location('network_change_safety', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NetworkChangeSafetyTests(unittest.TestCase):
    def setUp(self):
        self.interfaces = [{'interface': 'eth0', 'address': '192.168.1.201', 'operstate': 'UP'}]
        self.routes = [{'interface': 'eth1', 'gateway': '192.168.200.1'}]

    def test_even_single_default_requires_rollback_and_external_probe(self):
        report = module.evaluate(self.interfaces, self.routes, {})
        self.assertFalse(report['apply_permitted'])
        self.assertIn('rollback_timer_not_armed', report['blocking_reasons'])
        self.assertIn('external_management_probe_not_verified', report['blocking_reasons'])

    def test_multiple_default_routes_block(self):
        routes = self.routes + [{'interface': 'eth0', 'gateway': '192.168.1.1'}]
        report = module.evaluate(self.interfaces, routes, {})
        self.assertIn('multiple_or_missing_default_routes', report['blocking_reasons'])

    def test_proxmox_owned_files_block(self):
        report = module.evaluate(self.interfaces, self.routes,
                                 {'/etc/systemd/network/eth0.network': 'Interface eth0 autoconfigured by PVE'})
        self.assertIn('proxmox_managed_network_files', report['blocking_reasons'])

    def test_management_down_blocks(self):
        report = module.evaluate([{'interface': 'eth0', 'address': '192.168.1.201',
                                   'operstate': 'DOWN'}], self.routes, {})
        self.assertIn('management_interface_not_up', report['blocking_reasons'])


if __name__ == '__main__':
    unittest.main()
