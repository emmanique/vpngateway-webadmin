"""Read-only DNS route plan must install terminal unreachable before VPN."""
import importlib.util
from pathlib import Path
import unittest
src=Path(__file__).resolve().parents[1]/'scripts'/'vpngw-vpn-host-dns-route-plan.py'
spec=importlib.util.spec_from_file_location('dns_route',src)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
class DNSRouteTests(unittest.TestCase):
 def plan(self):
  return mod.render('192.168.1.229','172.20.0.2','br-test','wg-test',25449,15449,'ens18','172.20.0.2 dev br-test')
 def test_unreachable_installed_first(self):
  d=self.plan()
  self.assertEqual(d['commands'][0][4],'unreachable')
  self.assertFalse(d['applied'])
  self.assertIn('host kill switch active',d['required_before_execution'])
 def test_route_scoped_to_host(self):
  d=self.plan()
  self.assertEqual(d['commands'][-1][-3:],['ens18','lookup','25449'])
 def test_wrong_bridge_refused(self):
  with self.assertRaises(ValueError):mod.render('192.168.1.229','172.20.0.2','br-test','wg-test',25449,15449,'ens18','172.20.0.2 dev other')
