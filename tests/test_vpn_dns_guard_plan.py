"""Current DNS forwarding plan defaults to un-applied, blocked state."""
import importlib.util
from pathlib import Path
import unittest
src=Path(__file__).resolve().parents[1]/'scripts'/'vpngw-vpn-host-dns-forward-plan.py'
spec=importlib.util.spec_from_file_location('dns_forward',src)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class GuardTests(unittest.TestCase):
 def test_fail_closed_plan(self):
  d=m.render('testhost','192.168.1.229','ens18','br-test','172.20.0.2','bc:25:11:5b:59:e1')
  self.assertFalse(d['ready'])
  self.assertFalse(d['applied'])
  self.assertTrue(d['blockers'])
  self.assertIn('th dport 53',d['nft'])
 def test_separate_policy_names(self):
  a=m.render('client-a','192.168.1.228','ens18','br-test','172.20.0.2','bc:25:11:5b:59:e1')
  b=m.render('client-b','192.168.1.229','ens18','br-test','172.20.0.2','bc:25:11:5b:59:e2')
  self.assertNotEqual(a['table'],b['table'])
 def test_bad_mac_rejected(self):
  with self.assertRaises(ValueError):m.render('client-a','192.168.1.228','ens18','br-test','172.20.0.2','invalid')
