import importlib.util
from pathlib import Path
import unittest
p=Path(__file__).resolve().parents[1]/'scripts/vpngw-vpn-dhcp-inventory.py'
spec=importlib.util.spec_from_file_location('inventory',p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
P=[{'id':'office','host_ip':'10.3.4.10','registered_mac':'aa:bb:cc:dd:ee:ff','destination':'vpn-office'}]
def obs(ip,mac='aa:bb:cc:dd:ee:ff'):
 return {'ip':ip,'mac':mac,'state':['REACHABLE']}
class InventoryTests(unittest.TestCase):
 def test_changed_ip_is_unauthenticated(self):
  r=m.inspect(P,[obs('10.3.4.42')])[0]
  self.assertEqual(r['status'],'dhcp_change_observed')
  self.assertFalse(r['cutover_enabled'])
  self.assertFalse(r['ownership_confirmed'])
 def test_no_registered_mac(self):
  self.assertEqual(m.inspect([{'id':'desk','host_ip':'10.3.4.10'}],[obs('10.3.4.42')])[0]['status'],'identity_not_registered')
 def test_ambiguous_multiple_ips(self):
  self.assertEqual(m.inspect(P,[obs('10.3.4.10'),obs('10.3.4.42')])[0]['status'],'ambiguous')
 def test_unseen(self):
  self.assertEqual(m.inspect(P,[])[0]['status'],'not_observed')
 def test_other_mac_does_not_inherit(self):
  self.assertEqual(m.inspect(P,[obs('10.3.4.42','aa:bb:cc:dd:ee:11')])[0]['candidate_ipv4'],[])
