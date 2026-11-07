import importlib.util
from pathlib import Path
import unittest
p=Path(__file__).resolve().parents[1]/'scripts'/'vpngw-vpn-dhcp-host-rebind.py'
s=importlib.util.spec_from_file_location('dhcp_rebind',p)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
BASE=dict(policy_id='living-room',profile_id='my-custom-vpn',configured_ip='192.168.40.101',
          configured_mac='aa:bb:cc:01:02:03',observed_mac='AA:BB:CC:01:02:03',
          observed_ip='192.168.40.117',ownership_confirmed=True,identity_authenticated=True)
class TestDhcpRebind(unittest.TestCase):
 def test_authorized_change_is_proposal_only(self):
  r=m.plan(**BASE)
  self.assertEqual(r['status'],'rebind_proposal')
  self.assertEqual(len(r['actions']),4)
  self.assertFalse(r['network_changes'])
  self.assertFalse(r['cutover_enabled'])
 def test_mac_change_refused(self):
  r=m.plan(**{**BASE,'observed_mac':'aa:bb:cc:01:02:04'})
  self.assertIn('mac_mismatch',r['blockers'])
  self.assertFalse(r['actions'])
 def test_unknown_lease_refused(self):
  self.assertEqual(m.plan(**{**BASE,'ownership_confirmed':False})['status'],'blocked')
 def test_auth_missing_refused(self):
  self.assertEqual(m.plan(**{**BASE,'identity_authenticated':False})['status'],'blocked')
 def test_conflicting_ip_refused(self):
  self.assertEqual(m.plan(**{**BASE,'ip_conflict':True})['status'],'blocked')
 def test_same_ip_no_rebind(self):
  self.assertEqual(m.plan(**{**BASE,'observed_ip':BASE['configured_ip']})['status'],'no_change')
 def test_no_ipv6(self):
  with self.assertRaises(ValueError):m.plan(**{**BASE,'observed_ip':'fd00::7'})
