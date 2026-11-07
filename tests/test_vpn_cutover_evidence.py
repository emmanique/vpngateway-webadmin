import importlib.util
from pathlib import Path
import unittest
source=Path(__file__).resolve().parents[1]/'scripts'/'vpngw-vpn-cutover-evidence.py'
spec=importlib.util.spec_from_file_location('evidence',source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def good():
 return dict(policy='caio',interface='tun6eb314b8b6',observed_at=1000,public_ipv4='8.8.8.8',
  dns_through_vpn=True,direct_fallback_blocked=True,
  watchdog_armed=True,rollback_journal_durable=True,observation_source='verified_client_probe')
class ProofTests(unittest.TestCase):
 def test_valid_fixture(self):
  self.assertTrue(m.verify(good(),policy='caio',vpn_interface='tun6eb314b8b6',expected_public_ip='8.8.8.8',now=1005)['verified'])
 def test_wrong_identity(self):
  self.assertIn('policy_mismatch',m.verify(good(),policy='teste',vpn_interface='tun6eb314b8b6',expected_public_ip='8.8.8.8',now=1005)['errors'])
 def test_stale_proof(self):
  self.assertIn('stale_or_future_proof',m.verify(good(),policy='caio',vpn_interface='tun6eb314b8b6',expected_public_ip='8.8.8.8',now=1100)['errors'])
 def test_dns_missing(self):
  v=good();v['dns_through_vpn']=False
  self.assertFalse(m.verify(v,policy='caio',vpn_interface='tun6eb314b8b6',expected_public_ip='8.8.8.8',now=1005)['verified'])
 def test_private_egress_rejected(self):
  v=good();v['public_ipv4']='192.168.1.1'
  self.assertIn('non_public_egress',m.verify(v,policy='caio',vpn_interface='tun6eb314b8b6',expected_public_ip='8.8.8.8',now=1005)['errors'])
 def test_rollback_unarmed(self):
  v=good();v['watchdog_armed']=False
  self.assertFalse(m.verify(v,policy='caio',vpn_interface='tun6eb314b8b6',expected_public_ip='8.8.8.8',now=1005)['verified'])

 def test_untrusted_proof_source(self):
  v=good();v['observation_source']='local_gateway'
  self.assertIn('untrusted_observation_source',m.verify(v,policy='caio',vpn_interface='tun6eb314b8b6',expected_public_ip='8.8.8.8',now=1005)['errors'])
 def test_nan_timestamp_rejected(self):
  v=good();v['observed_at']=float('nan')
  self.assertIn('stale_or_future_proof',m.verify(v,policy='caio',vpn_interface='tun6eb314b8b6',expected_public_ip='8.8.8.8',now=1005)['errors'])
 def test_future_timestamp_rejected(self):
  v=good();v['observed_at']=1010
  self.assertIn('stale_or_future_proof',m.verify(v,policy='caio',vpn_interface='tun6eb314b8b6',expected_public_ip='8.8.8.8',now=1005)['errors'])

 def test_missing_trusted_vpn_egress_is_rejected(self):
  self.assertIn('missing_expected_vpn_egress',m.verify(good(),policy='caio',vpn_interface='tun6eb314b8b6',now=1005)['errors'])
 def test_wrong_public_egress_is_rejected(self):
  v=good();v['public_ipv4']='9.9.9.9'
  self.assertIn('egress_mismatch',m.verify(v,policy='caio',vpn_interface='tun6eb314b8b6',expected_public_ip='8.8.8.8',now=1005)['errors'])
