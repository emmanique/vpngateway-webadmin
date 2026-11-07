import importlib.util
from pathlib import Path
import unittest
import time
s=importlib.util.spec_from_file_location('trial_commit',Path(__file__).resolve().parents[1]/'scripts'/'vpngw-vpn-trial-commit-check.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def assess(proof,transaction=None):
 return m.assess(policy='caio',vpn_interface='tun6eb314b8b6',
  expected_public_ip='8.8.8.8',proof=proof,transaction=transaction)
def good():
 return dict(policy='caio',interface='tun6eb314b8b6',observed_at=time.time(),
  public_ipv4='8.8.8.8',observation_source='verified_client_probe',
  dns_through_vpn=True,direct_fallback_blocked=True,
  watchdog_armed=True,rollback_journal_durable=True)
class CommitTests(unittest.TestCase):
 def test_missing_proof_fails_closed(self):
  result=assess(None,{})
  self.assertFalse(result['can_commit'])
  self.assertIn('missing_proof',result['blockers'])
 def test_wrong_vpn_public_ip_blocks(self):
  proof=good();proof['public_ipv4']='9.9.9.9'
  self.assertIn('egress_mismatch',assess(proof,{})['blockers'])
 def test_all_true_flags_never_bypass_authentication(self):
  proof=good()
  tx={key:True for key in ('verified_direct','snapshot_durable','watchdog_armed',
      'boot_guard_installed','fail_closed_installed','routes_verified',
      'filter_and_nat_switched','live_egress_and_dns_ipv4_verified')}
  result=assess(proof,tx)
  self.assertTrue(result['client_proof_valid'])
  self.assertTrue(result['transaction_checks_complete'])
  self.assertFalse(result['can_commit'])
  self.assertIn('authenticated_client_collector_unavailable',result['blockers'])
 def test_transaction_flags_required(self):
  result=assess(good(),{'verified_direct':True})
  self.assertIn('transaction_watchdog_armed',result['blockers'])
