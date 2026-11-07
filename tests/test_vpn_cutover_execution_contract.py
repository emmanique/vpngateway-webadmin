import importlib.util
from pathlib import Path
import unittest
src=Path(__file__).resolve().parents[1]/'scripts'/'vpngw-vpn-cutover-execution-contract.py'
spec=importlib.util.spec_from_file_location('execution_contract',src)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ContractTests(unittest.TestCase):
 def test_watchdog_before_any_mutation(self):
  names=[s.name for s in m.STEPS]
  self.assertLess(names.index('arm_watchdog'),names.index('install_boot_guard'))
  self.assertLess(names.index('install_fail_closed'),names.index('install_routes'))
  self.assertLess(names.index('install_routes'),names.index('atomic_filter_and_nat'))
 def test_commit_only_after_live_verification(self):
  names=[s.name for s in m.STEPS]
  self.assertLess(names.index('verify_live_egress'),names.index('commit'))
 def test_missing_proofs_block(self):
  out=m.validate_evidence({'verified_direct':True})
  self.assertFalse(out['execute_enabled'])
  self.assertIn('watchdog_armed',out['missing'])
 def test_no_automatic_authorization_even_with_all_evidence(self):
  values={s.prerequisite:True for s in m.STEPS}
  self.assertFalse(m.validate_evidence(values)['execute_enabled'])
