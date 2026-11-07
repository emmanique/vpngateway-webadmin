import importlib.util
from pathlib import Path
import unittest
source=Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-cutover-gate.py"
spec=importlib.util.spec_from_file_location("gate",source)
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
class GateTests(unittest.TestCase):
 def test_full_preflight_never_enables_trial(self):
  r={"checks":{"route":True,"mac":True},"boot_guard":{"staged_candidate_valid":True},"integrated_preflight":True}
  out=gate.evaluate(r)
  self.assertFalse(out["eligible_for_trial"])
  self.assertEqual(out["reasons"],["executor_not_wired","live_egress_and_rollback_not_verified"])
 def test_missing_guard_rejected(self):
  r={"checks":{"route":True},"boot_guard":{"staged_candidate_valid":False},"integrated_preflight":True}
  self.assertIn("boot_guard_not_staged",gate.evaluate(r)["reasons"])
 def test_false_check_rejected(self):
  r={"checks":{"mac":False},"boot_guard":{"staged_candidate_valid":True},"integrated_preflight":False}
  self.assertIn("failed:mac",gate.evaluate(r)["reasons"])
 def test_missing_checks_rejected(self):
  self.assertIn("missing_integrated_checks",gate.evaluate({})["reasons"])
