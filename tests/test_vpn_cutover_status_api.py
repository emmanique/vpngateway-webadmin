"""Current transition endpoints must separate read-only planning from apply."""
import ast
import unittest
from pathlib import Path
source=(Path(__file__).resolve().parents[1]/'apps/api/main.py').read_text()
methods={n.name:n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)}
class TransitionAPIContract(unittest.TestCase):
 def test_read_only_preflight(self):
  fn=methods['vpn_host_preflight']
  self.assertIn('app.get',ast.unparse(fn.decorator_list[0]))
  body=ast.get_source_segment(source,fn)
  self.assertNotIn('vpn_transition(',body)
  self.assertIn('vpn_openvpn_preflight',body)
 def test_planning_never_advertises_apply(self):
  body=ast.get_source_segment(source,methods['host_transition_plan'])
  self.assertIn('"executor_available": False',body)
  self.assertIn('"can_apply": False',body)
 def test_activation_is_separate_endpoint(self):
  fn=methods['apply_vpn_transition']
  self.assertIn('app.post',ast.unparse(fn.decorator_list[0]))
  body=ast.get_source_segment(source,fn)
  self.assertIn('_require_policy_admin(request)',body)
  self.assertIn('"vpn_transition"',body)
