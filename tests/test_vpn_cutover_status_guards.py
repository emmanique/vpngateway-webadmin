"""Security gates in current host-scoped VPN transition implementation."""
import ast
import unittest
from pathlib import Path
s=(Path(__file__).resolve().parents[1]/'apps/api/main.py').read_text()
tree=ast.parse(s)
def method(name):
 return ast.get_source_segment(s,next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name))
class TransitionGuards(unittest.TestCase):
 def test_mac_identity_required(self):
  b=method('apply_vpn_transition')
  self.assertIn('network_neighbors()',b)
  self.assertIn('registered_mac',b)
  self.assertIn('MAC actual do cliente não corresponde',b)
 def test_kernel_confirmation_before_database_commit(self):
  b=method('apply_vpn_transition')
  self.assertLess(b.index('runtime.get("status")'),b.index('_save("policies"'))
  self.assertIn('"vpn_revert"',b)
 def test_vpn_dns_is_resolved_prior_to_transition(self):
  b=method('apply_vpn_transition')
  self.assertIn('_vpn_profile_dns_ipv4(destination)',b)
  self.assertIn('"dns_ipv4": dns',b)
