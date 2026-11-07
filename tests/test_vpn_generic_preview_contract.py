import ast
from pathlib import Path
import unittest
source=(Path(__file__).resolve().parents[1]/'apps/api/main.py').read_text()
tree=ast.parse(source)
method=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='vpn_generic_preview')
body=ast.get_source_segment(source,method)
class GenericPreview(unittest.TestCase):
 def test_names_taken_from_data(self):
  self.assertIn('profile.get("name")',body)
  self.assertIn('policy.get("name")',body)
 def test_no_specific_hosts_or_vpn(self):
  for value in ('192.168.1.226','192.168.1.227','vpn-proton','vpn-cyberghost'):
   self.assertNotIn(value,body)
 def test_no_execution(self):
  self.assertIn('"cutover_enabled":False',body)
  self.assertIn('"network_changes":False',body)
