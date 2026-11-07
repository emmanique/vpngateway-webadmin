import ast
from pathlib import Path
import unittest
source=(Path(__file__).resolve().parents[1]/'apps/api/main.py').read_text()
tree=ast.parse(source)
code=ast.get_source_segment(source,next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='_discovery_lan_networks'))
class LanCidrContract(unittest.TestCase):
 def test_lan_roles_only(self):
  self.assertNotIn('roles={draft.get("management_interface")}',code)
 def test_separate_lan_role(self):
  self.assertIn('item.get("role")=="lan"',code)
 def test_ipv4_only(self):
  self.assertIn('net.version==4',code)
