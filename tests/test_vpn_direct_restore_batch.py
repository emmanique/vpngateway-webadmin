import importlib.util
from pathlib import Path
import unittest
src=Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-direct-restore-batch.py"
s=importlib.util.spec_from_file_location("restorebatch",src);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class RestoreBatchTests(unittest.TestCase):
 def test_restore_both_atomically(self):
  p={"destination":"direct","shared":True,"host":"192.168.1.226","lan":"wlp2s0","wan":"wlp2s0"}
  batch=m.render("caio",p)
  self.assertEqual(batch.count("flush chain"),2)
  self.assertIn("masquerade",batch)
  self.assertIn("ct state established,related",batch)
 def test_reject_other_policy(self):
  with self.assertRaises(ValueError):m.render("caio",{"destination":"vpn"})
