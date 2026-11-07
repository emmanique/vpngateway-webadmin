import importlib.util
from pathlib import Path
import unittest
s=importlib.util.spec_from_file_location("nat",Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-host-nat-switch.py")
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class NatSwitchTests(unittest.TestCase):
 def setUp(self):
  self.table="vpngw_gw_7418df96f38366fa"
  self.saved=f'table ip {self.table} {{ chain postrouting {{ ip saddr 192.168.1.226 oifname "wlp2s0" counter masquerade }} chain no_redirect {{ }} }}'
 def test_switch_and_reverse(self):
  p=m.render("caio","192.168.1.226","wlp2s0","tun6eb314b8b6",self.saved)
  self.assertIn('oifname "tun6eb314b8b6"',p["apply"])
  self.assertIn('oifname "wlp2s0"',p["restore"])
  self.assertNotIn("delete table",p["apply"])
  self.assertFalse(p["applied"])
 def test_mismatch_rejected(self):
  with self.assertRaises(ValueError):m.render("caio","192.168.1.227","wlp2s0","tun6eb314b8b6",self.saved)
