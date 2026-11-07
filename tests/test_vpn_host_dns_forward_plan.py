import importlib.util
from pathlib import Path
import unittest
s=importlib.util.spec_from_file_location("host_dns_forward",Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-host-dns-forward-plan.py")
mod=importlib.util.module_from_spec(s);s.loader.exec_module(mod)
class DnsForwardTests(unittest.TestCase):
 def test_proton_dns_forward(self):
  p=mod.render("caio","192.168.1.226","wlp2s0","brvg6eb314b8b6","172.31.83.53","30:05:05:d0:8f:ae")
  self.assertIn('oifname "brvg6eb314b8b6"',p["nft"])
  self.assertIn("ct state established,related",p["nft"])
  self.assertFalse(p["applied"])
 def test_reject_bad_mac(self):
  with self.assertRaises(ValueError):mod.render("teste","192.168.1.227","wlp2s0","brvga713bb390e","172.31.163.53","bad")
