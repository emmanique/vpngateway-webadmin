import hashlib
import importlib.util
from pathlib import Path
import unittest
s=importlib.util.spec_from_file_location("atomic",Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-atomic-filter-plan.py")
a=importlib.util.module_from_spec(s);s.loader.exec_module(a)
class AtomicFilterTests(unittest.TestCase):
 def setUp(self):
  self.name="GW_"+hashlib.sha256(b"caio").hexdigest()[:16].upper()
  self.chain="table ip filter { chain "+self.name+" { counter accept } }"
  self.docker="ip daddr 192.168.1.226 jump "+self.name+"\nip saddr 192.168.1.226 jump "+self.name
 def test_one_transaction_preserves_jumps(self):
  p=a.render("caio","192.168.1.226","wlp2s0","tun6eb314b8b6","172.31.83.53",self.chain,self.docker)
  self.assertIn("flush chain ip filter "+self.name,p["batch"])
  self.assertIn('oifname "tun6eb314b8b6"',p["batch"])
  self.assertNotIn("delete chain",p["batch"])
  self.assertFalse(p["applied"])
 def test_requires_jumps(self):
  with self.assertRaises(ValueError):a.render("caio","192.168.1.226","wlp2s0","tun6eb314b8b6","172.31.83.53",self.chain,"")

class ReverseDnsTests(AtomicFilterTests):
 def test_docker_dns_return(self):
  p=a.render("caio","192.168.1.226","wlp2s0","tun6eb314b8b6","172.31.83.53",self.chain,self.docker,bridge="brvg6eb314b8b6")
  self.assertIn('iifname "brvg6eb314b8b6" oifname "wlp2s0"',p["batch"])
  self.assertIn("ct state established,related",p["batch"])
 def test_reject_bad_bridge(self):
  with self.assertRaises(ValueError):
   a.render("caio","192.168.1.226","wlp2s0","tun6eb314b8b6","172.31.83.53",self.chain,self.docker,bridge="bad;flush")
