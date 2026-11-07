import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
s=importlib.util.spec_from_file_location("demote",Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-boot-demote.py")
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class DemoteTests(unittest.TestCase):
 def setUp(self):
  self.r={"policy_id":"caio","state":"reverted","routing_restored":True,"guard_preserved":False,"guard_table":"vpngw_host_caio","vpn_interface":"tun6eb314b8b6"}
  self.state={"status":"active","plan":{"destination":"direct","host":"192.168.1.226","wan":"wlp2s0"}}
 def test_only_after_revert(self):
  with tempfile.TemporaryDirectory() as folder:
   p=Path(folder)/"caio.json";p.write_text(json.dumps({"id":"caio","host":"192.168.1.226","vpn":"tun6eb314b8b6"}));p.chmod(0o600)
   with self.assertRaises(ValueError):m.demote({**self.r,"state":"vpn_pending"},self.state,lambda *args:"",Path(folder))
   self.assertTrue(p.exists())
 def test_completed_reversion(self):
  with tempfile.TemporaryDirectory() as folder:
   p=Path(folder)/"caio.json";p.write_text(json.dumps({"id":"caio","host":"192.168.1.226","vpn":"tun6eb314b8b6"}));p.chmod(0o600)
   def cmd(*args):
    if args[:3]==("nft","list","table") and args[3]=="inet":raise RuntimeError("absent")
    return 'accept oifname "wlp2s0"'
   self.assertTrue(m.demote(self.r,self.state,cmd,Path(folder))["boot_config_removed"])
   self.assertFalse(p.exists())
