import importlib.util
from pathlib import Path
import unittest
src=Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-direct-snapshot.py"
spec=importlib.util.spec_from_file_location("snapshot",src)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class SnapshotTests(unittest.TestCase):
 def setUp(self):
  self.pid="caio"
  import hashlib
  self.name="GW_"+hashlib.sha256(b"caio").hexdigest()[:16].upper()
  self.state={"status":"active","plan":{"destination":"direct","host":"192.168.1.226","lan":"wlp2s0","wan":"wlp2s0"}}
  self.docker=f'ip saddr 192.168.1.226 jump {self.name} # handle 12\nip daddr 192.168.1.226 jump {self.name} # handle 13'
  self.chain='iifname "wlp2s0" oifname "wlp2s0" counter accept'
  self.nat='ip saddr 192.168.1.226 oifname "wlp2s0" counter masquerade'
 def test_valid(self):
  self.assertEqual(m.audit(self.pid,self.chain,self.docker,self.nat,self.state)["jump_handles"],[12,13])
 def test_missing_jump(self):
  with self.assertRaises(ValueError):m.audit(self.pid,self.chain,self.docker.splitlines()[0],self.nat,self.state)
 def test_reject_wrong_state(self):
  self.state["status"]="pending"
  with self.assertRaises(ValueError):m.audit(self.pid,self.chain,self.docker,self.nat,self.state)
