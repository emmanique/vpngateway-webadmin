import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
s=importlib.util.spec_from_file_location("ready",Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-host-boot-readiness.py")
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class BootReadiness(unittest.TestCase):
 def test_absent_refuses_cutover(self):
  with tempfile.TemporaryDirectory() as d:
   x=m.audit("caio","192.168.1.226","wlp2s0","tun6eb314b8b6","30:05:05:d0:8f:ae",d)
   self.assertFalse(x["boot_guard_ready"])
 def test_guard_matches(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/"caio.json"
   path.write_text(json.dumps({"id":"caio","host":"192.168.1.226","lan":"wlp2s0","vpn":"tun6eb314b8b6","mac":"30:05:05:d0:8f:ae","confirmed":True}))
   path.chmod(0o600)
   self.assertTrue(m.audit("caio","192.168.1.226","wlp2s0","tun6eb314b8b6","30:05:05:d0:8f:ae",d)["boot_guard_ready"])
   self.assertFalse(m.audit("caio","192.168.1.227","wlp2s0","tun6eb314b8b6","30:05:05:d0:8f:ae",d)["boot_guard_ready"])
