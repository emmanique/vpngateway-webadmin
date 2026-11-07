import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
s=importlib.util.spec_from_file_location("stage",Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-boot-stage.py")
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class StageTests(unittest.TestCase):
 def test_staging_does_not_activate_guard(self):
  with tempfile.TemporaryDirectory() as folder:
   data={"id":"caio","host":"192.168.1.226","lan":"wlp2s0","vpn":"tun6eb314b8b6","mac":"30:05:05:d0:8f:ae","confirmed":True}
   path=m.stage(data,Path(folder))
   self.assertEqual(json.loads(path.read_text()),data)
   self.assertEqual(path.stat().st_mode & 0o077,0)
 def test_reject_unconfirmed(self):
  with tempfile.TemporaryDirectory() as folder:
   with self.assertRaises(ValueError):
    m.stage({"id":"caio","confirmed":False},Path(folder))
