import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
base=Path(__file__).resolve().parents[1]/"scripts"
spec=importlib.util.spec_from_file_location("promote",base/"vpngw-vpn-boot-promote.py")
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
class PromoteTests(unittest.TestCase):
 def test_reject_without_journal(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);stage=root/"stage";active=root/"active";tx=root/"tx"
   for d in (stage,active,tx):d.mkdir(mode=0o700)
   data={"id":"caio","host":"192.168.1.226","lan":"wlp2s0","vpn":"tun6eb314b8b6","mac":"30:05:05:d0:8f:ae","confirmed":True}
   staged=stage/"caio.json";staged.write_text(json.dumps(data));staged.chmod(0o600)
   with self.assertRaises(FileNotFoundError):mod.promote("caio",lambda *args:"",stage,active,tx)
   self.assertEqual(list(active.iterdir()),[])
 def test_reject_without_live_guard(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);stage=root/"stage";active=root/"active";tx=root/"tx"
   for d in (stage,active,tx):d.mkdir(mode=0o700)
   data={"id":"caio","host":"192.168.1.226","lan":"wlp2s0","vpn":"tun6eb314b8b6","mac":"30:05:05:d0:8f:ae","confirmed":True}
   staged=stage/"caio.json";staged.write_text(json.dumps(data));staged.chmod(0o600)
   snap={"status":"snapshot_validated","policy":"caio","host":data["host"],"jump_handles":[1,2]}
   rec=mod.journal.prepare("caio",snap,now=__import__("time").time())
   rec.update(state="guarded",guard_table="vpngw_host_caio",vpn_interface=data["vpn"])
   mod.journal.persist(tx/"caio.json",rec)
   with self.assertRaises(RuntimeError):mod.promote("caio",lambda *args:"no guard",stage,active,tx)
   self.assertEqual(list(active.iterdir()),[])
 def test_promotes_only_with_matching_verified_guard(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);stage=root/"stage";active=root/"active";tx=root/"tx"
   for d in (stage,active,tx):d.mkdir(mode=0o700)
   data={"id":"caio","host":"192.168.1.226","lan":"wlp2s0","vpn":"tun6eb314b8b6","mac":"30:05:05:d0:8f:ae","confirmed":True}
   staged=stage/"caio.json";staged.write_text(json.dumps(data));staged.chmod(0o600)
   snap={"status":"snapshot_validated","policy":"caio","host":data["host"],"jump_handles":[1,2]}
   rec=mod.journal.prepare("caio",snap,now=__import__("time").time())
   rec.update(state="guarded",guard_table="vpngw_host_caio",vpn_interface=data["vpn"])
   mod.journal.persist(tx/"caio.json",rec)
   out=mod.promote("caio",lambda *args:" ".join((*data.values().__iter__(),)) if False else "192.168.1.226 wlp2s0 tun6eb314b8b6 30:05:05:d0:8f:ae drop",stage,active,tx)
   self.assertTrue(out["boot_guard_active"])
   self.assertEqual(json.loads((active/"caio.json").read_text()),data)

 def test_reject_expired_journal(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);stage=root/"stage";active=root/"active";tx=root/"tx"
   for d in (stage,active,tx):d.mkdir(mode=0o700)
   data={"id":"caio","host":"192.168.1.226","lan":"wlp2s0","vpn":"tun6eb314b8b6","mac":"30:05:05:d0:8f:ae","confirmed":True}
   staged=stage/"caio.json";staged.write_text(json.dumps(data));staged.chmod(0o600)
   snap={"status":"snapshot_validated","policy":"caio","host":data["host"],"jump_handles":[1,2]}
   rec=mod.journal.prepare("caio",snap,now=100)
   rec.update(state="guarded",guard_table="vpngw_host_caio",vpn_interface=data["vpn"])
   mod.journal.persist(tx/"caio.json",rec)
   with self.assertRaises(ValueError):mod.promote("caio",lambda *args:"192.168.1.226 wlp2s0 tun6eb314b8b6 30:05:05:d0:8f:ae drop",stage,active,tx)
