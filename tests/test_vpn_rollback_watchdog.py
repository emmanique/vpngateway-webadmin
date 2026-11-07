import importlib.util
from pathlib import Path
import tempfile
import unittest
src=Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-rollback-watchdog.py"
sp=importlib.util.spec_from_file_location("watchdog",src);w=importlib.util.module_from_spec(sp);sp.loader.exec_module(w)
class WatchdogTests(unittest.TestCase):
 def test_empty_safe(self):
  with tempfile.TemporaryDirectory() as tmp:self.assertEqual(w.scan(tmp,now=250),[])
 def test_expired_triggers_exact_policy(self):
  with tempfile.TemporaryDirectory() as tmp:
   snap={"status":"snapshot_validated","policy":"caio","jump_handles":[74,73]}
   rec=w.journal.prepare("caio",snap,now=100,seconds=60)
   w.journal.persist(Path(tmp)/"caio.json",rec)
   called=[]
   def executor(name):
    called.append(name)
    w.journal.persist(Path(tmp)/(name+".json"),{**rec,"state":"reverted"})
    return {"direct_restored":True,"guard_removed":True,"already_absent":True}
   result=w.scan(tmp,now=170,executor=executor)
   self.assertEqual(called,["caio"]);self.assertEqual(result[0]["status"],"rollback_verified")
 def test_unexpired_not_triggered(self):
  with tempfile.TemporaryDirectory() as tmp:
   snap={"status":"snapshot_validated","policy":"teste","jump_handles":[87,86]}
   w.journal.persist(Path(tmp)/"teste.json",w.journal.prepare("teste",snap,now=100,seconds=180))
   self.assertEqual(w.scan(tmp,now=150,executor=lambda n:None),[])
 def test_invalid_fails_closed(self):
  with tempfile.TemporaryDirectory() as tmp:
   (Path(tmp)/"caio.json").write_text("{}")
   result=w.scan(tmp,now=170)
   self.assertEqual(result[0]["status"],"rollback_failed")
   self.assertEqual(result[0]["policy"],"caio")


class FailedExecutorTests(unittest.TestCase):
 def test_false_success_is_failure(self):
  with tempfile.TemporaryDirectory() as tmp:
   snap={"status":"snapshot_validated","policy":"caio","jump_handles":[74,73]}
   rec=w.journal.prepare("caio",snap,now=100,seconds=60)
   w.journal.persist(Path(tmp)/"caio.json",rec)
   result=w.scan(tmp,now=170,executor=lambda _:{"direct_restored":False})
   self.assertEqual(result[0]["status"],"rollback_failed")
   self.assertEqual(w.journal.read(Path(tmp)/"caio.json")["state"],"prepared")
