import importlib.util
from pathlib import Path
import tempfile
import unittest
src=Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-rollback-journal.py"
sp=importlib.util.spec_from_file_location("journal",src)
j=importlib.util.module_from_spec(sp);sp.loader.exec_module(j)
SNAP={"status":"snapshot_validated","policy":"caio","jump_handles":[74,73]}
class JournalTests(unittest.TestCase):
 def test_persist_and_state_machine(self):
  r=j.prepare("caio",SNAP,now=100,seconds=180)
  with tempfile.TemporaryDirectory() as folder:
   target=Path(folder)/"caio.json"
   j.persist(target,r)
   self.assertEqual(j.read(target),r)
  for event in ("guard_installed","vpn_route_installed","fail","direct_verified"):
   r=j.next_state(r,event,now=120)
  self.assertEqual(r["state"],"reverted")
 def test_timeout_requires_rollback(self):
  r=j.prepare("caio",SNAP,now=100,seconds=60)
  self.assertEqual(j.next_state(r,"guard_installed",now=161)["state"],"revert_required")
 def test_late_confirmation_rejected(self):
  r=j.prepare("caio",SNAP,now=100,seconds=60)
  r=j.next_state(r,"guard_installed",now=110)
  r=j.next_state(r,"vpn_route_installed",now=120)
  self.assertEqual(j.next_state(r,"verified",now=161)["state"],"revert_required")
 def test_no_unverified_snapshot(self):
  with self.assertRaises(ValueError):j.prepare("caio",{"status":"draft"},now=100)
 def test_no_short_timeout(self):
  with self.assertRaises(ValueError):j.prepare("caio",SNAP,now=100,seconds=5)
