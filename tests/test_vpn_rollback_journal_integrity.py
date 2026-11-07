import importlib.util
from pathlib import Path
import unittest
path=Path(__file__).resolve().parents[1]/'scripts'/'vpngw-vpn-rollback-journal.py'
spec=importlib.util.spec_from_file_location('journal_integrity',path)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
def record():
 return mod.prepare('caio',{'status':'snapshot_validated','policy':'caio','host':'192.168.1.226','jump_handles':[11,12]},now=100,seconds=60)
class JournalIntegrity(unittest.TestCase):
 def test_nan_deadline_rejected(self):
  r=record();r['deadline']=float('nan')
  with self.assertRaises(ValueError):mod.validate(r)
 def test_infinite_deadline_rejected(self):
  r=record();r['deadline']=float('inf')
  with self.assertRaises(ValueError):mod.validate(r)
 def test_duplicate_jump_handles_rejected(self):
  r=record();r['snapshot']['jump_handles']=[11,11]
  with self.assertRaises(ValueError):mod.validate(r)
 def test_bad_jump_handle_rejected(self):
  r=record();r['snapshot']['jump_handles']=[True,12]
  with self.assertRaises(ValueError):mod.validate(r)
 def test_invalid_time_rejected(self):
  with self.assertRaises(ValueError):mod.next_state(record(),'guard_installed',now=float('nan'))
 def test_valid_record_survives(self):
  self.assertEqual(mod.next_state(record(),'guard_installed',now=120)['state'],'guarded')
