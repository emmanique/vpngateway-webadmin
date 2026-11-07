import importlib.util
from pathlib import Path
import tempfile
import unittest
BASE=Path(__file__).resolve().parents[1]/'scripts'
spec=importlib.util.spec_from_file_location('watchdog_isolation',BASE/'vpngw-vpn-rollback-watchdog.py')
watch=importlib.util.module_from_spec(spec);spec.loader.exec_module(watch)
class WatchdogIsolationTests(unittest.TestCase):
 def test_corrupt_journal_does_not_suppress_other_rollback(self):
  with tempfile.TemporaryDirectory() as folder:
   directory=Path(folder)
   (directory/'caio.json').write_text('corrupt json')
   r=watch.journal.prepare('teste',{'status':'snapshot_validated','policy':'teste','host':'192.168.1.227','jump_handles':[11,12]},now=100,seconds=60)
   watch.journal.persist(directory/'teste.json',r)
   seen=[]
   out=watch.scan(directory,now=170,executor=lambda name:(seen.append(name) or {}))
   self.assertEqual(seen,['teste'])
   self.assertEqual([(x['policy'],x['status']) for x in out],
                    [('caio','rollback_failed'),('teste','rollback_failed')])
 def test_corrupt_file_without_transaction_is_failure(self):
  with tempfile.TemporaryDirectory() as folder:
   (Path(folder)/'bad name.json').write_text('{}')
   r=watch.scan(folder,now=200,executor=lambda name:None)
   self.assertEqual(r[0]['status'],'rollback_failed')
