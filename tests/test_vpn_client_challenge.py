import importlib.util,json
from pathlib import Path
import tempfile
import unittest
s=importlib.util.spec_from_file_location('challenge',Path(__file__).resolve().parents[1]/'scripts'/'vpngw-vpn-client-challenge.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Challenges(unittest.TestCase):
 def test_issue_and_expire(self):
  with tempfile.TemporaryDirectory() as d:
   r=m.issue('caio','trial-123',d,host='192.168.1.226',now=100)
   self.assertTrue(m.validate(r,policy='caio',host='192.168.1.226',transaction_id='trial-123',now=105))
   self.assertFalse(m.validate(r,policy='caio',host='192.168.1.226',transaction_id='trial-123',now=130))
   self.assertEqual(json.loads((Path(d)/'caio-trial-123.json').read_text())['nonce'],r['nonce'])
 def test_no_duplicate_issuance(self):
  with tempfile.TemporaryDirectory() as d:
   m.issue('teste','trial-123',d,host='192.168.1.227',now=100)
   with self.assertRaises(FileExistsError):m.issue('teste','trial-123',d,host='192.168.1.227',now=110)
 def test_invalid_host_refused(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(ValueError):m.issue('other','trial-123',d,host='127.0.0.1',now=100)
 def test_path_traversal_refused(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(ValueError):m.issue('caio','../bad',d,host='192.168.1.226',now=100)
 def test_wrong_transaction_is_not_accepted(self):
  with tempfile.TemporaryDirectory() as d:
   r=m.issue('caio','trial-123',d,host='192.168.1.226',now=100)
   self.assertFalse(m.validate(r,policy='caio',host='192.168.1.226',transaction_id='trial-456',now=105))

 def test_arbitrary_private_ipv4_host_and_policy(self):
  with tempfile.TemporaryDirectory() as d:
   r=m.issue('host-office','trial-789',d,host='10.88.2.45',now=100)
   self.assertTrue(m.validate(r,policy='host-office',host='10.88.2.45',transaction_id='trial-789',now=101))
   self.assertFalse(m.validate(r,policy='host-office',host='10.88.2.46',transaction_id='trial-789',now=101))
