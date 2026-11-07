import hashlib,hmac,importlib.util
from pathlib import Path
import tempfile
import unittest
source=Path(__file__).resolve().parents[1]/'scripts'/'vpngw-vpn-client-proof-replay.py'
spec=importlib.util.spec_from_file_location('replay',source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
KEY=b'X'*32
def signed():
 p=dict(policy='caio',host='192.168.1.226',transaction_id='trial-123',
  nonce='nonce-456',observed_at=100,public_ipv4='8.8.8.8',
  dns_through_vpn=True,direct_fallback_blocked=True)
 return {'proof':p,'hmac_sha256':hmac.new(KEY,m.envelope_module.canonical(p),hashlib.sha256).hexdigest()}
def consume(envelope,directory):
 return m.consume(envelope,policy='caio',host='192.168.1.226',
   transaction_id='trial-123',nonce='nonce-456',secret=KEY,directory=directory,now=110)
class ReplayTests(unittest.TestCase):
 def test_single_use_persistent(self):
  with tempfile.TemporaryDirectory() as folder:
   self.assertTrue(consume(signed(),folder)['authenticated'])
   self.assertEqual(consume(signed(),folder)['error'],'challenge_already_consumed')
   self.assertEqual(len(list(Path(folder).glob('*.json'))),1)
 def test_invalid_proof_does_not_consume(self):
  with tempfile.TemporaryDirectory() as folder:
   bad=signed();bad['proof']['public_ipv4']='9.9.9.9'
   self.assertFalse(consume(bad,folder)['authenticated'])
   self.assertTrue(consume(signed(),folder)['authenticated'])
 def test_missing_directory_fails_closed(self):
  with tempfile.TemporaryDirectory() as folder:
   self.assertEqual(consume(signed(),str(Path(folder)/'missing'))['error'],'challenge_directory_unavailable')
 def test_invalid_transaction_identifier_fails_closed(self):
  with tempfile.TemporaryDirectory() as folder:
   self.assertFalse(m.consume(signed(),policy='caio',host='192.168.1.226',transaction_id='../escape',
      nonce='nonce-456',secret=KEY,directory=folder,now=110)['authenticated'])
