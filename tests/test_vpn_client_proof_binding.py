import hashlib,hmac,importlib.util,tempfile
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('binding',Path(__file__).resolve().parents[1]/'scripts'/'vpngw-vpn-client-proof-binding.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
KEY=b'T'*32
def signed(challenge):
 p={'policy':challenge['policy'],'host':challenge['host'],'transaction_id':challenge['transaction_id'],
    'nonce':challenge['nonce'],'observed_at':110,'public_ipv4':'8.8.8.8',
    'dns_through_vpn':True,'direct_fallback_blocked':True}
 return {'proof':p,'hmac_sha256':hmac.new(KEY,m.proof.canonical(p),hashlib.sha256).hexdigest()}
class Binding(unittest.TestCase):
 def test_valid_never_enables_cutover(self):
  with tempfile.TemporaryDirectory() as directory:
   ch=m.challenge.issue('teste','trial-one',directory,host='192.168.1.227',now=100)
   result=m.verify(issued=ch,envelope=signed(ch),host='192.168.1.227',policy='teste',transaction_id='trial-one',secret=KEY,now=110)
   self.assertTrue(result['authenticated'])
   self.assertFalse(result['cutover_enabled'])
 def test_expired_challenge_rejected(self):
  with tempfile.TemporaryDirectory() as directory:
   ch=m.challenge.issue('teste','trial-one',directory,host='192.168.1.227',now=100)
   self.assertFalse(m.verify(issued=ch,envelope=signed(ch),host='192.168.1.227',policy='teste',transaction_id='trial-one',secret=KEY,now=131)['authenticated'])
 def test_cross_client_rejected(self):
  with tempfile.TemporaryDirectory() as directory:
   ch=m.challenge.issue('teste','trial-one',directory,host='192.168.1.227',now=100)
   self.assertFalse(m.verify(issued=ch,envelope=signed(ch),host='192.168.1.227',policy='caio',transaction_id='trial-one',secret=KEY,now=110)['authenticated'])
