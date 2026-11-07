import hashlib,hmac,importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('envelope',Path(__file__).resolve().parents[1]/'scripts'/'vpngw-vpn-client-proof-envelope.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
KEY=b'X'*32
def signed():
 p=dict(policy='caio',host='192.168.1.226',transaction_id='trial-123',
  nonce='nonce-456',observed_at=100,public_ipv4='8.8.8.8',
  dns_through_vpn=True,direct_fallback_blocked=True)
 return {'proof':p,'hmac_sha256':hmac.new(KEY,m.canonical(p),hashlib.sha256).hexdigest()}
def verify(e,**kw):
 return m.verify(e,policy='caio',host='192.168.1.226',transaction_id='trial-123',
    expected_nonce='nonce-456',secret=KEY,now=110,**kw)
class EnvelopeTests(unittest.TestCase):
 def test_valid_signed_challenge(self):
  self.assertTrue(verify(signed())['authenticated'])
 def test_tampered_proof_rejected(self):
  e=signed();e['proof']['public_ipv4']='9.9.9.9'
  self.assertFalse(verify(e)['authenticated'])
 def test_replayed_nonce_rejected(self):
  e=signed()
  self.assertFalse(m.verify(e,policy='caio',host='192.168.1.226',transaction_id='trial-123',
    expected_nonce='different',secret=KEY,now=110)['authenticated'])
 def test_wrong_host_rejected(self):
  self.assertFalse(m.verify(signed(),policy='caio',host='192.168.1.227',transaction_id='trial-123',
    expected_nonce='nonce-456',secret=KEY,now=110)['authenticated'])
 def test_expired_rejected(self):
  self.assertFalse(m.verify(signed(),policy='caio',host='192.168.1.226',
    transaction_id='trial-123',expected_nonce='nonce-456',secret=KEY,now=150)['authenticated'])
 def test_no_key_rejected(self):
  self.assertFalse(m.verify(signed(),policy='caio',host='192.168.1.226',
    transaction_id='trial-123',expected_nonce='nonce-456',secret=b'',now=110)['authenticated'])
