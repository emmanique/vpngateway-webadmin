import hashlib,hmac,importlib.util,json
from pathlib import Path
import tempfile
import unittest
spec=importlib.util.spec_from_file_location('verify_store',Path(__file__).resolve().parents[1]/'scripts'/'vpngw-vpn-client-proof-verify-store.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
SECRET=b'S'*32
def signed(ch):
 p=dict(policy=ch['policy'],host=ch['host'],transaction_id=ch['transaction_id'],
 nonce=ch['nonce'],observed_at=110,public_ipv4='8.8.8.8',
 dns_through_vpn=True,direct_fallback_blocked=True)
 return {'proof':p,'hmac_sha256':hmac.new(SECRET,m.binding.proof.canonical(p),hashlib.sha256).hexdigest()}
def verify(folder,envelope):
 return m.verify_stored(policy='teste',transaction_id='trial-one',host='192.168.1.227',envelope=envelope,secret=SECRET,directory=folder,now=110)
class StoredChallenge(unittest.TestCase):
 def test_valid_stored_challenge(self):
  with tempfile.TemporaryDirectory() as folder:
   issued=m.challenge.issue('teste','trial-one',folder,host='192.168.1.227',now=100)
   self.assertTrue(verify(folder,signed(issued))['authenticated'])
 def test_modified_stored_challenge_rejected(self):
  with tempfile.TemporaryDirectory() as folder:
   issued=m.challenge.issue('teste','trial-one',folder,host='192.168.1.227',now=100)
   (Path(folder)/'teste-trial-one.json').write_text(json.dumps({**issued,'nonce':'0'*64}))
   self.assertFalse(verify(folder,signed(issued))['authenticated'])
 def test_missing_challenge_rejected(self):
  with tempfile.TemporaryDirectory() as folder:
   self.assertFalse(verify(folder,{})['authenticated'])
 def test_symlink_challenge_rejected(self):
  with tempfile.TemporaryDirectory() as folder:
   issued=m.challenge.issue('teste','trial-one',folder,host='192.168.1.227',now=100)
   source=Path(folder)/'teste-trial-one.json'
   source.rename(Path(folder)/'saved.json')
   source.symlink_to(Path(folder)/'saved.json')
   self.assertFalse(verify(folder,signed(issued))['authenticated'])
