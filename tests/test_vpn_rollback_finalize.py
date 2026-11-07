import hashlib
import importlib.util
from pathlib import Path
import subprocess
import unittest
s=importlib.util.spec_from_file_location("fin",Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-rollback-finalize.py")
f=importlib.util.module_from_spec(s);s.loader.exec_module(f)
class FinalizeTests(unittest.TestCase):
 def setUp(self):
  self.r={"policy_id":"caio","state":"revert_required","deadline":100,"routing_restored":True,
   "vpn_table":28690,"vpn_priority":18690,"vpn_interface":"tun6eb314b8b6","guard_table":"vpngw_host_caio",
   "snapshot":{"status":"snapshot_validated","policy":"caio","host":"192.168.1.226","jump_handles":[74,73]}}
  self.state={"status":"active","plan":{"destination":"direct","host":"192.168.1.226","lan":"wlp2s0","wan":"wlp2s0"}}
  self.name="GW_"+hashlib.sha256(b"caio").hexdigest()[:16].upper()
  self.removed=False
 def cmd(self,*args):
  v=" ".join(args)
  if v.startswith("nft list chain ip filter GW_"):return 'counter accept'
  if v.startswith("nft list table ip vpngw_"):return 'ip saddr 192.168.1.226 oifname "wlp2s0" counter masquerade'
  if v.endswith("DOCKER-USER"):return ("jump "+self.name+"\n")*2
  if v=="ip -4 rule show":return '32766: from all lookup main'
  if "route get" in v:return '1.1.1.1 from 192.168.1.226 dev wlp2s0'
  if v=="nft list table inet vpngw_host_caio":
   if self.removed:raise subprocess.CalledProcessError(1,args)
   return '192.168.1.226 tun6eb314b8b6 counter drop'
  if v=="nft delete table inet vpngw_host_caio":self.removed=True
  return ''
 def test_finalize(self):
  saved=[]
  result=f.finalize(self.r,self.state,self.cmd,saved.append)
  self.assertTrue(result["direct_restored"])
  self.assertEqual(saved[0]["state"],"reverted")
 def test_no_permission_without_route_restore(self):
  self.r["routing_restored"]=False
  with self.assertRaises(ValueError):f.finalize(self.r,self.state,self.cmd,lambda r:None)
  self.assertFalse(self.removed)
 def test_wrong_guard_owner(self):
  self.r["guard_table"]="vpngw_host_teste"
  with self.assertRaises(ValueError):f.finalize(self.r,self.state,self.cmd,lambda r:None)
  self.assertFalse(self.removed)
