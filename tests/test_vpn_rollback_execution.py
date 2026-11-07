import importlib.util
from pathlib import Path
import unittest
source=Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-rollback-executor.py"
spec=importlib.util.spec_from_file_location("rollback_testing",source)
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
class ExecutionTests(unittest.TestCase):
 def setUp(self):
  self.r={"policy_id":"caio","state":"revert_required","deadline":100,
       "vpn_table":28690,"vpn_priority":18690,"vpn_interface":"tun6eb314b8b6",
       "guard_table":"vpngw_host_caio",
       "snapshot":{"status":"snapshot_validated","policy":"caio","host":"192.168.1.226","jump_handles":[74,73]}}
  self.state={"status":"active","plan":{"destination":"direct","host":"192.168.1.226","lan":"wlp2s0","wan":"wlp2s0"}}
  import hashlib
  self.chain="GW_"+hashlib.sha256(b"caio").hexdigest()[:16].upper()
 def fake(self,*cmd):
  cmd=" ".join(cmd)
  if cmd.startswith("nft list chain ip filter GW_"):return 'iifname "wlp2s0" oifname "wlp2s0" counter accept'
  if "vpngw_gw_" in cmd:return 'ip saddr 192.168.1.226 oifname "wlp2s0" masquerade'
  if cmd.endswith("DOCKER-USER"):return 'jump '+self.chain+'\njump '+self.chain
  if cmd.endswith("vpngw_host_caio"):return 'ip saddr 192.168.1.226 oifname != "tun6eb314b8b6" counter drop'
  if cmd=="ip -4 rule show":return '18690: from 192.168.1.226 iif wlp2s0 lookup 28690'
  if "route get" in cmd:return '1.1.1.1 from 192.168.1.226 dev wlp2s0'
  return ''
 def test_execution_preserves_guard(self):
  results=[]
  actual=e.execute_rollback(self.r,self.state,self.fake,results.append)
  self.assertFalse(actual["direct_connectivity_restored"])
  self.assertTrue(actual["guard_preserved"])
  self.assertEqual(results[0]["state"],"revert_required")
 def test_guard_missing_blocks(self):
  def no_guard(*cmd):
   if cmd[-1]=="vpngw_host_caio":return ''
   return self.fake(*cmd)
  with self.assertRaises(RuntimeError):e.execute_rollback(self.r,self.state,no_guard,lambda r:None)
 def test_wrong_state_blocks(self):
  self.r["state"]="confirmed"
  with self.assertRaises(RuntimeError):e.execute_rollback(self.r,self.state,self.fake,lambda r:None)

class IdempotentRollbackTests(ExecutionTests):
 def test_repeated_rollback_is_safe(self):
  self.r["routing_restored"]=True
  commands=[]
  def fake(*args):
   if args[:4]==("ip","-4","rule","show"):
    return "32766: from all lookup main"
   if args[:3]==("ip","-4","route") and "get" not in args:
    commands.append(args)
   return self.fake(*args)
  result=e.execute_rollback(self.r,self.state,fake,lambda record:None)
  self.assertTrue(result["direct_route_restored"])
  self.assertFalse(commands)

class RejectWrongWanNatTests(ExecutionTests):
 def test_wrong_nat_interface_blocks_rollback(self):
  def wrong_nat(*parts):
   if "vpngw_gw_" in " ".join(parts):
    return 'ip saddr 192.168.1.226 oifname "tun6eb314b8b6" counter masquerade'
   return self.fake(*parts)
  with self.assertRaises(RuntimeError):
   e.verify_rollback_prerequisites(self.r,self.state,wrong_nat)
