import importlib.util
from pathlib import Path
import unittest
src=Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-rollback-executor.py"
spec=importlib.util.spec_from_file_location("rollbackexecutor",src)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ExecutorTests(unittest.TestCase):
 def setUp(self):
  self.rec={"policy_id":"caio","state":"revert_required","deadline":100,
            "snapshot":{"status":"snapshot_validated","policy":"caio","host":"192.168.1.226","jump_handles":[74,73]},
            "vpn_table":28690,"vpn_priority":18690,"vpn_interface":"tun6eb314b8b6"}
  self.old={"status":"active","plan":{"destination":"direct","host":"192.168.1.226","lan":"wlp2s0"}}
 def test_plan_preserves_guard(self):
  commands=m.commands_for(self.rec,self.old)
  self.assertEqual(commands[0][0:4],["ip","-4","rule","del"])
  self.assertFalse(any("nft" in command for command in commands))
 def test_mismatched_host_rejected(self):
  self.rec["snapshot"]["host"]="192.168.1.227"
  with self.assertRaises(ValueError):m.commands_for(self.rec,self.old)
 def test_out_of_scope_table_rejected(self):
  self.rec["vpn_table"]=10249
  with self.assertRaises(ValueError):m.commands_for(self.rec,self.old)
