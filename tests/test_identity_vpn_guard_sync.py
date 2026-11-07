import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("identity_agent",ROOT/"scripts/vpngw-policy-agent.py")
agent=importlib.util.module_from_spec(spec);spec.loader.exec_module(agent)
OLD="02:00:00:00:00:01";NEW="02:00:00:00:00:02"

class IdentityVpnSync(unittest.TestCase):
 def state(self,destination="vpn-test"):
  return {"status":"active","plan":{"host":"192.168.50.10","lan":"eth0","destination":destination,"registered_mac":OLD},"vpn_runtime":{"interface":"wg123456789ab","dns_ipv4":"10.2.0.1"}}
 def test_vpn_guard_changes_before_basic_guard_and_persistence(self):
  events=[];module=SimpleNamespace(guard_text=lambda pid,host,mac,*a:mac,replace_guard=lambda text,pid:events.append(("vpn",text)))
  loader=SimpleNamespace(exec_module=lambda module:None)
  with patch.object(agent,"read_state",return_value=self.state()),patch.object(agent,"_set_kernel_identity_guard",side_effect=lambda p,m,s:events.append(("basic",m))),patch.object(agent,"save_state",side_effect=lambda p,s:events.append(("save",s["plan"]["registered_mac"]))),patch.object(importlib.util,"spec_from_file_location",return_value=SimpleNamespace(loader=loader)),patch.object(importlib.util,"module_from_spec",return_value=module):
   result=agent.set_identity_guard("client-test",NEW)
  self.assertTrue(result["guard_verified"])
  self.assertEqual(events,[("vpn",NEW),("basic",NEW),("save",NEW)])
 def test_failure_restores_all_previous_guards_and_state(self):
  events=[];module=SimpleNamespace(guard_text=lambda pid,host,mac,*a:mac,replace_guard=lambda text,pid:events.append(("vpn",text)))
  def save(pid,state):
   mac=state["plan"]["registered_mac"];events.append(("save",mac))
   if mac==NEW:raise RuntimeError("storage unavailable")
  with patch.object(agent,"read_state",return_value=self.state()),patch.object(agent,"_set_kernel_identity_guard",side_effect=lambda p,m,s:events.append(("basic",m))),patch.object(agent,"save_state",side_effect=save),patch.object(importlib.util,"spec_from_file_location",return_value=SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module:None))),patch.object(importlib.util,"module_from_spec",return_value=module):
   with self.assertRaises(RuntimeError):agent.set_identity_guard("client-test",NEW)
  self.assertEqual(events,[("vpn",NEW),("basic",NEW),("save",NEW),("vpn",OLD),("basic",OLD),("save",OLD)])
 def test_unchanged_mac_does_not_rewrite_vpn_guard(self):
  with patch.object(agent,"read_state",return_value=self.state()),patch.object(agent,"_set_kernel_identity_guard"),patch.object(agent,"save_state") as save,patch.object(importlib.util,"spec_from_file_location") as load:
   agent.set_identity_guard("client-test",OLD)
   load.assert_not_called();save.assert_called_once()
 def test_direct_identity_uses_only_basic_guard(self):
  with patch.object(agent,"read_state",return_value=self.state("direct")),patch.object(agent,"_set_kernel_identity_guard"),patch.object(agent,"save_state") as save,patch.object(importlib.util,"spec_from_file_location") as load:
   agent.set_identity_guard("client-test",NEW)
   load.assert_not_called();self.assertEqual(save.call_args.args[1]["plan"]["registered_mac"],NEW)
