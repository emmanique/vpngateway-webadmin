"""No privilege needed: transaction sequencing, independent timer and rollback."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SRC=Path(__file__).resolve().parents[1]/"scripts/vpngw-dns-qa-cutover.py"
spec=importlib.util.spec_from_file_location("qa_dns_atomic",SRC)
agent=importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

PID="qa-example"
HOST="192.168.50.20"
PIHOLE="172.30.7.2"
BRIDGE="brqa0"

def policy():
    return {"status":"active",
            "plan":{"host":HOST,"lan":"ethqa0","wan":"ethwan0",
                    "registered_mac":"02:11:22:33:44:55","destination":"vpn-proton"},
            "vpn_runtime":{"interface":"wg123456789ab","dns_ipv4":"10.2.0.1",
                           "table":32101,"priority":12101}}


class AtomicCutoverTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.directory=Path(tmp.name)
        patcher=patch.object(agent,"JOURNAL_DIR",self.directory)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.operations=[]
        self.fail_nft_apply=False

    def simulated_run(self,*args,**kwargs):
        parts=list(args)
        self.operations.append(parts)
        if args[0]==agent.IP and "route" in args:
            if "show" in args:
                output=json.dumps([{"dst":PIHOLE,"dev":BRIDGE}])
            elif "get" in args and "1.1.1.1" in args:
                output="1.1.1.1 from "+HOST+" dev wg123456789ab table 32101"
            elif "get" in args:
                output=PIHOLE+" from "+HOST+" dev "+BRIDGE+" table 32101"
            else:output=""
        elif args[0]==agent.NFT and "list" in args:
            output="table inet"
        else:
            output=""
        if self.fail_nft_apply and args[:3]==(agent.NFT,"-f","-"):
            self.fail_nft_apply=False
            raise RuntimeError("simulated atomic nft install failure")
        return SimpleNamespace(returncode=0,stdout=output,stderr="")

    def mocks(self):
        return (patch.object(agent,"state_for",return_value=policy()),
                patch.object(agent,"port_preflight",return_value="172.30.7.1"),
                patch.object(agent,"run",side_effect=self.simulated_run))

    def test_timer_armed_before_any_policy_mutation_and_rollback_complete(self):
        with self.mocks()[0],self.mocks()[1],self.mocks()[2]:
            result=agent.apply(PID,PIHOLE,BRIDGE,"qa-pihole",120)
            self.assertTrue(result["active"])
            timer=next(i for i,x in enumerate(self.operations)
                       if x and x[0]=="/usr/bin/systemd-run")
            first_route=next(i for i,x in enumerate(self.operations)
                             if x and x[0]==agent.IP and "replace" in x)
            first_apply=next(i for i,x in enumerate(self.operations)
                             if x[:3]==[agent.NFT,"-f","-"])
            self.assertLess(timer,first_route)
            self.assertLess(first_route,first_apply)
            self.assertTrue(agent.journal_path(PID).is_file())
            self.assertEqual(agent.journal_path(PID).stat().st_mode&0o777,0o600)
            result=agent.rollback(PID)
            self.assertTrue(result["restored"])
            self.assertFalse(agent.journal_path(PID).exists())
            revert=next(i for i,x in enumerate(self.operations)
                        if i>first_apply and x[:3]==[agent.NFT,"-f","-"])
            del_route=next(i for i,x in enumerate(self.operations)
                           if x and x[0]==agent.IP and "del" in x)
            self.assertLess(revert,del_route)

    def test_apply_failure_restores_dns_guard_and_route(self):
        self.fail_nft_apply=True
        with self.mocks()[0],self.mocks()[1],self.mocks()[2]:
            with self.assertRaisesRegex(RuntimeError,"simulated atomic"):
                agent.apply(PID,PIHOLE,BRIDGE,"qa-pihole",120)
            self.assertFalse(agent.journal_path(PID).exists())
            self.assertTrue(any(x and x[0]==agent.IP and "del" in x
                                for x in self.operations))

    def test_rollback_preserves_newer_host_policy_without_stale_guard(self):
        with self.mocks()[0],self.mocks()[1],self.mocks()[2]:
            agent.apply(PID,PIHOLE,BRIDGE,"qa-pihole",120)
        point=len(self.operations)
        newer=policy()
        newer["plan"]["destination"]="direct"
        newer.pop("vpn_runtime")
        with patch.object(agent,"state_for",return_value=newer), \
             patch.object(agent,"run",side_effect=self.simulated_run):
            result=agent.rollback(PID)
        self.assertFalse(result["restored"])
        self.assertTrue(result["newer_policy_preserved"])
        operations=self.operations[point:]
        self.assertFalse(any(x[:3]==[agent.NFT,"-f","-"] for x in operations),
                         "Stale VPN guard must not overwrite newer DIRECT policy")
        self.assertTrue(any(x and x[0]==agent.IP and "del" in x for x in operations),
                        "Transient Pi-hole host route must still be removed")

    def test_lock_serialization_uses_agent_kernel_lock(self):
        with patch.object(agent.fcntl,"flock", wraps=agent.fcntl.flock) as flock:
            with agent.agent_policy_lock():
                with agent.agent_policy_lock():
                    self.assertEqual(agent._REENTRY.depth, 2)
            self.assertEqual(flock.call_count,2)

    def test_existing_journal_is_refused(self):
        agent.save_journal(PID,{"status":"armed"})
        with self.mocks()[0],self.mocks()[1],self.mocks()[2]:
            with self.assertRaisesRegex(ValueError,"Unresolved previous"):
                agent.apply(PID,PIHOLE,BRIDGE,"qa-pihole",120)

    def test_invalid_period_cannot_arm_network_change(self):
        with self.assertRaisesRegex(ValueError,"deadline"):
            agent.apply(PID,PIHOLE,BRIDGE,"qa-pihole",5)

if __name__=="__main__":
    unittest.main()
