"""MAC-bound policy filters must fail closed after a client IPv4 changes."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"),
                                                  SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


basic = load("vpngw-basic-transition-batch")
vpn = load("vpngw-vpn-filter-batch")
agent = load("vpngw-policy-agent")
MAC = "aa:bb:cc:dd:ee:ff"
OLD = "192.168.1.199"
LAN = "enp6s18"
PID = "host-a"


class RenumberGuardTests(unittest.TestCase):
    def test_direct_and_blocked_transitions_drop_changed_ip_by_mac(self):
        plan = {"host": OLD, "lan": LAN, "wan": LAN, "registered_mac": MAC}
        for route in ("direct", "blocked"):
            script = basic.batch(PID, plan, route)
            self.assertIn(f"ether saddr {MAC} ip saddr != {OLD} drop", script)
            self.assertIn('vpngw_ip_rebind_guard', script)

    def test_vpn_transition_retains_mac_based_changed_ip_drop(self):
        script = vpn.generate(PID, OLD, MAC, LAN, "wge99015ff58b")
        self.assertIn(f"ether saddr {MAC} ip saddr != {OLD} drop", script)
        self.assertIn('vpngw_ip_rebind_guard', script)

    def test_identity_update_stages_mac_jump_and_drop_atomically(self):
        chain = agent.chain_name(PID)
        outdated = (f'ip saddr {OLD} ether saddr != {MAC} '
                    f'drop comment "vpngw_identity_guard" # handle 12')
        state = {"applied": False}
        batch_calls = []

        def run(*args, input_text=None):
            if args[1:4] == ("-a", "list", "chain"):
                if args[-1] == chain:
                    return subprocess.CompletedProcess(args, 0, stdout=outdated)
                return subprocess.CompletedProcess(args, 0,
                    stdout=f'ip saddr {OLD} jump {chain} # handle 9')
            if args[1:4] == ("list", "chain", "ip"):
                if args[-1] == chain:
                    txt = outdated + ("\n" +
                        f'ether saddr {MAC} ip saddr != {OLD} drop '
                        'comment "vpngw_ip_rebind_guard"' if state["applied"] else "")
                else:
                    txt = (f'ether saddr {MAC} jump {chain}' if state["applied"] else "")
                return subprocess.CompletedProcess(args, 0, stdout=txt)
            if args[1:4] == ("-c", "-f", "-"):
                batch_calls.append(("check", input_text))
            if args[1:4] == ("-f", "-"):
                batch_calls.append(("apply", input_text))
                state["applied"] = True
            return subprocess.CompletedProcess(args, 0, stdout="")

        with patch.object(agent, "run", side_effect=run):
            agent._set_kernel_identity_guard(PID, MAC,
                {"host": OLD, "lan": LAN, "registered_mac": MAC})
        self.assertEqual([x[0] for x in batch_calls], ["check", "apply"])
        self.assertIn(f"ether saddr {MAC} jump {chain}", batch_calls[0][1])
        self.assertIn(f"ether saddr {MAC} ip saddr != {OLD}", batch_calls[0][1])

if __name__ == "__main__":
    unittest.main()
