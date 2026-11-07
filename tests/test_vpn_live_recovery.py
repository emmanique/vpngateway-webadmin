import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "scripts" / "vpngw-policy-agent.py"
spec = importlib.util.spec_from_file_location("recovery_agent", SRC)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class TestReturnedVpnRoutes(unittest.TestCase):
    def exercise(self, *, route_ok=False, tunnel_up=True, pending=False, destination="vpn-test",
                 status="active", reason=None):
        import tempfile
        import json
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = {"status": status, "reason": reason, "vpn_pending": pending,
                     "plan": {"host": "198.51.100.22", "lan": "lan7", "destination": destination},
                     "vpn_runtime": {"interface": "tun-test"}}
            (root / "qa-test.json").write_text(json.dumps(state))
            (root / "invalid.json").write_text("invalid")
            result = SimpleNamespace(returncode=0 if route_ok else 2,
                                     stdout='[{"dev":"tun-test"}]' if route_ok else "")
            with patch.object(agent, "BASE", root), \
                    patch.object(agent.subprocess, "run", return_value=result), \
                    patch.object(agent, "vpn_tunnel_status", return_value={"interface": "tun-test", "connected": True} if tunnel_up else {}), \
                    patch.object(agent, "recover_active_policy") as recover:
                agent.reconcile_returned_vpn_routes()
                return recover.call_count

    def test_returned_tunnel_restores_missing_client_route(self):
        self.assertEqual(self.exercise(), 1)

    def test_healthy_route_is_not_rebuilt(self):
        self.assertEqual(self.exercise(route_ok=True), 0)

    def test_stopped_tunnel_keeps_guard_and_is_not_reconnected(self):
        self.assertEqual(self.exercise(tunnel_up=False), 0)

    def test_pending_transition_is_left_to_rollback_watchdog(self):
        self.assertEqual(self.exercise(pending=True), 0)

    def test_direct_policy_is_not_changed(self):
        self.assertEqual(self.exercise(destination="direct"), 0)

    def test_transient_boot_error_retries_after_topology_returns(self):
        transient = "Recuperação após reinício falhou: Interface WAN/LAN mudou desde a confirmação"
        self.assertEqual(self.exercise(status="error", reason=transient, route_ok=True), 1)

    def test_unrelated_error_must_not_auto_restore(self):
        self.assertEqual(self.exercise(status="error",
                        reason="Host MAC identity mismatch"), 0)

    def test_recovered_error_becomes_active_only_after_sync(self):
        import json
        state = {"status": "error", "reason": "temporary topology error",
                 "plan": {"destination": "vpn-test"}, "vpn_runtime": {"interface": "tun-test"}}
        saved=[]
        def sync(pid, record):
            self.assertEqual(record["status"], "active")
        def write(pid, record):
            saved.append(record)
        with patch.object(agent, "sync_boot_policy", side_effect=sync), \
             patch.object(agent, "save_state", side_effect=write):
            agent.complete_recovered_vpn_policy("qa-host", state)
        self.assertEqual(len(saved), 1)
        self.assertTrue(saved[0]["applied"])
        self.assertEqual(saved[0]["status"], "active")
        self.assertNotIn("reason", saved[0])
        self.assertEqual(state["status"], "error", "Original state must not be silently mutated")
