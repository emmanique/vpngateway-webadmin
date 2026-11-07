import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("boot_sync_agent", ROOT / "scripts/vpngw-policy-agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

class BootSyncTests(unittest.TestCase):
    def setUp(self):
        self.state = {"status": "active", "plan": {"host": "192.168.50.20", "lan": "eth0",
                      "destination": "vpn-test", "registered_mac": "02:00:00:00:00:20"},
                      "vpn_runtime": {"interface": "wg123456789ab"}}
        self.guard = "192.168.50.20 eth0 wg123456789ab 02:00:00:00:00:20 drop"
    def test_confirmed_guard_is_persisted_privately(self):
        with tempfile.TemporaryDirectory() as d, patch.object(agent.subprocess, "run", return_value=SimpleNamespace(returncode=1)), patch.object(agent, "run", return_value=SimpleNamespace(stdout=self.guard)):
            agent.sync_boot_policy("client-test", self.state, d)
            p = Path(d) / "client-test.json"
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            self.assertTrue(json.loads(p.read_text())["confirmed"])
    def test_missing_guard_refuses_persistence(self):
        with tempfile.TemporaryDirectory() as d, patch.object(agent.subprocess, "run", return_value=SimpleNamespace(returncode=1)), patch.object(agent, "run", return_value=SimpleNamespace(stdout="")):
            with self.assertRaises(ValueError):
                agent.sync_boot_policy("client-test", self.state, d)
            self.assertFalse((Path(d) / "client-test.json").exists())
    def test_direct_transition_removes_old_guard_and_file(self):
        with tempfile.TemporaryDirectory() as d, patch.object(agent.subprocess, "run", return_value=SimpleNamespace(returncode=0)), patch.object(agent, "run") as command:
            p = Path(d) / "client-test.json"
            p.write_text("{}")
            self.state["plan"]["destination"] = "direct"
            agent.sync_boot_policy("client-test", self.state, d)
            self.assertFalse(p.exists())
            command.assert_called_once_with(agent.NFT, "delete", "table", "inet", "vpngw_boot_client_test")
    def test_trial_preserves_last_confirmed_boot_config(self):
        with tempfile.TemporaryDirectory() as d, patch.object(agent.subprocess, "run", return_value=SimpleNamespace(returncode=0)), patch.object(agent, "run"):
            p = Path(d) / "client-test.json"
            p.write_text("previous-confirmed-config")
            self.state["vpn_pending"] = {"previous": "vpn-old"}
            agent.sync_boot_policy("client-test", self.state, d)
            self.assertEqual(p.read_text(), "previous-confirmed-config")
    def test_purge_removes_persistent_config(self):
        with tempfile.TemporaryDirectory() as d, patch.object(agent.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
            p = Path(d) / "client-test.json"
            p.write_text("{}")
            agent.sync_boot_policy("client-test", None, d)
            self.assertFalse(p.exists())
