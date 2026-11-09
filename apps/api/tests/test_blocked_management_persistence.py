from pathlib import Path
from unittest.mock import patch
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("policy_recovery_test", ROOT / "scripts/vpngw-policy-agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class BlockedManagementRecovery(unittest.TestCase):
    def test_reinstall_blocked_policy_restores_https_exception(self):
        plan = {"destination": "blocked", "host": "192.168.1.249", "lan": "ens18",
                "wan": "ens18", "registered_mac": "7c:b5:66:9e:f7:be"}
        with patch.object(agent, "exists_chain", return_value=True), patch.object(agent, "run"), patch.object(
            agent, "ensure_blocked_management"
        ) as ensure:
            agent.install_rules(plan, "lenovo")
            ensure.assert_called_once_with("lenovo", plan)

    def test_missing_mac_fails_closed(self):
        with self.assertRaises(ValueError):
            agent.ensure_blocked_management("lenovo", {
                "destination": "blocked", "host": "192.168.1.249", "lan": "ens18"})
