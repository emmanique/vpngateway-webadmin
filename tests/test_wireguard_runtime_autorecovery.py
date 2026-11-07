"""WireGuard runtime recovery tests: no kernel or host-network changes."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "scripts" / "vpngw-policy-agent.py"
spec = importlib.util.spec_from_file_location("wg_runtime_agent", SRC)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

PROFILE = "vpn-qa-recovery"


class RuntimeWireGuardRecovery(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.state_dir = self.root / "state"
        self.state_dir.mkdir()
        self.profiles = self.root / "profiles"
        self.profiles.mkdir()
        (self.profiles / (PROFILE + ".conf")).write_text("[Interface]\n")
        self.patches = [
            patch.object(agent, "BASE", self.state_dir),
            patch.object(agent, "WG_RETRY_AFTER", {}),
            patch.dict(os.environ, {"VPNGW_WG_PROFILE_DIR": str(self.profiles)}),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def policy(self, name, profile=PROFILE, pending=False, status="active", interface=None):
        state = {"status": status, "plan": {
            "host": "192.0.2.22", "lan": "eth-test", "destination": profile},
            "vpn_runtime": {"interface": interface or agent.wireguard_iface(PROFILE),
                            "dns_ipv4": "10.3.0.1"}}
        if pending:
            state["vpn_pending"] = {"previous": "direct"}
        (self.state_dir / (name + ".json")).write_text(json.dumps(state))

    def test_lost_assigned_tunnel_recovers_once_without_reimport(self):
        self.policy("host-a")
        self.policy("host-b")
        with patch.object(agent, "wireguard_status", return_value={"interface": None}), \
             patch.object(agent, "wireguard_connect", return_value={}) as connect:
            agent.reconcile_missing_wireguard_profiles()
            connect.assert_called_once_with(PROFILE, "[Interface]\n")
            agent.reconcile_missing_wireguard_profiles()
            connect.assert_called_once()

    def test_operator_disconnect_is_durable_and_blocks_recovery(self):
        self.policy("host-a")
        with patch.object(agent, "wireguard_status", side_effect=[
                {"interface": agent.wireguard_iface(PROFILE)}, {"interface": None}]), \
             patch.object(agent, "run") as execute:
            agent.wireguard_disconnect(PROFILE)
            execute.assert_called_once()
        marker = agent.wireguard_paused_path(PROFILE)
        self.assertTrue(marker.is_file())
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        with patch.object(agent, "wireguard_status") as status, \
             patch.object(agent, "wireguard_connect") as connect:
            agent.reconcile_missing_wireguard_profiles()
            connect.assert_not_called()
            status.assert_not_called()

    def test_explicit_connect_clears_operator_pause(self):
        agent.set_wireguard_paused(PROFILE, True)
        self.assertTrue(agent.wireguard_paused_path(PROFILE).exists())
        agent.set_wireguard_paused(PROFILE, False)
        self.assertFalse(agent.wireguard_paused_path(PROFILE).exists())

    def test_pending_unconfirmed_cutover_is_excluded(self):
        self.policy("host-a", pending=True)
        with patch.object(agent, "wireguard_connect") as connect:
            agent.reconcile_missing_wireguard_profiles()
            connect.assert_not_called()

    def test_openvpn_interface_is_not_mistaken_for_wireguard(self):
        self.policy("host-a", interface="tun1122334455")
        with patch.object(agent, "wireguard_connect") as connect:
            agent.reconcile_missing_wireguard_profiles()
            connect.assert_not_called()

    def test_missing_or_symlinked_configuration_is_not_imported(self):
        self.policy("host-a")
        config = self.profiles / (PROFILE + ".conf")
        config.unlink()
        config.symlink_to(self.root / "missing")
        with patch.object(agent, "wireguard_status", return_value={"interface": None}), \
             patch.object(agent, "wireguard_connect") as connect:
            agent.reconcile_missing_wireguard_profiles()
            connect.assert_not_called()

    def test_manual_disconnect_does_not_reconnect_at_agent_boot(self):
        self.policy("host-a")
        agent.set_wireguard_paused(PROFILE, True)
        with patch.object(agent, "wireguard_connect") as connect, \
             patch.object(agent, "recover_active_policy") as restore:
            agent.restore_boot_vpn_profiles()
            connect.assert_not_called()
            restore.assert_not_called()

    def test_recreated_interface_triggers_route_reconciliation(self):
        self.policy("host-a")
        from types import SimpleNamespace
        with patch.object(agent.subprocess, "run", return_value=SimpleNamespace(returncode=2, stdout="")), \
             patch.object(agent, "vpn_tunnel_status",
                          return_value={"interface": agent.wireguard_iface(PROFILE), "connected": True}), \
             patch.object(agent, "recover_active_policy") as restore:
            agent.reconcile_returned_vpn_routes()
            restore.assert_called_once()

    def test_interface_exists_but_handshake_absent_does_not_rebuild_route(self):
        self.policy("host-a")
        from types import SimpleNamespace
        with patch.object(agent.subprocess, "run", return_value=SimpleNamespace(returncode=2, stdout="")), \
             patch.object(agent, "vpn_tunnel_status", return_value={
                 "interface": agent.wireguard_iface(PROFILE), "connected": False}), \
             patch.object(agent, "recover_active_policy") as restore:
            agent.reconcile_returned_vpn_routes()
            restore.assert_not_called()

    def test_disconnected_tunnel_does_not_rebuild_route(self):
        self.policy("host-a")
        from types import SimpleNamespace
        with patch.object(agent.subprocess, "run", return_value=SimpleNamespace(returncode=2, stdout="")), \
             patch.object(agent, "vpn_tunnel_status", return_value={}), \
             patch.object(agent, "recover_active_policy") as restore:
            agent.reconcile_returned_vpn_routes()
            restore.assert_not_called()


if __name__ == "__main__":
    unittest.main()
