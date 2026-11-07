import importlib.util
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[3] / "scripts" / "vpngw-vpn-recovery-plan.py"
spec = importlib.util.spec_from_file_location("vpngw_vpn_recovery", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class TestVpnRecoveryPlan(unittest.TestCase):
    def config(self):
        return {"id": "example-host", "host": "10.50.1.22",
                "lan": "enp3s0", "vpn": "wg123456789ab",
                "mac": "12:34:56:78:9a:bc", "confirmed": True}

    def plan(self, **changes):
        flags = dict(observed_lan=True, observed_vpn=True,
                     guard_installed=True, verified_mac=True,
                     vpn_handshake=True)
        flags.update(changes)
        return mod.build(self.config(), **flags)

    def test_recovery_plan_is_read_only_and_private(self):
        p = self.plan()
        self.assertTrue(p["ready"])
        self.assertFalse(p["applied"])
        self.assertEqual(len(p["commands"]), 3)
        self.assertTrue(all("main" not in " ".join(cmd) for cmd in p["commands"]))
        self.assertIn("unreachable", p["commands"][0])
        self.assertIn("wg123456789ab", p["commands"][1])
        self.assertIn("10.50.1.22/32", p["commands"][2])

    def test_missing_boot_guard_blocks(self):
        p = self.plan(guard_installed=False)
        self.assertFalse(p["ready"])
        self.assertIn("boot_guard_active", p["missing"])

    def test_missing_handshake_blocks(self):
        p = self.plan(vpn_handshake=False)
        self.assertFalse(p["ready"])
        self.assertIn("vpn_handshake_recent", p["missing"])

    def test_unverified_client_blocks(self):
        p = self.plan(verified_mac=False)
        self.assertFalse(p["ready"])

    def test_different_clients_get_independent_tables(self):
        first = self.plan()
        second_config = {**self.config(), "id": "other-host", "host": "10.50.1.23"}
        second = mod.build(second_config, observed_lan=True, observed_vpn=True,
                           guard_installed=True, verified_mac=True,
                           vpn_handshake=True)
        self.assertNotEqual(first["table"], second["table"])
        self.assertNotEqual(first["priority"], second["priority"])

    def test_reject_unconfirmed(self):
        cfg = self.config()
        cfg["confirmed"] = False
        with self.assertRaises(ValueError):
            mod.build(cfg, observed_lan=True, observed_vpn=True,
                      guard_installed=True, verified_mac=True, vpn_handshake=True)

if __name__ == "__main__":
    unittest.main()
