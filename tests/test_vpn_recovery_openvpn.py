"""Verified OpenVPN and WireGuard recovery plans remain fail-closed."""
import importlib.util
from pathlib import Path
import unittest

SRC = Path(__file__).resolve().parents[1] / "scripts" / "vpngw-vpn-recovery-plan.py"
spec = importlib.util.spec_from_file_location("vpngw_recovery_plan", SRC)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class VpnRecoveryProtocolTests(unittest.TestCase):
    def config(self, iface):
        return {"id": "caio", "host": "192.168.1.229", "lan": "ens18",
                "vpn": iface, "mac": "bc:25:11:5b:59:e1", "confirmed": True}

    def plan(self, iface, **overrides):
        flags = {"observed_lan": True, "observed_vpn": True,
                 "guard_installed": True, "verified_mac": True,
                 "vpn_handshake": True}
        flags.update(overrides)
        return mod.build(self.config(iface), **flags)

    def test_openvpn_tun_recovery_plan_accepted(self):
        plan = self.plan("tun94a8f84e48")
        self.assertTrue(plan["ready"])
        self.assertFalse(plan["applied"])
        self.assertEqual(plan["vpn"], "tun94a8f84e48")
        self.assertIn("unreachable", plan["commands"][0])
        self.assertEqual(plan["commands"][1][6], "tun94a8f84e48")
        self.assertNotIn("main", repr(plan["commands"]))

    def test_wireguard_recovery_remains_supported(self):
        self.assertTrue(self.plan("wg6321b7863b0")["ready"])

    def test_missing_tunnel_never_readies_recovery(self):
        plan = self.plan("tun94a8f84e48", observed_vpn=False)
        self.assertFalse(plan["ready"])
        self.assertIn("vpn_interface_up", plan["missing"])

    def test_missing_boot_guard_never_readies_recovery(self):
        plan = self.plan("tun94a8f84e48", guard_installed=False)
        self.assertFalse(plan["ready"])
        self.assertIn("boot_guard_active", plan["missing"])

    def test_mac_identity_mismatch_blocks_recovery(self):
        plan = self.plan("tun94a8f84e48", verified_mac=False)
        self.assertFalse(plan["ready"])

    def test_reject_untrusted_interface_and_unconfirmed_host(self):
        for interface in ("eth0", "tun0", "tun123", "tun94a8f84e48;rm", "wg0"):
            with self.subTest(interface=interface), self.assertRaises(ValueError):
                mod.validate(self.config(interface))
        cfg = self.config("tun94a8f84e48")
        cfg["confirmed"] = False
        with self.assertRaises(ValueError):
            mod.validate(cfg)


if __name__ == "__main__":
    unittest.main()
