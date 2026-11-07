"""Regression: early-boot VPN protection follows MAC, not a stale DHCP IPv4."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "vpngw-vpn-boot-guard.py"
SPEC = importlib.util.spec_from_file_location("vpngw_vpn_boot_guard", SOURCE)
boot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boot)

CONFIG = {
    "id": "mediahub", "host": "192.168.1.199",
    "lan": "enp6s18", "vpn": "wge99015ff58b",
    "mac": "aa:bb:cc:dd:ee:ff", "confirmed": True,
}


class BootGuardIdentityTests(unittest.TestCase):
    def test_ipv4_egress_and_dns_are_mac_scoped_after_dhcp_renumber(self):
        rules = boot.render(CONFIG)
        self.assertIn("ether saddr aa:bb:cc:dd:ee:ff meta nfproto ipv4 oifname !=", rules)
        self.assertIn("ether saddr aa:bb:cc:dd:ee:ff udp dport 53 counter drop", rules)
        self.assertIn("ether saddr aa:bb:cc:dd:ee:ff tcp dport 53 counter drop", rules)
        self.assertNotIn("ip saddr 192.168.1.199 oifname !=", rules)
        self.assertNotIn("ip saddr 192.168.1.199 udp dport 53", rules)

    def test_legacy_ip_only_guard_is_replaced_in_single_atomic_nft_batch(self):
        old = "table inet vpngw_boot_mediahub { meta nfproto ipv6 " + (
            "aa:bb:cc:dd:ee:ff enp6s18 wge99015ff58b "
            "oifname != udp dport 53 tcp dport 53") + " }"
        observed = []
        def fake_run(args, **kwargs):
            observed.append((args, kwargs.get("input")))
            return subprocess.CompletedProcess(args, 0, stdout=old)
        with patch.object(boot, "records", return_value=iter((CONFIG,))), \
             patch.object(boot.subprocess, "run", side_effect=fake_run):
            result = boot.reconcile(Path("."))
        self.assertEqual(result, ["mediahub"])
        self.assertEqual(len(observed), 3)
        self.assertEqual(observed[1][0][1:], ["-c", "-f", "-"])
        self.assertEqual(observed[2][0][1:], ["-f", "-"])
        for _, batch in observed[1:]:
            self.assertTrue(batch.startswith("delete table inet vpngw_boot_mediahub\n"))
            self.assertIn("meta nfproto ipv4", batch)

if __name__ == "__main__":
    unittest.main()
