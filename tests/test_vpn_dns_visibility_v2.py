"""Provider-DNS fallback is exposed accurately; standard DoT is blocked."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / "scripts/vpngw-vpn-host-guard.py"
spec = importlib.util.spec_from_file_location("dns_guard_v2", source)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class VpnDnsGuard(unittest.TestCase):
    def setUp(self):
        self.text = guard.render(
            "qa-host", "192.168.33.22", "02:aa:bb:cc:dd:ee",
            "eth2", "wgtest0", "10.2.0.1"
        )

    def test_provider_dns_redirect_cannot_be_confused_with_pihole(self):
        self.assertIn("udp dport 53 dnat ip to 10.2.0.1", self.text)
        self.assertIn("tcp dport 53 dnat ip to 10.2.0.1", self.text)
        self.assertIn('ip saddr 192.168.33.22 oifname != "wgtest0"', self.text)

    def test_dot_and_doq_on_853_are_denied(self):
        self.assertIn("ether saddr 02:aa:bb:cc:dd:ee tcp dport 853 counter drop", self.text)
        self.assertIn("ether saddr 02:aa:bb:cc:dd:ee udp dport 853 counter drop", self.text)

    def test_do_not_claim_doh_443_is_blocked(self):
        self.assertNotIn("tcp dport 443 counter drop", self.text)


class DnsStatusTransparency(unittest.TestCase):
    def test_vpn_clients_report_unverified_pihole_filtering(self):
        import sys
        sys.path.insert(0, str(ROOT / "apps/api"))
        try:
            import main
        except ModuleNotFoundError as exc:
            self.skipTest("Run API contract under the application dependency image: " + str(exc))
        with patch.object(main, "_policies", {
                "a": {"destination": "vpn-qa", "host_ip": "192.168.33.22"},
                "b": {"destination": "direct", "host_ip": "192.168.33.23"}}), \
             patch.object(main, "dns_summary", return_value={"reachable": True, "admin_url": "https://test/admin/"}), \
             patch("urllib.request.urlopen", side_effect=OSError("offline")):
            response = main.dns_live_dashboard()
            self.assertEqual(response["vpn_assigned_clients"], 1)
            self.assertEqual(response["vpn_dns_path"], "provider_dns_via_tunnel")
            self.assertFalse(response["pihole_filtering_verified_for_vpn_hosts"])


if __name__ == "__main__":
    unittest.main()
