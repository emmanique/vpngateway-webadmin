import importlib.util
import subprocess
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[3] / "scripts" / "vpngw-vpn-transition.py"
spec = importlib.util.spec_from_file_location("vpngw_transition", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class TestVpnTransition(unittest.TestCase):
    def make(self, **changes):
        kwargs = dict(profile="proton-test", host="10.55.8.17", lan="enp3s0",
                      vpn="wg123456789ab", management_ip="10.55.8.1",
                      vpn_dns="10.2.0.1", client_mac="7c:b5:66:9e:f7:be")
        kwargs.update(changes)
        return module.render(**kwargs)

    def test_nft_syntax_in_lab(self):
        result = subprocess.run(["nft", "-c", "-f", "-"], input=self.make()["nft"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_per_client_ipv6_and_dns_guard(self):
        nft = self.make()["nft"]
        self.assertIn("ether saddr 7c:b5:66:9e:f7:be meta nfproto ipv6", nft)
        self.assertIn("ip saddr 10.55.8.17 ip daddr 10.55.8.1 udp dport 53", nft)
        self.assertIn("dnat to 10.2.0.1", nft)
        self.assertIn('oifname != "wg123456789ab"', nft)
        self.assertNotIn("flush ruleset", nft)
        self.assertNotIn("wlp2s0", nft)
        self.assertFalse(self.make()["applied"])

    def test_portable_across_lan_wan_modes(self):
        for iface, host, management in (("br-lan", "172.24.1.22", "172.24.1.1"),
                                        ("wlan0", "192.168.77.23", "192.168.77.9"),
                                        ("eth0.7", "10.10.7.20", "10.10.7.1")):
            with self.subTest(iface=iface):
                nft = self.make(lan=iface, host=host, management_ip=management)["nft"]
                self.assertIn(f'iifname "{iface}"', nft)
                self.assertIn(f"ip saddr {host}", nft)

    def test_reject_unverified_mac_and_invalid_dns(self):
        for changes in ({"client_mac": ""}, {"client_mac": "00:00:00:00:00:00"},
                        {"vpn_dns": "10.55.8.17"}, {"vpn_dns": "10.55.8.1"},
                        {"vpn": "enp3s0"}, {"host": "10.55.8.1"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.make(**changes)

if __name__ == "__main__":
    unittest.main()
