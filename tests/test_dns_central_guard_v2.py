"""Central Pi-hole bridge plans must preserve VPN restrictions and MAC checks."""
import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]/"scripts"

def load(name):
    spec=importlib.util.spec_from_file_location(name.replace("-","_"),ROOT/(name+".py"))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

guard=load("vpngw-vpn-host-guard")
filter_=load("vpngw-vpn-filter-batch")
P={"pihole_ipv4":"172.19.9.2","bridge_interface":"brdns0"}
HOST="192.168.33.22"
MAC="02:ee:dd:cc:bb:aa"

class PiHoleGuard(unittest.TestCase):
    def test_bridge_53_only_and_suppress_provider_dns_dnat(self):
        text=guard.render("qa-host",HOST,MAC,"lan0","wg0",central_dns=P)
        self.assertIn("dnat ip to 172.19.9.2",text)
        self.assertIn('oifname "brdns0" ip daddr 172.19.9.2 udp dport 53 counter accept',text)
        self.assertIn('oifname != "wg0" counter drop',text)
        self.assertIn('meta nfproto ipv6 counter drop',text)
        self.assertIn('tcp dport 853 counter drop',text)
        self.assertNotIn("10.2.0.1",text)

    def test_legacy_host_filter_allow_bridge_only_for_dns(self):
        text=filter_.generate("qa-host",HOST,MAC,"lan0","wg0",central_dns=P)
        self.assertIn('oifname "brdns0" ip saddr',text)
        self.assertIn('ip daddr 172.19.9.2 udp dport 53 counter accept',text)
        self.assertIn('ether saddr != '+MAC+' drop',text)
        self.assertIn('oifname "wg0"',text)

    def test_no_implicit_central_mode(self):
        text=guard.render("qa-host",HOST,MAC,"lan0","wg0","10.2.0.1")
        self.assertIn("dnat ip to 10.2.0.1",text)
        self.assertNotIn("brdns0",text)

    def test_mixed_dnats_rejected(self):
        with self.assertRaises(ValueError):
            guard.render("qa-host",HOST,MAC,"lan0","wg0","10.2.0.1",central_dns=P)

    def test_untrusted_bridge_is_rejected(self):
        for data in ({"pihole_ipv4":"127.0.0.1","bridge_interface":"br0"},
                     {"pihole_ipv4":"172.19.9.2","bridge_interface":"lan0"},
                     {"pihole_ipv4":"8.8.8.8","bridge_interface":"br0"}):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    guard.render("qa-host",HOST,MAC,"lan0","wg0",central_dns=data)


if __name__=="__main__":
    unittest.main()
