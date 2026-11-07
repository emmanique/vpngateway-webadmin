"""Protocol-neutral, offline safety tests; never touch kernel state."""
import importlib.util
from pathlib import Path
import unittest

SOURCE=Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-boot-guard.py"
spec=importlib.util.spec_from_file_location("vpn_boot_guard",SOURCE)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class TestBootGuard(unittest.TestCase):
    def base(self,interface):
        return {"id":"testvpn","host":"192.168.1.227","lan":"wlp2s0",
                "vpn":interface,"mac":"bc:24:11:d3:7b:e3","confirmed":True}
    def test_wireguard(self):
        self.assertEqual(mod.validate(self.base("wga509c86fbd2"))["vpn"],"wga509c86fbd2")
    def test_openvpn_proton(self):
        self.assertEqual(mod.validate(self.base("tun6eb314b8b6"))["vpn"],"tun6eb314b8b6")
    def test_openvpn_cyberghost(self):
        rules=mod.render(self.base("tuna713bb390e"))
        self.assertIn('oifname != "tuna713bb390e"',rules)
        self.assertIn('meta nfproto ipv6 counter drop',rules)
        self.assertIn("udp dport 53 counter drop",rules)
    def test_reject_bad_interfaces(self):
        for interface in ["eth0","tun1","tunxxxxxxxxxx","wga509c86fbd2;rm"]:
            with self.subTest(interface=interface),self.assertRaises(ValueError):
                mod.validate(self.base(interface))
    def test_unconfirmed_rejected(self):
        entry=self.base("tun6eb314b8b6")
        entry["confirmed"]=False
        with self.assertRaises(ValueError):
            mod.validate(entry)
if __name__=="__main__":
    unittest.main()
