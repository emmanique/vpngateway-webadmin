import importlib.util
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[3] / "scripts" / "vpngw-vpn-route-plan.py"
spec = importlib.util.spec_from_file_location("vpngw_plan", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestVpnRoutePlan(unittest.TestCase):
    def plan(self, **updates):
        data = dict(host_ip="192.168.1.249", gateway_ip="192.168.1.1",
                    lan_iface="wlp2s0", vpn_iface="wga509c86fbd2",
                    vpn_profile="vpn-proton-wire", host_route="direct",
                    handshake=True, ipv6_default=False, dns_isolated=False)
        data.update(updates)
        return module.build_plan(**data)

    def test_never_applied_until_dns_and_atomic_transition_ready(self):
        result = self.plan()
        self.assertFalse(result["applied"])
        self.assertFalse(result["ready"])
        self.assertTrue(any("DNS" in b for b in result["blockers"]))
        self.assertTrue(any("revers" in b.lower() for b in result["blockers"]))

    def test_scope_only_client(self):
        result = self.plan()
        self.assertIn("from 192.168.1.249/32", result["routing"]["policy_rule"])
        self.assertIn("iif wlp2s0", result["routing"]["policy_rule"])
        self.assertNotIn("192.168.1.221", result["routing"]["policy_rule"])
        self.assertIn("oifname != wga509c86fbd2", result["firewall"]["client_forward"])
        self.assertIn("unreachable", result["routing"]["unreachable_fallback"])

    def test_lab_filter_scoped_to_client_and_dns_input(self):
        fixture = module.render_lab_nft(self.plan())
        self.assertIn('chain local_dns_guard', fixture)
        self.assertIn('chain forwarded_guard', fixture)
        self.assertIn('ip saddr 192.168.1.249 udp dport 53', fixture)
        self.assertIn('ip saddr 192.168.1.249 tcp dport 53', fixture)
        self.assertIn('oifname != "wga509c86fbd2"', fixture)
        self.assertNotIn('meta nfproto ipv6 drop', fixture)
        self.assertNotIn('flush ruleset', fixture)

    def test_ipv6_unverified_identity_not_executable(self):
        result = self.plan()
        self.assertIn("REQUIRES VERIFIED", result["firewall"]["ipv6_guard"])

    def test_portable_across_different_installations(self):
        for host, gateway, lan, vpn, profile in [
            ("10.66.4.17", "10.66.4.1", "enp3s0", "wg123456789ab", "profile-home"),
            ("172.25.8.34", "172.25.8.1", "eth0.42", "wgabcdef01234", "profile-work"),
            ("192.168.77.16", "192.168.77.254", "br-lan", "wg987654321ab", "profile-test"),
        ]:
            with self.subTest(lan=lan):
                result = self.plan(host_ip=host, gateway_ip=gateway, lan_iface=lan,
                                   vpn_iface=vpn, vpn_profile=profile)
                self.assertIn(f"iif {lan} from {host}/32", result["routing"]["policy_rule"])
                self.assertIn(f"default dev {vpn}", result["routing"]["vpn_default"])
                self.assertIn(f"ip saddr {host}", module.render_lab_nft(result))
                self.assertFalse(result["applied"])

    def test_client_policy_priorities_are_distinct(self):
        clients = [self.plan(host_ip=f"10.77.1.{index}", gateway_ip="10.77.1.1")
                   for index in (17, 18, 19, 20, 21)]
        priorities = [p["routing"]["priority"] for p in clients]
        self.assertEqual(len(set(priorities)), len(priorities))
        for policy in clients:
            self.assertIn("pref " + str(policy["routing"]["priority"]), policy["routing"]["policy_rule"])
        self.assertEqual(len({p["routing"]["table_id"] for p in clients}), len(clients))

    def test_different_profiles_have_separate_routing_tables(self):
        first = self.plan(vpn_profile="vpn-east")
        second = self.plan(vpn_profile="vpn-west")
        self.assertNotEqual(first["routing"]["table_id"], second["routing"]["table_id"])

    def test_ipv6_route_rejected(self):
        self.assertTrue(any("IPv6" in b for b in self.plan(ipv6_default=True)["blockers"]))

    def test_guard_disabled_handshake_rejected(self):
        self.assertTrue(any("handshake" in b for b in self.plan(handshake=False)["blockers"]))

    def test_protect_router(self):
        with self.assertRaises(ValueError):
            self.plan(host_ip="192.168.1.1")

    def test_wrong_interface_rejected(self):
        with self.assertRaises(ValueError):
            self.plan(vpn_iface="wlp2s0")

    def test_management_default_route_not_touched(self):
        result = self.plan()
        self.assertNotIn("main", result["routing"]["vpn_default"])
        self.assertIn("table " + str(result["routing"]["table_id"]), result["routing"]["vpn_default"])
        self.assertEqual(result["status"], "proposal_only")


if __name__ == "__main__":
    unittest.main()
