"""Offline nftables desired-state tests; never mutate the runner firewall."""
import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "vpngw-port-forward.py"
spec = importlib.util.spec_from_file_location("vpngw_port_forward", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def state(route="direct", interface="ens18"):
    base = {"status": "active", "applied": True,
            "plan": {"host": "192.168.1.199", "wan": "ens18",
                     "destination": route, "registered_mac": "aa:bb:cc:dd:ee:ff"}}
    if route != "direct":
        base["vpn_runtime"] = {"interface": interface}
    return base


def selection(route="direct", interface=None, protocol="tcp", port=6881):
    return {"host_ip": "192.168.1.199", "route": route,
            "vpn_interface": interface, "vpn_connected": True,
            "ingress_ipv4": ["192.168.1.231"] if route == "direct" else ["10.2.0.2"],
            "mappings": [{"protocol": p, "internal_port": 6881 if route == "direct" else port,
                          "external_port": port}
                         for p in (protocol, "udp" if protocol == "tcp" else "tcp")]}


class PortForwardNftTests(unittest.TestCase):
    def test_direct_targets_only_confirmed_ingress_ip(self):
        script, plan = module.nft_script(selection(), state())
        self.assertIn('iifname "ens18" ip daddr 192.168.1.231 tcp dport 6881', script)
        self.assertIn('dnat to 192.168.1.199:6881', script)
        self.assertNotIn("add chain ip vpngw_port_forward forward", script)
        self.assertEqual(plan["host"], "192.168.1.199")

    def test_vpn_udp_only_is_rejected_without_direct_fallback(self):
        request = selection("proton", "wgsecure", "udp", 36131)
        request["mappings"] = request["mappings"][:1]
        with self.assertRaises(module.ForwardingError):
            module.nft_script(request, state("proton", "wgsecure"))
        with self.assertRaises(module.ForwardingError):
            module.nft_script(selection("proton", "ens18", "udp", 36131),
                              state("proton", "wgsecure"))

    def test_vpn_refuses_translation_to_old_6881_port(self):
        request = selection("proton", "wgsecure", "tcp", 36131)
        request["mappings"][0]["internal_port"] = 6881
        with self.assertRaises(module.ForwardingError):
            module.nft_script(request, state("proton", "wgsecure"))

    def test_conflicting_provider_tcp_udp_ports_rejected(self):
        request = selection("proton", "wgsecure", "tcp", 36131)
        request["mappings"][1]["external_port"] = 36132
        request["mappings"][1]["internal_port"] = 36132
        with self.assertRaises(module.ForwardingError):
            module.nft_script(request, state("proton", "wgsecure"))

    def test_no_active_policy_no_forwarding(self):
        invalid = state()
        invalid["applied"] = False
        with self.assertRaises(module.ForwardingError):
            module.nft_script(selection(), invalid)

    def test_disconnect_rejects_vpn_mapping(self):
        request = selection("proton", "wgsecure", "udp", 36131)
        request["vpn_connected"] = False
        with self.assertRaises(module.ForwardingError):
            module.nft_script(request, state("proton", "wgsecure"))

    def test_empty_selection_drops_only_owned_table(self):
        script, plan = module.nft_script(None, None, table_exists=True)
        self.assertEqual(script, "delete table ip vpngw_port_forward\n")
        self.assertIsNone(plan)

    def test_bad_host_and_port_rejected(self):
        bad = selection()
        bad["host_ip"] = "127.0.0.1"
        with self.assertRaises(module.ForwardingError):
            module.nft_script(bad, state())
        bad = selection()
        bad["mappings"][0]["external_port"] = 0
        with self.assertRaises(module.ForwardingError):
            module.nft_script(bad, state())

    def test_different_owner_or_route_denied(self):
        wrong = state()
        wrong["plan"]["host"] = "192.168.1.229"
        with self.assertRaises(module.ForwardingError):
            module.nft_script(selection(), wrong)
        wrong = state("blocked")
        with self.assertRaises(module.ForwardingError):
            module.nft_script(selection(), wrong)


if __name__ == "__main__":
    unittest.main()
