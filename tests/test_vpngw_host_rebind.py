"""A changing IPv4 cannot transfer host policy ownership without fresh MAC evidence."""
import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "vpngw-host-rebind.py"
SPEC = importlib.util.spec_from_file_location("vpngw_host_rebind", SOURCE)
rebind = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rebind)

PLAN = {"host": "192.168.1.199", "lan": "enp6s18",
        "registered_mac": "aa:bb:cc:dd:ee:ff"}
LINK = [{"ifname": "enp6s18", "addr_info": [
    {"family": "inet", "local": "192.168.1.231", "prefixlen": 24}]}]


class RebindPreflightTests(unittest.TestCase):
    def neighbor(self, ip="192.168.1.205", mac="aa:bb:cc:dd:ee:ff",
                 state="REACHABLE", device="enp6s18"):
        return {"dst": ip, "lladdr": mac, "state": state, "dev": device}

    def test_unique_new_ip_with_registered_mac_is_candidate_only(self):
        result = rebind.candidate_from_neighbors(
            PLAN, [self.neighbor()], LINK, {"192.168.1.229"})
        self.assertTrue(result["changed"])
        self.assertEqual(result["candidate_ip"], "192.168.1.205")
        self.assertFalse(result["cutover_performed"])

    def test_same_ip_is_not_a_rebind(self):
        result = rebind.candidate_from_neighbors(
            PLAN, [self.neighbor("192.168.1.199")], LINK, set())
        self.assertFalse(result["changed"])

    def test_reject_stale_mac_conflict_and_other_network(self):
        for observed, occupied in (
            ([self.neighbor(state="STALE")], set()),
            ([self.neighbor(mac="aa:bb:cc:dd:ee:01")], set()),
            ([self.neighbor(), self.neighbor("192.168.1.206")], set()),
            ([self.neighbor()], {"192.168.1.205"}),
            ([self.neighbor(ip="192.168.2.205")], set()),
            ([self.neighbor(device="wlp2s0")], set()),
        ):
            with self.subTest(observed=observed, occupied=occupied):
                with self.assertRaises(rebind.RebindError):
                    rebind.candidate_from_neighbors(PLAN, observed, LINK, occupied)

    def test_reject_ambiguous_lan_subnets(self):
        two = [{"ifname": "enp6s18", "addr_info": [
            {"family": "inet", "local": "192.168.1.231", "prefixlen": 24},
            {"family": "inet", "local": "192.168.2.231", "prefixlen": 24}]}]
        with self.assertRaises(rebind.RebindError):
            rebind.candidate_from_neighbors(PLAN, [self.neighbor()], two, set())

if __name__ == "__main__":
    unittest.main()
