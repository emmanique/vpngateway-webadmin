"""Physical-router UPnP is allowed only on verified DIRECT WAN route."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "vpngw-direct-upnp.py"
SPEC = importlib.util.spec_from_file_location("vpngw_direct_upnp_tests", SOURCE)
direct = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(direct)

STATE = {
    "status": "active",
    "plan": {"destination": "direct", "host": "192.168.1.199",
             "wan": "enp6s18", "gateway": "192.168.1.1",
             "registered_mac": "aa:bb:cc:dd:ee:ff"},
}


def runner(argv, **kwargs):
    if argv[2:5] == ["-4", "route", "show"]:
        data = [{"dev":"enp6s18", "gateway":"192.168.1.1"}]
    elif argv[2:5] == ["-4", "address", "show"]:
        data = [{"ifname":"enp6s18", "addr_info":[
            {"family":"inet","scope":"global","local":"192.168.1.231"}]}]
    else:
        raise AssertionError("Unexpected command " + repr(argv))
    return subprocess.CompletedProcess(argv, 0, json.dumps(data), "")


class DirectUpnpTests(unittest.TestCase):
    def test_wan_must_match_confirmed_private_default_gateway(self):
        self.assertEqual(direct.wan_context(STATE,runner=runner), {
            "interface":"enp6s18", "local_ipv4":"192.168.1.231",
            "gateway":"192.168.1.1", "route_interface":"enp6s18",
            "host_route":"direct"})

    def test_vpn_and_blocked_never_use_physical_router_upnp(self):
        for destination in ("blocked","vpn-proton"):
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                direct.wan_context(
                    {**STATE,"plan":{**STATE["plan"],"destination":destination}},
                    runner=runner)

    def test_missing_igd_binary_is_not_reported_as_verified(self):
        result=direct.reconcile(
            owner="host-a",state=STATE,mode="apply",
            runner=lambda *a,**k: self.fail("Must not invoke upstream"),
            upnpc=Path("/nonexistent-upnpc-test"))
        self.assertFalse(result["mapping_verified"])
        self.assertEqual(result["reason"],"miniupnpc_not_installed")

    def test_default_gateway_mismatch_prevents_mapping(self):
        def mismatched(argv, **kwargs):
            p=runner(argv,**kwargs)
            if argv[2:5]==["-4","route","show"]:
                p.stdout=json.dumps([{"dev":"enp6s18","gateway":"192.168.1.254"}])
            return p
        with self.assertRaises(ValueError):
            direct.wan_context(STATE,runner=mismatched)

if __name__=="__main__":
    unittest.main()
