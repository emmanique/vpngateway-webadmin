"""No-network tests for upstream DIRECT UPnP mapping safety."""
import importlib.util
from pathlib import Path
import unittest
from types import SimpleNamespace

source=Path(__file__).resolve().parents[1]/"scripts"/"vpngw-upnpc-upstream.py"
spec=importlib.util.spec_from_file_location("vpngw_upnpc_upstream",source)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

BASE=dict(interface="ens18",local_ipv4="192.168.1.231",
          default_gateway="192.168.1.1",route_interface="ens18",
          discovered_igd_ipv4="192.168.1.1",host_route="direct",selected=True)


class UpstreamIGDTests(unittest.TestCase):
    def test_inventory_requires_exact_gateway_and_local_address(self):
        source = ("desc: http://192.168.1.1:5000/rootDesc.xml\n"
                  "Found valid IGD : http://192.168.1.1:5000/ctl/IPConn\n"
                  "Local LAN ip address : 192.168.1.231\n"
                  " 0 TCP 6881->192.168.1.231:6881 'VPNGW-host-a' '' 120\n")
        inventory = mod.parse_igd_inventory(
            source, expected_gateway="192.168.1.1",
            expected_local="192.168.1.231")
        rights = mod.owned_or_free(inventory, owner="host-a")
        self.assertEqual(rights["owned"], ["TCP"])
        self.assertEqual(rights["missing"], ["UDP"])
        with self.assertRaises(mod.IGDPreflightError):
            mod.parse_igd_inventory(source, expected_gateway="192.168.1.2",
                                    expected_local="192.168.1.231")
        with self.assertRaises(mod.IGDPreflightError):
            mod.parse_igd_inventory(source, expected_gateway="192.168.1.1",
                                    expected_local="192.168.1.229")

    def test_foreign_mapping_cannot_be_overwritten(self):
        source = ("desc: http://192.168.1.1:5000/rootDesc.xml\n"
                  "Found valid IGD : http://192.168.1.1:5000/ctl/IPConn\n"
                  "Local LAN ip address : 192.168.1.231\n"
                  " 0 UDP 6881->192.168.1.222:6881 'another-application' '' 0\n")
        state = mod.parse_igd_inventory(
            source, expected_gateway="192.168.1.1",
            expected_local="192.168.1.231")
        with self.assertRaises(mod.IGDPreflightError):
            mod.owned_or_free(state, owner="host-a")

    def test_upstream_apply_and_revoke_verify_ownership(self):
        mappings = set()
        commands = []
        def runner(argv, **kwargs):
            commands.append(argv)
            if argv[-1] == "-l":
                rows = "".join(
                    f" 0 {proto} 6881->192.168.1.231:6881 'VPNGW-host-a' '' 120\n"
                    for proto in sorted(mappings))
                return SimpleNamespace(returncode=0, stdout=(
                    "desc: http://192.168.1.1:5000/rootDesc.xml\n"
                  "Found valid IGD : http://192.168.1.1:5000/ctl/IPConn\n"
                    "Local LAN ip address : 192.168.1.231\n" + rows))
            if "-a" in argv:
                mappings.add(argv[-2])
            elif "-d" in argv:
                mappings.discard(argv[-1])
            return SimpleNamespace(returncode=0, stdout="")
        result=mod.run_verified_upnpc(interface="ens18",local_ipv4="192.168.1.231",
            gateway="192.168.1.1",route_interface="ens18",host_route="direct",
            selected=True,owner="host-a",mode="apply",runner=runner)
        self.assertTrue(result["mapping_verified"])
        self.assertEqual(mappings, {"TCP","UDP"})
        self.assertFalse(result["external_reachability_verified"])
        # A second poll must renew both existing leases, not wait until they
        # disappear and leave the selected TCP/UDP listener unreachable.
        before = len([cmd for cmd in commands if "-a" in cmd])
        again = mod.run_verified_upnpc(interface="ens18",local_ipv4="192.168.1.231",
            gateway="192.168.1.1",route_interface="ens18",host_route="direct",
            selected=True,owner="host-a",mode="apply",runner=runner)
        after = len([cmd for cmd in commands if "-a" in cmd])
        self.assertEqual(after - before, 2)
        self.assertTrue(again["mapping_verified"])
        result=mod.run_verified_upnpc(interface="ens18",local_ipv4="192.168.1.231",
            gateway="192.168.1.1",route_interface="ens18",host_route="direct",
            selected=False,owner="host-a",mode="revoke",runner=runner)
        self.assertEqual(mappings,set())
        self.assertTrue(result["mapping_verified"])

    def test_upstream_executor_rejects_unauthorised_igd(self):
        def runner(argv, **kwargs):
            return SimpleNamespace(returncode=0, stdout=(
                "desc: http://192.168.1.254:5000/rootDesc.xml\n"
                "Found valid IGD : http://192.168.1.254:5000/ctl/IPConn\n"
                "Local LAN ip address : 192.168.1.231\n"))
        with self.assertRaises(mod.IGDPreflightError):
            mod.run_verified_upnpc(interface="ens18",local_ipv4="192.168.1.231",
                gateway="192.168.1.1",route_interface="ens18",host_route="direct",
                selected=True,owner="host-a",mode="apply",runner=runner)

    def test_maps_gateway_not_final_lan_host(self):
        result=mod.build_direct_upstream_plan(**BASE)
        self.assertTrue(result["available"])
        self.assertFalse(result["verified"])
        self.assertEqual(len(result["commands"]),2)
        self.assertEqual(result["commands"][0],[
            "/usr/bin/upnpc","-m","ens18","-a","192.168.1.231",
            "6881","6881","TCP","120"])
        self.assertEqual(result["commands"][1][-2],"UDP")
        self.assertTrue(result["delete_requires_ownership_check"])

    def test_refuses_other_igd_and_vpn(self):
        with self.assertRaises(mod.IGDPreflightError):
            mod.build_direct_upstream_plan(**{**BASE,
                "discovered_igd_ipv4":"192.168.1.254"})
        result=mod.build_direct_upstream_plan(**{**BASE,"host_route":"proton"})
        self.assertFalse(result["available"])
        self.assertEqual(result["commands"],[])

    def test_no_igd_no_commands(self):
        result=mod.build_direct_upstream_plan(**{**BASE,
            "discovered_igd_ipv4":None})
        self.assertFalse(result["available"])
        self.assertEqual(result["commands"],[])

    def test_mismatched_wan_or_untrusted_address(self):
        with self.assertRaises(mod.IGDPreflightError):
            mod.build_direct_upstream_plan(**{**BASE,"route_interface":"wgsecure"})
        with self.assertRaises(mod.IGDPreflightError):
            mod.build_direct_upstream_plan(**{**BASE,"local_ipv4":"10.2.0.2",
                                             "interface":"../bad"})
        with self.assertRaises(mod.IGDPreflightError):
            mod.build_direct_upstream_plan(**{**BASE,"lease_seconds":0})

if __name__=="__main__":
    unittest.main()
