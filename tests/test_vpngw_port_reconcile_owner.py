"""Proton owner persistence is shared by WireGuard and OpenVPN on reboot."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import time
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]/"scripts"/"vpngw-port-reconcile.py"
SPEC=importlib.util.spec_from_file_location("vpngw_port_reconcile",SOURCE)
reconcile=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reconcile)


class PortOwnerPersistenceTests(unittest.TestCase):
    def test_proton_owner_persists_in_same_file_used_by_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            reconcile.save_owner(base,"host-a",provider="proton")
            record=base/"port-forward"/"port-forward-owner.json"
            self.assertTrue(record.is_file())
            self.assertEqual(reconcile.load_owner(base),"host-a")
            self.assertEqual(reconcile.load_owner_provider(base),"proton")
            self.assertEqual(json.loads(record.read_text())["provider"],"proton")
            reconcile.save_owner(base,None)
            self.assertIsNone(reconcile.load_owner(base))
            self.assertFalse(record.exists())

    def test_generic_and_legacy_owner_recover(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            reconcile.save_owner(base,"host-a")
            self.assertEqual(reconcile.load_owner_provider(base),"generic")
            record=base/"port-forward"/"port-forward-owner.json"
            record.write_text('{"policy_id":"host-a"}')
            self.assertEqual(reconcile.load_owner_provider(base),"generic")

    def test_vpn_runtime_expiry_uses_shortest_confirmed_protocol_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            reconcile.save_owner(base, "host-a", provider="proton")
            saved={"status":"active","applied":True,
                   "plan":{"registered_mac":"aa:bb:cc:dd:ee:ff",
                           "destination":"vpn-proton","host":"192.168.1.199"},
                   "vpn_runtime":{"interface":"wgsecure"}}
            packets=[
                {"protocol":"tcp","internal_port":6881,"external_port":36131,"lifetime":60},
                {"protocol":"udp","internal_port":6881,"external_port":36131,"lifetime":50},
            ]
            with (patch.object(reconcile.natpmp, "discover",
                               return_value={"status":"mapped","mappings":packets}),
                  patch.object(reconcile, "ingress_addresses",return_value=["10.2.0.2"]),
                  patch.object(reconcile, "observed_host_binding", return_value=True),
                  patch.object(reconcile.forward, "apply",
                               return_value={"applied":True,"protocols":["tcp","udp"],"route":"vpn-proton"}),
                  patch.object(reconcile.time, "time",return_value=1000.0)):
                result=reconcile.reconcile(
                    "host-a",base=base,read_state=lambda owner:saved,
                    inspect_rules=lambda owner:True,
                    identity_guard_ok=lambda owner,mac:True,
                    vpn_tunnel_status=lambda route:{"connected":True,"interface":"wgsecure","protocol":"wireguard"})
            self.assertEqual(result["lease_expires_at"],1045.0)
            self.assertEqual(result["external_ports"],{"tcp":36131,"udp":36131})

    def test_vpn_missing_lease_lifetime_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            reconcile.save_owner(base, "host-a",provider="proton")
            saved={"status":"active","applied":True,
                   "plan":{"registered_mac":"aa:bb:cc:dd:ee:ff",
                           "destination":"vpn-proton","host":"192.168.1.199"},
                   "vpn_runtime":{"interface":"wgsecure"}}
            with (patch.object(reconcile.natpmp, "discover",return_value={
                     "status":"mapped","mappings":[
                         {"protocol":"tcp","internal_port":6881,"external_port":36131,"lifetime":60},
                         {"protocol":"udp","internal_port":6881,"external_port":36131}]}),
                  patch.object(reconcile, "ingress_addresses",return_value=["10.2.0.2"]),
                  patch.object(reconcile, "observed_host_binding", return_value=True),
                  patch.object(reconcile.forward, "apply",return_value={"applied":False}) as apply_rules):
                with self.assertRaises(ValueError):
                    reconcile.reconcile(
                        "host-a",base=base,read_state=lambda owner:saved,
                        inspect_rules=lambda owner:True,
                        identity_guard_ok=lambda owner,mac:True,
                        vpn_tunnel_status=lambda route:{"connected":True,"interface":"wgsecure","protocol":"wireguard"})
                self.assertEqual(apply_rules.call_count, 1)
                self.assertIsNone(apply_rules.call_args.args[1])

    def test_partial_tcp_udp_lease_cannot_publish_dnat(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            reconcile.save_owner(base, "host-a", provider="proton")
            saved = {"status": "active", "applied": True,
                     "plan": {"registered_mac": "aa:bb:cc:dd:ee:ff",
                              "destination": "vpn-proton",
                              "host": "192.168.1.199"},
                     "vpn_runtime": {"interface": "wgsecure"}}
            # Even with a valid lifetime, UDP alone is unusable for the
            # required shared TCP/UDP libtorrent listening port.
            with (patch.object(reconcile.natpmp, "discover", return_value={
                     "status": "mapped", "mappings": [
                         {"protocol": "udp", "internal_port": 6881,
                          "external_port": 36131, "lifetime": 60}]}),
                  patch.object(reconcile, "ingress_addresses", return_value=["10.2.0.2"]),
                  patch.object(reconcile, "observed_host_binding", return_value=True),
                  patch.object(reconcile.forward, "apply",
                               return_value={"applied": False}) as apply_rules):
                result = reconcile.reconcile(
                    "host-a", base=base, read_state=lambda owner: saved,
                    inspect_rules=lambda owner: True,
                    identity_guard_ok=lambda owner, mac: True,
                    vpn_tunnel_status=lambda route: {
                        "connected": True, "interface": "wgsecure",
                        "protocol": "wireguard"})
            self.assertEqual(result["status"], "vpn_tcp_udp_mapping_incomplete")
            self.assertEqual(result["external_ports"], {})
            self.assertFalse(result["applied"])
            self.assertEqual(apply_rules.call_count, 1)
            self.assertIsNone(apply_rules.call_args.args[1])

    def test_mac_ip_binding_matches_kernel_neighbor_and_fails_closed(self):
        def observer(entries, code=0):
            class Result:
                returncode = code
                stdout = json.dumps(entries)
            return lambda command, **kwargs: Result()
        expected={"dst":"192.168.1.199","dev":"ens18",
                  "lladdr":"aa:bb:cc:dd:ee:ff","state":"REACHABLE"}
        self.assertTrue(reconcile.observed_host_binding(
            "192.168.1.199", "aa:bb:cc:dd:ee:ff", "ens18",
            runner=observer([expected])))
        for alternative in (
            [],
            [{**expected, "lladdr":"aa:bb:cc:dd:ee:01"}],
            [{**expected, "state":"FAILED"}],
            [{**expected, "dst":"192.168.1.230"}],
        ):
            self.assertFalse(reconcile.observed_host_binding(
                "192.168.1.199", "aa:bb:cc:dd:ee:ff", "ens18",
                runner=observer(alternative)))

    def test_iproute2_filtered_json_neighbour_output(self):
        # Real Ubuntu ip -j neigh ... dev ens18 has no "dev" and
        # represents the NUD state as a JSON array.
        def runner(command, **kwargs):
            self.assertEqual(command[-2:], ["dev", "ens18"])
            class Result:
                returncode = 0
                stdout = json.dumps([{
                    "dst": "192.168.1.199",
                    "lladdr": "bc:24:11:53:5f:65",
                    "state": ["REACHABLE"],
                }])
            return Result()
        self.assertTrue(reconcile.observed_host_binding(
            "192.168.1.199", "bc:24:11:53:5f:65", "ens18", runner))

    def test_neighbour_json_rejects_unverified_states_and_wrong_device(self):
        def observer(item):
            class Result:
                returncode = 0
                stdout = json.dumps([item])
            return lambda command, **kwargs: Result()
        valid = {"dst": "192.168.1.199", "lladdr": "bc:24:11:53:5f:65",
                 "state": ["REACHABLE"]}
        for invalid in (
            {**valid, "state": ["FAILED"]},
            {**valid, "state": ["INCOMPLETE"]},
            {**valid, "state": []},
            {**valid, "state": ["REACHABLE", "FAILED"]},
            {**valid, "dev": "eth9"},
        ):
            self.assertFalse(reconcile.observed_host_binding(
                "192.168.1.199", "bc:24:11:53:5f:65", "ens18",
                observer(invalid)))

    def test_reject_unsupported_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                reconcile.save_owner(Path(directory),"host-a",provider="fake")

if __name__=="__main__":
    unittest.main()
