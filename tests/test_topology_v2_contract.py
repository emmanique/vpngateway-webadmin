"""Isolated WAN/LAN topology regression: never modifies host network or production DB."""
import os
import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("VPNGW_DB_PATH", "/tmp/vpngw-topology-v2-import-test.sqlite3")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "apps" / "api"))
import main  # image includes FastAPI/Pydantic; use a private DB per test below


def link(name, address, cidr, kind, default=False):
    return dict(interface=name, address=address, network=cidr,
                prefixlen=int(cidr.rsplit("/", 1)[1]), kind=kind,
                operstate="UP", default_route=default)


ETH = link("lan_eth", "192.168.50.1", "192.168.50.0/24", "ethernet")
WIFI = link("wan_wifi", "192.168.60.2", "192.168.60.0/24", "wifi", True)
ETH2 = link("lan_eth2", "192.168.70.1", "192.168.70.0/24", "ethernet")


def iface(name, role, addr=None, gateway=None):
    return dict(interface=name, role=role, label=name,
                address_mode="static", ipv4_address=addr, prefix_length=24,
                gateway_ipv4=gateway, dns_ipv4=[])


def draft(mode, rows, management="lan_eth"):
    return main.NetworkDraft(mode=mode, interfaces=rows,
                             management_interface=management,
                             wan_webadmin_enabled=False,
                             wan_webadmin_allowed_cidrs=[])


class TopologyV2Contract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vpngw-topology-")
        self.path_patch = patch.object(main, "DB_PATH", str(Path(self.tmp.name) / "isolated.sqlite3"))
        self.policy_patch = patch.object(main, "_policies", {})
        self.path_patch.start()
        self.policy_patch.start()

    def tearDown(self):
        self.policy_patch.stop()
        self.path_patch.stop()
        self.tmp.cleanup()

    def topology(self, interfaces, gateway=True):
        return dict(interfaces=interfaces,
                    default_routes=[dict(interface="wan_wifi",gateway="192.168.60.1")] if gateway else [],
                    source="test_only")

    def routed(self):
        return draft("routed", [
            iface("lan_eth", "lan", "192.168.50.1"),
            iface("wan_wifi", "wan", "192.168.60.2", "192.168.60.1"),
        ])

    def test_separate_wan_wifi_lan_ethernet_acceptance(self):
        with patch.object(main, "network_topology", return_value=self.topology([ETH, WIFI])):
            result = main.save_network_config(self.routed())
            self.assertFalse(result["applied"])
            self.assertFalse(main.get_network_config()["applied"])
            with patch.object(main, "_require_policy_admin"):
                applied = main.accept_current_network(object())
            self.assertEqual(applied["outgoing_interface"], "wan_wifi")
            self.assertEqual(applied["gateway"], "192.168.60.1")
            self.assertTrue(main.get_network_config()["applied"])
            self.assertEqual(main.network_flow_preview()["mode"], "routed")
            self.assertTrue(main.route_preview()["ready"])

    def test_shared_one_interface(self):
        shared = dict(interfaces=[ETH], default_routes=[dict(interface="lan_eth",gateway="192.168.50.254")])
        with patch.object(main,"network_topology",return_value=shared):
            intent = draft("shared", [dict(interface="lan_eth", role="lan", label="shared")])
            main.save_network_config(intent)
            with patch.object(main, "_require_policy_admin"):
                result = main.accept_current_network(object())
            self.assertEqual(result["outgoing_interface"], "lan_eth")
            self.assertTrue(main.get_network_config()["applied"])

    def test_multi_lan_separate_subnets(self):
        with patch.object(main, "network_topology",return_value=self.topology([ETH,WIFI,ETH2])):
            intent=draft("multi_lan", [
                iface("lan_eth", "lan", "192.168.50.1"),
                iface("wan_wifi", "wan", "192.168.60.2", "192.168.60.1"),
                iface("lan_eth2", "lan", "192.168.70.1")])
            main.save_network_config(intent)
            with patch.object(main, "_require_policy_admin"):
                main.accept_current_network(object())
            self.assertTrue(main.get_network_config()["applied"])
            self.assertEqual(len(main.network_flow_preview()["interfaces"]),3)

    def test_invalid_management_is_wan(self):
        with patch.object(main,"network_topology",return_value=self.topology([ETH,WIFI])):
            with self.assertRaises(main.HTTPException) as cm:
                main.save_network_config(draft("routed",self.routed().interfaces,"wan_wifi"))
            self.assertEqual(cm.exception.status_code,422)

    def test_shared_rejects_wan_role(self):
        with patch.object(main,"network_topology",return_value=self.topology([ETH,WIFI])):
            with self.assertRaises(main.HTTPException):
                main.save_network_config(draft("shared",self.routed().interfaces))

    def test_separate_rejects_only_one_physical(self):
        with patch.object(main,"network_topology",return_value=self.topology([ETH])):
            with self.assertRaises(main.HTTPException):
                main.save_network_config(draft("routed",[
                    iface("lan_eth","lan","192.168.50.1")]))

    def test_multi_lan_rejects_less_than_three_physicals(self):
        with patch.object(main,"network_topology",return_value=self.topology([ETH,WIFI])):
            with self.assertRaises(main.HTTPException):
                main.save_network_config(draft("multi_lan",self.routed().interfaces))

    def test_overlapping_lan_and_wan_rejected(self):
        with patch.object(main,"network_topology",return_value=self.topology([ETH,WIFI])):
            data=self.routed()
            data.interfaces[1].ipv4_address="192.168.50.2"
            data.interfaces[1].gateway_ipv4="192.168.50.254"
            with self.assertRaises(main.HTTPException):
                main.save_network_config(data)

    def test_lan_default_gateway_rejected(self):
        with patch.object(main,"network_topology",return_value=self.topology([ETH,WIFI])):
            data=self.routed()
            data.interfaces[0].gateway_ipv4="192.168.50.254"
            with self.assertRaises(main.HTTPException):
                main.save_network_config(data)

    def test_wan_gateway_outside_subnet_rejected(self):
        with patch.object(main,"network_topology",return_value=self.topology([ETH,WIFI])):
            data=self.routed()
            data.interfaces[1].gateway_ipv4="192.168.90.1"
            with self.assertRaises(main.HTTPException):
                main.save_network_config(data)

    def test_draft_mismatch_cannot_be_confirmed(self):
        with patch.object(main,"network_topology",return_value=self.topology([ETH,WIFI])):
            data=self.routed()
            data.interfaces[1].ipv4_address="192.168.60.3"
            main.save_network_config(data)
            with patch.object(main,"_require_policy_admin"):
                with self.assertRaises(main.HTTPException) as cm:
                    main.accept_current_network(object())
            self.assertEqual(cm.exception.status_code,409)
            self.assertFalse(main.get_network_config()["applied"])

    def test_missing_wan_default_route_cannot_be_confirmed(self):
        with patch.object(main,"network_topology",return_value=self.topology([ETH,WIFI],False)):
            main.save_network_config(self.routed())
            with patch.object(main,"_require_policy_admin"):
                with self.assertRaises(main.HTTPException) as cm:
                    main.accept_current_network(object())
            self.assertEqual(cm.exception.status_code,409)

    def test_diagram_labels_are_client_outbound_and_stateful(self):
        source=(Path(__file__).resolve().parents[1] / "apps" / "web" / "src" / "main.tsx").read_text(encoding="utf-8")
        self.assertIn("Fluxo lógico: clientes LAN → gateway → Internet",source)
        self.assertNotIn("Encaminhamento WAN → LAN",source)
        self.assertIn("networkSaved&&networkApplied?'confirmada'",source)
        self.assertIn("topology-management",source)
        self.assertIn("lans.map",source)


if __name__ == "__main__":
    unittest.main()
