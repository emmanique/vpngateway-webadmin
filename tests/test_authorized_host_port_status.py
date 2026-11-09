"""LAN-only read-only observer must match an authorised host IP+MAC."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("gateway_host_status",ROOT/"scripts/vpngw-port-status-service.py")
MOD=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class AuthorizedHostPortStatus(unittest.TestCase):
    def snapshot(self):
        return {
            "selected_host":{"policy_id":"stremio","registered_mac":"3c:2c:30:9b:c2:75",
                             "host_ip":"192.168.1.250","route":"vpn-proton"},
            "forwarding":{"policy_id":"stremio"},"rules_applied":True,
            "runtime":{"status":"nat_rules_verified","owner":"stremio",
                       "external_ports":{"tcp":62743,"udp":62743}}
        }

    def test_only_authorized_ip_and_kernel_neighbor_mac(self):
        f=lambda ip,nic:"3c:2c:30:9b:c2:75"
        self.assertTrue(MOD.authorized_lan_host(self.snapshot(),
            source_ip="192.168.1.250",interface="ens18",neighbor_check=f))
        self.assertFalse(MOD.authorized_lan_host(self.snapshot(),
            source_ip="192.168.1.251",interface="ens18",neighbor_check=f))
        self.assertFalse(MOD.authorized_lan_host(self.snapshot(),
            source_ip="192.168.1.250",interface="ens18",neighbor_check=lambda ip,nic:"00:11:22:33:44:55"))

    def test_removed_forwarding_or_rules_revokes_access(self):
        x=self.snapshot();x["forwarding"]=None
        self.assertFalse(MOD.authorized_lan_host(x,source_ip="192.168.1.250",
            interface="ens18",neighbor_check=lambda ip,nic:"3c:2c:30:9b:c2:75"))
        x=self.snapshot();x["rules_applied"]=False
        self.assertFalse(MOD.authorized_lan_host(x,source_ip="192.168.1.250",
            interface="ens18",neighbor_check=lambda ip,nic:"3c:2c:30:9b:c2:75"))


if __name__=="__main__":
    unittest.main()