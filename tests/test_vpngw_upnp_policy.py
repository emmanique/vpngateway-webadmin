"""Offline UPnP IGD least-privilege policy compilation tests."""
import importlib.util
from pathlib import Path
import unittest

source=Path(__file__).resolve().parents[1]/"scripts"/"vpngw-upnp-policy.py"
spec=importlib.util.spec_from_file_location("vpngw_upnp_policy",source)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

UUID="12345678-1234-1234-1234-123456789abc"

class UPnPPolicyTests(unittest.TestCase):
    def test_default_deny_and_exact_host_acl(self):
        config=mod.render_config(lan_interface="lan0",wan_interface="wan0",
                                 allowed_hosts=["192.168.1.229","192.168.1.199"],uuid=UUID)
        self.assertIn("secure_mode=yes",config)
        self.assertIn("enable_pcp_pmp=no",config)
        self.assertIn("ipv6_disable=yes",config)
        self.assertIn("ext_allow_private_ipv4=no",config)
        self.assertIn("allow 1024-65535 192.168.1.199/32 1024-65535",config)
        self.assertIn("allow 1024-65535 192.168.1.229/32 1024-65535",config)
        self.assertTrue(config.rstrip().endswith(mod.DEFAULT_DENY))
        self.assertNotIn("allow 1024-65535 0.0.0.0/0",config)

    def test_empty_acl_deny_all(self):
        config=mod.render_config(lan_interface="lan0",wan_interface="wan0",
                                 allowed_hosts=[],uuid=UUID)
        self.assertEqual(config.count("allow "),0)
        self.assertEqual(config.count(mod.DEFAULT_DENY),1)

    def test_vpn_blocked_and_disabled_never_get_igd_acl(self):
        policies={
            "direct":{"host_ip":"192.168.1.199","destination":"direct","status":"active",
                      "registered_mac":"aa:bb:cc:dd:ee:ff","upnp_enabled":True},
            "vpn":{"host_ip":"192.168.1.229","destination":"proton","status":"active",
                   "registered_mac":"aa:bb:cc:dd:ee:ef","upnp_enabled":True},
            "blocked":{"host_ip":"192.168.1.230","destination":"blocked","status":"active",
                       "registered_mac":"aa:bb:cc:dd:ee:ed","upnp_enabled":True},
            "off":{"host_ip":"192.168.1.231","destination":"direct","status":"active",
                   "registered_mac":"aa:bb:cc:dd:ee:ec","upnp_enabled":False}}
        result=mod.eligibility(policies)
        self.assertEqual(result["eligible_direct"],{"direct":"192.168.1.199"})
        self.assertEqual(result["unsupported"]["vpn"],"vpn_provider_mapping_required")
        self.assertEqual(result["unsupported"]["blocked"],"blocked_route")
        self.assertNotIn("off",result["eligible_direct"])

    def test_invalid_scope_and_interfaces_rejected(self):
        for host in ("127.0.0.1","0.0.0.0","1.1.1.1","::1"):
            with self.subTest(host=host), self.assertRaises(mod.UPnPConfigError):
                mod.render_config(lan_interface="lan0",wan_interface="wan0",
                                  allowed_hosts=[host],uuid=UUID)
        with self.assertRaises(mod.UPnPConfigError):
            mod.render_config(lan_interface="ens18",wan_interface="ens18",
                              allowed_hosts=["192.168.1.199"],uuid=UUID)

if __name__=="__main__":
    unittest.main()
