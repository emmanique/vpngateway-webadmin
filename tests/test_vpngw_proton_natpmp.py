"""Proton official NAT-PMP contract, OpenVPN suffix and WireGuard readiness."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("vpngw_proton_natpmp",ROOT/"scripts"/"vpngw-proton-natpmp.py")
proton=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proton)


class ProtonContractTests(unittest.TestCase):
    def test_official_linux_command_same_for_wireguard_openvpn(self):
        self.assertEqual(proton.mapping_command("udp"),
                         ["/usr/bin/natpmpc","-a","1","0","udp","60","-g","10.2.0.1"])
        self.assertEqual(proton.mapping_command("tcp"),
                         ["/usr/bin/natpmpc","-a","1","0","tcp","60","-g","10.2.0.1"])
        self.assertEqual(proton.RENEW_SECONDS,45)
        with self.assertRaises(TypeError):
            proton.mapping_command("udp", public_hint=36131, revoke=True)

    def test_openvpn_pmp_suffix_and_additional_flags(self):
        self.assertFalse(proton.is_openvpn_pmp_username("myusername2023"))
        self.assertTrue(proton.is_openvpn_pmp_username("myusername2023+pmp"))
        self.assertTrue(proton.is_openvpn_pmp_username("myusername2023+pmp+f2"))
        self.assertFalse(proton.is_openvpn_pmp_username("myusername2023+pmpfake"))

    def test_readiness_applies_both_protocols(self):
        self.assertTrue(proton.provider_readiness(
            protocol="openvpn",p2p_confirmed=True,openvpn_pmp_authorized=True)["ready"])
        self.assertTrue(proton.provider_readiness(
            protocol="wireguard",p2p_confirmed=True,wireguard_natpmp_enabled=True)["ready"])
        self.assertFalse(proton.provider_readiness(
            protocol="openvpn",p2p_confirmed=True)["ready"])
        self.assertFalse(proton.provider_readiness(
            protocol="wireguard",p2p_confirmed=True)["ready"])
        self.assertFalse(proton.provider_readiness(
            protocol="wireguard",p2p_confirmed=True,wireguard_natpmp_enabled=True,
            moderate_nat_enabled=True)["ready"])

    def test_version_threshold(self):
        self.assertTrue(proton.natpmp_binary_version_acceptable("20230423-1"))
        self.assertFalse(proton.natpmp_binary_version_acceptable("20150609-7"))
        self.assertFalse(proton.natpmp_binary_version_acceptable("unknown"))

if __name__=="__main__":
    unittest.main()
