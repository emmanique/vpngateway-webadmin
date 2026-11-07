"""Installer must not publish management services on an inferred WAN."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("select_install_lan", ROOT / "scripts/select-install-lan.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def link(name, address="10.20.0.1", scope="global"):
    return {"ifname": name, "addr_info": [
        {"family": "inet", "scope": scope, "local": address}]}


class InstallLanSelection(unittest.TestCase):
    def test_single_physical_shared_interface(self):
        self.assertEqual(MODULE.select_lan([link("eth0")], {"eth0"}), "eth0")

    def test_routed_requires_explicit_lan(self):
        with self.assertRaises(ValueError):
            MODULE.select_lan([link("lan0"), link("wan0", "10.30.0.2")], {"lan0", "wan0"})

    def test_multi_lan_requires_explicit_management(self):
        with self.assertRaises(ValueError):
            MODULE.select_lan([link(n) for n in ("lan0", "lan1", "wan0")], {"lan0", "lan1", "wan0"})

    def test_docker_bridges_not_selected(self):
        self.assertEqual(MODULE.select_lan([link("docker0"), link("eth0")], {"eth0"}), "eth0")

    def test_loopback_only_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.select_lan([link("lo", "127.0.0.1", "host")], set())

    def test_unaddressed_interfaces_not_candidates(self):
        self.assertEqual(MODULE.select_lan([link("eth0"), {"ifname": "eth1", "addr_info": []}],
                                          {"eth0", "eth1"}), "eth0")


if __name__ == "__main__":
    unittest.main()
