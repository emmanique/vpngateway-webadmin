"""LAN-only authenticated host status endpoint cannot publish expired ports."""
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/vpngw-port-status-service.py"
spec = importlib.util.spec_from_file_location("vpngw_port_status_service", SOURCE)
status = importlib.util.module_from_spec(spec)
spec.loader.exec_module(status)


def sample(now=1000.0, expires=1045):
    return {
        "selected_host": {"policy_id":"stremio","registered_mac":"aa:bb:cc:dd:ee:ff",
                          "host_ip":"192.168.1.199","route":"vpn-proton"},
        "rules_applied":True,
        "runtime": {"applied":True,"owner":"stremio","route":"vpn-proton",
                    "updated_at":now-5,"lease_expires_at":expires,
                    "provider_lease":True,"external_ports":{"tcp":37718,"udp":37718}},
    }


class StatusServiceTests(unittest.TestCase):
    def test_only_private_management_address_and_port(self):
        self.assertEqual(status.validate_binding("ens18","192.168.1.231",9443),
                         ("ens18","192.168.1.231",9443))
        for iface,addr,port in [
            ("ens18","8.8.8.8",9443),("ens18","127.0.0.1",9443),
            (";touch /tmp/pwned","192.168.1.231",9443),
            ("ens18","192.168.1.231",80)]:
            with self.assertRaises(ValueError):
                status.validate_binding(iface,addr,port)

    def test_unexpired_port_retained_and_expired_hidden(self):
        good = status.sanitized_observation(sample(), 1000.0)
        self.assertTrue(good["rules_applied"])
        self.assertEqual(good["runtime"]["external_ports"]["tcp"],37718)
        denied = status.sanitized_observation(sample(expires=999),1000)
        self.assertFalse(denied["rules_applied"])
        self.assertEqual(denied["runtime"]["external_ports"],{})
        self.assertEqual(denied["runtime"]["lease_state"],"unverified")

    def test_agent_not_applied_fails_closed(self):
        data=sample()
        data["rules_applied"]=False
        self.assertEqual(status.sanitized_observation(data,1000)["runtime"]["external_ports"],{})
        data=sample()
        data["runtime"]["updated_at"]=850
        self.assertEqual(status.sanitized_observation(data,1000)["runtime"]["external_ports"],{})

    def test_bundle_only_serves_allowlisted_regular_root_files(self):
        if __import__("os").geteuid() != 0:
            self.skipTest("Requires root ownership")
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/"scripts").mkdir()
            public=root/"scripts"/"mediahub-gateway-port-sync.py"
            public.write_text("print('installer')\n")
            self.assertEqual(status.read_public_bundle(
                "/mediahub-sync/v1/scripts/mediahub-gateway-port-sync.py",
                root=root), b"print('installer')\n")
            self.assertIsNone(status.read_public_bundle(
                "/mediahub-sync/v1/../../etc/shadow", root=root))
            self.assertIsNone(status.read_public_bundle(
                "/mediahub-sync/v1/not-allowlisted", root=root))
            public.chmod(0o666)
            self.assertIsNone(status.read_public_bundle(
                "/mediahub-sync/v1/scripts/mediahub-gateway-port-sync.py",
                root=root))
            public.chmod(0o644)
            public.unlink()
            public.symlink_to("/etc/hosts")
            self.assertIsNone(status.read_public_bundle(
                "/mediahub-sync/v1/scripts/mediahub-gateway-port-sync.py",
                root=root))

    def test_separate_status_token_file_requires_root_only_permissions(self):
        if __import__("os").geteuid() != 0:
            self.skipTest("Root-owned test file required")
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"token"
            path.write_text("f"*64+"\n")
            path.chmod(0o600)
            self.assertEqual(status.read_token(path),"f"*64)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                status.read_token(path)
            path.chmod(0o600)
            path.write_text("short")
            with self.assertRaises(ValueError):
                status.read_token(path)


if __name__=="__main__":
    unittest.main()
