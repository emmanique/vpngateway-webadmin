"""Dynamic policy DNS worker discovery must fail closed on topology changes."""
import importlib.util
import json
from pathlib import Path
import subprocess
from unittest import TestCase
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "vpngw-dns-worker-bootstrap.py"
spec = importlib.util.spec_from_file_location("dnsworkerbootstrap", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class BootstrapTest(TestCase):
    def result(self, payload):
        return subprocess.CompletedProcess([], 0, stdout=json.dumps(payload))

    def inspection(self, *, running=True, networks=1):
        entry = {
            "Gateway": "172.18.0.1",
            "IPAddress": "172.18.0.3",
            "NetworkID": "b5f9615299a5" + "0" * 52,
        }
        return [{"State": {"Running": running}, "NetworkSettings": {
            "Networks": {str(i): entry for i in range(networks)}
        }}]

    def test_dynamic_discovery(self):
        with patch.object(mod.subprocess, "run", return_value=self.result(self.inspection())) as mocked:
            found = mod.discover(container="vpngateway-v001-staging-pihole-1", inspector=mocked)
        self.assertEqual(found, {
            "bridge": "br-b5f9615299a5",
            "listener": "172.18.0.1",
            "peer": "172.18.0.3",
        })

    def test_not_running_or_multiple_networks_is_refused(self):
        for running, n in ((False, 1), (True, 2), (True, 0)):
            with self.subTest(running=running, networks=n):
                with patch.object(mod.subprocess, "run",
                                  return_value=self.result(self.inspection(
                                      running=running, networks=n))) as mocked:
                    with self.assertRaises(mod.BootstrapError):
                        mod.discover(container="pihole", inspector=mocked)

    def test_untrusted_container_name_refused(self):
        for value in ("", "../pihole", "pihole;sh", "pihole with spaces"):
            with self.subTest(container=value):
                with self.assertRaises(mod.BootstrapError):
                    mod.discover(container=value)

    def test_bad_bridge_network_is_refused(self):
        item = self.inspection()
        item[0]["NetworkSettings"]["Networks"]["0"]["NetworkID"] = "nonsense"
        with patch.object(mod.subprocess, "run", return_value=self.result(item)) as mocked:
            with self.assertRaises(mod.BootstrapError):
                mod.discover(container="pihole", inspector=mocked)

    def test_verified_runtime_matches_kernel(self):
        values = [
            [{"ifname": "br-b5f9615299a5", "addr_info": [
                {"family": "inet", "local": "172.18.0.1"}]}],
            [{"dev": "br-b5f9615299a5", "dst": "172.18.0.3"}],
        ]
        with patch.object(mod.subprocess, "run", side_effect=[
            self.result(v) for v in values
        ]) as mocked:
            result = mod.verified_runtime({
                "bridge": "br-b5f9615299a5", "listener": "172.18.0.1",
                "peer": "172.18.0.3"
            }, runner=mocked)
        self.assertEqual(result["peer"], "172.18.0.3")

    def test_kernel_bridge_mismatch_refused(self):
        with patch.object(mod.subprocess, "run", return_value=self.result([
            {"ifname": "ens18", "addr_info": [{"family": "inet",
                                              "local": "192.168.1.231"}]}
        ])) as mocked:
            with self.assertRaises(mod.BootstrapError):
                mod.verified_runtime({"bridge": "br-b5f9615299a5",
                                      "listener": "172.18.0.1",
                                      "peer": "172.18.0.3"}, runner=mocked)
