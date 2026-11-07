import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[3] / "scripts" / "vpngw-vpn-boot-guard.py"
spec = importlib.util.spec_from_file_location("vpngw_boot_guard", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class TestPersistentVpnBootGuard(unittest.TestCase):
    def config(self, **kwargs):
        data = {"id": "client-test", "host": "10.99.8.17",
                "lan": "lan0", "vpn": "wg123456789ab",
                "mac": "12:34:56:78:9a:bc", "confirmed": True}
        data.update(kwargs)
        return data

    def test_syntax_and_per_client_scope(self):
        source = module.render(self.config())
        result = subprocess.run(["nft", "-c", "-f", "-"], input=source,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("oifname != \"wg123456789ab\"", source)
        self.assertIn("ether saddr 12:34:56:78:9a:bc meta nfproto ipv6", source)
        self.assertNotIn("flush ruleset", source)

    def test_never_install_unconfirmed_or_invalid(self):
        for changes in ({"confirmed": False}, {"host": "8.8.8.8"},
                        {"lan": "w;evil"}, {"mac": "bad"}, {"vpn": "wlan0"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                module.render(self.config(**changes))

    def test_permissions_and_name_checked(self):
        with tempfile.TemporaryDirectory() as dirname:
            d = Path(dirname)
            path = d / "client-test.json"
            path.write_text(json.dumps(self.config()))
            os.chmod(path, 0o600)
            self.assertEqual(len(list(module.records(d))), 1)
            os.chmod(path, 0o644)
            with self.assertRaises(ValueError):
                list(module.records(d))

    def test_boot_reinstall_idempotent(self):
        with tempfile.TemporaryDirectory() as dirname:
            d = Path(dirname)
            path = d / "client-test.json"
            path.write_text(json.dumps(self.config()))
            os.chmod(path, 0o600)
            render = module.render(self.config())
            def runner(argv, **kwargs):
                if "list" in argv:
                    return subprocess.CompletedProcess(argv, 1, "", "")
                return subprocess.CompletedProcess(argv, 0, "", "")
            with patch.object(module.subprocess, "run", side_effect=runner) as mocked:
                self.assertEqual(module.reconcile(d), ["client-test"])
                self.assertTrue(any("-f" in call.args[0] for call in mocked.call_args_list))

if __name__ == "__main__":
    unittest.main()
