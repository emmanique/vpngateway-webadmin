"""Fail-closed rebind contract: no guessed IP or partially opened lockdown."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

HERE = Path(__file__).resolve().parents[1] / "scripts"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, HERE / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = load("vpngw-host-rebind.py", "rebind_helper")
cutover = load("vpngw-host-rebind-transaction.py", "rebind_cutover")
MAC = "aa:bb:cc:dd:ee:ff"


class QuarantineTests(unittest.TestCase):
    def test_both_directions_and_local_input_are_quarantined(self):
        script = helper.quarantine_script(
            "host-a", MAC, "enp6s18", "192.168.1.199", "192.168.1.205")
        self.assertIn("ether saddr " + MAC + " counter drop", script)
        self.assertIn("ip daddr 192.168.1.199 counter drop", script)
        self.assertIn("ip daddr 192.168.1.205 counter drop", script)
        self.assertIn("type filter hook input priority -310", script)
        self.assertIn("type filter hook forward priority -310", script)

    def test_journal_remains_after_failed_quarantine_install(self):
        with tempfile.TemporaryDirectory() as folder:
            from pathlib import Path
            root = Path(folder)
            record = {"pid": "host-a", "mac": MAC, "lan": "enp6s18",
                      "previous_ip": "192.168.1.199",
                      "candidate_ip": "192.168.1.205", "route": "direct"}
            # Chosen temp root is root-owned in CI. chmod it to mode 0700.
            root.chmod(0o700)
            helper.write_pending(record, root)
            self.assertEqual(helper.read_pending("host-a", root), record)
            def unavailable(*args, **kwargs):
                raise subprocess.CalledProcessError(1, args[0])
            with self.assertRaises(subprocess.CalledProcessError):
                helper.ensure_quarantine(record, runner=unavailable)
            self.assertIsNotNone(helper.read_pending("host-a", root))

    def test_failure_during_kernel_rebuild_preserves_fail_closed_quarantine(self):
        from types import SimpleNamespace
        events = []
        plan = {"host": "192.168.1.199", "registered_mac": MAC,
                "destination": "direct", "lan": "enp6s18", "wan": "enp6s18"}
        def fail_kernel(*args):
            events.append("kernel_failure")
            raise RuntimeError("Kernel replace failed")
        agent = SimpleNamespace(
            read_state=lambda pid: {"status": "active", "plan": plan},
            validate_saved_plan=lambda p: None,
            host_rebind_preflight=lambda pid: {
                "previous_ip": "192.168.1.199", "candidate_ip": "192.168.1.205",
                "registered_mac": MAC, "changed": True},
            identity_guard_ok=lambda *a: True,
            renumber_guard_ok=lambda *a: True,
            suspend_owned_forwarding=lambda pid: events.append("suspend_port"),
            remove_rules=fail_kernel)
        with (patch.object(cutover.helper, "read_pending", return_value=None),
              patch.object(cutover.helper, "write_pending",
                           side_effect=lambda record: events.append("journal")),
              patch.object(cutover.helper, "ensure_quarantine",
                           side_effect=lambda record: events.append("quarantine")),
              patch.object(cutover.helper, "release_quarantine") as release):
            with self.assertRaises(RuntimeError):
                cutover.prepare(agent, "host-a", old_ip="192.168.1.199",
                                new_ip="192.168.1.205", mac=MAC)
        self.assertEqual(events, ["journal", "quarantine", "suspend_port", "kernel_failure"])
        release.assert_not_called()

    def test_crash_recovery_reuses_matching_journal_without_new_cutover(self):
        from types import SimpleNamespace
        record={"pid":"host-a", "previous_ip":"192.168.1.199",
                "candidate_ip":"192.168.1.205",
                "mac":MAC, "lan":"enp6s18", "route":"direct"}
        agent=SimpleNamespace(read_state=lambda pid: {
            "status":"active", "plan":{"host":"192.168.1.205"}})
        with (patch.object(cutover.helper, "read_pending", return_value=record),
              patch.object(cutover.helper, "ensure_quarantine") as ensure,
              patch.object(cutover.helper, "write_pending") as write):
            result=cutover.prepare(agent,"host-a",old_ip="192.168.1.199",
                                   new_ip="192.168.1.205",mac=MAC)
        self.assertTrue(result["prepared"])
        self.assertTrue(result["pending_commit"])
        ensure.assert_called_once_with(record)
        write.assert_not_called()

    def test_conflicting_crash_journal_cannot_change_owner(self):
        from types import SimpleNamespace
        record={"previous_ip":"192.168.1.199",
                "candidate_ip":"192.168.1.206",
                "mac":MAC}
        with patch.object(cutover.helper, "read_pending", return_value=record):
            with self.assertRaises(ValueError):
                cutover.prepare(SimpleNamespace(),"host-a",
                                old_ip="192.168.1.199",
                                new_ip="192.168.1.205",mac=MAC)

    def test_no_new_host_without_confirmed_old_mac(self):
        state = {"status": "active",
                 "plan": {"host": "192.168.1.199",
                          "registered_mac": MAC}}
        with self.assertRaises(ValueError):
            cutover._check_tuple(state, old_ip="192.168.1.199",
                                 new_ip="192.168.1.205", mac="aa:bb:cc:dd:ee:01")
        with self.assertRaises(ValueError):
            cutover._check_tuple(state, old_ip="192.168.1.199",
                                 new_ip="192.168.1.199", mac=MAC)

if __name__ == "__main__":
    unittest.main()
