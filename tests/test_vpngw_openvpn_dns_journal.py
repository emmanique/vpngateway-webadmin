"""OpenVPN pushed DNS must survive noisy journals and stay session-scoped."""
import importlib.util
from io import StringIO
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "vpngw-openvpn-agent.py"
spec = importlib.util.spec_from_file_location("vpngw_openvpn_agent_dns_test", SCRIPT)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class FakeResult:
    returncode = 0
    stdout = "Wed 2026-11-04 13:54:23 UTC"


class FakeJournal:
    def __init__(self, messages):
        self.stdout = StringIO("\n".join(messages) + "\n")
        self.stderr = None
        self.terminated = False

    def poll(self):
        return None if not self.terminated else -15

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.terminated = True

    def wait(self, timeout=None):
        return -15


class PushedDnsJournalTests(TestCase):
    def probe(self, messages):
        process = FakeJournal(messages)
        with patch.object(agent.subprocess, "run", return_value=FakeResult()) as run, \
             patch.object(agent.subprocess, "Popen", return_value=process) as spawn:
            result = agent.pushed_dns_ipv4("vpn-protopen")
        cmd = spawn.call_args.args[0]
        self.assertIn("--reverse", cmd)
        self.assertIn("--since", cmd)
        self.assertIn("Wed 2026-11-04 13:54:23 UTC", cmd)
        self.assertTrue(process.terminated)
        self.assertIn("ActiveEnterTimestamp", run.call_args.args[0])
        return result

    def test_noisy_log_uses_current_session_push(self):
        push = "NOTE: PUSH_REPLY,route-gateway 10.96.0.1,dhcp-option DNS 10.96.0.1,peer-id 0"
        messages = ["AEAD Decrypt error"] * 500 + [push]
        self.assertEqual(self.probe(messages), "10.96.0.1")

    def test_no_provider_dns_fails_closed(self):
        self.assertIsNone(self.probe(["AEAD Decrypt error"] * 200))

    def test_invalid_provider_dns_fails_closed(self):
        self.assertIsNone(self.probe(["PUSH_REPLY,dhcp-option DNS 0.0.0.0,peer-id 0"]))
