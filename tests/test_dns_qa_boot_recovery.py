"""Recovery after reboot and safe cleanup of a stale boot DNS allow rule."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "scripts" / "vpngw-dns-qa-cutover.py"
spec = importlib.util.spec_from_file_location("qa_dns_recovery", SRC)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

POLICY="caio"
BOOT="vpngw_boot_caio"
PILOT="172.18.0.6"
BRIDGE="br-b5f9615299a5"
MAC="bc:25:11:5b:59:e1"


class DnsQaBootRecoveryTest(TestCase):
    def test_no_journals_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(agent, "JOURNAL_DIR", Path(tmp) / "missing"):
                self.assertEqual(agent.recover_pending(), {"recovered":[]})

    def test_reboot_recovers_all_valid_journals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root / "caio.json").write_text("{}")
            (root / "stremio.json").write_text("{}")
            for name in ("caio","stremio"):
                (root / (name+".json")).chmod(0o600)
            with patch.object(agent, "JOURNAL_DIR", root), \
                 patch.object(agent, "rollback", side_effect=lambda x: {"restored": True}):
                result=agent.recover_pending()
            self.assertEqual([x["policy"] for x in result["recovered"]],
                             ["caio","stremio"])
            self.assertTrue(all(x["restored"] for x in result["recovered"]))

    def test_unknown_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root / "unexpected.tmp").write_text("x")
            with patch.object(agent, "JOURNAL_DIR", root):
                with self.assertRaisesRegex(ValueError,"Unexpected"):
                    agent.recover_pending()

    def test_stale_exception_deletes_only_exact_pilot_allow(self):
        rule=(f'  iifname "ens18" ether saddr {MAC} ip saddr 192.168.1.229 '
              f'oifname "{BRIDGE}" ip daddr {PILOT} '
              'meta l4proto { tcp, udp } th dport 53 counter packets 10 bytes 590 accept # handle 24')
        journal={"pihole":PILOT,"bridge":BRIDGE,
                 "policy":{"plan":{"registered_mac":MAC}}}
        calls=[]
        def fake_run(*args,**kwargs):
            calls.append(args)
            if "list" in args:
                return SimpleNamespace(returncode=0,stdout=rule)
            return SimpleNamespace(returncode=0,stdout="")
        with patch.object(agent,"run",side_effect=fake_run):
            self.assertTrue(agent.strip_stale_boot_exception(POLICY,journal))
        self.assertEqual(calls[-1],(agent.NFT,"delete","rule","inet",
                                      BOOT,"forwarding","handle","24"))

    def test_unrelated_boot_rule_is_not_deleted(self):
        journal={"pihole":PILOT,"bridge":BRIDGE,
                 "policy":{"plan":{"registered_mac":MAC}}}
        with patch.object(agent,"run",return_value=SimpleNamespace(
            returncode=0,stdout='ip daddr 172.18.0.7 accept # handle 99')) as mocked:
            self.assertFalse(agent.strip_stale_boot_exception(POLICY,journal))
        self.assertEqual(mocked.call_count,1)


if __name__ == "__main__":
    import unittest
    unittest.main()
