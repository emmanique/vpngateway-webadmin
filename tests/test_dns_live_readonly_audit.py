"""Read-only QA capture validation without touching a real device."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/"scripts/audit-dns-live-readonly.py"
spec=importlib.util.spec_from_file_location("qa_dns_audit",SCRIPT)
auditor=importlib.util.module_from_spec(spec)
spec.loader.exec_module(auditor)


class ReadOnlyAuditTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.name="qa-policy-a"

    def write(self,status="active",pending=False,runtime=None):
        policy={
            "status":status,
            "plan":{"host":"192.168.90.22","lan":"lan-test",
                    "destination":"vpn-qa"},
            "vpn_runtime":runtime if runtime is not None
                else {"interface":"tun-test","dns_ipv4":"10.1.0.1"}
        }
        if pending:policy["vpn_pending"]={"previous":"direct"}
        (self.root/(self.name+".json")).write_text(json.dumps(policy))

    def test_active_confirmed_policy_is_visible(self):
        self.write()
        mapping=auditor.inspect_clients(self.root,[self.name],"192.168.90.1")
        self.assertEqual(mapping[self.name]["ip"],"192.168.90.22")
        self.assertEqual(mapping[self.name]["vpn"],"tun-test")
        self.assertEqual(mapping[self.name]["resolver"],"10.1.0.1")

    def test_pending_policy_is_refused(self):
        self.write(pending=True)
        with self.assertRaisesRegex(ValueError,"confirmed active"):
            auditor.inspect_clients(self.root,[self.name],"192.168.90.1")

    def test_error_policy_is_refused(self):
        self.write(status="error")
        with self.assertRaisesRegex(ValueError,"confirmed active"):
            auditor.inspect_clients(self.root,[self.name],"192.168.90.1")

    def test_missing_interface_is_refused(self):
        self.write(runtime={"dns_ipv4":"10.1.0.1"})
        with self.assertRaisesRegex(ValueError,"Expected VPN"):
            auditor.inspect_clients(self.root,[self.name],"192.168.90.1")

    def test_symlinked_state_is_refused(self):
        backing=self.root/"saved.json"
        backing.write_text("{}")
        (self.root/(self.name+".json")).symlink_to(backing)
        with self.assertRaisesRegex(ValueError,"symlink"):
            auditor.inspect_clients(self.root,[self.name],"192.168.90.1")


if __name__=="__main__":
    unittest.main()
