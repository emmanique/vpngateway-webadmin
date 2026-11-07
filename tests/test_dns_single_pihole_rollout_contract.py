"""Central DNS is deliberately opt-in and never silently changes public v1."""
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class SinglePiHoleDNSRollout(unittest.TestCase):
    def test_opt_in_overlay_reuses_only_existing_pihole(self):
        overlay=(ROOT/"deploy/compose.v2-central-dns.opt-in.yml").read_text()
        self.assertEqual(overlay.count("\n  pihole:"),1)
        self.assertNotIn("\n  pihole-v2:",overlay)
        self.assertIn("FTLCONF_dns_upstreams:",overlay)
        self.assertIn("strip-subnet;add-subnet=32,128",overlay)
        self.assertIn("FTLCONF_dns_cache_size: '0'",overlay)
        self.assertNotIn("1.1.1.1",overlay)

    def test_worker_remains_opt_in_not_release_installer(self):
        unit=ROOT/"deploy/systemd/vpngw-dns-policy-upstream.service"
        self.assertTrue(unit.is_file())
        service=unit.read_text()
        self.assertIn("ConditionPathExists=/etc/default/vpngw-dns-policy-upstream",service)
        self.assertIn("ExecStart=/usr/bin/python3 /usr/local/libexec/vpngw-dns-worker-bootstrap.py",service)
        for filename in ("start.sh","installers/install-policy-agent-linux.sh"):
            source=(ROOT/filename).read_text()
            self.assertNotIn("systemctl enable --now vpngw-dns-policy-upstream",source)
            self.assertNotIn("compose.v2-central-dns.opt-in.yml",source)

    def test_release_dns_path_remains_provider_until_cutover_proven(self):
        original=(ROOT/"deploy/compose.pihole-lan-dns.yml").read_text()
        self.assertIn("FTLCONF_dns_upstreams: '1.1.1.1'",original)
        agent=(ROOT/"scripts/vpngw-dns-central-preflight.py").read_text()
        self.assertIn('check("atomic_pihole_cutover",False',agent)
        self.assertIn('check("dns_fail_closed_live",False',agent)

    def test_dns_over_https_not_misrepresented_as_blocked(self):
        guard=(ROOT/"scripts/vpngw-vpn-host-guard.py").read_text()
        self.assertIn("tcp dport 853 counter drop",guard)
        self.assertIn("udp dport 853 counter drop",guard)
        self.assertNotIn("tcp dport 443 counter drop",guard)
        ui=(ROOT/"apps/web/src/main.tsx").read_text()
        self.assertIn("DNS-over-HTTPS (port 443)",ui)

    def test_no_workflow_changes_published_repo(self):
        workflow=ROOT/".github/workflows/ci.yml"
        if workflow.is_file():
            self.assertIn("scripts/test-dns-origin-dnat-netns.py",workflow.read_text())
        else:
            # Public clone explicitly carries no GitHub Actions; local QA is authoritative.
            self.assertFalse((ROOT/".github/workflows").exists())
            local_ci=(ROOT/"scripts/run-local-ci.sh").read_text()
            self.assertIn("scripts/test-dns-origin-dnat-netns.py",local_ci)


if __name__=="__main__":
    unittest.main()
