"""Regression tests for the static Pi-hole installer safety audit."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[3] / 'scripts' / 'pihole-installer-audit.py'
spec = importlib.util.spec_from_file_location('pihole_installer_audit', SCRIPT)
audit_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_module)


class InstallerAuditTests(unittest.TestCase):
    def test_sensitive_first_start_order_is_reported(self):
        script = '''disable_resolved_stublistener() {
cat > /etc/systemd/resolved.conf.d/90-pi-hole-disable-stub-listener.conf
systemctl reload-or-restart systemd-resolved
}
disable_resolved_stublistener
restart_service pihole-FTL
setFTLConfigValue "dns.interface" "eth0"
'''
        report = audit_module.audit(script)
        self.assertTrue(report['audit_complete'])
        self.assertTrue(report['installer_modifies_systemd_resolved'])
        self.assertTrue(report['first_ftl_start_precedes_interface_configuration'])
        self.assertFalse(report['safe_to_execute_on_gateway'])

    def test_missing_markers_fail_closed(self):
        report = audit_module.audit('echo safe')
        self.assertFalse(report['audit_complete'])
        self.assertFalse(report['safe_to_execute_on_gateway'])

    def test_order_reversal_is_visible(self):
        script = '''disable_resolved_stublistener() {
90-pi-hole-disable-stub-listener.conf
systemctl reload-or-restart systemd-resolved
}
disable_resolved_stublistener
setFTLConfigValue "dns.interface" "eth0"
restart_service pihole-FTL
'''
        report = audit_module.audit(script)
        self.assertTrue(report['audit_complete'])
        self.assertFalse(report['first_ftl_start_precedes_interface_configuration'])


if __name__ == '__main__':
    unittest.main()
