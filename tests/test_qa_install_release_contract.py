"""Regression gates for deployment packaging and VPN lifecycle fixes."""
import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class QAInstallReleaseContract(unittest.TestCase):
    def test_nginx_configs_are_versioned(self):
        for filename in ('webadmin-nginx.conf', 'webadmin-lan-https.conf'):
            self.assertTrue((ROOT / 'deploy' / filename).is_file())
        rules = (ROOT / '.dockerignore').read_text()
        self.assertIn('!deploy/webadmin-nginx.conf', rules)
        self.assertIn('!deploy/webadmin-lan-https.conf', rules)

    def test_pihole_install_is_passwordless_on_lan_only(self):
        compose = (ROOT / 'deploy/compose.yml').read_text()
        self.assertIn('FTLCONF_webserver_api_password: "${PIHOLE_WEBPASSWORD:-}"', compose)
        installer = (ROOT / 'start.sh').read_text()
        self.assertIn("printf 'PIHOLE_WEBPASSWORD=\\n' > deploy/.env", installer)
        self.assertIn('if [[ ! -f deploy/.env ]]; then', installer)
        self.assertNotIn('Segredo inválido', installer)
        self.assertIn('PIHOLE_WEBPASSWORD=', (ROOT / 'deploy/.env.example').read_text())

    def test_openvpn_agent_has_explicit_write_access(self):
        unit = (ROOT / 'deploy/systemd/vpngw-policy-agent.service').read_text()
        self.assertIn('ProtectSystem=strict', unit)
        self.assertIn('/etc/openvpn/client', next(line for line in unit.splitlines() if line.startswith('ReadWritePaths=')))

    def test_npm_downloads_have_retry_and_timeout(self):
        for filename in ('apps/web/Dockerfile', 'apps/web/Dockerfile.webadmin'):
            content = (ROOT / filename).read_text()
            self.assertIn('npm_config_fetch_retries=5', content)
            self.assertIn('npm_config_fetch_timeout=180000', content)

    def test_pypi_downloads_have_retry_and_timeout(self):
        for filename in ('apps/api/Dockerfile', 'apps/web/Dockerfile.webadmin'):
            content = (ROOT / filename).read_text()
            self.assertIn('pip install --timeout 180 --retries 10', content)

    def test_missing_vpn_guard_is_defined_and_openvpn_delete_cleans_files(self):
        source = (ROOT / 'apps/api/main.py').read_text()
        tree = ast.parse(source)
        names = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.assertIn('_vpn_host_automation_ready', names)
        delete = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'delete_connection')
        body = ast.get_source_segment(source, delete)
        self.assertIn('openvpn_backup_export', body)
        self.assertIn('openvpn_backup_restore', body)

    def test_direct_host_lifecycle_contract_is_consistent(self):
        source = (ROOT / 'apps/api/main.py').read_text()
        tree = ast.parse(source)
        methods = {n.name: ast.get_source_segment(source, n) for n in tree.body if isinstance(n, ast.FunctionDef)}
        self.assertIn('"service_active":False', methods['direct_hosts'])
        for name in ('create_policy', 'update_policy', 'delete_policy'):
            self.assertIn('h.get("service_active", False)', methods[name])
            self.assertNotIn('h["service_active"]', methods[name])

    def test_dns_ui_uses_current_management_host(self):
        ui = (ROOT / 'apps/web/src/main.tsx').read_text()
        self.assertNotIn('https://IP da LAN:8443/admin/', ui)
        self.assertIn('window.location.hostname}:8443/admin/', ui)


if __name__ == '__main__':
    unittest.main()
