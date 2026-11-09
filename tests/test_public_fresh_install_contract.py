import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class PublicFreshInstallContract(unittest.TestCase):
    def test_non_login_root_shell_has_sbin_path(self):
        script = (ROOT / "start.sh").read_text()
        self.assertIn('export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:', script)
        self.assertLess(script.index('export PATH='), script.index('dependencies_ok()'))

    def test_compose_package_fallback_on_debian13(self):
        script = (ROOT / "start.sh").read_text()
        self.assertRegex(script, r"for compose_package in docker-compose-v2 docker-compose-plugin docker-compose")
        self.assertIn('docker compose version >/dev/null 2>&1', script)

    def test_buildx_required_for_clean_source_build(self):
        script = (ROOT / "start.sh").read_text()
        self.assertIn('docker buildx version >/dev/null 2>&1', script)
        self.assertIn('docker-buildx-plugin', script)

    def test_fresh_install_uses_passwordless_lan_pihole(self):
        script = (ROOT / "start.sh").read_text()
        self.assertIn("printf 'PIHOLE_WEBPASSWORD=\\n' > deploy/.env", script)
        self.assertNotIn('PIHOLE_FRESH_PASSWORD', script)
        self.assertIn('chmod 0600 deploy/.env', script)

    def test_runtime_images_match_repository_version(self):
        launcher = (ROOT / "start.sh").read_text()
        compose = (ROOT / "deploy/compose.yml").read_text()
        self.assertIn('export VPNGW_IMAGE_TAG="$(cat VERSION)"', launcher)
        version = (ROOT / "VERSION").read_text().strip()
        self.assertIn('image: vpngateway/webadmin:${VPNGW_IMAGE_TAG:-' + version + '}', compose)
        self.assertIn('image: vpngateway/vpn:${VPNGW_IMAGE_TAG:-' + version + '}', compose)
        self.assertNotIn('image: vpngateway/webadmin:1.0.3', compose)

    def test_existing_env_is_not_overwritten(self):
        script = (ROOT / "start.sh").read_text()
        self.assertRegex(script, r'if \[\[ ! -f deploy/\.env \]\]; then')
        self.assertIn("if [[ ! -f deploy/.env ]]; then", script)


if __name__ == "__main__":
    unittest.main()
