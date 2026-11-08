import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class PublicFreshInstallContract(unittest.TestCase):
    def test_compose_package_fallback_on_debian13(self):
        script = (ROOT / "start.sh").read_text()
        self.assertRegex(script, r"for compose_package in docker-compose-v2 docker-compose-plugin docker-compose")
        self.assertIn('docker compose version >/dev/null 2>&1', script)

    def test_buildx_required_for_clean_source_build(self):
        script = (ROOT / "start.sh").read_text()
        self.assertIn('docker buildx version >/dev/null 2>&1', script)
        self.assertIn('docker-buildx-plugin', script)

    def test_new_install_never_creates_blank_pihole_password(self):
        script = (ROOT / "start.sh").read_text()
        self.assertIn('openssl rand -hex 24', script)
        self.assertNotIn("printf 'PIHOLE_WEBPASSWORD=\\n' > deploy/.env", script)
        self.assertIn('chmod 0600 deploy/.env', script)

    def test_existing_env_is_not_overwritten(self):
        script = (ROOT / "start.sh").read_text()
        self.assertRegex(script, r'if \[\[ ! -f deploy/\.env \]\]; then')
        self.assertIn('PIHOLE_FRESH_PASSWORD', script)


if __name__ == "__main__":
    unittest.main()
