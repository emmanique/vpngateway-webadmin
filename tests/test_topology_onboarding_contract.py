"""Fresh-install onboarding: topology confirmation gates menu and locks edits."""
import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TopologyOnboardingContract(unittest.TestCase):
    def test_confirmed_network_is_not_silently_editable(self):
        src = (ROOT / "apps/api/main.py").read_text()
        tree = ast.parse(src)
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "save_network_config")
        body = ast.get_source_segment(src, fn)
        self.assertIn('get_network_config()["applied"]', body)
        self.assertIn("HTTPException(409", body)

    def test_menu_locked_until_topology_confirmed(self):
        src = (ROOT / "apps/web/src/main.tsx").read_text()
        self.assertIn("const [networkLoaded,setNetworkLoaded]", src)
        self.assertIn("setNetworkLoaded(true)", src)
        self.assertIn("disabled={!networkLoaded || (!networkApplied && key!=='overview' && key!=='network')}", src)
        self.assertIn("<fieldset disabled={networkApplied}", src)
        self.assertIn("page!=='overview'&&page!=='network'", src)

    def test_installed_version_comes_from_release(self):
        src = (ROOT / "apps/api/main.py").read_text()
        self.assertIn('version=os.environ.get("VPNGW_RELEASE_VERSION"', src)
        self.assertIn("return {'version':app.version,", src)
        compose = (ROOT / "deploy/compose.yml").read_text()
        self.assertIn('VPNGW_RELEASE_VERSION: "${VPNGW_IMAGE_TAG:-1.0.7}"', compose)


if __name__ == "__main__":
    unittest.main()