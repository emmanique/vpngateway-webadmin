"""Isolated timer callback cannot target the live network."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[3] / 'scripts' / 'network-rollback-dryrun.py'
spec = importlib.util.spec_from_file_location('network_rollback_dryrun', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DryRunTests(unittest.TestCase):
    def test_writes_one_marker_only(self):
        with tempfile.TemporaryDirectory(dir='/tmp', prefix='vpngw-rollback-rehearsal-') as directory:
            run_id = Path(directory).name.removeprefix('vpngw-rollback-rehearsal-')
            marker = module.mark(run_id)
            self.assertTrue(marker.is_file())
            self.assertIn('"network_modified": false', marker.read_text())
            with self.assertRaises(FileExistsError):
                module.mark(run_id)

    def test_rejects_traversal(self):
        with self.assertRaisesRegex(ValueError, 'invalid_run_id'):
            module.mark('../../etc')

    def test_missing_directory_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'rehearsal_directory_missing'):
            module.mark('missing123456789')


if __name__ == '__main__':
    unittest.main()
