"""Byte-exact network rollback snapshot regression tests."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[3] / 'scripts' / 'network-rollback-snapshot.py'
spec = importlib.util.spec_from_file_location('network_rollback_snapshot', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NetworkRollbackSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name) / 'network'
        self.source.mkdir()
        self.file = self.source / 'eth0.network'
        self.data = b'[Match]\nName=eth0\n[Network]\nAddress=192.168.1.201/24\n'
        self.file.write_bytes(self.data)
        self.target = Path(self.tmp.name) / 'backup'

    def test_snapshot_preserves_bytes_and_hash(self):
        report = module.snapshot(self.source, self.target)
        self.assertEqual((self.target / 'eth0.network').read_bytes(), self.data)
        self.assertEqual(report['files'][0]['sha256'], hashlib.sha256(self.data).hexdigest())
        self.assertFalse(report['network_changes_applied'])

    def test_existing_snapshot_never_overwritten(self):
        module.snapshot(self.source, self.target)
        with self.assertRaisesRegex(ValueError, 'snapshot_already_exists'):
            module.snapshot(self.source, self.target)

    def test_symlink_network_file_refused(self):
        (self.source / 'eth1.network').symlink_to(self.file)
        with self.assertRaisesRegex(ValueError, 'unsafe_network_file'):
            module.snapshot(self.source, self.target)
        self.assertFalse(self.target.exists())

    def test_empty_source_refused(self):
        self.file.unlink()
        with self.assertRaisesRegex(ValueError, 'no_network_files'):
            module.snapshot(self.source, self.target)


if __name__ == '__main__':
    unittest.main()
