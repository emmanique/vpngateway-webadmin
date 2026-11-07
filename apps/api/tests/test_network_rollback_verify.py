"""Offline restore tests, including tampering and unsafe paths."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3] / 'scripts'

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

snapshot_module = load('snapshot_module', 'network-rollback-snapshot.py')
verify_module = load('verify_module', 'network-rollback-verify.py')


class RollbackVerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        source = base / 'source'
        source.mkdir()
        (source / 'eth0.network').write_bytes(b'[Network]\nAddress=192.168.1.201/24\n')
        self.snapshot = base / 'snapshot'
        snapshot_module.snapshot(source, self.snapshot)

    def test_verify_valid_snapshot(self):
        self.assertEqual(verify_module.verify(self.snapshot)[0][0], 'eth0.network')

    def test_restore_bytes_to_sandbox(self):
        target = Path('/tmp') / ('vpngw-restore-test-' + Path(self.temp.name).name)
        self.addCleanup(lambda: target.rmdir() if target.exists() and not list(target.iterdir()) else None)
        report = verify_module.restore_to_sandbox(self.snapshot, target)
        self.assertFalse(report['system_network_modified'])
        self.assertEqual((target / 'eth0.network').read_bytes(),
                         (self.snapshot / 'eth0.network').read_bytes())
        (target / 'eth0.network').unlink()

    def test_tampering_rejected(self):
        (self.snapshot / 'eth0.network').write_text('modified')
        with self.assertRaisesRegex(ValueError, 'snapshot_integrity_failure'):
            verify_module.verify(self.snapshot)

    def test_symlink_rejected(self):
        path = self.snapshot / 'eth0.network'
        path.unlink()
        path.symlink_to('/etc/hosts')
        with self.assertRaisesRegex(ValueError, 'unsafe_snapshot_file'):
            verify_module.verify(self.snapshot)

    def test_live_destination_rejected(self):
        with self.assertRaisesRegex(ValueError, 'sandbox_destination_required'):
            verify_module.restore_to_sandbox(self.snapshot, '/etc/systemd/network')

    def test_existing_destination_rejected(self):
        with self.assertRaisesRegex(ValueError, 'sandbox_destination_required'):
            verify_module.restore_to_sandbox(self.snapshot, self.snapshot)


if __name__ == '__main__':
    unittest.main()
