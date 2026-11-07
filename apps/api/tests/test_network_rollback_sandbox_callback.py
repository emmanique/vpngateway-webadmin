"""Restore actual bytes in isolated candidate directory, not host network."""
import importlib.util
from pathlib import Path
import tempfile
import secrets
import unittest

ROOT = Path(__file__).resolve().parents[3] / 'scripts'

def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

snapshot = load('network-rollback-snapshot')
callback = load('network-rollback-sandbox-callback')


class SandboxCallbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/tmp', prefix='vpngw-rollback-rehearsal-' + secrets.token_hex(8), suffix='')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run_id = self.root.name.removeprefix('vpngw-rollback-rehearsal-')
        self.candidate = self.root / 'candidate'
        self.candidate.mkdir()
        self.network = self.candidate / 'eth0.network'
        self.original = b'[Network]\nAddress=192.168.1.201/24\n'
        self.network.write_bytes(self.original)
        snapshot.snapshot(self.candidate, self.root / 'snapshot')

    def test_corruption_restored_by_callback(self):
        self.network.write_bytes(b'BROKEN CONFIG')
        result = callback.restore(self.run_id)
        self.assertEqual(self.network.read_bytes(), self.original)
        self.assertFalse(result['system_network_modified'])

    def test_snapshot_tampering_fails_closed(self):
        self.network.write_bytes(b'BROKEN CONFIG')
        (self.root / 'snapshot' / 'eth0.network').write_bytes(b'TAMPERED')
        with self.assertRaisesRegex(ValueError, 'snapshot_integrity_failure'):
            callback.restore(self.run_id)
        self.assertEqual(self.network.read_bytes(), b'BROKEN CONFIG')

    def test_rejects_traversal(self):
        with self.assertRaisesRegex(ValueError, 'invalid_run_id'):
            callback.restore('../etc')

    def test_candidate_symlink_fails_closed(self):
        self.network.unlink()
        self.network.symlink_to('/etc/hosts')
        with self.assertRaisesRegex(ValueError, 'candidate_files_mismatch'):
            callback.restore(self.run_id)


if __name__ == '__main__':
    unittest.main()
