#!/usr/bin/env python3
"""Systemd timer callback: restore deliberately corrupted *sandbox* network files.

Never writes outside a fixed /tmp rehearsal directory. Not a live rollback.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path

BASE = Path('/tmp')
PREFIX = 'vpngw-rollback-rehearsal-'


def verify_module():
    spec = importlib.util.spec_from_file_location('rollback_verify', Path(__file__).with_name('network-rollback-verify.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def restore(run_id):
    if not run_id.isascii() or not all(c.isalnum() or c == '_' for c in run_id) or len(run_id) > 32:
        raise ValueError('invalid_run_id')
    root = BASE / (PREFIX + run_id)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('rehearsal_directory_missing')
    snapshot = root / 'snapshot'
    target = root / 'candidate'
    if target.is_symlink() or not target.is_dir() or snapshot.is_symlink():
        raise ValueError('unsafe_rehearsal_paths')
    entries = verify_module().verify(snapshot)
    expected = {name for name, _, _ in entries}
    present = {p.name for p in target.iterdir()}
    if expected != present or any(p.is_symlink() or not p.is_file() for p in target.iterdir()):
        raise ValueError('candidate_files_mismatch')
    # All source bytes verified before any sandbox writes.
    for name, data, mode in entries:
        destination = target / name
        fd = os.open(destination, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(destination, mode)
    report = {'mode': 'sandbox_rollback', 'restored_files': sorted(expected),
              'restored_sha256': {name: hashlib.sha256((target / name).read_bytes()).hexdigest()
                                  for name in expected},
              'system_network_modified': False}
    marker = root / 'restored.json'
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(report, output)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    print(json.dumps(restore(args.run_id), indent=2))


if __name__ == '__main__':
    main()
