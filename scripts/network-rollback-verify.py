#!/usr/bin/env python3
"""Offline verification and sandbox restore of networkd snapshots.

Never writes /etc, reloads networkd, changes routes or arms timers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re


def verify(snapshot):
    snapshot = Path(snapshot)
    if not snapshot.is_dir() or snapshot.is_symlink():
        raise ValueError('invalid_snapshot_directory')
    manifest_file = snapshot / 'manifest.json'
    if manifest_file.is_symlink():
        raise ValueError('unsafe_manifest')
    manifest = json.loads(manifest_file.read_text())
    if manifest.get('format') != 1 or not isinstance(manifest.get('files'), list) or not manifest['files']:
        raise ValueError('invalid_manifest')
    verified = []
    seen = set()
    for entry in manifest['files']:
        if not isinstance(entry, dict):
            raise ValueError('invalid_entry')
        name = entry.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+\.network', name) or name in seen:
            raise ValueError('unsafe_or_duplicate_filename')
        seen.add(name)
        path = snapshot / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('unsafe_snapshot_file')
        data = path.read_bytes()
        if len(data) != entry.get('size') or hashlib.sha256(data).hexdigest() != entry.get('sha256'):
            raise ValueError('snapshot_integrity_failure')
        mode = entry.get('mode')
        if not isinstance(mode, str) or not re.fullmatch(r'0o[0-7]{3,4}', mode):
            raise ValueError('invalid_file_mode')
        verified.append((name, data, int(mode, 8)))
    return verified


def restore_to_sandbox(snapshot, destination):
    """Exercise restoration only to a new directory below /tmp."""
    destination = Path(destination)
    resolved_parent = destination.parent.resolve()
    if resolved_parent != Path('/tmp') or destination.exists() or destination.is_symlink():
        raise ValueError('sandbox_destination_required')
    files = verify(snapshot)
    destination.mkdir(mode=0o700)
    try:
        for name, data, mode in files:
            fd = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            os.chmod(destination / name, mode)
        return {'mode': 'sandbox_restore', 'restored_files': [name for name, _, _ in files],
                'system_network_modified': False, 'destination': str(destination)}
    except Exception:
        for child in destination.iterdir():
            child.unlink()
        destination.rmdir()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', required=True)
    parser.add_argument('--sandbox-destination')
    args = parser.parse_args()
    result = (restore_to_sandbox(args.snapshot, args.sandbox_destination)
              if args.sandbox_destination else
              {'mode': 'verify_only', 'verified_files': [n for n, _, _ in verify(args.snapshot)],
               'system_network_modified': False})
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
