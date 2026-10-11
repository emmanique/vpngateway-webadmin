#!/usr/bin/env python3
"""Create an immutable, byte-exact snapshot of networkd files for future rollback.

Snapshot only. Never reload networkd or change an interface/route. Refuses
symlinks, duplicate targets and existing destination directories.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


def snapshot(source, destination):
    source, destination = Path(source), Path(destination)
    if not source.is_dir() or source.is_symlink():
        raise ValueError('invalid_source_directory')
    if destination.exists() or destination.is_symlink():
        raise ValueError('snapshot_already_exists')
    entries = sorted(source.glob('*.network'))
    if not entries:
        raise ValueError('no_network_files')
    payload = []
    for path in entries:
        if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError('unsafe_network_file')
        data = path.read_bytes()
        payload.append((path.name, data, stat.S_IMODE(path.stat().st_mode)))
    destination.mkdir(mode=0o700, parents=False)
    try:
        manifest = []
        for name, data, mode in payload:
            target = destination / name
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(target, mode)
            manifest.append({'name': name, 'sha256': hashlib.sha256(data).hexdigest(),
                             'size': len(data), 'mode': oct(mode)})
        manifest_path = destination / 'manifest.json'
        manifest_path.write_text(json.dumps({'format': 1, 'files': manifest}, indent=2))
        os.chmod(manifest_path, 0o600)
        return {'mode': 'snapshot_only', 'directory': str(destination),
                'files': manifest, 'network_changes_applied': False}
    except Exception:
        for child in destination.iterdir():
            child.unlink()
        destination.rmdir()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', default='/etc/systemd/network')
    parser.add_argument('--destination', required=True)
    args = parser.parse_args()
    print(json.dumps(snapshot(args.source, args.destination), indent=2))


if __name__ == '__main__':
    main()
