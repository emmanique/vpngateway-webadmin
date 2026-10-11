#!/usr/bin/env python3
"""Systemd timer callback for isolated rollback rehearsal only.

The callback can only write a marker in a dedicated /tmp directory.
It cannot restore /etc/network, invoke networkctl, or modify routes.
"""
import argparse
import json
import os
from pathlib import Path

PREFIX = '/tmp/vpngw-rollback-rehearsal-'


def mark(run_id):
    if not run_id.isascii() or not all(c.isalnum() or c == '_' for c in run_id) or len(run_id) > 32:
        raise ValueError('invalid_run_id')
    directory = Path(PREFIX + run_id)
    if directory.is_symlink() or not directory.is_dir() or directory.parent != Path('/tmp'):
        raise ValueError('rehearsal_directory_missing')
    marker = directory / 'rollback-triggered.json'
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump({'mode': 'dry_run', 'rollback_triggered': True,
                   'network_modified': False}, output)
        output.flush()
        os.fsync(output.fileno())
    return marker


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    print(mark(args.run_id))


if __name__ == '__main__':
    main()
