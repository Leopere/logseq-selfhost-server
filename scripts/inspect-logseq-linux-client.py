#!/usr/bin/env python3
# Copyright (c) 2026 Colin Knapp, https://colinknapp.com
# SPDX-License-Identifier: AGPL-3.0-only
"""Inspect the pinned upstream Linux Logseq archive without patching it."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / 'client/base/patch-plan.json'
BUILD_PATH = ROOT / 'scripts/build-logseq-selfhost-client.py'
EXPECTED_ZIP_SHA256 = '289eadd4dfcbdd2ab71aeb6cf02a53d0b5d7340865c528b1434bef8001900a9a'
MAX_ZIP_BYTES = 200_000_000
MAX_ASAR_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
CRITICAL_ENTRIES = (
    'electron.js', 'js/preload.js', 'js/main.js', 'package.json',
    'js/db-worker-node.js',
)
CONTEXT_RADIUS = 240
CONTEXT_LIMIT = 8


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def safe_member_name(name: str) -> bool:
    if not name or '\\' in name or '\x00' in name:
        return False
    path = PurePosixPath(name)
    parts = name.split('/')
    if parts[-1] == '':
        parts.pop()
    return not path.is_absolute() and all(part not in ('', '.', '..') for part in parts)


def extract_pinned_asar(zip_path: Path, destination: Path, expected_sha256: str = EXPECTED_ZIP_SHA256) -> tuple[str, str]:
    """Validate the supplied ZIP and stream its one permitted ASAR member."""
    if zip_path.is_symlink() or not zip_path.is_file():
        raise ValueError('Input must be a regular, non-symlink ZIP file')
    if zip_path.stat().st_size > MAX_ZIP_BYTES:
        raise ValueError('ZIP exceeds the bounded input size')
    zip_digest = sha256_file(zip_path)
    if zip_digest != expected_sha256:
        raise ValueError('Pinned Linux ZIP SHA-256 differs')

    with zipfile.ZipFile(zip_path) as archive:
        members = archive.infolist()
        if not members or len(members) > MAX_ARCHIVE_MEMBERS:
            raise ValueError('ZIP member count is outside the permitted bounds')
        selected = []
        seen = set()
        for info in members:
            name = info.filename
            if not safe_member_name(name.rstrip('/') if info.is_dir() else name):
                raise ValueError('ZIP contains an unsafe member path')
            if name in seen:
                raise ValueError('ZIP contains duplicate member names')
            seen.add(name)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError('ZIP contains a symbolic link')
            if not info.is_dir() and (name == 'resources/app.asar' or name.endswith('/resources/app.asar')):
                selected.append(info)
        if len(selected) != 1:
            raise ValueError('ZIP must contain exactly one resources/app.asar member')
        info = selected[0]
        if info.file_size <= 0 or info.file_size > MAX_ASAR_BYTES:
            raise ValueError('ASAR member size is outside the permitted bounds')
        if info.compress_size < 0 or info.compress_size > MAX_ZIP_BYTES:
            raise ValueError('ASAR compressed size is outside the permitted bounds')
        written = 0
        with archive.open(info) as source, destination.open('xb') as target:
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                written += len(chunk)
                if written > info.file_size or written > MAX_ASAR_BYTES:
                    raise ValueError('ASAR extraction exceeded its declared bounds')
                target.write(chunk)
        if written != info.file_size:
            raise ValueError('ASAR member size differs from ZIP metadata')
    return zip_digest, sha256_file(destination)


def inspect_asar(asar_path: Path, asar_sha256: str) -> dict:
    spec = importlib.util.spec_from_file_location('logseq_client_build', BUILD_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError('Unable to load the reviewed ASAR reader')
    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    plan = json.loads(PLAN_PATH.read_text())
    header, base, _ = build.asar_header(asar_path)
    entries = {}
    contents = {}
    for name in CRITICAL_ENTRIES:
        data = build.read_entry(asar_path, header, base, name)
        digest = hashlib.sha256(data).hexdigest()
        entries[name] = {'sha256': digest, 'matches_mac_plan': digest == plan['files'].get(name)}
        contents[name] = data
    package = json.loads(contents['package.json'])
    if package.get('version') != '2.0.2':
        raise ValueError('ASAR package version differs from pinned Logseq 2.0.2')
    worker = contents['js/db-worker-node.js'].decode('utf-8')
    contexts = []
    cursor = 0
    while len(contexts) < CONTEXT_LIMIT:
        found = worker.find('runtime-locks', cursor)
        if found < 0:
            break
        start, end = max(0, found - CONTEXT_RADIUS), min(len(worker), found + len('runtime-locks') + CONTEXT_RADIUS)
        contexts.append({'offset': found, 'text': worker[start:end]})
        cursor = found + len('runtime-locks')
    return {
        'schema': 'cisl2-logseq-linux-upstream-inspection/v1',
        'status': 'upstream-inspected',
        'patched': False,
        'e2ee_accepted': False,
        'platform': 'linux-x86_64',
        'version': package.get('version'),
        'upstream_zip_sha256': None,
        'asar_sha256': asar_sha256,
        'critical_entries': entries,
        'runtime_locks_context': contexts,
    }


def write_report_no_overwrite(path: Path, report: dict) -> None:
    path = path.expanduser().absolute()
    if path.is_symlink() or path.exists() or not path.parent.is_dir():
        raise ValueError('Output must be a new file in an existing directory')
    payload = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
    fd, temporary_name = tempfile.mkstemp(prefix='.logseq-inspection-', dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        # Hard-link creation is atomic and fails if another writer created path.
        os.link(temporary, path)
    except FileExistsError as error:
        raise ValueError('Refusing to overwrite existing output report') from error
    finally:
        temporary.unlink(missing_ok=True)


def inspect(zip_path: Path, output: Path, expected_sha256: str = EXPECTED_ZIP_SHA256) -> dict:
    with tempfile.TemporaryDirectory(prefix='logseq-linux-inspect-') as temporary:
        asar_path = Path(temporary) / 'app.asar'
        zip_digest, asar_digest = extract_pinned_asar(zip_path, asar_path, expected_sha256)
        report = inspect_asar(asar_path, asar_digest)
        report['upstream_zip_sha256'] = zip_digest
        write_report_no_overwrite(output, report)
        return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zip', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        print(json.dumps(inspect(args.zip, args.output), sort_keys=True))
    except (OSError, ValueError, KeyError, RuntimeError, zipfile.BadZipFile, json.JSONDecodeError) as error:
        message = str(error) if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__
        print('Linux upstream inspection failed: ' + message, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
