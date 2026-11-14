#!/usr/bin/env python3
# Copyright (c) 2026 Colin Knapp, https://colinknapp.com
# SPDX-License-Identifier: AGPL-3.0-only
"""Package an isolated Logseq Selfhost Linux x86_64 candidate; no launch/install."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
INSPECT_PATH = ROOT / 'scripts/inspect-logseq-linux-client.py'
BUILD_PATH = ROOT / 'scripts/build-logseq-selfhost-client.py'
LINUX_ASAR_SHA256 = '2cd1334062360b64ac1a9c3dcafbc1140be62281f721a66a0d09cc8c2319a572'
LINUX_RUNTIME_PATH = 'r.join(n,".local","state","Logseq","runtime-locks")'
SELFHOST_RUNTIME_PATH = 'r.join(n,".local","state","Logseq Selfhost","runtime-locks")'
MAX_TOTAL_UNCOMPRESSED = 2 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 1024 * 1024 * 1024


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError('Unable to load reviewed Logseq helper')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INSPECT = load_module('logseq_linux_inspect_for_build', INSPECT_PATH)
BUILD = load_module('logseq_client_build_for_linux', BUILD_PATH)
PLAN = json.loads((ROOT / 'client/base/patch-plan.json').read_text())


def safe_revision(value: str) -> bool:
    return len(value) == 40 and all(char in '0123456789abcdef' for char in value)


def isolate_linux_runtime_path(source: str) -> str:
    if source.count(LINUX_RUNTIME_PATH) != 1:
        raise ValueError('Reviewed Linux runtime ownership path must occur exactly once')
    patched = source.replace(LINUX_RUNTIME_PATH, SELFHOST_RUNTIME_PATH, 1)
    if LINUX_RUNTIME_PATH in patched:
        raise ValueError('Original Linux runtime ownership path remains')
    return patched


def safe_output_path(path: Path) -> Path:
    output = path.expanduser().absolute()
    if any(parent.is_symlink() for parent in (output, *output.parents)):
        raise ValueError('Output path or one of its parents is a symlink')
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output.is_symlink() or not output.is_dir():
        raise ValueError('Output root must be a real directory')
    if any(parent.is_symlink() for parent in (output, *output.parents)):
        raise ValueError('Output path or one of its parents is a symlink')
    metadata = output.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ValueError('Output root must be owned by the current user and not group/world-writable')
    return output


def create_candidate_directory(output_root: Path, revision: str) -> Path:
    if not safe_revision(revision):
        raise ValueError('Exact 40-character lowercase source revision required')
    output_root = safe_output_path(output_root)
    candidate = output_root / revision
    if candidate.is_symlink() or candidate.exists():
        raise ValueError('Candidate revision directory already exists; reconcile it before retry')
    candidate.mkdir(mode=0o700, exist_ok=False)
    return candidate


def validate_and_extract(zip_path: Path, staging: Path) -> tuple[str, str, Path]:
    """Verify the immutable ZIP, safely extract all entries, return app root."""
    if zip_path.is_symlink() or not zip_path.is_file():
        raise ValueError('Input must be a regular, non-symlink ZIP file')
    if zip_path.stat().st_size > INSPECT.MAX_ZIP_BYTES:
        raise ValueError('ZIP exceeds the pinned input size bound')
    zip_digest = INSPECT.sha256_file(zip_path)
    if zip_digest != INSPECT.EXPECTED_ZIP_SHA256:
        raise ValueError('Pinned Linux ZIP SHA-256 differs')

    # Reuse the inspector's guarded single-member extraction and published hash.
    upstream_asar = staging.parent / 'validated-upstream.asar'
    _, asar_digest = INSPECT.extract_pinned_asar(zip_path, upstream_asar)
    if asar_digest != LINUX_ASAR_SHA256:
        raise ValueError('Pinned Linux upstream ASAR SHA-256 differs')

    staging.mkdir(mode=0o700)
    total = 0
    seen = set()
    directory_modes = {}
    app_prefix = None
    with zipfile.ZipFile(zip_path) as archive:
        members = archive.infolist()
        if not members or len(members) > INSPECT.MAX_ARCHIVE_MEMBERS:
            raise ValueError('ZIP member count is outside the permitted bounds')
        selected = []
        for info in members:
            name = info.filename
            normalized = name.rstrip('/') if info.is_dir() else name
            if not INSPECT.safe_member_name(normalized):
                raise ValueError('ZIP contains an unsafe member path')
            if name in seen:
                raise ValueError('ZIP contains duplicate member names')
            seen.add(name)
            raw_mode = info.external_attr >> 16
            if stat.S_ISLNK(raw_mode):
                raise ValueError('ZIP contains a symbolic link')
            file_type = stat.S_IFMT(raw_mode)
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError('ZIP contains a non-regular file')
            if info.file_size < 0 or info.file_size > MAX_MEMBER_BYTES:
                raise ValueError('ZIP member exceeds the bounded extraction size')
            total += info.file_size
            if total > MAX_TOTAL_UNCOMPRESSED:
                raise ValueError('ZIP total uncompressed size exceeds the bound')
            if not info.is_dir() and (name == 'resources/app.asar' or name.endswith('/resources/app.asar')):
                selected.append(info)
        if len(selected) != 1:
            raise ValueError('ZIP must contain exactly one resources/app.asar member')
        parts = PurePosixPath(selected[0].filename).parts
        if len(parts) < 2:
            raise ValueError('Linux app archive root is invalid')
        app_prefix = tuple(parts[:-2])

        for info in members:
            parts = PurePosixPath(info.filename.rstrip('/') if info.is_dir() else info.filename).parts
            destination = staging.joinpath(*parts)
            if info.is_dir():
                destination.mkdir(parents=True, exist_ok=True, mode=0o755)
                directory_modes[destination] = (info.external_attr >> 16) & 0o777 or 0o755
                continue
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            mode = (info.external_attr >> 16) & 0o777 or 0o644
            written = 0
            with archive.open(info) as source, destination.open('xb') as target:
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    written += len(chunk)
                    if written > info.file_size or written > MAX_MEMBER_BYTES:
                        raise ValueError('ZIP member exceeded its declared extraction bound')
                    target.write(chunk)
                if written != info.file_size:
                    raise ValueError('ZIP member size differs from its metadata')
            os.chmod(destination, mode)
        for directory, mode in sorted(directory_modes.items(), key=lambda pair: len(pair[0].parts), reverse=True):
            os.chmod(directory, mode)

    app_root = staging.joinpath(*app_prefix)
    if not app_root.is_dir() or app_root.is_symlink():
        raise ValueError('Pinned ZIP app root is missing or unsafe')
    return zip_digest, asar_digest, app_root


def validate_original_entries(asar: Path, expected_asar_sha256: str) -> tuple[dict, int, dict]:
    if BUILD.sha(asar) != expected_asar_sha256:
        raise ValueError('Pinned Linux upstream ASAR SHA-256 differs')
    header, base, _ = BUILD.asar_header(asar)
    package = json.loads(BUILD.read_entry(asar, header, base, 'package.json'))
    if package.get('version') != '2.0.2':
        raise ValueError('ASAR package version differs from pinned Logseq 2.0.2')
    # replacements() enforces every unchanged Mac-plan entry digest and exact patch anchors.
    updates = BUILD.replacements(asar, header, base)
    worker = BUILD.read_entry(asar, header, base, 'js/db-worker-node.js').decode('utf-8')
    if worker.count(LINUX_RUNTIME_PATH) != 1:
        raise ValueError('Linux runtime ownership path must occur exactly once upstream')
    updates['js/db-worker-node.js'] = isolate_linux_runtime_path(updates['js/db-worker-node.js'].decode()).encode()
    for name, expected in PLAN['files'].items():
        if name not in updates:
            # The recipe must still provide a changed entry for each reviewed source file.
            data = BUILD.read_entry(asar, header, base, name)
            if hashlib.sha256(data).hexdigest() != expected:
                raise ValueError('Reviewed upstream critical entry differs: ' + name)
    return header, base, updates


def write_runtime_archive(app: Path, stream) -> None:
    # Keep the validated upstream copy on the builder for immutable reuse; the
    # runnable download needs only the patched archive, not that duplicate.
    def runtime_member(member):
        if member.name == 'Logseq Selfhost/resources/app.asar.upstream':
            return None
        return member
    with tarfile.open(fileobj=stream, mode='w:gz', compresslevel=1) as archive:
        archive.add(app, arcname='Logseq Selfhost', recursive=True, filter=runtime_member)


def write_launcher(app: Path) -> None:
    binary = app / 'logseq'
    if not binary.is_file() or binary.is_symlink() or not os.access(binary, os.X_OK):
        raise ValueError('Official Linux Logseq executable is missing or not executable')
    launcher = app / 'logseq-selfhost'
    launcher.write_text('#!/bin/sh\nset -eu\nHERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec "$HERE/logseq" "$@"\n')
    os.chmod(launcher, 0o755)
    (app / 'README-SELFHOST.txt').write_text(
        'Logseq Selfhost 2.0.2 for Linux x86_64\n\n'
        'Run ./logseq-selfhost. Enter your operator\'s HTTPS sync server URL and issued private sync code.\n'
        'Use Sync > Sync settings to change the URL or code. The app restarts after verification.\n'
        'Open your graph under Remote graphs. No Logseq account or separate encryption password is required.\n\n'
        'The app saves its owner configuration privately at ~/.config/cisl2/logseq-selfhost/owner.json '
        '(directory0700/file0600). Keep your code outside the application package and Git. '
        'The code unlocks your encrypted graphs on every enrolled device.\n\n'
        'Electron runtime locks are isolated under ~/.local/state/Logseq Selfhost. '
        'This Linux build has not been run on your ASUS.\n'
    )


def package_candidate(zip_path: Path, output_root: Path, revision: str) -> dict:
    output_root = safe_output_path(output_root)
    if not safe_revision(revision):
        raise ValueError('Exact 40-character lowercase source revision required')
    candidate = output_root / revision
    archive_path = output_root / f'logseq-selfhost-linux-x86_64-{revision}.tar.gz'
    if archive_path.is_symlink() or archive_path.exists():
        raise ValueError('Candidate output already exists; reconcile it before retry')
    candidate = create_candidate_directory(output_root, revision)
    try:
        staging = candidate / '.zip-extract'
        zip_digest, upstream_asar_digest, app_root = validate_and_extract(zip_path, staging)
        app = candidate / 'Logseq Selfhost'
        shutil.copytree(app_root, app, symlinks=False)
        shutil.rmtree(staging)
        (candidate / 'validated-upstream.asar').unlink(missing_ok=True)

        resources = app / 'resources'
        asar = resources / 'app.asar'
        if not asar.is_file() or asar.is_symlink():
            raise ValueError('Extracted app.asar is missing or unsafe')
        original = resources / 'app.asar.upstream'
        shutil.copy2(asar, original)
        header, base, updates = validate_original_entries(original, upstream_asar_digest)
        temp_asar = resources / 'app.asar.selfhost'
        header_hash = BUILD.append_archive(original, temp_asar, updates)
        os.chmod(temp_asar, stat.S_IMODE(asar.stat().st_mode))
        os.replace(temp_asar, asar)
        if LINUX_RUNTIME_PATH in BUILD.read_entry(asar, *BUILD.asar_header(asar)[:2], 'js/db-worker-node.js').decode():
            raise ValueError('Original Linux runtime ownership path remains in candidate')
        write_launcher(app)

        fd, temporary_name = tempfile.mkstemp(prefix='.logseq-selfhost-', suffix='.tar.gz', dir=output_root)
        temporary_archive = Path(temporary_name)
        try:
            with os.fdopen(fd, 'wb') as stream:
                write_runtime_archive(app, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary_archive, archive_path)
        finally:
            temporary_archive.unlink(missing_ok=True)

        candidate_asar_digest = BUILD.sha(asar)
        receipt = {
            'schema': 'cisl2-logseq-linux-selfhost-client/v1',
            'status': 'linux-candidate',
            'platform': 'linux-x86_64',
            'version': '2.0.2',
            'source_revision': revision,
            'upstream_zip_sha256': zip_digest,
            'upstream_asar_sha256': upstream_asar_digest,
            'candidate_asar_sha256': candidate_asar_digest,
            'upstream_asar_preserved_at': str(original.relative_to(candidate)),
            'candidate_archive': str(archive_path),
            'candidate_archive_sha256': BUILD.sha(archive_path),
            'asar_header_sha256': header_hash,
            'runtime_locks_path': '~/.local/state/Logseq Selfhost/runtime-locks',
            'patched': True,
            'e2ee_accepted': False,
            'runtime_accepted': False,
            'installed': False,
            'launched': False,
            'modified_entries': sorted(updates),
        }
        (candidate / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
        os.chmod(candidate / 'receipt.json', 0o600)
        return receipt
    except Exception:
        # Preserve a failed fresh candidate for inspection; never overwrite it on retry.
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zip', type=Path, required=True)
    parser.add_argument('--output-root', type=Path, required=True)
    parser.add_argument('--source-revision', required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        print(json.dumps(package_candidate(args.zip, args.output_root, args.source_revision), sort_keys=True))
    except (OSError, ValueError, KeyError, RuntimeError, zipfile.BadZipFile, tarfile.TarError, json.JSONDecodeError) as error:
        message = str(error) if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__
        print('Linux Selfhost candidate failed: ' + message, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
