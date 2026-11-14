#!/usr/bin/env python3
# Copyright (c) 2026 Colin Knapp, https://colinknapp.com
# SPDX-License-Identifier: AGPL-3.0-only
"""Package a pinned, isolated Logseq Selfhost candidate; Jenkins owns execution."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / 'client/base'
PLAN = json.loads((CLIENT / 'patch-plan.json').read_text())
IDENTITY = '9D9502AA3D76C0357249ED691034FA430D53238E'
TEAM = '3J3MP52AVR'
DEADLINE = None


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''): digest.update(chunk)
    return digest.hexdigest()


def bounded_timeout(timeout):
    if DEADLINE is None: return timeout
    remaining = DEADLINE - time.monotonic()
    if remaining <= 0: raise RuntimeError('Candidate packaging deadline expired; retain and reconcile its output')
    return min(timeout, remaining)


def run(args, timeout=60):
    timeout = bounded_timeout(timeout)
    result = subprocess.run([str(value) for value in args], capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Candidate command failed: ' + Path(str(args[0])).name)
    return result


def asar_header(path):
    with path.open('rb') as stream:
        prefix = stream.read(16)
        if len(prefix) != 16: raise ValueError('Invalid ASAR prefix')
        size_payload, header_size, header_payload, json_size = struct.unpack('<IIII', prefix)
        if size_payload != 4 or header_size != header_payload + 4 or not 0 < json_size <= header_payload - 4 < 4 * 1024 * 1024:
            raise ValueError('Invalid bounded ASAR header')
        raw = stream.read(json_size)
    return json.loads(raw), 8 + header_size, raw


def asar_entry(header, name):
    entry = header
    for part in name.split('/'):
        if part in ('', '.', '..'): raise ValueError('Unsafe archive member')
        entry = entry['files'][part]
    if entry.get('unpacked') or 'link' in entry or 'offset' not in entry:
        raise ValueError('Expected packed archive member')
    return entry


def read_entry(path, header, base, name):
    entry = asar_entry(header, name)
    offset, size = int(entry['offset']), entry['size']
    if offset < 0 or not isinstance(size, int) or size < 0 or base + offset + size > path.stat().st_size:
        raise ValueError('Archive member bounds differ')
    with path.open('rb') as stream:
        stream.seek(base + offset)
        data = stream.read(size)
    if len(data) != size: raise ValueError('Truncated archive member')
    return data


def replace_exact(source, before, after, count=1):
    if source.count(before) != count: raise ValueError('Reviewed client patch anchor differs')
    return source.replace(before, after)


def replace_body(source, start, end, replacement):
    if source.count(start) != 1 or source.count(end) != 1: raise ValueError('Reviewed function boundary differs')
    first, last = source.index(start), source.index(end)
    if first >= last: raise ValueError('Reviewed function ordering differs')
    return source[:first] + replacement + source[last:]


def replacements(path, header, base):
    original = {}
    for name, digest in PLAN['files'].items():
        data = read_entry(path, header, base, name)
        if hashlib.sha256(data).hexdigest() != digest: raise ValueError('Reviewed inner client hash differs: ' + name)
        original[name] = data
    package = json.loads(original['package.json'])
    package['main'] = 'selfhost-main.cjs'
    package['name'] = 'logseq-selfhost'
    result = {'package.json': (json.dumps(package, indent=2) + '\n').encode()}
    recipe = json.loads((CLIENT / 'selfhost-client.patch').read_text())
    if recipe.get('schema') != 'cisl2-logseq-client-replacement-patch/v1': raise ValueError('Invalid client patch schema')
    texts = {name: data.decode() for name, data in original.items() if name != 'package.json'}
    for operation in recipe['operations']:
        name, kind = operation['file'], operation['kind']
        if name not in texts: raise ValueError('Unreviewed client patch target')
        if kind in ('function', 'replace-fragment'):
            fragment = operation['fragment']
            if '/' in fragment or fragment in ('.', '..'): raise ValueError('Invalid patch fragment path')
            replacement = (CLIENT / fragment).read_text().rstrip()
        if kind == 'replace':
            texts[name] = replace_exact(texts[name], operation['before'], operation['after'], operation['count'])
        elif kind == 'replace-fragment':
            texts[name] = replace_exact(texts[name], operation['before'], replacement)
        elif kind == 'function':
            texts[name] = replace_body(texts[name], operation['start'], operation['end'], replacement)
        else: raise ValueError('Unknown client patch operation')
    result.update({name: text.encode() for name, text in texts.items()})
    result['selfhost-main.cjs'] = (CLIENT / 'selfhost-main.cjs').read_bytes()
    result['selfhost-bootstrap.cjs'] = (CLIENT / 'bootstrap.cjs').read_bytes()
    result['selfhost-preload-guard.cjs'] = (CLIENT / 'preload-guard.cjs').read_bytes()
    for name in ('selfhost-setup.html', 'selfhost-setup.js', 'selfhost-setup-preload.cjs'):
        result[name] = (CLIENT / name).read_bytes()
    overlay = ROOT / 'client'
    for name in ('selfhost-settings-files.cjs', 'selfhost-settings-main.cjs', 'selfhost-onboarding.cjs'):
        result[name] = (overlay / name).read_bytes()
    result['selfhost-code-identity.cjs'] = (ROOT / 'server/auth/code-identity.cjs').read_bytes()
    result['selfhost-bootstrap.cjs'] = result['selfhost-bootstrap.cjs'].replace(b'../../server/auth/code-identity.cjs', b'./selfhost-code-identity.cjs')
    main = result['selfhost-main.cjs'].decode()
    anchor = "  require('./electron.js');"
    main = replace_exact(main, anchor,
        "  require('./selfhost-settings-main.cjs').install({app,ipcMain,allowedFrame});\n" + anchor)
    result['selfhost-main.cjs'] = main.encode()
    preload = result['js/preload.js'].decode()
    anchor = "  getSelfhostSession: async () => selfhostSession(),"
    preload = replace_exact(preload, anchor,
        "  readSelfhostSettings: async () => ipcRenderer.invoke('logseq-selfhost:settings-read'),\n"
        "  restoreSelfhostSettings: async request => ipcRenderer.invoke('logseq-selfhost:settings-restore', request),\n" + anchor)
    result['js/preload.js'] = preload.encode()
    worker=result['js/db-worker-node.js'].decode()
    worker=worker.replace('"Logseq Selfhost E2EE"', '(process.env.LOGSEQ_SELFHOST_VAULT_NAMESPACE||"Logseq Selfhost E2EE")')
    result['js/db-worker-node.js']=worker.encode()
    result['js/main.js'] += b'\n' + (overlay / 'selfhost-settings-engine.js').read_bytes() + b'\n' + (overlay / 'selfhost-settings-renderer.js').read_bytes()
    return result


def append_archive(source, destination, updates):
    header, base, _ = asar_header(source)
    header = copy.deepcopy(header)
    payload_size = source.stat().st_size - base
    appended = bytearray()
    for name, data in updates.items():
        parent = header
        parts = name.split('/')
        for part in parts[:-1]:
            if part in ('', '.', '..'): raise ValueError('Unsafe archive patch member')
            parent = parent['files'][part]
        if parts[-1] in ('', '.', '..'): raise ValueError('Unsafe archive patch member')
        block_size = 4 * 1024 * 1024
        parent['files'][parts[-1]] = {'size': len(data), 'offset': str(payload_size + len(appended)),
            'integrity': {'algorithm': 'SHA256', 'hash': hashlib.sha256(data).hexdigest(), 'blockSize': block_size,
                          'blocks': [hashlib.sha256(data[i:i + block_size]).hexdigest() for i in range(0, len(data), block_size)]}}
        appended.extend(data)
    raw = json.dumps(header, ensure_ascii=False, separators=(',', ':')).encode()
    string_payload = struct.pack('<I', len(raw)) + raw
    string_payload += b'\0' * ((-len(string_payload)) % 4)
    pickle = struct.pack('<I', len(string_payload)) + string_payload
    with destination.open('xb') as output, source.open('rb') as original:
        output.write(struct.pack('<II', 4, len(pickle)))
        output.write(pickle)
        original.seek(base)
        shutil.copyfileobj(original, output, 1024 * 1024)
        output.write(appended)
    # Independently read each changed member after offsets/header growth.
    rebuilt, rebuilt_base, _ = asar_header(destination)
    for name, data in updates.items():
        if read_entry(destination, rebuilt, rebuilt_base, name) != data: raise ValueError('Rebuilt archive verification failed')
    return hashlib.sha256(raw).hexdigest()


MACHO_MAGICS = {bytes.fromhex(value) for value in (
    'feedface','cefaedfe','feedfacf','cffaedfe','cafebabe','bebafeca','cafebabf','bfbafeca')}


def signing_inventory(app):
    if app.name != 'Logseq Selfhost.app' or app.is_symlink(): raise ValueError('Owned candidate signing root required')
    if any(parent in (Path('/Applications'), Path.home() / 'Applications') or parent.is_symlink()
           for parent in (app, *app.parents)):
        raise ValueError('Installed or linked signing root refused')
    leaves, bundles = [], []
    for item in app.rglob('*'):
        if item.is_symlink(): continue
        if item.is_dir() and item.suffix in ('.framework','.app'):
            bundles.append(item)
        elif item.is_file():
            with item.open('rb') as stream: magic = stream.read(4)
            if magic in MACHO_MAGICS: leaves.append(item)
    if not leaves: raise ValueError('Candidate contains no Mach-O code')
    order = lambda item: (-len(item.relative_to(app).parts), str(item))
    return sorted(leaves,key=order), sorted(bundles,key=order) + [app]


def admit_signing_command(args, candidate):
    if candidate is None: raise ValueError('Owned candidate signing scope required')
    leaves, bundles = signing_inventory(candidate)
    target = Path(args[-1]) if args else Path('.')
    if target not in leaves + bundles: raise ValueError('Signing target is outside the exact candidate code inventory')
    expected = ['/usr/bin/codesign','--force','--sign',IDENTITY,'--options','runtime']
    if target == candidate:
        expected += ['--entitlements',str(candidate.parent / 'entitlements.plist')]
    else:
        # Each code object's own original entitlements remain unchanged. In
        # particular, no library-validation exception is added to fix a TeamID.
        expected += ['--preserve-metadata=entitlements']
    expected += [str(target)]
    if args != expected: raise ValueError('Only the fixed candidate signing command is permitted')


def gui_run(args, timeout=60, *, candidate=None):
    timeout = bounded_timeout(timeout)
    if args != ['/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning']:
        admit_signing_command(args,candidate)
    with tempfile.TemporaryDirectory(prefix='logseq-selfhost-sign-') as temporary:
        directory = Path(temporary)
        label = 'us.nixc.logseq-selfhost.sign-' + uuid.uuid4().hex
        service = 'gui/' + str(os.getuid()) + '/' + label
        output, errors = directory / 'stdout', directory / 'stderr'
        job = {'Label': label, 'ProgramArguments': [str(value) for value in args], 'RunAtLoad': True,
               'ProcessType': 'Interactive', 'StandardOutPath': str(output), 'StandardErrorPath': str(errors),
               'EnvironmentVariables': {'HOME': str(Path.home()), 'PATH': '/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin'}}
        manifest = directory / 'job.plist'
        manifest.write_bytes(plistlib.dumps(job))
        loaded = False
        try:
            run(['launchctl', 'bootstrap', 'gui/' + str(os.getuid()), manifest], 10)
            loaded = True
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                state = run(['launchctl', 'print', service], 5).stdout.decode()
                completed = re.search(r'^\s*last exit code = ([0-9]+)$', state, re.M)
                active = re.search(r'^\s*pid = [1-9][0-9]*$', state, re.M)
                ran = re.search(r'^\s*runs = [1-9][0-9]*$', state, re.M)
                if ran and completed and not active:
                    if int(completed.group(1)): raise RuntimeError('GUI signing operation failed; candidate retained')
                    return output.read_bytes() if output.exists() else b''
                time.sleep(0.1)
            raise RuntimeError('GUI signing deadline exceeded; reconcile retained candidate before retry')
        finally:
            if loaded: subprocess.run(['launchctl', 'bootout', service], capture_output=True, timeout=5)


def package_candidate(dmg, output_root, revision):
    if sys.platform != 'darwin': raise RuntimeError('The reviewed client packaging target is macOS arm64')
    if not re.fullmatch('[a-f0-9]{40}', revision): raise ValueError('Exact source revision required')
    if dmg.is_symlink() or not dmg.is_file() or sha(dmg) != PLAN['dmg_sha256']: raise ValueError('Pinned official DMG differs')
    output_root = output_root.expanduser().absolute()
    if output_root.is_symlink() or any(parent in (Path('/Applications'), Path.home() / 'Applications') for parent in (output_root, *output_root.parents)):
        raise ValueError('A new private candidate output directory is required; installation is separate')
    destination = output_root / revision
    destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    app = destination / 'Logseq Selfhost.app'
    with tempfile.TemporaryDirectory(prefix='logseq-selfhost-mount-') as temporary:
        mount = Path(temporary) / 'mount'
        mount.mkdir()
        attached = False
        try:
            run(['hdiutil', 'attach', '-readonly', '-nobrowse', '-mountpoint', mount, dmg], 45)
            attached = True
            source_app = mount / 'Logseq.app'
            source_asar = source_app / 'Contents/Resources/app.asar'
            if sha(source_asar) != PLAN['asar_sha256']: raise ValueError('Pinned official app archive differs')
            run(['codesign', '--verify', '--deep', '--strict', source_app], 40)
            entitlements = run(['codesign', '--display', '--entitlements', ':-', source_app], 10).stdout
            plistlib.loads(entitlements)
            (destination / 'entitlements.plist').write_bytes(entitlements)
            run(['ditto', '--noqtn', source_app, app], 90)
            asar = app / 'Contents/Resources/app.asar'
            header, base, _ = asar_header(asar)
            updates = replacements(asar, header, base)
            rebuilt = asar.with_name('app.asar.selfhost')
            header_hash = append_archive(asar, rebuilt, updates)
            rebuilt.replace(asar)
            plist = app / 'Contents/Info.plist'
            metadata = plistlib.loads(plist.read_bytes())
            # Electron resolves helper bundle paths from CFBundleName before JS runs.
            # Keep its original helper basename; display name and private app identity differ.
            metadata.update(CFBundleIdentifier=PLAN['bundle_id'], CFBundleDisplayName='Logseq Selfhost')
            if metadata.get('CFBundleName') != 'Logseq':
                raise ValueError('Pinned Electron helper basename differs')
            if not (app / 'Contents/Frameworks/Logseq Helper.app/Contents/MacOS/Logseq Helper').is_file():
                raise ValueError('Pinned Electron helper executable missing')
            metadata.pop('CFBundleURLTypes', None)
            metadata['ElectronAsarIntegrity'] = {'Resources/app.asar': {'algorithm': 'SHA256', 'hash': header_hash}}
            plist.write_bytes(plistlib.dumps(metadata))
            for helper in (app / 'Contents/Frameworks').glob('Logseq Helper*.app/Contents/Info.plist'):
                info = plistlib.loads(helper.read_bytes())
                original = info.get('CFBundleIdentifier', '')
                if original.startswith('com.logseq.logseq'): info['CFBundleIdentifier'] = original.replace('com.logseq.logseq', PLAN['bundle_id'], 1)
                helper.write_bytes(plistlib.dumps(info))
        finally:
            if attached: run(['hdiutil', 'detach', mount], 20)
    receipt = {'schema': 'cisl2-logseq-selfhost-client/v1', 'source_revision': revision,
               'upstream_dmg_sha256': PLAN['dmg_sha256'], 'original_asar_sha256': PLAN['asar_sha256'],
               'candidate_asar_sha256': sha(app / 'Contents/Resources/app.asar'), 'bundle_id': PLAN['bundle_id'],
               'candidate': str(app), 'status': 'packaged', 'installed': False,
               'crypto_worker_changes': 'private-auth-file-path-only',
               'worker_auth_refresh': 'offline-renew-and-restart', 'worker_ownership_root': 'Logseq Selfhost', 'modified_entries': sorted(updates)}
    (destination / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    return app


def sign_candidate(app):
    if app.name != 'Logseq Selfhost.app' or not (app.parent / 'receipt.json').is_file(): raise ValueError('Owned candidate receipt required')
    receipt = json.loads((app.parent / 'receipt.json').read_text())
    if receipt.get('candidate') != str(app) or receipt.get('status') != 'packaged': raise ValueError('Unsigned owned candidate required')
    if sha(app / 'Contents/Resources/app.asar') != receipt.get('candidate_asar_sha256'):
        raise ValueError('Candidate archive changed after packaging')
    available = gui_run(['/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning'], 15).decode()
    if IDENTITY not in available: raise RuntimeError('Existing Apple Development signing identity unavailable in GUI session')
    leaves, bundles = signing_inventory(app)
    # --deep skips already-signed nested dylibs/native modules. Re-sign every
    # real code leaf first, then the enclosing bundles, and finally the app.
    for target in leaves + bundles:
        command = ['/usr/bin/codesign','--force','--sign',IDENTITY,'--options','runtime']
        if target == app: command += ['--entitlements',str(app.parent / 'entitlements.plist')]
        else: command += ['--preserve-metadata=entitlements']
        gui_run(command + [str(target)],30,candidate=app)
    for target in leaves:
        run(['/usr/bin/codesign','--verify','--strict',target],10)
        identity = run(['/usr/bin/codesign','--display','--verbose=4',target],10).stderr.decode()
        if 'TeamIdentifier=' + TEAM not in identity:
            raise RuntimeError('Nested candidate Mach-O signing team differs: ' + str(target.relative_to(app)))
    run(['codesign', '--verify', '--deep', '--strict', app], 40)
    signed = run(['codesign', '--display', '--verbose=4', app], 10).stderr.decode()
    if 'TeamIdentifier=' + TEAM not in signed or 'Identifier=' + PLAN['bundle_id'] not in signed:
        raise RuntimeError('Candidate signing team or bundle identity differs')
    receipt.update(status='signed-candidate', signing_team=TEAM, signing_family='Apple Development', notarized=False,
                   signed_macho_count=len(leaves),signed_bundle_count=len(bundles),nested_team_verified=True)
    (app.parent / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['pack', 'sign', 'build'])
    parser.add_argument('--dmg', type=Path, default=Path.home() / 'hedgeseq-work/logseq-client-research/Logseq-darwin-arm64-2.0.2.dmg')
    parser.add_argument('--output-root', type=Path, required=True)
    parser.add_argument('--source-revision', required=True)
    args = parser.parse_args()
    global DEADLINE
    DEADLINE = time.monotonic() + 270
    os.umask(0o077)
    try:
        if not re.fullmatch('[a-f0-9]{40}', args.source_revision): raise ValueError('Exact source revision required')
        output = args.output_root.expanduser().absolute()
        if any(parent in (Path('/Applications'), Path.home() / 'Applications') or parent.is_symlink() for parent in (output, *output.parents)):
            raise ValueError('Candidate output cannot address installed applications or linked paths')
        app = args.output_root.expanduser().absolute() / args.source_revision / 'Logseq Selfhost.app'
        if args.phase in ('pack', 'build'): app = package_candidate(args.dmg, args.output_root, args.source_revision)
        receipt = sign_candidate(app) if args.phase in ('sign', 'build') else json.loads((app.parent / 'receipt.json').read_text())
        print(json.dumps(receipt, sort_keys=True))
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print('Logseq Selfhost candidate failed: ' + (str(error) if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__': raise SystemExit(main())
