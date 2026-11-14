#!/usr/bin/env python3
"""Publish a live quick-tunnel URL without an account or a central service.

Copyright (c) 2026 Colin Knapp, https://colinknapp.com
SPDX-License-Identifier: AGPL-3.0-only
"""
import json
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import uuid

STATE = Path('/run/logseq-tunnel/public-url.json')
URL = re.compile(r'https://[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com\b')


def clear_state():
    STATE.unlink(missing_ok=True)


def publish(url, generation):
    temporary = STATE.with_suffix('.tmp')
    temporary.write_text(json.dumps({'schema': 'logseq-public-url/v1', 'url': url,
                                     'generation': generation, 'updatedAt': int(time.time() * 1000)}))
    temporary.chmod(0o644)
    temporary.replace(STATE)


def healthy():
    try:
        value = json.loads(STATE.read_text())
        return (value['schema'] == 'logseq-public-url/v1' and
                URL.fullmatch(value['url']) is not None and
                re.fullmatch(r'[a-f0-9]{32}', value['generation']) is not None and
                -5000 <= time.time() * 1000 - value['updatedAt'] <= 12000)
    except (OSError, ValueError, KeyError, TypeError):
        return False


def connected():
    try:
        # Connector readiness is independent of the origin, so sync can wait
        # for its public URL before opening its listener without a startup cycle.
        with urllib.request.urlopen('http://127.0.0.1:2000/ready', timeout=1) as response:
            return response.status == 200
    except (OSError, ValueError):
        return False


def main():
    if sys.argv[1:] == ['--check']:
        return 0 if healthy() else 1
    clear_state()  # The named volume may contain a lease from an earlier run.
    generation = uuid.uuid4().hex
    process = subprocess.Popen(['/usr/local/bin/cloudflared', 'tunnel', '--no-autoupdate',
                                '--url', 'http://sync:8787', '--metrics', '127.0.0.1:2000',
                                '--protocol', 'http2'], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, bufsize=1)
    discovered = queue.Queue()
    stopping = threading.Event()

    def stop(_signum, _frame):
        stopping.set()
        process.terminate()

    def logs():
        for line in process.stdout:
            print(line.rstrip(), flush=True)
            match = URL.search(line)
            if match:
                discovered.put(match.group())

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    threading.Thread(target=logs, daemon=True).start()
    url = None
    started = time.monotonic()
    try:
        while process.poll() is None and not stopping.is_set():
            try:
                while True:
                    url = discovered.get_nowait()
            except queue.Empty:
                pass
            if url and connected():
                publish(url, generation)
            else:
                clear_state()
            if not url and time.monotonic() - started > 90:
                print('Public tunnel did not issue a URL within 90 seconds', file=sys.stderr)
                return 1
            stopping.wait(2)
        return process.returncode if process.returncode is not None and process.returncode > 0 else 1
    finally:
        clear_state()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    sys.exit(main())
