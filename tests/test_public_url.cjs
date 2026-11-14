// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { setTimeout: delay } = require('node:timers/promises');
const { readPublicUrl, configurePublicUrl } = require('../server/auth/public-url.cjs');

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'logseq-public-url-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'public-url.json');
  const state = { schema: 'logseq-public-url/v1', url: 'https://test-sync-url.trycloudflare.com',
    generation: 'a'.repeat(32), updatedAt: Date.now() };
  const write = (changes = {}) => fs.writeFileSync(file, JSON.stringify({ ...state, ...changes }));
  write();
  return { file, state, write };
}

test('accepts only a fresh generated HTTPS hostname without paths or credentials', t => {
  const { file, state, write } = fixture(t);
  assert.equal(readPublicUrl(file).url, state.url);
  for (const url of ['http://test.trycloudflare.com', 'https://test.trycloudflare.com.evil.example',
    'https://user:test@test.trycloudflare.com', 'https://test.trycloudflare.com/path',
    'https://test.trycloudflare.com?token=secret', 'https://localhost']) {
    write({ url });
    assert.throws(() => readPublicUrl(file));
  }
  write({ updatedAt: Date.now() - 13000 });
  assert.throws(() => readPublicUrl(file));
  write({ updatedAt: Date.now() + 6000 });
  assert.throws(() => readPublicUrl(file));
  write({ generation: 'invalid' });
  assert.throws(() => readPublicUrl(file));
});

test('direct deployments retain their configured stable URL', async () => {
  const env = { DB_SYNC_BASE_URL: 'https://sync.example.com' };
  assert.equal(await configurePublicUrl(env), null);
  assert.equal(env.DB_SYNC_BASE_URL, 'https://sync.example.com');
});

test('waits for a current tunnel before configuring asset links', async t => {
  const { file, state } = fixture(t);
  fs.unlinkSync(file);
  const env = { LOGSEQ_PUBLIC_URL_FILE: file, DB_SYNC_BASE_URL: 'http://localhost:8787' };
  const waiting = configurePublicUrl(env);
  await delay(30);
  assert.equal(env.DB_SYNC_BASE_URL, 'http://localhost:8787');
  fs.writeFileSync(file, JSON.stringify(state));
  const watchdog = await waiting;
  t.after(() => clearInterval(watchdog));
  assert.equal(env.DB_SYNC_BASE_URL, state.url);
});

test('stops sync when the tunnel lease is stale, missing, or replaced', async t => {
  const cases = [
    ({ write }) => write({ generation: 'b'.repeat(32) }),
    ({ write }) => write({ url: 'https://replacement.trycloudflare.com' }),
    ({ write }) => write({ updatedAt: Date.now() - 13000 }),
    ({ file }) => fs.unlinkSync(file),
  ];
  await Promise.all(cases.map(async change => {
    const item = fixture(t);
    let stopped = false;
    const watchdog = await configurePublicUrl({ LOGSEQ_PUBLIC_URL_FILE: item.file }, () => { stopped = true; });
    t.after(() => clearInterval(watchdog));
    change(item);
    await delay(2200);
    assert.equal(stopped, true);
  }));
});
