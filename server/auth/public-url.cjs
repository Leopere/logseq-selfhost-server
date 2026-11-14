// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
const fs = require('node:fs');
const { setTimeout: delay } = require('node:timers/promises');
const MAX_AGE_MS = 12000;

function readPublicUrl(file, now = Date.now()) {
  const stat = fs.statSync(file);
  if (!stat.isFile() || stat.size > 1024) throw Error('Tunnel URL is unavailable');
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (value.schema !== 'logseq-public-url/v1' ||
      typeof value.url !== 'string' || !/^https:\/\/[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com$/.test(value.url) ||
      typeof value.generation !== 'string' || !/^[a-f0-9]{32}$/.test(value.generation) ||
      !Number.isSafeInteger(value.updatedAt) || value.updatedAt > now + 5000 || now - value.updatedAt > MAX_AGE_MS) {
    throw Error('Tunnel URL is unavailable');
  }
  return value;
}

async function configurePublicUrl(env = process.env, onInvalid = () => process.exit(1)) {
  if (!env.LOGSEQ_PUBLIC_URL_FILE) return null;
  const started = Date.now();
  let current;
  while (!current) {
    try { current = readPublicUrl(env.LOGSEQ_PUBLIC_URL_FILE); }
    catch (_) {
      if (Date.now() - started >= 90000) throw Error('Public tunnel did not become ready within 90 seconds');
      await delay(250);
    }
  }
  env.DB_SYNC_BASE_URL = current.url;
  console.info('Sync URL: ' + current.url);
  const watchdog = setInterval(() => {
    try {
      const next = readPublicUrl(env.LOGSEQ_PUBLIC_URL_FILE);
      if (next.url !== current.url || next.generation !== current.generation) throw Error('Tunnel changed');
    } catch (_) {
      clearInterval(watchdog);
      console.error('Public tunnel changed or became unavailable; restarting sync');
      onInvalid();
    }
  }, 2000);
  watchdog.unref();
  return watchdog;
}

module.exports = { readPublicUrl, configurePublicUrl };
if (require.main === module) {
  try { console.log(readPublicUrl(process.env.LOGSEQ_PUBLIC_URL_FILE || '/run/logseq-tunnel/public-url.json').url); }
  catch (_) { console.error('Public tunnel is not ready'); process.exitCode = 1; }
}
