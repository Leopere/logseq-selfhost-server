// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
const path = require('node:path');
const files = require('./selfhost-settings-files.cjs');

function install({ app, ipcMain, allowedFrame }) {
  const root = path.join(app.getPath('userData'), 'logseq-config');
  const backups = path.join(app.getPath('userData'), 'settings-sync-backups');
  const check = event => {
    const frame = event.senderFrame;
    if (!frame || frame !== event.sender.mainFrame || !allowedFrame({ isMainFrame: true, topLevel: true, href: frame.url })) {
      throw Error('Settings sync requires the local main document');
    }
  };
  // Existing LS1 users retain portable settings from the original Logseq app.
  // A newly generated identity has its own home and must start independently.
  const bootstrap = require('./selfhost-bootstrap.cjs');
  const fs = require('node:fs');
  const imported = path.join(app.getPath('userData'), 'portable-settings-imported-v1');
  if (bootstrap.readBootstrap()?.protocol === 1 && !fs.existsSync(imported)) {
    const original = path.join(app.getPath('home'), '.logseq');
    if (fs.existsSync(original)) {
      files.importPortableSettings(original, root, backups);
      fs.writeFileSync(imported, '1\n', {flag:'wx', mode:0o600});
    }
  }
  let tail = Promise.resolve();
  ipcMain.handle('logseq-selfhost:settings-read', event => {
    check(event);
    return files.snapshot(root);
  });
  ipcMain.handle('logseq-selfhost:settings-restore', (event, request) => {
    check(event);
    if (!request || Buffer.byteLength(JSON.stringify(request)) > 300 * 1024) throw Error('Invalid settings request');
    const next = tail.then(() => {
      check(event);
      return { restored: files.restore(root, backups, request.path, request.document), needsReload: true };
    });
    tail = next.catch(() => {});
    return next;
  });
}
module.exports = { install };
