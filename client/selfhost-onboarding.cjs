// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
const path = require('node:path');
const { pathToFileURL } = require('node:url');
function install({ app, BrowserWindow, ipcMain, Menu, MenuItem, clipboard, currentSyncCode, currentServerUrl, verifySyncCode, importSyncCode }) {
  let dialog;
  function show() {
    if (dialog && !dialog.isDestroyed()) { dialog.show(); dialog.focus(); return; }
    const file = path.join(__dirname, 'selfhost-setup.html'), url = pathToFileURL(file).href;
    dialog = new BrowserWindow({ width: 540, height: 680, resizable: false, title: 'Sync settings',
      webPreferences: { preload: path.join(__dirname, 'selfhost-setup-preload.cjs'), contextIsolation: true,
        nodeIntegration: false, sandbox: true, webSecurity: true, webviewTag: false } });
    dialog.setMenu(null);
    dialog.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    dialog.webContents.on('will-navigate', event => event.preventDefault());
    const check = event => {
      if (!dialog || dialog.isDestroyed() || event.sender !== dialog.webContents ||
        event.senderFrame !== dialog.webContents.mainFrame || event.senderFrame.url !== url) throw Error('Local sync-code window required');
    };
    ipcMain.handle('logseq-selfhost:current-code', event => { check(event); return currentSyncCode(); });
    ipcMain.handle('logseq-selfhost:current-server', event => { check(event); return currentServerUrl(); });
    ipcMain.handle('logseq-selfhost:copy-code', event => { check(event); clipboard.writeText(currentSyncCode()); return true; });
    let pending = false;
    ipcMain.handle('logseq-selfhost:setup-code', async (event, code, serverUrl) => {
      check(event);
      if (pending) return { ok: false, message: 'A connection is already in progress.' };
      pending = true;
      try {
        if (typeof code !== 'string' || code.length > 80) throw Error('Invalid sync code');
        await verifySyncCode(code, serverUrl);
        check(event);
        importSyncCode(code, undefined, { replace: true, serverUrl });
        setTimeout(() => { app.relaunch(); app.exit(0); }, 150);
        return { ok: true };
      } catch (_) { return { ok: false, message: 'Could not connect. Check the server URL, issued code and connection. Your current notes are unchanged.' }; }
      finally { pending = false; }
    });
    dialog.on('closed', () => {
      for (const channel of ['current-code','current-server','copy-code','setup-code']) ipcMain.removeHandler('logseq-selfhost:' + channel);
      dialog = null;
    });
    dialog.loadFile(file);
  }
  function menu() {
    const current = Menu.getApplicationMenu();
    if (current && !current.getMenuItemById('logseq-selfhost-sync-code')) {
      current.append(new MenuItem({ id: 'logseq-selfhost-sync-code', label: 'Sync', submenu: [
        { label: 'Sync settings…', click: show },
      ] }));
      Menu.setApplicationMenu(current);
    }
  }
  app.whenReady().then(() => setTimeout(menu, 500));
  app.on('browser-window-focus', menu);
}
module.exports = { install };
