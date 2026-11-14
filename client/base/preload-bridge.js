// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
const selfhostFrameGuard = require('../selfhost-preload-guard.cjs');
function selfhostAllowedFrame() {
  return selfhostFrameGuard.allowedFrame({isMainFrame: process.isMainFrame, href: window.location.href, topLevel: window.top === window});
}
async function selfhostSession() {
  if (!selfhostAllowedFrame()) throw new Error('Selfhost bootstrap is restricted to the local main document');
  return ipcRenderer.invoke('logseq-selfhost:session');
}
const selfhostAPI = selfhostAllowedFrame() ? {
  getSelfhostSession: async () => selfhostSession(),
  refreshSelfhostSession: async () => selfhostSession()
} : {};
contextBridge.exposeInMainWorld('apis', {
  ...selfhostAPI,
