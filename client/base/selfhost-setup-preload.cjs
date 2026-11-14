// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
const {contextBridge,ipcRenderer}=require('electron');
if(process.isMainFrame&&window.top===window) {
  contextBridge.exposeInMainWorld('syncCodeSetup',Object.freeze({
    current:()=>ipcRenderer.invoke('logseq-selfhost:current-code'),
    currentServer:()=>ipcRenderer.invoke('logseq-selfhost:current-server'),
    copy:()=>ipcRenderer.invoke('logseq-selfhost:copy-code'),
    submit:(code,serverUrl)=>ipcRenderer.invoke('logseq-selfhost:setup-code',code,serverUrl)
  }));
}
