// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {pathToFileURL} = require('node:url');
const {app,BrowserWindow,ipcMain,Menu,MenuItem,clipboard} = require('electron');
const {readBootstrap,initializeBootstrap,currentSyncCode,currentServerUrl,ensurePrivateDirectory,REAL_HOME,importSyncCode,verifySyncCode,DEFAULT_FILE} = require('./selfhost-bootstrap.cjs');
const {allowedFrame} = require('./selfhost-preload-guard.cjs');
process.umask(0o077);
function privateDirectory(directory) {
  let info;
  try { info=fs.lstatSync(directory); }
  catch (error) {
    if(error.code!=='ENOENT')throw error;
    fs.mkdirSync(directory,{mode:0o700});
    info=fs.lstatSync(directory);
  }
  if(!info.isDirectory()||info.isSymbolicLink()||(info.mode&0o777)!==0o700||info.uid!==process.getuid()) {
    throw new Error('Owned mode0700 isolated application directory required');
  }
}
let configuration;
try { configuration=initializeBootstrap(); } catch (_) { configuration=null; }
// Keep the existing owner's paths unchanged. New identities get their own
// app profile, native graph root, settings, auth file and vault namespace.
// Isolate the setup window before Chromium opens any profile storage.
app.setName('Logseq Selfhost');
const baseData = path.join(app.getPath('appData'), 'Logseq Selfhost');
privateDirectory(baseData);
let userData=baseData, authDirectory=path.dirname(DEFAULT_FILE);
process.env.LOGSEQ_SELFHOST_VAULT_NAMESPACE='Logseq Selfhost E2EE';
if(configuration?.protocol===2) {
  // A server URL can change while its sync identity and local notes stay the
  // same. Keep profile and vault selection tied to the identity, not the URL.
  const identityRoot=path.join(baseData,'identities',configuration.subject);
  ensurePrivateDirectory(identityRoot);
  userData=path.join(identityRoot,'app');privateDirectory(userData);
  const profileHome=path.join(identityRoot,'home');privateDirectory(profileHome);
  process.env.HOME=profileHome;
  process.env.XDG_CONFIG_HOME=path.join(profileHome,'.config');
  process.env.LOGSEQ_SELFHOST_VAULT_NAMESPACE='Logseq Selfhost E2EE '+configuration.subject;
  app.setPath('home',profileHome);
  authDirectory=path.join(profileHome,'.config/cisl2/logseq-selfhost');
  ensurePrivateDirectory(authDirectory);
}
app.setPath('userData', userData);
const sessionData = path.join(userData, 'session');
privateDirectory(sessionData);
app.setPath('sessionData', sessionData);

function prepareAuth(config) {
  const directory=authDirectory;
  const info=fs.lstatSync(directory);
  if(!info.isDirectory()||info.isSymbolicLink()||(info.mode&0o777)!==0o700||info.uid!==process.getuid())throw Error('Private configuration directory required');
  const auth=path.join(directory,'auth.json');
  let previous={};
  let previousStat=null,exists=false;
  try{const stat=fs.lstatSync(auth);if(stat.isSymbolicLink())throw Error('Private isolated auth file required');exists=true}
  catch(error){if(error.code!=='ENOENT')throw error}
  if(exists){
    const fd=fs.openSync(auth,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
    try {
      const saved=fs.fstatSync(fd);
      if(!saved.isFile()||(saved.mode&0o777)!==0o600||saved.uid!==process.getuid()||saved.size>65536)throw Error('Private isolated auth file required');
      previousStat=saved;
      previous=JSON.parse(fs.readFileSync(fd,'utf8'));
      if(!previous||typeof previous!=='object'||Array.isArray(previous))throw Error('Private isolated auth file required');
    } finally {fs.closeSync(fd)}
    if(previous['refresh-token']&&previous['refresh-token']!==config.wrappingKey)throw Error('Stable wrapping key changed');
  }
  const next={...previous,'id-token':config.token,'access-token':config.token,'refresh-token':config.wrappingKey,'updated-at':Date.now()};
  const temporary=path.join(directory,'.auth-'+crypto.randomBytes(16).toString('hex'));
  let fd;
  try {
    fd=fs.openSync(temporary,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
    fs.writeFileSync(fd,JSON.stringify(next)+'\n');fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
    if(previousStat){
      const current=fs.lstatSync(auth);
      if(current.isSymbolicLink()||current.dev!==previousStat.dev||current.ino!==previousStat.ino||current.mtimeMs!==previousStat.mtimeMs||current.size!==previousStat.size)throw Error('Private auth file changed during refresh');
      fs.renameSync(temporary,auth);
    }else fs.linkSync(temporary,auth);
    const directoryFD=fs.openSync(directory,fs.constants.O_RDONLY);
    try{fs.fsyncSync(directoryFD)}finally{fs.closeSync(directoryFD)}
  } finally {
    if(fd!==undefined)fs.closeSync(fd);
    try{fs.unlinkSync(temporary)}catch(error){if(error.code!=='ENOENT')throw error}
  }
}

function startClient(config) {
  prepareAuth(config);
  ipcMain.handle('logseq-selfhost:session', event => {
    const frame=event.senderFrame;
    if(!frame||frame!==event.sender.mainFrame||!allowedFrame({isMainFrame:true,topLevel:true,href:frame.url})) {
      throw new Error('Selfhost session is restricted to the local main document');
    }
    // Token generation and the short-lived signing key stay in this process.
    const current=readBootstrap();
    if(current.subject!==config.subject || current.wrappingKey!==config.wrappingKey || current.serverUrl!==config.serverUrl) throw Error('Sync identity or server changed; reopen Logseq');
    prepareAuth(current);
    return {serverUrl:current.serverUrl,idToken:current.token,accessToken:current.token,refreshToken:current.wrappingKey,
      ...(current.rsaPassword ? {rsaPassword:current.rsaPassword} : {})};
  });
  // The side-by-side candidate must not claim the installed app's URL handler.
  const registerProtocol = app.setAsDefaultProtocolClient.bind(app);
  app.setAsDefaultProtocolClient = (scheme, ...args) => scheme === 'logseq' ? false : registerProtocol(scheme, ...args);
  // A stock upstream auto-update would remove this reviewed local patch.
  const updater = require('electron-updater').autoUpdater;
  updater.autoDownload = false;
  updater.checkForUpdates = async () => null;
  updater.checkForUpdatesAndNotify = async () => null;
  updater.downloadUpdate = async () => { throw new Error('Selfhost updates require a new signed candidate'); };
  updater.quitAndInstall = () => { throw new Error('Selfhost updates require a new signed candidate'); };
  require('./electron.js');
  require('./selfhost-onboarding.cjs').install({app,BrowserWindow,ipcMain,Menu,MenuItem,clipboard,currentSyncCode,currentServerUrl,verifySyncCode,importSyncCode});
}

function startSetup() {
  app.whenReady().then(async () => {
    const setupFile=path.join(__dirname,'selfhost-setup.html');
    const setupURL=pathToFileURL(setupFile).href;
    const setup=new BrowserWindow({width:540,height:680,resizable:false,show:false,title:'Logseq Selfhost',
      webPreferences:{preload:path.join(__dirname,'selfhost-setup-preload.cjs'),contextIsolation:true,nodeIntegration:false,
        sandbox:true,webSecurity:true,webviewTag:false}});
    let accepted=false,pending=false;
    setup.setMenu(null);
    setup.webContents.setWindowOpenHandler(()=>({action:'deny'}));
    setup.webContents.on('will-navigate',event=>event.preventDefault());
    setup.webContents.on('will-attach-webview',event=>event.preventDefault());
    ipcMain.handle('logseq-selfhost:setup-code', async (event, code, serverUrl) => {
      const frame=event.senderFrame;
      if(event.sender!==setup.webContents||!frame||frame!==setup.webContents.mainFrame||frame.url!==setupURL||accepted||pending) {
        throw new Error('Sync code setup is restricted to its local window');
      }
      pending=true;
      try {
        if(typeof code!=='string'||code.length>128)throw new Error('Invalid sync code');
        await verifySyncCode(code, serverUrl);
        if(setup.isDestroyed()||event.senderFrame!==setup.webContents.mainFrame||event.senderFrame.url!==setupURL)throw new Error('Setup window changed');
        importSyncCode(code, undefined, {serverUrl});
        accepted=true;
        // Upstream installs schemes and an app-ready listener before launch.
        // Relaunch after saving instead of loading upstream after app-ready.
        setTimeout(()=>{app.relaunch();app.exit(0)},150);
        return {ok:true};
      } catch(error) {
        const safe=['Invalid sync code','This device already belongs to another sync identity','The sync code could not be verified. Check your connection and try again.'];
        return {ok:false,message:safe.includes(error.message)?error.message:'The sync code could not be saved for this device.'};
      } finally {pending=false}
    });
    setup.on('closed',()=>{
      ipcMain.removeHandler('logseq-selfhost:setup-code');
      if(!accepted)app.quit();
    });
    await setup.loadFile(setupFile);
    setup.show();
  }).catch(()=>{app.exit(1)});
}

if(configuration){
  try{startClient(configuration)}catch(_){app.exit(1);throw new Error('Selfhost bootstrap refused')}
}
else startSetup();
