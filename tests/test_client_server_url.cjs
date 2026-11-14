// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const http = require('node:http');
const vm = require('node:vm');
const bootstrap = require('../client/base/bootstrap.cjs');
const identity = require('../server/auth/code-identity.cjs');

test('sync URLs require an explicit secure origin, with HTTP restricted to loopback', () => {
  for (const [input, expected] of [
    ['https://sync.example.com/', 'https://sync.example.com'],
    ['https://sync.example.com:443', 'https://sync.example.com'],
    ['https://sync.example.com:8443', 'https://sync.example.com:8443'],
    ['http://127.0.0.1:8787', 'http://127.0.0.1:8787'],
    ['http://localhost:8787', 'http://localhost:8787'],
    ['http://[::1]:8787', 'http://[::1]:8787'],
  ]) assert.equal(bootstrap.normalizeServerUrl(input), expected);
  for (const input of [undefined, '', 'https:example.com', 'http://example.com', 'http://192.168.1.2',
    'http://localhost.evil.test', 'https://user:pass@example.com', 'https://example.com/sync',
    'https://example.com?token=secret', 'https://example.com#secret', 'https://example.com?',
    'https://example.com#', 'https://example.com\\@evil.test', ' https://example.com',
    'file:///tmp/notes', 'ws://localhost:8787']) assert.throws(() => bootstrap.normalizeServerUrl(input));
});

test('chosen URLs survive restart without changing LS1/LS2 roots, subjects or passwords', t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'logseq-server-choice-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const script = `process.type='browser';
    const fs=require('node:fs'),assert=require('node:assert/strict');
    const b=require(${JSON.stringify(path.resolve(__dirname, '../client/base/bootstrap.cjs'))});
    const c=require(${JSON.stringify(path.resolve(__dirname, '../server/auth/code-identity.cjs'))});
    assert.equal(b.initializeBootstrap(),null);
    const value=c.createIdentity(),code=c.encodeCode(value),serverUrl='https://sync.example.com:8443';
    b.importSyncCode(code,undefined,{serverUrl});
    const saved=b.readBootstrap(),password=b.nativePassword(value.wrappingKey);
    assert.equal(saved.serverUrl,serverUrl);assert.equal(saved.subject,value.subject);
    assert.equal(saved.wrappingKey,value.wrappingKey);assert.equal(saved.rsaPassword,password);
    assert.equal(b.currentServerUrl(),serverUrl);assert.equal(b.currentSyncCode(),code);
    assert.equal(b.initializeBootstrap().serverUrl,serverUrl);
    assert.equal(c.verifyToken(saved.token,null).sub,value.subject);
    b.importSyncCode(code,undefined,{serverUrl:'https://replacement.example.com',replace:true});
    assert.equal(b.readBootstrap().serverUrl,'https://replacement.example.com');
    assert.equal(b.readBootstrap().rsaPassword,password);assert.equal(b.currentSyncCode(),code);
    const bytes=Buffer.concat([Buffer.from([1]),Buffer.from(value.subject.replaceAll('-',''),'hex'),Buffer.from(value.wrappingKey,'hex')]);
    const legacy='ls1_'+bytes.toString('base64url');
    b.importSyncCode(legacy,undefined,{serverUrl:b.ENDPOINT,replace:true});
    assert.equal(b.readBootstrap().protocol,1);assert.equal(b.currentSyncCode(),legacy);
    assert.equal(b.readBootstrap().serverUrl,b.ENDPOINT);assert.equal(b.readBootstrap().rsaPassword,password);
    const old=JSON.parse(fs.readFileSync(b.DEFAULT_FILE));old.serverUrl='https://logseq-sync.nixc.us';
    fs.writeFileSync(b.DEFAULT_FILE,JSON.stringify(old),{mode:384});
    assert.equal(b.initializeBootstrap().serverUrl,old.serverUrl);`;
  cp.execFileSync(process.execPath, ['-e', script], { env: { ...process.env, HOME: home }, stdio: 'pipe', timeout: 10000 });
});

test('code verification reaches only the chosen server and refuses redirects and denied grants', async t => {
  const previousType = process.type;
  process.type = 'browser';
  t.after(() => { if (previousType === undefined) delete process.type; else process.type = previousType; });
  const generated = identity.createIdentity(), code = identity.encodeCode(generated);
  let status = 200, requests = 0, redirectRequests = 0;
  const other = http.createServer((request, response) => { redirectRequests++; response.end('{}'); });
  const server = http.createServer((request, response) => {
    requests++;
    assert.equal(request.url, '/graphs');
    assert.equal(identity.verifyToken(request.headers.authorization.slice(7), null).sub, generated.subject);
    response.writeHead(status, { location: `http://127.0.0.1:${other.address().port}/stolen` });
    response.end('{}');
  });
  await Promise.all([new Promise(resolve => server.listen(0, '127.0.0.1', resolve)), new Promise(resolve => other.listen(0, '127.0.0.1', resolve))]);
  t.after(() => { server.close(); other.close(); });
  const url = `http://127.0.0.1:${server.address().port}`;
  await bootstrap.verifySyncCode(code, url);
  status = 302;
  await assert.rejects(bootstrap.verifySyncCode(code, url));
  status = 404;
  await assert.rejects(bootstrap.verifySyncCode(code, url));
  assert.equal(requests, 3);assert.equal(redirectRequests, 0);
  assert.throws(() => bootstrap.verifySyncCode(code, 'http://example.com'));
  assert.equal(requests, 3);
});

test('renderer installs the selected sync URL before exposing authentication to Logseq', async () => {
  const source = fs.readFileSync(path.join(__dirname, '../client/base/renderer-refresh.js'), 'utf8');
  const order = [];
  const session = {serverUrl:'https://sync.example.com',idToken:'id',accessToken:'access',refreshToken:'root'};
  const context = {
    window:{apis:{refreshSelfhostSession:async () => session}},
    localStorage:{getItem:() => 'root'},
    sh:() => ({tk:() => order.push('closed')}),
    vfb:url => order.push(url),
    Zxb:(...tokens) => order.push(tokens),
    wra:() => order.push('ready'),
    console:{error:() => order.push('error')},
  };
  vm.runInNewContext(source, context);
  context.gyb();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(order[0], session.serverUrl);
  assert.deepEqual(Array.from(order[1]), ['id','access','root']);
  assert.deepEqual(order.slice(2), ['ready','closed']);
  order.length = 0;
  context.localStorage.getItem = () => 'different-root';
  context.gyb();
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(order, ['error','closed']);
});

test('sync settings IPC verifies the supplied URL and rejects failed verification and foreign frames', async () => {
  const handlers = new Map(), events = new Map(), calls = [];
  let dialog, menuEntry;
  class Window {
    constructor() {
      dialog = this;
      this.webContents = {mainFrame:{url:''},setWindowOpenHandler(){},on(){}};
    }
    isDestroyed() { return false; }
    setMenu() {}
    on() {}
    loadFile(file) { this.webContents.mainFrame.url = require('node:url').pathToFileURL(file).href; }
  }
  require('../client/selfhost-onboarding.cjs').install({
    app:{whenReady:() => new Promise(() => {}),on:(name, action) => events.set(name, action)},
    BrowserWindow:Window,
    ipcMain:{handle:(name, action) => handlers.set(name, action),removeHandler(){}},
    Menu:{getApplicationMenu:() => ({getMenuItemById:() => null,append:entry => { menuEntry=entry; }}),setApplicationMenu(){}},
    MenuItem:class { constructor(value) { Object.assign(this, value); } },
    clipboard:{writeText(){}},
    currentSyncCode:() => 'issued-code',currentServerUrl:() => 'https://old.example.com',
    verifySyncCode:async (...args) => { calls.push(['verify',...args]);throw Error('denied'); },
    importSyncCode:(...args) => calls.push(['save',...args]),
  });
  events.get('browser-window-focus')();
  menuEntry.submenu[0].click();
  const submit = handlers.get('logseq-selfhost:setup-code');
  const event = {sender:dialog.webContents,senderFrame:dialog.webContents.mainFrame};
  assert.equal(handlers.get('logseq-selfhost:current-server')(event), 'https://old.example.com');
  await assert.rejects(submit({...event,senderFrame:{url:'https://evil.example.com'}},'issued-code','https://sync.example.com'));
  const result = await submit(event,'issued-code','https://sync.example.com');
  assert.equal(result.ok,false);
  assert.deepEqual(calls,[['verify','issued-code','https://sync.example.com']]);
});

test('changing only the URL retains offline profiles and vaults while the next session uses the new URL', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'logseq-profile-continuity-'));
  t.after(() => fs.rmSync(root, {recursive:true,force:true}));
  const source = fs.readFileSync(path.join(__dirname, '../client/base/selfhost-main.cjs'), 'utf8');
  const subject = '00000000-0000-4000-8000-000000000001';
  function launch(config, appData) {
    fs.mkdirSync(appData, {recursive:true,mode:0o700});
    const paths = new Map([['appData',appData]]), handlers = new Map();
    const owner = path.join(appData,'private-owner','owner.json');
    fs.mkdirSync(path.dirname(owner), {recursive:true,mode:0o700});
    const fakeProcess = {env:{},getuid:() => process.getuid(),umask(){}};
    const app = {setName(){},getPath:name => paths.get(name),setPath:(name,value) => paths.set(name,value),setAsDefaultProtocolClient(){}};
    const modules = {
      'electron':{app,ipcMain:{handle:(name,action) => handlers.set(name,action)}},
      './selfhost-bootstrap.cjs':{
        initializeBootstrap:() => config,readBootstrap:() => config,DEFAULT_FILE:owner,
        ensurePrivateDirectory:directory => fs.mkdirSync(directory,{recursive:true,mode:0o700}),
      },
      './selfhost-preload-guard.cjs':{allowedFrame:() => true},
      'electron-updater':{autoUpdater:{}},
      './electron.js':{},
      './selfhost-onboarding.cjs':{install(){}},
    };
    vm.runInNewContext(source, {
      require:name => Object.hasOwn(modules,name) ? modules[name] : require(name),
      process:fakeProcess, __dirname:path.resolve(__dirname,'../client/base'),
    });
    const frame = {url:'file:///app/index.html'};
    const session = handlers.get('logseq-selfhost:session')({sender:{mainFrame:frame},senderFrame:frame});
    return {profile:paths.get('userData'),vault:fakeProcess.env.LOGSEQ_SELFHOST_VAULT_NAMESPACE,session};
  }
  for (const protocol of [1,2]) {
    const appData = path.join(root,String(protocol));
    const identity = {subject,wrappingKey:'11'.repeat(32),token:'test-token',protocol};
    const first = launch({...identity,serverUrl:'https://old.trycloudflare.com'},appData);
    const offline = path.join(first.profile,'offline-note.fixture');
    fs.writeFileSync(offline,'unsynced local edit',{mode:0o600});
    const second = launch({...identity,serverUrl:'https://new.trycloudflare.com'},appData);
    assert.equal(second.profile,first.profile);
    assert.equal(second.vault,first.vault);
    assert.equal(fs.readFileSync(path.join(second.profile,'offline-note.fixture'),'utf8'),'unsynced local edit');
    assert.equal(second.session.serverUrl,'https://new.trycloudflare.com');
    if (protocol === 1) assert.equal(second.profile,path.join(appData,'Logseq Selfhost'));
    if (protocol === 2) {
      assert.equal(second.profile,path.join(appData,'Logseq Selfhost','identities',subject,'app'));
      const other = launch({...identity,subject:'00000000-0000-4000-8000-000000000002',serverUrl:'https://new.trycloudflare.com'},appData);
      assert.notEqual(other.profile,second.profile);assert.notEqual(other.vault,second.vault);
    }
  }
});
