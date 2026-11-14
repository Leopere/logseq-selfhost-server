// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const files = require('../client/selfhost-settings-files.cjs');
const engine = require('../client/selfhost-settings-engine.js');
const writerA = '00000000-0000-4000-8000-000000000001';
const writerB = '00000000-0000-4000-8000-000000000002';
function directory(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'logseq-settings-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
function put(root, name, value) {
  const file = path.join(root, name);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, value, { mode: 0o600 });
}
function baseline(local, seen) {
  return { fingerprints: Object.fromEntries(Object.entries(local).map(([n, d]) => [n, engine.fingerprint(d)])), seen };
}
test('capture includes inventory and portable plugin settings, excludes credentials, paths and code', t => {
  const root = directory(t);
  put(root, 'config/plugins.edn', '{:example {:repo "owner/example" :version "1.0.0" :theme false :effect true}}');
  put(root, 'settings/example.json', JSON.stringify({ enabled: true, style: { color: 'blue', apiKey: 'private' }, token: 'private', output: '/Users/example/notes', models: [{ token: 'private' }] }));
  put(root, 'settings/example_layouts.json', '{"width":123}');
  put(root, 'preferences.json', '{"theme":"dark","externals":{"path":"/device/plugin"}}');
  put(root, 'owner.json', '{"privateKey":"private"}');
  put(root, 'plugins/code.js', 'not settings');
  const s = files.snapshot(root);
  assert.deepEqual(Object.keys(s.files).sort(), ['config/plugins.edn', 'preferences.json', 'settings/example.json']);
  assert.deepEqual(JSON.parse(JSON.stringify(s.files['settings/example.json'].value)), { enabled: true, style: { color: 'blue' } });
  assert.doesNotMatch(JSON.stringify(s), /private|\/Users\/example|\/device\/plugin/);
});
test('two devices restore settings then propagate a later edit without overwriting local credentials', t => {
  const a = directory(t), b = directory(t), backups = path.join(directory(t), 'backups');
  put(a, 'settings/example.json', '{"color":"blue","apiKey":"a-private"}');
  put(b, 'settings/example.json', '{"color":"red","apiKey":"b-private"}');
  const initial = files.snapshot(a).files;
  const send = engine.reconcile(initial, null, [], writerA, 1000);
  const receive = engine.reconcile(files.snapshot(b).files, null, send.publish, writerB, 1001);
  assert.equal(receive.publish.length, 0);
  for (const r of receive.restore) files.restore(b, backups, r.path, r.document);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(b, 'settings/example.json'))), { apiKey: 'b-private', color: 'blue' });
  const previous = baseline(files.snapshot(b).files, receive.seen);
  put(b, 'settings/example.json', '{"color":"green","apiKey":"b-private"}');
  const edited = engine.reconcile(files.snapshot(b).files, previous, send.publish, writerB, 1002);
  assert.equal(edited.publish.length, 1);
  const back = engine.reconcile(initial, baseline(initial, send.seen), [...send.publish, ...edited.publish], writerA, 1003);
  assert.equal(back.restore.length, 1);
  files.restore(a, path.join(directory(t), 'backups'), back.restore[0].path, back.restore[0].document);
  assert.equal(JSON.parse(fs.readFileSync(path.join(a, 'settings/example.json'))).apiKey, 'a-private');
  assert.equal(JSON.parse(fs.readFileSync(path.join(a, 'settings/example.json'))).color, 'green');
  assert.equal(fs.readdirSync(backups).length, 1);
});
test('empty second device adopts the remote inventory instead of publishing an empty list', () => {
  const remote = engine.reconcile({ 'config/plugins.edn': { kind: 'edn', value: '{}' } }, null, [], writerA, 1000).publish;
  const plan = engine.reconcile({}, null, remote, writerB, 1001);
  assert.equal(plan.publish.length, 0);
  assert.equal(plan.restore.length, 1);
});
test('concurrent edits of different files converge and same-file edits have a deterministic winner', () => {
  const a = engine.reconcile({ 'settings/a.json': { kind: 'json', value: { x: 1 } } }, null, [], writerA, 1000);
  const b = engine.reconcile({ 'settings/b.json': { kind: 'json', value: { x: 2 } } }, null, [], writerB, 1000);
  const plan = engine.reconcile({}, null, [...a.publish, ...b.publish], writerA, 1001);
  assert.equal(plan.restore.length, 2);
  const tie = { ...a.publish[0], writer: writerB, document: { kind: 'json', value: { x: 3 } } };
  assert.equal(engine.reconcile({}, null, [...a.publish, tie], writerA, 1001).restore[0].writer, writerB);
});
test('portable restoration preserves nested local secrets and private provider arrays', () => {
  const local = { credentials: { token: 'keep' }, nested: { password: 'keep' }, providers: [{ token: 'keep' }], obsolete: 1 };
  const merged = files.mergeLocal(local, { enabled: true, providers: [] });
  assert.equal(merged.credentials.token, 'keep');
  assert.equal(merged.nested.password, 'keep');
  assert.equal(merged.providers[0].token, 'keep');
  assert.equal(merged.obsolete, undefined);
});
test('traversal, symlink reads and writes, malformed documents and executable reader forms are refused', t => {
  const root = directory(t), outside = directory(t);
  put(outside, 'private.json', '{"secret":"private"}');
  fs.mkdirSync(path.join(root, 'settings'), { mode: 0o700 });
  fs.symlinkSync(path.join(outside, 'private.json'), path.join(root, 'settings/link.json'));
  const doc = { kind: 'json', value: { enabled: true } };
  assert.throws(() => files.restore(root, path.join(root, 'backups'), '../escape.json', doc));
  assert.throws(() => files.restore(root, path.join(root, 'backups'), 'settings/link.json', doc));
  assert.equal(files.snapshot(root).files['settings/link.json'], undefined);
  assert.throws(() => files.validateDocument('settings/a.json', { kind: 'json', value: { token: 'private' } }));
  assert.throws(() => files.validateDocument('config/config.edn', { kind: 'edn', value: '{:x #=(run)}' }));
  assert.equal(engine.valid({ schema: engine.schema, path: '../escape.json', writer: writerA, clock: 1, deleted: false, document: doc }), false);
});
test('unsafe existing global config remains local and is not overwritten by an incoming safe config', t => {
  const root = directory(t);
  put(root, 'config/config.edn', '{:api-key "private" :preferred-format :markdown}');
  assert.equal(files.snapshot(root).files['config/config.edn'], undefined);
  assert.equal(files.restore(root, path.join(root, 'backups'), 'config/config.edn', { kind: 'edn', value: '{}' }), false);
  assert.match(fs.readFileSync(path.join(root, 'config/config.edn'), 'utf8'), /private/);
});
test('a settings backup can be reused safely without discarding an earlier copy', t => {
  const root = directory(t), backups = path.join(directory(t), 'backups');
  const original = '{"x":1}';
  put(root, 'settings/a.json', original);
  files.restore(root, backups, 'settings/a.json', { kind: 'json', value: { x: 2 } });
  put(root, 'settings/a.json', original);
  files.restore(root, backups, 'settings/a.json', { kind: 'json', value: { x: 3 } });
  assert.equal(fs.readdirSync(backups).length, 1);
});
test('renderer refuses graphs without native E2EE before reading or writing any settings', async () => {
  let reads = 0, writes = 0, pending;
  const context = { window: { apis: { readSelfhostSettings: () => reads++ }, logseq: { api: {
    get_current_graph: async () => ({ name: 'logseq_db_Test' }),
    datascript_query: async () => false,
    create_page: async () => writes++,
  } }, addEventListener() {} }, setInterval() {}, localStorage: {}, crypto: {} };
  context.window.LogseqSelfhostSettingsEngine = engine;
  const source = fs.readFileSync(path.join(__dirname, '../client/selfhost-settings-renderer.js'), 'utf8');
  // Expose the initial promise so the E2EE boundary is tested without timer polling.
  vm.runInNewContext(source.replace('  tick();\n})();', '  globalThis.initial = tick();\n})();'), context);
  await context.initial;
  assert.equal(reads, 0);
  assert.equal(writes, 0);
  assert.equal(context.window.__logseqSelfhostSettingsSync.state, 'waiting-for-encrypted-sync');
});

test('legacy settings import keeps existing settings and never copies plugin code or credentials', t => {
  const original = directory(t), current = directory(t), backups = path.join(directory(t), 'backups');
  put(original, 'config/plugins.edn', '{:example {:repo "owner/example" :version "1.0.0"}}');
  put(original, 'settings/example.json', '{"color":"blue","apiKey":"private"}');
  put(original, 'preferences.json', '{"theme":"dark"}');
  put(original, 'plugins/code.js', 'do not copy');
  put(current, 'preferences.json', '{"theme":"light"}');
  assert.equal(files.importPortableSettings(original, current, backups), 2);
  assert.equal(files.importPortableSettings(original, current, backups), 0);
  assert.equal(JSON.parse(fs.readFileSync(path.join(current, 'preferences.json'))).theme, 'light');
  assert.doesNotMatch(fs.readFileSync(path.join(current, 'settings/example.json'), 'utf8'), /apiKey|private/);
  assert.equal(fs.existsSync(path.join(current, 'plugins/code.js')), false);
  assert.equal(fs.readFileSync(path.join(original, 'settings/example.json'), 'utf8'), '{"color":"blue","apiKey":"private"}');
});

test('renderer recognizes native blocks after Logseq removes the JSON fence', async () => {
  for (const fenced of [false, true]) {
    const doc = {kind:'json',value:{theme:'dark'}};
    const record = {schema:engine.schema,path:'preferences.json',writer:writerA,clock:1,deleted:false,document:doc};
    let writes=0, restored=0, local={};
    const store=new Map();
    const context={window:{apis:{readSelfhostSettings:async()=>({files:local,skipped:[]}),restoreSelfhostSettings:async r=>{restored++;local[r.path]=r.document;return {restored:true};}},logseq:{api:{
      get_current_graph:async()=>({name:'logseq_db_Test'}),datascript_query:async()=>true,get_page:async()=>({}),
      get_page_blocks_tree:async()=>[{uuid:writerA,content:fenced?'```json\n'+JSON.stringify(record)+'\n```':JSON.stringify(record)}],
      append_block_in_page:async()=>writes++,update_block:async()=>writes++,
    }},addEventListener(){}},setInterval(){},localStorage:{getItem:k=>store.get(k),setItem:(k,v)=>store.set(k,v)},crypto:{randomUUID:()=>writerB}};
    context.window.LogseqSelfhostSettingsEngine=engine;
    const source=fs.readFileSync(path.join(__dirname,'../client/selfhost-settings-renderer.js'),'utf8');
    vm.runInNewContext(source.replace('  tick();\n})();','  globalThis.initial = tick();\n})();'),context);
    await context.initial;
    assert.equal(restored,1);assert.equal(writes,0);assert.deepEqual(JSON.parse(JSON.stringify(local['preferences.json'])),doc);
  }
});
