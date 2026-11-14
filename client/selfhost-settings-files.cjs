// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
// Portable settings only. Logseq identity files, databases and plugin code are never read.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const LIMIT = 256 * 1024;
const SECRET = /password|secret|token|api[-_]?key|credential|private[-_]?key|authorization|cookie/i;
const BAD_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const absolute = value => typeof value === 'string' && /^(?:\/|~\/|[a-z]:[\\/]|\\\\|file:)/i.test(value);
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
function hasPrivate(value, depth = 0) {
  if (depth > 20 || absolute(value)) return true;
  if (Array.isArray(value)) return value.some(v => hasPrivate(v, depth + 1));
  return value && typeof value === 'object' && Object.entries(value).some(([k, v]) => SECRET.test(k) || BAD_KEYS.has(k) || hasPrivate(v, depth + 1));
}

function permitted(name) {
  return ['config/plugins.edn', 'config/config.edn', 'preferences.json'].includes(name) ||
    /^settings\/[a-z0-9][a-z0-9._-]{0,95}\.json$/i.test(name) && !name.endsWith('_layouts.json');
}
function portable(value, key = '', depth = 0) {
  if (depth > 20 || SECRET.test(key) || BAD_KEYS.has(key) || absolute(value)) return undefined;
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
  if (Array.isArray(value)) {
    if (hasPrivate(value)) return undefined;
    const result = value.map(v => portable(v, '', depth + 1));
    return result.some(v => v === undefined) ? undefined : result;
  }
  if (!value || typeof value !== 'object') return undefined;
  const result = Object.create(null);
  for (const name of Object.keys(value).sort()) {
    const clean = portable(value[name], name, depth + 1);
    if (clean !== undefined) result[name] = clean;
  }
  return result;
}
function safeEdn(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > LIMIT || !text.trim().startsWith('{')) return false;
  // EDN is copied as data, never evaluated. Reject unsafe reader forms and files
  // containing private settings rather than attempting a lossy EDN rewrite.
  if (/:(?:[^\s{}\[\]";]*\/)?[^\s{}\[\]";]*(?:password|secret|token|api[-_]?key|credential|private[-_]?key|authorization|cookie)[^\s{}\[\]";]*/i.test(text) ||
      /"(?:\/|~\/|[a-z]:\\|\\\\|file:)/i.test(text)) return false;
  let quoted = false, escape = false, comment = false;
  const stack = [], pairs = { '}': '{', ']': '[', ')': '(' };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (comment) { if (c === '\n') comment = false; continue; }
    if (quoted) {
      if (escape) escape = false;
      else if (c === '\\') escape = true;
      else if (c === '"') quoted = false;
      continue;
    }
    if (c === ';') comment = true;
    else if (c === '"') quoted = true;
    else if (c === '#' && text[i + 1] !== '{') return false;
    else if ('{[('.includes(c)) stack.push(c);
    else if ('}])'.includes(c) && stack.pop() !== pairs[c]) return false;
  }
  return !quoted && stack.length === 0;
}
function documentFor(name, text) {
  if (!permitted(name) || Buffer.byteLength(text) > LIMIT) throw Error('Unsupported settings file');
  if (name.endsWith('.edn')) {
    if (!safeEdn(text)) throw Error('Settings remain local');
    return { kind: 'edn', value: text };
  }
  let object = JSON.parse(text);
  if (!object || typeof object !== 'object' || Array.isArray(object)) throw Error('Settings object required');
  if (name === 'preferences.json') object = Object.fromEntries(Object.entries(object).filter(([k]) => ['theme', 'themes'].includes(k)));
  return { kind: 'json', value: portable(object) };
}
function validateDocument(name, document) {
  if (!document || !['json', 'edn'].includes(document.kind)) throw Error('Invalid settings document');
  const text = document.kind === 'edn' ? document.value : JSON.stringify(document.value);
  const clean = documentFor(name, text);
  if (clean.kind !== document.kind || JSON.stringify(clean.value) !== JSON.stringify(document.value)) throw Error('Nonportable incoming settings');
  return clean;
}
function checked(root, name, create = false) {
  if (!permitted(name)) throw Error('Unsupported settings path');
  const parts = name.split('/');
  let current = root;
  for (const component of ['', ...parts.slice(0, -1)]) {
    current = component ? path.join(current, component) : current;
    if (create && !fs.existsSync(current)) fs.mkdirSync(current, { mode: 0o700 });
    const st = fs.lstatSync(current);
    if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid() || st.mode & 0o022) throw Error('Unsafe settings directory');
  }
  return path.join(root, ...parts);
}
function read(root, name) {
  let file;
  try { file = checked(root, name); }
  catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); }
  catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.uid !== process.getuid() || st.mode & 0o022 || st.size > LIMIT) throw Error('Unsafe settings file');
    const text = fs.readFileSync(fd, 'utf8');
    return { text, stamp: { ino: st.ino, dev: st.dev, mtimeMs: st.mtimeMs, size: st.size }, hash: hash(text) };
  } finally { fs.closeSync(fd); }
}
function snapshot(root) {
  const names = ['config/plugins.edn', 'config/config.edn', 'preferences.json'];
  const directory = path.join(root, 'settings');
  if (fs.existsSync(directory)) {
    checked(root, 'settings/probe.json');
    names.push(...fs.readdirSync(directory).map(n => 'settings/' + n).filter(permitted));
  }
  if (names.length > 128) throw Error('Settings file count exceeds bound');
  const files = Object.create(null), skipped = [];
  let total = 0;
  for (const name of names.sort()) {
    try {
      const saved = read(root, name);
      if (!saved) continue;
      const doc = documentFor(name, saved.text);
      total += Buffer.byteLength(JSON.stringify(doc));
      if (total > 2 * 1024 * 1024) throw Error('Settings size exceeds bound');
      files[name] = doc;
    } catch (_) { skipped.push(name); }
  }
  return { files, skipped };
}
function mergeLocal(local, remote, key = '', depth = 0) {
  if (depth > 20) throw Error('Settings nesting exceeds bound');
  if (SECRET.test(key) || BAD_KEYS.has(key) || absolute(local) || Array.isArray(local) && hasPrivate(local)) return local;
  if (!remote || typeof remote !== 'object' || Array.isArray(remote)) return remote;
  const result = Object.create(null);
  if (local && typeof local === 'object' && !Array.isArray(local)) {
    for (const k of Object.keys(local)) {
      if (BAD_KEYS.has(k)) continue;
      if (portable(local[k], k) === undefined) result[k] = local[k];
      else if (local[k] && typeof local[k] === 'object' && !Array.isArray(local[k])) {
        const protectedBranch = mergeLocal(local[k], {}, '', depth + 1);
        if (Object.keys(protectedBranch).length) result[k] = protectedBranch;
      }
    }
  }
  for (const [k, v] of Object.entries(remote)) {
    if (BAD_KEYS.has(k)) throw Error('Unsafe settings key');
    result[k] = mergeLocal(local && local[k], v, k, depth + 1);
  }
  return result;
}
function restore(root, backupRoot, name, document) {
  const doc = validateDocument(name, document);
  const previous = read(root, name);
  if (doc.kind === 'edn' && previous && !safeEdn(previous.text)) return false;
  let value = doc.value;
  if (doc.kind === 'json' && previous) {
    const local = JSON.parse(previous.text);
    value = name === 'preferences.json' ? { ...local, ...value } : mergeLocal(local, value);
  }
  const text = doc.kind === 'edn' ? value : JSON.stringify(value, null, 2) + '\n';
  if (previous && previous.text === text) return false;
  const file = checked(root, name, true);
  if (previous) {
    fs.mkdirSync(backupRoot, { recursive: true, mode: 0o700 });
    const info = fs.lstatSync(backupRoot);
    if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid() || info.mode & 0o077) throw Error('Private backup directory required');
    const backup = path.join(backupRoot, hash(name) + '-' + previous.hash);
    try { fs.writeFileSync(backup, previous.text, { mode: 0o600, flag: 'wx' }); }
    catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const fd = fs.openSync(backup, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
      try {
        const st = fs.fstatSync(fd);
        if (!st.isFile() || st.uid !== process.getuid() || st.mode & 0o077 || st.size > LIMIT || hash(fs.readFileSync(fd)) !== previous.hash) throw Error('Unsafe settings backup');
      } finally { fs.closeSync(fd); }
    }
  }
  const temporary = file + '.sync-' + crypto.randomBytes(12).toString('hex');
  const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, text); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const current = read(root, name);
  if ((previous && (!current || current.hash !== previous.hash || current.stamp.ino !== previous.stamp.ino)) || (!previous && current)) {
    throw Error('Local settings changed during restore; retained pending file');
  }
  fs.renameSync(temporary, file);
  return true;
}
function importPortableSettings(source, root, backups) {
  const saved = snapshot(source);
  let imported = 0;
  for (const [name, doc] of Object.entries(saved.files)) {
    // Never replace a setting already present in the customized app.
    if (read(root, name)) continue;
    if (restore(root, backups, name, doc)) imported++;
  }
  return imported;
}
module.exports = { importPortableSettings, permitted, portable, documentFor, validateDocument, safeEdn, snapshot, restore, mergeLocal };
