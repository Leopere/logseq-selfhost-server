'use strict';
// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_BYTES = 1024 * 1024;
function registryPath() {
  const file = process.env.LOGSEQ_GRANTS_FILE || '/app/data/grants.json';
  if (!path.isAbsolute(file)) throw Error('Grant registry path must be absolute');
  return path.normalize(file);
}
function secureParent(file) {
  const parent = path.dirname(file), info = fs.lstatSync(parent);
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o022)) throw Error('Grant registry directory must be private to its owner');
  return parent;
}
function validate(value) {
  if (!value || value.version !== 1 || !Array.isArray(value.grants) || value.grants.length > 4096 || Object.keys(value).sort().join(',') !== 'grants,version') throw Error('Invalid grant registry');
  const ids = new Set();
  for (const grant of value.grants) {
    if (!grant || Object.keys(grant).sort().join(',') !== 'createdAt,id,kind,label,revokedAt' || !UUID.test(grant.id) || ids.has(grant.id) ||
        !['ed25519', 'legacy-hs256'].includes(grant.kind) || !validLabel(grant.label) ||
        !Number.isSafeInteger(grant.createdAt) || grant.createdAt < 0 ||
        !(grant.revokedAt === null || (Number.isSafeInteger(grant.revokedAt) && grant.revokedAt >= grant.createdAt))) throw Error('Invalid grant registry');
    ids.add(grant.id);
  }
  return value;
}
function validLabel(label) { return typeof label === 'string' && label.trim().length > 0 && label.length <= 128 && !/[\x00-\x1f\x7f]/.test(label); }
function readRegistry(file = registryPath(), {allowMissing = false} = {}) {
  secureParent(file);
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); }
  catch (error) { if (allowMissing && error.code === 'ENOENT') return {version: 1, grants: []}; throw error; }
  try {
    const info = fs.fstatSync(fd);
    if (!info.isFile() || info.size > MAX_BYTES || (info.mode & 0o077)) throw Error('Grant registry must be a private regular file');
    return validate(JSON.parse(fs.readFileSync(fd, 'utf8')));
  } finally { fs.closeSync(fd); }
}
function activeGrant(subject, kind, file = registryPath()) {
  try { return readRegistry(file).grants.some(grant => grant.id === subject && grant.kind === kind && grant.revokedAt === null); }
  catch (_) { return false; }
}
function updateRegistry(change, file = registryPath()) {
  const parent = secureParent(file), lock = file + '.lock';
  let lockFd, tmp, fd;
  try {
    lockFd = fs.openSync(lock, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    const value = readRegistry(file, {allowMissing: true});
    const result = change(value);
    const bytes = JSON.stringify(validate(value), null, 2) + '\n';
    if (Buffer.byteLength(bytes) > MAX_BYTES) throw Error('Grant registry is full');
    tmp = path.join(parent, '.' + path.basename(file) + '.' + crypto.randomBytes(12).toString('hex'));
    fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    // Never overwrite a link or nonregular existing target, even when corrupt.
    try { const target = fs.lstatSync(file); if (!target.isFile() || target.isSymbolicLink()) throw Error('Invalid grant registry target'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    fs.renameSync(tmp, file); tmp = undefined;
    const dirFd = fs.openSync(parent, fs.constants.O_RDONLY); try { fs.fsyncSync(dirFd); } finally { fs.closeSync(dirFd); }
    return result;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    if (tmp) fs.unlinkSync(tmp);
    if (lockFd !== undefined) { fs.closeSync(lockFd); fs.unlinkSync(lock); }
  }
}
function addGrant(subject, label, kind = 'ed25519', file = registryPath()) {
  if (!UUID.test(subject) || !validLabel(label) || !['ed25519', 'legacy-hs256'].includes(kind)) throw Error('Invalid grant');
  return updateRegistry(value => {
    if (value.grants.some(grant => grant.id === subject)) throw Error('Identity already has a grant; revoked grants cannot be silently reactivated');
    const grant = {id: subject, label, kind, createdAt: Math.floor(Date.now()/1000), revokedAt: null};
    value.grants.push(grant); return grant;
  }, file);
}
function revokeGrant(id, file = registryPath()) {
  if (!UUID.test(id)) throw Error('Invalid grant id');
  return updateRegistry(value => {
    const grant = value.grants.find(grant => grant.id === id);
    if (!grant) throw Error('Grant not found');
    if (grant.revokedAt === null) grant.revokedAt = Math.max(grant.createdAt, Math.floor(Date.now()/1000));
    return grant;
  }, file);
}
module.exports = {registryPath, readRegistry, activeGrant, addGrant, revokeGrant};
