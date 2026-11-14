// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const https = require('node:https');
const http = require('node:http');
const codeIdentity = require('../../server/auth/code-identity.cjs');
const REAL_HOME = os.homedir();
const DEFAULT_FILE = path.join(os.homedir(), '.config/cisl2/logseq-selfhost/owner.json');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ENDPOINT = 'https://logseq-sync.knappcolin04.workers.dev';
const ISSUER = 'https://logseq-sync.nixc.us';
const SCHEMA = 'logseq-sync-code/v1';
const SALT = 'logseq-selfhost-sync-code-v1';
const TOKEN_SECONDS = 168 * 60 * 60;

function normalizeServerUrl(value) {
  if (typeof value !== 'string' || value.length > 2048 || !/^https?:\/\//.test(value) || /[\\\s]/.test(value)) throw new Error('Invalid sync server URL');
  let url;
  try { url = new URL(value); } catch (_) { throw new Error('Invalid sync server URL'); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) ||
      url.username || url.password || url.pathname !== '/' || url.search || url.hash || value.includes('?') || value.includes('#')) {
    throw new Error('Use an HTTPS sync server URL, or HTTP on localhost');
  }
  return url.origin;
}

function privateAncestors(file) {
  const home=path.resolve(REAL_HOME),directory=path.dirname(path.resolve(file));
  const relative=path.relative(home,directory),components=relative?relative.split(path.sep):[];
  if(relative.startsWith('..')||path.isAbsolute(relative)||components.length>32)throw new Error('Private owner file is outside this home');
  let current=home;
  for(const component of ['',...components]){
    if(component)current=path.join(current,component);
    const stat=fs.lstatSync(current);
    if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid()||(stat.mode&0o022)!==0)throw new Error('Private owner ancestor is unsafe');
  }
}

function privateJSON(file) {
  privateAncestors(file);
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const info = fs.fstatSync(fd);
    if (!info.isFile() || info.size > 32768 || (info.mode & 0o777) !== 0o600 || info.uid !== process.getuid()) {
      throw new Error('Private mode0600 selfhost owner configuration required');
    }
    return JSON.parse(fs.readFileSync(fd, 'utf8'));
  } finally { fs.closeSync(fd); }
}

function identity(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      !UUID.test(value.subject) || !/^[0-9a-f]{64}$/.test(value.wrappingKey)) {
    throw new Error('Invalid private owner identity');
  }
  return value;
}

function decodeSyncCode(code, serverUrl) {
  serverUrl = normalizeServerUrl(serverUrl);
  if (typeof code === 'string' && code.startsWith('ls2_')) return Object.freeze({...codeIdentity.decodeCode(code), serverUrl});
  if (typeof code !== 'string' || !/^ls1_[A-Za-z0-9_-]{66}$/.test(code)) throw new Error('Invalid sync code');
  const bytes = Buffer.from(code.slice(4), 'base64url');
  try {
    if (bytes.length !== 49 || bytes[0] !== 1 || bytes.toString('base64url') !== code.slice(4)) throw new Error('Invalid sync code');
    const hex = bytes.subarray(1, 17).toString('hex');
    const subject = [hex.slice(0,8),hex.slice(8,12),hex.slice(12,16),hex.slice(16,20),hex.slice(20)].join('-');
    return Object.freeze(identity({schema: SCHEMA, subject, serverUrl, wrappingKey: bytes.subarray(17).toString('hex')}));
  } finally { bytes.fill(0); }
}

function deriveKey(rootHex, info) {
  const root = Buffer.from(rootHex, 'hex');
  try { return Buffer.from(crypto.hkdfSync('sha256', root, Buffer.from(SALT), Buffer.from(info), 32)); }
  finally { root.fill(0); }
}

function nativePassword(rootHex) {
  if (!/^[0-9a-f]{64}$/.test(rootHex)) throw new Error('Invalid private owner identity');
  const key = deriveKey(rootHex, 'owner-rsa-password');
  try { return key.toString('base64url'); }
  finally { key.fill(0); }
}

function issueToken(value, now) {
  if (process.type !== 'browser') throw new Error('Owner token issuance requires the main process');
  if (value.schema === codeIdentity.SCHEMA) return codeIdentity.issueToken(value, now);
  if (!Number.isSafeInteger(now) || now < 5 || now > Number.MAX_SAFE_INTEGER - TOKEN_SECONDS) throw new Error('Invalid owner token time');
  const header = Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
  const claims = Buffer.from(JSON.stringify({iss:ISSUER,aud:'cisl2-logseq-owner',sub:value.subject,
    name:'Selfhost owner',email:'owner@logseq.invalid',
    token_use:'owner',iat:now,nbf:now-5,exp:now+TOKEN_SECONDS})).toString('base64url');
  const key = deriveKey(value.wrappingKey, 'owner-auth-hs256');
  try { return header + '.' + claims + '.' + crypto.createHmac('sha256', key).update(header + '.' + claims).digest('base64url'); }
  finally { key.fill(0); }
}

function sessionFromCode(code, now = Math.floor(Date.now() / 1000), serverUrl) {
  const value=decodeSyncCode(code, serverUrl);
  return Object.freeze({token:issueToken(value,now),serverUrl:value.serverUrl,subject:value.subject});
}

function verifySyncCode(code, serverUrl) {
  const session=sessionFromCode(code, undefined, serverUrl);
  return new Promise((resolve,reject)=>{
    let request,settled=false,bytes=0;
    const finish=ok=>{
      if(settled)return;settled=true;clearTimeout(timer);
      if(request)request.destroy();
      if(ok)resolve();else reject(new Error('The sync code could not be verified. Check your connection and try again.'));
    };
    const timer=setTimeout(()=>finish(false),8000);
    try {
      const target = new URL(session.serverUrl+'/graphs');
      const transport = target.protocol === 'https:' ? https : http;
      // Deliberately never follow redirects with this identity's bearer token.
      request=transport.request(target,{method:'GET',rejectUnauthorized:true,maxHeaderSize:16384,
        headers:{authorization:'Bearer '+session.token,accept:'application/json','User-Agent':'cisl2-logseq-sync/1.0'}},response=>{
        if(response.statusCode!==200){response.destroy();finish(false);return}
        response.on('data',chunk=>{bytes+=Buffer.byteLength(chunk);if(bytes>65536){response.destroy();finish(false)}});
        response.on('end',()=>finish(true));
        response.on('error',()=>finish(false));
        response.on('aborted',()=>finish(false));
      });
      request.on('error',()=>finish(false));
      request.end();
    } catch(_){finish(false)}
  });
}

function loadBootstrap(file, now) {
  let value = privateJSON(file);
  identity(value);
  value = {...value, serverUrl: normalizeServerUrl(value.serverUrl)};
  const codeRecord = value.schema === SCHEMA || value.schema === codeIdentity.SCHEMA;
  const selfCertifying = value.schema === codeIdentity.SCHEMA;
  if (selfCertifying) codeIdentity.encodeCode(value);
  if (value.schema !== undefined && !codeRecord) throw new Error('Invalid private sync code record');
  if (codeRecord) {
    if (Object.keys(value).sort().join(',') !== 'schema,serverUrl,subject,wrappingKey') throw new Error('Invalid private sync code record');
    value = {...value, token: issueToken(value, now)};
  }
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      !UUID.test(value.subject) || !/^[0-9a-f]{64}$/.test(value.wrappingKey) ||
      typeof value.token !== 'string' || value.token.length > 16384 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.(?:[A-Za-z0-9_-]{43}|[A-Za-z0-9_-]{86})$/.test(value.token)) {
    throw new Error('Invalid selfhost owner configuration');
  }
  const parts = value.token.split('.');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  // Signature authority stays on the server. This is local bootstrap validation.
  if (header.alg !== (selfCertifying ? 'EdDSA' : 'HS256') || header.typ !== 'JWT' || Object.keys(header).some(k=>!(selfCertifying ? ['alg','typ','jwk'] : ['alg','typ']).includes(k)) || (selfCertifying && !codeIdentity.verifyToken(value.token, null, now)) || (!selfCertifying && claims.iss !== ISSUER) ||
      claims.aud !== 'cisl2-logseq-owner' || claims.sub !== value.subject || claims.token_use !== 'owner' ||
      !Number.isSafeInteger(claims.exp) || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.nbf) ||
      claims.exp <= now || claims.exp <= claims.iat || claims.exp <= claims.nbf || claims.iat > now || claims.nbf > now || claims.iat < 0 || claims.nbf < 0) {
    throw new Error('Owner token claims are invalid or expired');
  }
  return Object.freeze({token: value.token, serverUrl: value.serverUrl, subject: value.subject, wrappingKey: value.wrappingKey, protocol: selfCertifying ? 2 : 1,
    ...(codeRecord ? {rsaPassword: nativePassword(value.wrappingKey)} : {})});
}
function readBootstrap(file = DEFAULT_FILE, now = Math.floor(Date.now() / 1000)) {
  try { return loadBootstrap(file, now); }
  catch (_) { throw new Error('Private selfhost owner configuration is unavailable, invalid or expired'); }
}
function ensurePrivateDirectory(directory) {
  const home = REAL_HOME;
  const relative = path.relative(home, directory);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('Private owner directory is outside this home');
  let current = home;
  for (const component of relative.split(path.sep)) {
    current = path.join(current, component);
    try { fs.mkdirSync(current, {mode:0o700}); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o022) !== 0) throw new Error('Private owner directory is unsafe');
  }
  if ((fs.lstatSync(directory).mode & 0o777) !== 0o700) throw new Error('Private owner directory requires mode0700');
}

function importSyncCode(code, file = DEFAULT_FILE, options = {}) {
  const value = decodeSyncCode(code, options.serverUrl);
  const directory = path.dirname(file);
  ensurePrivateDirectory(directory);
  let previous = null;
  try { previous = identity(privateJSON(file)); }
  catch (error) { if (error.code !== 'ENOENT') throw new Error('Existing private owner configuration could not be verified'); }
  if (previous && (previous.subject !== value.subject || previous.wrappingKey !== value.wrappingKey)) {
    if (!options.replace) throw new Error('This device already belongs to another sync identity');
    const archive = path.join(directory, 'identities', previous.subject);
    ensurePrivateDirectory(archive);
    const backup = path.join(archive, 'owner.saved.json');
    try { fs.writeFileSync(backup, JSON.stringify(privateJSON(file)) + '\n', {mode:0o600, flag:'wx'}); }
    catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const saved=identity(privateJSON(backup));
      if(saved.subject!==previous.subject || saved.wrappingKey!==previous.wrappingKey) throw Error('Saved identity differs');
    }
  }
  const auth = path.join(directory, 'auth.json');
  try {
    const saved = options.replace ? {} : privateJSON(auth);
    if (saved['refresh-token'] && saved['refresh-token'] !== value.wrappingKey) throw new Error('The existing encryption vault uses a different key');
  } catch (error) { if (error.code !== 'ENOENT') throw new Error('The existing encryption vault could not be verified'); }
  const temporary = path.join(directory, '.owner-' + crypto.randomBytes(16).toString('hex'));
  let fd;
  try {
    fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(fd, JSON.stringify(value) + '\n');
    fs.fsyncSync(fd);fs.closeSync(fd);fd = undefined;
    if (previous) {
      const current = identity(privateJSON(file));
      if (current.subject !== previous.subject || current.wrappingKey !== previous.wrappingKey || current.serverUrl !== previous.serverUrl) throw new Error('Private owner configuration changed during setup');
      fs.renameSync(temporary, file);
    } else fs.linkSync(temporary, file);
    const directoryFD = fs.openSync(directory, fs.constants.O_RDONLY);
    try { fs.fsyncSync(directoryFD); } finally { fs.closeSync(directoryFD); }
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temporary); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return Object.freeze({subject:value.subject, serverUrl:value.serverUrl});
}

function initializeBootstrap(file=DEFAULT_FILE) {
  try { privateJSON(file); }
  catch (error) {
    if (error.code!=='ENOENT') throw error;
    // Fresh installations must explicitly choose their operator's server.
    return null;
  }
  return readBootstrap(file);
}
function currentSyncCode(file=DEFAULT_FILE) {
  const value=privateJSON(file); identity(value);
  if(value.schema===codeIdentity.SCHEMA)return codeIdentity.encodeCode(value);
  const bytes=Buffer.concat([Buffer.from([1]),Buffer.from(value.subject.replaceAll('-',''),'hex'),Buffer.from(value.wrappingKey,'hex')]);
  try{return 'ls1_'+bytes.toString('base64url')}finally{bytes.fill(0)}
}
function currentServerUrl(file=DEFAULT_FILE) { return normalizeServerUrl(privateJSON(file).serverUrl); }
module.exports = {initializeBootstrap,currentSyncCode,currentServerUrl,normalizeServerUrl,ensurePrivateDirectory,REAL_HOME,DEFAULT_FILE, ENDPOINT, ISSUER, SCHEMA, readBootstrap, decodeSyncCode, importSyncCode, nativePassword, sessionFromCode, verifySyncCode};
