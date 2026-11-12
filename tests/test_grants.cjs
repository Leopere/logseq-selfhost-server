'use strict';
// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const grants = require('../server/auth/grants.cjs');
const code = require('../server/auth/code-identity.cjs');
const auth = require('../server/auth/owner-auth.cjs');
const admin = path.resolve(__dirname, '../server/auth/logseq-sync-admin.cjs');
function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'logseq-grants-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  return path.join(directory, 'grants.json');
}
function environment(file) {
  const env = {...process.env, LOGSEQ_GRANTS_FILE: file};
  for (const key of ['LOGSEQ_OWNER_SIGNING_KEY_FILE', 'LOGSEQ_OWNER_USER_ID', 'LOGSEQ_OWNER_ISSUER', 'LOGSEQ_OWNER_AUDIENCE', 'DB_SYNC_ADMIN_TOKEN', 'DB_SYNC_ALLOW_UNVERIFIED_JWT_CLAIMS']) delete env[key];
  return env;
}
function cli(file, ...args) { return cp.execFileSync(process.execPath, [admin, ...args], {env: environment(file), encoding: 'utf8'}); }
test('a self-generated identity is denied until deliberately granted, then revoked without restart', async t => {
  const file = fixture(t), old = process.env.LOGSEQ_GRANTS_FILE;
  process.env.LOGSEQ_GRANTS_FILE = file;
  t.after(() => { if (old === undefined) delete process.env.LOGSEQ_GRANTS_FILE; else process.env.LOGSEQ_GRANTS_FILE = old; });
  const identity = code.createIdentity(), other = code.createIdentity();
  const request = value => new Request('http://localhost/graphs', {headers: {authorization: 'Bearer ' + code.issueToken(value, Math.floor(Date.now()/1000))}});
  assert.equal(await auth.verifyRequest(request(identity)), null);
  grants.addGrant(identity.subject, 'manual grant', 'ed25519', file);
  assert.equal((await auth.verifyRequest(request(identity))).sub, identity.subject);
  assert.equal(await auth.verifyRequest(request(other)), null);
  grants.revokeGrant(identity.subject, file);
  assert.equal(await auth.verifyRequest(request(identity)), null);
  assert.throws(() => grants.addGrant(identity.subject, 'silent restoration', 'ed25519', file));
});
test('console issuance persists no E2EE root or code; list and revoke do not disclose credentials', t => {
  const file = fixture(t), issued = JSON.parse(cli(file, 'grant', 'new device'));
  const identity = code.decodeCode(issued.syncCode);
  assert.equal(identity.subject, issued.id);
  const registry = fs.readFileSync(file, 'utf8'), listing = cli(file, 'list');
  for (const output of [registry, listing]) {
    assert.ok(!output.includes(issued.syncCode));
    assert.ok(!output.includes(identity.wrappingKey));
  }
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(grants.activeGrant(issued.id, 'ed25519', file), true);
  const revoked = JSON.parse(cli(file, 'revoke', issued.id));
  assert.ok(Number.isInteger(revoked.revokedAt));
  assert.equal(grants.activeGrant(issued.id, 'ed25519', file), false);
  assert.equal(JSON.parse(cli(file, 'list')).length, 1);
});
test('registry missing, malformed, unsafe, or linked fails closed; locks do not erase existing grants', t => {
  const file = fixture(t), id = code.createIdentity().subject;
  assert.equal(grants.activeGrant(id, 'ed25519', file), false);
  grants.addGrant(id, 'keep me', 'ed25519', file);
  const original = fs.readFileSync(file, 'utf8');
  fs.writeFileSync(file + '.lock', '', {mode: 0o600});
  assert.throws(() => grants.revokeGrant(id, file));
  assert.equal(fs.readFileSync(file, 'utf8'), original);
  fs.unlinkSync(file + '.lock');
  fs.chmodSync(file, 0o644);
  assert.equal(grants.activeGrant(id, 'ed25519', file), false);
  fs.chmodSync(file, 0o600);
  fs.writeFileSync(file, 'invalid', {mode: 0o600});
  assert.equal(grants.activeGrant(id, 'ed25519', file), false);
  assert.throws(() => grants.addGrant(code.createIdentity().subject, 'do not reset', 'ed25519', file));
  assert.equal(fs.readFileSync(file, 'utf8'), 'invalid');
  fs.unlinkSync(file);
  const target = file + '.target';
  fs.writeFileSync(target, original, {mode: 0o600}); fs.symlinkSync(target, file);
  assert.equal(grants.activeGrant(id, 'ed25519', file), false);
  assert.throws(() => grants.revokeGrant(id, file));
  assert.equal(fs.readFileSync(target, 'utf8'), original);
});
test('legacy HMAC identity also requires an explicit legacy grant; EdDSA grant cannot authorize it', t => {
  const file = fixture(t), keyFile = path.join(path.dirname(file), 'key');
  fs.writeFileSync(keyFile, '11'.repeat(32), {mode: 0o600});
  const subject = '00000000-0000-4000-8000-000000000001', now = Math.floor(Date.now()/1000);
  const env = {...environment(file), LOGSEQ_OWNER_SIGNING_KEY_FILE: keyFile, LOGSEQ_OWNER_USER_ID: subject,
    LOGSEQ_OWNER_ISSUER: 'https://legacy.example.invalid', LOGSEQ_OWNER_AUDIENCE: 'cisl2-logseq-owner'};
  const claims = {iss:env.LOGSEQ_OWNER_ISSUER, aud:env.LOGSEQ_OWNER_AUDIENCE, sub:subject, token_use:'owner', iat:now, nbf:now-5, exp:now+604800};
  const body = Buffer.from(JSON.stringify({alg:'HS256', typ:'JWT'})).toString('base64url') + '.' + Buffer.from(JSON.stringify(claims)).toString('base64url');
  const token = body + '.' + crypto.createHmac('sha256', Buffer.from('11'.repeat(32), 'hex')).update(body).digest('base64url');
  const script = `const assert=require('node:assert/strict'),auth=require(${JSON.stringify(path.resolve(__dirname, '../server/auth/owner-auth.cjs'))});
    auth.verifyRequest(new Request('http://localhost/graphs',{headers:{authorization:'Bearer '+process.env.TEST_TOKEN}})).then(result=>assert.equal(!!result,process.env.EXPECT==='yes'));`;
  function check(expect) { cp.execFileSync(process.execPath, ['-e', script], {env:{...env, TEST_TOKEN:token, EXPECT:expect}, stdio:'pipe'}); }
  check('no');
  cp.execFileSync(process.execPath, [admin, 'import', subject, 'existing devices', '--legacy'], {env, stdio:'pipe'});
  check('yes');
  grants.revokeGrant(subject, file); check('no');
});
test('manual import accepts a public subject only and does not create another identity', t => {
  const file = fixture(t), identity = code.createIdentity();
  const imported = JSON.parse(cli(file, 'import', identity.subject, 'existing LS2 devices'));
  assert.equal(imported.id, identity.subject);
  assert.equal(imported.kind, 'ed25519');
  assert.equal(grants.activeGrant(identity.subject, 'ed25519', file), true);
  assert.equal(grants.activeGrant(identity.subject, 'legacy-hs256', file), false);
  assert.throws(() => cli(file, 'grant', 'bad\nlabel'));
});
