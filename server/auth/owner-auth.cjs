'use strict';
// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
// Signed bearer tokens require an explicit local operator grant.
const crypto = require('node:crypto');
const {verifyToken} = require('./code-identity.cjs');
const fs = require('node:fs');
const {activeGrant} = require('./grants.cjs');
const AUDIENCE = 'cisl2-logseq-owner';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function createVerifier({keyHex, issuer, audience, owner, now = () => Math.floor(Date.now() / 1000)}) {
  if (!/^[0-9a-f]{64}$/.test(keyHex) || typeof issuer !== 'string' || issuer.length < 1 || issuer.length > 256 || audience !== AUDIENCE || !UUID.test(owner)) {
    throw new Error('Invalid owner authentication configuration');
  }
  const key = Buffer.from(keyHex, 'hex');
  function decode(part) {
    if (!/^[A-Za-z0-9_-]+$/.test(part)) throw new Error('Invalid token encoding');
    const bytes = Buffer.from(part, 'base64url');
    if (bytes.toString('base64url') !== part) throw new Error('Noncanonical token encoding');
    const result = JSON.parse(bytes.toString('utf8'));
    if (result === null || typeof result !== 'object' || Array.isArray(result)) throw new Error('Invalid token object');
    return result;
  }
  return function verify(token) {
    try {
      if (typeof token !== 'string' || token.length > 16384) return null;
      const parts = token.split('.');
      if (parts.length !== 3 || !/^[A-Za-z0-9_-]{43}$/.test(parts[2])) return null;
      const header = decode(parts[0]);
      if (header.alg !== 'HS256' || header.typ !== 'JWT' || Object.keys(header).some(k => !['alg', 'typ'].includes(k))) return null;
      const signature = Buffer.from(parts[2], 'base64url');
      if (signature.toString('base64url') !== parts[2]) return null;
      const expected = crypto.createHmac('sha256', key).update(parts[0] + '.' + parts[1]).digest();
      if (signature.length !== expected.length || !crypto.timingSafeEqual(signature, expected)) return null;
      const claims = decode(parts[1]);
      const current = now();
      if (claims.iss !== issuer || claims.aud !== audience || claims.sub !== owner || claims.token_use !== 'owner' ||
          !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.nbf) || !Number.isSafeInteger(claims.exp) ||
          claims.iat < 0 || claims.nbf < 0 || claims.iat > current || claims.nbf > current || claims.exp <= current ||
          claims.exp <= claims.iat || claims.exp <= claims.nbf) return null;
      return claims;
    } catch (_) { return null; }
  };
}

let configured;
function validateEnvironment() {
  if (configured) return configured;
  if (process.env.DB_SYNC_ALLOW_UNVERIFIED_JWT_CLAIMS || process.env.DB_SYNC_ADMIN_TOKEN) {
    throw new Error('Alternative authentication bypass configuration is prohibited');
  }
  const path = process.env.LOGSEQ_OWNER_SIGNING_KEY_FILE;
  if (!path) {
    if (process.env.LOGSEQ_OWNER_USER_ID || process.env.LOGSEQ_OWNER_ISSUER || process.env.LOGSEQ_OWNER_AUDIENCE) {
      throw new Error('Incomplete legacy authentication configuration');
    }
    configured = () => null;
    return configured;
  }
  if (!require('node:path').isAbsolute(path)) throw new Error('Absolute owner signing secret file required');
  const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  let keyHex;
  try {
    const info = fs.fstatSync(fd);
    if (!info.isFile() || info.size !== 64) throw new Error('Owner signing secret must contain exactly64hex characters');
    keyHex = fs.readFileSync(fd, 'utf8');
  } finally { fs.closeSync(fd); }
  configured = createVerifier({keyHex, issuer: process.env.LOGSEQ_OWNER_ISSUER,
    audience: process.env.LOGSEQ_OWNER_AUDIENCE, owner: process.env.LOGSEQ_OWNER_USER_ID});
  return configured;
}

function tokenFromRequest(request) {
  const authorization = request.headers.get('authorization');
  if (authorization !== null) {
    return authorization.startsWith('Bearer ') ? authorization.slice(7) : null;
  }
  const values = new URL(request.url).searchParams.getAll('token');
  return values.length === 1 ? values[0] : null;
}

let lastRejectionLog = -Infinity;
function logRejection() {
  const now = Date.now();
  if (now - lastRejectionLog >= 30000) {
    lastRejectionLog = now;
    console.warn('logseq-sync: authorization denied (further denials suppressed for 30s)');
  }
}
async function verifyRequest(request) {
  // Invalid credentials and missing/corrupt authorization state resolve nil;
  // never throw into the upstream authentication recovery/fallback path.
  try {
    const verify = validateEnvironment(), token = tokenFromRequest(request);
    const legacy = verify(token);
    const claims = legacy || verifyToken(token, process.env.LOGSEQ_OWNER_USER_ID);
    if (claims && activeGrant(claims.sub, legacy ? 'legacy-hs256' : 'ed25519')) return claims;
  } catch (_) {}
  logRejection();
  return null;
}
module.exports = {createVerifier, validateEnvironment, tokenFromRequest, verifyRequest};
