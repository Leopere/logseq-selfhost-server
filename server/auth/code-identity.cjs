// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
const crypto = require('node:crypto');
const ISSUER = 'logseq-selfhost';
const AUDIENCE = 'cisl2-logseq-owner';
const SCHEMA = 'logseq-sync-code/v2';
const ENDPOINT = process.env.DB_SYNC_BASE_URL || 'http://localhost:8787';
const HEX = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function subjectFor(publicBytes) {
  const id = crypto.createHash('sha256').update('logseq-selfhost-identity/v2\0').update(publicBytes).digest().subarray(0, 16);
  id[6] = (id[6] & 15) | 64; id[8] = (id[8] & 63) | 128;
  const hex = id.toString('hex');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}
function signingIdentity(rootHex) {
  if (!HEX.test(rootHex)) throw Error('Invalid sync identity');
  const root = Buffer.from(rootHex, 'hex');
  const seed = Buffer.from(crypto.hkdfSync('sha256', root, Buffer.from('logseq-selfhost-sync-code-v1'), Buffer.from('owner-auth-ed25519/v2'), 32));
  try {
    const privateKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'), seed]), format: 'der', type: 'pkcs8' });
    const jwk = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
    return { privateKey, jwk, subject: subjectFor(Buffer.from(jwk.x, 'base64url')) };
  } finally { root.fill(0); seed.fill(0); }
}
function createIdentity() {
  const root = crypto.randomBytes(32);
  try {
    const wrappingKey = root.toString('hex');
    return { schema: SCHEMA, subject: signingIdentity(wrappingKey).subject, serverUrl: ENDPOINT, wrappingKey };
  } finally { root.fill(0); }
}
function encodeCode(value) {
  if (!HEX.test(value.wrappingKey) || !UUID.test(value.subject) || signingIdentity(value.wrappingKey).subject !== value.subject) throw Error('Invalid sync identity');
  const bytes = Buffer.concat([Buffer.from([2]), Buffer.from(value.subject.replaceAll('-',''), 'hex'), Buffer.from(value.wrappingKey,'hex')]);
  try { return 'ls2_' + bytes.toString('base64url'); } finally { bytes.fill(0); }
}
function decodeCode(code) {
  if (typeof code !== 'string' || !/^ls2_[A-Za-z0-9_-]{66}$/.test(code)) throw Error('Invalid sync code');
  const bytes = Buffer.from(code.slice(4), 'base64url');
  try {
    if (bytes.length !== 49 || bytes[0] !== 2 || bytes.toString('base64url') !== code.slice(4)) throw Error('Invalid sync code');
    const wrappingKey = bytes.subarray(17).toString('hex');
    const subject = subjectFor(Buffer.from(signingIdentity(wrappingKey).jwk.x, 'base64url'));
    if (bytes.subarray(1,17).toString('hex') !== subject.replaceAll('-','')) throw Error('Invalid sync identity');
    return { schema: SCHEMA, subject, serverUrl: ENDPOINT, wrappingKey };
  } finally { bytes.fill(0); }
}
function issueToken(value, now) {
  const identity = signingIdentity(value.wrappingKey);
  if (identity.subject !== value.subject || !Number.isSafeInteger(now) || now < 5) throw Error('Invalid sync identity');
  const header = Buffer.from(JSON.stringify({ alg:'EdDSA', typ:'JWT', jwk:identity.jwk })).toString('base64url');
  const claims = Buffer.from(JSON.stringify({ iss:ISSUER, aud:AUDIENCE, sub:identity.subject, name:'Selfhost owner',
    email:identity.subject+'@logseq.invalid', token_use:'owner', iat:now, nbf:now-5, exp:now+604800 })).toString('base64url');
  const body=header+'.'+claims;
  return body+'.'+crypto.sign(null,Buffer.from(body),identity.privateKey).toString('base64url');
}
function decodePart(part) {
  if (!/^[A-Za-z0-9_-]{1,8192}$/.test(part)) throw Error('Invalid token');
  const bytes=Buffer.from(part,'base64url');
  if (bytes.toString('base64url')!==part) throw Error('Invalid token');
  const object=JSON.parse(bytes.toString('utf8'));
  if (!object || typeof object!=='object' || Array.isArray(object)) throw Error('Invalid token');
  return object;
}
function verifyToken(token, reservedOwner, now = Math.floor(Date.now()/1000)) {
  try {
    if (typeof token!=='string' || token.length>16384) return null;
    const parts=token.split('.');
    if (parts.length!==3 || !/^[A-Za-z0-9_-]{86}$/.test(parts[2])) return null;
    const header=decodePart(parts[0]), claims=decodePart(parts[1]);
    if (header.alg!=='EdDSA' || header.typ!=='JWT' || Object.keys(header).sort().join(',')!=='alg,jwk,typ') return null;
    const jwk=header.jwk;
    if (!jwk || Object.keys(jwk).sort().join(',')!=='crv,kty,x' || jwk.kty!=='OKP' || jwk.crv!=='Ed25519' || !/^[A-Za-z0-9_-]{43}$/.test(jwk.x)) return null;
    const publicBytes=Buffer.from(jwk.x,'base64url');
    if (publicBytes.length!==32 || publicBytes.toString('base64url')!==jwk.x || claims.sub===reservedOwner || claims.sub!==subjectFor(publicBytes)) return null;
    if (Object.keys(claims).sort().join(',')!=='aud,email,exp,iat,iss,name,nbf,sub,token_use' ||
      (claims.iss!==ISSUER && claims.iss!==process.env.LOGSEQ_OWNER_ISSUER) || claims.aud!==AUDIENCE || claims.token_use!=='owner' || claims.email!==claims.sub+'@logseq.invalid' ||
      !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.nbf) || !Number.isSafeInteger(claims.exp) ||
      claims.iat<0 || claims.nbf<0 || claims.iat>now+30 || claims.nbf>now || claims.exp<=now || claims.exp<=claims.iat || claims.exp-claims.iat>604800) return null;
    const signature=Buffer.from(parts[2],'base64url');
    if (signature.length!==64 || signature.toString('base64url')!==parts[2]) return null;
    return crypto.verify(null,Buffer.from(parts[0]+'.'+parts[1]),crypto.createPublicKey({key:jwk,format:'jwk'}),signature) ? claims : null;
  } catch (_) { return null; }
}
module.exports={SCHEMA,createIdentity,encodeCode,decodeCode,issueToken,verifyToken,signingIdentity,subjectFor};
