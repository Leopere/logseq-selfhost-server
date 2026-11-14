// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const code = require('../server/auth/code-identity.cjs');
const { createVerifier } = require('../server/auth/owner-auth.cjs');
const now = Math.floor(Date.now()/1000);
const legacyOwner = '00000000-0000-4000-8000-000000000001';
function resigned(token, edit) {
  const parts=token.split('.');
  const header=JSON.parse(Buffer.from(parts[0],'base64url')),claims=JSON.parse(Buffer.from(parts[1],'base64url'));
  const identity=edit(header,claims);
  const body=Buffer.from(JSON.stringify(header)).toString('base64url')+'.'+Buffer.from(JSON.stringify(claims)).toString('base64url');
  return body+'.'+crypto.sign(null,Buffer.from(body),identity.privateKey).toString('base64url');
}
test('a generated code recreates the same identity and a different device gets the same authentication key',()=>{
  const identity=code.createIdentity(),encoded=code.encodeCode(identity),restored=code.decodeCode(encoded);
  assert.deepEqual(restored,identity);
  assert.equal(code.issueToken(identity,now),code.issueToken(restored,now));
  assert.notEqual(code.createIdentity().subject,identity.subject);
  const token=code.issueToken(identity,now);
  assert.equal(code.verifyToken(token,legacyOwner,now).sub,identity.subject);
  assert.ok(!token.includes(identity.wrappingKey));
});
test('public-key identity cannot claim another owner or email, even with a valid signature',()=>{
  const a=code.createIdentity(),b=code.createIdentity(),signing=code.signingIdentity(a.wrappingKey),token=code.issueToken(a,now);
  assert.equal(code.verifyToken(token,a.subject,now),null);
  for(const edit of [
    (h,c)=>{c.sub=b.subject}, (h,c)=>{c.email=b.subject+'@logseq.invalid'},
    (h,c)=>{c['cognito:username']=legacyOwner}, (h)=>{h.jwk.d='private'},
    (h,c)=>{c.exp=c.iat+604801}, (h,c)=>{c.exp=now-1},
    (h)=>{h.alg='none'}, (h)=>{h.kid='external-key'},
  ])assert.equal(code.verifyToken(resigned(token,(h,c)=>{edit(h,c);return signing}),legacyOwner,now),null);
  assert.equal(code.verifyToken(token.slice(0,-1)+'!',legacyOwner,now),null);
});
test('changing the code identity independently from its secret is refused',()=>{
  const encoded=code.encodeCode(code.createIdentity()),bytes=Buffer.from(encoded.slice(4),'base64url');
  bytes[2]^=1;
  assert.throws(()=>code.decodeCode('ls2_'+bytes.toString('base64url')));
});
test('the existing single-owner HMAC identity remains valid and its scope stays fixed',()=>{
  const keyHex='11'.repeat(32),claims={iss:'https://logseq-sync.nixc.us',aud:'cisl2-logseq-owner',sub:legacyOwner,
    token_use:'owner',iat:now,nbf:now-5,exp:now+604800};
  const header=Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
  const payload=Buffer.from(JSON.stringify(claims)).toString('base64url');
  const body=header+'.'+payload;
  const token=body+'.'+crypto.createHmac('sha256',Buffer.from(keyHex,'hex')).update(body).digest('base64url');
  const verify=createVerifier({keyHex,issuer:claims.iss,audience:claims.aud,owner:legacyOwner,now:()=>now});
  assert.equal(verify(token).sub,legacyOwner);
  assert.equal(verify(code.issueToken(code.createIdentity(),now)),null);
});
test('first launch requires an explicit server; an explicit code override archives the prior identity',t=>{
  const home=fs.mkdtempSync(path.join(os.tmpdir(),'logseq-code-test-'));
  t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
  const bootstrap=path.resolve(__dirname,'../client/base/bootstrap.cjs');
  const script=`process.type='browser';const fs=require('fs'),path=require('path'),assert=require('assert/strict');
    const bootstrap=require(${JSON.stringify(bootstrap)}),code=require(${JSON.stringify(path.resolve(__dirname,'../server/auth/code-identity.cjs'))});
    assert.equal(bootstrap.initializeBootstrap(),null);assert.equal(fs.existsSync(bootstrap.DEFAULT_FILE),false);
    const initial=code.createIdentity();
    assert.throws(()=>bootstrap.importSyncCode(code.encodeCode(initial)));
    bootstrap.importSyncCode(code.encodeCode(initial),undefined,{serverUrl:bootstrap.ENDPOINT});
    const first=bootstrap.initializeBootstrap(),original=bootstrap.currentSyncCode();
    assert.equal(first.protocol,2);assert.equal(bootstrap.initializeBootstrap().subject,first.subject);
    assert.equal(bootstrap.currentSyncCode(),original);
    const second=code.createIdentity();assert.throws(()=>bootstrap.importSyncCode(code.encodeCode(second)));
    bootstrap.importSyncCode(code.encodeCode(second),undefined,{replace:true,serverUrl:bootstrap.ENDPOINT});
    assert.equal(bootstrap.readBootstrap().subject,second.subject);
    const archived=path.join(path.dirname(bootstrap.DEFAULT_FILE),'identities',first.subject,'owner.saved.json');
    assert.equal(JSON.parse(fs.readFileSync(archived)).wrappingKey,first.wrappingKey);
    assert.equal(fs.statSync(archived).mode&511,384);
    fs.writeFileSync(bootstrap.DEFAULT_FILE,'invalid',{mode:384});
    assert.throws(()=>bootstrap.initializeBootstrap());assert.equal(fs.readFileSync(bootstrap.DEFAULT_FILE,'utf8'),'invalid');`;
  cp.execFileSync(process.execPath,['-e',script],{env:{...process.env,HOME:home},stdio:'pipe',timeout:10000});
});
