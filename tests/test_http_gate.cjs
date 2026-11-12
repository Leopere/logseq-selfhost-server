'use strict';
// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const gate=require('../server/auth/http-gate.cjs'),grants=require('../server/auth/grants.cjs'),code=require('../server/auth/code-identity.cjs');
test('standalone origin gates exact protocol and revocation without exposing upstream APIs',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'logseq-gate-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));process.env.LOGSEQ_GRANTS_FILE=path.join(dir,'grants.json');t.after(()=>delete process.env.LOGSEQ_GRANTS_FILE);
 const identity=code.createIdentity(),token=code.issueToken(identity,Math.floor(Date.now()/1000));
 const req=(p,opts={})=>new Request('https://sync.example'+p,{headers:{Authorization:'Bearer '+token,...opts.headers},method:opts.method||'GET'});
 assert.equal(await gate.allowRequest(req('/health')),true);
 assert.equal(await gate.allowRequest(req('/graphs')),false);
 grants.addGrant(identity.subject,'test');assert.equal(await gate.allowRequest(req('/graphs')),true);
 const uuid='123e4567-e89b-42d3-a456-426614174000';
 const ws=p=>req(p,{headers:{Upgrade:'websocket'}});
 assert.equal(await gate.allowUpgrade(ws('/sync/'+uuid+'?token='+token)),true);
 for(const p of ['/api/a','/openapi.json','/graphs/'+uuid,'/graphs?admin=1','/grant-access','/sync/'+uuid+'/admin/reset'])assert.equal(await gate.allowRequest(req(p)),false,p);
 assert.equal(await gate.allowUpgrade(ws('/sync/'+uuid+'/pull?token='+token)),false);
 assert.equal(await gate.allowUpgrade(ws('/sync/'+uuid+'?token='+token+'&token='+token)),false);
 grants.revokeGrant(identity.subject);assert.equal(await gate.allowRequest(req('/graphs')),false);assert.equal(await gate.allowUpgrade(ws('/sync/'+uuid+'?token='+token)),false);
 for(const status of [401,403,404]){const r=gate.normalizeResponse(new Response('hint',{status}));assert.equal(r.status,404);assert.equal(await r.text(),'');assert.equal(r.headers.get('Content-Type'),null);}
});
