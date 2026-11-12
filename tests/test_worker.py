# Copyright (c) 2026 Colin Knapp, https://colinknapp.com
# SPDX-License-Identifier: AGPL-3.0-only
"""Functional tests for the Cloudflare Worker WebSocket preflight."""
from pathlib import Path
import shutil
import subprocess
import unittest

WORKER = Path(__file__).resolve().parents[1] / 'worker.example.mjs'


class WorkerPreflightTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node unavailable')
    def test_authenticated_upgrade_and_http_binary_passthrough(self):
        code = r'''
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
const worker=(await import(pathToFileURL(process.argv[1]))).default;
const token='eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.'+'A'.repeat(43);
const graph='123e4567-e89b-42d3-a456-426614174000';
let seen=[];
const upgraded={status:101,webSocket:{accepted:true}};
const env={SYNC_ORIGIN:{fetch:async request=>{
  seen.push(request);
  if(request.url==='http://sync-origin.internal:8787/graphs')return new Response('{}',{status:200});
  return upgraded;
}}};
let original=new Request('https://edge.example/sync/'+graph+'?token='+encodeURIComponent(token),
  {headers:{Upgrade:'websocket','X-Fixture':'kept'}});
assert.equal(await worker.fetch(original,env),upgraded);
assert.equal(seen.length,2);
assert.equal(seen[0].url,'http://sync-origin.internal:8787/graphs');
assert.equal(seen[0].headers.get('Authorization'),'Bearer '+token);
assert.equal(seen[1].url,'http://sync-origin.internal:8787/sync/'+graph+'?token='+encodeURIComponent(token));
assert.equal(seen[1].headers.get('Upgrade'),'websocket');
assert.equal(seen[1].headers.get('X-Fixture'),'kept');

seen=[];
original=new Request('https://edge.example/graphs',{method:'POST',
  headers:{Authorization:'Bearer fixture','Content-Type':'application/octet-stream'},
  body:new Uint8Array([0,255,3,128])});
await worker.fetch(original,env);
assert.equal(seen.length,1);
assert.equal(seen[0].url,'http://sync-origin.internal:8787/graphs');
assert.equal(seen[0].headers.get('Authorization'),'Bearer fixture');
assert.deepEqual([...new Uint8Array(await seen[0].arrayBuffer())],[0,255,3,128]);
seen=[];
await worker.fetch(new Request('https://edge.example/assets/6412bac2-a7e4-4f3d-8a1a-2983cc4d3f0c/6412bac2-a7e4-4f3d-8a1a-2983cc4d3f0c.png',{headers:{Authorization:'Bearer fixture'}}),env);
assert.equal(seen.length,1);assert.equal(seen[0].headers.get('Authorization'),'Bearer fixture');
'''
        self.run_node(code)

    @unittest.skipUnless(shutil.which('node'), 'Node unavailable')
    def test_origin_rejects_forged_well_formed_token_before_websocket(self):
        code = r'''
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
const worker=(await import(pathToFileURL(process.argv[1]))).default;
const forged='eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciJ9.'+'B'.repeat(43);
let calls=[];
const env={SYNC_ORIGIN:{fetch:async request=>{calls.push(request);return new Response(null,{status:401})}}};
const request=new Request('https://edge.example/sync/123e4567-e89b-42d3-a456-426614174000?token='+encodeURIComponent(forged),
  {headers:{Upgrade:'websocket'}});
const response=await worker.fetch(request,env);
assert.equal(response.status,404);
assert.equal(calls.length,1);
assert.equal(calls[0].url,'http://sync-origin.internal:8787/graphs');
assert.equal(calls[0].headers.get('Authorization'),'Bearer '+forged);
'''
        self.run_node(code)

    @unittest.skipUnless(shutil.which('node'), 'Node unavailable')
    def test_missing_or_malformed_token_is_rejected_without_origin_access(self):
        code = r'''
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
const worker=(await import(pathToFileURL(process.argv[1]))).default;
let calls=0;
const env={SYNC_ORIGIN:{fetch:async()=>{calls++;return new Response('{}')}}};
for(const query of ['', '?token=bad', '?token=a.b.short',
                    '?token=a.b.short&token=c.d.'+'B'.repeat(43)]){
  const request=new Request('https://edge.example/sync/123e4567-e89b-42d3-a456-426614174000'+query,{headers:{Upgrade:'websocket'}});
  assert.equal((await worker.fetch(request,env)).status,404);
}
assert.equal(calls,0);
'''
        self.run_node(code)

    @unittest.skipUnless(shutil.which('node'), 'Node unavailable')
    def test_allowlist_routes_and_denies_without_origin_fallback(self):
        code = r'''
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
const worker=(await import(pathToFileURL(process.argv[1]))).default;
const graph='123e4567-e89b-42d3-a456-426614174000';
const asset='123e4567-e89b-42d3-a456-426614174001.png';
const now=Math.floor(Date.now()/1000);
let seen=[];
const env={SYNC_ORIGIN:{fetch:async request=>{seen.push(request);return new Response('ok')}}};
const good=[
  ['GET','/health'], ['GET','/graphs'], ['POST','/graphs'],
  ['GET','/e2ee/user-keys'], ['POST','/e2ee/user-keys'],
  ['GET',`/e2ee/graphs/${graph}/aes-key`], ['POST',`/e2ee/graphs/${graph}/aes-key`],
  ['GET',`/sync/${graph}/pull`], ['GET',`/sync/${graph}/snapshot/download`],
  ['GET',`/sync/${graph}/snapshot/stream`],
  ['POST',`/sync/${graph}/snapshot/upload?reset=true&finished=false&checksum=opaque`],
  ['POST',`/sync/${graph}/snapshot/upload?reset=false&finished=true`],
  ['PUT',`/assets/${graph}/${asset}`],
  ['GET',`/assets/${graph}/${asset}?expires=${now+120}&signature=${'a'.repeat(64)}`],
];
for(const [method,path] of good){
  const request=new Request('https://edge.example'+path,{method,body:['GET','HEAD'].includes(method)?undefined:'body'});
  assert.equal((await worker.fetch(request,env)).status,200,path);
}
assert.equal(seen.length,good.length);
seen=[];
const denied=[
  ['DELETE','/graphs',405], ['GET','/graphs?admin=1',400],
  ['GET','/members',404], ['POST','/invites',404], ['POST','/grant-access',404],
  ['GET','/api',404], ['GET','/openapi.json',404], ['GET','/docs',404],
  ['POST','/reset',404], ['GET','/sync/graph/pull',404],
  ['GET','/sync/not-a-uuid/pull',404], ['GET',`/sync/${graph}/pull?x=1`,400],
  ['POST',`/sync/${graph}/snapshot/upload?reset=true&finished=maybe`,400],
  ['POST',`/sync/${graph}/snapshot/upload?reset=true&finished=false&checksum=${'x'.repeat(4097)}`,400],
  ['GET',`/assets/${graph}/123e4567-e89b-42d3-a456-426614174001.png?expires=${now+600}&signature=${'a'.repeat(64)}`,400],
  ['GET',`/assets/${graph}/123e4567-e89b-42d3-a456-426614174001.png?expires=${now+60}&signature=bad`,400],
];
for(const [method,path,status] of denied){
  const request=new Request('https://edge.example'+path,{method,body:['GET','HEAD'].includes(method)?undefined:'x'});
  assert.equal((await worker.fetch(request,env)).status,status,path);
}
const invalidUpgrade=new Request('https://edge.example/members',{headers:{Upgrade:'websocket'}});
assert.equal((await worker.fetch(invalidUpgrade,env)).status,404);
assert.equal(seen.length,0);
'''
        self.run_node(code)

    @unittest.skipUnless(shutil.which('node'), 'Node unavailable')
    def test_browser_cors_is_limited_to_logseq_origin_and_allowlisted_routes(self):
        code = r'''
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
const worker=(await import(pathToFileURL(process.argv[1]))).default;
const graph='123e4567-e89b-42d3-a456-426614174000';
let seen=[];
const env={SYNC_ORIGIN:{fetch:async request=>{seen.push(request);return new Response('unexpected')}}};
async function options(path, origin='lsp://logseq.com', method='GET', headers='authorization'){
  return worker.fetch(new Request('https://edge.example'+path,{method:'OPTIONS',headers:{
    Origin:origin,'Access-Control-Request-Method':method,
    ...(headers ? {'Access-Control-Request-Headers':headers} : {})
  }}),env);
}
let response=await options('/graphs');
assert.equal(response.status,204);
assert.equal(response.headers.get('Access-Control-Allow-Origin'),'lsp://logseq.com');
assert.equal(response.headers.get('Access-Control-Allow-Methods'),'GET');
assert.equal(response.headers.get('Access-Control-Allow-Headers'),'authorization');
assert.equal(response.headers.get('Vary'),'Origin');
response=await options(`/assets/${graph}/123e4567-e89b-42d3-a456-426614174001.png`,'lsp://logseq.com','PUT','content-type');
assert.equal(response.status,204);
assert.equal(response.headers.get('Access-Control-Allow-Methods'),'PUT');
assert.equal(response.headers.get('Access-Control-Allow-Headers'),'content-type');
assert.equal((await options('/not-a-route')).status,404);
assert.equal((await options('/graphs','https://evil.example')).status,403);
assert.equal((await options('/graphs','lsp://logseq.com','DELETE','authorization')).status,405);
assert.equal((await options('/graphs','lsp://logseq.com','GET','x-custom')).status,400);
assert.equal(seen.length,0);

const binary=new Uint8Array([0,255,3,128]);
env.SYNC_ORIGIN.fetch=async()=>new Response(binary,{status:200,headers:{'Content-Type':'application/octet-stream','Vary':'Accept-Encoding'}});
response=await worker.fetch(new Request('https://edge.example/graphs',{headers:{Origin:'lsp://logseq.com'}}),env);
assert.equal(response.headers.get('Access-Control-Allow-Origin'),'lsp://logseq.com');
assert.equal(response.headers.get('Vary'),'Accept-Encoding, Origin');
assert.equal(response.headers.get('Content-Type'),'application/octet-stream');
assert.deepEqual([...new Uint8Array(await response.arrayBuffer())],[...binary]);

env.SYNC_ORIGIN.fetch=async()=>new Response('plain');
response=await worker.fetch(new Request('https://edge.example/graphs',{headers:{Origin:'https://evil.example'}}),env);
assert.equal(response.headers.get('Access-Control-Allow-Origin'),null);
'''
        self.run_node(code)

    def run_node(self, code):
        result = subprocess.run(['node', '--input-type=module', '-e', code, str(WORKER)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
