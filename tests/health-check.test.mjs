import test from 'node:test';
import assert from 'node:assert/strict';
import {onRequest} from '../docs/functions/health-check.js';
const call=(url,env={})=>onRequest({request:new Request('https://market.example/health-check?url='+encodeURIComponent(url)),env});
test('no configuration fails closed',async()=>assert.equal((await call('http://127.0.0.1/')).status,503));
test('unlisted, prefix-spoofed and credential URLs denied before fetch',async(t)=>{
 let fetched=false;t.mock.method(globalThis,'fetch',async()=>{fetched=true;throw Error()});
 const env={HEALTH_CHECK_ALLOWED_URLS:'https://provider.example/metadata.json'};
 for(const url of ['http://169.254.169.254/','https://provider.example.attacker.example/metadata.json','https://provider.example/private']) assert.equal((await call(url,env)).status,403);
 assert.equal((await call('https://user:pass@provider.example/metadata.json',env)).status,400);assert.equal(fetched,false);
});
test('allowed metadata fetched with redirects disabled',async(t)=>{
 t.mock.method(globalThis,'fetch',async(u,o)=>{assert.equal(o.redirect,'error');return Response.json({name:'test'});});
 const r=await call('https://provider.example/metadata.json',{HEALTH_CHECK_ALLOWED_URLS:'https://provider.example/metadata.json'});
 assert.equal((await r.json()).ok,true);
});
test('oversized metadata rejected',async(t)=>{
 t.mock.method(globalThis,'fetch',async()=>Response.json({text:'x'.repeat(70000)}));
 const r=await call('https://provider.example/metadata.json',{HEALTH_CHECK_ALLOWED_URLS:'https://provider.example/metadata.json'});
 assert.equal((await r.json()).error,'metadata_too_large');
});
