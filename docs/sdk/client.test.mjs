import test from 'node:test';
import assert from 'node:assert/strict';
import { ArkeoClient } from './arkeo-client.js';
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
const mnemonic='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const make=(extra={})=>new ArkeoClient({sentinelUrl:'https://sentinel.example',contractId:42,privateKey:mnemonic,service:'test',startNonce:1,...extra});

test('Cosmos HD derivation matches reference public key and address',()=>{
 const c=make();
 assert.equal(c.getInfo().publicKey,'024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62');
 assert.equal(c.address,'arkeo19rl4cm2hmr8afy4kldpxz3fka4jguq0alqcczs');
});
test('signature verifies against chain raw PAYG preimage',async()=>{
 const c=make();const auth=await c.generateArkAuth();
 const sig=auth.split(':')[3];
 assert.ok(secp.verify(sig,sha256(new TextEncoder().encode('42:1:')),c.publicKey));
});
test('concurrent calls allocate different nonces; HTTP failure does not reuse one',async(t)=>{
 const seen=[];
 t.mock.method(globalThis,'fetch',async(url,o)=>{seen.push(o.headers.get('arkauth').split(':')[2]);await new Promise(r=>setTimeout(r,5));return new Response('{}',{status:seen.length===1?503:200});});
 const c=make(); await Promise.all([c.rpc('/status'),c.rpc('/status'),c.rpc('/status')]);
 assert.deepEqual(seen,['1','2','3']); assert.equal(c.getNonce(),4);
});
test('network timeout consumes nonce and does not poison the request queue',async(t)=>{
 let calls=0;const seen=[];
 t.mock.method(globalThis,'fetch',async(u,o)=>{seen.push(o.headers.get('arkauth').split(':')[2]);if(++calls===1)throw Error('timeout');return new Response('{}');});
 const c=make();await assert.rejects(c.rpc('/status'));await c.rpc('/status');assert.deepEqual(seen,['1','2']);
});
test('persist failure stops request before network',async(t)=>{
 let calls=0;t.mock.method(globalThis,'fetch',async()=>{calls++;return new Response('{}');});
 await assert.rejects(make({saveNonce:async()=>{throw Error('disk full')}}).rpc('/status'));assert.equal(calls,0);
});
test('nonce discovery fails closed rather than guessing',async(t)=>{
 t.mock.method(globalThis,'fetch',async()=>new Response('{}',{status:503}));
 await assert.rejects(make({startNonce:undefined}).rpc('/status'),/Cannot safely initialize/);
});
test('nonce discovery uses greater of chain and unclaimed sentinel nonce',async(t)=>{
 let nonce;
 t.mock.method(globalThis,'fetch',async(u,o)=>{
  if(String(u).includes('/arkeo/contract/')) return Response.json({contract:{nonce:'4'}});
  if(String(u).includes('/claims')) return Response.json({highestNonce:9});
  nonce=o.headers.get('arkauth').split(':')[2];return Response.json({});
 });
 await make({startNonce:undefined}).rpc('/status');assert.equal(nonce,'10');
});
test('credentials stay in header, query preserved and redirects rejected',async(t)=>{
 t.mock.method(globalThis,'fetch',async(u,o)=>{assert.equal(u.searchParams.get('height'),'12');assert.equal(u.searchParams.has('arkauth'),false);assert.notEqual(o.headers.get('arkauth'),'attacker');assert.equal(o.redirect,'error');return new Response('{}');});
 await make().rpc('/status?height=12&arkauth=attacker',{headers:{arkauth:'attacker'}});
});
test('invalid keys and backwards nonces rejected',()=>{
 assert.throws(()=>make({privateKey:'gg'.repeat(32)}));
 assert.throws(()=>make({privateKey:'bad mnemonic'}));
 const c=make({startNonce:4});assert.throws(()=>c.setNonce(3));assert.throws(()=>c.setNonce(-1));
});
