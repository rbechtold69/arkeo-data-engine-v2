import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import protobuf from 'protobufjs';
import Long from 'long';
const sandbox={window:{Long:{fromString:(value,unsigned)=>({value,unsigned})}},console,URL};
vm.runInNewContext(fs.readFileSync(new URL('../docs/js/arkeo-tx.js',import.meta.url),'utf8'),sandbox);
const tx=sandbox.window.arkeoTx;
test('browser transaction IDs and nonces retain all decimal digits',()=>{
 assert.equal(tx.integer('9007199254740993',undefined,true).value,'9007199254740993');
 for(const value of [9007199254740993,'1abc','-1','1.2','9223372036854775808'])assert.throws(()=>tx.integer(value,undefined));
 assert.equal(tx.integer('18446744073709551615',undefined,true).value,'18446744073709551615');
});
test('zero-valued contract and provider enums are preserved',()=>{
 assert.equal(tx.enumValue(0,1,[0,1]),0);assert.equal(tx.enumValue(undefined,1,[0,1]),1);
 assert.throws(()=>tx.enumValue('1garbage',1,[0,1]));
});
test('script allowlist rejects lookalike hosts and unpinned scripts',async()=>{
 await assert.rejects(tx.loadScript('https://cdn.jsdelivr.net.evil.example/steal.js'),/not allowed/);
 await assert.rejects(tx.loadScript('https://cdn.jsdelivr.net/npm/unknown.js'),/not allowed/);
});

async function realEncoder(){
 const context={window:{Long,protobuf},protobuf,console:{log(){}},URL,TextEncoder,Uint8Array,atob,btoa};
 vm.runInNewContext(fs.readFileSync(new URL('../docs/js/arkeo-tx.js',import.meta.url),'utf8'),context);
 await context.window.arkeoTx.init();return context.window.arkeoTx;
}
test('real protobuf close/claim messages and auth sequence retain uint64 precision',async()=>{
 const helper=await realEncoder();
 const body=helper.TxBody.decode(helper.buildTxBody([{typeUrl:'/arkeo.arkeo.MsgCloseContract',value:{creator:'arkeo1test',contractId:'9007199254740993',client:'client',delegate:'delegate'}}]));
 assert.equal(body.messages[0].typeUrl,'/arkeo.arkeo.MsgCloseContract');
 const close=helper.MsgCloseContract.decode(body.messages[0].value);assert.equal(close.contractId.toString(),'9007199254740993');assert.equal(close.client,'client');
 const claim=helper.MsgClaimContractIncome.decode(helper.encodeClaimContractIncome({creator:'arkeo1test',contractId:'9007199254740993',nonce:'9007199254740995',signature:new Uint8Array(64).fill(1)}));
 assert.equal(claim.nonce.toString(),'9007199254740995');assert.equal(claim.signature.length,64);
 const auth=helper.AuthInfo.decode(helper.buildAuthInfo(new Uint8Array(33).fill(2),'9007199254740997','10000',300000));
 assert.equal(auth.signerInfos[0].sequence.toString(),'9007199254740997');
 assert.throws(()=>helper.buildTxBody([{typeUrl:'/unknown',value:{}}]),/Unsupported/);
});
