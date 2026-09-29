import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import C from '../docs/js/chain-client.js';
const bytes=new Uint8Array([1,2,3]), hash=createHash('sha256').update(bytes).digest('hex').toUpperCase();
const ok=data=>({ok:true,status:200,json:async()=>data});
function fixture(fetcher) {
 const data=new Map();let now=0;
 return {storage:{getItem:k=>data.get(k),setItem:(k,v)=>data.set(k,v),removeItem:k=>data.delete(k)},fetcher,clock:()=>now,sleep:async ms=>{now+=ms;},intervalMs:1,timeoutMs:3};
}
test('mempool acceptance is not success; only confirmed height and matching hash complete the operation',async()=>{
 let calls=0;const opts=fixture(async(url,init)=>{calls++;return ok({tx_response:{txhash:hash,code:0,height:init.method==='POST'?'0':'123'}});});
 const tx=await C.submit('https://chain.example',bytes,'open',opts);assert.equal(tx.height,'123');assert.equal(calls,2);assert.equal(C.pending('open',opts.storage),null);
});
test('pending submissions survive reload and resume without rebroadcast',async()=>{
 let posts=0,confirmed=false;
 const opts=fixture(async(url,init)=>{if(init.method==='POST')posts++;return ok({tx_response:{txhash:hash,code:0,height:confirmed?'123':'0'}});});
 await assert.rejects(C.submit('https://chain.example',bytes,'open',opts),C.TransactionPendingError);
 assert.equal(C.pending('open',opts.storage).hash,hash);confirmed=true;
 await C.submit('https://chain.example',bytes,'open',opts);assert.equal(posts,1);
});
test('ambiguous broadcast transport failure is reconciled by hash without another POST',async()=>{
 let posts=0;const opts=fixture(async(url,init)=>{if(init.method==='POST'){posts++;throw Error('timeout');}return ok({tx_response:{txhash:hash,code:0,height:'10'}});});
 assert.equal((await C.submit('https://chain.example',bytes,'open',opts)).height,'10');assert.equal(posts,1);
});
test('delivery rejection stops polling immediately and never reports successful creation',async()=>{
 let calls=0;const opts=fixture(async(url,init)=>{calls++;return ok({tx_response:{txhash:hash,code:init.method==='POST'?0:9,height:init.method==='POST'?'0':'12',raw_log:'custom failure text'}});});
 await assert.rejects(C.submit('https://chain.example',bytes,'open',opts),C.TransactionRejectedError);assert.equal(calls,2);assert.equal(C.pending('open',opts.storage),null);
});
test('journal failure prevents broadcast; mismatched confirmation remains pending',async()=>{
 const opts=fixture(async()=>ok({tx_response:{txhash:'F'.repeat(64),code:0,height:'12'}}));
 await assert.rejects(C.submit('https://chain.example',bytes,'open',{...opts,storage:{...opts.storage,setItem:()=>{throw Error('disk full');}},fetcher:()=>assert.fail('must not send')}),/disk full/);
 await assert.rejects(C.submit('https://chain.example',bytes,'open',opts),C.TransactionPendingError);
});
test('account numbers and contract IDs remain exact; missing accounts are not guessed',async()=>{
 const account=await C.account('https://chain.example','arkeo1fixture',{fetcher:async()=>ok({account:{base_account:{address:'arkeo1fixture',account_number:'9007199254740993',sequence:'9007199254740994'}}})});
 assert.equal(account.sequence,'9007199254740994');
 await assert.rejects(C.account('https://chain.example','arkeo1fixture',{fetcher:async()=>ok({})}),/Unable to verify/);
 assert.equal(C.contractId({events:[{type:'arkeo.arkeo.EventOpenContract',attributes:[{key:'contract_id',value:'"9007199254740993"'}]}]}),'9007199254740993');
 assert.throws(()=>C.contractId({events:[]}),/could not be verified/);
});

test('simultaneous submit attempts share one broadcast',async()=>{
 let posts=0;
 const opts=fixture(async(url,init)=>{if(init.method==='POST')posts++;return ok({tx_response:{txhash:hash,code:0,height:init.method==='POST'?'0':'22'}});});
 await Promise.all([C.submit('https://chain.example',bytes,'same-operation',opts),C.submit('https://chain.example',bytes,'same-operation',opts)]);
 assert.equal(posts,1);
});
