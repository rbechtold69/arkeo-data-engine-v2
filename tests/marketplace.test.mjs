import test from 'node:test';
import assert from 'node:assert/strict';
import M from '../docs/js/marketplace.js';
const response = body => ({ok:true, json:async()=>body});

test('discovery loads all pages and encodes opaque pagination keys', async () => {
  const calls=[];
  const fetcher=async url=>{calls.push(new URL(url)); return response(calls.length===1 ? {services:[{service_id:32,name:'thorchain-mainnet-fullnode'}],pagination:{next_key:'a+/='}} : {services:[{service_id:99,name:'maya-mainnet-rpc'}],pagination:{next_key:''}});};
  const rows=await M.collection('https://registry.example','services',['services'],{fetcher});
  assert.equal(rows.length,2);
  assert.equal(calls[1].searchParams.get('pagination.key'),'a+/=');
  assert.equal(M.resolveService(99,rows.map(M.normalizeService)).name,'maya-mainnet-rpc');
});

test('discovery fails closed on repeated cursors, invalid schema and incomplete results', async()=>{
  await assert.rejects(M.collection('https://registry.example','providers',['providers'],{fetcher:async()=>response({providers:[],pagination:{next_key:'same'}})}), /Repeated/);
  await assert.rejects(M.collection('https://registry.example','providers',['providers'],{fetcher:async()=>response({unexpected:[]})}), /Unexpected/);
  await assert.rejects(M.collection('https://registry.example','providers',['providers'],{maxPages:1,fetcher:async()=>response({providers:[],pagination:{next_key:'more'}})}), /Incomplete/);
});

test('scope is a configurable display policy and leaves unrelated networks out of the pilot',()=>{
  for (const s of ['thorchain-mainnet-fullnode','thorchain-mainnet-midgard','maya-mainnet-rpc','btc-mainnet-fullnode','eth-mainnet-archivenode']) assert.ok(M.inScope(s),s);
  for (const s of ['dash-mainnet-fullnode','eth-testnet-fullnode','uniswap','aave','thorchain-malicious-fullnode']) assert.equal(M.inScope(s),false,s);
  assert.equal(M.inScope('dash-mainnet-fullnode',{id:'all'}),true);
  assert.equal(M.inScope('custom-mainnet-rpc',{id:'new-project',services:['custom-mainnet-rpc']}),true);
});

test('preferred identity must match exactly and can be replaced for another project',()=>{
  const other={pubkey:'arkeopub1other',name:'Other'}, liquify={pubkey:M.LIQUIFY,name:'Liquify'};
  assert.equal([other,liquify].sort(M.providerOrder)[0],liquify);
  assert.equal([liquify,other].sort((a,b)=>M.providerOrder(a,b,{preferredProviders:[other.pubkey]}))[0],other);
  const spoof={pubkey:M.LIQUIFY+'x',name:'A lookalike'};
  assert.equal([spoof,liquify].sort(M.providerOrder)[0],liquify);
});

test('rates retain exact signing amounts and zero; incompatible denominations are not invented',()=>{
  assert.equal(M.paygRate({pay_as_you_go_rate:[{denom:'other',amount:'1'}]}),null);
  assert.equal(M.paygRate({pay_as_you_go_rate:[{denom:'uarkeo',amount:'0'}]}).amount,'0');
  assert.equal(M.paygRate({pay_as_you_go_rate:[{denom:'uarkeo',amount:'9007199254740993'}]}).amount,'9007199254740993');
  assert.equal(M.paygRate({pay_as_you_go_rate:[{denom:'uarkeo',amount:'1.1'}]}),null);
});

test('live preflight rejects mismatched provider identities and unavailable service names',async()=>{
  await assert.rejects(M.provider('https://registry.example','arkeopub1selected','thorchain-mainnet-rpc',{fetcher:async()=>response({provider:{pub_key:'arkeopub1other'}})}),/identity/);
  await assert.rejects(M.service('https://registry.example','missing-mainnet-rpc',{fetcher:async()=>response({services:[{service_id:32,name:'thorchain-mainnet-rpc'}]})}),/no longer/);
});

test('registry status accepts actual enum representations but is not an uptime check',()=>{
  for (const status of ['ONLINE',1,'1']) assert.equal(M.registered({status,bond:'100000000'}),true);
  for (const p of [{status:'OFFLINE',bond:'100000000'}, {status:'ONLINE',bond:'0'}, {status:'ONLINE',bond:'invalid'}]) assert.equal(M.registered(p),false);
});

test('deposit conversion is exact and rejects silent rounding or exponential notation',()=>{
  assert.equal(M.amountToUnits('0.29'),'29000000');
  assert.equal(M.amountToUnits('0.00000001'),'1');
  assert.equal(M.amountToUnits('9007199254740993.12345678'),'900719925474099312345678');
  for (const input of ['0.000000001','1e3','-1','NaN','1.2garbage']) assert.throws(()=>M.amountToUnits(input));
});
