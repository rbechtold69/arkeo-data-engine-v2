import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

test('polling probes each selected provider without modifying live routing or provider priority',async()=>{
  const source=fs.readFileSync(new URL('../subscriber-core/admin/index.html',import.meta.url),'utf8');
  const start=source.indexOf('    async function pollListener(id)');
  const end=source.indexOf('    async function refreshTopServices',start);
  const calls=[];
  const listener={id:'pilot',port:3637,service_id:'32',top_services:[{provider_pubkey:'liquify'},{provider_pubkey:'backup'}]};
  const context=vm.createContext({
    listenersCache:[listener],openListenerId:null,document:{getElementById:()=>null},
    dedupTopServices:x=>x,formatServiceLabel:x=>x,escapeHtml:String,
    showResultModal:()=>{},updateModalBodyHtml:()=>{},loadListeners:async()=>{},
    apiUrl:x=>x,isTestOk:()=>true,setTimeout:fn=>fn(),
    fetch:async (url,opts)=>{calls.push({url,opts});const p=new URL(url,'https://admin.example').searchParams.get('provider_pubkey');return {ok:true,json:async()=>({used_provider_pubkey:p,arkeo_contract_id:'1',last_timings:{total_ms:10}})};},
  });
  new vm.Script(source.slice(start,end)).runInContext(context);
  await context.pollListener('pilot');
  assert.equal(calls.filter(c=>c.opts.method==='PUT').length,0,'health polling must not change listener configuration');
  const tests=calls.filter(c=>c.url.includes('/test?'));
  assert.equal(tests.length,6);
  assert.ok(tests.slice(0,3).every(c=>c.url.includes('provider_pubkey=liquify')));
  assert.ok(tests.slice(3).every(c=>c.url.includes('provider_pubkey=backup')));
  assert.deepEqual(listener.top_services.map(p=>p.provider_pubkey),['liquify','backup']);
});
