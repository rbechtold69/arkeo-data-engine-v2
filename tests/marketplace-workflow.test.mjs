import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import jsdom from 'jsdom';
const { JSDOM, requestInterceptor, VirtualConsole } = jsdom;
import M from '../docs/js/marketplace.js';
const docs = path.resolve(import.meta.dirname,'../docs');
const services = [
  {service_id:'32',name:'thorchain-mainnet-fullnode'},
  {service_id:'33',name:'maya-mainnet-rpc'},
  {service_id:'34',name:'eth-mainnet-archivenode'},
  {service_id:'35',name:'dash-mainnet-fullnode'},
];
const makeProvider=(service,pub_key,extra={})=>({service,pub_key,status:'ONLINE',bond:'100000000',metadata_uri:'',pay_as_you_go_rate:[{denom:'uarkeo',amount:'1'}],settlement_duration:'10',min_contract_duration:'10',max_contract_duration:'5256000',...extra});
const providers = [makeProvider('32','arkeopub1independent'),makeProvider('32',M.LIQUIFY),makeProvider('33','arkeopub1independent'),makeProvider('34','arkeopub1archive'),makeProvider('35','arkeopub1dash'),makeProvider('33','arkeopub1offline',{status:'OFFLINE'})];
const localResources = {interceptors:[requestInterceptor(request=>{
  const u=new URL(request.url);
  const file=path.join(docs,u.pathname);
  const body=u.origin==='https://marketplace.test' && fs.existsSync(file) ? fs.readFileSync(file) : '';
  return new Response(body,{headers:{'Content-Type':u.pathname.endsWith('.css')?'text/css':'application/javascript'}});
})]};
async function page(t,filename,{fail=false,search=''}={}) {
  const errors=[], calls=[];
  const console = new VirtualConsole(); console.on('jsdomError', e => {if(e.type==='unhandled-exception') errors.push(e.message);});
  const dom = new JSDOM(fs.readFileSync(path.join(docs,filename),'utf8'),{
    url:'https://marketplace.test/'+filename+search,runScripts:'dangerously',resources:localResources,virtualConsole:console,
    beforeParse(w) {
      w.AbortController=AbortController;w.AbortSignal=AbortSignal;w.TextEncoder=TextEncoder;w.TextDecoder=TextDecoder;w.alert=()=>{};
      w.fetch=async input=>{
        const u=new URL(input);calls.push(u.pathname);
        if (u.pathname==='/arkeo/services' || u.pathname==='/arkeo/providers') {
          if(fail) throw new Error('registry unavailable');
          const rows=u.pathname.endsWith('services')?services:providers;
          const key=u.searchParams.get('pagination.key');
          const field=u.pathname.endsWith('services')?'services':'provider';
          return {ok:true,json:async()=>({[field]:key?rows.slice(2):rows.slice(0,2),pagination:{next_key:key?'':'page+/='}})};
        }
        return {ok:false,status:503,json:async()=>({})};
      };
    },
  });
  t.after(()=>dom.window.close());
  await new Promise(resolve=>dom.window.addEventListener('load',resolve,{once:true}));
  for(let i=0;i<40;i++) {
    const body=[...dom.window.document.querySelectorAll('#loadingChains,#chainGrid,#providerTableBody')].map(e=>e.textContent).join(' ');
    if(fail && /Cannot load the current service registry|Failed to load providers|Unable to load the registry/.test(body)) break;
    if(!fail && (dom.window.document.querySelector('[data-service-id]') || /Registered online/.test(dom.window.document.querySelector('#providerTableBody')?.textContent||''))) break;
    await new Promise(resolve=>setTimeout(resolve,10));
  }
  assert.deepEqual(errors,[],'No uncaught page JavaScript errors');
  return {w:dom.window,d:dom.window.document,calls};
}
const change=(w,el,value)=>{el.value=value;el.dispatchEvent(new w.Event('change',{bubbles:true}));};

test('provider directory paginates, filters service type/status and opens the full registry without refetching',async t=>{
  const {w,d,calls}=await page(t,'data.html');
  const rows=()=>d.querySelector('#providerTableBody').textContent;
  assert.match(rows(),/Liquify/);assert.doesNotMatch(rows(),/DASH/);
  assert.equal(d.querySelector('#statServices').textContent,'3');
  change(w,d.querySelector('#dataTypeFilter'),'archivenode');
  assert.equal(d.querySelector('#statServices').textContent,'1');assert.match(rows(),/Ethereum/);assert.doesNotMatch(rows(),/Liquify/);
  change(w,d.querySelector('#dataTypeFilter'),'');
  change(w,d.querySelector('#statusFilter'),'offline');assert.match(rows(),/Registered offline/);assert.doesNotMatch(rows(),/Liquify/);
  change(w,d.querySelector('#statusFilter'),'');
  const count=calls.length;
  change(w,d.querySelector('[aria-label="Service scope"]'),'all');assert.match(rows(),/DASH/);assert.equal(calls.length,count);
  assert.ok(!calls.some(s=>s.includes('/contracts')));
});

test('consumer sees Liquify first but can select an independent provider at its exact rate',async t=>{
  const {w,d}=await page(t,'subscribe.html');
  assert.equal(d.querySelectorAll('[data-service-id]').length,3);
  d.querySelector('[data-service-id="32"]').click();
  d.querySelector('#nextBtn1').click();
  const cards=[...d.querySelectorAll('[data-pubkey]')];
  assert.equal(cards.length,2);assert.equal(cards[0].dataset.pubkey,M.LIQUIFY);
  assert.match(cards[0].textContent,/0\.00000001 ARKEO/);
  cards[1].click();assert.ok(cards[1].classList.contains('selected'));
  assert.equal(d.querySelector('#nextBtn2').disabled,false);
  assert.doesNotMatch(cards[1].textContent,/99\.9|requests served/);
});

test('provider signup selects real service IDs; full registry is opt-in',async t=>{
  const {w,d}=await page(t,'become-provider.html');
  assert.equal(d.querySelectorAll('[data-service-id]').length,3);
  assert.equal(d.querySelector('[data-service-id="35"]'),null);
  d.querySelector('[data-service-id="33"]').click();assert.equal(d.querySelector('#nextBtn1').disabled,false);
  change(w,d.querySelector('[aria-label="Service scope"]'),'all');
  assert.ok(d.querySelector('[data-service-id="35"]'));
});

test('provider signup cannot advance with invented service IDs when discovery fails',async t=>{
  const {d}=await page(t,'become-provider.html',{fail:true});
  assert.equal(d.querySelectorAll('[data-service-id]').length,0);
  assert.equal(d.querySelector('#nextBtn1').disabled,true);
  assert.match(d.querySelector('#loadingChains').textContent,/No service IDs have been assumed/);
});

test('consumer discovery failure offers retry without a fake provider list',async t=>{
  const {d}=await page(t,'subscribe.html',{fail:true});
  assert.equal(d.querySelectorAll('[data-service-id]').length,0);
  assert.match(d.querySelector('#chainGrid').textContent,/Retry/);
});

test('provider details use complete registry data and do not present registration as uptime',async t=>{
  const {d,calls}=await page(t,'provider.html',{search:'?address='+M.LIQUIFY});
  assert.match(d.querySelector('#content').textContent,/Liquify/);
  assert.match(d.querySelector('#content').textContent,/THORChain|Thorchain/i);
  assert.match(d.querySelector('#content').textContent,/Live availability/);
  assert.match(d.querySelector('#content').textContent,/Not measured/);
  assert.ok(!calls.some(p=>p.includes('/contracts')));
});

test('a single-provider contract wizard does not promise that backup contracts or routing are active',async t=>{
  const {d}=await page(t,'subscribe.html');
  assert.equal(d.querySelector('#enableFailover'),null);
  assert.match(d.querySelector('#failoverStatus').textContent,/Requires subscriber setup/);
  assert.match(d.querySelector('#failoverInfo').textContent,/does not configure routing or fund backup/);
});
