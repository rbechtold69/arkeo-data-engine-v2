import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {JSDOM,VirtualConsole} from 'jsdom';
const html=fs.readFileSync(new URL('../docs/rpc-demo.html',import.meta.url),'utf8');
function open(t){const errors=[];const console=new VirtualConsole();console.on('jsdomError',e=>errors.push(e.message));const dom=new JSDOM(html,{runScripts:'dangerously',url:'https://demo.test/',virtualConsole:console});t.after(()=>dom.window.close());assert.deepEqual(errors,[]);return dom.window;}
test('recorded demonstration starts with explicit fixture disclosure and measured results',t=>{
 const w=open(t),d=w.document;
 assert.match(d.querySelector('#mode').textContent,/TEST PROVIDERS/);
 assert.match(d.querySelector('#limitations').textContent,/not provider performance/);
 assert.equal(d.querySelectorAll('#providers article').length,3);
 assert.equal(d.querySelectorAll('#results tr').length,6);
 assert.equal(d.querySelectorAll('.provider.active').length,1);
 assert.match(d.querySelector('.provider.active').textContent,/Liquify role/);
 assert.equal(d.querySelector('#failed').textContent,'3');
});
test('phase controls, replay scrubber and all-down state reflect the recording',t=>{
 const w=open(t),d=w.document;
 d.querySelector('[data-phase="all-out"]').click();
 assert.match(d.querySelector('#request-status').textContent,/Request failed/);
 assert.equal(d.querySelectorAll('.provider.blocked').length,3);
 assert.equal(d.querySelectorAll('.provider.active').length,0);
 d.querySelector('#all').click();assert.match(d.querySelector('.provider.active').textContent,/Liquify role/);
 const slider=d.querySelector('#scrub');slider.value='0';slider.dispatchEvent(new w.Event('input',{bubbles:true}));
 assert.match(d.querySelector('#progress').textContent,/request 1 of 28/);
 d.querySelector('#next').click();assert.match(d.querySelector('#progress').textContent,/request 2 of 28/);
 assert.ok(d.querySelectorAll('#chart circle').length>=2);
});
test('opening or replaying evidence never contacts providers or needs a wallet',t=>{
 let contacted=false;const dom=new JSDOM(html,{runScripts:'dangerously',beforeParse(w){w.fetch=()=>{contacted=true;throw Error('network forbidden');};}});t.after(()=>dom.window.close());
 dom.window.document.querySelector('#play').click();dom.window.document.querySelector('#play').click();assert.equal(contacted,false);
 assert.match(dom.window.document.querySelector('#metadata').textContent,/fixture runs have no payments/);
});
