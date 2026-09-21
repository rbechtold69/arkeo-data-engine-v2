import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
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
