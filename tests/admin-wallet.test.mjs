import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import protobuf from 'protobufjs';
import {createRequire} from 'node:module';
import {SwapMessage} from '../subscriber-core/admin/src/swap-codec.ts';
const requireAdmin=createRequire(new URL('../subscriber-core/admin/package.json',import.meta.url));
const {build}=requireAdmin('esbuild');

test('narrow swap codec matches the official protobuf wire schema including uint64 pool IDs',()=>{
 const schema=protobuf.parse(`syntax="proto3"; message Route { uint64 pool_id=1; string token_out_denom=2; } message Coin {string denom=1; string amount=2;} message Swap {string sender=1; repeated Route routes=2; Coin token_in=3; string token_out_min_amount=4;}`).root.lookupType('Swap');
 const input={sender:'osmo1test',routes:[{poolId:'18446744073709551615',tokenOutDenom:'ibc/TEST'}],tokenIn:{denom:'uosmo',amount:'9007199254740993'},tokenOutMinAmount:'500'};
 const bytes=SwapMessage.encode(input).finish();
 assert.deepEqual(bytes,schema.encode(schema.fromObject(input)).finish());
 assert.deepEqual(SwapMessage.decode(bytes),input);
 assert.throws(()=>SwapMessage.decode(Uint8Array.from([18,100,8,1])));
 assert.equal(fs.readFileSync(new URL('../provider-core/admin/src/swap-codec.ts',import.meta.url),'utf8'),fs.readFileSync(new URL('../subscriber-core/admin/src/swap-codec.ts',import.meta.url),'utf8'));
});

async function walletHarness(){
 const output=await build({entryPoints:[new URL('../subscriber-core/admin/src/keplr.ts',import.meta.url).pathname],bundle:true,write:false,format:'iife',globalName:'Wallet',platform:'browser',plugins:[{name:'wallet-fixtures',setup(builder){
 builder.onResolve({filter:/^@cosmjs\//},args=>({path:args.path,namespace:'fixture'}));
 builder.onLoad({filter:/.*/,namespace:'fixture'},args=>({contents:args.path.endsWith('stargate')?`export const GasPrice={fromString:x=>x}; export const calculateFee=()=>({}); export const defaultRegistryTypes=[]; export const SigningStargateClient={connectWithSigner:async(endpoint,signer)=>globalThis.makeClient(endpoint,signer)};`:`export class Registry {constructor(types){this.types=types;}}`,loader:'js'}));
 }}]});
 let address='osmo1first',network='osmosis-1';const broadcasts=[];
 const sandbox={console,Uint8Array,TextEncoder,TextDecoder,window:{keplr:{enable:async()=>{}},getOfflineSigner:()=>({getAccounts:async()=>[{address}]}),addEventListener:()=>{}},makeClient:async(endpoint,signer)=>{const bound=(await signer.getAccounts())[0].address;return{disconnect(){},getChainId:async()=>network,getBlock:async()=>({header:{time:new Date().toISOString(),height:100}}),sendIbcTokens:async(...args)=>{broadcasts.push({ibc:args});return{code:0,transactionHash:"test"};},signAndBroadcast:async(sender,msg)=>{broadcasts.push({bound,sender,msg});return{code:0,transactionHash:'test'};}};}};
 vm.runInNewContext(output.outputFiles[0].text,sandbox);
 return{wallet:sandbox.Wallet,broadcasts,setAddress:x=>address=x,setNetwork:x=>network=x};
}
test('admin signing refreshes wallet identity and rejects a mismatched RPC or sender',async()=>{
 const h=await walletHarness();const opts={rpcEndpoint:'https://rpc.example',tokenInDenom:'uosmo',tokenOutDenom:'ibc/TEST',amountInBase:'10',minOutBase:'1'};
 await h.wallet.connectKeplr(opts);h.setAddress('osmo1second');await h.wallet.signAndBroadcastSwap(opts);
 assert.equal(h.broadcasts[0].bound,'osmo1second');assert.equal(h.broadcasts[0].sender,'osmo1second');
 await assert.rejects(h.wallet.signAndBroadcastSwap({...opts,senderAddress:'osmo1first'}),/active wallet/);
 h.setNetwork('wrong-network');await assert.rejects(h.wallet.signAndBroadcastSwap(opts),/network/);assert.equal(h.broadcasts.length,1);
});
test('admin amounts reject rounding, negative values and zero minimum output',async()=>{
 const h=await walletHarness();const opts={rpcEndpoint:'https://rpc.example',tokenInDenom:'uosmo',tokenOutDenom:'ibc/TEST',amountInBase:'10',minOutBase:'1'};
 for(const value of [9007199254740993,'1.2','-1','0','NaN']) await assert.rejects(h.wallet.signAndBroadcastSwap({...opts,amountInBase:value}),/integer/);
 await assert.rejects(h.wallet.signAndBroadcastSwap({...opts,minOutBase:'0'}),/positive/);assert.equal(h.broadcasts.length,0);
});

test('IBC uses seconds and never mistakes source height for destination height',async()=>{
 const h=await walletHarness();const before=Math.floor(Date.now()/1000);
 await h.wallet.signAndBroadcastIbcTransfer({rpcEndpoint:'https://rpc.example',receiver:'arkeo1test',denom:'ibc/TEST',amountBase:'9007199254740993',sourceChannel:'channel-1',timeoutSeconds:600});
 const args=h.broadcasts[0].ibc;assert.equal(args[5],undefined);assert.ok(args[6]>=before+600&&args[6]<=before+602);assert.equal(args[2].amount,'9007199254740993');
});
