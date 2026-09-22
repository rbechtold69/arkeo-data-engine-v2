/* Confirmed transaction lifecycle shared by marketplace wallet flows. */
(function (root) {
  'use strict';
  const decimal = value => typeof value === 'string' && /^\d+$/.test(value) && BigInt(value) <= 18446744073709551615n;
  class TransactionPendingError extends Error {
    constructor(hash) { super('Transaction '+hash+' is submitted or may have been submitted. Check confirmation before trying again.'); this.name='TransactionPendingError'; this.txHash=hash; }
  }
  class TransactionRejectedError extends Error {
    constructor(hash, code) { super('Transaction '+hash+' was rejected with code '+code+'.'); this.name='TransactionRejectedError'; this.txHash=hash; this.code=code; }
  }
  const inFlight = new Map();
  function once(key, fn) {
    if (inFlight.has(key)) return inFlight.get(key);
    const task=Promise.resolve().then(fn).finally(()=>inFlight.delete(key));
    inFlight.set(key,task); return task;
  }
  async function request(url, {fetcher=root.fetch.bind(root), timeoutMs=6000, ...init}={}) {
    const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),timeoutMs);
    try { const response=await fetcher(url,{...init,signal:controller.signal,redirect:'error'}); return {ok:response.ok,status:response.status,data:await response.json()}; }
    finally { clearTimeout(timer); }
  }
  async function account(base, address, options={}) {
    if (!/^arkeo1[a-z0-9]+$/.test(address || '')) throw new Error('Invalid wallet address');
    const r=await request(base.replace(/\/$/,'')+'/cosmos/auth/v1beta1/accounts/'+address,options);
    const wrapper=r.data?.account;
    const a=wrapper?.base_account || wrapper?.base_vesting_account?.base_account || wrapper;
    if (!r.ok || !a || !decimal(a.account_number) || !decimal(a.sequence) || (a.address && a.address!==address)) throw new Error('Unable to verify wallet account and sequence. Retry before signing.');
    return {accountNumber:a.account_number,sequence:a.sequence};
  }
  const operationKey=(chain,address,operation)=>'arkeo-pending:'+chain+':'+address+':'+operation;
  function pending(key, storage=root.sessionStorage) {
    if (!key || !storage) throw new Error('Transaction recovery storage is required before signing.');
    const raw=storage.getItem(key);
    if (!raw) return null;
    let row; try { row=JSON.parse(raw); } catch { throw new Error('Transaction recovery record is invalid. Reconcile it before signing again.'); }
    if (!/^[A-F0-9]{64}$/.test(row.hash || '')) throw new Error('Transaction recovery hash is invalid. Reconcile it before signing again.');
    return row;
  }
  async function confirm(base, hash, {fetcher, timeoutMs=60000, intervalMs=1500, clock=Date.now, sleep=ms=>new Promise(r=>setTimeout(r,ms))}={}) {
    if (!/^[A-F0-9]{64}$/.test(hash || '')) throw new Error('Invalid transaction hash');
    const end=clock()+timeoutMs;
    while (clock()<end) {
      let r;
      try { r=await request(base.replace(/\/$/,'')+'/cosmos/tx/v1beta1/txs/'+hash,{fetcher,timeoutMs:Math.max(1,Math.min(6000,end-clock()))}); }
      catch { /* A read failure does not establish whether the transaction was committed. */ }
      const tx=r?.data?.tx_response;
      if (r?.ok && tx?.txhash?.toUpperCase()===hash && decimal(String(tx.height)) && BigInt(tx.height)>0n && /^\d+$/.test(String(tx.code))) {
        if (String(tx.code)!=='0') throw new TransactionRejectedError(hash,tx.code);
        return tx;
      }
      if (clock()<end) await sleep(Math.min(intervalMs,end-clock()));
    }
    throw new TransactionPendingError(hash);
  }
  async function resume(base, key, options={}) {
    const storage=options.storage || root.sessionStorage;
    const row=pending(key,storage); if (!row) return null;
    try { const tx=await confirm(base,row.hash,options); if(options.validateResult) options.validateResult(tx); if(!options.retainConfirmed) storage.removeItem(key); return tx; }
    catch(e) { if(e instanceof TransactionRejectedError) storage.removeItem(key); throw e; }
  }
  async function submitOnce(base, txBytes, key, options={}) {
    const storage=options.storage || root.sessionStorage;
    if (pending(key,storage)) return resume(base,key,options);
    const bytes=txBytes instanceof Uint8Array ? txBytes : Uint8Array.from(txBytes);
    if (!bytes.length) throw new Error('Cannot submit an empty transaction');
    const digest=await root.crypto.subtle.digest('SHA-256',bytes);
    const hash=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('').toUpperCase();
    // Persist before dispatch. Never automatically send a second transaction after an ambiguous result.
    storage.setItem(key,JSON.stringify({hash}));
    let r;
    try {
      const encoded=root.btoa(Array.from(bytes,b=>String.fromCharCode(b)).join(''));
      r=await request(base.replace(/\/$/,'')+'/cosmos/tx/v1beta1/txs',{fetcher:options.fetcher,method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tx_bytes:encoded,mode:'BROADCAST_MODE_SYNC'})});
    } catch { /* Reconcile the locally calculated hash, including after a network timeout. */ }
    const tx=r?.data?.tx_response;
    if (tx?.txhash?.toUpperCase()===hash && /^\d+$/.test(String(tx.code)) && String(tx.code)!=='0') {
      storage.removeItem(key); throw new TransactionRejectedError(hash,tx.code);
    }
    return resume(base,key,options);
  }
  async function signOnce({base,chainId,address,message,memo='via Arkeo Marketplace',helper=root.arkeoTx,wallet=root.keplr,key,options={}}) {
    if (!key) throw new Error('Transaction operation key is required');
    const resumed=await resume(base,key,options);
    if (resumed) return resumed;
    if (!wallet) throw new Error('Connect your wallet before signing');
    const info=await account(base,address,options);
    await helper.init();
    const accounts=await wallet.getOfflineSigner(chainId).getAccounts();
    const signer=accounts.find(a=>a.address===address);
    if (!signer?.pubkey) throw new Error('Connected wallet changed. Reconnect before signing.');
    const bodyBytes=helper.buildTxBody([message],memo);
    const authInfoBytes=helper.buildAuthInfo(signer.pubkey,info.sequence,'10000',300000);
    const signed=await wallet.signDirect(chainId,address,{bodyBytes,authInfoBytes,chainId,accountNumber:info.accountNumber});
    const bytes=helper.buildTxRaw(signed.signed.bodyBytes,signed.signed.authInfoBytes,[helper.base64ToBytes(signed.signature.signature)]);
    return submit(base,bytes,key,options);
  }
  function submit(base,bytes,key,options={}) { return once('submit:'+key,()=>submitOnce(base,bytes,key,options)); }
  function signAndSubmit(args) { return once('sign:'+args.key,()=>signOnce(args)); }
  function contractId(tx) {
    for (const event of tx?.events || []) {
      if (event.type!=='arkeo.arkeo.EventOpenContract') continue;
      const raw=event.attributes?.find(a=>a.key==='contract_id')?.value;
      const value=String(raw ?? '').replace(/^"|"$/g,'');
      if (decimal(value) && BigInt(value)>0n) return value;
    }
    throw new Error('Transaction confirmed, but its contract ID could not be verified. Check My Contracts before opening another.');
  }
  const api={account,operationKey,pending,confirm,resume,submit,signAndSubmit,contractId,TransactionPendingError,TransactionRejectedError};
  root.ChainClient=Object.freeze(api);
  if(typeof module!=='undefined' && module.exports) module.exports=api;
})(typeof globalThis!=='undefined'?globalThis:this);
