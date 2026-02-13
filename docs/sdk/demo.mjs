import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hmac } from '@noble/hashes/hmac';

if (secp.etc && secp.etc.hmacSha256Sync === undefined) {
  secp.etc.hmacSha256Sync = (key, ...msgs) => hmac(sha256, key, secp.etc.concatBytes(...msgs));
}

const CONTRACT_ID = process.argv[2] || '942';
const PRIVATE_KEY = process.argv[3] || '';
const SENTINEL = 'https://red5-arkeo.duckdns.org';
const SERVICE = 'arkeo-mainnet-fullnode';

if (!PRIVATE_KEY) { console.log('Usage: node demo.mjs <contract_id> <private_key_hex>'); process.exit(1); }

function hexToBytes(hex) { const b = new Uint8Array(hex.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16); return b; }
function bytesToHex(bytes) { return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''); }

function bech32Encode(prefix, data) {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  function polymod(values) { let chk = 1; for (const v of values) { const top = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v; for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i]; } return chk; }
  const hrpExp = []; for (let i = 0; i < prefix.length; i++) hrpExp.push(prefix.charCodeAt(i) >> 5); hrpExp.push(0); for (let i = 0; i < prefix.length; i++) hrpExp.push(prefix.charCodeAt(i) & 31);
  const words = []; let acc = 0, bits = 0; for (const b of data) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; words.push((acc >> bits) & 31); } } if (bits > 0) words.push((acc << (5 - bits)) & 31);
  const values = hrpExp.concat(words).concat([0,0,0,0,0,0]); const mod = polymod(values) ^ 1; const cs = []; for (let i = 0; i < 6; i++) cs.push((mod >> (5*(5-i))) & 31);
  return prefix + '1' + words.concat(cs).map(v => CHARSET[v]).join('');
}

let nonce = 0;

// Derive keys
const privKeyBytes = hexToBytes(PRIVATE_KEY);
const pubKeyBytes = secp.getPublicKey(privKeyBytes, true);
const amino = new Uint8Array(38);
amino[0]=0xeb;amino[1]=0x5a;amino[2]=0xe9;amino[3]=0x87;amino[4]=0x21;
amino.set(pubKeyBytes, 5);
const pubKeyBech32 = bech32Encode('arkeopub', amino);
const addr = bech32Encode('arkeo', ripemd160(sha256(pubKeyBytes)));

async function signedQuery(path) {
  nonce++;
  const preimage = CONTRACT_ID + ':' + pubKeyBech32 + ':' + nonce;
  const signDoc = JSON.stringify({account_number:"0",chain_id:"",fee:{amount:[],gas:"0"},memo:"",msgs:[{type:"sign/MsgSignData",value:{data:Buffer.from(preimage).toString('base64'),signer:addr}}],sequence:"0"});
  const msgHash = sha256(new TextEncoder().encode(signDoc));
  const sig = secp.sign(msgHash, privKeyBytes);
  let sigBytes = sig.toCompactRawBytes();
  
  // Normalize high-S
  const N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
  const s = BigInt('0x' + bytesToHex(sigBytes.slice(32)));
  if (s > N / 2n) {
    const newS = N - s;
    const newSHex = newS.toString(16).padStart(64, '0');
    const newSBytes = hexToBytes(newSHex);
    const normalized = new Uint8Array(64);
    normalized.set(sigBytes.slice(0, 32));
    normalized.set(newSBytes, 32);
    sigBytes = normalized;
  }
  
  const sigBase64 = Buffer.from(sigBytes).toString('base64');
  const pubBase64 = Buffer.from(pubKeyBytes).toString('base64');
  const arkauth = `${pubBase64}:${sigBase64}:${preimage}:${nonce}`;
  
  const url = `${SENTINEL}/${SERVICE}${path}`;
  const resp = await fetch(url, { headers: { 'X-Arkauth': arkauth } });
  return { status: resp.status, data: await resp.json() };
}

console.log('');
console.log('╔══════════════════════════════════════════════╗');
console.log('║     🚀 ARKEO MARKETPLACE — LIVE DEMO 🚀      ║');
console.log('║   Decentralized RPC Data, Paid Per Query     ║');
console.log('╚══════════════════════════════════════════════╝');
console.log('');
console.log(`Contract: #${CONTRACT_ID}`);
console.log(`Provider: Red_5 (${SENTINEL})`);
console.log(`Signing Key: ${addr}`);
console.log('');

// Demo 1: Latest block
console.log('━━━ 📦 QUERY 1: Latest Block ━━━');
const block = await signedQuery('/cosmos/base/tendermint/v1beta1/blocks/latest');
if (block.status === 200) {
  const h = block.data.block?.header;
  console.log(`  Height: ${h?.height}`);
  console.log(`  Time: ${h?.time}`);
  console.log(`  Proposer: ${h?.proposer_address?.slice(0,16)}...`);
  console.log(`  Txs in block: ${block.data.block?.data?.txs?.length || 0}`);
}
console.log('');

// Demo 2: Check a wallet balance
console.log('━━━ 💰 QUERY 2: Wallet Balance ━━━');
const wallet = 'arkeo1a7c5dwq7etnhe38r32kqmvlntk9y27cdgnfvxq';
const bal = await signedQuery(`/cosmos/bank/v1beta1/balances/${wallet}`);
if (bal.status === 200) {
  const balances = bal.data.balances || [];
  const arkeo = balances.find(b => b.denom === 'uarkeo');
  console.log(`  Wallet: ${wallet.slice(0,15)}...${wallet.slice(-6)}`);
  console.log(`  Balance: ${arkeo ? (parseInt(arkeo.amount)/1e8).toFixed(2) : '0'} ARKEO`);
}
console.log('');

// Demo 3: Staking info
console.log('━━━ 🥩 QUERY 3: Staking Delegations ━━━');
const del = await signedQuery(`/cosmos/staking/v1beta1/delegations/${wallet}`);
if (del.status === 200) {
  const delegations = del.data.delegation_responses || [];
  let totalStaked = 0;
  for (const d of delegations.slice(0, 5)) {
    const amount = parseInt(d.balance?.amount || 0) / 1e8;
    totalStaked += amount;
    const validator = d.delegation?.validator_address?.slice(0, 20) + '...';
    console.log(`  → ${amount.toFixed(2)} ARKEO staked with ${validator}`);
  }
  if (delegations.length > 5) console.log(`  ... and ${delegations.length - 5} more`);
  console.log(`  Total Staked: ${totalStaked.toFixed(2)} ARKEO`);
}
console.log('');

// Demo 4: Active providers on marketplace
console.log('━━━ 🏪 QUERY 4: Active Providers ━━━');
const prov = await signedQuery('/arkeo/providers');
if (prov.status === 200) {
  const providers = prov.data.provider || prov.data.providers || [];
  const online = providers.filter(p => p.status === 'ONLINE');
  console.log(`  Total Providers: ${providers.length}`);
  console.log(`  Online: ${online.length}`);
  for (const p of online.slice(0, 5)) {
    const rate = parseInt(p.pay_as_you_go_rate?.[0]?.amount || 0);
    const bond = parseInt(p.bond || 0) / 1e8;
    console.log(`  → ${p.pub_key?.slice(0,25)}... | Rate: ${rate} uarkeo/req | Bond: ${bond} ARKEO`);
  }
}
console.log('');

// Demo 5: Active contracts
console.log('━━━ 📋 QUERY 5: Network Contracts ━━━');
const contracts = await signedQuery('/arkeo/contracts?pagination.limit=10&pagination.reverse=true');
if (contracts.status === 200) {
  const list = contracts.data.contract || contracts.data.contracts || [];
  let active = 0;
  for (const c of list) {
    if (parseInt(c.deposit || 0) > 0) active++;
  }
  console.log(`  Recent contracts shown: ${list.length}`);
  console.log(`  With active deposits: ${active}`);
}
console.log('');

// Demo 6: Governance params
console.log('━━━ ⚖️ QUERY 6: Network Parameters ━━━');
const params = await signedQuery('/cosmos/staking/v1beta1/params');
if (params.status === 200) {
  const p = params.data.params;
  console.log(`  Max Validators: ${p?.max_validators}`);
  console.log(`  Unbonding Time: ${parseInt(p?.unbonding_time || 0) / 86400}s`);
  console.log(`  Bond Denom: ${p?.bond_denom}`);
}

console.log('');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log(`✅ ${nonce} paid queries completed — all auto-signed`);
console.log(`💸 Cost: ${nonce * 25000} uarkeo (${(nonce * 25000 / 1e8).toFixed(4)} ARKEO)`);
console.log(`🔑 No manual signing — SDK handles everything`);
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('');
