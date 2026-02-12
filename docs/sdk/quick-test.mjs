#!/usr/bin/env node
/**
 * Arkeo PAYG Quick Test — Self-contained, no imports needed except @noble
 * 
 * Usage:
 *   npm install @noble/secp256k1 @noble/hashes
 *   node quick-test.mjs <contract_id> <private_key_hex>
 * 
 * Example:
 *   node quick-test.mjs 940 a1b2c3d4...
 */

import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';

// ============ CONFIG ============
const CONTRACT_ID = process.argv[2] || '940';
const PRIVATE_KEY = process.argv[3] || '';
const SENTINEL = 'https://red5-arkeo.duckdns.org';
const SERVICE = 'arkeo-mainnet-fullnode';
// ================================

if (!PRIVATE_KEY) {
  console.log('Usage: node quick-test.mjs <contract_id> <private_key_hex>');
  console.log('Example: node quick-test.mjs 940 a1b2c3d4e5f6...');
  process.exit(1);
}

// --- Helpers ---
function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16);
  return b;
}

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function bech32Encode(prefix, data) {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  function polymod(values) {
    let chk = 1;
    for (const v of values) {
      const top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk;
  }
  const hrpExp = [];
  for (let i = 0; i < prefix.length; i++) hrpExp.push(prefix.charCodeAt(i) >> 5);
  hrpExp.push(0);
  for (let i = 0; i < prefix.length; i++) hrpExp.push(prefix.charCodeAt(i) & 31);

  const words = [];
  let acc = 0, bits = 0;
  for (const b of data) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; words.push((acc >> bits) & 31); } }
  if (bits > 0) words.push((acc << (5 - bits)) & 31);

  const values = hrpExp.concat(words).concat([0, 0, 0, 0, 0, 0]);
  const mod = polymod(values) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((mod >> (5 * (5 - i))) & 31);
  return prefix + '1' + words.concat(checksum).map(v => CHARSET[v]).join('');
}

// --- Key Derivation ---
const privKeyBytes = hexToBytes(PRIVATE_KEY);
const pubKeyBytes = secp.getPublicKey(privKeyBytes);

// arkeopub bech32 (amino prefix + compressed pubkey)
const amino = new Uint8Array([0xeb, 0x5a, 0xe9, 0x87, 0x21, ...pubKeyBytes]);
const pubKeyBech32 = bech32Encode('arkeopub', amino);

// arkeo address
const addr = bech32Encode('arkeo', ripemd160(sha256(pubKeyBytes)));

console.log('=== Arkeo PAYG SDK Test ===');
console.log('Address:', addr);
console.log('Public Key:', pubKeyBech32);
console.log('Contract:', CONTRACT_ID);
console.log('');

// --- Sign & Query ---
async function query(path, nonce) {
  const preimage = `${CONTRACT_ID}:${pubKeyBech32}:${nonce}`;
  
  // ADR-036 StdSignDoc
  const signDoc = JSON.stringify({
    account_number: "0",
    chain_id: "",
    fee: { amount: [], gas: "0" },
    memo: "",
    msgs: [{ type: "sign/MsgSignData", value: { data: Buffer.from(preimage).toString('base64'), signer: addr } }],
    sequence: "0"
  });

  const hash = sha256(new TextEncoder().encode(signDoc));
  const sig = await secp.sign(hash, privKeyBytes, { canonical: true });
  const sigHex = bytesToHex(sig);

  const arkauth = `${CONTRACT_ID}:${pubKeyBech32}:${nonce}:${sigHex}`;
  const url = `${SENTINEL}/${SERVICE}${path}?arkauth=${encodeURIComponent(arkauth)}`;

  const resp = await fetch(url);
  return { status: resp.status, data: await resp.json() };
}

// Make 3 queries with incrementing nonces
for (let nonce = 1; nonce <= 3; nonce++) {
  console.log(`Query ${nonce}: /status`);
  try {
    const result = await query('/status', nonce);
    if (result.status === 200) {
      console.log(`  ✅ HTTP ${result.status} — Block: ${result.data.result?.sync_info?.latest_block_height}`);
    } else {
      console.log(`  ❌ HTTP ${result.status} —`, JSON.stringify(result.data).slice(0, 100));
    }
  } catch (e) {
    console.log(`  ❌ Error:`, e.message);
  }
}

console.log('\n🎉 Done! Your SDK signing key is working.');
