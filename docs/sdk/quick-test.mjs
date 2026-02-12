import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hmac } from '@noble/hashes/hmac';

// Required for @noble/secp256k1 v2
if (secp.etc && secp.etc.hmacSha256Sync === undefined) {
  secp.etc.hmacSha256Sync = function(key, ...msgs) {
    return hmac(sha256, key, secp.etc.concatBytes(...msgs));
  };
}

var CONTRACT_ID = process.argv[2] || '940';
var PRIVATE_KEY = process.argv[3] || '';
var START_NONCE = parseInt(process.argv[4] || '0');
var SENTINEL = 'https://red5-arkeo.duckdns.org';
var SERVICE = 'arkeo-mainnet-fullnode';

if (!PRIVATE_KEY) { console.log('Usage: node quick-test.mjs <contract_id> <private_key_hex> [start_nonce]'); console.log('Example: node quick-test.mjs 940 a1b2c3... 4'); process.exit(1); }

function hexToBytes(hex) { var b = new Uint8Array(hex.length / 2); for (var i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16); return b; }
function bytesToHex(bytes) { return Array.from(bytes, function(b) { return b.toString(16).padStart(2, '0'); }).join(''); }

function bech32Encode(prefix, data) {
  var CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  function polymod(values) { var chk = 1; for (var v of values) { var top = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v; for (var i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i]; } return chk; }
  var hrpExp = []; for (var i = 0; i < prefix.length; i++) hrpExp.push(prefix.charCodeAt(i) >> 5); hrpExp.push(0); for (var i = 0; i < prefix.length; i++) hrpExp.push(prefix.charCodeAt(i) & 31);
  var words = []; var acc = 0, bits = 0; for (var b of data) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; words.push((acc >> bits) & 31); } } if (bits > 0) words.push((acc << (5 - bits)) & 31);
  var values = hrpExp.concat(words).concat([0,0,0,0,0,0]); var mod = polymod(values) ^ 1; var cs = []; for (var i = 0; i < 6; i++) cs.push((mod >> (5*(5-i))) & 31);
  return prefix + '1' + words.concat(cs).map(function(v) { return CHARSET[v]; }).join('');
}

var privKeyBytes = hexToBytes(PRIVATE_KEY);
var pubKeyBytes = secp.getPublicKey(privKeyBytes, true);
var amino = new Uint8Array(38);
amino[0] = 0xeb; amino[1] = 0x5a; amino[2] = 0xe9; amino[3] = 0x87; amino[4] = 0x21;
amino.set(pubKeyBytes, 5);
var pubKeyBech32 = bech32Encode('arkeopub', amino);
var addr = bech32Encode('arkeo', ripemd160(sha256(pubKeyBytes)));

console.log('=== Arkeo PAYG SDK Test ===');
console.log('Address:', addr);
console.log('Public Key:', pubKeyBech32);
console.log('Contract:', CONTRACT_ID);
console.log('');

async function query(path, nonce) {
  var preimage = CONTRACT_ID + ':' + pubKeyBech32 + ':' + nonce;
  var signDoc = JSON.stringify({ account_number:"0", chain_id:"", fee:{amount:[],gas:"0"}, memo:"", msgs:[{type:"sign/MsgSignData",value:{data:Buffer.from(preimage).toString('base64'),signer:addr}}], sequence:"0" });
  var hash = sha256(new TextEncoder().encode(signDoc));
  var sigObj = await secp.sign(hash, privKeyBytes, {lowS: true});
  var sig = typeof sigObj.toCompactRawBytes === 'function' ? sigObj.toCompactRawBytes() : sigObj;
  var sigHex = bytesToHex(sig);
  var arkauth = CONTRACT_ID + ':' + pubKeyBech32 + ':' + nonce + ':' + sigHex;
  var url = SENTINEL + '/' + SERVICE + path + '?arkauth=' + encodeURIComponent(arkauth);
  var resp = await fetch(url);
  return { status: resp.status, data: await resp.json() };
}

// Auto-fetch current nonce from chain if not provided
if (START_NONCE === 0) {
  try {
    var contractResp = await fetch('https://rest-seed.arkeo.network/arkeo/contract/' + CONTRACT_ID);
    var contractData = await contractResp.json();
    START_NONCE = parseInt(contractData.contract.nonce || '0') + 1;
    if (START_NONCE < 1) START_NONCE = 1;
    console.log('Auto-detected start nonce:', START_NONCE);
  } catch(e) { START_NONCE = 1; }
}

for (var nonce = START_NONCE; nonce <= START_NONCE + 2; nonce++) {
  console.log('Query ' + nonce + ': /status');
  try {
    var r = await query('/status', nonce);
    if (r.status === 200) {
      console.log('  OK HTTP 200 - Block: ' + (r.data.result && r.data.result.sync_info && r.data.result.sync_info.latest_block_height));
    } else {
      console.log('  FAIL HTTP ' + r.status + ' - ' + JSON.stringify(r.data).slice(0, 100));
    }
  } catch (e) { console.log('  FAIL Error: ' + e.message); }
}
console.log('');
console.log('Done! Paid queries with auto-signing.');
