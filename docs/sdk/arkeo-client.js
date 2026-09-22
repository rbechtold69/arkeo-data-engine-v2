/**
 * ArkeoClient — Node.js SDK for Arkeo PAYG authenticated RPC calls
 * 
 * Automatically signs the chain PAYG preimage with incrementing nonces.
 * Provides a transparent proxy to any Arkeo sentinel service.
 * 
 * @version 1.0.0
 * @license MIT
 */

import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { ripemd160 } from '@noble/hashes/ripemd160';

// Required for @noble/secp256k1 synchronous signing
secp256k1.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, secp256k1.etc.concatBytes(...m));
import * as bip39 from 'bip39';
import { HDKey } from '@scure/bip32';
import { Buffer } from 'buffer';

/**
 * Bech32 encoding (BIP-173)
 */
function bech32Encode(prefix, data) {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

  function polymod(values) {
    let chk = 1;
    for (const v of values) {
      const top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) {
        if ((top >> i) & 1) chk ^= GENERATOR[i];
      }
    }
    return chk;
  }

  function hrpExpand(hrp) {
    const ret = [];
    for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
    ret.push(0);
    for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
    return ret;
  }

  // Convert 8-bit to 5-bit groups
  const words = [];
  let acc = 0, bits = 0;
  for (const b of data) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      words.push((acc >> bits) & 31);
    }
  }
  if (bits > 0) words.push((acc << (5 - bits)) & 31);

  // Checksum
  const values = hrpExpand(prefix).concat(words).concat([0, 0, 0, 0, 0, 0]);
  const mod = polymod(values) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((mod >> (5 * (5 - i))) & 31);

  return prefix + '1' + words.concat(checksum).map(v => CHARSET[v]).join('');
}

/**
 * Derive private key from mnemonic using BIP-39 and BIP-44 (Cosmos path: m/44'/118'/0'/0/0)
 */
function privateKeyFromMnemonic(mnemonic) {
  if (!bip39.validateMnemonic(mnemonic)) throw new Error('Invalid BIP-39 mnemonic');
  return HDKey.fromMasterSeed(bip39.mnemonicToSeedSync(mnemonic))
    .derive("m/44'/118'/0'/0/0").privateKey;
}

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex) {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error('Private key must be 32 bytes of hex');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Encode public key in amino format with bech32 (arkeopub prefix)
 */
function encodePubKeyBech32(pubKeyBytes) {
  // Amino prefix for secp256k1 pubkey: eb5ae987 21 (5 bytes)
  const aminoPrefix = new Uint8Array([0xeb, 0x5a, 0xe9, 0x87, 0x21]);
  const prefixed = new Uint8Array(aminoPrefix.length + pubKeyBytes.length);
  prefixed.set(aminoPrefix);
  prefixed.set(pubKeyBytes, aminoPrefix.length);
  return bech32Encode('arkeopub', prefixed);
}

/**
 * Get bech32 address from public key (arkeo prefix)
 */
function pubKeyToAddress(pubKeyBytes) {
  const hash1 = sha256(pubKeyBytes);
  const hash2 = ripemd160(hash1);
  return bech32Encode('arkeo', hash2);
}

/**
 * Build ADR-036 StdSignDoc for signing
 */
function buildADR036SignDoc(signerAddress, data) {
  const doc = {
    account_number: "0",
    chain_id: "",
    fee: {
      amount: [],
      gas: "0"
    },
    memo: "",
    msgs: [{
      type: "sign/MsgSignData",
      value: {
        data: Buffer.from(data).toString('base64'),
        signer: signerAddress
      }
    }],
    sequence: "0"
  };
  
  // Return canonical JSON (keys sorted by JS object property order)
  return JSON.stringify(doc);
}

/**
 * Normalize signature to low-S form
 */
function normalizeSig(sig) {
  const CURVE_ORDER = secp256k1.CURVE.n;
  const HALF_ORDER = CURVE_ORDER / 2n;
  
  // Signature is 64 bytes: r (32) + s (32)
  const r = sig.slice(0, 32);
  const s = sig.slice(32, 64);
  
  // Convert s to bigint
  let sBigInt = 0n;
  for (let i = 0; i < 32; i++) {
    sBigInt = (sBigInt << 8n) | BigInt(s[i]);
  }
  
  // If s > N/2, flip it to N - s
  if (sBigInt > HALF_ORDER) {
    sBigInt = CURVE_ORDER - sBigInt;
    
    // Convert back to bytes
    const sNormalized = new Uint8Array(32);
    for (let i = 31; i >= 0; i--) {
      sNormalized[i] = Number(sBigInt & 0xFFn);
      sBigInt >>= 8n;
    }
    
    // Return normalized signature
    const normalized = new Uint8Array(64);
    normalized.set(r, 0);
    normalized.set(sNormalized, 32);
    return normalized;
  }
  
  return sig;
}

/**
 * Main ArkeoClient class
 */
export class ArkeoClient {
  /**
   * Create a new Arkeo PAYG client
   * @param {Object} config
   * @param {string} config.sentinelUrl - Sentinel base URL (e.g. "https://sentinel.arkeo.network")
   * @param {number} config.contractId - Your contract ID
   * @param {string} config.privateKey - Private key (hex) or mnemonic phrase
   * @param {string} config.service - Service name (e.g. "arkeo-mainnet-fullnode")
   * @param {number} [config.startNonce] - Starting nonce (default: auto-detect from chain)
   * @param {string} [config.restApi] - Arkeo REST API endpoint (default: "https://rest-seed.arkeo.network")
   */
  constructor(config) {
    this.sentinelUrl = config.sentinelUrl.replace(/\/$/, '');
    this.contractId = config.contractId;
    if (!Number.isSafeInteger(this.contractId) || this.contractId <= 0) throw new Error('Invalid contract ID');
    this.timeoutMs = config.timeoutMs ?? 10000;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs <= 0) throw new Error('Invalid timeout');
    this.saveNonce = config.saveNonce;
    this._tail = Promise.resolve();
    this.service = config.service;
    this.restApi = config.restApi || 'https://rest-seed.arkeo.network';
    
    // Parse private key (hex or mnemonic)
    let privKeyBytes;
    if (config.privateKey.includes(' ')) {
      // Mnemonic phrase
      privKeyBytes = privateKeyFromMnemonic(config.privateKey);
    } else {
      // Hex string
      privKeyBytes = hexToBytes(config.privateKey);
    }
    
    this.privateKey = privKeyBytes;
    this.publicKey = secp256k1.getPublicKey(privKeyBytes, true); // compressed
    this.publicKeyBech32 = encodePubKeyBech32(this.publicKey);
    this.address = pubKeyToAddress(this.publicKey);
    
    // Nonce tracking - will auto-fetch on first request if not provided
    this.currentNonce = null;
    this._nonceFetched = false;
    if (config.startNonce !== undefined) this.setNonce(config.startNonce);
  }
  
  /**
   * Get current nonce
   */
  getNonce() {
    return this.currentNonce;
  }
  
  /**
   * Set nonce manually (useful for persistence/recovery)
   */
  setNonce(nonce) {
    if (!Number.isSafeInteger(nonce) || nonce <= 0 || (this.currentNonce !== null && nonce < this.currentNonce)) {
      throw new Error('Nonce must be a positive safe integer and cannot move backwards');
    }
    this.currentNonce = nonce;
    this._nonceFetched = true;
  }
  
  /**
   * Sign a message using ADR-036 format
   * @param {string} message - Message to sign (will be SHA-256 hashed then signed)
   * @returns {string} Hex-encoded 64-byte signature (r||s, low-S normalized)
   */
  async sign(message) {
    // Hash the message with SHA-256 (matches chain's pk.VerifySignature which does sha256 internally)
    const hash = sha256(new TextEncoder().encode(message));
    
    // Sign the hash
    const sig = await secp256k1.sign(hash, this.privateKey, { lowS: true });
    
    // Normalize to low-S (secp256k1.sign should already do this with lowS: true)
    const normalized = normalizeSig(sig.toCompactRawBytes());
    
    return bytesToHex(normalized);
  }
  
  /**
   * Generate arkauth header for PAYG requests.
   * Preimage format: "{contractId}:{nonce}:" (matches chain's claim verification)
   * Header format: "contractId:pubkey:nonce:signature" (4-part, for sentinel parsing)
   * @returns {Promise<string>} arkauth value
   */
  async generateArkAuth(nonce = this.currentNonce) {
    // Chain verifies signature over "{contractId}:{nonce}:" (no chain ID, trailing colon)
    const preimage = `${this.contractId}:${nonce}:`;
    const signature = await this.sign(preimage);
    
    // 4-part format for sentinel: contractId:pubkey:nonce:signature
    return `${this.contractId}:${this.publicKeyBech32}:${nonce}:${signature}`;
  }
  
  /**
   * Auto-fetch current nonce from Arkeo blockchain if not set
   * @private
   */
  async _ensureNonce() {
    if (this._nonceFetched) return;
    const claimsUrl = new URL(`${this.sentinelUrl}/claims`);
    claimsUrl.searchParams.set('contract_id', this.contractId);
    claimsUrl.searchParams.set('client', this.publicKeyBech32);
    const responses = await Promise.all([
      fetch(`${this.restApi}/arkeo/contract/${this.contractId}`, { signal: AbortSignal.timeout(this.timeoutMs), redirect: 'error' }),
      fetch(claimsUrl, { signal: AbortSignal.timeout(this.timeoutMs), redirect: 'error' }),
    ]);
    if (responses.some(r => !r.ok)) throw new Error('Cannot safely initialize nonce; chain and sentinel must be reachable');
    const [chain, claims] = await Promise.all(responses.map(r => r.json()));
    if (chain.contract?.nonce === undefined || (claims.highest_nonce === undefined && claims.highestNonce === undefined)) {
      throw new Error('Missing nonce in chain or sentinel response');
    }
    const values = [Number(chain.contract.nonce), Number(claims.highest_nonce ?? claims.highestNonce)];
    if (values.some(n => !Number.isSafeInteger(n) || n < 0)) throw new Error('Invalid remote nonce');
    this.setNonce(Math.max(...values) + 1);
  }

  /**
   * Make an authenticated RPC call
   * @param {string} path - RPC path (e.g. "/status" or "/abci_info")
   * @param {Object} [options] - Fetch options (method, body, headers, etc.)
   * @returns {Promise<Response>} Fetch response
   */
  async rpc(path, options = {}) {
    const run = this._tail.then(async () => {
      await this._ensureNonce();
      const nonce = this.currentNonce;
      this.setNonce(nonce + 1); // Reserve before sending, including failed/ambiguous requests.
      if (this.saveNonce) await this.saveNonce(this.currentNonce);
      const arkauth = await this.generateArkAuth(nonce);
      if (!path.startsWith('/') || path.includes('#')) throw new Error('RPC path must be relative');
      const url = new URL(`${this.sentinelUrl}/${this.service}${path}`);
      url.searchParams.delete('arkauth');
      url.searchParams.delete('arkcontract');
      const headers = new Headers(options.headers);
      headers.set('arkauth', arkauth);
      const timeout = AbortSignal.timeout(this.timeoutMs);
      const signal = options.signal ? AbortSignal.any([timeout, options.signal]) : timeout;
      return fetch(url, { ...options, headers, signal, redirect: 'error' });
    });
    this._tail = run.catch(() => {});
    return run;
  }

  /**
   * Make authenticated RPC call and return JSON
   * @param {string} path - RPC path
   * @param {Object} [options] - Fetch options
   * @returns {Promise<any>} JSON response
   */
  async rpcJson(path, options = {}) {
    const response = await this.rpc(path, options);
    return response.json();
  }
  
  /**
   * Make authenticated RPC call and return text
   * @param {string} path - RPC path
   * @param {Object} [options] - Fetch options
   * @returns {Promise<string>} Text response
   */
  async rpcText(path, options = {}) {
    const response = await this.rpc(path, options);
    return response.text();
  }
  
  /**
   * Get client info
   */
  getInfo() {
    return {
      address: this.address,
      publicKey: bytesToHex(this.publicKey),
      publicKeyBech32: this.publicKeyBech32,
      contractId: this.contractId,
      currentNonce: this.currentNonce,
      service: this.service
    };
  }
}

export default ArkeoClient;
