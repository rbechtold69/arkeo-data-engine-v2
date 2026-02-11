/**
 * ArkAuth — Browser signing library for Arkeo PAYG contract authentication.
 *
 * Generates the "arkauth" query parameter that Arkeo sentinels require for
 * pay-as-you-go requests. Uses the preferred SHA-256(preimage) signing method.
 *
 * @version 1.0.0
 * @license MIT
 */

const ArkAuth = (() => {
  'use strict';

  /**
   * Convert a Uint8Array to hex string.
   * @param {Uint8Array} bytes
   * @returns {string}
   */
  function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Bech32 encoding (BIP-173).
   * @param {string} prefix - Human-readable prefix (e.g. "arkeopub")
   * @param {Uint8Array} data - Raw bytes to encode
   * @returns {string} Bech32-encoded string
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
   * SHA-256 hash using SubtleCrypto.
   * @param {string} message - UTF-8 string to hash
   * @returns {Promise<Uint8Array>} 32-byte hash
   */
  async function sha256(message) {
    const encoded = new TextEncoder().encode(message);
    const buffer = await crypto.subtle.digest('SHA-256', encoded);
    return new Uint8Array(buffer);
  }

  /**
   * Build the preimage message: `{contractId}:{nonce}:`
   * @param {number|string} contractId
   * @param {number|string} nonce
   * @returns {string}
   */
  function buildPreimage(contractId, nonce) {
    return `${contractId}:${nonce}:`;
  }

  /**
   * Generate a 3-part arkauth string (STRICT format).
   *
   * Format: `{contractId}:{nonce}:{signature_hex}`
   *
   * @param {number|string} contractId - On-chain contract ID
   * @param {number|string} nonce - Incrementing nonce (must be > last used)
   * @param {(hash: Uint8Array) => Promise<Uint8Array>} signerFn - Signs SHA-256 hash, returns signature bytes
   * @returns {Promise<string>} arkauth query parameter value
   */
  async function generateArkAuth(contractId, nonce, signerFn) {
    const preimage = buildPreimage(contractId, nonce);
    const hash = await sha256(preimage);
    const signature = await signerFn(hash, preimage);
    return `${contractId}:${nonce}:${toHex(signature)}`;
  }

  /**
   * Generate a 4-part arkauth string (with spender/delegate pubkey).
   *
   * Format: `{contractId}:{bech32PubKey}:{nonce}:{signature_hex}`
   *
   * @param {number|string} contractId
   * @param {number|string} nonce
   * @param {string} bech32PubKey - Bech32-encoded public key (e.g. arkeoPub1...)
   * @param {(hash: Uint8Array) => Promise<Uint8Array>} signerFn
   * @returns {Promise<string>}
   */
  async function generateArkAuthWithSpender(contractId, nonce, bech32PubKey, signerFn) {
    const preimage = buildPreimage(contractId, nonce);
    const hash = await sha256(preimage);
    const signature = await signerFn(hash, preimage);
    return `${contractId}:${bech32PubKey}:${nonce}:${toHex(signature)}`;
  }

  /**
   * Make an authenticated request to an Arkeo sentinel.
   *
   * @param {string} baseUrl - Sentinel base URL (e.g. "http://sentinel.example.com:3636")
   * @param {string} service - Service path (e.g. "arkeo-mainnet-fullnode")
   * @param {number|string} contractId
   * @param {number|string} nonce
   * @param {(hash: Uint8Array) => Promise<Uint8Array>} signerFn
   * @param {RequestInit} [fetchOpts] - Additional fetch options
   * @returns {Promise<Response>}
   */
  async function makeAuthenticatedRequest(baseUrl, service, contractId, nonce, signerFn, fetchOpts = {}) {
    const arkauth = await generateArkAuth(contractId, nonce, signerFn);
    const url = `${baseUrl.replace(/\/$/, '')}/${service}?arkauth=${encodeURIComponent(arkauth)}`;
    return fetch(url, fetchOpts);
  }

  /**
   * Create a signer function that uses the Keplr wallet.
   *
   * Keplr's signArbitrary returns an amino-style signature. We decode the
   * base64 signature and return the raw bytes (typically 64-byte compact secp256k1).
   *
   * @param {string} chainId - Cosmos chain ID (e.g. "arkeo-main-1")
   * @returns {Promise<{signerFn: (hash: Uint8Array) => Promise<Uint8Array>, address: string, pubKeyBech32: string}>}
   */
  async function getKeplrSigner(chainId) {
    if (!window.keplr) {
      throw new Error('Keplr wallet not found. Please install the Keplr extension.');
    }

    await window.keplr.enable(chainId);
    const offlineSigner = window.keplr.getOfflineSigner(chainId);
    const accounts = await offlineSigner.getAccounts();

    if (!accounts.length) {
      throw new Error('No accounts found in Keplr for chain: ' + chainId);
    }

    const account = accounts[0];
    const address = account.address;

    // Get bech32-encoded public key via getKey
    let pubKeyBech32 = '';
    try {
      const key = await window.keplr.getKey(chainId);
      // key.pubKey is a Uint8Array of the raw secp256k1 compressed public key (33 bytes)
      // We need to bech32-encode it with prefix "arkeopub" using amino encoding
      // Amino prefix for secp256k1 pubkey: eb5ae987 21 (5 bytes)
      const aminoPrefix = new Uint8Array([0xeb, 0x5a, 0xe9, 0x87, 0x21]);
      const pubKeyWithPrefix = new Uint8Array(aminoPrefix.length + key.pubKey.length);
      pubKeyWithPrefix.set(aminoPrefix);
      pubKeyWithPrefix.set(key.pubKey, aminoPrefix.length);
      pubKeyBech32 = bech32Encode('arkeopub', pubKeyWithPrefix);
    } catch (e) {
      console.warn('Could not derive bech32 pubkey:', e);
    }

    /**
     * Sign the preimage for arkauth using Keplr.
     *
     * The sentinel verifies signatures in this order:
     * 1. SHA-256(preimage) — preferred (pk.VerifySignature does SHA-256 internally)
     * 2. Raw preimage (pk.VerifySignature also does SHA-256 internally)
     * 3. Keccak-256(preimage)
     * 4. EIP-191 personal_sign
     *
     * Cosmos SDK's secp256k1 VerifySignature(msg, sig) internally computes
     * SHA-256(msg) then verifies the signature against that hash.
     *
     * Keplr's signArbitrary(chainId, signer, data) signs SHA-256(data) with
     * the raw secp256k1 key (for short messages it uses direct signing).
     *
     * So if we pass the preimage string to signArbitrary, Keplr signs
     * SHA-256(preimage). The sentinel's method #2 calls
     * pk.VerifySignature([]byte(preimage), sig) which also computes
     * SHA-256(preimage) internally. These should match.
     *
     * @param {Uint8Array} _hash - SHA-256 hash (unused, kept for interface compat)
     * @param {string} preimage - Raw preimage string "{contractId}:{nonce}:"
     * @returns {Promise<Uint8Array>} 64-byte compact signature
     */
    async function signerFn(_hash, preimage) {
      const signResponse = await window.keplr.signArbitrary(chainId, address, preimage);
      const sigBytes = Uint8Array.from(atob(signResponse.signature), c => c.charCodeAt(0));
      return sigBytes;
    }

    return { signerFn, address, pubKeyBech32 };
  }

  /**
   * Test arkauth by making a request and logging results.
   *
   * @param {string} sentinelUrl - Sentinel base URL
   * @param {string} service - Service name
   * @param {number|string} contractId
   * @param {(hash: Uint8Array) => Promise<Uint8Array>} signerFn
   * @param {number|string} [nonce=1] - Nonce to use
   * @returns {Promise<{arkauth: string, status: number, body: string}>}
   */
  async function testArkAuth(sentinelUrl, service, contractId, signerFn, nonce = 1) {
    const arkauth = await generateArkAuth(contractId, nonce, signerFn);
    console.log('[ArkAuth] Generated:', arkauth);

    const url = `${sentinelUrl.replace(/\/$/, '')}/${service}?arkauth=${encodeURIComponent(arkauth)}`;
    console.log('[ArkAuth] Request URL:', url);

    try {
      const resp = await fetch(url);
      const body = await resp.text();
      const result = { arkauth, status: resp.status, body, url };
      console.log('[ArkAuth] Response:', result);
      return result;
    } catch (err) {
      const result = { arkauth, status: 0, body: err.message, url, error: err };
      console.error('[ArkAuth] Error:', result);
      return result;
    }
  }

  // Public API
  return {
    generateArkAuth,
    generateArkAuthWithSpender,
    makeAuthenticatedRequest,
    getKeplrSigner,
    testArkAuth,
    // Utilities
    sha256,
    toHex,
    buildPreimage,
    bech32Encode,
  };
})();

// Also export for module contexts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ArkAuth;
}

/*
 * ============================================================
 * USAGE EXAMPLES
 * ============================================================
 *
 * // 1. Basic usage with a custom signer
 * const arkauth = await ArkAuth.generateArkAuth(42, 1, async (hash) => {
 *   // Your secp256k1 signing logic here
 *   return signatureBytes; // Uint8Array, 64 bytes
 * });
 * // Result: "42:1:abcdef1234..."
 *
 * // 2. With Keplr wallet
 * const { signerFn, address } = await ArkAuth.getKeplrSigner('arkeo-main-1');
 * const result = await ArkAuth.testArkAuth(
 *   'http://sentinel.example.com:3636',
 *   'arkeo-mainnet-fullnode',
 *   42,
 *   signerFn
 * );
 *
 * // 3. Making authenticated requests
 * const response = await ArkAuth.makeAuthenticatedRequest(
 *   'http://sentinel.example.com:3636',
 *   'arkeo-mainnet-fullnode',
 *   42,       // contractId
 *   5,        // nonce (must increment)
 *   signerFn
 * );
 * const data = await response.json();
 *
 * // 4. With spender (delegate) key
 * const arkauth4 = await ArkAuth.generateArkAuthWithSpender(
 *   42, 1, 'arkeoPub1addwnpepq...', signerFn
 * );
 * // Result: "42:arkeoPub1addwnpepq...:1:abcdef1234..."
 */
