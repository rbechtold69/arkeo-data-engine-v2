import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { registerExactEvmScheme } from "@x402/evm/exact/server";
import { createFacilitatorConfig } from "@coinbase/x402";
import { bazaarResourceServerExtension, declareDiscoveryExtension } from "@x402/extensions/bazaar";
import http from "http";
import crypto from "crypto";

const app = express();
const PORT = 3637;
const SENTINEL_PORT = 3636;
const PAY_TO = "0xd5e0fAA9905b91B9b89f1703C1C228120Bc54E61";

// CDP API Keys for mainnet facilitator
const CDP_API_KEY_ID = process.env.CDP_API_KEY_ID;
const CDP_API_KEY_SECRET = process.env.CDP_API_KEY_SECRET;

// === ARKEO CONTRACT INTEGRATION ===
// x402 payments flow through an ARKEO PAYG contract so the 10% reserve tax applies
// and every query creates on-chain settlement
const ARKEO_CONTRACT_ID = parseInt(process.env.X402_ARKEO_CONTRACT_ID || "0");
const ARKEO_SIGNING_KEY = process.env.X402_ARKEO_SIGNING_KEY || "";
const ARKEO_SERVICE = process.env.X402_ARKEO_SERVICE || "arkeo-mainnet-fullnode";
const ARKEO_CHAIN_ID = process.env.X402_ARKEO_CHAIN_ID || "arkeo-main-v1";

// Simple arkauth generator (matches sentinel_auth.go format)
// Format: contractId:nonce:chainId:signature
let currentNonce = 0;
let signingKeyBytes = null;
let publicKeyBech32 = "";

async function initArkeoAuth() {
  if (!ARKEO_CONTRACT_ID || !ARKEO_SIGNING_KEY) {
    console.log("⚠️  No ARKEO contract configured — x402 queries will use free tier");
    return;
  }

  try {
    signingKeyBytes = Buffer.from(ARKEO_SIGNING_KEY, "hex");
    
    // Fetch current nonce from sentinel
    try {
      const res = await fetch(`http://127.0.0.1:${SENTINEL_PORT}/claim/${ARKEO_CONTRACT_ID}`);
      if (res.ok) {
        const claim = await res.json();
        currentNonce = (claim.nonce || 0) + 1;
        console.log(`📡 Loaded nonce from sentinel: starting at ${currentNonce}`);
      }
    } catch (e) {
      console.log("⚠️  Could not fetch nonce from sentinel, starting at 1");
      currentNonce = 1;
    }

    console.log(`✅ ARKEO contract integration active:`);
    console.log(`   Contract ID: ${ARKEO_CONTRACT_ID}`);
    console.log(`   Service: ${ARKEO_SERVICE}`);
    console.log(`   Starting nonce: ${currentNonce}`);
    console.log(`   → 10% reserve tax applies to every x402 query`);
  } catch (e) {
    console.error("❌ Failed to init ARKEO auth:", e.message);
  }
}

async function generateArkAuth() {
  if (!signingKeyBytes || !ARKEO_CONTRACT_ID) return null;

  try {
    const { secp256k1 } = await import("@noble/curves/secp256k1");
    
    const nonce = currentNonce++;
    
    // Sign preimage matching SDK format: "{contractId}:{nonce}:" (trailing colon)
    const preimage = `${ARKEO_CONTRACT_ID}:${nonce}:`;
    const preimageBytes = new TextEncoder().encode(preimage);
    
    // Sign raw bytes (same as SDK)
    const sig = secp256k1.sign(preimageBytes, signingKeyBytes, { lowS: true });
    const sigHex = Buffer.from(sig.toCompactRawBytes()).toString("hex");
    
    // Get compressed public key and bech32 encode it
    const pubKeyBytes = secp256k1.getPublicKey(signingKeyBytes, true);
    
    // Bech32 encode: amino prefix (eb5ae98721) + compressed pubkey
    const aminoPrefix = Buffer.from("eb5ae98721", "hex");
    const bech32PubKey = bech32Encode("arkeopub", Buffer.concat([aminoPrefix, Buffer.from(pubKeyBytes)]));
    
    // 4-part arkauth format: contractId:pubkey:nonce:signature
    return `${ARKEO_CONTRACT_ID}:${bech32PubKey}:${nonce}:${sigHex}`;
  } catch (e) {
    console.error("Failed to generate arkauth:", e.message);
    return null;
  }
}

// Bech32 encoding
function bech32Encode(prefix, data) {
  const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  function polymod(values) {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
      const b = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i];
    }
    return chk;
  }
  function hrpExpand(hrp) {
    const ret = [];
    for (const c of hrp) ret.push(c.charCodeAt(0) >> 5);
    ret.push(0);
    for (const c of hrp) ret.push(c.charCodeAt(0) & 31);
    return ret;
  }
  function convertBits(data, fromBits, toBits, pad) {
    let acc = 0, bits = 0;
    const ret = [];
    const maxv = (1 << toBits) - 1;
    for (const value of data) {
      acc = (acc << fromBits) | value;
      bits += fromBits;
      while (bits >= toBits) {
        bits -= toBits;
        ret.push((acc >> bits) & maxv);
      }
    }
    if (pad && bits > 0) ret.push((acc << (toBits - bits)) & maxv);
    return ret;
  }
  const words = convertBits(data, 8, 5, true);
  const chkData = [...hrpExpand(prefix), ...words];
  const pm = polymod([...chkData, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((pm >> (5 * (5 - i))) & 31);
  return prefix + "1" + [...words, ...checksum].map(d => CHARSET[d]).join("");
}

// Rate limiting — 100 requests per minute per IP
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Try again in a minute." },
});
app.use(limiter);

// CORS — allow browser requests + expose payment headers
app.use(cors({
  origin: "*",
  exposedHeaders: ["PAYMENT-REQUIRED", "PAYMENT-RESPONSE"],
}));

// MAINNET — Base (eip155:8453) via CDP facilitator
const facilitatorConfig = createFacilitatorConfig(CDP_API_KEY_ID, CDP_API_KEY_SECRET);
const facilitatorClient = new HTTPFacilitatorClient(facilitatorConfig);

const server2 = new x402ResourceServer(facilitatorClient);
registerExactEvmScheme(server2);

// Register Bazaar discovery extension
server2.registerExtension(bazaarResourceServerExtension);

// Bazaar discovery metadata for JSON-RPC endpoint
const bazaarDiscovery = declareDiscoveryExtension({
  method: "POST",
  bodyType: "json",
  input: {
    jsonrpc: "2.0",
    method: "eth_blockNumber",
    params: [],
    id: 1
  },
  inputSchema: {
    type: "object",
    properties: {
      jsonrpc: { type: "string", const: "2.0" },
      method: { type: "string", description: "JSON-RPC method" },
      params: { type: "array", description: "Method parameters" },
      id: { type: "number" }
    },
    required: ["jsonrpc", "method", "id"]
  },
  output: {
    example: { jsonrpc: "2.0", result: "0x134e82a", id: 1 },
    schema: {
      type: "object",
      properties: {
        jsonrpc: { type: "string" },
        result: {},
        id: { type: "number" }
      }
    }
  }
});

const paymentConfig = {
  accepts: [
    {
      scheme: "exact",
      price: "$0.0001",
      network: "eip155:8453",  // Base MAINNET
      payTo: PAY_TO,
    },
  ],
  description: "Arkeo Decentralized RPC — permissionless blockchain data access. Powered by ARKEO token economics with 10% protocol reserve. Pay per request with USDC on Base.",
  mimeType: "application/json",
  extensions: {
    ...bazaarDiscovery,
  },
};

app.use(
  paymentMiddleware(
    {
      "GET /": paymentConfig,
      "POST /": paymentConfig,
    },
    server2,
  ),
);

// Proxy all paid requests to the sentinel WITH arkauth
app.use(async (req, res) => {
  // Generate arkauth for this query (ties it to ARKEO contract)
  let arkAuthParam = "";
  if (ARKEO_CONTRACT_ID) {
    const arkauth = await generateArkAuth();
    if (arkauth) {
      arkAuthParam = `${req.originalUrl.includes("?") ? "&" : "?"}arkauth=${encodeURIComponent(arkauth)}`;
    }
  }

  // Route through the service path if ARKEO contract is configured
  const servicePath = ARKEO_CONTRACT_ID ? `/${ARKEO_SERVICE}` : "";
  const targetPath = `${servicePath}${req.originalUrl}${arkAuthParam}`;

  const options = {
    hostname: "127.0.0.1",
    port: SENTINEL_PORT,
    path: targetPath,
    method: req.method,
    headers: { ...req.headers, host: "localhost:" + SENTINEL_PORT },
  };

  const proxyReq = http.request(options, (proxyRes) => {
    // If sentinel rejects (bad nonce, rate limit), pass through the error
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on("error", (err) => {
    res.status(502).json({ error: "Sentinel unavailable", details: err.message });
  });

  req.pipe(proxyReq);
});

// Initialize ARKEO auth and start server
await initArkeoAuth();

app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🚀 x402 proxy listening on port ${PORT} [BASE MAINNET + ARKEO]`);
  console.log(`   Rate limit: 100 req/min per IP`);
  console.log(`   Proxying to sentinel on port ${SENTINEL_PORT}`);
  console.log(`   USDC payments go to: ${PAY_TO}`);
  if (ARKEO_CONTRACT_ID) {
    console.log(`   ARKEO contract: ${ARKEO_CONTRACT_ID} (10% reserve tax active)`);
  }
});
