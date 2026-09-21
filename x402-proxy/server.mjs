import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { registerExactEvmScheme } from "@x402/evm/exact/server";
import { createFacilitatorConfig } from "@coinbase/x402";
import { bazaarResourceServerExtension, declareDiscoveryExtension } from "@x402/extensions/bazaar";
import http from "http";


const app = express();
// This optional billing bridge is excluded from the institutional pilot until
// facilitator settlement, refunds and the operator's account are tested.
if (process.env.ARKEO_ENABLE_EXPERIMENTAL_X402 !== 'true') {
  throw new Error('x402 is disabled pending separate payment acceptance testing');
}
const PORT = Number(process.env.X402_PORT || 3637);
const PAY_TO = process.env.X402_PAY_TO || '';
const CDP_API_KEY_ID = process.env.CDP_API_KEY_ID;
const CDP_API_KEY_SECRET = process.env.CDP_API_KEY_SECRET;
const UPSTREAM = new URL(process.env.X402_SUBSCRIBER_URL || 'http://127.0.0.1:62001/');
if (!/^0x[0-9a-fA-F]{40}$/.test(PAY_TO) || !CDP_API_KEY_ID || !CDP_API_KEY_SECRET) throw new Error('Explicit payment recipient and facilitator credentials required');
if (UPSTREAM.protocol !== 'http:' || !['127.0.0.1','[::1]'].includes(UPSTREAM.hostname) || UPSTREAM.username || UPSTREAM.password || UPSTREAM.search || UPSTREAM.hash) {
  throw new Error('Use a dedicated loopback subscriber listener');
}
// All accepted routes must pass through paymentMiddleware. Never expose a
// wildcard path that can reach an unpaid management or funded subscriber route.
app.use((req,res,next) => {
  if (req.path !== '/' || !['GET','POST'].includes(req.method)) return res.status(404).end();
  next();
});
app.use(express.raw({type:()=>true,limit:'1mb'}));

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
  description: "Arkeo Decentralized RPC — permissionless blockchain data access. Pay per request with USDC on Base. Arkeo payment handling is delegated to the configured subscriber.",
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

// The subscriber owns contract authorization, durable nonces and safe routing.
// Do not implement a second, incompatible signer in this payment bridge.
app.use((req, res) => {
  const target = new URL(UPSTREAM);
  const incoming = new URL(req.originalUrl, 'http://localhost');
  for (const [key,value] of incoming.searchParams) {
    if (!['arkauth','arkcontract'].includes(key.toLowerCase())) target.searchParams.append(key,value);
  }
  const proxyReq = http.request(target, {
    method:req.method,
    headers:{'Content-Type':req.headers['content-type'] || 'application/json','Accept':'application/json'},
    timeout:10000,
  }, proxyRes => {
    // Buffer a bounded response so failure cannot be returned as partial success.
    const chunks=[]; let size=0;
    proxyRes.on('data',chunk=>{size+=chunk.length;if(size>16*1024*1024)proxyRes.destroy(new Error('response too large'));else chunks.push(chunk);});
    proxyRes.on('end',()=>res.status(proxyRes.statusCode || 502).type(proxyRes.headers['content-type'] || 'application/json').send(Buffer.concat(chunks)));
    proxyRes.on('error',()=>{if(!res.headersSent)res.status(502).json({error:'Subscriber response unavailable'});});
  });
  proxyReq.on('timeout',()=>proxyReq.destroy(new Error('timeout')));
  proxyReq.on('error',()=>{if(!res.headersSent)res.status(502).json({error:'Subscriber unavailable'});});
  req.on('aborted',()=>proxyReq.destroy());
  proxyReq.end(Buffer.isBuffer(req.body)?req.body:undefined);
});

app.listen(PORT,'127.0.0.1',()=>console.log(`Experimental x402 bridge listening on loopback port ${PORT}`));
