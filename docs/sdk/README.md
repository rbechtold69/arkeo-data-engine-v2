# Arkeo PAYG Client SDK

Dead-simple client libraries for making authenticated RPC calls to Arkeo sentinels using Pay-As-You-Go (PAYG) contracts.

## Features

✅ **Automatic signing** — Every request signed with ADR-036 signatures  
✅ **Auto-incrementing nonce** — Tracks nonce automatically  
✅ **Transparent proxy** — Returns raw RPC responses  
✅ **Zero config** — Just provide sentinel URL, contract ID, and private key  
✅ **TypeScript-ready** — Written in modern JavaScript (ES modules)  

---

## JavaScript / Node.js

### Installation

```bash
npm install
```

### Quick Start

```javascript
import { ArkeoClient } from './arkeo-client.js';

const client = new ArkeoClient({
  sentinelUrl: 'https://sentinel.arkeo.network',
  contractId: 42,
  privateKey: 'your_private_key_hex_or_mnemonic',
  service: 'arkeo-mainnet-fullnode'
});

// Make RPC calls
const status = await client.rpcJson('/status');
console.log(status);
```

### Configuration

```javascript
new ArkeoClient({
  sentinelUrl: 'https://sentinel.arkeo.network',  // Sentinel base URL
  contractId: 42,                                  // Your contract ID
  privateKey: 'beef1234...',                       // Hex string or mnemonic phrase
  service: 'arkeo-mainnet-fullnode',               // Service name
  startNonce: 1                                    // Optional: starting nonce (default: 1)
})
```

### API

#### `rpc(path, options)`
Make authenticated RPC call and return Response object.

```javascript
const response = await client.rpc('/status');
const data = await response.json();
```

#### `rpcJson(path, options)`
Make authenticated RPC call and return JSON.

```javascript
const data = await client.rpcJson('/abci_info');
```

#### `rpcText(path, options)`
Make authenticated RPC call and return text.

```javascript
const text = await client.rpcText('/health');
```

#### `getNonce()` / `setNonce(n)`
Get or set current nonce (useful for persistence).

```javascript
const nonce = client.getNonce();
client.setNonce(5); // Resume from nonce 5
```

#### `getInfo()`
Get client information.

```javascript
console.log(client.getInfo());
// {
//   address: 'arkeo1abc...',
//   publicKey: '02beef...',
//   publicKeyBech32: 'arkeopub1addwnpepq...',
//   contractId: 42,
//   currentNonce: 3,
//   service: 'arkeo-mainnet-fullnode'
// }
```

### Private Key Formats

**Hex string:**
```javascript
privateKey: '0123456789abcdef...' // 64 hex characters (32 bytes)
```

**Mnemonic phrase:**
```javascript
privateKey: 'word1 word2 word3 ... word24'
```

### Running the Example

```bash
# Edit example.js with your credentials
node example.js
```

---

## Python

### Installation

```bash
cd python
pip install -r requirements.txt
```

### Quick Start

```python
from arkeo_client import ArkeoClient

client = ArkeoClient(
    sentinel_url='https://sentinel.arkeo.network',
    contract_id=42,
    private_key='your_private_key_hex_or_mnemonic',
    service='arkeo-mainnet-fullnode'
)

# Make RPC calls
status = client.rpc_json('/status')
print(status)
```

### API

Same as JavaScript:
- `rpc(path, **kwargs)` → requests.Response
- `rpc_json(path, **kwargs)` → dict
- `rpc_text(path, **kwargs)` → str
- `get_nonce()` / `set_nonce(n)`
- `get_info()` → dict

### Running the Example

```bash
cd python
# Edit example.py with your credentials
python example.py
```

---

## How It Works

### Arkauth Format

Arkeo uses a 4-part authentication header:

```
contractId:spender_pubkey:nonce:signature
```

Example:
```
42:arkeopub1addwnpepq8abc...:1:a1b2c3d4...
```

### Signing Process

1. **Build preimage:** `{contractId}:{spender_pubkey}:{nonce}`
2. **Wrap in ADR-036 StdSignDoc** (Cosmos standard for arbitrary signing)
3. **SHA-256 hash** the canonical JSON
4. **Sign with secp256k1** (low-S normalized)
5. **Encode signature as hex**

### ADR-036 StdSignDoc Structure

```json
{
  "account_number": "0",
  "chain_id": "",
  "fee": {"amount": [], "gas": "0"},
  "memo": "",
  "msgs": [{
    "type": "sign/MsgSignData",
    "value": {
      "data": "<base64_preimage>",
      "signer": "<bech32_address>"
    }
  }],
  "sequence": "0"
}
```

### Nonce Management

- Starts at 1 (or custom `startNonce`)
- Auto-increments after each successful request
- Must be strictly increasing (no replay)
- Can persist/restore with `getNonce()` / `setNonce()`

---

## Security Notes

⚠️ **Never commit private keys**  
⚠️ **Use environment variables** for credentials  
⚠️ **Persist nonce** to avoid replay issues after restarts  

---

## Troubleshooting

### "bad nonce" error

The sentinel tracks nonces in memory. If you restart and use an old nonce:

```javascript
// Query contract on-chain to get current nonce
const currentNonce = await queryContractNonce(contractId);
client.setNonce(currentNonce + 1);
```

### "invalid signature" error

- Check that your private key matches the contract's client/spender
- Verify contract ID is correct
- Ensure nonce is incrementing properly

### Connection errors

- Verify sentinel URL is correct
- Check service name matches contract
- Ensure contract has sufficient deposit remaining

---

## Examples

See [`example.js`](./example.js) and [`python/example.py`](./python/example.py) for complete working examples.

---

## License

MIT
