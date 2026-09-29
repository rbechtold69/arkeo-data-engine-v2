# Arkeo PAYG client SDK — audit candidate

This branch contains repairs, not an institutional production approval. See
`docs/INSTITUTIONAL_READINESS.md` for the deployment gates.

## Authentication and wallet compatibility

The SDK signs SHA-256 of the UTF-8 PAYG preimage `<contractId>:<nonce>:` with
secp256k1, returning a compact low-S signature. It sends
`<contractId>:<spenderPublicKey>:<nonce>:<signature>` in the `arkauth` header.
This matches the raw-preimage compatibility path in the audited chain source.
It does not use ADR-036. JavaScript and Python signatures are checked against
the same public test vector.

Mnemonic input now uses BIP-39 plus BIP-32 path `m/44'/118'/0'/0/0`.
**Upgrade compatibility:** older releases incorrectly hashed the seed instead of
using that derivation path, producing a different wallet. Before upgrading an
existing funded installation, record its public address and contract client;
reconcile its balances/contracts and arrange a migration. Do not assume the new
SDK address controls an older SDK-created contract. No funds are moved by this
patch. An explicitly provided 32-byte private key retains its existing identity.

## JavaScript

Run `npm ci --ignore-scripts` in this directory. Import `ArkeoClient` from
`arkeo-client.js` and supply `sentinelUrl`, `service`, positive integer
`contractId`, and `privateKey` through your application's secret store.

- `rpc(path, options)` supports Fetch request options and returns a Response.
- `rpcJson` and `rpcText` decode that response; callers must check HTTP status
  with `rpc` when distinguishing transport failures from application responses.
- `timeoutMs` defaults to 10000; redirects are rejected.
- `startNonce` means the **next** nonce to send. When omitted, initialization
  requires both chain contract state and sentinel `/claims` state and uses the
  larger nonce plus one. An unavailable source fails initialization.
- `saveNonce(nextNonce)` is an optional asynchronous hook called before sending.
  Configure durable storage for a funded service. If it fails, no request is sent.
- `setNonce` cannot move backwards; `getNonce` returns the next reserved value.

## Python

Install `python/requirements.txt`. `ArkeoClient` takes `sentinel_url`,
`contract_id`, `private_key`, `service`, and `start_nonce`.
`rpc(path, method='POST', json=payload)` supports read and write transport; it
never automatically retries. `timeout` defaults to 10 seconds; redirects are
disabled. A `save_nonce` callback can persist the next nonce before each request.

Python does not automatically discover a restart nonce. The default of 1 is
only suitable for a new, unused contract. Operators must restore a value above
both the last persisted authorization and the sentinel/chain high-water mark.

## Concurrency and billing boundaries

Calls within one SDK instance are serialized. A nonce is reserved before
transmission, including failed requests: a timeout does not prove that the
sentinel did not receive the authorization. Gaps may affect cumulative PAYG
billing and must be reconciled against the contract's rate and claims.

These clients do not coordinate multiple processes or hosts. Give each replica
its own wallet/contracts, or implement a durable distributed sequencer before
sharing a contract. Do not reuse one contract concurrently through standalone
`generateArkAuth` calls. Sentinel restart, funded settlement and multi-region
recovery remain live acceptance gates.

## Verification

`npm test` runs offline regression tests. The repository's Python suite verifies
matching key derivation/signatures and concurrent nonce allocation. These tests
use public test vectors, fake contracts and mocked transport; they do not spend
funds or prove that a live provider accepts and settles payment.
