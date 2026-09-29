# Liquify-primary demonstration

Open `rpc-demo.html` in a browser. It is a self-contained, interactive replay of a measured **local rehearsal**, with no external resources or wallet access. It does not make live Liquify requests. The recorded run contains 28 requests across six phases: normal primary, primary interrupted, first backup interrupted, all routes down, backups restored, primary restored.

Use **Replay measured run**, the request slider or the phase buttons. The page shows the serving provider, response time, failed requests, phase summaries and return to primary. Download JSON exports the exact embedded evidence. A repeatable local run uses the actual subscriber router, health gate, HTTP transport and nonce storage; blockchain queries, contracts and signatures are fixtures. Provider roles stand in for Liquify and two independent operators. A 150 ms local fault delay and 1 second cooldown are test settings, not claims about production latency.

## Re-run locally

Install the dependencies listed in `RPC_REHEARSAL_RUNBOOK.md`, then run from the repository root:

```sh
python scripts/rpc_demo.py --fixture --output /tmp/arkeo-demo/rpc-demo.html
```

The command produces HTML and adjacent JSON. No public provider is contacted, no wallet is loaded, no chain transaction is broadcast and no payment occurs. A replay is a recording; it does not re-execute the drill when clicked. For the demo, provider choice is fixed to three roles. The production marketplace still permits consumer-selected providers.

## Measurements

- **Response time:** elapsed router time for one client request, including internal health/contract handling and any injected transport delay.
- **Primary-to-backup recovery:** from fault injection to completion of the first successful response from the expected backup.
- **Return to primary:** from removing the local fault to completion of the first successful primary response. Existing cooldown state is retained.
- **Failures:** actual failed client requests, including the intentional all-down phase. Injected upstream failures are recorded separately in `attempts`.
- **Phase outcome:** normal requests must use the primary successfully; recovery phases must reach and end on their expected provider; all-down must fail honestly. A missing recovery is `null`, never zero.

These are single-run measurements. Sampling interval, cooldown and injected fault delay are included in the evidence. No throughput, sustained-load, SLA or availability claims follow from this demonstration.

## Existing provider access checked

The public directory loaded provider registrations, including Liquify (Arkeo and Base), Nodefleet (including Arkeo/Base), RoomIT (Arkeo/Osmosis), and Red_5 (Arkeo). The listed Online state is not a successful paid RPC test. Liquify's displayed contract history had no active contracts; the deployed legacy UI is not an authoritative reconciliation of every wallet's entitlement.

On September 22, the local runtime timed out reaching Liquify metadata and Arkeo registry endpoints. The cloud browser could display the marketplace but reported `ERR_BLOCKED_BY_CLIENT` for Liquify's metadata endpoint. This is an access limitation in this environment, not evidence that Liquify is down. No paid request or external outage was attempted. Native THORChain/Maya service coverage has not been established by the Arkeo/Base listings.

## Bounded live runner, prepared but not accepted against providers

The same recorder supports `--live-config`. This code path still needs a real-provider acceptance run. It imports the existing subscriber implementation with an isolated configuration/cache directory, uses the local `arkeod` signing key, pins selection to explicit pre-funded contract IDs, checks the signing public key, fresh chain height, usable contracts and maximum rates, and runs configured health checks before paid requests. It does not create contracts, fund wallets, change provider registrations, modify a deployed listener or send broadcast transactions. Normal paid API requests can incur contract charges.

This first live drill is deliberately limited to `arkeo-mainnet-fullnode` `/status` reads on `arkeo-main-v1`, with Liquify first and exactly two backups. Successful live responses must contain the expected network, positive height, non-syncing state and fresh block time. The selected service ID must be verified against the deployed registry; never copy the fixture service ID.

Operators must provide:

1. A host able to reach the providers, with the pinned companion Arkeo runtime and Python dependencies installed.
2. A **dedicated** demo wallet and three approved, already funded contracts for the same service. Do not use a concurrently active gateway wallet or counter directory. No private keys go in the JSON file, report or chat.
3. Provider-confirmed public terms or existing authorized access, exact HTTPS sentinel URLs, current service IDs/rates and provider-bound health checks. Normal marketplace consumption may use published terms; new partner-specific infrastructure is not assumed necessary.
4. An explicit total request-charge ceiling in **uarkeo** and dispatch limit. The script conservatively reserves the contract rate before each upstream dispatch, including retries. It never silently falls back to fixture mode if live setup fails.

Start from `rpc-demo-live.example.json`, outside the public docs directory. Its placeholders must be replaced. Health policies use listener ID `rpc-demo` and each exact provider key, including Liquify's key (this paid-primary mode does not use a direct bypass). Preserve nonce state for subsequent runs.

Example command format, **only after the operator sets an approved cap**:

```sh
python scripts/rpc_demo.py --live-config /private/demo.json \
  --allow-paid-requests --max-uarkeo APPROVED_UARKEO_CAP \
  --max-dispatches 90 --output /private/evidence/rpc-demo.html
```

Each fault is injected in this separate process immediately before its own upstream dispatch. No provider process is stopped or changed. The script records configured local fault latency; a future network-timeout drill should use a separately reviewed fault profile, not represent this 503 injection as a physical outage.

The state directory must be empty on first use or previously initialized by this runner. A local file lock prevents two demo processes using it together; it cannot detect an unrelated gateway using the same wallet elsewhere. The operator's dedicated-wallet confirmation remains necessary. Inspect evidence before publishing it. Live HTML/JSON is refused under public `docs/` to reduce accidental publication; explicit external sharing/deployment still needs approval.

No public preview URL or production deployment was created by this change. The saved local rehearsal can be reviewed before any spending or live deployment.
