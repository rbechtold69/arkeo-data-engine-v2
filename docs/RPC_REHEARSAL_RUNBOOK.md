# RPC pilot rehearsal and release handoff

This candidate updates the existing marketplace. Liquify stays the preferred primary for the THORChain/Maya pilot; consumers retain control of provider order. Nothing in this handoff deploys a service, creates a contract or authorizes funds.

## Reproduce the offline checks

Use Python 3.12 and Node 24 from the repository root:

```sh
python -m pip install flask pyyaml -r docs/sdk/python/requirements.txt
npm ci --ignore-scripts --prefix docs/sdk
npm ci --ignore-scripts --prefix tests
npm ci --ignore-scripts --prefix subscriber-core/admin
npm ci --ignore-scripts --prefix provider-core/admin
npm run build --prefix subscriber-core/admin
npm run build --prefix provider-core/admin
python -m unittest discover -s tests -v
node --test docs/sdk/client.test.mjs tests/*.test.mjs
python scripts/rehearse_rpc.py
```

The rehearsal starts three ephemeral loopback HTTP servers and invokes the actual subscriber router, ordered candidate selection, health checker, upstream HTTP transport and durable nonce store. It covers native REST, Comet RPC and Midgard path/query forwarding; first and second backup selection; all-down; return to primary; wrong-network/stale/syncing nodes; mixed write batches; read batches; missing/expired/exhausted contracts; and missing health bindings. All nodes and responses are fixtures. Chain height, contracts and signatures are fixtures too. No external provider is contacted and no payment is made. This proves local routing behavior, not compatibility, uptime, capacity or settlement of a live provider.

## Prepare deployment configuration without deploying it

Start from `rpc-pilot-manifest.example.json`, `rpc-listeners.example.json` and `rpc-health.example.json` in this directory. They intentionally contain unresolved placeholders and fail preflight. Fill them with the approved service inventory and an export of the subscriber's actual `listeners.json`. Never commit populated credentials, wallets, private health headers or runtime nonce files.

```sh
python scripts/rpc_preflight.py --manifest /private/pilot-manifest.json --listeners /private/listeners.json --health /private/health.json
```

This is an offline consistency check. It checks explicit spending controls, exact service/provider/endpoint mapping, consumer order, one or two independent declared backups, health network/freshness bindings, pre-funded contract declarations, unique listener ports and complete workload coverage. `--lab` permits loopback HTTP fixtures; production endpoints require HTTPS. It prints errors without printing endpoints or credentials and exits nonzero on failure. It always reports `production_ready: false`: declared approvals, independent ownership and funded contracts still need external verification. It cannot verify deployment environment variables, TLS, contracts, budgets or provider independence by reading JSON alone.

Every required API is a distinct workload row. Include THORNode/Maya REST, Comet RPC and Midgard only where the application actually uses them; include external-chain RPCs only after confirming that workload. Obtain exact service IDs/names from the deployed Arkeo registry. Do not invent IDs or treat one API as a substitute for another. Use additional `external:<name>` roles for reviewed chains/projects. `sample_read_path` records the application's real request path. It does not rewrite paths: the gateway preserves the inbound path at the direct primary and prefixes the Arkeo service slug at a sentinel. Verify each sentinel maps that suffix to the compatible upstream.

For direct Liquify primary access, use `bypass_uri`; health policy key `primary` binds that URL. Backup `top_services` entries must explicitly contain the provider key, matching service ID and sentinel URL, in consumer order. For a primary purchased through Arkeo, omit bypass and place its provider first in `top_services`. Health policies must check the same underlying endpoint serving traffic, not an unrelated healthy server. Midgard needs its own freshness signal as well as network identity. Field pointers and network strings must be verified from real provider responses.

## Live acceptance boundary

The following needs the responsible owners' access and approval:

1. **Endpoints and capacity:** Liquify's approved URLs/credentials and one or two compatible independent operators per required API. Confirm methods, archive requirements, request limits, path mapping, health responses and failure domains with them.
2. **Staging infrastructure:** two independent gateways, TLS ingress, admin access controls, private logs, persistent counters and monitoring. Each active gateway needs its own wallet/contracts; do not clone counters into concurrently active replicas.
3. **Capped funds:** explicitly approved small contracts and fees. Exercise actual Keplr registration, configuration, subscription, close and settlement, including delayed confirmation and recovery. An IBC submission is only source-chain inclusion; verify destination receipt before treating funding as available.
4. **Controlled faults and load:** agree permission to interrupt staging upstreams, then record baseline/load latency, error rates, failover, restoration, stale/indexer responses, restart, settlement and gateway loss. Set acceptance thresholds from the application's needs before the run. WebSocket subscriptions are not implemented by this HTTP gateway; any workload requiring them is a separate release blocker.
5. **Review and release:** inspect the exact PR commit, successful container builds and measured evidence. Back up configuration and nonce state, canary read traffic and approve deployment separately. Roll back routing/image/configuration without decrementing a payment counter or replaying an ambiguous transaction.

No messages have been sent to Liquify or other partners. No provider SLA, formal security certification or production readiness is asserted.

## Transaction recovery

Public marketplace signing stores a transaction hash before broadcasting, waits for matching confirmed inclusion, and resumes a pending operation before prompting for another transaction. A timeout is an unknown result, not permission to resubmit. The journal uses session storage: keep the same tab open and record the hash before closing it. If storage is lost, reconcile against the chain before starting again. Bond-then-configure signup retains the confirmed bond receipt through configuration retries. A confirmed open-contract result without a verifiable event remains recorded for manual reconciliation through My Contracts.

Do not enable optional x402 or legacy application hosting in this RPC pilot. They require their own acceptance work.


## Visual failover demonstration

Open `rpc-demo.html` for an interactive replay of a measured local rehearsal. See `RPC_DEMO_GUIDE.md` for regenerating evidence and the bounded, separately authorized live runner. The embedded recording uses test providers; it is not live Liquify performance evidence.
