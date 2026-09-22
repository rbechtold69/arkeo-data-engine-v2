# Existing marketplace RPC review — 22 September 2026

This change updates the existing marketplace and subscriber. It preserves the provider/consumer wizards, visual styles and permissionless registry. It does not deploy a replacement marketplace, provision chains, enter partner agreements, spend ARKEO or certify production readiness.

## Rollout scope and configuration

`docs/js/marketplace.js` is the shared discovery/profile module used by the directory, consumer wizard, provider wizard and provider details. Its default profile highlights THORChain/Maya mainnet service families plus Bitcoin/Ethereum. This is a conservative starting scope, **not a claim that these cover every THORChain/Maya application dependency**. Match each integration's actual requests and required chains before rollout. DASH is excluded from this pilot by the owner's direction; this is not a statement that Maya does not support DASH.

Profile fields are `id`, `label`, `description`, `families`, optional exact `services`, and `preferredProviders` (complete provider public keys). Change the centralized default profile for a deployment, or provide `CONFIG.MARKETPLACE_PROFILE` before using discovery. Custom profiles can prefer any provider. Exact `services` entries supplement `families`; use an empty family list for an exact-only allowlist. “All registered services” exposes the rest of the registry. These are storefront defaults, not chain permissions or instructions to create nodes.

Liquify's known full public key is preferred in the pilot listings. Static provider names are descriptive labels, not health attestations. The subscriber's ordered provider list is separately controlled by the consumer. For this pilot, put the approved Liquify endpoint/provider first for each compatible service. A direct Liquify endpoint can use `bypass_uri` and independently contracted Arkeo providers can back it up. Future consumers may choose a different primary.

## Repaired issues

- Directory and wizard discovery stopped at the first provider/service page. Shared discovery now loads opaque cursor pages with time limits and rejects incomplete or repeated pagination results.
- Provider signup contained fallback service IDs that could target the wrong service when registry loading failed. It now fails closed and rechecks the selected service before asking for a bond transaction.
- Provider identity matching relied on public-key prefixes. Known identities now match exactly; independent providers with the same display name are retained separately.
- Subscription cards estimated request volume from bond and displayed fixed uptime. These claims are removed. Directory/detail pages distinguish registration from measured health, and no longer calculate “reputation” from incomplete request/contract data.
- Service/type/status directory controls now filter actual data locally. Scope changes do not repeatedly fetch the registry. Historical contract scans no longer block basic discovery.
- The consumer wizard displayed “Failover Protection Active” and promised automatic backup contracts even though it only opened one contract. The unsupported checkbox/status is replaced by accurate subscriber setup guidance. It also no longer guesses a sentinel endpoint from a provider’s marketing website.
- Consumer pricing no longer invents a fallback rate or loses the exact integer signing amount. Deposit conversion avoids floating-point rounding. The wizard rechecks provider identity, service, registration, rate, duration and settlement terms before signing.
- Provider metadata updates previously queried the Arkeo service regardless of the selected service. Updates now target the exact selection and preserve its current on-chain contract terms and status.
- Marketplace transactions now journal their hash before submission and require confirmed chain inclusion. Ambiguous responses resume confirmation without automatic resubmission. Provider signup retains the confirmed bond through configuration retries, and account/contract IDs retain integer precision.
- Provider registration verification now checks the complete registry for the exact wallet public key and service, rather than an address prefix.
- Subscriber backup selection could inherit a different provider's sentinel URL. Only the matching provider can inherit its parent endpoint, and cross-service backups are excluded.
- A primary's historical Down label could exclude it while a backup remained Up. Configured order is now retained; runtime cooldowns and fresh health checks govern eligibility.
- A standalone configured primary is supported without requiring a populated backup list.
- Listener service changes compared the new service ID with itself, retaining old-service provider/contract state. Runtime and persistence paths now compare the previous service and replace the selection on a service change.
- Discovery refresh retains consumer order and persisted contract state. Explicit `reset_order: true` requests the existing location/price ordering; manual reorder remains available.
- The subscriber Poll action previously reordered live routing during tests and then saved price/latency ordering. It now uses the existing forced-provider test route without rewriting listener settings or changing the primary.
- Public landing/navigation copy focuses on RPC. Uniswap/Aave application cards and frontend-hosting links are removed from the active entry flow. Legacy application files are retained to avoid destroying unrelated assets; no application-hosting offering is promoted in this rollout.

## Additional pre-live repairs

- Public close/claim/unbond flows now use the shared confirmed transaction client. The older close page previously broadcast JSON in place of protobuf. Contract and bond lists paginate, unbond signing preserves the exact amount, and first provider claims no longer require an already-advanced on-chain nonce. Registry text is escaped in contract/bond rendering.
- Listener `auto_create` is explicitly configurable and defaults off. Institutional mode rejects automatic spending, absolute health probe URLs and write probes. Bound backup endpoints survive edits. Missing chain height and exhausted contracts fail closed. Sensitive raw configuration previews are no longer logged.
- Both admin bundles replace old Osmosis aggregate dependencies with a narrow, wire-tested swap codec and updated CosmJS/protobuf packages. npm audit reports zero advisories for both updated trees (previously 15 each, including one critical). Signing refreshes wallet identity, checks the RPC network, rejects rounded amounts and fixes IBC timeout units and source/destination height confusion. Node 24 is used in the admin build stage.
- Optional x402 signup controls are hidden and guarded unless explicitly enabled. They remain outside pilot acceptance.
- `scripts/rehearse_rpc.py` runs seven local HTTP outage scenarios. `scripts/rpc_preflight.py` rejects inconsistent deployment inputs and unresolved example templates without starting services or spending funds. See [RPC_REHEARSAL_RUNBOOK.md](RPC_REHEARSAL_RUNBOOK.md).

## Verification and limits

Run from the repository root:

```sh
python -m pip install flask pyyaml -r docs/sdk/python/requirements.txt
npm ci --ignore-scripts --prefix docs/sdk
npm ci --ignore-scripts --prefix tests
npm ci --ignore-scripts --prefix subscriber-core/admin
npm ci --ignore-scripts --prefix provider-core/admin
python -m unittest discover -s tests -v
node --test docs/sdk/client.test.mjs tests/*.test.mjs
```

Final local result: **59 Python tests and 46 JavaScript tests pass (105 total)**. Modified HTML inline scripts parse successfully and `git diff --check` is clean.

Tests exercise actual Flask routing and candidate selection, payment nonce durability, raw signature/transaction encoding, health policy checks, SDK failures and local HTTP failover. New DOM tests load the actual marketplace HTML and scripts using paginated fixtures, click through provider/consumer choices, test directory filters and failure states, and verify provider detail rendering. A subscriber Poll regression checks that probes never PUT a replacement routing order.

Fixture tests do not establish live endpoint availability or successful wallet-funded transactions. The cloud browser could not reach the local preview (`ERR_BLOCKED_BY_CLIENT`). Direct network checks of the public Arkeo registry returned 403 in this environment; THORChain/Maya endpoint checks timed out. These results are not evidence that those services are down. Live registry schemas, wallet signing, exact deployed paths and appearance still need a reachable staging rehearsal.

The test matrix does not constitute an exhaustive security audit of every legacy marketplace page or the chain implementation. Existing institutional release gates in `INSTITUTIONAL_READINESS.md` still apply, including the companion sentinel changes. Optional x402 and legacy application workflows remain outside the initial release; the provider detail page does not advertise x402 without an explicit configuration flag.

## Operator work before a live community demo

1. Confirm the actual THORChain/Maya application workload: THORNode/Maya REST, Comet RPC, Midgard/indexer endpoints and any required external-chain methods. Record exact chain/network, Arkeo service ID, path mapping, rate and capacity requirements. Do not substitute an Ethereum RPC for a native node or indexer API.
2. Obtain Liquify's approved primary endpoints plus one or two compatible independent backups for each required service, including credentials, health endpoints, supported methods and failure domains. The marketplace listing is not proof that these are ready.
3. Configure independent gateway hosts/ingress, persistent state and monitoring. Use the enforced institutional profile documented in `INSTITUTIONAL_READINESS.md`, with provider-bound identity/freshness checks and `auto_create=false`. Fund each backup contract in advance under an approved test budget; never create contracts during a failover rehearsal by accident.
4. Rehearse real primary failure, backup failure, all-down, stale/wrong-network responses, restoration, restart, contract expiry and settlement. Verify read retries and absence of ambiguous write replay. Measure latency and errors under realistic load.
5. Present a canary demo with the existing marketplace flow and observable provider changes. Describe any simulated failure as simulated. Approve production only after the measured evidence satisfies the existing release gates.

## Liquify positioning

The operating design keeps Liquify as the preferred primary for this pilot and adds independent continuity when an endpoint is unavailable or stale. Coverage and test results should be reviewed jointly with Liquify. No partner has been contacted or committed to an SLA by this change.
