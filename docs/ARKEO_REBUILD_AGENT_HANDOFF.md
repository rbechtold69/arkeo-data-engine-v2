# Arkeo RPC rebuild — agent handoff and execution prompt

Prepared September 29, 2026 UTC (September 28 in America/Cancun). This document is a standalone handoff for Randy Bechtold's next agent. Repository references and CI were checked during preparation. Read the current branch before making changes; later commits may supersede this snapshot.

## Copy-ready instructions to the next agent

You are taking over an existing Arkeo Marketplace RPC reliability project for Randy Bechtold. Continue the existing implementation and audit it critically. Do not start a replacement marketplace or assume prior tests prove production readiness. Work through everything you can complete safely, then present the concrete access, funding or deployment decisions Randy must make.

Randy is a business-development professional, not an infrastructure engineer. Explain outcomes in plain language, show working evidence, and distinguish completed implementation from unverified assumptions. Give concise progress updates during sustained work. Do not repeatedly ask for GitHub permission when access already works. If a tool requires authorization, explain the specific blocked action; do not bypass access controls.

### 1. Business purpose and agreed scope

- The immediate goal is reliable RPC access for THORChain and Maya applications. Randy reports community concerns about interruptions in Liquify service; this handoff does not independently quantify Liquify outages.
- Liquify remains the preferred primary for the initial pilot. Add one or two compatible, independently operated backups that take over automatically when the primary is unavailable or unhealthy. Restore the preferred primary when it is healthy again.
- Position this constructively as continuity and uptime protection for an existing partner. Do not describe it as replacing Liquify or disparage the provider.
- Preserve the existing marketplace's appearance and provider/consumer signup flows. Repair and simplify them where necessary. No wholesale redesign has been requested.
- Focus the active product on RPC data providers and consumers. Uniswap/Aave frontend-hosting offerings were removed from the active entry flow. Legacy assets remain in the repository; their presence does not mean they are in pilot scope.
- Future consumers must be able to choose other providers and their own priority order. Do not hard-code Liquify as everyone's mandatory provider or create a private provider whitelist disguised as permissionless access.
- Initial chain/service scope must follow the actual THORChain/Maya application workload. Do not provision unnecessary nodes. DASH is excluded from this pilot by Randy's scope instruction; do not repeat the unsupported claim that Maya cannot support DASH. Verify current chain support when it affects a decision.
- THORNode REST, Comet RPC, Midgard and Maya equivalents are distinct services. External-chain RPC is a separate requirement. An Ethereum or Arkeo node cannot substitute for native THORChain/Maya APIs.
- Arkeo revival, future revenue and possible community ownership were strategic ideas, not completed acquisitions, approved budgets or authority to change network governance. Do not assume a revenue allocation or token-economic change has been agreed.
- Fireblocks/Unstoppable Wallet discussions motivated institutional reliability concerns, but this work is an RPC marketplace project. Do not expand it into swap aggregation, institutional entity formation or compliance certification.

### 2. Repositories, branches and exact starting points

**Marketplace / data engines:** https://github.com/rbechtold69/arkeo-data-engine-v2

- Continue branch `codex/institutional-readiness-audit`.
- Draft PR: https://github.com/rbechtold69/arkeo-data-engine-v2/pull/1
- Last implementation commit before this documentation handoff: `de3555d7e9448c74cdf6933fdd3fdb2bb976b5e8`.
- Main branch was `0939295ecf202f9a48d3b5635a67287333cde3a0` when checked. The rebuild is not merged into main.
- Existing public site: https://arkeomarketplace.com — do not assume it contains the candidate fixes.

**Companion Arkeo chain / sentinel fork:** https://github.com/rbechtold69/arkeo

- Candidate branch: `codex/institutional-readiness-audit`.
- Draft PR: https://github.com/rbechtold69/arkeo/pull/1 (base `master`).
- Branch head checked: `6b084a1fc5d16fa6bd36fab721cbe8c2cb52d7e6`.
- Marketplace provider/subscriber/dashboard Dockerfiles intentionally pin an earlier companion commit: `e16dbf84f8874e06d52677e4036bbec983baa226`.
- The difference between the branch head and image pin must be reviewed before updating it. A newer branch is not automatically the validated runtime. Keep commit pins reproducible; do not silently switch to upstream latest.
- Another branch, `feat/adr036-arkauth-verification`, exists. It is not part of this accepted pilot baseline; do not merge it implicitly.

Fresh checkout example (choose unused local directories):

```sh
git clone --branch codex/institutional-readiness-audit https://github.com/rbechtold69/arkeo-data-engine-v2.git arkeo-marketplace
git clone --branch codex/institutional-readiness-audit https://github.com/rbechtold69/arkeo.git arkeo-chain
```

Fetch and inspect current heads and PRs before editing. Preserve other people's changes; do not force-push or overwrite a moving branch. GitHub-backed source and documentation are the durable handoff, not the previous agent's temporary workspace.

### 3. Read these files first

All paths in this table are relative to the marketplace repository.

| Path | Purpose |
| --- | --- |
| `docs/ARKEO_REBUILD_AGENT_HANDOFF.md` | This master handoff and next-agent instructions |
| `docs/RPC_MARKETPLACE_REVIEW.md` | Marketplace fixes, scope choices, known limitations |
| `docs/INSTITUTIONAL_READINESS.md` | Security configuration, payment/health rules and release gates |
| `docs/RPC_REHEARSAL_RUNBOOK.md` | Reproducible checks, deployment preflight, operator handoff |
| `docs/RPC_DEMO_GUIDE.md` | Recorded demo, measurements and bounded live-run prerequisites |
| `docs/rpc-demo.html` and `docs/rpc-demo.json` | Interactive local-test replay and exact recorded evidence |
| `docs/rpc-demo.template.html` | Replay template used by the recorder |
| `docs/rpc-rollout.html` | Existing rollout/rehearsal presentation page |
| `scripts/rpc_demo.py` | Fixture recorder and separately authorized live drill |
| `scripts/rehearse_rpc.py` | Actual-router offline outage regression runner |
| `scripts/rpc_preflight.py` | Offline manifest/listener/health consistency checks |
| `docs/rpc-pilot-manifest.example.json`, `docs/rpc-listeners.example.json`, `docs/rpc-health.example.json` | Intentionally incomplete pilot templates |
| `docs/provider-health.example.json`, `docs/rpc-demo-live.example.json` | Health and live-demo templates; never mistake placeholders for verified endpoints |
| `subscriber-core/README.md`, `provider-core/README.md`, `docs/sdk/README.md` | Existing component and SDK instructions, including migration notes |
| `.github/workflows/readiness-tests.yml` | Exact marketplace CI test/build commands |

Some older documents and legacy pages contain broad readiness language or older test counts. Current measured evidence and explicit release gates take precedence. Correct misleading status text when encountered without treating marketing copy as technical proof.

### 4. Architecture and important implementation areas

- Public marketplace: static `docs/` HTML and shared `docs/js/marketplace.js`, `chain-client.js`, `arkeo-tx.js` and configuration. It discovers providers/services and manages wallet transactions; buying one contract does not itself configure automatic failover.
- Subscriber: `subscriber-core/admin_api.py`, `provider_health.py`, cache/config handling and React admin. It serves the consumer-facing HTTP gateway, selects compatible providers in configured order and handles authorization/counters.
- Provider: `provider-core/admin_api.py`, React admin and sentinel integration. Operators publish services and manage their provider state.
- Dashboard: `dashboard-core/`; container build is independently checked.
- SDKs: JavaScript under `docs/sdk/` and Python under `docs/sdk/python/`.
- Companion fork: sentinel authentication/replay protection, durable claim state and chain settlement logic; inspect `sentinel/`, `x/arkeo/keeper/`, `x/arkeo/types/` and its readiness workflow.

For a direct Liquify primary, the subscriber can use `bypass_uri` plus separately contracted Arkeo backups. For a primary purchased through Arkeo, place Liquify first in `top_services` and omit the direct bypass. Provider identity, exact service ID and sentinel URL must match. A consumer-selected priority order must survive polling, discovery refresh and editing.

### 5. Repairs already implemented — verify, do not blindly trust

- Complete paginated registry discovery; exact provider identity matching; real filters and profiles; no invented service IDs or guessed sentinel URLs when data is missing.
- Removed unsupported fixed-uptime/reputation claims and misleading "failover active" messaging from single-contract signup.
- Exact integer amounts and 64-bit transaction identifiers; corrected close/claim/unbond encoding and first-claim behavior.
- Wallet transaction hashes are journaled before broadcast. Confirmation and pending-operation recovery avoid automatic duplicate submission. Session-storage loss still requires on-chain reconciliation.
- Subscriber preserves consumer ordering; rejects cross-service backups and mismatched endpoints; supports a standalone primary; clears incompatible state after service changes.
- Safe-read retry rules, runtime cooldowns, provider-bound network/freshness/sync checks and fail-closed health policies in institutional mode. HTTP 200 alone is not health evidence.
- Unknown writes and transaction broadcasts are not automatically replayed after ambiguous failure. A network halt is not a provider outage.
- Durable payment counters and local-process locking; no nonce reuse after failures. OS locks are not a distributed sequencer for separately hosted gateways.
- Admin password hashing/migration, protected setup, origin/session controls and confirmed provider claims.
- Updated provider/subscriber admin dependencies and narrow transaction codec. Prior zero-advisory results are dated evidence, not a permanent security guarantee.
- Companion sentinel changes cover contract/provider/spender matching, atomic replay protection, overflow checks, durable reservations, bounded queries and safe claim updates.
- x402 is disabled by default and outside acceptance. Browser Keplr ADR-036 `signArbitrary` is not interchangeable with the current raw PAYG signing format; the unsupported adapter fails before prompting. On-chain `signDirect` transactions are a different path.

### 6. Verified evidence and unresolved CI

At marketplace implementation commit `de3555d`, **66 Python + 49 JavaScript tests passed (115 total)**. All four GitHub workflows completed successfully:

- Readiness: https://github.com/rbechtold69/arkeo-data-engine-v2/actions/runs/35760625544
- Subscriber image build: https://github.com/rbechtold69/arkeo-data-engine-v2/actions/runs/35760625518
- Provider image build: https://github.com/rbechtold69/arkeo-data-engine-v2/actions/runs/35760625564
- Dashboard image build: https://github.com/rbechtold69/arkeo-data-engine-v2/actions/runs/35760625528

These PR image builds did not publish images. A documentation commit after `de3555d` is not the same CI revision; check its own status if claiming exact-head validation.

During this September 29 handoff, the marketplace's 66 Python and 49 JavaScript tests were rerun successfully. The refreshed workspace initially lacked Python dependencies; after installing the documented requirements, the suite passed. No application code or dependency lockfile was changed for this handoff.

**The companion repository is not fully green.** At head `6b084a1`:

- Targeted sentinel/keeper/types race checks passed: https://github.com/rbechtold69/arkeo/actions/runs/35657701892
- Linter and release checks passed.
- The broader Test workflow failed: https://github.com/rbechtold69/arkeo/actions/runs/35657701843
- Its `Run tests` job passed, but its Docker `Regression Test` job failed. The log reports zero successful and nine failed YAML suites, with exported-state differences including service registry fields. Root cause is not established by this handoff. Investigate the complete log, distinguish fixture drift from real defects, and do not simply rewrite expected output to make it green.
- At the marketplace's pinned `e16dbf8`, the targeted readiness checks passed, but the broad Test workflow was cancelled. Successful marketplace container builds are not a replacement for chain integration tests.

An exhaustive audit of all legacy pages, consensus code or economic mechanisms has not been completed. No institutional SLA, SOC 2 assessment or production certification is claimed.

### 7. What the demonstration actually proves

`docs/rpc-demo.html` is a self-contained replay of a measured local run through the actual subscriber router, HTTP forwarding, health gate and nonce storage. It does not make live requests when opened or replayed. Provider servers, chain queries, contracts and signatures are fixtures.

Recorded phases: normal primary; primary interrupted; first backup interrupted; all routes interrupted; backups restored; primary restored. There are **28 requests: 25 successes and three expected failures during all-down**.

The recorded primary-to-first-backup recovery is approximately 160 ms, but the test deliberately injects a 150 ms delay and uses local servers, a one-second cooldown and 350 ms sampling. Do not advertise this as Liquify or production performance. "Liquify role (test server)" is a role label, not a response from Liquify.

The next community demonstration should show real provider responses through the same routing path, with faults injected only into our own isolated test process. No need to stop or alter Liquify's infrastructure. Record response times, time to first successful backup response, errors and recovery to primary. Distinguish an injected 503 from an actual network timeout; separately test relevant fault types.

The bounded live recorder currently targets Arkeo mainnet `/status`, using Liquify and exactly two backups. A shared Arkeo service can prove the mechanism with existing providers, but it does not prove THORChain/Maya service coverage. No publicly hosted candidate demo has been deployed.

### 8. Provider observations and access limitations

On September 22 the existing public directory displayed Liquify (Arkeo/Base), Nodefleet (including Arkeo/Base), RoomIT (Arkeo/Osmosis) and Red_5 (Arkeo). These are historical registration observations, not current health or paid entitlement confirmations. Recheck before selecting providers.

Liquify's observed full public key:

```text
arkeopub1addwnpepqdgt6w2qqkt4jydfud507nl740gxeag7gaaj5hzc8w7x9p0ka8ln6e8kkvk
```

The previous environment could display the marketplace but timed out on direct registry/Liquify metadata checks; the cloud browser returned `ERR_BLOCKED_BY_CLIENT` for Liquify metadata. Do not infer an outage, bypass access controls or claim an authenticated response was received. No successful paid provider request has been established in this work. Listing an existing node does not grant unrestricted access or authorize spending.

Prefer ordinary published provider terms and existing authorized services when sufficient. Randy wants to avoid unnecessary partner meetings or demands on operators' time. Do not send outreach on his behalf without explicit authorization.

### 9. Reproduce the offline baseline

Use Python 3.12 and Node 24. Install the documented dependencies before interpreting import failures as code regressions. From the marketplace root:

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
python scripts/rpc_demo.py --fixture --output /tmp/arkeo-demo/rpc-demo.html
git diff --check
```

Keep a newly generated run separate from the committed evidence unless deliberately updating it; measurements will vary. Follow the companion workflow for Go 1.24 and its race command:

```sh
go test -race ./sentinel/... ./x/arkeo/keeper/... ./x/arkeo/types/...
```

Do not run unreviewed lifecycle/deployment scripts just because they are in an old README. Verify their effects first. A meaningful test failure must be diagnosed, not skipped or hidden.

### 10. Highest-priority remaining work

1. Verify both branches/PRs and reproduce the baseline. Investigate the companion Docker regression failure and reconcile its head with the Dockerfile pin before recommending a release.
2. Inspect the existing UI in a reachable browser environment. Prior DOM tests passed, but a rendered browser check of the local candidate was blocked. Verify provider signup, consumer signup, filters, status messaging and transaction recovery.
3. Establish an exact application workload inventory for THORChain and Maya: API types, paths, methods, networks, freshness, capacity and any required external chains. Do not invent service IDs.
4. Verify at least one common service across Liquify and two independent backups for the first bounded live drill. Check provider identity, actual endpoint compatibility, published terms, current rates and funded contract eligibility.
5. Prepare dedicated test hosting, wallets/contracts and an explicit spending cap. The recorder does not create or fund contracts. Require the approved cap before any paid dispatch.
6. Run the isolated live drill and record real response/identity/freshness evidence, fault and recovery timing, all-down failures and actual charges. Never silently replace failed live access with fixtures.
7. Extend acceptance to the actual THORChain/Maya workload. Validate contract opening/closure/settlement, wallet confirmation, expiry/exhaustion, restarts, ambiguous writes, rate limits, malformed/stale responses and realistic load.
8. Address gateway availability itself: independent hosts, TLS/authentication, monitoring and durable state. Each concurrently active gateway needs a distinct wallet/contracts unless a distributed sequencer is designed and tested. Do not clone a funded nonce snapshot into active replicas.
9. Produce a reviewable release package: exact commits/image digests, sanitized configuration, measured results, rollback procedure, remaining risks and named operator responsibilities. Production remains a separate approval.

The current gateway is HTTP-based and does not implement WebSocket subscription recovery. If the real workload requires it, that is an explicit design and acceptance gap. The routing budget is not a proven end-to-end SLA.

### 11. Live-run boundary and safety rules

Randy has authorized repository review, reversible fixes, local tests, documentation and backing work up to GitHub. He has asked to complete everything possible before asking others for permissions. That is not an unlimited spending or production deployment authorization.

Do not merge to main/master, publish a live candidate site, change production routing/DNS, stop partner infrastructure, create/fund contracts, broadcast funded transactions or incur paid API charges without the applicable concrete authorization. Do not contact partners without explicit approval. Prepare the work first so any request concerns a specific ready-to-review action.

Never commit credentials, seed phrases, private keys, populated sensitive health headers, real wallet homes or mutable payment counters. Use a dedicated test wallet and isolated state, preserve monotonic nonces, redact sensitive evidence, and never reverse counters as part of rollback.

The live runner requires `--allow-paid-requests`, a positive `--max-uarkeo` cap, a dispatch limit and valid existing contracts. Those flags enforce limits; their presence is not a substitute for Randy's spending authorization. See `RPC_DEMO_GUIDE.md` for the exact procedure.

### 12. Expected deliverables and communication

Continue toward a credible community demonstration with Liquify primary and observable backup takeover. Save changes in GitHub, keep PRs reviewable, and report exact commits and tests. Make the recorded/local, staging/live and production states unmistakable.

At each milestone tell Randy: what now works; what was actually tested; what remains unverified; and the smallest specific action needed from him. Do not claim work will continue in the background after your turn ends. Do not call the project complete merely because local tests pass.

Begin by reading the listed files and current PRs, confirming the two repository revisions and the unresolved companion regression, then proceed with the highest-value work that does not need new access or live changes.
