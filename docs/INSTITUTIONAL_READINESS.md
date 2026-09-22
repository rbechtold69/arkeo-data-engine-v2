# Institutional readiness — candidate branch

**Status: NOT APPROVED FOR PRODUCTION.** This branch repairs reproduced issues;
local tests do not establish live THORChain/Maya service availability, contract
settlement, node freshness, failover latency under load, or institutional SLAs.

## Intended pilot

For each exact service (THORNode REST/quotes, THORNode RPC, Midgard, and each Maya
equivalent), identify a primary and two independent compatible providers. A
provider serving Ethereum RPC is not a substitute for THORNode or Midgard.
The subscriber's `bypass_uri` can be the primary direct endpoint; its configured
Arkeo provider list supplies backups. Path mapping must match on every endpoint.

Run the subscriber behind a private network boundary and an authenticated TLS
edge. Use independent gateways/hosts and a stable ingress; a single subscriber
host is otherwise a new single point of failure. Each replica needs a separate
funded wallet and contracts unless a distributed payment sequencer is added.

## Configuration and migration changes

1. Admin password status returns only `enabled`. Passwords are hashed on write;
   successful login migrates legacy plaintext files. New passwords require at
   least 12 characters. Blank passwords no longer disable authentication.
2. Initialize an unset password by calling POST `/api/admin-password` from
   loopback inside the container/private host, with a matching `X-Admin-Setup-Token`
   header and an operator-provisioned `ADMIN_SETUP_TOKEN` of at least 32 characters.
   Remove the setup token after initialization. No-password installations now
   reject protected requests. Do not expose initial setup through a local public
   reverse proxy. Operators must preinitialize before exposing any ingress.
3. Set `ADMIN_UI_ORIGIN` to the exact UI origin. Untrusted origins are rejected.
   Use HTTPS and set `ADMIN_COOKIE_SECURE=true` when TLS terminates upstream.
   Admin APIs still require VPN/firewall isolation and edge rate limiting.
4. Subscriber client allowlist now defaults to loopback, and forwarding headers
   are untrusted by default. Configure actual private client addresses. Enable
   forwarded-header trust only behind an edge that overwrites those headers and
   cannot be bypassed by direct clients.
5. Mount writable, persistent nonce storage. Corrupt files and failed durable
   writes now stop requests. Counters are now locked across local workers and shared by contract ID, with
   legacy counters migrated upward. Stop old-version workers before upgrading.
   Use distinct wallets/contracts on different hosts; unique counters alone do
   not guarantee that concurrent requests arrive in nonce order. Never reset counters to zero to
   recover a funded service.
6. Apply the separate chain sentinel patch. Set the same randomly generated
   `SENTINEL_ADMIN_TOKEN` (at least 32 characters) in the sentinel and provider
   admin API environments. Mark-claimed requests now require that bearer token.
   Provider bookkeeping only marks claims after a confirmed successful delivery
   at a positive block height, not mempool acceptance.
7. For the optional marketplace metadata probe, set `HEALTH_CHECK_ALLOWED_URLS`
   to a comma-separated list of complete trusted metadata URLs. Redirects and
   unlisted targets are rejected; responses are limited to 64 KiB.
8. SDK mnemonic derivation changed; follow `sdk/README.md` migration notes before
   using an existing funded wallet or contract. Durable nonce callbacks are
   required operationally even though standalone SDK examples remain flexible.

## Scope of failover

Safe reads retry HTTP 408/429/500/502/503/504 and primary connection failures.
Known JSON-RPC reads are allowlisted. Unknown POSTs and transaction broadcasts
are not automatically replayed after ambiguous failure. A protocol halt or a
valid business rejection is not an infrastructure outage. HTTP 200 alone does
not prove a node is current; operator-configured identity, sync-state and timestamp checks now gate provider
selection when enabled. Exact policies still require live verification. Subscriber forwarding does not provide
WebSocket session recovery.

## Release gates

- Build pinned chain/sentinel and container images; record exact commits/digests.
  Candidate Dockerfiles pin the companion fork commit
  `e16dbf84f8874e06d52677e4036bbec983baa226`. Coordinate any revision with the
  chain pull request; successful image builds and digest pinning are still required.
- Run Go/race tests for sentinel and claim settlement. The targeted Go race suite and the three candidate container builds have
  passed in GitHub CI; local Go/Docker execution was unavailable. Recheck final
  commits and retain run links and image digests before any release.
- Confirm live endpoints, service IDs, path mapping, certificates, provider terms
  and independent failure domains. Public checks from the audit environment were
  inconclusive, not evidence that the providers are down.
- Rehearse primary failure, secondary failure, all-down, stale-node responses,
  rate limiting, recovery, malformed responses, chain halt and gateway outage.
- Verify funded authorization, contract opening, budget caps, settlement,
  expiration/renewal, durable restart and backup restoration in staging.
- Test sustained peak load and measure latency/error rates against agreed SLOs.
  Contract creation must not become a long delay on the failover request path.
- Finish frontend schema/wallet integration, dependency advisories, Maya coverage,
  balance/price/gas/tracking redundancy, and transaction-status correctness.
- Review secrets, log retention, admin exposure, CDN scripts, TLS, backups,
  monitoring, incident ownership and operating entity/service commitments.
- Keep x402 and marketplace transaction wizards out of an institutional launch
  until their separate payment/authentication flows are repaired and tested.

## Rollout

Use staging with fake upstreams first; then approved small funded test contracts.
Do not merge/deploy this candidate as a readiness sign-off. Back up configuration
and counters before migration. Canary read traffic and rehearse rollback without
rolling nonce counters backwards. An operator must approve the tested image
and evidence against the gates above before production rollout.

## Enforced pilot profile

Set `ARKEO_INSTITUTIONAL_MODE=true`, `ARKEO_PROVIDER_HEALTH_FILE=/run/arkeo/health.json`,
and `auto_create=false` on every listener. Preprovision and fund backup contracts
before enabling traffic. In this mode a missing policy or unavailable health
check stops use of that provider, and contract creation on the request path is
rejected. The request starts with a 20-second routing budget; individual socket,
CLI and queue delays still require measurement (this is not a strict end-to-end SLA).
Responses are capped at 16 MiB. Unknown writes are never retried after dispatch,
including authentication failures. A rejected health preflight may safely select
another provider before the write is sent anywhere.

Start with `docs/provider-health.example.json`. Replace every placeholder with
approved operator values. Each listener maps `primary` (its direct bypass) and
exact backup provider pubkeys to an exact configured upstream URL. Checks are
HTTPS GETs (loopback HTTP allowed for fixtures), limited to 64 KiB and two seconds
per attempt, without redirects. Positive cache entries are retained for two
seconds and timestamp age is revalidated on every use. At least one exact network
identity and one freshness timestamp check are mandatory. Include an explicit
sync-state requirement and height check for node RPC. For Midgard, require BOTH
its own indexer freshness and a matching network identity check; probing a healthy
node alone cannot prove its indexer is current. Field paths are JSON pointers.

Use separate policies for THORNode REST, Comet RPC, Midgard and Maya equivalents.
The example Comet response paths are not a claim that every advertised provider
exposes them. Inspect real responses and bind the health target to the same node
or indexer that serves traffic. Do not use one shared unrelated health endpoint
for every provider. Public RPC availability does not establish paid service
capacity, provider independence, or support commitments.

Health policies may contain authorization headers. Mount them read-only with
restricted permissions; do not commit populated policies or include them in logs.
Configuration changes take effect on the next request. Deploy independent gateways
with distinct wallets/contracts and persistent local state, behind an authenticated
TLS edge and health-aware load balancer. Never clone a funded counter snapshot into
concurrently active gateways. OS file locks protect local processes, not separately
hosted replicas, and shared network filesystems are outside this tested profile.

### Outside-access acceptance evidence

The remaining live acceptance run needs: exact primary/backup URLs and credentials;
registered service IDs and provider pubkeys; approved staging hosts/TLS/ingress;
distinct staging wallets and a capped funding budget; the operator responsible for
recovery; and permission to interrupt staging providers. Record identity and indexer
freshness responses, failure-domain ownership, baseline and sustained-load latency,
primary/secondary/all-down results, stale/wrong-network rejections, ambiguous-write
reconciliation, successful settlement, restart/restore, and gateway failover. No
production merge, deployment or transfer is authorized by this document.

## Additional browser and billing restrictions

Transaction encoders now preserve 64-bit IDs/nonces from decimal strings and
zero-valued subscription/offline enums. The browser protobuf dependency is pinned
to 7.6.6 with an integrity hash; dynamic script origins must match exactly and have
an integrity pin. Keplr `signArbitrary` uses ADR-036, which is incompatible with the
current raw PAYG settlement preimage. Its PAYG adapter now rejects this unsupported
flow before prompting the wallet. This does not disable on-chain `signDirect`
transactions. See https://docs.keplr.app/api/guide/sign-arbitrary.

The optional x402 billing bridge is disabled by default. Its duplicate signer and
volatile counters were removed in favor of a dedicated local subscriber. It still
requires separate dependency packaging and approved facilitator/funded acceptance;
it is not part of the gateway readiness result. Public marketplace transaction
wizards also require wallet interaction and chain acceptance tests before use.


## September 22 pre-live rehearsal update

See `RPC_REHEARSAL_RUNBOOK.md` for executable local outage drills and offline deployment validation. The marketplace transaction wizards now have confirmed-inclusion and pending-hash recovery, exact integer signing and repaired close/claim encoding; they still require the funded browser acceptance gate above. Provider and subscriber admin dependency trees now pass npm audit with zero reported advisories. This is dependency evidence, not a formal security certification. The rollout still requires the pinned companion sentinel, approved compatible endpoints, distinct funded gateway contracts, staging infrastructure and measured live acceptance. No live system was changed by this review branch.
