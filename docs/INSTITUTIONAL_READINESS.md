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
   writes now stop requests. Do not share a funded contract between listeners or
   hosts without sequencing across all of them. Never reset counters to zero to
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
not prove a node is current; chain/service-specific freshness checks still need
implementation and live verification. Subscriber forwarding does not provide
WebSocket session recovery.

## Release gates

- Build pinned chain/sentinel and container images; record exact commits/digests.
  Candidate Dockerfiles pin the companion fork commit
  `e4830e6e4f0d4792aceff571c26392de942be784`. Coordinate any revision with the
  chain pull request; successful image builds and digest pinning are still required.
- Run Go/race tests for sentinel and claim settlement. Go and Docker execution
  were unavailable in the audit environment.
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
