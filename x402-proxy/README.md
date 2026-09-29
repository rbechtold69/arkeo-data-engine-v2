# Experimental x402 bridge

Disabled by default and excluded from the institutional RPC pilot. The old raw
signer, in-memory payment counter, hardcoded payment recipient, and free-tier
fallback have been removed. This bridge now delegates Arkeo authorization to a
separately configured subscriber listener on loopback.

To evaluate it in a separately approved billing sandbox, set
`ARKEO_ENABLE_EXPERIMENTAL_X402=true`, `X402_PAY_TO`, `CDP_API_KEY_ID`,
`CDP_API_KEY_SECRET` and `X402_SUBSCRIBER_URL`. Never use real funds before testing
facilitator settlement/refunds and the dedicated listener's funded contracts.
Use a listener with no free/direct bypass if every request must generate an Arkeo
claim. Configure its health policy, durable counter storage and spending limits.

There is no production deployment manifest or lockfile for this optional service
in the supplied repository. Its x402 dependency integration and funded settlement
remain unverified. A private TLS edge must protect the loopback service. Only root
GET/POST are forwarded, with caller payment credentials stripped, bounded bodies,
a timeout and no request replay. No payment addresses or credentials are defaulted.
