/**
 * Cloudflare Pages Function: /health-check
 *
 * Proxies Arkeo sentinel health checks server-side, bypassing the browser's
 * mixed-content block (marketplace is HTTPS, most sentinels are HTTP-only).
 *
 * Usage: GET /health-check?url=http://arkeo-provider.liquify.com:3636/metadata.json
 *
 * Returns:
 *   { ok: true,  latencyMs: 234, data: { ... metadata ... } }
 *   { ok: false, error: "timeout" | "network" | "bad_status", latencyMs: 234 }
 */

const TIMEOUT_MS = 7000;
const ALLOWED_PROTOCOLS = ['http:', 'https:'];
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Cache-Control': 'no-cache, no-store',
};

export async function onRequest(context) {
  const { request } = context;

  // Handle preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  const reqUrl = new URL(request.url);
  const targetUrl = reqUrl.searchParams.get('url');

  if (!targetUrl) {
    return Response.json(
      { ok: false, error: 'missing_param', message: 'url parameter required' },
      { status: 400, headers: CORS_HEADERS }
    );
  }

  // Validate URL
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return Response.json(
      { ok: false, error: 'invalid_url' },
      { status: 400, headers: CORS_HEADERS }
    );
  }

  if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) {
    return Response.json(
      { ok: false, error: 'protocol_not_allowed' },
      { status: 400, headers: CORS_HEADERS }
    );
  }

  // Fetch with timeout
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  const t0 = Date.now();

  try {
    const resp = await fetch(targetUrl, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
      cf: { cacheTtl: 0 },  // Don't cache in Cloudflare edge
    });
    clearTimeout(timer);
    const latencyMs = Date.now() - t0;

    let data = null;
    const ct = resp.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      try { data = await resp.json(); } catch { data = null; }
    }

    return Response.json(
      { ok: resp.ok, status: resp.status, latencyMs, data },
      { headers: CORS_HEADERS }
    );
  } catch (err) {
    clearTimeout(timer);
    const latencyMs = Date.now() - t0;
    const isTimeout = err.name === 'AbortError';
    return Response.json(
      { ok: false, error: isTimeout ? 'timeout' : 'network', latencyMs },
      { status: 502, headers: CORS_HEADERS }
    );
  }
}
