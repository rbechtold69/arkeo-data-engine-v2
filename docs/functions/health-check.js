/** Metadata probe. Operators must explicitly allow each complete metadata URL. */
const TIMEOUT_MS = 7000;
const MAX_BYTES = 65536;
const HEADERS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, OPTIONS', 'Cache-Control': 'no-store' };
const reply = (data, status = 200) => Response.json(data, { status, headers: HEADERS });

export async function onRequest({ request, env = {} }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: HEADERS });
  if (request.method !== 'GET') return reply({ ok: false, error: 'method_not_allowed' }, 405);
  let target;
  try {
    target = new URL(new URL(request.url).searchParams.get('url'));
    if (!['https:', 'http:'].includes(target.protocol) || target.username || target.password || target.hash) throw Error();
  } catch { return reply({ ok: false, error: 'invalid_url' }, 400); }
  // Exact URLs prevent this public endpoint from becoming an arbitrary server-side proxy.
  // Only trusted operator-managed hosts may be added; never populate this from user input.
  const allowed = String(env.HEALTH_CHECK_ALLOWED_URLS || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!allowed.length) return reply({ ok: false, error: 'health_check_not_configured' }, 503);
  if (!allowed.includes(target.href)) return reply({ ok: false, error: 'target_not_allowed' }, 403);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  const start = Date.now();
  try {
    const response = await fetch(target, { signal: controller.signal, redirect: 'error', headers: { Accept: 'application/json' }, cf: { cacheTtl: 0 } });
    if (!response.ok) { await response.body?.cancel(); return reply({ ok: false, error: 'bad_status', status: response.status }, 502); }
    if (!response.headers.get('content-type')?.includes('application/json')) { await response.body?.cancel(); return reply({ ok: false, error: 'invalid_metadata' }, 502); }
    const reader = response.body?.getReader();
    if (!reader) return reply({ ok: false, error: 'empty_metadata' }, 502);
    const chunks = []; let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BYTES) { await reader.cancel(); return reply({ ok: false, error: 'metadata_too_large' }, 502); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    const data = JSON.parse(new TextDecoder().decode(bytes));
    return reply({ ok: true, status: response.status, latencyMs: Date.now() - start, data });
  } catch (error) {
    return reply({ ok: false, error: controller.signal.aborted ? 'timeout' : 'network_or_invalid_metadata', latencyMs: Date.now() - start }, 502);
  } finally { clearTimeout(timer); }
}
