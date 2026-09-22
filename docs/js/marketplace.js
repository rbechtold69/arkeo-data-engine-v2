/* Shared marketplace discovery. Profiles affect this storefront, never protocol permissions. */
(function (root) {
  'use strict';
  const LIQUIFY = 'arkeopub1addwnpepqdgt6w2qqkt4jydfud507nl740gxeag7gaaj5hzc8w7x9p0ka8ln6e8kkvk';
  const DEFAULT_PROFILE = Object.freeze({
    id: 'thorchain-maya',
    label: 'THORChain + Maya initial rollout',
    description: 'Initial focus: THORChain/Maya native APIs and Bitcoin/Ethereum RPC. Liquify is preferred; you choose your provider. Other registered services remain available.',
    // Start with native APIs and shared BTC/ETH dependencies. Extend after workload review.
    families: ['thorchain', 'maya', 'mayachain', 'btc', 'eth'],
    preferredProviders: [LIQUIFY],
  });
  function profile() {
    return typeof CONFIG !== 'undefined' && CONFIG.MARKETPLACE_PROFILE || DEFAULT_PROFILE;
  }
  function normalizeService(s) {
    const id = String(s?.service_id ?? s?.id ?? (/^\d+$/.test(String(s?.service)) ? s.service : '')).trim();
    const name = String(s?.name ?? (typeof s?.service === 'string' && !/^\d+$/.test(s.service) ? s.service : '')).trim();
    if (!/^\d+$/.test(id) || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(name)) throw new Error('Invalid service registry entry');
    return { ...s, id, service_id: id, name };
  }
  function inScope(service, p = profile()) {
    const name = typeof service === 'string' ? service : service?.name || '';
    if (p.id === 'all') return true;
    if (p.services?.includes(name)) return true;
    return (p.families || []).includes(name.split('-')[0]) && name.split('-').includes('mainnet');
  }
  function resolveService(value, services) {
    return services.find(s => s.id === String(value) || s.name === String(value)) || null;
  }
  function providerOrder(a, b, p = profile()) {
    const rank = x => { const i = (p.preferredProviders || []).indexOf(x.pubkey || x.pub_key || x.id); return i < 0 ? Number.MAX_SAFE_INTEGER : i; };
    return rank(a) - rank(b) || String(a.name || a.pubkey || a.pub_key).localeCompare(String(b.name || b.pubkey || b.pub_key));
  }
  function paygRate(provider) {
    const rates = provider?.pay_as_you_go_rate;
    if (!Array.isArray(rates)) return null;
    const coin = rates.find(c => c.denom === 'uarkeo');
    const amount = String(coin?.amount ?? '');
    if (!/^\d+$/.test(amount)) return null;
    return { amount, display: Number(amount) / 100000000 };
  }
  function amountToUnits(value, decimals = 8) {
    const text = String(value).trim();
    const match = /^(\d{1,32})(?:\.(\d+))?$/.exec(text);
    if (!match || (match[2] || '').length > decimals) throw new Error('Enter an amount with at most ' + decimals + ' decimal places');
    return (BigInt(match[1]) * 10n ** BigInt(decimals) + BigInt((match[2] || '').padEnd(decimals, '0'))).toString();
  }
  function registered(provider) {
    try { return ['ONLINE', 1, '1'].includes(provider.status) && BigInt(provider.bond || '0') > 0n; }
    catch { return false; }
  }
  async function json(url, { timeoutMs = 6000, fetcher = root.fetch.bind(root) } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetcher(url, { signal: controller.signal, redirect: 'error' });
      if (!response.ok) throw new Error('API returned HTTP ' + response.status);
      return await response.json();
    } finally { clearTimeout(timer); }
  }
  async function collection(base, resource, fields, { fetcher, maxPages = 100, timeoutMs = 15000 } = {}) {
    const items = [], keys = new Set(); let key = ''; const until = Date.now() + timeoutMs;
    for (let page = 0; page < maxPages; page++) {
      if (Date.now() >= until) throw new Error('Registry loading timed out; retry before selecting a service');
      const url = new URL(base.replace(/\/$/, '') + '/arkeo/' + resource);
      url.searchParams.set('pagination.limit', '100');
      if (key) url.searchParams.set('pagination.key', key);
      const data = await json(url.href, { fetcher, timeoutMs: Math.min(6000, until - Date.now()) });
      const rows = Array.isArray(data) ? data : fields.map(f => data[f]).find(Array.isArray);
      if (!rows) throw new Error('Unexpected ' + resource + ' response');
      items.push(...rows);
      const next = data.pagination?.next_key;
      if (!next) return items;
      if (keys.has(next)) throw new Error('Repeated pagination cursor for ' + resource);
      keys.add(next); key = next;
    }
    throw new Error('Incomplete ' + resource + ' registry; narrow the query or increase the configured limit');
  }
  async function registry(base, options = {}) {
    const [rawServices, providers] = await Promise.all([
      collection(base, 'services', ['services', 'service'], options),
      collection(base, 'providers', ['provider', 'providers'], options),
    ]);
    const services = rawServices.map(normalizeService);
    return { services, providers };
  }
  async function service(base, name, options = {}) {
    const rows = await collection(base, 'services', ['services', 'service'], options);
    const found = rows.map(normalizeService).find(s => s.name === name);
    if (!found) throw new Error('Selected service is no longer in the registry; select it again');
    return found;
  }
  async function provider(base, pubkey, name, options = {}) {
    if (!/^arkeopub1[a-z0-9]+$/.test(pubkey)) throw new Error('Invalid provider identity');
    const data = await json(base.replace(/\/$/, '') + '/arkeo/provider/' + encodeURIComponent(pubkey) + '/' + encodeURIComponent(name), options);
    const p = data.provider;
    if (!p || p.pub_key !== pubkey) throw new Error('Provider identity did not match the selection');
    return p;
  }
  function mountScope(container, onChange) {
    const el = typeof container === 'string' ? document.getElementById(container) : container;
    if (!el) return;
    const p = profile();
    el.textContent = '';
    const label = document.createElement('label'), select = document.createElement('select');
    label.textContent = 'Service scope: '; select.setAttribute('aria-label', 'Service scope');
    for (const [value, text] of [['pilot', p.label], ['all', 'All registered services']]) {
      const option = document.createElement('option'); option.value = value; option.textContent = text; select.appendChild(option);
    }
    select.addEventListener('change', () => onChange(select.value === 'all'));
    label.appendChild(select); el.appendChild(label);
    const note = document.createElement('p'); note.style.cssText = 'font-size:.85rem;color:var(--text-dim);margin:.5rem 0 1rem';
    note.textContent = p.description || 'Choose a service and provider. Other registered services remain available.';
    el.appendChild(note);
  }
  const api = { LIQUIFY, DEFAULT_PROFILE, profile, normalizeService, inScope, resolveService, providerOrder, paygRate, amountToUnits, registered, json, collection, registry, service, provider, mountScope };
  root.Marketplace = Object.freeze(api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
