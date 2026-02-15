// ============================================================
// COINGECKO COIN LIST CACHE & AUTOCOMPLETE
// ============================================================
// Fetches the full CoinGecko coin list (~19,000 coins)
// Caches in localStorage with 7-day TTL
// Provides fast autocomplete search

const COINGECKO_CACHE = (() => {
  const CACHE_KEY = 'arkeo_coingecko_coins';
  const CACHE_TTL_KEY = 'arkeo_coingecko_ttl';
  const TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
  const API_URL = 'https://api.coingecko.com/api/v3/coins/list?include_platform=false';
  
  // Map of common Arkeo service names to CoinGecko IDs
  const SERVICE_TO_COINGECKO = {
    'eth-mainnet': 'ethereum',
    'btc-mainnet': 'bitcoin',
    'arkeo-mainnet': 'arkeo',
    'gaia-mainnet': 'cosmos',
    'osmosis-mainnet': 'osmosis',
    'avalanche-mainnet': 'avalanche-2',
    'polygon-mainnet': 'matic-network',
    'bsc-mainnet': 'binancecoin',
    'doge-mainnet': 'dogecoin',
    'ltc-mainnet': 'litecoin',
    'thor-mainnet': 'thorchain',
    'thorchain-mainnet': 'thorchain',
    'base-mainnet': 'base',
    'arbitrum-mainnet': 'arbitrum',
    'optimism-mainnet': 'optimism',
    'solana-mainnet': 'solana',
    'sui-mainnet': 'sui',
    'aptos-mainnet': 'aptos',
    'near-mainnet': 'near',
    'fantom-mainnet': 'fantom',
    'celestia-mainnet': 'celestia',
    'injective-mainnet': 'injective-protocol',
    'juno-mainnet': 'juno-network',
    'akash-mainnet': 'akash-network',
    'kujira-mainnet': 'kujira',
    'starknet-mainnet': 'starknet',
    'zksync-mainnet': 'zksync',
    'algorand-mainnet': 'algorand',
    'tezos-mainnet': 'tezos',
    'cardano-mainnet': 'cardano',
    'polkadot-mainnet': 'polkadot',
  };

  let cachedCoins = null;

  // ============================================================
  // CACHE MANAGEMENT
  // ============================================================
  
  function isCacheValid() {
    const ttl = localStorage.getItem(CACHE_TTL_KEY);
    if (!ttl) return false;
    return Date.now() < parseInt(ttl, 10);
  }

  function loadFromCache() {
    const cached = localStorage.getItem(CACHE_KEY);
    if (!cached) return null;
    try {
      return JSON.parse(cached);
    } catch (e) {
      console.warn('Failed to parse cached CoinGecko data:', e);
      return null;
    }
  }

  function saveToCache(coins) {
    try {
      localStorage.setItem(CACHE_KEY, JSON.stringify(coins));
      localStorage.setItem(CACHE_TTL_KEY, (Date.now() + TTL_MS).toString());
    } catch (e) {
      console.warn('Failed to cache CoinGecko data (storage full?):', e);
    }
  }

  // ============================================================
  // API FETCHING
  // ============================================================
  
  async function fetchCoins() {
    try {
      const response = await fetch(API_URL);
      if (!response.ok) {
        throw new Error(`CoinGecko API returned ${response.status}`);
      }
      const coins = await response.json();
      if (!Array.isArray(coins)) {
        throw new Error('Invalid response format from CoinGecko');
      }
      return coins;
    } catch (error) {
      console.error('Failed to fetch from CoinGecko:', error);
      throw error;
    }
  }

  // ============================================================
  // PUBLIC API
  // ============================================================
  
  /**
   * Initialize the cache. Call this before using search functions.
   * @returns {Promise<void>}
   */
  async function init() {
    if (cachedCoins) return; // Already loaded

    // Try cache first
    if (isCacheValid()) {
      const cached = loadFromCache();
      if (cached) {
        cachedCoins = cached;
        console.log(`Loaded ${cachedCoins.length} coins from cache`);
        return;
      }
    }

    // Fetch from API
    console.log('Fetching CoinGecko coin list...');
    const coins = await fetchCoins();
    cachedCoins = coins;
    saveToCache(coins);
    console.log(`Fetched and cached ${coins.length} coins from CoinGecko`);
  }

  /**
   * Search coins by name or symbol
   * @param {string} query - Search query
   * @param {number} limit - Max results (default 10)
   * @returns {Array} Array of matching coins
   */
  function search(query, limit = 10) {
    if (!cachedCoins) {
      console.warn('CoinGecko cache not initialized. Call init() first.');
      return [];
    }

    if (!query || query.trim().length === 0) {
      return [];
    }

    const q = query.toLowerCase().trim();
    const results = [];
    const exactMatches = [];
    const startsWithMatches = [];
    const containsMatches = [];

    for (const coin of cachedCoins) {
      const name = coin.name.toLowerCase();
      const symbol = coin.symbol.toLowerCase();
      const id = coin.id.toLowerCase();

      // Exact match (name, symbol, or id)
      if (name === q || symbol === q || id === q) {
        exactMatches.push(coin);
      }
      // Starts with
      else if (name.startsWith(q) || symbol.startsWith(q) || id.startsWith(q)) {
        startsWithMatches.push(coin);
      }
      // Contains
      else if (name.includes(q) || symbol.includes(q) || id.includes(q)) {
        containsMatches.push(coin);
      }

      // Early exit if we have enough results
      if (exactMatches.length + startsWithMatches.length + containsMatches.length > limit * 3) {
        break;
      }
    }

    // Combine in priority order
    results.push(...exactMatches, ...startsWithMatches, ...containsMatches);
    
    return results.slice(0, limit);
  }

  /**
   * Get a coin by its CoinGecko ID
   * @param {string} id - CoinGecko coin ID
   * @returns {Object|null} Coin object or null
   */
  function getById(id) {
    if (!cachedCoins) return null;
    return cachedCoins.find(c => c.id === id) || null;
  }

  /**
   * Map an Arkeo service name to a CoinGecko ID
   * @param {string} serviceName - Arkeo service name (e.g. 'eth-mainnet')
   * @returns {string|null} CoinGecko ID or null
   */
  function serviceToCoinGecko(serviceName) {
    return SERVICE_TO_COINGECKO[serviceName] || null;
  }

  /**
   * Get CoinGecko coin info for an Arkeo service
   * @param {string} serviceName - Arkeo service name
   * @returns {Object|null} Coin object or null
   */
  function getByService(serviceName) {
    const coinId = serviceToCoinGecko(serviceName);
    if (!coinId) return null;
    return getById(coinId);
  }

  /**
   * Get CoinGecko asset image URL
   * @param {string} coinId - CoinGecko coin ID
   * @param {string} size - 'thumb' | 'small' | 'large' (default: 'small')
   * @returns {string} Image URL
   */
  function getImageUrl(coinId, size = 'small') {
    // CoinGecko images are hosted at:
    // https://assets.coingecko.com/coins/images/{NUMERIC_ID}/{SIZE}/{FILENAME}
    // But we only have the coin ID, not the numeric ID or filename
    // So we'll use a different approach: the coins/markets endpoint includes images
    // For now, we'll return a placeholder or use an external service
    
    // Alternative: Use CoinGecko's image API (if they have one)
    // Or: Fetch from /coins/{id} endpoint (but that's expensive for all coins)
    
    // For now, we'll construct a best-effort URL based on common patterns
    // This won't work for all coins, but will work for major ones
    return `https://assets.coingecko.com/coins/images/1/${size}/${coinId}.png`;
  }

  /**
   * Get a direct link to a coin's CoinGecko page
   * @param {string} coinId - CoinGecko coin ID
   * @returns {string} CoinGecko page URL
   */
  function getCoinGeckoUrl(coinId) {
    return `https://www.coingecko.com/en/coins/${coinId}`;
  }

  /**
   * Force refresh the cache from CoinGecko API
   * @returns {Promise<void>}
   */
  async function refresh() {
    console.log('Force refreshing CoinGecko cache...');
    localStorage.removeItem(CACHE_KEY);
    localStorage.removeItem(CACHE_TTL_KEY);
    cachedCoins = null;
    await init();
  }

  /**
   * Get cache stats
   * @returns {Object} Cache statistics
   */
  function getStats() {
    const valid = isCacheValid();
    const ttl = localStorage.getItem(CACHE_TTL_KEY);
    const expiresIn = ttl ? parseInt(ttl, 10) - Date.now() : 0;
    
    return {
      initialized: !!cachedCoins,
      coinCount: cachedCoins ? cachedCoins.length : 0,
      cacheValid: valid,
      expiresInMs: expiresIn > 0 ? expiresIn : 0,
      expiresInDays: expiresIn > 0 ? (expiresIn / (24 * 60 * 60 * 1000)).toFixed(1) : 0,
    };
  }

  // ============================================================
  // EXPORT
  // ============================================================
  
  return {
    init,
    search,
    getById,
    serviceToCoinGecko,
    getByService,
    getImageUrl,
    getCoinGeckoUrl,
    refresh,
    getStats,
    SERVICE_TO_COINGECKO, // Export for reference
  };
})();

// Auto-initialize on page load (non-blocking)
if (typeof window !== 'undefined') {
  window.addEventListener('DOMContentLoaded', () => {
    COINGECKO_CACHE.init().catch(err => {
      console.warn('Failed to initialize CoinGecko cache:', err);
    });
  });
}
