// ============================================================
// CENTRALIZED CONFIGURATION
// ============================================================
const CONFIG = {
  // API Endpoints
  REST_API: 'https://rest-seed.arkeo.network',
  RPC_API: 'https://rpc-seed.arkeo.network',
  
  // Chain Info
  CHAIN_ID: 'arkeo-main-v1',
  ARKEO_DENOM: 'uarkeo',
  ARKEO_DIVISOR: 100_000_000,
  
  // Transaction Defaults
  MIN_BOND: '100000000', // 1 ARKEO
  DEFAULT_GAS: '200000',
  GAS_PRICE: '0.001uarkeo',
  
  // UI Settings
  CACHE_TTL_MS: 5 * 60 * 1000, // 5 minutes
  REFRESH_INTERVAL_MS: 30 * 1000, // 30 seconds
  MAX_PROVIDERS_DISPLAY: 50,
  CHART_TOP_N: 10,
  
  // External Links
  EXPLORER_TX: 'https://explorer.arkeo.network/arkeo/tx/',
  DOCS_URL: 'https://docs.arkeo.network',
  DISCORD_URL: 'https://discord.gg/arkeo',
  TWITTER_URL: 'https://twitter.com/arkaboreal',
  GITHUB_URL: 'https://github.com/arkeonetwork',
  
  // Feature Flags
  ENABLE_CACHING: true,
  ENABLE_REAL_TIME: false, // WebSocket support (future)
  DEBUG_MODE: false,
};

// Freeze config to prevent accidental modification
Object.freeze(CONFIG);
