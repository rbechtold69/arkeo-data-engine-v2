import React, { useState, useEffect, useMemo, useCallback, useRef } from "react";
import { createRoot } from "react-dom/client";
import Chart from "chart.js/auto";

    const BLOCK_TIME_FALLBACK = 5.79954919;
    const ARKEO_DIVISOR = 100_000_000;
    const CHAIN_ICON_SLUGS = {
      agoric: "agoric",
      akash: "akash",
      aptos: "aptos",
      arbitrum: "arbitrum",
      avax: "avalanchec",
      base: "base",
      bch: "bitcoincash",
      bnb: "binance",
      bsc: "smartchain",
      btc: "bitcoin",
      btg: "bitcoingold",
      cardano: "cardano",
      celo: "celo",
      cro: "cronos",
      dash: "dash",
      dcr: "decred",
      dgb: "digibyte",
      doge: "doge",
      etc: "classic",
      eth: "ethereum",
      "eth-sepolia": "sepolia",
      evmos: "evmos",
      fil: "filecoin",
      ftm: "fantom",
      gaia: "cosmos",
      glmr: "moonbeam",
      grs: "groestlcoin",
      hbar: "hedera",
      inj: "nativeinjective",
      iotx: "iotex",
      juno: "juno",
      kava: "kava",
      klay: "klaytn",
      linea: "linea",
      ltc: "litecoin",
      manta: "manta",
      mantle: "mantle",
      movr: "moonriver",
      near: "near",
      neutron: "neutron",
      one: "harmony",
      optimism: "optimism",
      osmosis: "osmosis",
      polkadot: "polkadot",
      polygon: "polygon",
      "polygon-Mumbai": "polygonmumbai",
      qtum: "qtum",
      rvn: "ravencoin",
      scroll: "scroll",
      scrt: "secret",
      sei: "sei",
      sol: "solana",
      stride: "stride",
      sui: "sui",
      sys: "syscoin",
      taiko: "",
      thorchain: "thorchain",
      tia: "tia",
      ton: "ton",
      trx: "tron",
      via: "viacoin",
      xdai: "xdai",
      xec: "ecash",
      xlm: "stellar",
      xprt: "persistence",
      zec: "zcash",
      zksync: "zksync",
      allora: "allora",
      arch: "arch",
      arkeo: "arkeo",
      aur: "aur",
      azero: "azero",
      babylon: "babylon",
      bera: "bera",
      blast: "blast",
      ccd: "",
      cere: "",
      cfg: "",
      cheqd: "",
      d: "",
      dfk: "",
      dvpn: "dvpn",
      dym: "dym",
      erowan: "erowan",
      flare: "flare",
      flo: "flo",
      flow: "flow",
      frx: "frx",
      ftc: "ftc",
      fuse: "fuse",
      hopr: "hopr",
      imx: "imx",
      initia: "initia",
      iota: "iota",
      ixo: "ixo",
      jackal: "jackal",
      kavaevm: "kavaevm",
      koii: "koii",
      lbtc: "lbtc",
      ln: "ln",
      mantaevm: "mantaevm",
      mantra: "mantra",
      maya: "maya",
      mina: "mina",
      mock: "mock",
      namada: "namada",
      ngm: "ngm",
      nibiru: "nibiru",
      nlg: "nlg",
      nmc: "nmc",
      nomic: "nomic",
      paloma: "paloma",
      part: "part",
      penumbra: "penumbra",
      ppc: "ppc",
      pyth: "pyth",
      rdd: "rdd",
      router: "router",
      seda: "seda",
      selfchain: "selfchain",
      shardeum: "shardeum",
      smart: "smart",
      somnia: "somnia",
      starknet: "starknet",
      supra: "supra",
      tao: "tao",
      union: "union",
      vtc: "vtc",
      zircuit: "zircuit",
      zkfair: "zkfair",
    };
    const PROVIDER_ENV_EXAMPLE = `KEY_NAME=provider
KEY_KEYRING_BACKEND=test
KEY_MNEMONIC=
CHAIN_ID="arkeo-main-v1"

ARKEOD_HOME=~/.arkeo
ARKEOD_NODE=tcp://127.0.0.1:26657

ADMIN_PORT=8077
ADMIN_API_PORT=9996`;
    const PROVIDER_RUN_CMD = `# create host dirs
mkdir -p ~/provider-core/config ~/provider-core/cache ~/provider-core/arkeo

# stop/remove any existing container with this name
docker stop provider-core || true
docker rm provider-core || true

# pull latest image (optional but recommended)
docker pull ghcr.io/arkeonetwork/provider-core:latest

# run
docker run -d --name provider-core --restart=unless-stopped \\
  --env-file ~/provider.env \\
  -e ENV_ADMIN_PORT=8080 \\
  -p 8080:8080 -p 3636:3636 -p 9999:9999 \\
  -v ~/provider-core/config:/app/config \\
  -v ~/subscriber-core/cache:/app/cache \\
  -v ~/provider-core/arkeo:/root/.arkeo \\
  ghcr.io/arkeonetwork/provider-core:latest`;
    const SUBSCRIBER_ENV_EXAMPLE = `SUBSCRIBER_NAME=Arkeo Core Subscriber

KEY_NAME=subscriber
KEY_KEYRING_BACKEND=test
KEY_MNEMONIC=
CHAIN_ID="arkeo-main-v1"

ARKEOD_HOME=~/.arkeo
ARKEOD_NODE=tcp://127.0.0.1:26657
EXTERNAL_SENTINEL_NODE=http://127.0.0.1:3636

ADMIN_PORT=8079
ADMIN_API_PORT=9998`;
    const SUBSCRIBER_RUN_CMD = `# create host dirs
mkdir -p ~/subscriber-core/config ~/subscriber-core/cache ~/subscriber-core/arkeo

# stop/remove any existing container with this name
docker stop subscriber-core || true
docker rm subscriber-core || true

# pull latest image (optional but recommended)
docker pull ghcr.io/arkeonetwork/subscriber-core:latest

# run
docker run -d --name subscriber-core --restart=unless-stopped \\
  --env-file ~/subscriber-core/subscriber.env \\
  -e ENV_ADMIN_PORT=8079 \\
  -p 8079:8079 -p 9998:9998 -p 62001-62100:62001-62100 \\
  -v ~/subscriber-core/config:/app/config \\
  -v ~/subscriber-core/cache:/app/cache \\
  -v ~/subscriber-core/arkeo:/root/.arkeo \\
  ghcr.io/arkeonetwork/subscriber-core:latest`;
    const resolveApiBase = () => {
      if (window.API_BASE) return window.API_BASE;
      const portHint = window.ENV_ADMIN_API_PORT || window.ADMIN_API_PORT || null;
      const loc = window.location;
      const host = loc.hostname;
      const proto = loc.protocol;
      const currentPort = loc.port;
      // If served from 8077 (static UI), default API to 9996
      if (currentPort === '8077') {
        return `${proto}//${host}:9996`;
      }
      // If an explicit port hint is provided, use it
      if (portHint) {
        return `${proto}//${host}:${portHint}`;
      }
      // Fallback to same origin
      return `${proto}//${host}${currentPort ? `:${currentPort}` : ''}`;
    };
    const API_BASE = resolveApiBase();

    const chainSlugFromServiceName = (name = "") => {
      const lower = String(name || "").toLowerCase();
      if (!lower) return "";
      const prefix = lower.split("-")[0];
      return CHAIN_ICON_SLUGS[prefix] || "";
    };

    const chainIconUrl = (slug) => {
      if (!slug) return null;
      return `/resources/${slug}/info/logo.png`;
    };

    const TIME_WINDOWS = {
      daily: 86400,
      weekly: 604800,
      monthly: 2592000,
    };

    // Location regions for filtering
    const REGIONS = [
      { id: 'all', name: 'All Regions', icon: '🌍' },
      { id: 'africa', name: 'Africa', icon: '🌍' },
      { id: 'africa-northern', name: 'Africa – Northern', icon: '🌍' },
      { id: 'africa-eastern', name: 'Africa – Eastern', icon: '🌍' },
      { id: 'africa-middle', name: 'Africa – Middle', icon: '🌍' },
      { id: 'africa-western', name: 'Africa – Western', icon: '🌍' },
      { id: 'africa-southern', name: 'Africa – Southern', icon: '🌍' },
      { id: 'americas', name: 'Americas', icon: '🌎' },
      { id: 'americas-northern', name: 'Americas – Northern', icon: '🌎' },
      { id: 'americas-caribbean', name: 'Americas – Caribbean', icon: '🌎' },
      { id: 'americas-central', name: 'Americas – Central', icon: '🌎' },
      { id: 'americas-south', name: 'Americas – South', icon: '🌎' },
      { id: 'asia', name: 'Asia', icon: '🌏' },
      { id: 'asia-central', name: 'Asia – Central', icon: '🌏' },
      { id: 'asia-eastern', name: 'Asia – Eastern', icon: '🌏' },
      { id: 'asia-southeastern', name: 'Asia – Southeastern', icon: '🌏' },
      { id: 'asia-southern', name: 'Asia – Southern', icon: '🌏' },
      { id: 'asia-western', name: 'Asia – Western', icon: '🌏' },
      { id: 'europe', name: 'Europe', icon: '🇪🇺' },
      { id: 'europe-northern', name: 'Europe – Northern', icon: '🇪🇺' },
      { id: 'europe-eastern', name: 'Europe – Eastern', icon: '🇪🇺' },
      { id: 'europe-southern', name: 'Europe – Southern', icon: '🇪🇺' },
      { id: 'europe-western', name: 'Europe – Western', icon: '🇪🇺' },
      { id: 'oceania', name: 'Oceania', icon: '🇦🇺' },
      { id: 'oceania-aus-nz', name: 'Oceania – Australia & New Zealand', icon: '🇦🇺' },
      { id: 'oceania-melanesia', name: 'Oceania – Melanesia', icon: '🇦🇺' },
      { id: 'oceania-micronesia', name: 'Oceania – Micronesia', icon: '🇦🇺' },
      { id: 'oceania-polynesia', name: 'Oceania – Polynesia', icon: '🇦🇺' },
      { id: 'antarctica', name: 'Antarctica', icon: '🧊' },
    ];
    const REGION_IDS = new Set(REGIONS.map(r => r.id));
    const regionSlug = (val) => {
      if (!val) return null;
      const slug = String(val)
        .toLowerCase()
        .replace(/[\u2013\u2014]/g, '-') // normalize en/em dash
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .replace(/--+/g, '-');
      return REGION_IDS.has(slug) ? slug : null;
    };

    const SMART_SELECT_CRITERIA = [
      { id: 'price', label: 'Lowest Price', icon: '💰', description: 'Find the cheapest rate per query' },
      { id: 'latency', label: 'Fastest Response', icon: '⚡', description: 'Lowest latency for speed-critical apps' },
      { id: 'uptime', label: 'Most Reliable', icon: '🛡️', description: '99.9%+ uptime guarantee providers' },
    ];

    // Utilities
    const formatArkeo = (uarkeo = 0, decimals = 2) => {
      const val = parseInt(uarkeo || 0, 10) / ARKEO_DIVISOR;
      if (val >= 1_000_000) return (val / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M';
      if (val >= 1_000) return (val / 1_000).toFixed(1).replace(/\.0$/, '') + 'K';
      const fixed = val.toFixed(decimals);
      return decimals > 0 ? fixed.replace(/\.?0+$/, '') : fixed;
    };

    const CHART_DECIMALS = 8;
    const formatChartNumber = (value) => {
      const num = Number(value);
      if (!Number.isFinite(num)) return '0';
      const fixed = num.toFixed(CHART_DECIMALS);
      return fixed.replace(/\.?0+$/, '') || '0';
    };

    const blocksForRange = (range, blockTimeSeconds) => {
      const secs = TIME_WINDOWS[range];
      if (!secs) return null;
      const bt = parseFloat(blockTimeSeconds || BLOCK_TIME_FALLBACK) || BLOCK_TIME_FALLBACK;
      return Math.max(1, Math.round(secs / bt));
    };

    const getEarningsByRange = (provider, range, latestHeight, blockTimeSeconds, heightOverride = null, blockTimeOverride = null) => {
      const heightRef = heightOverride ?? latestHeight;
      const contracts = provider.contracts || [];
      const heightLimitBlocks = blocksForRange(range, blockTimeOverride ?? blockTimeSeconds);
      const cutoff = heightRef && heightLimitBlocks ? heightRef - heightLimitBlocks : null;
      return contracts.reduce((sum, c) => {
        const paid = parseInt(c.paid || 0, 10);
        const hRaw = c.height || c.settlement_height || c.raw?.height || c.raw?.settlement_height;
        const h = hRaw !== undefined ? parseInt(hRaw, 10) : null;
        if (cutoff && h && h < cutoff) return sum;
        return sum + (isFinite(paid) ? paid : 0);
      }, 0);
    };

    const TIME_RANGES = [
      { id: 'daily', label: 'Daily' },
      { id: 'weekly', label: 'Weekly' },
      { id: 'monthly', label: 'Monthly' },
      { id: 'all_time', label: 'All Time' },
    ];

    const SORT_OPTIONS = [
      { id: 'earnings', label: 'Highest Earnings' },
      { id: 'cost', label: 'Lowest Cost' },
    ];

    // Icons
    const Icons = {
      Server: () => (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" xmlns="http://www.w3.org/2000/svg">
          <path strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" d="M4 7a2 2 0 012-2h12a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V7zM4 15a2 2 0 012-2h12a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2z" />
          <path strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" d="M6 7h.01M6 15h.01" />
        </svg>
      ),
      Provider: () => (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
          <path d="M22 1H18a1 1 0 00-1 1V9h-2V7a1 1 0 00-1.447-.895L9 8.382V7a1 1 0 00-1.447-.895l-6 3A1 1 0 001 10v12a1 1 0 001 1H22a1 1 0 001-1V2a1 1 0 00-1-1zM21 3v2h-2V3zM3 21V10.618l4-2V10a1 1 0 001.447.895L13 8.618V10a1 1 0 001 1h4a1 1 0 001-1V7h2V21zm2-8H8v2H5zm5 0h4v2h-4zm6 0h3v2h-3zM5 17H8v2H5zm5 0h4v2h-4zm6 0h3v2h-3z" />
        </svg>
      ),
      EarningCoin: () => (
        <svg className="w-5 h-5" viewBox="0 0 512 512" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
          <path d="M326.344 137l-11.641 16.047c1.797.766 3.547 1.547 5.266 2.344s3.375 1.609 5 2.438 3.188 1.672 4.719 2.531c1.516.859 3 1.734 4.438 2.609 2.406 1.516 4.641 3.266 6.625 5.063 2 1.797 3.766 3.641 5.234 5.297 1.469 1.672 2.656 3.156 3.484 4.266.844 1.109 1.328 1.844 1.406 1.969l.672.844.359.922.031.953-.25.969-.625.891-.875.766-1.063.609-1.219.438-22.938 5.656-1.203.203-1.203.031-1.156-.125-1.094-.281-.563-.219-.547-.297-.484-.313-.438-.375c-.078-.094-.469-.609-1.125-1.406-.641-.797-1.563-1.844-2.672-3.016-1.109-1.188-2.422-2.469-3.875-3.719-1.469-1.266-3.047-2.469-4.75-3.484-1.656-1.016-3.375-2-5.156-2.938s-3.609-1.859-5.516-2.719c-1.891-.875-3.844-1.719-5.859-2.516s-4.078-1.563-6.203-2.297c-2.781-.953-5.469-1.75-8.031-2.391-2.547-.625-5-1.109-7.344-1.438-2.328-.328-4.531-.5-6.641-.516s-4.094.109-5.969.406c-1.891.297-3.641.719-5.281 1.25s-3.141 1.188-4.531 1.938c-1.391.766-2.656 1.641-3.797 2.609-1.125 1-2.141 2.094-3.016 3.297-.797 1.094-1.422 2.156-1.891 3.203-.469 1.031-.75 2.063-.891 3.063s-.109 1.969.094 2.922c.188.953.547 1.891 1.078 2.797.531.922 1.25 1.844 2.188 2.75.922.922 2.063 1.844 3.391 2.781 1.328.922 2.859 1.844 4.594 2.781 1.734.922 3.672 1.859 5.797 2.781L277 206.531c4.469 1.891 8.563 3.844 12.25 5.844 3.703 2 7 4.031 9.906 6.141 2.891 2.094 5.406 4.234 7.531 6.422 2.125 2.203 3.859 4.453 5.188 6.75 1.359 2.297 2.281 4.656 2.781 7.078.484 2.438.563 4.922.203 7.484-.344 2.563-1.109 5.172-2.313 7.859-1.188 2.688-2.813 5.438-4.844 8.25-1.219 1.688-2.516 3.281-3.906 4.766-1.391 1.5-2.828 2.906-4.391 4.219-1.531 1.313-3.156 2.531-4.844 3.641-1.703 1.125-3.469 2.156-5.313 3.078-1.875.969-3.813 1.828-5.781 2.609-1.984.766-4.016 1.469-6.094 2.078s-4.203 1.141-6.391 1.594c-2.172.453-4.391.828-6.672 1.141-2.297.297-4.625.5-7 .625s-4.781.172-7.234.125c-2.469-.047-4.969-.156-7.5-.359-2.547-.203-5.109-.469-7.734-.844-1.156-.172-2.297-.375-3.438-.578-1.141-.188-2.297-.406-3.438-.625-1.156-.234-2.313-.469-3.453-.719-1.156-.25-2.328-.516-3.484-.781l-13.828 19.094-32.125-11.016 13.563-18.688c-2.188-.922-4.328-1.859-6.422-2.828s-4.125-1.953-6.125-2.969c-1.969-1.016-3.922-2.047-5.797-3.109s-3.703-2.141-5.484-3.25c-2.703-1.688-5.281-3.875-7.656-6.203-2.344-2.344-4.469-4.844-6.281-7.156s-3.297-4.438-4.344-6.031c-1.063-1.578-1.688-2.656-1.813-2.844l-.609-.859-.297-.922.031-.938.313-.906.594-.859.859-.734 1.078-.594 1.25-.391 24.375-5.922 1.156-.203 1.156-.016 1.125.125 1.063.266.703.297.641.344.563.406.484.469c.078.141.547.938 1.297 2.125.781 1.172 1.844 2.75 3.156 4.469 1.297 1.719 2.844 3.563 4.547 5.281 1.703 1.734 3.578 3.344 5.547 4.563 1.938 1.219 3.938 2.391 5.969 3.484 2.016 1.125 4.078 2.172 6.188 3.172s4.25 1.938 6.438 2.813c2.172.891 4.391 1.719 6.641 2.5 2.859.969 5.672 1.813 8.406 2.531s5.406 1.313 8.031 1.766c2.609.453 5.188.766 7.688.969 2.5.188 4.953.234 7.328.172 2.406-.078 4.641-.344 6.719-.781 2.063-.438 3.969-1.047 5.719-1.844 1.734-.797 3.313-1.766 4.734-2.922 1.438-1.172 2.688-2.5 3.797-4.016.781-1.094 1.406-2.156 1.875-3.219.484-1.047.797-2.078.953-3.109.156-1.016.172-2.016.016-3.016-.156-.969-.469-1.938-.938-2.875s-1.125-1.891-1.984-2.813c-.875-.953-1.953-1.891-3.219-2.828s-2.734-1.875-4.391-2.797c-1.688-.938-3.547-1.859-5.625-2.797l-27.547-11.625c-4.047-1.75-7.766-3.563-11.141-5.422-3.359-1.844-6.391-3.766-9.078-5.734-2.688-1.953-5.031-3.969-7.016-6.031-2-2.078-3.656-4.203-4.938-6.375-1.313-2.172-2.219-4.422-2.688-6.766-.453-2.328-.5-4.734-.141-7.234.375-2.484 1.172-5.047 2.391-7.703 1.203-2.656 2.844-5.391 4.875-8.203 1.125-1.531 2.328-3 3.609-4.391s2.641-2.688 4.078-3.922c1.453-1.234 2.969-2.375 4.578-3.438 1.609-1.078 3.297-2.063 5.094-2.969 1.766-.922 3.578-1.766 5.438-2.516 1.859-.781 3.766-1.469 5.734-2.078 1.969-.625 3.953-1.156 6-1.609 2.063-.469 4.156-.844 6.297-1.156 2.141-.297 4.328-.547 6.516-.688 2.203-.172 4.422-.266 6.688-.281 2.25-.016 4.516.047 6.813.172 2.297.141 4.625.344 6.969.625.984.125 1.969.25 2.953.406s1.969.313 2.938.484c.984.172 1.953.359 2.938.563.984.188 1.969.406 2.953.609l11.891-16.375L326.344 137z" />
          <path d="M256 55.109c-141.375 0-256 72.266-256 161.422v78.938C0 384.641 114.625 456.891 256 456.891s256-72.25 256-161.422v-78.938C512 127.375 397.375 55.109 256 55.109zm0 34.625c120 0 221.375 58.063 221.375 126.797C477.375 285.25 376 343.313 256 343.313S34.625 285.25 34.625 216.531C34.625 147.797 136 89.734 256 89.734z" />
        </svg>
      ),
      Zap: () => <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>,
      Close: () => <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>,
      Check: () => <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>,
      Search: () => <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>,
      DataTypes: () => (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" xmlns="http://www.w3.org/2000/svg">
          <path d="M18 12V17C18 18.6569 15.3137 20 12 20C8.68629 20 6 18.6569 6 17V12M18 12V7M18 12C18 13.6569 15.3137 15 12 15C8.68629 15 6 13.6569 6 12M18 7C18 5.34315 15.3137 4 12 4C8.68629 4 6 5.34315 6 7M18 7C18 8.65685 15.3137 10 12 10C8.68629 10 6 8.65685 6 7M6 12V7" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      ),
      Globe: () => (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
      Activity: () => <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" /></svg>,
      External: () => <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>,
      Wand: () => <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" /></svg>,
      Docker: () => <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><path d="M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.887c0 .102.082.186.185.186m-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.185.185 0 00-.185.185v1.887c0 .102.083.186.185.186m-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.185.185 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.887c0 .102.084.186.186.186m5.893 2.715h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.93 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.083.185.185.185m-2.964 0h2.119a.185.185 0 00.185-.185V9.006a.185.185 0 00-.185-.186h-2.12a.186.186 0 00-.185.186v1.887c0 .102.084.185.186.185m-2.92 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.082.185.185.185M23.763 9.89c-.065-.051-.672-.51-1.954-.51-.338.001-.676.03-1.01.087-.248-1.7-1.653-2.53-1.716-2.566l-.344-.199-.226.327c-.284.438-.49.922-.612 1.43-.23.97-.09 1.882.403 2.661-.595.332-1.55.413-1.744.42H.751a.751.751 0 00-.75.748 11.376 11.376 0 00.692 4.062c.545 1.428 1.355 2.48 2.41 3.124 1.18.723 3.1 1.137 5.275 1.137.983.003 1.963-.086 2.93-.266a12.248 12.248 0 003.823-1.389c.98-.567 1.86-1.288 2.61-2.136 1.252-1.418 1.998-2.997 2.553-4.4h.221c1.372 0 2.215-.549 2.68-1.009.309-.293.55-.65.707-1.046l.098-.288z"/></svg>,
      Cloud: () => <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" /></svg>,
      Chip: () => <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" /></svg>,
      Cart: () => <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.293 2.293c-.63.63-.184 1.707.707 1.707H17m0 0a2 2 0 100 4 2 2 0 000-4zm-8 2a2 2 0 11-4 0 2 2 0 014 0z" /></svg>,
      MapPin: () => <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" /></svg>,
      ChevronDown: () => <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>,
      DollarSign: () => <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>,
      Coin: () => (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" xmlns="http://www.w3.org/2000/svg">
          <path d="M21 8C21 6.34315 17.866 5 14 5C10.134 5 7 6.34315 7 8M21 8V12C21 13.0195 19.8135 13.9202 18 14.4623C16.8662 14.8012 15.4872 15 14 15C12.5128 15 11.1338 14.8012 10 14.4623C8.18652 13.9202 7 13.0195 7 12V8M21 8C21 9.01946 19.8135 9.92016 18 10.4623C16.8662 10.8012 15.4872 11 14 11C12.5128 11 11.1338 10.8012 10 10.4623C8.18652 9.92016 7 9.01946 7 8" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          <path d="M3 12.0001V16.0001C3 17.0196 4.18652 17.9203 6 18.4624C7.13383 18.8013 8.51275 19.0001 10 19.0001C11.4872 19.0001 12.8662 18.8013 14 18.4624C15.8135 17.9203 17 17.0196 17 16.0001V15.0001M3 12.0001C3 10.8034 4.63505 9.7703 7 9.28882M3 12.0001C3 13.0196 4.18652 13.9203 6 14.4624C7.13383 14.8013 8.51275 15.0001 10 15.0001C10.695 15.0001 11.3663 14.9567 12 14.8759" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      ),
      Services: () => (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" xmlns="http://www.w3.org/2000/svg">
          <path d="M20,15 C19,16 21.25,18.75 20,20 C18.75,21.25 16,19 15,20 C14,21 13.5,23 12,23 C10.5,23 10,21 9,20 C8,19 5.25,21.25 4,20 C2.75,18.75 5,16 4,15 C3,14 1,13.5 1,12 C1,10.5 3,10 4,9 C5,8 2.75,5.25 4,4 C5.25,2.75 8,5 9,4 C10,3 10.5,1 12,1 C13.5,1 14,3 15,4 C16,5 18.75,2.75 20,4 C21.25,5.25 19,8 20,9 C21,10 23,10.5 23,12 C23,13.5 21,14 20,15 Z M7,12 L10,15 L17,8" />
        </svg>
      ),
      Validators: () => (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" xmlns="http://www.w3.org/2000/svg">
          <path d="M20,15 C19,16 21.25,18.75 20,20 C18.75,21.25 16,19 15,20 C14,21 13.5,23 12,23 C10.5,23 10,21 9,20 C8,19 5.25,21.25 4,20 C2.75,18.75 5,16 4,15 C3,14 1,13.5 1,12 C1,10.5 3,10 4,9 C5,8 2.75,5.25 4,4 C5.25,2.75 8,5 9,4 C10,3 10.5,1 12,1 C13.5,1 14,3 15,4 C16,5 18.75,2.75 20,4 C21.25,5.25 19,8 20,9 C21,10 23,10.5 23,12 C23,13.5 21,14 20,15 Z M7,12 L10,15 L17,8" />
        </svg>
      ),
      Contracts: () => (
        <svg className="w-5 h-5" viewBox="0 0 1024 1024" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
          <path d="M182.52 146.2h585.14v402.28h73.15V73.06H109.38v877.71h402.28v-73.14H182.52z" />
          <path d="M255.67 219.34h438.86v73.14H255.67zM255.67 365.63h365.71v73.14H255.67zM255.67 511.91H475.1v73.14H255.67zM731.02 585.06c-100.99 0-182.86 81.87-182.86 182.86s81.87 182.86 182.86 182.86 182.86-81.87 182.86-182.86-81.87-182.86-182.86-182.86zm0 292.57c-60.5 0-109.71-49.22-109.71-109.71 0-60.5 49.22-109.71 109.71-109.71 60.5 0 109.71 49.22 109.71 109.71 0 60.49-49.22 109.71-109.71 109.71z" />
          <path d="M717.88 777.65l-42.55-38.13-36.61 40.86 84.02 75.27 102.98-118.47-41.39-36z" />
        </svg>
      ),
      Subscribers: () => (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 7V13M12 13L14 11M12 13L10 11M4 14H6.67452C7.1637 14 7.40829 14 7.63846 14.0553C7.84254 14.1043 8.03763 14.1851 8.21657 14.2947C8.4184 14.4184 8.59136 14.5914 8.93726 14.9373L9.06274 15.0627C9.40865 15.4086 9.5816 15.5816 9.78343 15.7053C9.96237 15.8149 10.1575 15.8957 10.3615 15.9447C10.5917 16 10.8363 16 11.3255 16H12.6745C13.1637 16 13.4083 16 13.6385 15.9447C13.8425 15.8957 14.0376 15.8149 14.2166 15.7053C14.4184 15.5816 14.5914 15.4086 14.9373 15.0627L15.0627 14.9373C15.4086 14.5914 15.5816 14.4184 15.7834 14.2947C15.9624 14.1851 16.1575 14.1043 16.3615 14.0553C16.5917 14 16.8363 14 17.3255 14H20M7.2 4H16.8C17.9201 4 18.4802 4 18.908 4.21799C19.2843 4.40973 19.5903 4.71569 19.782 5.09202C20 5.51984 20 6.07989 20 7.2V16.8C20 17.9201 20 18.4802 19.782 18.908C19.5903 19.2843 19.2843 19.5903 18.908 19.782C18.4802 20 17.9201 20 16.8 20H7.2C6.0799 20 5.51984 20 5.09202 19.782C4.71569 19.5903 4.40973 19.2843 4.21799 18.908C4 18.4802 4 17.9201 4 16.8V7.2C4 6.0799 4 5.51984 4.21799 5.09202C4.40973 4.71569 4.71569 4.40973 5.09202 4.21799C5.51984 4 6.0799 4 7.2 4Z" />
        </svg>
      ),
      Transactions: () => (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" xmlns="http://www.w3.org/2000/svg">
          <path d="M2,7 L20,7 M16,2 L21,7 L16,12 M22,17 L4,17 M8,12 L3,17 L8,22" />
        </svg>
      ),
      CheckCircle: () => (
        <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
          <path fillRule="evenodd" d="M3 10a7 7 0 019.307-6.611 1 1 0 00.658-1.889 9 9 0 105.98 7.501 1 1 0 00-1.988.22A7 7 0 113 10zm14.75-5.338a1 1 0 00-1.5-1.324l-6.435 7.28-3.183-2.593a1 1 0 00-1.264 1.55l3.929 3.2a1 1 0 001.38-.113l7.072-8z" clipRule="evenodd" />
        </svg>
      ),
    };

    // Arkeo Logo Component
    const ArkeoLogo = ({ size = 44 }) => (
      <img
        src="images/arkeo-logo-200px_1.png"
        alt="Arkeo"
        style={{ width: size, height: size, objectFit: 'contain' }}
        className="rounded-full bg-arkeo/10 p-1 shadow-sm"
      />
    );

    // Stats Card
    const StatsCard = ({ icon, label, value, subvalue, color }) => (
      <div className="card-surface card-shadow backdrop-blur rounded-2xl p-5 transition-all hover:border-arkeo/60">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-secondaryText text-sm mb-1">{label}</p>
            <p className={`text-3xl font-bold ${color || 'text-white'}`}>{value}</p>
            {subvalue && <p className="text-secondaryText text-xs mt-1">{subvalue}</p>}
          </div>
          <div className="p-3 rounded-xl bg-arkeo/15 text-arkeo">{icon}</div>
        </div>
      </div>
    );

    // Infrastructure Badge
    const InfrastructureBadge = () => null;

    // Earnings Display Component
    const EarningsDisplay = ({ earnings, range, onRangeChange, decimals = 2 }) => {
      const [period, setPeriod] = useState('all_time');
      const activePeriod = range || period;

      const periods = [
        { id: 'daily', label: 'Daily' },
        { id: 'weekly', label: 'Weekly' },
        { id: 'monthly', label: 'Monthly' },
        { id: 'all_time', label: 'All Time' },
      ];

      return (
        <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-xl p-3">
          <div className="flex items-center gap-1 text-emerald-400 text-xs font-medium mb-2">
            <Icons.DollarSign /> <span>Earnings</span>
          </div>
          <div className="flex flex-wrap gap-1 mb-2">
            {periods.map(p => (
              <button
                key={p.id}
                onClick={(e) => { e.stopPropagation(); onRangeChange?.(p.id); if (!range) setPeriod(p.id); }}
                className={`px-2 py-0.5 rounded text-xs font-medium transition-all ${activePeriod === p.id ? 'bg-emerald-500 text-slate-900' : 'text-emerald-400 hover:bg-emerald-500/20'}`}
              >
                {p.label}
              </button>
            ))}
          </div>
          <p className="text-xl font-bold text-emerald-400">{formatArkeo(earnings[activePeriod], decimals)} <span className="text-sm font-normal">ARKEO</span></p>
        </div>
      );
    };

    // Location Filter Dropdown
    const LocationFilter = ({ selectedRegion, onSelect }) => {
      const [isOpen, setIsOpen] = useState(false);
      const [query, setQuery] = useState('');
      const selected = REGIONS.find(r => r.id === selectedRegion) || REGIONS[0];
      const filteredRegions = REGIONS.filter(r => (r.name || '').toLowerCase().includes((query || '').toLowerCase()));

      return (
        <div className="relative min-w-0">
          <button
            onClick={() => setIsOpen(!isOpen)}
            className="flex items-center gap-2 card-surface rounded-xl px-4 py-3 text-white hover:border-arkeo/60 transition-all min-w-[200px] w-full"
            style={{ minWidth: '220px' }}
          >
            <Icons.MapPin />
            <span className="flex-1 text-left text-sm truncate">{selected.icon} {selected.name}</span>
            <Icons.ChevronDown />
          </button>
          
          {isOpen && (
            <>
              <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />
              <div className="absolute top-full left-0 right-0 mt-2 bg-[var(--surface)] border border-[var(--border)] rounded-xl shadow-2xl py-2 z-50 max-h-80 overflow-y-auto">
                <div className="px-3 pb-2">
                  <input
                    type="text"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Search regions..."
                    className="w-full bg-[#1E222C] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-white placeholder-secondaryText focus:border-arkeo focus:ring-1 focus:ring-arkeo"
                  />
                </div>
                {filteredRegions.map(region => (
                  <button
                    key={region.id}
                    onClick={() => { onSelect(region.id); setIsOpen(false); }}
                    className={`w-full text-left px-4 py-2.5 text-sm transition-colors flex items-center gap-2 ${selectedRegion === region.id ? 'bg-arkeo/15 text-white' : 'text-secondaryText hover:bg-[#1E222C]'}`}
                  >
                    <span>{region.icon}</span>
                    <span>{region.name}</span>
                  </button>
                ))}
                {filteredRegions.length === 0 && <p className="text-secondaryText text-xs px-4 py-2.5">No regions</p>}
              </div>
            </>
          )}
        </div>
      );
    };

    const DataServiceFilter = ({ selected, onSelect, options }) => {
      const [isOpen, setIsOpen] = useState(false);
      const [query, setQuery] = useState('');
      const normalizedOpts = (options || []).map((o) => ({
        id: o?.id ?? '',
        name: typeof o?.name === 'string' ? o.name : String(o?.name ?? ''),
        icon: o?.icon || '🌐',
        iconUrl: o?.iconUrl || '',
      }));
      const opts = [{ id: 'all', name: 'All Data Types', icon: '🌐', iconUrl: '' }, ...normalizedOpts];
      const active = opts.find(o => o.id === selected) || opts[0];
      const filtered = opts.filter(o => (o.name || '').toLowerCase().includes((query || '').toLowerCase()));

      return (
        <div className="relative min-w-0">
          <button onClick={() => setIsOpen(!isOpen)} className="flex items-center gap-2 card-surface rounded-xl px-4 py-3 text-white hover:border-arkeo/60 transition-all min-w-[200px] w-full">
            <Icons.Server />
            <span className="flex-1 text-left text-sm truncate">{active.name}</span>
            <Icons.ChevronDown />
          </button>
          {isOpen && (
            <>
              <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />
              <div className="absolute top-full left-0 right-0 mt-2 bg-[var(--surface)] border border-[var(--border)] rounded-xl shadow-2xl py-2 z-50 max-h-72 overflow-y-auto">
                <div className="px-3 pb-2">
                  <input
                    autoFocus
                    value={query}
                    onChange={e => setQuery(e.target.value)}
                    placeholder="Search services..."
                    className="w-full bg-[var(--bg-main)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-white placeholder-secondaryText focus:border-arkeo focus:ring-1 focus:ring-arkeo"
                  />
                </div>
                {filtered.map(opt => (
                  <button
                    key={opt.id}
                    onClick={() => { onSelect(opt.id); setIsOpen(false); setQuery(''); }}
                    className={`w-full text-left px-4 py-2.5 text-sm transition-colors flex items-center gap-2 ${selected === opt.id ? 'bg-arkeo/15 text-white' : 'text-secondaryText hover:bg-[#1E222C]'}`}
                  >
                    {opt.iconUrl ? (
                      <span className="w-7 h-7 rounded-full overflow-hidden bg-[#0f121a] flex items-center justify-center border border-[var(--border)]">
                        <img src={opt.iconUrl} alt={opt.name} className="w-6 h-6 object-contain" />
                      </span>
                    ) : (
                      <span className="w-7 h-7 rounded-full bg-[#0f121a] flex items-center justify-center border border-[var(--border)] text-sm">{opt.icon}</span>
                    )}
                    <span>{opt.name}</span>
                  </button>
                ))}
                {filtered.length === 0 && <p className="text-secondaryText text-xs px-4 py-3">No matches</p>}
              </div>
            </>
          )}
        </div>
      );
    };

    const SimpleDropdown = ({ label, selected, options, onChange }) => {
      const [isOpen, setIsOpen] = useState(false);
      const active = options.find(o => o.id === selected) || options[0];
      return (
        <div className="relative min-w-0">
          <button className="flex items-center gap-2 card-surface rounded-xl px-4 py-3 text-white hover:border-arkeo/60 transition-all min-w-[200px] w-full" onClick={() => setIsOpen(!isOpen)}>
            <span className="text-sm text-secondaryText">{label}</span>
            <span className="flex-1 text-left text-sm text-white truncate">{active.label}</span>
            <Icons.ChevronDown />
          </button>
          {isOpen && (
            <>
              <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />
              <div className="absolute top-full left-0 right-0 mt-2 bg-[var(--surface)] border border-[var(--border)] rounded-xl shadow-2xl py-2 z-50">
                {options.map(opt => (
                  <button
                    key={opt.id}
                    onClick={() => { onChange(opt.id); setIsOpen(false); }}
                    className={`w-full text-left px-4 py-2 text-sm transition-colors ${opt.id === selected ? 'bg-arkeo/15 text-white' : 'text-secondaryText hover:bg-[#1E222C]'}`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </>
          )}
        </div>
      );
    };

    const SortDropdown = ({ selected, options, onChange, showOffline, onToggleOffline, disableCost }) => {
      const [isOpen, setIsOpen] = useState(false);
      const active = options.find(o => o.id === selected) || options[0];
      return (
        <div className="relative min-w-0">
          <button className="flex items-center gap-2 card-surface rounded-xl px-4 py-3 text-white hover:border-arkeo/60 transition-all min-w-[200px] w-full" onClick={() => setIsOpen(!isOpen)}>
            <span className="text-sm text-secondaryText">Sort By</span>
            <span className="flex-1 text-left text-sm text-white truncate">{active.label}</span>
            <Icons.ChevronDown />
          </button>
          {isOpen && (
            <>
              <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />
              <div className="absolute top-full left-0 right-0 mt-2 bg-[var(--surface)] border border-[var(--border)] rounded-xl shadow-2xl py-2 z-50">
                {options.map(opt => {
                  const disabled = disableCost && opt.id === 'cost';
                  return (
                  <button
                    key={opt.id}
                    onClick={() => { if (disabled) return; onChange(opt.id); setIsOpen(false); }}
                    className={`w-full text-left px-4 py-2 text-sm transition-colors flex items-center justify-between ${opt.id === selected ? 'bg-arkeo/15 text-white' : 'text-secondaryText hover:bg-[#1E222C]'} ${disabled ? 'opacity-40 cursor-not-allowed' : ''}`}
                    disabled={disabled}
                  >
                    <span>{opt.label}</span>
                    {disabled && <span className="text-[10px] text-secondaryText">Select a data type</span>}
                  </button>
                  );
                })}
                <div className="border-t border-[var(--border)] mt-1 pt-1">
                  <button
                    onClick={() => { onToggleOffline?.(!showOffline); setIsOpen(false); }}
                    className="w-full text-left px-4 py-2 text-sm flex items-center gap-2 text-secondaryText hover:bg-[#1E222C]"
                  >
                    <span className={`w-5 h-5 rounded border flex items-center justify-center ${showOffline ? 'border-arkeo bg-arkeo/20 text-arkeo' : 'border-[var(--border)] text-transparent'}`}>{showOffline ? '✓' : ''}</span>
                    Show Offline
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      );
    };

    // Provider Card
  const ProviderCard = ({ provider, onOpenContract, serviceFilter, timeRange, onRangeChange, earnings }) => {
    const isOnline = provider.status === 'ONLINE';
    const selectedService =
      serviceFilter && serviceFilter !== 'all'
        ? (provider.services || []).find(s => String(s.id) === String(serviceFilter))
        : null;
    
    return (
        <div className={`card-surface card-shadow backdrop-blur rounded-2xl overflow-hidden transition-all ${isOnline ? 'hover:border-arkeo/60 hover:shadow-[0_10px_30px_rgba(59,224,255,0.12)]' : 'opacity-70'}`}>
            <div className="p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="font-bold text-lg text-white">{provider.moniker}</h3>
                  <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${isOnline ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'}`}>{provider.status}</span>
                </div>
                {provider.location && (
                  <div className="flex items-center gap-2 text-secondaryText text-sm">
                    <span className="flex items-center gap-1"><Icons.Globe />{provider.location}</span>
                  </div>
                )}
              </div>
              <a href={`provider.html?id=${provider.id}`} className="flex items-center gap-1 text-secondaryText hover:text-white text-sm px-2 py-1 rounded-lg hover:bg-[#1E222C]" title="View provider details">
                Details <Icons.External />
              </a>
            </div>

            <p className="text-secondaryText text-sm mb-4 line-clamp-2">{provider.description}</p>

            {selectedService ? (
              <div className="grid grid-cols-2 gap-2 mb-4">
                <div className="text-center p-2 rounded-lg bg-[#1E222C]">
                  <p className="text-xs text-secondaryText mb-1">Cost</p>
                  <p className="text-lg font-bold text-white">
                    {formatArkeo(selectedService.paygoRate, 8)} <span className="text-xs text-secondaryText">ARKEO/query</span>
                  </p>
                </div>
                <div className="text-center p-2 rounded-lg bg-[#1E222C]">
                  <p className="text-xs text-secondaryText mb-1">Data Services</p>
                  <p className="text-lg font-bold text-white">{serviceFilter === 'all' ? provider.services.length : provider.services.filter(s => String(s.id) === String(serviceFilter)).length}</p>
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-1 gap-2 mb-4">
                <div className="text-center p-2 rounded-lg bg-[#1E222C]">
                  <p className="text-xs text-secondaryText mb-1">Data Services</p>
                  <p className="text-lg font-bold text-white">{provider.services.length}</p>
                </div>
              </div>
            )}

            {/* Earnings Display */}
            <div className="mb-4">
              <EarningsDisplay earnings={earnings} range={timeRange} onRangeChange={onRangeChange} decimals={8} />
            </div>
          </div>
        </div>
      );
    };

    // Smart Select Modal - Updated with all services
    const SmartSelectModal = ({ isOpen, onClose, onSuccess, timeRange, onRangeChange, providers, serviceOptions, computeEarnings }) => {
      const [selectedService, setSelectedService] = useState(null);
      const [selectedCriteria, setSelectedCriteria] = useState('price');
      const [step, setStep] = useState(1);
      const [txState, setTxState] = useState('idle');
      const [recommendedProvider, setRecommendedProvider] = useState(null);

      useEffect(() => { if (isOpen) { setStep(1); setSelectedService(null); setTxState('idle'); setRecommendedProvider(null); } }, [isOpen]);

      if (!isOpen) return null;

      const findBestProvider = () => {
        const providersWithService = (providers || []).filter(p => p.status === 'ONLINE' && p.services.some(s => s.id === selectedService));
        if (providersWithService.length === 0) return null;
        
        let sorted;
        switch (selectedCriteria) {
          case 'price': sorted = providersWithService.sort((a, b) => parseInt(a.services.find(s => s.id === selectedService)?.paygoRate || '999') - parseInt(b.services.find(s => s.id === selectedService)?.paygoRate || '999')); break;
          case 'latency': sorted = providersWithService.sort((a, b) => b.uptime - a.uptime); break;
          case 'uptime': sorted = providersWithService.sort((a, b) => b.uptime - a.uptime); break;
          default: sorted = providersWithService.sort((a, b) => b.uptime - a.uptime);
        }
        return sorted[0];
      };

      const handleFindProvider = () => { setRecommendedProvider(findBestProvider()); setStep(3); };

      const handleSubmit = async () => {
        setTxState('signing');
        await new Promise(r => setTimeout(r, 1500));
        setTxState('broadcasting');
        await new Promise(r => setTimeout(r, 2000));
        setTxState('success');
        onSuccess?.();
      };

      const criteria = SMART_SELECT_CRITERIA.find(c => c.id === selectedCriteria);

      return (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={onClose}>
          <div className="card-surface card-shadow rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-6 border-b border-[var(--border)]">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-arkeo/15 text-arkeo"><Icons.Wand /></div>
                <div>
                  <h2 className="text-xl font-bold text-white">Smart Provider Selection</h2>
                  <p className="text-secondaryText text-sm">Find the best provider for your needs</p>
                </div>
              </div>
              <button onClick={onClose} className="p-2 hover:bg-[#1E222C] rounded-xl text-secondaryText"><Icons.Close /></button>
            </div>

            {txState === 'success' ? (
              <div className="p-8 text-center">
                <div className="w-20 h-20 bg-emerald-500/20 rounded-full flex items-center justify-center mx-auto mb-6 text-emerald-400"><Icons.Check /></div>
                <h3 className="text-2xl font-bold text-white mb-2">Contract Opened!</h3>
                <p className="text-secondaryText mb-6">Your contract with {recommendedProvider?.moniker} is now active.</p>
                <button onClick={onClose} className="w-full primary-gradient text-white font-semibold py-3 rounded-xl primary-shadow">Done</button>
              </div>
            ) : txState !== 'idle' ? (
              <div className="p-8 text-center">
                <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-6" />
                <p className="text-lg font-medium text-white">{txState === 'signing' ? 'Sign in Wallet...' : 'Broadcasting...'}</p>
              </div>
            ) : (
              <>
                <div className="flex items-center justify-center gap-2 py-4 border-b border-[var(--border)]">
                  {[1, 2, 3].map(s => (
                    <React.Fragment key={s}>
                      <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${step >= s ? 'bg-primary text-white' : 'bg-[#1E222C] text-secondaryText'}`}>{step > s ? '✓' : s}</div>
                      {s < 3 && <div className={`w-12 h-0.5 ${step > s ? 'bg-primary' : 'bg-[#1E222C]'}`} />}
                    </React.Fragment>
                  ))}
                </div>

                <div className="p-6">
                  {step === 1 && (
                    <>
                      <h3 className="text-lg font-semibold text-white mb-4">Select Service / Chain</h3>
                      <p className="text-secondaryText text-sm mb-4">Choose from all supported blockchains on the Arkeo marketplace</p>
                      <div className="grid grid-cols-3 gap-3">
                        {(serviceOptions || []).filter(s => s.id !== 'all').map(svc => (
                          <button key={svc.id} onClick={() => setSelectedService(svc.id)} className={`p-4 rounded-xl border-2 text-center transition-all ${selectedService === svc.id ? 'border-primary bg-primary/10' : 'border-[var(--border)] bg-[var(--surface)] hover:border-primary/40'}`}>
                            <span className="text-2xl mb-2 block">
                              {svc.iconUrl ? <img src={svc.iconUrl} alt={svc.name} className="w-8 h-8 mx-auto rounded-full" /> : (svc.icon || '🌐')}
                            </span>
                            <p className="font-medium text-white text-sm">{svc.name}</p>
                          </button>
                        ))}
                      </div>
                    </>
                  )}

                  {step === 2 && (
                    <>
                      <h3 className="text-lg font-semibold text-white mb-4">What matters most?</h3>
                      <div className="space-y-3">
                        {SMART_SELECT_CRITERIA.map(c => (
                          <button key={c.id} onClick={() => setSelectedCriteria(c.id)} className={`w-full p-4 rounded-xl border-2 text-left flex items-center gap-4 ${selectedCriteria === c.id ? 'border-primary bg-primary/10' : 'border-[var(--border)] bg-[var(--surface)] hover:border-primary/40'}`}>
                            <span className="text-2xl">{c.icon}</span>
                            <div><p className="font-semibold text-white">{c.label}</p><p className="text-sm text-secondaryText">{c.description}</p></div>
                          </button>
                        ))}
                      </div>
                    </>
                  )}

                  {step === 3 && recommendedProvider && (
                    <>
                      <div className="bg-primary/10 border border-primary/40 rounded-xl p-4 mb-6">
                        <p className="text-arkeo text-sm mb-1">🎯 Best match for {criteria?.label}</p>
                        <p className="text-white font-bold text-lg">{recommendedProvider.moniker}</p>
                        <p className="text-secondaryText text-sm">{recommendedProvider.location}</p>
                      </div>
                      <div className="card-surface rounded-xl p-4 mb-4">
                        <div className="grid grid-cols-3 gap-4 text-center">
                          <div><p className="text-2xl font-bold text-white">{recommendedProvider.uptime}%</p><p className="text-xs text-secondaryText">Reliability</p></div>
                          <div><p className="text-2xl font-bold text-white">{serviceFilter === 'all' ? recommendedProvider.services.length : recommendedProvider.services.filter(s => s.id === serviceFilter).length}</p><p className="text-xs text-secondaryText">Services</p></div>
                          <div><p className="text-2xl font-bold text-white">{recommendedProvider.location}</p><p className="text-xs text-secondaryText">Location</p></div>
                        </div>
                      </div>
                  <EarningsDisplay earnings={computeEarnings ? computeEarnings(recommendedProvider) : { daily: 0, weekly: 0, monthly: 0, all_time: 0 }} range={timeRange} onRangeChange={onRangeChange} />
                    </>
                  )}

                  {step === 3 && !recommendedProvider && (
                    <div className="text-center py-8">
                      <p className="text-secondaryText">No providers found for this service. Try a different chain.</p>
                    </div>
                  )}
                </div>

                <div className="p-6 border-t border-[var(--border)] flex gap-3">
                  {step > 1 && <button onClick={() => setStep(step - 1)} className="flex-1 px-4 py-3 rounded-xl font-medium secondary-btn hover:brightness-110">Back</button>}
                  {step < 3 ? (
                    <button onClick={() => step === 2 ? handleFindProvider() : setStep(step + 1)} disabled={step === 1 && !selectedService} className="flex-1 primary-gradient text-white font-semibold py-3 rounded-xl primary-shadow disabled:opacity-40 disabled:cursor-not-allowed">
                      {step === 2 ? 'Find Best Provider' : 'Continue'}
                    </button>
                  ) : recommendedProvider && (
                    <button onClick={handleSubmit} className="flex-1 primary-gradient text-white font-semibold py-3 rounded-xl flex items-center justify-center gap-2 primary-shadow">
                      <Icons.Zap /> Open Contract
                    </button>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      );
    };

    // Become Provider Modal
    const BecomeProviderModal = ({ isOpen, onClose, onCopy, providerEnvExample, providerRunCmd }) => {
      const [step, setStep] = useState(2);

      useEffect(() => { if (isOpen) { setStep(2); } }, [isOpen]);

      if (!isOpen) return null;

      return (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={onClose}>
          <div className="card-surface card-shadow rounded-2xl max-w-3xl w-full max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-6 border-b border-[var(--border)]">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-arkeo/15 text-arkeo"><Icons.Server /></div>
                <div>
                  <h2 className="text-xl font-bold text-white">Become a Data Provider</h2>
                  <p className="text-secondaryText text-sm">Start earning ARKEO</p>
                </div>
              </div>
              <button onClick={onClose} className="p-2 hover:bg-[#1E222C] rounded-xl text-secondaryText"><Icons.Close /></button>
            </div>

            <div className="p-6">
              {step === 2 && (
                <>
                  <div className="mb-5 space-y-2">
                    <p className="text-secondaryText text-sm">The Arkeo Provider Data Engine lets you turn existing infrastructure into steady revenue by publishing services to the marketplace. Run the provider core and admin UI to list endpoints, set pricing, and get paid in ARKEO as subscribers use your data.</p>
                    <a href="https://github.com/arkeonetwork/arkeo-data-engine/blob/main/provider-core/README.md" target="_blank" rel="noopener noreferrer" className="text-arkeo text-sm font-semibold inline-flex items-center gap-2 hover:brightness-110">
                        Provider install guide <Icons.External />
                    </a>
                  </div>
                <div className="mt-6 flex gap-3">
                  <button onClick={onClose} className="flex-1 px-4 py-3 rounded-xl font-medium secondary-btn hover:brightness-110">Back</button>
                  <a href="https://github.com/arkeonetwork/arkeo-data-engine/blob/main/provider-core/README.md" target="_blank" className="flex-1 primary-gradient text-white font-semibold py-3 rounded-xl flex items-center justify-center gap-2 primary-shadow">
                    View on GitHub <Icons.External />
                  </a>
                </div>
              </>
            )}

            </div>
          </div>
        </div>
      );
    };

    // Become Subscriber Modal
    const BecomeSubscriberModal = ({ isOpen, onClose, onCopy, subscriberEnvExample, subscriberRunCmd }) => {
      const [step, setStep] = useState(2);

      useEffect(() => { if (isOpen) { setStep(2); } }, [isOpen]);

      if (!isOpen) return null;

      return (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={onClose}>
          <div className="card-surface rounded-2xl max-w-3xl w-full shadow-2xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-6 border-b border-[var(--border)]">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-arkeo/15 text-arkeo"><Icons.Wand /></div>
                <div>
                  <h2 className="text-xl font-bold text-white">Become a Data Subscriber</h2>
                  <p className="text-secondaryText text-sm">Start using ARKEO</p>
                </div>
              </div>
              <button onClick={onClose} className="p-2 hover:bg-[#1E222C] rounded-xl text-secondaryText"><Icons.Close /></button>
            </div>

            <div className="p-6">
              {step === 2 && (
                <>
                  <div className="mb-5 space-y-2">
                    <p className="text-secondaryText text-sm">Arkeo Subscriber Data Engine gives developers and users a managed way to consume blockchain data through a docker-based listener proxy. It auto-selects providers by service and region, handles PAYG contracts and hot-wallet payments, and adds cost-effective failover so your apps stay online without locking into a single provider.</p>
                    <a href="https://github.com/arkeonetwork/arkeo-data-engine/blob/main/subscriber-core/README.md" target="_blank" rel="noopener noreferrer" className="text-arkeo text-sm font-semibold inline-flex items-center gap-2 hover:brightness-110">
                      Subscriber install guide <Icons.External />
                    </a>
                  </div>
                <div className="mt-6 flex gap-3">
                  <button onClick={onClose} className="flex-1 px-4 py-3 rounded-xl font-medium secondary-btn hover:brightness-110">Back</button>
                  <a href="https://github.com/arkeonetwork/arkeo-data-engine/blob/main/subscriber-core/README.md" target="_blank" className="flex-1 primary-gradient text-white font-semibold py-3 rounded-xl flex items-center justify-center gap-2 primary-shadow">
                    View on GitHub <Icons.External />
                  </a>
                </div>
              </>
            )}
            </div>
          </div>
        </div>
      );
    };
    // How It Works Modal (one-time popup and on-demand)
    const HowItWorksModal = ({ isOpen, onClose, timeRange, onRangeChange }) => {
      if (!isOpen) return null;
      return (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={onClose}>
          <div className="card-surface rounded-2xl max-w-4xl w-full shadow-2xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-6 border-b border-[var(--border)]">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-arkeo/15 text-arkeo"><Icons.Wand /></div>
                <div>
                  <h2 className="text-xl font-bold text-white">See How Arkeo Works in Action</h2>
                  <p className="text-secondaryText text-sm">A Brief Walkthrough for Providers and Subscribers</p>
                </div>
              </div>
              <button onClick={onClose} className="p-2 hover:bg-[#1E222C] rounded-xl text-secondaryText"><Icons.Close /></button>
            </div>
            <div className="px-6 pb-6 grid md:grid-cols-2 gap-6 items-start">
              <div className="space-y-3">
                <p className="text-secondaryText text-sm">Arkeo is an open data marketplace where anyone can publish or consume data services with trustless metering and automatic settlement.</p>
                <div className="flex items-start gap-2 text-secondaryText text-sm">
                  <span className="text-arkeo mt-0.5"><Icons.CheckCircle /></span>
                  <p>Providers list endpoints, set prices, and earn ARKEO as subscribers use their services.</p>
                </div>
                <div className="flex items-start gap-2 text-secondaryText text-sm">
                  <span className="text-arkeo mt-0.5"><Icons.CheckCircle /></span>
                  <p>Subscribers get reliable access with optimized performance and major cost savings.</p>
                </div>
                <div className="flex items-start gap-2 text-secondaryText text-sm">
                  <span className="text-arkeo mt-0.5"><Icons.CheckCircle /></span>
                  <p>Smart routing and reputation keep the marketplace efficient and fair.</p>
                </div>
                <p className="text-secondaryText text-sm font-semibold">Watch how Arkeo works and see the network in action.</p>
                <div className="flex gap-3 mt-4 pt-1">
                  <a href="https://docs.arkeo.network" target="_blank" className="secondary-btn px-4 py-2.5 rounded-xl font-medium border border-[var(--border)] hover:brightness-110">View Docs</a>
                  <button onClick={onClose} className="bg-arkeo text-white font-semibold px-4 py-2.5 rounded-xl shadow-lg hover:brightness-110 transition-all">Got it</button>
                </div>
              </div>
              <div className="relative rounded-2xl overflow-hidden border border-[var(--border)] shadow-lg">
                <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(255,79,210,0.15),transparent_55%),radial-gradient(circle_at_bottom_left,rgba(255,138,43,0.15),transparent_55%)]" />
                <div className="relative aspect-video">
                  <iframe
                    src="https://www.youtube.com/embed/nCgQDjiotG0?rel=0"
                    title="See How Arkeo Works in Action"
                    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                    allowFullScreen
                    loading="lazy"
                    className="absolute inset-0 w-full h-full"
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      );
    };

    // Open Contract Modal
    const OpenContractModal = ({ provider, earnings, isOpen, onClose, onSuccess, timeRange, onRangeChange, serviceOptions }) => {
      const [selectedService, setSelectedService] = useState(null);
      const [txState, setTxState] = useState('idle');

      useEffect(() => { if (isOpen && provider?.services?.length) { setSelectedService(provider.services[0].id); setTxState('idle'); } }, [isOpen, provider]);

      if (!isOpen || !provider) return null;

      const service = provider.services.find(s => s.id === selectedService);
      const cost = service ? (parseInt(service.paygoRate) * 10000) / ARKEO_DIVISOR : 0;

      const handleSubmit = async () => {
        setTxState('signing');
        await new Promise(r => setTimeout(r, 1500));
        setTxState('broadcasting');
        await new Promise(r => setTimeout(r, 2000));
        setTxState('success');
        onSuccess?.();
      };

      if (txState === 'success') {
        return (
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={onClose}>
            <div className="card-surface rounded-2xl max-w-lg w-full p-8 text-center" onClick={e => e.stopPropagation()}>
              <div className="w-20 h-20 bg-emerald-500/20 rounded-full flex items-center justify-center mx-auto mb-6 text-emerald-400"><Icons.Check /></div>
              <h3 className="text-2xl font-bold text-white mb-2">Contract Opened!</h3>
              <p className="text-secondaryText mb-6">Your contract with {provider.moniker} is active.</p>
              <button onClick={onClose} className="w-full primary-gradient text-white font-semibold py-3 rounded-xl primary-shadow">Done</button>
            </div>
          </div>
        );
      }

      if (txState !== 'idle') {
        return (
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="card-surface rounded-2xl max-w-lg w-full p-8 text-center">
              <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-6" />
              <p className="text-lg font-medium text-white">{txState === 'signing' ? 'Sign in Wallet...' : 'Broadcasting...'}</p>
            </div>
          </div>
        );
      }

      return (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={onClose}>
          <div className="card-surface rounded-2xl max-w-lg w-full shadow-2xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-6 border-b border-[var(--border)]">
              <h2 className="text-xl font-bold text-white">Open Contract</h2>
              <button onClick={onClose} className="p-2 hover:bg-[#1E222C] rounded-xl text-secondaryText"><Icons.Close /></button>
            </div>
            <div className="p-6 space-y-5">
              <div className="card-surface rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <div><h3 className="font-bold text-white">{provider.moniker}</h3><p className="text-secondaryText text-sm">{provider.location}</p></div>
                </div>
              </div>
              
              <EarningsDisplay earnings={earnings || { daily: 0, weekly: 0, monthly: 0, all_time: 0 }} range={timeRange} onRangeChange={onRangeChange} />
              
              <div>
                <label className="block text-sm font-medium text-secondaryText mb-2">Select Service</label>
                <div className="grid grid-cols-2 gap-2">
                  {provider.services.map(svc => {
                    const svcInfo = (serviceOptions || []).find(s => s.id === svc.id);
                    return (
                      <button key={svc.id} onClick={() => setSelectedService(svc.id)} className={`p-3 rounded-xl text-left ${selectedService === svc.id ? 'bg-primary/10 border-2 border-primary' : 'bg-[var(--surface)] border-2 border-transparent hover:border-primary/40'}`}>
                        <p className="font-medium text-white text-sm flex items-center gap-2">
                          {svcInfo?.iconUrl ? <img src={svcInfo.iconUrl} alt={svc.name} className="w-5 h-5 rounded-full" /> : (svcInfo?.icon || '🌐')}
                          <span>{svc.name}</span>
                        </p>
                        <p className="text-xs text-secondaryText">{formatArkeo(svc.paygoRate, 8)} ARKEO/query</p>
                      </button>
                    );
                  })}
                </div>
              </div>
              <div className="bg-primary/10 border border-primary/40 rounded-xl p-4">
                <div className="flex justify-between items-center">
                  <span className="text-arkeo">Deposit (≈10K queries)</span>
                  <span className="text-2xl font-bold text-white">{cost.toFixed(4)} ARKEO</span>
                </div>
              </div>
            </div>
            <div className="p-6 border-t border-[var(--border)]">
              <button onClick={handleSubmit} className="w-full primary-gradient text-white font-semibold py-3 rounded-xl flex items-center justify-center gap-2 primary-shadow">
                <Icons.Zap /> Open PAYG Contract
              </button>
            </div>
          </div>
        </div>
      );
    };

    // Main App
    function App() {
      const [providers, setProviders] = useState([]);
      const [counts, setCounts] = useState(null);
      const [dashboardInfo, setDashboardInfo] = useState(null);
      const [loading, setLoading] = useState(true);
      const [error, setError] = useState(null);
      const [rangeTotals, setRangeTotals] = useState(null);
      const [activeServices, setActiveServices] = useState([]);
      const [activeServiceTypes, setActiveServiceTypes] = useState([]);
      const [showBecomeProvider, setShowBecomeProvider] = useState(false);
      const [showContractModal, setShowContractModal] = useState(false);
      const [showHowItWorks, setShowHowItWorks] = useState(false);
      const [showSubscriberModal, setShowSubscriberModal] = useState(false);
      const [contractProvider, setContractProvider] = useState(null);
      const [serviceFilter, setServiceFilter] = useState('all');
      const [regionFilter, setRegionFilter] = useState('all');
      const [providerSearch, setProviderSearch] = useState('');
      const [timeRange, setTimeRange] = useState('all_time');
      const [sortBy, setSortBy] = useState('earnings');
      const [showOffline, setShowOffline] = useState(false);
      const [notification, setNotification] = useState(null);
      const [hideInfoBlock, setHideInfoBlock] = useState(false);
      const [showCookieBanner, setShowCookieBanner] = useState(false);
      const [showPrivacyModal, setShowPrivacyModal] = useState(false);
      const [optOutSale, setOptOutSale] = useState(false);
      const showNotif = useCallback((msg) => {
        setNotification(msg);
        setTimeout(() => setNotification(null), 3000);
      }, []);
      const handleCopy = useCallback((txt) => {
        if (!txt) return;
        try {
          navigator.clipboard?.writeText(txt);
        } catch (e) {
          // ignore clipboard failures
        }
        showNotif('Copied!');
      }, [showNotif]);
      const latestHeight = useMemo(() => {
        if (!dashboardInfo || dashboardInfo.block_height === undefined || dashboardInfo.block_height === null) return null;
        const h = parseInt(dashboardInfo.block_height, 10);
        return Number.isFinite(h) ? h : null;
      }, [dashboardInfo]);
      const blockTimeSeconds = useMemo(() => {
        const val = parseFloat(dashboardInfo?.block_time_seconds || BLOCK_TIME_FALLBACK);
        return Number.isFinite(val) ? val : BLOCK_TIME_FALLBACK;
      }, [dashboardInfo]);
      const buildEarnings = useCallback((provider) => {
        const heightHint = rangeTotals?.latest_height ?? latestHeight;
        const blockHint = rangeTotals?.block_time_seconds ?? blockTimeSeconds;
        return {
          daily: getEarningsByRange(provider, 'daily', latestHeight, blockTimeSeconds, heightHint, blockHint),
          weekly: getEarningsByRange(provider, 'weekly', latestHeight, blockTimeSeconds, heightHint, blockHint),
          monthly: getEarningsByRange(provider, 'monthly', latestHeight, blockTimeSeconds, heightHint, blockHint),
          all_time: getEarningsByRange(provider, 'all_time', latestHeight, blockTimeSeconds, heightHint, blockHint),
        };
      }, [rangeTotals, latestHeight, blockTimeSeconds]);
      const normalizeProviders = useCallback((payload) => {
        const list = Array.isArray(payload?.providers) ? payload.providers : [];
        return list.map((p, idx) => {
          const meta = p.metadata || {};
          const raw = p.provider || {};
          const metaConfig = typeof meta === 'object' ? (meta.config || {}) : {};
          const name = meta.name || meta.moniker || metaConfig.moniker || p.provider_moniker || raw.moniker || raw.name || `Provider ${idx + 1}`;
          const description = meta.description || meta.desc || raw.description || raw.desc || '';
          const location = meta.location || meta.geo || metaConfig.location || raw.location || '';
          const region =
            regionSlug(meta.region || metaConfig.region || raw.region) ||
            regionSlug(meta.location || meta.geo || metaConfig.location || raw.location) ||
            'all';
          const statusVal = p.status;
          const isOnline = statusVal === 1 || statusVal === '1' || statusVal === true || (typeof statusVal === 'string' && statusVal.toLowerCase() === 'online');
          const servicesRaw = Array.isArray(p.services) ? p.services : [];
          const services = servicesRaw.map((s) => {
            const id = s.id ?? s.service_id ?? s.service ?? s.serviceId;
            const svcName = s.name || s.display || s.slug || s.type || `Service ${id ?? ''}`.trim();
            const payAmt = s.pay_as_you_go_rate?.amount ?? s.raw?.pay_as_you_go_rate?.amount ?? (Array.isArray(s.raw?.pay_as_you_go_rates) ? s.raw.pay_as_you_go_rates[0]?.amount : 0) ?? 0;
            const denom = s.pay_as_you_go_rate?.denom ?? s.raw?.pay_as_you_go_rate?.denom ?? 'uarkeo';
            const chainSlug = chainSlugFromServiceName(svcName);
            const iconUrl = chainIconUrl(chainSlug);
            return { id: id ?? svcName, name: svcName, paygoRate: payAmt || 0, denom, raw: s.raw || s, iconUrl };
          });
          const contracts = Array.isArray(p.contracts) ? p.contracts : [];
          return {
            id: p.pubkey || `provider-${idx}`,
            pubKey: p.pubkey,
            moniker: name,
            description,
            location: location || 'Unknown',
            region: region || 'all',
            infrastructure: meta.infrastructure || '',
            status: isOnline ? 'ONLINE' : 'OFFLINE',
            totalContracts: contracts.length,
            activeContracts: contracts.length,
            uptime: meta.uptime || raw.uptime || 0,
            avgLatency: meta.latency || raw.latency || null,
            reputation: meta.reputation || raw.reputation || null,
            earnings: {},
            services,
            contracts,
          };
        });
      }, []);
      const loadData = useCallback(async () => {
        try {
          setLoading(true);
          setError(null);
          const [countsRes, providersRes, infoRes, activeSvcRes, activeSvcTypesRes] = await Promise.all([
            fetch(`${API_BASE}/api/cache-counts`).then(r => r.json()).catch(() => ({})),
            fetch(`${API_BASE}/api/providers-with-contracts`).then(r => r.json()).catch(() => ({})),
            fetch(`${API_BASE}/api/dashboard-info`).then(r => r.json()).catch(() => ({})),
            fetch(`${API_BASE}/api/active-services`).then(r => r.json()).catch(() => ({})),
            fetch(`${API_BASE}/api/active-service-types`).then(r => r.json()).catch(() => ({})),
          ]);
          setCounts(countsRes || {});
          setDashboardInfo(infoRes || {});
          setProviders(normalizeProviders(providersRes || {}));
          const activeSvcList = Array.isArray(activeSvcRes?.active_services) ? activeSvcRes.active_services : [];
          setActiveServices(activeSvcList);
          const activeSvcTypesList = Array.isArray(activeSvcTypesRes?.active_service_types) ? activeSvcTypesRes.active_service_types : [];
          setActiveServiceTypes(activeSvcTypesList);
        } catch (e) {
          setError('Failed to load data');
        } finally {
          setLoading(false);
        }
      }, [API_BASE, normalizeProviders]);
      const fetchRangeTotals = useCallback(async (rangeParam) => {
        try {
          const res = await fetch(`${API_BASE}/api/contracts-range?range=${encodeURIComponent(rangeParam)}`);
          const data = await res.json();
          setRangeTotals(data || null);
        } catch (e) {
          setRangeTotals(null);
        }
      }, [API_BASE]);
      useEffect(() => { loadData(); }, [loadData]);

      useEffect(() => {
        fetchRangeTotals(timeRange);
      }, [timeRange, fetchRangeTotals]);

      useEffect(() => {
        const interval = setInterval(() => {
          loadData();
          fetchRangeTotals(timeRange);
        }, 60000);
        return () => clearInterval(interval);
      }, [loadData, fetchRangeTotals, timeRange]);

      // If user switches to "All Data Types" while on "Lowest Cost", snap back to Highest Earnings
      useEffect(() => {
        if (serviceFilter === 'all' && sortBy === 'cost') {
          setSortBy('earnings');
        }
      }, [serviceFilter, sortBy]);
      const timeRangeLabel = useMemo(() => TIME_RANGES.find(t => t.id === timeRange)?.label || 'All Time', [timeRange]);

      const regionGroups = useMemo(() => ({
        africa: ['africa', 'africa-northern', 'africa-eastern', 'africa-middle', 'africa-western', 'africa-southern'],
        americas: ['americas', 'americas-northern', 'americas-caribbean', 'americas-central', 'americas-south'],
        asia: ['asia', 'asia-central', 'asia-eastern', 'asia-southeastern', 'asia-southern', 'asia-western'],
        europe: ['europe', 'europe-northern', 'europe-eastern', 'europe-southern', 'europe-western'],
        oceania: ['oceania', 'oceania-aus-nz', 'oceania-melanesia', 'oceania-micronesia', 'oceania-polynesia'],
        antarctica: ['antarctica'],
      }), []);

      const filteredProviders = useMemo(() => {
        const filtered = providers.filter(p => {
          if (!showOffline && p.status !== 'ONLINE') return false;
          if (serviceFilter !== 'all' && !p.services.some(s => String(s.id) === String(serviceFilter))) return false;
          if (regionFilter !== 'all') {
            const allowedRegions = regionGroups[regionFilter] || [regionFilter];
            if (!allowedRegions.includes(p.region)) return false;
          }
          if (providerSearch && !p.moniker.toLowerCase().includes(providerSearch.toLowerCase())) return false;
          return true;
        });

        const sorted = filtered.sort((a, b) => {
          if (sortBy === 'earnings') {
            const ea = buildEarnings(a)?.[timeRange] || 0;
            const eb = buildEarnings(b)?.[timeRange] || 0;
            return eb - ea;
          }
          if (sortBy === 'cost') {
            const rateFor = (p) => {
              const rates = serviceFilter === 'all' ? p.services : p.services.filter(s => String(s.id) === String(serviceFilter));
              const min = rates.reduce((acc, s) => Math.min(acc, parseFloat(s.paygoRate || '9999')), 9999);
              return isFinite(min) ? min : 9999;
            };
            return rateFor(a) - rateFor(b);
          }
          return (b.uptime || 0) - (a.uptime || 0);
        });

        // If a specific service is selected, force Best Cost sort
        if (serviceFilter !== 'all') {
          return sorted.sort((a, b) => {
            const rateFor = (p) => {
              const rates = p.services.filter(s => String(s.id) === String(serviceFilter));
              const min = rates.reduce((acc, s) => Math.min(acc, parseFloat(s.paygoRate || '9999')), 9999);
              return isFinite(min) ? min : 9999;
            };
            return rateFor(a) - rateFor(b);
          });
        }

        return sorted;
      }, [providers, serviceFilter, regionFilter, providerSearch, sortBy, showOffline, regionGroups, timeRange, buildEarnings]);

  const serviceOptions = useMemo(() => {
    const map = new Map();
    const sourceList = Array.isArray(activeServiceTypes) ? activeServiceTypes : [];
    sourceList.forEach((s) => {
      const key = String(s.service_id ?? s.id ?? '');
      if (!key || key === 'all') return;
      const svcType = s.service_type || {};
      const name = svcType.description || svcType.name || s.service || s.name || s.service_id || key;
      const slugRaw = svcType.chain || chainSlugFromServiceName(svcType.name || name);
      const slug = typeof slugRaw === 'string' ? slugRaw.trim().toLowerCase() : '';
      const iconUrl = chainIconUrl(slug);
      if (!map.has(key)) {
        map.set(key, { id: key, name, icon: iconUrl || '🌐', iconUrl });
      }
    });
    return Array.from(map.values());
  }, [activeServiceTypes]);

  const summary = useMemo(() => {
    const providers = filteredProviders;
    const heightHint = rangeTotals?.latest_height ?? latestHeight;
    const blockTime = rangeTotals?.block_time_seconds ?? blockTimeSeconds;
    const volumeForRange = providers.reduce((sum, p) => sum + getEarningsByRange(p, timeRange, latestHeight, blockTime, heightHint, blockTime), 0);
    const contractsForRange = providers.reduce((sum, p) => {
      const cutoffBlocks = blocksForRange(timeRange, blockTime);
      const cutoff = heightHint && cutoffBlocks ? heightHint - cutoffBlocks : null;
      const contracts = Array.isArray(p.contracts) ? p.contracts : [];
      const filtered = contracts.filter((c) => {
        if (!cutoff) return true;
        const h = c.height || c.settlement_height || c.raw?.height || c.raw?.settlement_height;
        const hInt = h !== undefined ? parseInt(h, 10) : null;
        return hInt === null || Number.isNaN(hInt) ? true : hInt >= cutoff;
      });
      return sum + filtered.length;
    }, 0);
    const volumeResolved = rangeTotals?.total_paid_uarkeo ?? volumeForRange;
    const transactionsResolved = rangeTotals?.total_transactions ?? contractsForRange;
    return {
      providers: counts?.active_providers ?? providers.length,
      online: providers.filter(p => p.status === 'ONLINE').length,
      contracts: counts?.contracts ?? providers.reduce((sum, p) => sum + p.activeContracts, 0),
      volume: volumeResolved,
      dailyVolume: volumeResolved,
      services: counts?.active_services ?? providers.reduce((sum, p) => {
        const count = serviceFilter === 'all' ? p.services.length : p.services.filter(s => String(s.id) === String(serviceFilter)).length;
        return sum + count;
      }, 0),
      subscribers: counts?.subscribers ?? 0,
      validators: counts?.validators_active ?? counts?.validators_bonded ?? 0,
      transactions: transactionsResolved,
      dataTypes: counts?.supported_chains ?? serviceOptions.length,
    };
  }, [filteredProviders, timeRange, serviceFilter, counts, latestHeight, blockTimeSeconds, serviceOptions, rangeTotals]);

  const contractProviderEarnings = useMemo(() => {
    if (!contractProvider) return null;
    return buildEarnings(contractProvider);
  }, [contractProvider, buildEarnings]);

  const chartRef = useRef(null);
  const chartInstanceRef = useRef(null);

  const providerEarningsChartData = useMemo(() => {
    const data = filteredProviders.map((p) => {
      const earnings = buildEarnings(p);
      const val = earnings?.[timeRange] ? earnings[timeRange] / ARKEO_DIVISOR : 0;
      return { label: p.moniker || p.id, value: val };
    }).filter(d => d.value > 0);
    data.sort((a, b) => b.value - a.value);
    return data.slice(0, 10);
  }, [filteredProviders, timeRange, buildEarnings]);

  useEffect(() => {
    const ctx = chartRef.current?.getContext('2d');
    if (!ctx || typeof Chart === 'undefined') return;
    const labels = providerEarningsChartData.map(d => d.label);
    const values = providerEarningsChartData.map(d => d.value);
    // Destroy/recreate to avoid state issues when toggling between empty/non-empty datasets
    if (chartInstanceRef.current) {
      chartInstanceRef.current.destroy();
      chartInstanceRef.current = null;
    }
    if (labels.length === 0) return;
    chartInstanceRef.current = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {
            label: 'ARKEO Earned',
            data: values,
            backgroundColor: 'rgba(59, 224, 255, 0.35)',
            borderColor: 'rgba(59, 224, 255, 0.8)',
            borderWidth: 1.5,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        backgroundColor: 'transparent',
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (context) => `${formatChartNumber(context.parsed.y)} ARKEO`,
            },
          },
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              callback: (val) => formatChartNumber(val),
            },
            grid: { color: 'rgba(255,255,255,0.05)' },
          },
          x: {
            ticks: { color: '#A9AFC0' },
            grid: { display: false },
          },
        },
      },
    });
  }, [providerEarningsChartData]);

      const earningsMomentum = useMemo(() => {
        const totalRange = summary.volume || 0;
        const base = totalRange ? totalRange / 7 : 0;
        const labels = ['M', 'T', 'W', 'T', 'F', 'S', 'S'];
        const series = labels.map((_, i) => Math.max(0, base * (0.9 + i * 0.06)));
        const total = series.reduce((a, b) => a + b, 0);
        return { labels, series, total };
      }, [summary.volume]);

      useEffect(() => {
        try {
          const params = new URLSearchParams(window.location.search);
          const uiReset = params.get('ui_reset');
          if (uiReset) {
            localStorage.removeItem('arkeo-how-it-works-seen');
            localStorage.removeItem('arkeo-info-dismissed');
            localStorage.removeItem('arkeo-cookie-consent');
            localStorage.removeItem('arkeo-optout-sale');
            setHideInfoBlock(false);
            setShowCookieBanner(true);
            setShowHowItWorks(true);
            setOptOutSale(false);
            return;
          }
          const seen = localStorage.getItem('arkeo-how-it-works-seen');
          if (!seen) {
            setShowHowItWorks(true);
            localStorage.setItem('arkeo-how-it-works-seen', '1');
          }
        } catch (e) {
          // safe fallback if localStorage unavailable
        }
      }, []);

      useEffect(() => {
        try {
          const dismissed = localStorage.getItem('arkeo-info-dismissed');
          if (dismissed === '1') setHideInfoBlock(true);
        } catch (e) {
          // ignore if storage unavailable
        }
      }, []);

      useEffect(() => {
        try {
          const consent = localStorage.getItem('arkeo-cookie-consent');
          if (!consent) {
            setShowCookieBanner(true);
          }
          const optOut = localStorage.getItem('arkeo-optout-sale');
          if (optOut === '1') setOptOutSale(true);
        } catch (e) {
          setShowCookieBanner(true);
        }
      }, []);

      const handleCookieChoice = (value) => {
        setShowCookieBanner(false);
        try { localStorage.setItem('arkeo-cookie-consent', value); } catch (e) { /* ignore */ }
      };

      return (
        <div className="min-h-screen bg-background text-white">
          {notification && (
            <div className="fixed top-6 left-1/2 -translate-x-1/2 z-[60] px-5 py-3 rounded-xl bg-emerald-500 text-white font-medium shadow-xl animate-pulse pointer-events-none">
              {notification}
            </div>
          )}

          <header className="sticky top-0 z-40 backdrop-blur-xl bg-background/90 border-b border-border relative overflow-hidden header-shadow">
            <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_top_right,rgba(59,224,255,0.12),transparent_50%),radial-gradient(circle_at_bottom_left,rgba(59,224,255,0.08),transparent_45%)]" />
            <div className="max-w-7xl mx-auto px-4 py-4 relative z-10">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <a href="https://arkeo.network" aria-label="Arkeo Home">
                    <ArkeoLogo size={44} />
                  </a>
                  <div>
                    <h1 className="text-xl font-bold text-white">The Arkeo Data Marketplace</h1>
                    <p className="text-xs text-secondaryText">Powering a global economy of data.</p>
                  </div>
                </div>
                <div className="flex flex-wrap items-center justify-end gap-3">
                  <button onClick={() => setShowBecomeProvider(true)} className="primary-gradient text-white font-semibold px-4 py-2.5 rounded-xl transition-all primary-shadow flex items-center gap-2">
                    <Icons.Server /> I Want to Provide Data
                  </button>
                  <button onClick={() => setShowSubscriberModal(true)} className="primary-gradient text-white font-semibold px-4 py-2.5 rounded-xl transition-all primary-shadow flex items-center gap-2">
                    <Icons.Wand /> I Want to Use Data
                  </button>
                  <a href="https://app.osmosis.zone/?from=USDC&to=ARKEO" target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-2 bg-arkeo text-white font-semibold px-4 py-2.5 rounded-xl transition-all hover:brightness-110">
                    <Icons.Coin /> Get ARKEO Token
                  </a>
                </div>
              </div>
            </div>
          </header>

          <main className="max-w-7xl mx-auto px-4 py-8">
            {loading && <div className="mb-4 px-4 py-3 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-secondaryText text-sm">Loading latest marketplace data…</div>}
            {error && <div className="mb-4 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/40 text-red-200 text-sm">{error}</div>}
            <div className="card-surface card-shadow rounded-2xl p-6 mb-8 relative overflow-hidden">
              <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_top_right,rgba(59,224,255,0.18),transparent_50%),radial-gradient(circle_at_bottom_left,rgba(59,224,255,0.12),transparent_45%)]" />
              <div className="relative z-10 grid md:grid-cols-3 gap-6 items-stretch">
                <div className="space-y-3 md:col-span-1">
                  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-arkeo/10 text-arkeo text-xs font-semibold">
                    <Icons.Activity /> Marketplace Momentum
                  </div>
                  <h3 className="text-3xl font-bold text-white">Don’t Miss Out on Your Data’s Full Earning Potential!</h3>
                  <p className="text-secondaryText text-sm">Arkeo lets you turn your data and services into real earnings. Powered by the Arkeo chain, this open marketplace is where people come to access data and where you get paid when they choose you.</p>
                  <p className="text-secondaryText text-sm">Getting started is simple: provide a service, register it on Arkeo, and watch your earnings grow as users tap into what you offer. No barriers, no middlemen, no censorship. Just a straightforward way to earn ARKEO by powering the open data economy.</p>
                  <div className="flex gap-3">
                    <button onClick={() => setShowBecomeProvider(true)} className="bg-arkeo text-white font-semibold px-4 py-2.5 rounded-xl shadow-lg flex items-center gap-2 hover:brightness-110 transition-all">
                      <Icons.EarningCoin /> Start Earning
                    </button>
                    <button onClick={() => setShowHowItWorks(true)} className="secondary-btn px-4 py-2.5 rounded-xl font-medium border border-[var(--border)] hover:brightness-110 flex items-center gap-2">
                      <Icons.Wand /> Learn How
                    </button>
                  </div>
                </div>
                <div className="md:col-span-2 h-full">
                  <div className="chart-card rounded-2xl p-4 h-full flex flex-col">
                    <div className="flex items-center justify-between mb-3">
                      <div>
                        <p className="text-sm text-white font-semibold">Top Providers (by ARKEO Earnings)</p>
                      </div>
                      <div className="flex gap-1">
                        {['daily', 'weekly', 'monthly', 'all_time'].map(r => (
                          <button
                            key={r}
                            onClick={(e) => { e.stopPropagation(); setTimeRange(r); fetchRangeTotals(r); }}
                            className={`px-2 py-1 rounded text-xs font-medium transition-all ${timeRange === r ? 'bg-arkeo text-slate-900' : 'text-secondaryText hover:bg-[#1E222C]'}`}
                          >
                            {TIME_RANGES.find(t => t.id === r)?.label || r}
                          </button>
                        ))}
                      </div>
                    </div>
                    <div className="h-full min-h-[220px]">
                      {providerEarningsChartData.length > 0 ? (
                        <canvas ref={chartRef} height="220"></canvas>
                      ) : (
                        <div className="text-secondaryText text-sm text-center py-10">No earnings data available for this range.</div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
              <StatsCard icon={<Icons.Coin />} label="ARKEO Earned" value={formatArkeo(summary.volume, 8)} color="text-arkeo" />
              <StatsCard icon={<Icons.Transactions />} label="Transactions" value={summary.transactions} color="text-arkeo" />
              <StatsCard icon={<Icons.Provider />} label="Providers" value={summary.providers} color="text-arkeo" />
              <StatsCard icon={<Icons.Subscribers />} label="Subscribers" value={summary.subscribers.toLocaleString()} color="text-arkeo" />
              <StatsCard icon={<Icons.Services />} label="Services" value={summary.services} color="text-arkeo" />
              <StatsCard icon={<Icons.Contracts />} label="Contracts" value={summary.contracts} color="text-arkeo" />
              <StatsCard icon={<Icons.Validators />} label="Validators" value={summary.validators} color="text-arkeo" />
              <StatsCard icon={<Icons.DataTypes />} label="Active Types" value={summary.dataTypes} color="text-arkeo" />
            </div>

            {!hideInfoBlock && (
              <div className="card-surface rounded-2xl p-6 pr-[2.5rem] mb-8 relative overflow-hidden">
                <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_top_right,rgba(59,224,255,0.18),transparent_50%),radial-gradient(circle_at_bottom_left,rgba(59,224,255,0.12),transparent_45%)]" />
                <div className="absolute top-3 right-3 z-20">
                  <button
                    onClick={() => {
                      setHideInfoBlock(true);
                      try { localStorage.setItem('arkeo-info-dismissed', '1'); } catch (e) {}
                    }}
                    className="p-2 hover:bg-[#1E222C] rounded-xl text-secondaryText"
                    aria-label="Dismiss"
                  >
                    <Icons.Close />
                  </button>
                </div>
                <div className="relative z-10 grid md:grid-cols-2 gap-6 items-center">
                  <div className="space-y-4">
                    <div className="flex items-center gap-3">
                      <div className="p-2.5 rounded-xl bg-arkeo/15 text-arkeo"><Icons.Wand /></div>
                      <div>
                        <h3 className="text-xl font-bold text-white">See How Arkeo Works in Action</h3>
                        <p className="text-secondaryText text-sm">A Brief Walkthrough for Providers and Subscribers</p>
                      </div>
                    </div>
                    <p className="text-secondaryText text-sm">Arkeo is an open data marketplace where anyone can publish or consume data services with trustless metering and automatic settlement.</p>
                    <div className="flex items-start gap-2 text-secondaryText text-sm">
                      <span className="text-arkeo mt-0.5"><Icons.CheckCircle /></span>
                      <p>Providers list endpoints, set prices, and earn ARKEO as subscribers use their services.</p>
                    </div>
                    <div className="flex items-start gap-2 text-secondaryText text-sm">
                      <span className="text-arkeo mt-0.5"><Icons.CheckCircle /></span>
                      <p>Subscribers get reliable access with optimized performance and major cost savings.</p>
                    </div>
                    <div className="flex items-start gap-2 text-secondaryText text-sm">
                      <span className="text-arkeo mt-0.5"><Icons.CheckCircle /></span>
                      <p>Smart routing and reputation keep the marketplace efficient and fair.</p>
                    </div>
                    <p className="text-secondaryText text-sm font-semibold">Watch how Arkeo works and see the network in action.</p>
                    <div className="flex gap-3 flex-wrap">
                      <a href="https://docs.arkeo.network" target="_blank" className="secondary-btn px-4 py-2.5 rounded-xl font-medium border border-[var(--border)] hover:brightness-110">View Docs</a>
                    </div>
                  </div>
                  <div className="relative rounded-2xl overflow-hidden border border-[var(--border)] shadow-lg md:ml-4 md:mr-4">
                    <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(59,224,255,0.15),transparent_55%),radial-gradient(circle_at_bottom_left,rgba(59,224,255,0.15),transparent_55%)]" />
                    <div className="relative aspect-video">
                      <iframe
                        src="https://www.youtube.com/embed/nCgQDjiotG0?rel=0"
                        title="Arkeo Overview"
                        allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                        allowFullScreen
                        loading="lazy"
                        className="absolute inset-0 w-full h-full"
                      />
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Filters */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3 grid-flow-row-dense mb-6">
              <div className="relative">
                <input type="text" placeholder="Search providers..." value={providerSearch} onChange={e => setProviderSearch(e.target.value)} className="w-full bg-[var(--surface)] border border-[var(--border)] rounded-xl pl-11 pr-4 py-3 text-white placeholder-secondaryText focus:border-arkeo focus:ring-1 focus:ring-arkeo" style={{ paddingLeft: '2.75rem' }} />
                <div className="absolute left-4 top-1/2 -translate-y-1/2 text-secondaryText"><Icons.Search /></div>
              </div>
              <DataServiceFilter selected={serviceFilter} onSelect={setServiceFilter} options={serviceOptions} />
              <LocationFilter selectedRegion={regionFilter} onSelect={setRegionFilter} />
              <SimpleDropdown label="Time Range" selected={timeRange} options={TIME_RANGES} onChange={setTimeRange} />
              <SortDropdown
                selected={sortBy}
                options={SORT_OPTIONS}
                onChange={setSortBy}
                showOffline={showOffline}
                onToggleOffline={setShowOffline}
                disableCost={serviceFilter === 'all'}
              />
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-5">
              {filteredProviders.map(provider => {
                const providerEarnings = buildEarnings(provider);
                return (
                <ProviderCard
                  key={provider.id}
                  provider={provider}
                  earnings={providerEarnings}
                  serviceFilter={serviceFilter}
                  timeRange={timeRange}
                  onRangeChange={setTimeRange}
                  onOpenContract={(p) => { setContractProvider(p); setShowContractModal(true); }}
                />
              );})}
            </div>

            {filteredProviders.length === 0 && (
              <div className="text-center py-16">
                <div className="w-16 h-16 bg-[var(--surface)] border border-[var(--border)] rounded-2xl flex items-center justify-center mx-auto mb-4 text-secondaryText"><Icons.Search /></div>
                <h3 className="text-lg font-semibold text-white mb-2">No providers found</h3>
                <p className="text-secondaryText">Try adjusting your search, chain, or location filter</p>
              </div>
            )}

            <div className="mt-8 card-surface rounded-2xl p-6 relative overflow-hidden">
              <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_top_right,rgba(59,224,255,0.2),transparent_50%),radial-gradient(circle_at_bottom_left,rgba(59,224,255,0.12),transparent_45%)]" />
              <div className="flex flex-col md:flex-row items-center gap-4">
                <ArkeoLogo size={48} />
                <div className="flex-1 text-center md:text-left relative z-10">
                  <h3 className="font-bold text-white mb-1">Get ARKEO on Osmosis</h3>
                  <p className="text-secondaryText text-sm">ARKEO tokens are available on Osmosis DEX.</p>
                </div>
                <a href="https://app.osmosis.zone/?from=USDC&to=ARKEO" target="_blank" className="px-6 py-3 bg-arkeo text-white font-semibold rounded-xl flex items-center gap-2 relative z-10 shadow-lg hover:brightness-110 transition-all">
                  Buy ARKEO <Icons.External />
                </a>
              </div>
            </div>

          </main>

          <footer className="max-w-7xl mx-auto px-4 pb-8 text-secondaryText text-sm text-center">
            © 2025 Arkeo Network. All rights reserved.
          </footer>

          {showCookieBanner && (
            <CookieBanner
              onAccept={() => handleCookieChoice('accepted')}
              onReject={() => handleCookieChoice('rejected')}
              onPrivacy={() => setShowPrivacyModal(true)}
            />
          )}

          <BecomeProviderModal
            isOpen={showBecomeProvider}
            onClose={() => setShowBecomeProvider(false)}
            onCopy={handleCopy}
            providerEnvExample={PROVIDER_ENV_EXAMPLE}
            providerRunCmd={PROVIDER_RUN_CMD}
          />
          <OpenContractModal
            provider={contractProvider}
            earnings={contractProviderEarnings}
            isOpen={showContractModal}
            onClose={() => setShowContractModal(false)}
            onSuccess={() => { showNotif('✓ Contract opened!'); setShowContractModal(false); }}
            timeRange={timeRange}
            onRangeChange={setTimeRange}
            serviceOptions={serviceOptions}
          />
          <HowItWorksModal
            isOpen={showHowItWorks}
            onClose={() => setShowHowItWorks(false)}
            timeRange={timeRange}
            onRangeChange={setTimeRange}
          />
          <BecomeSubscriberModal
            isOpen={showSubscriberModal}
            onClose={() => setShowSubscriberModal(false)}
            onCopy={handleCopy}
            subscriberEnvExample={SUBSCRIBER_ENV_EXAMPLE}
            subscriberRunCmd={SUBSCRIBER_RUN_CMD}
          />
          <PrivacyModal
            isOpen={showPrivacyModal}
            onClose={() => setShowPrivacyModal(false)}
            optOutSale={optOutSale}
            onToggleOptOut={(val) => {
              setOptOutSale(val);
              try { localStorage.setItem('arkeo-optout-sale', val ? '1' : '0'); } catch (e) { /* ignore */ }
            }}
          />
        </div>
      );
    }

    const CookieBanner = ({ onAccept, onReject, onPrivacy }) => (
      <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50 max-w-5xl w-[95%] bg-arkeo text-white rounded-2xl border border-arkeo/60 shadow-2xl p-5">
        <div className="flex flex-col gap-3">
          <p className="text-white text-sm leading-relaxed">
            Our website uses "Strictly Necessary" cookies to keep our site reliable and secure. It also uses additional cookies to enhance user experience, analyze traffic, and assist in our marketing campaigns. By clicking the "Accept Cookies and Continue" button, you agree to and accept the use of cookies. You can select the "Reject Additional Cookies" button to limit the use of non-essential cookies or adapt your choices in the ‘Your Privacy Rights’ section anytime.
          </p>
          <div className="flex flex-wrap gap-3">
            <button onClick={onPrivacy} className="bg-white/10 text-white font-semibold px-4 py-2.5 rounded-xl border border-white/30 hover:bg-white/15 transition-all">Your Privacy Rights</button>
            <button onClick={onReject} className="bg-white/10 text-white font-semibold px-4 py-2.5 rounded-xl border border-white/30 hover:bg-white/15 transition-all">Reject Additional Cookies</button>
            <button onClick={onAccept} className="bg-white text-arkeo font-semibold px-4 py-2.5 rounded-xl shadow-lg hover:brightness-110 transition-all">Accept Cookies and Continue</button>
          </div>
        </div>
      </div>
    );

    const PrivacyModal = ({ isOpen, onClose, optOutSale, onToggleOptOut }) => {
      if (!isOpen) return null;
      return (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={onClose}>
          <div className="bg-arkeo text-white rounded-2xl max-w-5xl w-full shadow-2xl max-h-[90vh] overflow-y-auto border border-arkeo/60" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-6 border-b border-white/20">
              <div>
                <h2 className="text-xl font-bold text-white">Do Not Sell or Share My Personal Data</h2>
              </div>
              <button onClick={onClose} className="p-2 hover:bg-white/10 rounded-xl text-white"><Icons.Close /></button>
            </div>
            <div className="p-6 space-y-5">
              <p className="text-white/90 text-sm leading-relaxed">
                When you visit our website, we store cookies on your browser to collect information. The information collected might relate to you, your preferences or your device, and is mostly used to make the site work as you expect it to and to provide a more personalized web experience. However, you can choose not to allow certain types of cookies, which may impact your experience of the site and the services we are able to offer. Click on the different category headings to find out more and change our default settings according to your preference. You cannot opt-out of our First Party Strictly Necessary Cookies as they are deployed in order to ensure the proper functioning of our website (such as prompting the cookie banner and remembering your settings, to log into your account, to redirect you when you log out, etc.).
              </p>
              <div className="space-y-3">
                <h3 className="text-white font-semibold">Manage Consent Preferences</h3>

                <div className="bg-white/10 rounded-xl p-4 border border-white/20 space-y-2">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-white font-semibold text-sm">Strictly Necessary Cookies</p>
                      <p className="text-white/80 text-xs">These cookies are necessary for the website to function and cannot be switched off in our systems.</p>
                    </div>
                    <span className="px-2 py-1 rounded-lg bg-white/15 text-white text-xs">Always Active</span>
                  </div>
                  <p className="text-white/80 text-xs">
                    They are usually only set in response to actions made by you which amount to a request for services, such as setting your privacy preferences, logging in or filling in forms. You can set your browser to block or alert you about these cookies, but some parts of the site will not then work. These cookies do not store any personally identifiable information.
                  </p>
                </div>

                <div className="bg-white/10 rounded-xl p-4 border border-white/20 space-y-2">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-white font-semibold text-sm">Opt Out of Sale of Sharing/Targeted Advertising</p>
                      <p className="text-white/80 text-xs">As a California consumer, you have the right to opt-out from the sale or sharing of your personal information.</p>
                    </div>
                    <label className="inline-flex items-center gap-2 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={optOutSale}
                        onChange={(e) => onToggleOptOut(e.target.checked)}
                        className="h-4 w-4 rounded border-white/40 bg-white/10 text-arkeo focus:ring-arkeo focus:ring-1"
                      />
                      <span className="text-white text-xs font-semibold">{optOutSale ? 'Enabled' : 'Disabled'}</span>
                    </label>
                  </div>
                  <p className="text-white/80 text-xs">
                    As a California consumer, you have the right to opt-out from the sale or sharing of your personal information at any time across business platform, services, businesses and devices. You can opt-out of the sale and sharing of your personal information by using this toggle switch. As a Virginia, Utah, Colorado and Connecticut consumer, you have the right to opt-out from the sale of your personal data and the processing of your personal data for targeted advertising. You can opt-out of the sale of your personal data and targeted advertising by using this toggle switch. For more information on your rights as a United States consumer see our privacy notice.
                  </p>
                </div>

                <div className="bg-white/10 rounded-xl p-4 border border-white/20 space-y-2">
                  <p className="text-white font-semibold text-sm">Targeting Cookies</p>
                  <p className="text-white/80 text-xs">These cookies may be set through our site by our advertising partners.</p>
                  <p className="text-white/80 text-xs">If you do not allow these cookies, you will experience less targeted advertising.</p>
                </div>

                <div className="bg-white/10 rounded-xl p-4 border border-white/20 space-y-2">
                  <p className="text-white font-semibold text-sm">Performance Cookies</p>
                  <p className="text-white/80 text-xs">These cookies allow us to count visits and traffic sources so we can measure and improve the performance of our site.</p>
                  <p className="text-white/80 text-xs">If you do not allow these cookies we will not know when you have visited our site, and will not be able to monitor its performance.</p>
                </div>
              </div>

              <div className="flex flex-wrap gap-3 pt-2">
                <button onClick={onClose} className="bg-white/10 text-white font-semibold px-4 py-2.5 rounded-xl border border-white/30 hover:bg-white/15 transition-all">Reject All</button>
                <button onClick={onClose} className="bg-white text-arkeo font-semibold px-4 py-2.5 rounded-xl shadow-lg hover:brightness-110 transition-all">Confirm My Choices</button>
              </div>
            </div>
          </div>
        </div>
      );
    };

createRoot(document.getElementById('root')).render(<App />);
