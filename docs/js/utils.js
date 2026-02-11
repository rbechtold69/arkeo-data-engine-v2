// ============================================================
// UTILITY FUNCTIONS
// ============================================================

// ---- CACHING ----
const Cache = {
  prefix: 'arkeo_',
  
  set(key, data, ttlMs = CONFIG.CACHE_TTL_MS) {
    if (!CONFIG.ENABLE_CACHING) return;
    try {
      const item = {
        data: data,
        expiry: Date.now() + ttlMs,
      };
      localStorage.setItem(this.prefix + key, JSON.stringify(item));
    } catch (e) {
      console.warn('Cache write failed:', e);
    }
  },
  
  get(key) {
    if (!CONFIG.ENABLE_CACHING) return null;
    try {
      const item = localStorage.getItem(this.prefix + key);
      if (!item) return null;
      
      const parsed = JSON.parse(item);
      if (Date.now() > parsed.expiry) {
        this.remove(key);
        return null;
      }
      return parsed.data;
    } catch (e) {
      console.warn('Cache read failed:', e);
      return null;
    }
  },
  
  remove(key) {
    try {
      localStorage.removeItem(this.prefix + key);
    } catch (e) {
      // Ignore
    }
  },
  
  clear() {
    try {
      Object.keys(localStorage)
        .filter(k => k.startsWith(this.prefix))
        .forEach(k => localStorage.removeItem(k));
    } catch (e) {
      // Ignore
    }
  }
};

// ---- ERROR HANDLING ----
class AppError extends Error {
  constructor(message, code = 'UNKNOWN', details = null) {
    super(message);
    this.code = code;
    this.details = details;
    this.timestamp = new Date().toISOString();
  }
}

const ErrorHandler = {
  errors: [],
  maxErrors: 50,
  
  handle(error, context = '') {
    const appError = error instanceof AppError ? error : new AppError(
      error.message || 'Unknown error',
      'RUNTIME',
      { originalError: error.toString(), context }
    );
    
    this.errors.unshift(appError);
    if (this.errors.length > this.maxErrors) {
      this.errors.pop();
    }
    
    if (CONFIG.DEBUG_MODE) {
      console.error(`[${context}]`, appError);
    }
    
    return appError;
  },
  
  showToast(message, type = 'error') {
    // Create toast notification
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 1rem 1.5rem;
      border-radius: 0.5rem;
      background: ${type === 'error' ? '#ef4444' : type === 'success' ? '#10b981' : '#3BE0FF'};
      color: white;
      font-weight: 500;
      z-index: 9999;
      animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
  },
  
  getRecent(count = 10) {
    return this.errors.slice(0, count);
  }
};

// ---- FORMATTING ----
const Format = {
  arkeo(uarkeo, decimals = 2) {
    const val = parseInt(uarkeo || 0) / CONFIG.ARKEO_DIVISOR;
    if (val >= 1_000_000) return (val / 1_000_000).toFixed(1) + 'M';
    if (val >= 1_000) return (val / 1_000).toFixed(1) + 'K';
    return val.toFixed(decimals);
  },
  
  address(addr, startChars = 10, endChars = 6) {
    if (!addr || addr.length < startChars + endChars + 3) return addr;
    return `${addr.slice(0, startChars)}...${addr.slice(-endChars)}`;
  },
  
  date(timestamp) {
    return new Date(timestamp).toLocaleDateString();
  },
  
  relativeTime(timestamp) {
    const seconds = Math.floor((Date.now() - new Date(timestamp)) / 1000);
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  },
  
  number(num) {
    return new Intl.NumberFormat().format(num);
  }
};

// ---- API HELPERS ----
const API = {
  async fetch(endpoint, options = {}) {
    const url = endpoint.startsWith('http') ? endpoint : `${CONFIG.REST_API}${endpoint}`;
    const cacheKey = options.cacheKey || endpoint;
    
    // Check cache first
    if (options.useCache !== false) {
      const cached = Cache.get(cacheKey);
      if (cached) {
        if (CONFIG.DEBUG_MODE) console.log('Cache hit:', cacheKey);
        return cached;
      }
    }
    
    const maxRetries = options.retries || 3;
    let lastError;
    
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        if (attempt > 0) await new Promise(r => setTimeout(r, 1000 * attempt));
        
        const response = await fetch(url, {
          ...options,
          headers: {
            'Content-Type': 'application/json',
            ...options.headers,
          },
        });
        
        if (!response.ok) {
          throw new AppError(`API error: ${response.status}`, 'API_ERROR', { status: response.status, url });
        }
        
        const data = await response.json();
        
        // Cache successful response
        if (options.useCache !== false) {
          Cache.set(cacheKey, data, options.cacheTtl);
        }
        
        return data;
      } catch (error) {
        lastError = error;
        if (CONFIG.DEBUG_MODE) console.warn(`API attempt ${attempt + 1}/${maxRetries} failed:`, error.message);
      }
    }
    
    ErrorHandler.handle(lastError, `API.fetch(${url})`);
    throw lastError;
  },
  
  async getProviders() {
    const data = await this.fetch('/arkeo/providers', { cacheKey: 'providers' });
    return data.provider || data.providers || [];
  },
  
  async getServices() {
    const data = await this.fetch('/arkeo/services', { cacheKey: 'services' });
    return data.services || data.service || [];
  },
  
  async getContracts() {
    // Paginate through ALL contracts (API returns 100 at a time)
    let allContracts = [];
    let nextKey = null;
    let page = 0;
    const maxPages = 20; // Safety limit
    
    do {
      try {
        const params = nextKey ? `?pagination.key=${encodeURIComponent(nextKey)}` : '';
        const data = await this.fetch(`/arkeo/contracts${params}`, { 
          cacheKey: nextKey ? null : 'contracts', // Only cache first page
          useCache: page === 0 // Only use cache for first page
        });
        const contracts = data.contract || data.contracts || [];
        allContracts = allContracts.concat(contracts);
        nextKey = data.pagination?.next_key || null;
        page++;
        console.log(`Contracts page ${page}: ${contracts.length} loaded (total: ${allContracts.length})`);
      } catch (e) {
        console.warn(`Contracts page ${page + 1} failed:`, e.message);
        break;
      }
    } while (nextKey && page < maxPages);
    
    console.log(`Loaded ${allContracts.length} contracts across ${page} pages`);
    return allContracts;
  }
};

// ---- DOM HELPERS ----
const DOM = {
  $(selector) {
    return document.querySelector(selector);
  },
  
  $$(selector) {
    return document.querySelectorAll(selector);
  },
  
  create(tag, attrs = {}, children = []) {
    const el = document.createElement(tag);
    Object.entries(attrs).forEach(([key, val]) => {
      if (key === 'className') el.className = val;
      else if (key === 'innerHTML') el.innerHTML = val;
      else if (key === 'textContent') el.textContent = val;
      else if (key.startsWith('on')) el.addEventListener(key.slice(2).toLowerCase(), val);
      else el.setAttribute(key, val);
    });
    children.forEach(child => {
      if (typeof child === 'string') el.appendChild(document.createTextNode(child));
      else el.appendChild(child);
    });
    return el;
  },
  
  show(el) {
    if (typeof el === 'string') el = this.$(el);
    if (el) el.style.display = '';
  },
  
  hide(el) {
    if (typeof el === 'string') el = this.$(el);
    if (el) el.style.display = 'none';
  },
  
  toggle(el, show) {
    if (show) this.show(el);
    else this.hide(el);
  }
};

// ---- ESCAPE HTML ----
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}

// Add CSS animation for toasts
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
`;
document.head.appendChild(style);
