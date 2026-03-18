/**
 * Shared Navigation Component
 * Injects consistent nav + mobile menu into all pages.
 * Usage: <div id="arkeo-nav" data-active="home|data|providers|network"></div>
 * Then call: injectNav()
 */
function injectNav() {
  const el = document.getElementById('arkeo-nav');
  if (!el) return;
  const active = el.dataset.active || '';

  const isActive = (key) => active === key ? 'active' : '';

  el.innerHTML = `
    <nav class="an-nav">
      <div class="an-nav-inner">
        <a href="index.html" class="an-logo">
          <img src="images/arkeo-logo-200px_1.png" alt="Arkeo" height="32">
          <span>Arkeo <em>Marketplace</em></span>
        </a>

        <div class="an-links">
          <a href="index.html" class="an-link ${isActive('home')}">Apps</a>
          
          <div class="an-dropdown">
            <a href="data.html" class="an-link ${isActive('data')}">Data ▾</a>
            <div class="an-dropdown-menu">
              <a href="data.html">Provider Directory</a>
              <a href="subscribe.html">Subscribe / Buy Data</a>
              <a href="agents.html">AI Agents</a>
              <a href="test-arkauth.html">Test Connection</a>
            </div>
          </div>

          <div class="an-dropdown">
            <a href="providers.html" class="an-link ${isActive('providers')}">Providers ▾</a>
            <div class="an-dropdown-menu">
              <a href="providers.html">Overview & Leaderboard</a>
              <a href="become-provider.html">Become a Provider</a>
              <a href="x402-provider-guide.html">x402 Provider Guide</a>
              <a href="cli-reference.html">CLI Reference</a>
            </div>
          </div>

          <div class="an-dropdown">
            <a href="network.html" class="an-link ${isActive('network')}">Network ▾</a>
            <div class="an-dropdown-menu">
              <a href="analytics.html">Analytics</a>
              <a href="request-chain.html">Request a Chain</a>
              <a href="my-contracts.html">My Contracts</a>
              <a href="close-contract.html">Close Contract</a>
              <a href="x402-setup.html">x402 Payments</a>
            </div>
          </div>

          <a href="https://docs.arkeo.network" target="_blank" rel="noopener" class="an-link">Docs</a>
        </div>

        <button class="an-hamburger" onclick="toggleMobileMenu()">☰</button>
      </div>

      <div class="an-mobile" id="anMobile">
        <div class="an-mobile-section">
          <div class="an-mobile-label">Apps</div>
          <a href="index.html">Home / Frontends</a>
        </div>
        <div class="an-mobile-section">
          <div class="an-mobile-label">Data</div>
          <a href="data.html">Provider Directory</a>
          <a href="subscribe.html">Subscribe / Buy Data</a>
          <a href="agents.html">AI Agents</a>
          <a href="test-arkauth.html">Test Connection</a>
        </div>
        <div class="an-mobile-section">
          <div class="an-mobile-label">Providers</div>
          <a href="providers.html">Overview & Leaderboard</a>
          <a href="become-provider.html">Become a Provider</a>
          <a href="x402-provider-guide.html">x402 Provider Guide</a>
          <a href="cli-reference.html">CLI Reference</a>
        </div>
        <div class="an-mobile-section">
          <div class="an-mobile-label">Network</div>
          <a href="analytics.html">Analytics</a>
          <a href="request-chain.html">Request a Chain</a>
          <a href="my-contracts.html">My Contracts</a>
          <a href="x402-setup.html">x402 Payments</a>
        </div>
        <div class="an-mobile-section">
          <a href="https://docs.arkeo.network" target="_blank">Docs</a>
        </div>
      </div>
    </nav>
  `;
}

function toggleMobileMenu() {
  const m = document.getElementById('anMobile');
  if (m) m.classList.toggle('open');
}

// Auto-init
document.addEventListener('DOMContentLoaded', injectNav);
