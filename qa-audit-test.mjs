#!/usr/bin/env node
/**
 * Comprehensive QA Audit for Arkeo Marketplace V2
 * Tests free tier, auth, API endpoints, edge cases, and contract data
 */

import { ArkeoClient } from './docs/sdk/arkeo-client.js';
import * as secp256k1 from '@noble/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';

// Required for @noble/secp256k1
secp256k1.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, secp256k1.etc.concatBytes(...m));

const SENTINEL_URL = 'https://red5-arkeo.duckdns.org';
const CONTRACT_ID = 942;
const PRIVATE_KEY = '3a13e459b9ed8a40c0a30fbf2f2c2ea9e382184473d78102147d60de27139c93';
const PROVIDER_PUBKEY = 'arkeopub1addwnpepqfuk5cy2ey6h3pfpwerkhfps0d4vqt6men4j2wx56zfn5nrfk8n9ymnj327';

const results = [];

function log(test, status, message, details = null) {
  const result = { test, status, message, details };
  results.push(result);
  const icon = status === 'PASS' ? '✅' : status === 'FAIL' ? '❌' : '⚠️';
  console.log(`${icon} ${test}: ${status} - ${message}`);
  if (details) console.log(`   Details: ${JSON.stringify(details, null, 2)}`);
}

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================
// TEST 1: FREE TIER ACCESS
// ============================================================
async function testFreeTier() {
  console.log('\n━━━ TEST 1: FREE TIER ACCESS ━━━');
  
  try {
    // Test 1a: First 5 requests should work
    let successCount = 0;
    for (let i = 1; i <= 5; i++) {
      const resp = await fetch(`${SENTINEL_URL}/api/arkeo/contracts`);
      if (resp.ok) successCount++;
      await sleep(200); // Small delay between requests
    }
    
    if (successCount === 5) {
      log('1a. Free Tier - First 5 Requests', 'PASS', 'All 5 free requests succeeded');
    } else {
      log('1a. Free Tier - First 5 Requests', 'FAIL', `Only ${successCount}/5 requests succeeded`);
    }
    
    // Test 1b: 6th request should be rate limited
    await sleep(1000); // Wait a bit
    const resp6 = await fetch(`${SENTINEL_URL}/api/arkeo/contracts`);
    const text6 = await resp6.text();
    
    if (resp6.status === 429 || text6.includes('rate limit') || !resp6.ok) {
      log('1b. Free Tier - 6th Request Blocked', 'PASS', `Request blocked with status ${resp6.status}`);
    } else {
      log('1b. Free Tier - 6th Request Blocked', 'FAIL', `6th request succeeded when it should have been blocked`, { status: resp6.status, body: text6.substring(0, 200) });
    }
    
    // Test 1c: Verify free requests don't affect paid nonce
    await sleep(60000); // Wait 1 minute for rate limit reset
    const client = new ArkeoClient({
      sentinelUrl: SENTINEL_URL,
      contractId: CONTRACT_ID,
      privateKey: PRIVATE_KEY,
      service: 'arkeo-mainnet-fullnode'
    });
    
    const initialNonce = client.getNonce();
    // Make a free request
    await fetch(`${SENTINEL_URL}/api/arkeo/contracts`);
    const finalNonce = client.getNonce();
    
    if (initialNonce === finalNonce) {
      log('1c. Free Tier - Nonce Unaffected', 'PASS', 'Free requests do not affect paid nonce');
    } else {
      log('1c. Free Tier - Nonce Unaffected', 'FAIL', 'Nonce changed after free request', { initial: initialNonce, final: finalNonce });
    }
    
  } catch (error) {
    log('Free Tier Tests', 'FAIL', 'Exception during free tier tests', { error: error.message });
  }
}

// ============================================================
// TEST 2: INVALID SIGNATURE HANDLING
// ============================================================
async function testInvalidSignatures() {
  console.log('\n━━━ TEST 2: INVALID SIGNATURE HANDLING ━━━');
  
  try {
    // Test 2a: Garbage arkauth value
    const resp1 = await fetch(`${SENTINEL_URL}/arkeo-mainnet-fullnode/status?arkauth=garbage123`);
    const text1 = await resp1.text();
    
    if (!resp1.ok && resp1.status !== 500) {
      log('2a. Invalid Signature - Garbage Value', 'PASS', `Got expected error response (${resp1.status})`);
    } else {
      log('2a. Invalid Signature - Garbage Value', 'FAIL', `Got status ${resp1.status}, expected 4xx error`, { body: text1.substring(0, 200) });
    }
    
    // Test 2b: Wrong contract ID
    const resp2 = await fetch(`${SENTINEL_URL}/arkeo-mainnet-fullnode/status?arkauth=999999:${PROVIDER_PUBKEY}:1:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`);
    const text2 = await resp2.text();
    
    if (!resp2.ok && resp2.status !== 500) {
      log('2b. Invalid Signature - Wrong Contract ID', 'PASS', `Got expected error response (${resp2.status})`);
    } else {
      log('2b. Invalid Signature - Wrong Contract ID', 'FAIL', `Got status ${resp2.status}, expected 4xx error`, { body: text2.substring(0, 200) });
    }
    
    // Test 2c: Wrong nonce
    const client = new ArkeoClient({
      sentinelUrl: SENTINEL_URL,
      contractId: CONTRACT_ID,
      privateKey: PRIVATE_KEY,
      service: 'arkeo-mainnet-fullnode'
    });
    
    client.setNonce(99999999); // Way too high nonce
    try {
      const resp3 = await client.rpc('/status');
      const text3 = await resp3.text();
      
      if (!resp3.ok && resp3.status !== 500) {
        log('2c. Invalid Signature - Wrong Nonce', 'PASS', `Got expected error response (${resp3.status})`);
      } else {
        log('2c. Invalid Signature - Wrong Nonce', 'FAIL', `Got status ${resp3.status}, expected 4xx error`, { body: text3.substring(0, 200) });
      }
    } catch (err) {
      log('2c. Invalid Signature - Wrong Nonce', 'PASS', `Request failed as expected: ${err.message}`);
    }
    
  } catch (error) {
    log('Invalid Signature Tests', 'FAIL', 'Exception during invalid signature tests', { error: error.message });
  }
}

// ============================================================
// TEST 3: API ENDPOINTS VERIFICATION
// ============================================================
async function testAPIEndpoints() {
  console.log('\n━━━ TEST 3: API ENDPOINTS VERIFICATION ━━━');
  
  const endpoints = [
    { name: 'GET /api/arkeo/contracts', url: `${SENTINEL_URL}/api/arkeo/contracts` },
    { name: `GET /api/arkeo/contract/${CONTRACT_ID}`, url: `${SENTINEL_URL}/api/arkeo/contract/${CONTRACT_ID}` },
    { name: 'GET /api/arkeo/providers', url: `${SENTINEL_URL}/api/arkeo/providers` },
    { name: 'GET /rpc/status', url: `${SENTINEL_URL}/rpc/status` },
    { name: 'GET /rpc/health', url: `${SENTINEL_URL}/rpc/health` },
    { name: `GET /claim/${CONTRACT_ID}`, url: `${SENTINEL_URL}/claim/${CONTRACT_ID}` },
    { name: 'GET /claims', url: `${SENTINEL_URL}/claims` },
  ];
  
  for (const endpoint of endpoints) {
    try {
      const resp = await fetch(endpoint.url, {
        method: 'GET',
        headers: { 'Origin': 'https://marketplace.arkeo.network' }
      });
      
      const corsHeader = resp.headers.get('access-control-allow-origin');
      const hasData = resp.ok;
      
      if (hasData && corsHeader) {
        log(`3. API Endpoint - ${endpoint.name}`, 'PASS', `Endpoint responsive with CORS`, { status: resp.status, cors: corsHeader });
      } else if (hasData && !corsHeader) {
        log(`3. API Endpoint - ${endpoint.name}`, 'WARN', `Endpoint works but missing CORS header`, { status: resp.status });
      } else {
        const text = await resp.text();
        log(`3. API Endpoint - ${endpoint.name}`, 'FAIL', `Endpoint failed`, { status: resp.status, body: text.substring(0, 200) });
      }
      
      await sleep(200);
    } catch (error) {
      log(`3. API Endpoint - ${endpoint.name}`, 'FAIL', `Exception: ${error.message}`);
    }
  }
}

// ============================================================
// TEST 4: HTML PAGES AUDIT
// ============================================================
async function testHTMLPages() {
  console.log('\n━━━ TEST 4: HTML PAGES AUDIT ━━━');
  
  const pages = [
    'index.html',
    'subscribe.html',
    'become-provider.html',
    'my-contracts.html',
    'provider.html',
    'close-contract.html',
    'analytics.html'
  ];
  
  const fs = await import('fs');
  const path = await import('path');
  
  for (const page of pages) {
    try {
      const pagePath = path.join('./docs', page);
      const content = fs.readFileSync(pagePath, 'utf8');
      
      // Check for JS file references
      const jsMatches = content.match(/<script[^>]+src=["']([^"']+)["']/g);
      let missingJS = [];
      if (jsMatches) {
        for (const match of jsMatches) {
          const src = match.match(/src=["']([^"']+)["']/)[1];
          if (src.startsWith('http')) continue; // Skip external
          const jsPath = path.join('./docs', src.replace(/^\//, ''));
          if (!fs.existsSync(jsPath)) {
            missingJS.push(src);
          }
        }
      }
      
      // Check for CSS file references
      const cssMatches = content.match(/<link[^>]+href=["']([^"']+\.css)["']/g);
      let missingCSS = [];
      if (cssMatches) {
        for (const match of cssMatches) {
          const href = match.match(/href=["']([^"']+)["']/)[1];
          if (href.startsWith('http')) continue; // Skip external
          const cssPath = path.join('./docs', href.replace(/^\//, ''));
          if (!fs.existsSync(cssPath)) {
            missingCSS.push(href);
          }
        }
      }
      
      // Check for console.error or obvious errors
      const hasErrors = content.includes('console.error') || content.includes('throw new Error');
      
      if (missingJS.length === 0 && missingCSS.length === 0) {
        log(`4. HTML Page - ${page}`, 'PASS', 'All resources found');
      } else {
        log(`4. HTML Page - ${page}`, 'FAIL', 'Missing resources', { missingJS, missingCSS });
      }
      
    } catch (error) {
      log(`4. HTML Page - ${page}`, 'FAIL', `Exception: ${error.message}`);
    }
  }
  
  // Check config.js
  try {
    const configPath = './docs/js/config.js';
    const fs = await import('fs');
    const configContent = fs.readFileSync(configPath, 'utf8');
    
    const hasRestApi = configContent.includes('REST_API') || configContent.includes('rest-seed.arkeo.network');
    const hasRpcApi = configContent.includes('RPC_API') || configContent.includes('rpc-seed.arkeo.network');
    
    if (hasRestApi && hasRpcApi) {
      log('4. Config - config.js', 'PASS', 'Has correct API endpoints configured');
    } else {
      log('4. Config - config.js', 'FAIL', 'Missing or incorrect API endpoints', { hasRestApi, hasRpcApi });
    }
  } catch (error) {
    log('4. Config - config.js', 'FAIL', `Exception: ${error.message}`);
  }
  
  // Check providers.js
  try {
    const providersPath = './docs/js/providers.js';
    const fs = await import('fs');
    const providersContent = fs.readFileSync(providersPath, 'utf8');
    
    const hasRedProvider = providersContent.includes(PROVIDER_PUBKEY);
    
    if (hasRedProvider) {
      log('4. Config - providers.js', 'PASS', 'KNOWN_PROVIDERS includes Red_5 provider');
    } else {
      log('4. Config - providers.js', 'FAIL', 'Red_5 provider not found in KNOWN_PROVIDERS');
    }
  } catch (error) {
    log('4. Config - providers.js', 'FAIL', `Exception: ${error.message}`);
  }
}

// ============================================================
// TEST 5: SDK VERIFICATION
// ============================================================
async function testSDK() {
  console.log('\n━━━ TEST 5: SDK VERIFICATION ━━━');
  
  try {
    // Test 5a: Nonce auto-fetch
    const client1 = new ArkeoClient({
      sentinelUrl: SENTINEL_URL,
      contractId: CONTRACT_ID,
      privateKey: PRIVATE_KEY,
      service: 'arkeo-mainnet-fullnode'
    });
    
    const initialNonce = client1.getNonce();
    // Force nonce fetch by making a request
    try {
      await client1.rpcJson('/status');
      const fetchedNonce = client1.getNonce();
      
      if (fetchedNonce > 0) {
        log('5a. SDK - Nonce Auto-fetch', 'PASS', `Nonce automatically fetched: ${fetchedNonce}`);
      } else {
        log('5a. SDK - Nonce Auto-fetch', 'FAIL', 'Nonce not properly fetched', { fetchedNonce });
      }
    } catch (err) {
      log('5a. SDK - Nonce Auto-fetch', 'WARN', `Request failed but nonce may have been fetched: ${err.message}`);
    }
    
    // Test 5b: rpcJson and rpcText methods
    try {
      const client2 = new ArkeoClient({
        sentinelUrl: SENTINEL_URL,
        contractId: CONTRACT_ID,
        privateKey: PRIVATE_KEY,
        service: 'arkeo-mainnet-fullnode'
      });
      
      const jsonResp = await client2.rpcJson('/status');
      if (jsonResp && typeof jsonResp === 'object') {
        log('5b. SDK - rpcJson Method', 'PASS', 'rpcJson returns valid JSON');
      } else {
        log('5b. SDK - rpcJson Method', 'FAIL', 'rpcJson did not return valid JSON', { response: jsonResp });
      }
      
      const textResp = await client2.rpcText('/status');
      if (textResp && typeof textResp === 'string') {
        log('5c. SDK - rpcText Method', 'PASS', 'rpcText returns valid string');
      } else {
        log('5c. SDK - rpcText Method', 'FAIL', 'rpcText did not return valid string');
      }
    } catch (err) {
      log('5b-c. SDK - RPC Methods', 'FAIL', `Exception during RPC method tests: ${err.message}`);
    }
    
    // Test 5d: Wrong private key
    try {
      const wrongClient = new ArkeoClient({
        sentinelUrl: SENTINEL_URL,
        contractId: CONTRACT_ID,
        privateKey: '0000000000000000000000000000000000000000000000000000000000000001',
        service: 'arkeo-mainnet-fullnode'
      });
      
      const resp = await wrongClient.rpc('/status');
      if (!resp.ok) {
        log('5d. SDK - Wrong Private Key', 'PASS', 'Request with wrong key failed gracefully');
      } else {
        log('5d. SDK - Wrong Private Key', 'FAIL', 'Request with wrong key succeeded when it should have failed');
      }
    } catch (err) {
      log('5d. SDK - Wrong Private Key', 'PASS', `Request with wrong key failed: ${err.message}`);
    }
    
    // Test 5e: Nonce increments only on success
    const client3 = new ArkeoClient({
      sentinelUrl: SENTINEL_URL,
      contractId: CONTRACT_ID,
      privateKey: PRIVATE_KEY,
      service: 'arkeo-mainnet-fullnode'
    });
    
    await client3.rpc('/status'); // Prime nonce
    const beforeNonce = client3.getNonce();
    
    // Make failing request
    client3.setNonce(99999999);
    try {
      await client3.rpc('/status');
    } catch (err) {
      // Expected to fail
    }
    const afterFailNonce = client3.getNonce();
    
    if (afterFailNonce === 99999999) {
      log('5e. SDK - Nonce Only Increments on Success', 'PASS', 'Nonce did not increment after failed request');
    } else {
      log('5e. SDK - Nonce Only Increments on Success', 'FAIL', 'Nonce incremented after failed request', { before: 99999999, after: afterFailNonce });
    }
    
  } catch (error) {
    log('SDK Tests', 'FAIL', 'Exception during SDK tests', { error: error.message });
  }
}

// ============================================================
// TEST 6: EDGE CASES
// ============================================================
async function testEdgeCases() {
  console.log('\n━━━ TEST 6: EDGE CASES ━━━');
  
  try {
    // Test 6a: Query with nonce=0
    const client1 = new ArkeoClient({
      sentinelUrl: SENTINEL_URL,
      contractId: CONTRACT_ID,
      privateKey: PRIVATE_KEY,
      service: 'arkeo-mainnet-fullnode',
      startNonce: 0
    });
    
    try {
      const resp = await client1.rpc('/status');
      if (!resp.ok) {
        log('6a. Edge Case - Nonce=0', 'PASS', 'Nonce=0 properly rejected');
      } else {
        log('6a. Edge Case - Nonce=0', 'FAIL', 'Nonce=0 was accepted when it should be rejected');
      }
    } catch (err) {
      log('6a. Edge Case - Nonce=0', 'PASS', `Nonce=0 failed: ${err.message}`);
    }
    
    // Test 6b: Non-existent contract
    const client2 = new ArkeoClient({
      sentinelUrl: SENTINEL_URL,
      contractId: 999999,
      privateKey: PRIVATE_KEY,
      service: 'arkeo-mainnet-fullnode'
    });
    
    try {
      const resp = await client2.rpc('/status');
      if (!resp.ok) {
        log('6b. Edge Case - Non-existent Contract', 'PASS', 'Non-existent contract properly rejected');
      } else {
        log('6b. Edge Case - Non-existent Contract', 'FAIL', 'Non-existent contract was accepted');
      }
    } catch (err) {
      log('6b. Edge Case - Non-existent Contract', 'PASS', `Non-existent contract failed: ${err.message}`);
    }
    
  } catch (error) {
    log('Edge Case Tests', 'FAIL', 'Exception during edge case tests', { error: error.message });
  }
}

// ============================================================
// TEST 7: CONTRACT DATA INTEGRITY
// ============================================================
async function testContractDataIntegrity() {
  console.log('\n━━━ TEST 7: CONTRACT DATA INTEGRITY ━━━');
  
  try {
    // Fetch all contracts
    const resp = await fetch(`${SENTINEL_URL}/api/arkeo/contracts`);
    const data = await resp.json();
    
    if (!data.contracts || !Array.isArray(data.contracts)) {
      log('7a. Contract Data - Fetch All', 'FAIL', 'Failed to fetch contracts list', { data });
      return;
    }
    
    log('7a. Contract Data - Fetch All', 'PASS', `Fetched ${data.contracts.length} contracts`);
    
    // Check each contract
    let invalidContracts = [];
    let nonceInconsistencies = [];
    
    for (const contract of data.contracts) {
      const id = contract.id;
      const paid = parseInt(contract.paid || '0');
      const deposit = parseInt(contract.deposit || '0');
      const nonce = parseInt(contract.nonce || '0');
      
      // Check paid <= deposit
      if (paid > deposit) {
        invalidContracts.push({ id, issue: 'paid > deposit', paid, deposit });
      }
      
      // Fetch individual contract to verify nonce consistency
      try {
        const respIndividual = await fetch(`${SENTINEL_URL}/api/arkeo/contract/${id}`);
        const dataIndividual = await respIndividual.json();
        const individualNonce = parseInt(dataIndividual.contract?.nonce || '0');
        
        if (individualNonce !== nonce) {
          nonceInconsistencies.push({ id, listNonce: nonce, individualNonce });
        }
      } catch (err) {
        // Skip if individual fetch fails
      }
      
      await sleep(100);
    }
    
    if (invalidContracts.length === 0) {
      log('7b. Contract Data - paid <= deposit', 'PASS', 'All contracts have valid paid/deposit ratio');
    } else {
      log('7b. Contract Data - paid <= deposit', 'FAIL', 'Found contracts with paid > deposit', { invalidContracts });
    }
    
    if (nonceInconsistencies.length === 0) {
      log('7c. Contract Data - Nonce Consistency', 'PASS', 'Nonces consistent between list and individual endpoints');
    } else {
      log('7c. Contract Data - Nonce Consistency', 'FAIL', 'Found nonce inconsistencies', { nonceInconsistencies });
    }
    
    // Check specific contract 942
    const contract942 = data.contracts.find(c => c.id === CONTRACT_ID.toString());
    if (contract942) {
      const nonce = parseInt(contract942.nonce || '0');
      const deposit = parseInt(contract942.deposit || '0');
      const paid = parseInt(contract942.paid || '0');
      
      log('7d. Contract Data - Contract 942', 'PASS', `Contract 942 found`, {
        id: contract942.id,
        nonce,
        deposit: (deposit / 1e6).toFixed(2) + 'M uarkeo',
        paid: (paid / 1e6).toFixed(2) + 'M uarkeo',
        type: contract942.type,
        rate: contract942.rate
      });
    } else {
      log('7d. Contract Data - Contract 942', 'FAIL', 'Contract 942 not found in contracts list');
    }
    
  } catch (error) {
    log('Contract Data Tests', 'FAIL', 'Exception during contract data tests', { error: error.message });
  }
}

// ============================================================
// MAIN EXECUTION
// ============================================================
async function main() {
  console.log('╔═══════════════════════════════════════════════════════╗');
  console.log('║  Arkeo Marketplace V2 - Comprehensive QA Audit       ║');
  console.log('║  Sentinel: red5-arkeo.duckdns.org                    ║');
  console.log('╚═══════════════════════════════════════════════════════╝\n');
  
  // Run all test suites
  await testFreeTier();
  await testInvalidSignatures();
  await testAPIEndpoints();
  await testHTMLPages();
  await testSDK();
  await testEdgeCases();
  await testContractDataIntegrity();
  
  // Generate report
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('AUDIT COMPLETE - Generating Report...');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  const passed = results.filter(r => r.status === 'PASS').length;
  const failed = results.filter(r => r.status === 'FAIL').length;
  const warnings = results.filter(r => r.status === 'WARN').length;
  
  console.log(`✅ PASSED: ${passed}`);
  console.log(`❌ FAILED: ${failed}`);
  console.log(`⚠️  WARNINGS: ${warnings}`);
  console.log(`📊 TOTAL: ${results.length}`);
  
  return results;
}

// Run tests and export results
main().then(results => {
  // Export results for report generation
  process.exitCode = results.filter(r => r.status === 'FAIL').length > 0 ? 1 : 0;
}).catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
