/**
 * Example usage of ArkeoClient
 */

import { ArkeoClient } from './arkeo-client.js';

async function main() {
  // Initialize client
  const client = new ArkeoClient({
    sentinelUrl: 'https://red5-arkeo.duckdns.org',
    contractId: 916,
    privateKey: 'YOUR_PRIVATE_KEY_HEX_OR_MNEMONIC',
    service: 'arkeo-mainnet-fullnode',
    startNonce: 1
  });
  
  console.log('🔐 Client Info:');
  console.log(client.getInfo());
  console.log('');
  
  try {
    // Example 1: Get node status
    console.log('📡 Making RPC call to /status...');
    const status = await client.rpcJson('/status');
    console.log('✅ Status:', status.result?.node_info?.network || status);
    console.log('');
    
    // Example 2: Get ABCI info
    console.log('📡 Making RPC call to /abci_info...');
    const abciInfo = await client.rpcJson('/abci_info');
    console.log('✅ ABCI Info:', abciInfo.result?.response?.data || abciInfo);
    console.log('');
    
    // Example 3: Get block at height 1
    console.log('📡 Making RPC call to /block?height=1...');
    const block = await client.rpcJson('/block?height=1');
    console.log('✅ Block:', block.result?.block?.header?.height || block);
    console.log('');
    
    console.log('🎉 All requests successful!');
    console.log('Current nonce:', client.getNonce());
    
  } catch (error) {
    console.error('❌ Error:', error.message);
    
    if (error.response) {
      const text = await error.response.text();
      console.error('Response:', text);
    }
  }
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}

export default main;
