"""
Example usage of ArkeoClient (Python)
"""

from arkeo_client import ArkeoClient
import json


def main():
    # Initialize client
    client = ArkeoClient(
        sentinel_url='https://red5-arkeo.duckdns.org',
        contract_id=916,
        private_key='YOUR_PRIVATE_KEY_HEX_OR_MNEMONIC',
        service='arkeo-mainnet-fullnode',
        start_nonce=1
    )
    
    print('🔐 Client Info:')
    print(json.dumps(client.get_info(), indent=2))
    print('')
    
    try:
        # Example 1: Get node status
        print('📡 Making RPC call to /status...')
        status = client.rpc_json('/status')
        network = status.get('result', {}).get('node_info', {}).get('network', status)
        print(f'✅ Status: {network}')
        print('')
        
        # Example 2: Get ABCI info
        print('📡 Making RPC call to /abci_info...')
        abci_info = client.rpc_json('/abci_info')
        data = abci_info.get('result', {}).get('response', {}).get('data', abci_info)
        print(f'✅ ABCI Info: {data}')
        print('')
        
        # Example 3: Get block at height 1
        print('📡 Making RPC call to /block?height=1...')
        block = client.rpc_json('/block?height=1')
        height = block.get('result', {}).get('block', {}).get('header', {}).get('height', block)
        print(f'✅ Block: {height}')
        print('')
        
        print('🎉 All requests successful!')
        print(f'Current nonce: {client.get_nonce()}')
        
    except Exception as error:
        print(f'❌ Error: {error}')
        if hasattr(error, 'response'):
            print(f'Response: {error.response.text[:2000]}')


if __name__ == '__main__':
    main()
