// Arkeo Transaction Helper
// Uses protobuf.js for proper message encoding

const ARKEO_PROTO = `
syntax = "proto3";
package arkeo.arkeo;

message MsgBondProvider {
  string creator = 1;
  string provider = 2;
  string service = 3;
  string bond = 4;
}

message MsgModProvider {
  string creator = 1;
  string provider = 2;
  string service = 3;
  string metadata_uri = 4;
  uint64 metadata_nonce = 5;
  int32 status = 6;
  int64 min_contract_duration = 7;
  int64 max_contract_duration = 8;
  repeated Coin subscription_rate = 9;
  repeated Coin pay_as_you_go_rate = 10;
  int64 settlement_duration = 11;
}

message Coin {
  string denom = 1;
  string amount = 2;
}
`;

const COSMOS_PROTO = `
syntax = "proto3";

message Any {
  string type_url = 1;
  bytes value = 2;
}

message TxBody {
  repeated Any messages = 1;
  string memo = 2;
  uint64 timeout_height = 3;
  repeated Any extension_options = 1023;
  repeated Any non_critical_extension_options = 2047;
}

message AuthInfo {
  repeated SignerInfo signer_infos = 1;
  Fee fee = 2;
}

message SignerInfo {
  Any public_key = 1;
  ModeInfo mode_info = 2;
  uint64 sequence = 3;
}

message ModeInfo {
  oneof sum {
    Single single = 1;
  }
  message Single {
    int32 mode = 1;
  }
}

message Fee {
  repeated Coin amount = 1;
  uint64 gas_limit = 2;
  string payer = 3;
  string granter = 4;
}

message Coin {
  string denom = 1;
  string amount = 2;
}

message PubKey {
  bytes key = 1;
}

message TxRaw {
  bytes body_bytes = 1;
  bytes auth_info_bytes = 2;
  repeated bytes signatures = 3;
}

message SignDoc {
  bytes body_bytes = 1;
  bytes auth_info_bytes = 2;
  string chain_id = 3;
  uint64 account_number = 4;
}
`;

class ArkeoTxHelper {
  constructor() {
    this.root = null;
    this.cosmosRoot = null;
    this.initialized = false;
  }

  async init() {
    if (this.initialized) return;
    
    // Load protobuf.js from CDN
    if (!window.protobuf) {
      await this.loadScript('https://cdn.jsdelivr.net/npm/protobufjs@7.2.6/dist/protobuf.min.js');
    }
    
    // Parse the proto definitions
    this.root = protobuf.parse(ARKEO_PROTO).root;
    this.cosmosRoot = protobuf.parse(COSMOS_PROTO).root;
    
    // Arkeo messages
    this.MsgBondProvider = this.root.lookupType('arkeo.arkeo.MsgBondProvider');
    this.MsgModProvider = this.root.lookupType('arkeo.arkeo.MsgModProvider');
    this.ArkeoCoin = this.root.lookupType('arkeo.arkeo.Coin');
    
    // Cosmos tx types
    this.Any = this.cosmosRoot.lookupType('Any');
    this.TxBody = this.cosmosRoot.lookupType('TxBody');
    this.AuthInfo = this.cosmosRoot.lookupType('AuthInfo');
    this.SignerInfo = this.cosmosRoot.lookupType('SignerInfo');
    this.ModeInfo = this.cosmosRoot.lookupType('ModeInfo');
    this.Fee = this.cosmosRoot.lookupType('Fee');
    this.Coin = this.cosmosRoot.lookupType('Coin');
    this.PubKey = this.cosmosRoot.lookupType('PubKey');
    this.TxRaw = this.cosmosRoot.lookupType('TxRaw');
    this.SignDoc = this.cosmosRoot.lookupType('SignDoc');
    
    this.initialized = true;
    console.log('ArkeoTxHelper initialized');
  }

  loadScript(src) {
    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = src;
      script.onload = resolve;
      script.onerror = reject;
      document.head.appendChild(script);
    });
  }

  encodeBondProvider(creator, provider, service, bond) {
    const message = this.MsgBondProvider.create({
      creator: creator,
      provider: provider,
      service: service,
      bond: bond
    });
    return this.MsgBondProvider.encode(message).finish();
  }

  encodeModProvider(params) {
    const payAsYouGoRate = params.payAsYouGoRate.map(coin => 
      this.Coin.create({ denom: coin.denom, amount: coin.amount })
    );
    
    const message = this.MsgModProvider.create({
      creator: params.creator,
      provider: params.provider,
      service: params.service,
      metadataUri: params.metadataUri || '',
      metadataNonce: params.metadataNonce || 1,
      status: params.status || 1,
      minContractDuration: params.minContractDuration || 10,
      maxContractDuration: params.maxContractDuration || 1000000,
      subscriptionRate: [],
      payAsYouGoRate: payAsYouGoRate,
      settlementDuration: params.settlementDuration || 10
    });
    return this.MsgModProvider.encode(message).finish();
  }

  // Create a proper Any-wrapped message
  wrapAsAny(typeUrl, value) {
    // Manually create the Any message
    // Any = { type_url: string, value: bytes }
    const typeUrlBytes = new TextEncoder().encode(typeUrl);
    
    // Encode as protobuf:
    // field 1 (type_url): tag=10 (field 1, wire type 2), length, string
    // field 2 (value): tag=18 (field 2, wire type 2), length, bytes
    const result = [];
    
    // type_url field
    result.push(10); // tag
    this.writeVarint(result, typeUrlBytes.length);
    for (const b of typeUrlBytes) result.push(b);
    
    // value field  
    result.push(18); // tag
    this.writeVarint(result, value.length);
    for (const b of value) result.push(b);
    
    return new Uint8Array(result);
  }

  writeVarint(arr, value) {
    while (value > 127) {
      arr.push((value & 0x7f) | 0x80);
      value >>>= 7;
    }
    arr.push(value);
  }

  bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  
  base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Build TxBody bytes
  buildTxBody(messages, memo = '') {
    const anyMessages = messages.map(msg => {
      let msgBytes;
      if (msg.typeUrl === '/arkeo.arkeo.MsgBondProvider') {
        msgBytes = this.encodeBondProvider(
          msg.value.creator,
          msg.value.provider,
          msg.value.service,
          msg.value.bond
        );
      } else if (msg.typeUrl === '/arkeo.arkeo.MsgModProvider') {
        msgBytes = this.encodeModProvider(msg.value);
      }
      
      return this.Any.create({
        typeUrl: msg.typeUrl,
        value: msgBytes
      });
    });
    
    const txBody = this.TxBody.create({
      messages: anyMessages,
      memo: memo,
      timeoutHeight: 0
    });
    
    return this.TxBody.encode(txBody).finish();
  }

  // Build AuthInfo bytes  
  buildAuthInfo(pubkeyBytes, sequence, feeAmount, gasLimit) {
    const pubkeyAny = this.Any.create({
      typeUrl: '/cosmos.crypto.secp256k1.PubKey',
      value: this.PubKey.encode(this.PubKey.create({ key: pubkeyBytes })).finish()
    });
    
    const signerInfo = this.SignerInfo.create({
      publicKey: pubkeyAny,
      modeInfo: this.ModeInfo.create({
        single: { mode: 1 } // SIGN_MODE_DIRECT = 1
      }),
      sequence: sequence
    });
    
    const fee = this.Fee.create({
      amount: [this.Coin.create({ denom: 'uarkeo', amount: feeAmount })],
      gasLimit: gasLimit
    });
    
    const authInfo = this.AuthInfo.create({
      signerInfos: [signerInfo],
      fee: fee
    });
    
    return this.AuthInfo.encode(authInfo).finish();
  }

  // Build SignDoc for Keplr signDirect
  buildSignDoc(bodyBytes, authInfoBytes, chainId, accountNumber) {
    const signDoc = this.SignDoc.create({
      bodyBytes: bodyBytes,
      authInfoBytes: authInfoBytes,
      chainId: chainId,
      accountNumber: accountNumber
    });
    return this.SignDoc.encode(signDoc).finish();
  }

  // Build final TxRaw
  buildTxRaw(bodyBytes, authInfoBytes, signatures) {
    const txRaw = this.TxRaw.create({
      bodyBytes: bodyBytes,
      authInfoBytes: authInfoBytes,
      signatures: signatures
    });
    return this.TxRaw.encode(txRaw).finish();
  }
}

// Global instance
window.arkeoTx = new ArkeoTxHelper();
