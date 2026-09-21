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
  string metadataUri = 4;
  uint64 metadataNonce = 5;
  int32 status = 6;
  int64 minContractDuration = 7;
  int64 maxContractDuration = 8;
  repeated Coin subscriptionRate = 9;
  repeated Coin payAsYouGoRate = 10;
  int64 settlementDuration = 11;
}

message MsgOpenContract {
  string creator = 1;
  string provider = 2;
  string service = 3;
  string client = 4;
  string delegate = 5;
  int32 contractType = 6;
  int64 duration = 7;
  Coin rate = 8;
  string deposit = 9;
  int64 settlementDuration = 10;
  int32 authorization = 11;
  int64 queriesPerMinute = 12;
}

message MsgCloseContract {
  string creator = 1;
  uint64 contract_id = 2;
  string client = 3;
  string delegate = 4;
}

message MsgClaimContractIncome {
  string creator = 1;
  uint64 contract_id = 2;
  bytes signature = 4;
  int64 nonce = 5;
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
    
    // Load Long.js first (required for int64 support)
    if (!window.Long) {
      await this.loadScript('https://cdn.jsdelivr.net/npm/long@5.2.3/umd/index.min.js');
    }
    
    // Load protobuf.js from CDN
    if (!window.protobuf) {
      await this.loadScript('https://cdn.jsdelivr.net/npm/protobufjs@7.6.6/dist/protobuf.min.js');
    }
    
    // Configure protobufjs to use Long
    if (window.Long && window.protobuf) {
      protobuf.util.Long = window.Long;
      protobuf.configure();
    }
    
    // Parse the proto definitions
    this.root = protobuf.parse(ARKEO_PROTO).root;
    this.cosmosRoot = protobuf.parse(COSMOS_PROTO).root;
    
    // Arkeo messages
    this.MsgBondProvider = this.root.lookupType('arkeo.arkeo.MsgBondProvider');
    this.MsgModProvider = this.root.lookupType('arkeo.arkeo.MsgModProvider');
    this.MsgOpenContract = this.root.lookupType('arkeo.arkeo.MsgOpenContract');
    this.MsgCloseContract = this.root.lookupType('arkeo.arkeo.MsgCloseContract');
    this.MsgClaimContractIncome = this.root.lookupType('arkeo.arkeo.MsgClaimContractIncome');
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

  // SRI hashes for dynamically loaded CDN scripts
  static SRI_HASHES = {
    'https://cdn.jsdelivr.net/npm/long@5.2.3/umd/index.min.js': 'sha384-WMR9gjTtdEVLsU2eEynLDmwo7Fv0l59CyDWb5zzAPWBVxEsh3bz9V3A/YW4yZW1K',
    'https://cdn.jsdelivr.net/npm/protobufjs@7.6.6/dist/protobuf.min.js': 'sha384-RcCYQWe/1f2wGOto33rpxe6p/aNfxBAda7lSQgQvLW+WDT5X6jZZhPjhWBTM7hVh',
  };

  // Allowed CDN origins for dynamic script loading
  static ALLOWED_SCRIPT_ORIGINS = [
    'https://cdn.jsdelivr.net',
  ];

  loadScript(src) {
    return new Promise((resolve, reject) => {
      // Validate URL origin against allowlist
      try {
        const url = new URL(src);
        const allowed = ArkeoTxHelper.ALLOWED_SCRIPT_ORIGINS.some(origin => url.origin === origin);
        if (!allowed || !ArkeoTxHelper.SRI_HASHES[src]) {
          return reject(new Error(`Script origin not allowed: ${url.origin}`));
        }
      } catch (e) {
        return reject(new Error(`Invalid script URL: ${src}`));
      }

      const script = document.createElement('script');
      script.src = src;
      script.crossOrigin = 'anonymous';

      // Add SRI hash if available
      const sriHash = ArkeoTxHelper.SRI_HASHES[src];
      if (sriHash) {
        script.integrity = sriHash;
      }

      script.onload = resolve;
      script.onerror = reject;
      document.head.appendChild(script);
    });
  }

  integer(value, fallback, unsigned = false) {
    const input = value === undefined || value === null || value === '' ? fallback : value;
    if (typeof input === 'number' && !Number.isSafeInteger(input)) throw new Error('Unsafe integer; use a decimal string');
    const text = String(input);
    const maximum = unsigned ? 18446744073709551615n : 9223372036854775807n;
    if (!/^(0|[1-9][0-9]*)$/.test(text) || BigInt(text) > maximum) throw new Error('Integer outside supported range');
    if (!window.Long) throw new Error('Initialize transaction encoder before use');
    return window.Long.fromString(text, unsigned);
  }

  enumValue(value, fallback, allowed) {
    const n = Number(value === undefined || value === null || value === '' ? fallback : value);
    if (!Number.isInteger(n) || !allowed.includes(n)) throw new Error('Invalid enum value');
    return n;
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
    // protobufjs converts snake_case to camelCase automatically
    const subscriptionRate = (params.subscriptionRate || []).map(coin => 
      this.ArkeoCoin.create({ denom: coin.denom, amount: String(coin.amount) })
    );
    
    const payAsYouGoRate = (params.payAsYouGoRate || []).map(coin => 
      this.ArkeoCoin.create({ denom: coin.denom, amount: String(coin.amount) })
    );
    
    console.log('Encoding subscriptionRate:', subscriptionRate);
    console.log('Encoding payAsYouGoRate:', payAsYouGoRate);
    console.log('minContractDuration input:', params.minContractDuration, '→', parseInt(params.minContractDuration) || 10);
    
    // Use Long for int64 fields
    const Long = window.Long;
    const minDur = this.integer(params.minContractDuration, 10);
    const maxDur = this.integer(params.maxContractDuration, 1000000);
    const settleDur = this.integer(params.settlementDuration, 10);
    
    console.log('Duration values (Long):', { minDur, maxDur, settleDur });
    
    const message = this.MsgModProvider.create({
      creator: params.creator,
      provider: params.provider,
      service: params.service,
      metadataUri: params.metadataUri || '',
      metadataNonce: this.integer(params.metadataNonce, 1, true),
      status: this.enumValue(params.status, 1, [0, 1]),
      minContractDuration: minDur,
      maxContractDuration: maxDur,
      subscriptionRate: subscriptionRate,
      payAsYouGoRate: payAsYouGoRate,
      settlementDuration: settleDur
    });
    
    console.log('MsgModProvider message:', message);
    return this.MsgModProvider.encode(message).finish();
  }

  encodeOpenContract(params) {
    const Long = window.Long;
    
    const rate = this.ArkeoCoin.create({
      denom: params.rate.denom,
      amount: String(params.rate.amount)
    });
    
    const duration = this.integer(params.duration, 1000000);
    const settlementDuration = this.integer(params.settlementDuration, 10);
    const queriesPerMinute = this.integer(params.queriesPerMinute, 100);
    
    const message = this.MsgOpenContract.create({
      creator: params.creator,
      provider: params.provider,
      service: params.service,
      client: params.client,
      delegate: params.delegate || '',
      contractType: this.enumValue(params.contractType, 1, [0, 1]), // PAY_AS_YOU_GO = 1
      duration: duration,
      rate: rate,
      deposit: String(params.deposit),
      settlementDuration: settlementDuration,
      authorization: this.enumValue(params.authorization, 0, [0, 1]), // STRICT = 0
      queriesPerMinute: queriesPerMinute
    });
    
    console.log('MsgOpenContract message:', message);
    return this.MsgOpenContract.encode(message).finish();
  }

  encodeCloseContract(params) {
    const Long = window.Long;
    const message = this.MsgCloseContract.create({
      creator: params.creator,
      contractId: this.integer(params.contractId, undefined, true),
      client: params.client || '',
      delegate: params.delegate || ''
    });
    console.log('MsgCloseContract message:', message);
    return this.MsgCloseContract.encode(message).finish();
  }

  encodeClaimContractIncome(params) {
    const Long = window.Long;
    const message = this.MsgClaimContractIncome.create({
      creator: params.creator,
      contractId: this.integer(params.contractId, undefined, true),
      signature: params.signature || new Uint8Array(0),
      nonce: this.integer(params.nonce, undefined)
    });
    console.log('MsgClaimContractIncome message:', message);
    return this.MsgClaimContractIncome.encode(message).finish();
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
      } else if (msg.typeUrl === '/arkeo.arkeo.MsgOpenContract') {
        msgBytes = this.encodeOpenContract(msg.value);
      } else if (msg.typeUrl === '/arkeo.arkeo.MsgCloseContract') {
        msgBytes = this.encodeCloseContract(msg.value);
      } else if (msg.typeUrl === '/arkeo.arkeo.MsgClaimContractIncome') {
        msgBytes = this.encodeClaimContractIncome(msg.value);
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
      sequence: this.integer(sequence, undefined, true)
    });
    
    const fee = this.Fee.create({
      amount: [this.Coin.create({ denom: 'uarkeo', amount: feeAmount })],
      gasLimit: this.integer(gasLimit, undefined, true)
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
      accountNumber: this.integer(accountNumber, undefined, true)
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
