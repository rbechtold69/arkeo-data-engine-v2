"""
ArkeoClient — Python SDK for Arkeo PAYG authenticated RPC calls

Automatically signs requests using ADR-036 signatures with incrementing nonces.
Provides a transparent proxy to any Arkeo sentinel service.

@version 1.0.0
@license MIT
"""

import json
import hashlib
import requests
from typing import Optional, Dict, Any
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string_canonize
from mnemonic import Mnemonic


# Bech32 encoding (BIP-173)
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]


def bech32_polymod(values):
    """Bech32 checksum polymod"""
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= GENERATOR[i]
    return chk


def bech32_hrp_expand(hrp):
    """Expand HRP for bech32"""
    ret = []
    for c in hrp:
        ret.append(ord(c) >> 5)
    ret.append(0)
    for c in hrp:
        ret.append(ord(c) & 31)
    return ret


def bech32_encode(prefix, data):
    """Bech32 encode data with prefix"""
    # Convert 8-bit to 5-bit groups
    words = []
    acc = 0
    bits = 0
    for b in data:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            words.append((acc >> bits) & 31)
    if bits > 0:
        words.append((acc << (5 - bits)) & 31)
    
    # Checksum
    values = bech32_hrp_expand(prefix) + words + [0, 0, 0, 0, 0, 0]
    mod = bech32_polymod(values) ^ 1
    checksum = []
    for i in range(6):
        checksum.append((mod >> (5 * (5 - i))) & 31)
    
    return prefix + '1' + ''.join([CHARSET[w] for w in words + checksum])


def private_key_from_mnemonic(mnemonic_phrase: str) -> bytes:
    """Derive private key from mnemonic (simplified BIP-39)"""
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic_phrase)
    # Simplified derivation (for production use proper BIP-32)
    return hashlib.sha256(seed).digest()[:32]


def encode_pubkey_bech32(pubkey_bytes: bytes) -> str:
    """Encode public key in amino format with bech32 (arkeopub prefix)"""
    # Amino prefix for secp256k1: eb5ae987 21
    amino_prefix = bytes([0xeb, 0x5a, 0xe9, 0x87, 0x21])
    prefixed = amino_prefix + pubkey_bytes
    return bech32_encode('arkeopub', prefixed)


def pubkey_to_address(pubkey_bytes: bytes) -> str:
    """Get bech32 address from public key (arkeo prefix)"""
    hash1 = hashlib.sha256(pubkey_bytes).digest()
    hash2 = hashlib.new('ripemd160', hash1).digest()
    return bech32_encode('arkeo', hash2)


def build_adr036_signdoc(signer_address: str, data: bytes) -> str:
    """Build ADR-036 StdSignDoc for signing"""
    doc = {
        "account_number": "0",
        "chain_id": "",
        "fee": {
            "amount": [],
            "gas": "0"
        },
        "memo": "",
        "msgs": [{
            "type": "sign/MsgSignData",
            "value": {
                "data": data.hex() if isinstance(data, bytes) else data,
                "signer": signer_address
            }
        }],
        "sequence": "0"
    }
    
    # Must use base64 for data field
    import base64
    doc["msgs"][0]["value"]["data"] = base64.b64encode(data).decode('ascii')
    
    # Return canonical JSON (sorted keys)
    return json.dumps(doc, separators=(',', ':'), sort_keys=True)


class ArkeoClient:
    """
    Arkeo PAYG Client
    
    Automatically signs RPC requests using ADR-036 signatures.
    """
    
    def __init__(
        self,
        sentinel_url: str,
        contract_id: int,
        private_key: str,
        service: str,
        start_nonce: int = 1
    ):
        """
        Create a new Arkeo PAYG client
        
        Args:
            sentinel_url: Sentinel base URL (e.g. "https://sentinel.arkeo.network")
            contract_id: Your contract ID
            private_key: Private key (hex) or mnemonic phrase
            service: Service name (e.g. "arkeo-mainnet-fullnode")
            start_nonce: Starting nonce (default: 1)
        """
        self.sentinel_url = sentinel_url.rstrip('/')
        self.contract_id = contract_id
        self.service = service
        
        # Parse private key (hex or mnemonic)
        if ' ' in private_key:
            # Mnemonic phrase
            privkey_bytes = private_key_from_mnemonic(private_key)
        else:
            # Hex string
            if private_key.startswith('0x'):
                private_key = private_key[2:]
            privkey_bytes = bytes.fromhex(private_key)
        
        # Initialize signing key
        self.signing_key = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
        self.public_key = self.signing_key.get_verifying_key().to_string('compressed')
        self.public_key_bech32 = encode_pubkey_bech32(self.public_key)
        self.address = pubkey_to_address(self.public_key)
        
        # Nonce tracking
        self.current_nonce = start_nonce
    
    def get_nonce(self) -> int:
        """Get current nonce"""
        return self.current_nonce
    
    def set_nonce(self, nonce: int):
        """Set nonce manually (useful for persistence/recovery)"""
        self.current_nonce = nonce
    
    def sign(self, preimage: str) -> str:
        """
        Sign a message using ADR-036 format
        
        Args:
            preimage: Message to sign: "{contractId}:{pubkey}:{nonce}"
        
        Returns:
            Hex-encoded signature
        """
        # Build ADR-036 StdSignDoc
        sign_doc = build_adr036_signdoc(self.address, preimage.encode('utf-8'))
        
        # Hash the sign doc
        hash_bytes = hashlib.sha256(sign_doc.encode('utf-8')).digest()
        
        # Sign the hash (with low-S normalization via sigencode_string_canonize)
        sig_bytes = self.signing_key.sign_digest(
            hash_bytes,
            sigencode=sigencode_string_canonize
        )
        
        return sig_bytes.hex()
    
    def generate_arkauth(self) -> str:
        """
        Generate arkauth header
        
        Returns:
            arkauth value (contractId:pubkey:nonce:signature)
        """
        preimage = f"{self.contract_id}:{self.public_key_bech32}:{self.current_nonce}"
        signature = self.sign(preimage)
        
        # Format: contractId:pubkey:nonce:signature
        return f"{self.contract_id}:{self.public_key_bech32}:{self.current_nonce}:{signature}"
    
    def rpc(self, path: str, **kwargs) -> requests.Response:
        """
        Make an authenticated RPC call
        
        Args:
            path: RPC path (e.g. "/status" or "/abci_info")
            **kwargs: Additional arguments passed to requests.get
        
        Returns:
            requests.Response object
        """
        arkauth = self.generate_arkauth()
        
        # Build URL with arkauth query parameter
        separator = '&' if '?' in path else '?'
        url = f"{self.sentinel_url}/{self.service}{path}{separator}arkauth={arkauth}"
        
        # Make request
        response = requests.get(url, **kwargs)
        
        # Auto-increment nonce on success
        if response.ok:
            self.current_nonce += 1
        
        return response
    
    def rpc_json(self, path: str, **kwargs) -> Dict[str, Any]:
        """
        Make authenticated RPC call and return JSON
        
        Args:
            path: RPC path
            **kwargs: Additional arguments passed to requests.get
        
        Returns:
            Parsed JSON response
        """
        response = self.rpc(path, **kwargs)
        response.raise_for_status()
        return response.json()
    
    def rpc_text(self, path: str, **kwargs) -> str:
        """
        Make authenticated RPC call and return text
        
        Args:
            path: RPC path
            **kwargs: Additional arguments passed to requests.get
        
        Returns:
            Text response
        """
        response = self.rpc(path, **kwargs)
        response.raise_for_status()
        return response.text
    
    def get_info(self) -> Dict[str, Any]:
        """Get client information"""
        return {
            'address': self.address,
            'public_key': self.public_key.hex(),
            'public_key_bech32': self.public_key_bech32,
            'contract_id': self.contract_id,
            'current_nonce': self.current_nonce,
            'service': self.service
        }
