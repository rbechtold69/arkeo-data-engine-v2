import hashlib
import importlib.util
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch
from ecdsa.util import sigdecode_string
p=Path(__file__).resolve().parents[1]/'docs/sdk/python/arkeo_client.py'
spec=importlib.util.spec_from_file_location('arkeo_python',p);sdk=importlib.util.module_from_spec(spec);spec.loader.exec_module(sdk)
MN='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
class PythonSDKTests(unittest.TestCase):
 def make(self): return sdk.ArkeoClient('https://sentinel.example',42,MN,'test',1)
 def test_matches_javascript_key_and_signature(self):
  c=self.make(); self.assertEqual(c.public_key.hex(),'024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62')
  signature=bytes.fromhex(c.generate_arkauth().split(':')[3])
  self.assertTrue(c.signing_key.verifying_key.verify_digest(signature,hashlib.sha256(b'42:1:').digest(),sigdecode=sigdecode_string))
  self.assertEqual(signature.hex(),'fdefcbbc9179aca013e0dfa22618ef4bd084da91ded2b1f489b643ebd0e50ab0445fad6bb371c59fd8ace941196f7463205826d61e1744fea1edf2cc312e4526')
 def test_parallel_requests_and_failures_never_reuse_nonce(self):
  c=self.make(); seen=[]
  def send(method,url,**kw):
   seen.append(int(kw['headers']['arkauth'].split(':')[2])); self.assertFalse(kw['allow_redirects']); self.assertEqual(kw['timeout'],10)
   return sdk.requests.Response()
  with patch.object(sdk.requests,'request',side_effect=send):
   with ThreadPoolExecutor(8) as pool: list(pool.map(lambda _:c.rpc('/status'),range(20)))
  self.assertEqual(seen,list(range(1,21)))
 def test_failed_persistence_prevents_request(self):
  with patch.object(sdk.requests,'request') as send:
   with self.assertRaises(OSError): self.make().rpc('/status',save_nonce=lambda n:(_ for _ in ()).throw(OSError('disk full')))
   send.assert_not_called()
 def test_backwards_nonce_rejected(self):
  c=self.make();c.set_nonce(10)
  with self.assertRaises(ValueError):c.set_nonce(1)
