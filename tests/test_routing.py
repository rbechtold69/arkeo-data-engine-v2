import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
from contextlib import ExitStack
from test_admin_security import load_admin


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.m = load_admin('subscriber', self.tmp.name)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.server = types.SimpleNamespace(client_pubkey='client', cooldowns={}, contract_cache={}, nonce_stores={}, cors_configured={})
        self.cfg = {'listener_id':'test', 'service_id':1, 'service_name':'eth-mainnet-fullnode',
                    'auto_create':False, 'whitelist_ips':'127.0.0.1', '_server_ref':self.server}
        self.providers = [{'provider_pubkey':'p1', 'sentinel_url':'https://p1.example'},
                          {'provider_pubkey':'p2', 'sentinel_url':'https://p2.example'}]
        self.stack.enter_context(patch.object(self.m, '_candidate_providers', return_value=self.providers))
        self.stack.enter_context(patch.object(self.m, '_get_height_with_source', return_value=(100,False)))
        self.stack.enter_context(patch.object(self.m, '_fetch_contracts', return_value=[]))
        self.stack.enter_context(patch.object(self.m, '_select_active_contract', side_effect=lambda *a, **kw: {'id': 1 if kw['provider_filter']=='p1' else 2,'client':'client','provider':kw['provider_filter']}))
        for name in ('_update_top_service_contract','_set_top_service_status','_update_top_service_metrics','_persist_listener_nonce'):
            self.stack.enter_context(patch.object(self.m, name))
        self.stack.enter_context(patch.object(self.m, '_claims_highest_nonce', return_value=0))
        self.stack.enter_context(patch.object(self.m, '_read_persisted_nonce', return_value=0))
        self.stack.enter_context(patch.object(self.m, '_sign_message', return_value=('fake-test-signature',None)))

    def work(self, rpc_method='eth_blockNumber', method='POST'):
        return self.m.WorkItem(method, 'eth-mainnet-fullnode', '', {},
            json.dumps({'jsonrpc':'2.0','id':1,'method':rpc_method,'params':[]}).encode(), '127.0.0.1')

    def result(self, code):
        return (code, b'{"result":"0x10"}' if code==200 else b'{"error":"unavailable"}', {'Content-Type':'application/json'}, 'https://test.example', {})

    def test_backup_serves_same_read_after_primary_http_503(self):
        with patch.object(self.m, '_forward_to_sentinel', side_effect=[self.result(503),self.result(200)]) as f:
            r=self.m._handle_forward_lane(self.work(),self.cfg)
            self.assertEqual(r['status'],200)
            self.assertEqual(f.call_count,2)
            self.assertIn('p1',self.server.cooldowns)

    def test_bypass_http_500_fails_over_for_read(self):
        self.cfg['bypass_uri']='https://primary.example'
        with patch.object(self.m, '_forward_to_bypass', return_value=self.result(500)), patch.object(self.m, '_forward_to_sentinel', return_value=self.result(200)) as f:
            self.assertEqual(self.m._handle_forward_lane(self.work(),self.cfg)['status'],200)
            self.assertEqual(f.call_count,1)

    def test_write_never_replayed_after_ambiguous_failure(self):
        with patch.object(self.m, '_forward_to_sentinel', return_value=self.result(503)) as f:
            self.assertEqual(self.m._handle_forward_lane(self.work('eth_sendRawTransaction'),self.cfg)['status'],503)
            self.assertEqual(f.call_count,1)

    def test_write_never_replayed_after_bypass_timeout(self):
        self.cfg['bypass_uri']='https://primary.example'
        with patch.object(self.m, '_forward_to_bypass', side_effect=self.m.BypassError('timeout')), patch.object(self.m, '_forward_to_sentinel') as f:
            self.assertEqual(self.m._handle_forward_lane(self.work('eth_sendRawTransaction'),self.cfg)['status'],502)
            f.assert_not_called()

    def test_client_error_not_retried(self):
        with patch.object(self.m, '_forward_to_sentinel', return_value=self.result(400)) as f:
            self.assertEqual(self.m._handle_forward_lane(self.work(),self.cfg)['status'],400)
            self.assertEqual(f.call_count,1)

    def test_nonce_persistence_failure_is_fatal(self):
        store=self.m.NonceStore(str(Path(self.tmp.name)/'nonce.json'))
        with patch.object(self.m.os,'replace',side_effect=OSError('disk full')):
            with self.assertRaises(OSError): store.next()

    def test_nonce_cannot_move_backwards(self):
        store=self.m.NonceStore(str(Path(self.tmp.name)/'nonce.json'))
        store.set(100)
        store.set(1)
        self.assertEqual(store.next(),101)

    def test_corrupt_nonce_file_is_not_silently_reset(self):
        p=Path(self.tmp.name)/'nonce.json'; p.write_text('{broken')
        with self.assertRaises((ValueError,OSError)):
            self.m.NonceStore(str(p))

    def test_header_auth_preserves_query_and_strips_supplied_auth(self):
        captured=[]
        class Response:
            status=200
            def __enter__(self): return self
            def __exit__(self,*a): pass
            def read(self,*a): return b'{}'
            def getheaders(self): return []
        def send(req,**kw): captured.append(req); return Response()
        # Both implementations must use a no-redirect opener after the patch.
        with patch.object(self.m.urllib.request,'urlopen',side_effect=send), patch.object(self.m.urllib.request,'build_opener') as opener:
            opener.return_value.open.side_effect=send
            self.m._forward_to_sentinel('https://p1.example','svc/status',None,'trusted',as_header=True,method='GET',query_string='height=12&arkauth=untrusted')
        self.assertIn('height=12',captured[0].full_url)
        self.assertNotIn('untrusted',captured[0].full_url)

if __name__=='__main__': unittest.main()
