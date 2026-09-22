"""Real loopback HTTP + production router/health checks; chain/signing are fixtures.
No public endpoints, wallet, token transfers, or provider-performance claims.
"""
from contextlib import ExitStack
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch
from test_admin_security import load_admin

class NativeRehearsalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.m=load_admin('subscriber',self.tmp.name)
        self.stack=ExitStack(); self.addCleanup(self.stack.close)
        self.nodes=[]
        for name in ('preferred-primary','independent-one','independent-two'):
            state={'name':name,'status':200,'network':'thorchain-mainnet-v1','age':0,'syncing':False,'calls':[]}
            class Handler(BaseHTTPRequestHandler):
                def log_message(self,*args): pass
                def do_GET(handler): handler.respond()
                def do_POST(handler): handler.respond()
                def respond(handler):
                    row=handler.server.state
                    if handler.path=='/health':
                        doc={'network':row['network'],'height':'123456','time':time.time()-row['age'],'syncing':row['syncing']}; code=200
                    else:
                        body=handler.rfile.read(int(handler.headers.get('Content-Length','0')))
                        row['calls'].append((handler.command,handler.path,body))
                        doc={'provider':row['name'],'path':handler.path}; code=row['status']
                    data=json.dumps(doc).encode();handler.send_response(code);handler.send_header('Content-Type','application/json');handler.send_header('Content-Length',str(len(data)));handler.end_headers();handler.wfile.write(data)
            server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.state=state
            thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':0.01},daemon=True);thread.start()
            self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
            state['url']=f'http://127.0.0.1:{server.server_port}';self.nodes.append(state)
        self.server=types.SimpleNamespace(client_pubkey='fixture-client',cooldowns={},contract_cache={},nonce_stores={},cors_configured={})
        self.cfg={'listener_id':'native','service_id':11,'service_name':'thorchain-mainnet-rest','auto_create':False,'whitelist_ips':'127.0.0.1','_server_ref':self.server,'bypass_uri':self.nodes[0]['url'],'bypass_cooldown_sec':0,'timeout_secs':1,'top_services':[{'provider_pubkey':f'p{i}','service_id':11,'sentinel_url':self.nodes[i]['url']} for i in (1,2)]}
        self.contracts=[{'id':str(i),'service':11,'client':'fixture-client','provider':f'p{i}','height':'1','duration':'10000','deposit':'100000','paid':'0','settlement_height':'0'} for i in (1,2)]
        for name,value in [('_load_cached',{}),('_active_service_lookup',{}),('_lookup_settlement_duration',1),('_active_provider_moniker','fixture'),('_get_height_with_source',(100,False)),('_claims_highest_nonce',0),('_read_persisted_nonce',0),('_sign_message',('fixture-signature',None))]:
            self.stack.enter_context(patch.object(self.m,name,return_value=value))
        self.stack.enter_context(patch.object(self.m,'_fetch_contracts',side_effect=lambda *a,**kw:self.contracts))
        for name in ('_update_top_service_contract','_set_top_service_status','_update_top_service_metrics','_persist_listener_nonce'):
            self.stack.enter_context(patch.object(self.m,name))
        self.create=self.stack.enter_context(patch.object(self.m,'_create_contract_now',side_effect=AssertionError('rehearsal must never create contracts')))
        self.path=Path(self.tmp.name)/'health.json'
        self.stack.enter_context(patch.dict(os.environ,ARKEO_PROVIDER_HEALTH_FILE=str(self.path),ARKEO_INSTITUTIONAL_MODE='true'))
        self.stack.enter_context(patch.object(self.m,'HEALTH_GATE',self.m.HEALTH_GATE.__class__()))
        self.policy('thorchain-mainnet-v1')

    def policy(self,network):
        rows={}
        for i,node in enumerate(self.nodes):
            rows['primary' if i==0 else f'p{i}']={'upstream':node['url'],'checks':[{'url':node['url']+'/health','network_path':'/network','expected_network':network,'timestamp_path':'/time','timestamp_unit':'seconds','max_age_seconds':30,'height_path':'/height','equals':{'/syncing':False}}]}
        self.path.write_text(json.dumps({'listeners':{'native':rows}}));self.m.HEALTH_GATE.cache.clear()

    def request(self,path='/thorchain/pools',query='height=123&asset=BTC.BTC',body=None):
        work=self.m.WorkItem('POST' if body else 'GET',self.cfg['service_name']+path,query,{},json.dumps(body).encode() if body else b'','127.0.0.1',raw_path=path)
        return self.m._handle_forward_lane(work,self.cfg)

    def test_native_rest_rpc_and_midgard_keep_path_query_and_consumer_priority(self):
        for network,path in [('thorchain-mainnet-v1','/thorchain/pools'),('mayachain-mainnet-v1','/mayachain/pools'),('thorchain-mainnet-v1','/status'),('mayachain-mainnet-v1','/v2/pools')]:
            with self.subTest(network=network,path=path):
                for row in self.nodes:row['network']=network;row['status']=200
                self.policy(network);self.server.cooldowns.clear()
                result=self.request(path);self.assertEqual(result['status'],200);self.assertEqual(json.loads(result['body'])['provider'],'preferred-primary')
                self.nodes[0]['status']=503
                result=self.request(path);self.assertEqual(result['status'],200);doc=json.loads(result['body']);self.assertEqual(doc['provider'],'independent-one');self.assertIn(path+'?height=123&asset=BTC.BTC',doc['path'])

    def test_second_backup_all_down_and_recovery_to_original_primary(self):
        self.nodes[0]['status']=503;self.nodes[1]['status']=503
        result=self.request();self.assertEqual(result['status'],200);self.assertEqual(json.loads(result['body'])['provider'],'independent-two')
        self.nodes[2]['status']=503;self.assertGreaterEqual(self.request()['status'],500)
        self.nodes[0]['status']=200
        self.assertEqual(json.loads(self.request()['body'])['provider'],'preferred-primary')
        self.create.assert_not_called()

    def test_wrong_network_stale_and_syncing_primary_never_receives_user_request(self):
        for field,value in [('network','wrong'),('age',100),('syncing',True)]:
            with self.subTest(field=field):
                self.nodes[0].update(network='thorchain-mainnet-v1',age=0,syncing=False,calls=[]);self.nodes[0][field]=value;self.m.HEALTH_GATE.cache.clear()
                self.assertEqual(json.loads(self.request()['body'])['provider'],'independent-one');self.assertEqual(self.nodes[0]['calls'],[])

    def test_transaction_and_mixed_batch_are_not_replayed_after_ambiguous_failure(self):
        self.nodes[0]['status']=503
        for body in [{'jsonrpc':'2.0','id':1,'method':'broadcast_tx_sync','params':['abc']},[{'jsonrpc':'2.0','id':1,'method':'status'},{'jsonrpc':'2.0','id':2,'method':'broadcast_tx_sync'}]]:
            self.server.bypass_cooldown_until=0
            self.assertEqual(self.request('/',body=body)['status'],503)
        self.assertFalse(self.nodes[1]['calls']);self.assertFalse(self.nodes[2]['calls'])

    def test_missing_expired_and_exhausted_contracts_never_trigger_purchase(self):
        self.nodes[0]['status']=503
        for contracts in [[],[{**c,'duration':'1'} for c in self.contracts],[{**c,'paid':c['deposit']} for c in self.contracts]]:
            self.contracts=contracts;self.server.contract_cache.clear();self.server.cooldowns.clear()
            self.assertGreaterEqual(self.request()['status'],500)
        self.create.assert_not_called();self.assertFalse(self.nodes[1]['calls']);self.assertFalse(self.nodes[2]['calls'])

    def test_absent_health_binding_fails_closed_without_forwarding(self):
        self.path.write_text('{"listeners":{}}')
        self.assertGreaterEqual(self.request()['status'],500)
        self.assertTrue(all(not row['calls'] for row in self.nodes))

    def test_known_read_batch_fails_over_with_identical_body(self):
        self.nodes[0]['status']=503
        body=[{'jsonrpc':'2.0','id':1,'method':'status'},{'jsonrpc':'2.0','id':2,'method':'block','params':{'height':'100'}}]
        self.assertEqual(json.loads(self.request('/',body=body)['body'])['provider'],'independent-one')
        self.assertEqual(self.nodes[0]['calls'][0][2],self.nodes[1]['calls'][0][2])
