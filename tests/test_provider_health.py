import copy
import io
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from test_admin_security import load_admin


class ProviderHealthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.m = load_admin('subscriber', self.tmp.name)
        import provider_health
        self.h = provider_health
        self.now = 1800000000.0
        self.check = {'url':'https://node.example/status', 'network_path':'/result/node_info/network',
                      'expected_network':'expected-chain', 'height_path':'/result/sync_info/latest_block_height',
                      'timestamp_path':'/result/sync_info/latest_block_time', 'timestamp_unit':'seconds',
                      'max_age_seconds':30, 'equals':{'/result/sync_info/catching_up':False}}
        self.document = {'result':{'node_info':{'network':'expected-chain'}, 'sync_info':{
            'latest_block_height':'100', 'latest_block_time':self.now, 'catching_up':False}}}
        self.path = Path(self.tmp.name)/'health.json'
        self.policy = {'listeners':{'test':{'primary':{'upstream':'https://primary.example','checks':[self.check]}}}}
        self.path.write_text(json.dumps(self.policy))
        env = patch.dict(os.environ, {'ARKEO_PROVIDER_HEALTH_FILE':str(self.path),'ARKEO_INSTITUTIONAL_MODE':'true'})
        env.start(); self.addCleanup(env.stop)

    def test_wrong_network_stale_future_and_syncing_nodes_rejected(self):
        for field,value in [('network','wrong'),('latest_block_time',self.now-31),
                            ('latest_block_time',self.now+11),('catching_up',True),('latest_block_height','0')]:
            doc=copy.deepcopy(self.document)
            target=doc['result']['node_info'] if field=='network' else doc['result']['sync_info']
            target[field]=value
            gate=self.h.HealthGate(fetch=lambda *a:doc,clock=lambda:self.now)
            with self.subTest(field=field,value=value),self.assertRaises(self.h.HealthError):
                gate.check('test','primary','https://primary.example')

    def test_cache_rechecks_timestamp_and_requires_exact_upstream(self):
        calls=[]
        self.document['result']['sync_info']['latest_block_time']=self.now-29
        gate=self.h.HealthGate(fetch=lambda *a: calls.append(1) or self.document,clock=lambda:self.now)
        gate.check('test','primary','https://primary.example')
        self.now+=1.5
        with self.assertRaises(self.h.HealthError): gate.check('test','primary','https://primary.example')
        self.assertEqual(len(calls),1)
        with self.assertRaises(self.h.HealthError): gate.check('test','primary','https://other.example')

    def test_missing_policy_and_expired_request_fail_closed(self):
        gate=self.h.HealthGate(fetch=lambda *a:self.fail('must not fetch'),clock=lambda:self.now)
        with self.assertRaises(self.h.HealthError):gate.check('test','primary','https://primary.example',self.now-1)
        with patch.dict(os.environ,{'ARKEO_PROVIDER_HEALTH_FILE':''}):
            with self.assertRaises(self.h.HealthError):gate.check('test','primary','https://primary.example')

    def test_oversized_response_is_rejected(self):
        with self.assertRaises(self.h.HealthError):self.h.read_limited(io.BytesIO(b'x'*101),100,1)
        self.assertEqual(self.h.read_limited(io.BytesIO(b'abc'),100,1),b'abc')

    def test_independent_nonce_store_instances_reserve_unique_values(self):
        path=str(Path(self.tmp.name)/'counter.json')
        stores=[self.m.NonceStore(path) for _ in range(8)]
        with ThreadPoolExecutor(8) as pool:
            values=list(pool.map(lambda i: stores[i%8].next(),range(128)))
        self.assertEqual(sorted(values),list(range(1,129)))
        self.assertEqual(self.m.NonceStore(path).next(),129)

    def test_nonce_reservations_across_processes(self):
        path=str(Path(self.tmp.name)/'counter.json')
        ctx=multiprocessing.get_context('fork'); output=ctx.Queue()
        def reserve():
            store=self.m.NonceStore(path)
            output.put([store.next() for _ in range(20)])
        processes=[ctx.Process(target=reserve) for _ in range(4)]
        for process in processes:process.start()
        values=[]
        for _ in processes:values.extend(output.get(timeout=5))
        for process in processes:
            process.join(5);self.assertEqual(process.exitcode,0)
        self.assertEqual(sorted(values),list(range(1,81)))

    def test_nonce_overflow_and_legacy_counter_migration(self):
        directory=Path(self.m.NONCE_STORE_DIR);directory.mkdir(parents=True,exist_ok=True)
        (directory/'nonce_store_old_123.json').write_text('{"nonce":500}')
        a=self.m._nonce_store_path('a','123');b=self.m._nonce_store_path('b','123')
        self.assertEqual(a,b);self.assertEqual(self.m.NonceStore(a).next(),501)
        store=self.m.NonceStore(a);store.set(9223372036854775807)
        with self.assertRaises(ValueError):store.next()
