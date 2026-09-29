import copy
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('rpc_preflight',Path(__file__).resolve().parents[1]/'scripts/rpc_preflight.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class PreflightTests(unittest.TestCase):
    def setUp(self):
        pk='arkeopub1'+'q'*60
        self.providers=[{'provider_pubkey':'primary','upstream':'https://primary.test','failure_domain':'operator-a','endpoint_approved':True},{'provider_pubkey':pk,'upstream':'https://backup.test','failure_domain':'operator-b','endpoint_approved':True,'contract':{'id':'123','provider':pk,'service':'11','verified_active':True}}]
        self.manifest={'version':1,'environment':{'ARKEO_INSTITUTIONAL_MODE':'true','PROXY_AUTO_CREATE':'false','ARKEO_PROVIDER_HEALTH_FILE':'/config/health.json'},'persistent_nonce_state':True,'admin_private_ingress':True,'redundant_gateway_hosts':True,'workload':[{'role':'thorchain-rest','listener_id':'native','service_id':'11','service_name':'thorchain-mainnet-rest','network':'thorchain-mainnet-v1','sample_read_path':'/thorchain/pools','workload_confirmed':True,'providers':self.providers}]}
        self.listeners={'listeners':[{'id':'native','port':11001,'service_id':11,'service_name':'thorchain-mainnet-rest','auto_create':False,'bypass_uri':self.providers[0]['upstream'],'top_services':[{'provider_pubkey':pk,'service_id':11,'sentinel_url':self.providers[1]['upstream']}]}]}
        self.health={'listeners':{'native':{p['provider_pubkey']:{'upstream':p['upstream'],'checks':[{'url':p['upstream']+'/health','network_path':'/network','expected_network':'thorchain-mainnet-v1','timestamp_path':'/time','max_age_seconds':30}]} for p in self.providers}}}

    def test_matching_configuration_passes_only_static_review(self):
        self.assertEqual(m.validate(self.manifest,self.listeners,self.health),[])

    def test_mismatched_identity_service_order_endpoint_and_automatic_spending_rejected(self):
        for field,value in [('provider_pubkey','other'),('service_id',99),('sentinel_url','https://unreviewed.test')]:
            runtime=copy.deepcopy(self.listeners);runtime['listeners'][0]['top_services'][0][field]=value
            with self.subTest(field=field):self.assertTrue(m.validate(self.manifest,runtime,self.health))
        self.listeners['listeners'][0]['auto_create']=True
        self.assertTrue(m.validate(self.manifest,self.listeners,self.health))

    def test_shared_failure_domain_and_missing_contract_rejected(self):
        self.providers[1]['failure_domain']='operator-a';self.providers[1].pop('contract')
        errors=m.validate(self.manifest,self.listeners,self.health)
        self.assertTrue(any('independent' in e for e in errors));self.assertTrue(any('contract' in e for e in errors))

    def test_stale_policy_missing_indexer_check_and_placeholders_rejected(self):
        self.manifest['workload'][0]['role']='maya-midgard'
        self.providers[0]['upstream']='https://REPLACE.invalid'
        self.health['listeners']['native']['primary']['checks'][0]['max_age_seconds']=float('nan')
        errors=m.validate(self.manifest,self.listeners,self.health)
        self.assertTrue(any('indexer' in e for e in errors));self.assertTrue(any('freshness' in e for e in errors));self.assertTrue(any('TLS' in e for e in errors))

    def test_unreviewed_listener_and_duplicate_ports_fail(self):
        self.listeners['listeners'].append({**self.listeners['listeners'][0],'id':'extra'})
        errors=m.validate(self.manifest,self.listeners,self.health)
        self.assertTrue(any('ports' in e for e in errors));self.assertTrue(any('Every deployed' in e for e in errors))

    def test_invalid_inputs_are_rejected_without_printing_secrets(self):
        self.assertTrue(m.validate([],{},{}))
        self.providers[0]['upstream']='https://name:secret@private.test'
        errors=m.validate(self.manifest,self.listeners,self.health)
        self.assertTrue(errors);self.assertNotIn('secret',str(errors))
        self.assertFalse(m.valid_url('http://127.0.0.1:1234'))
        self.assertTrue(m.valid_url('http://127.0.0.1:1234',True))
