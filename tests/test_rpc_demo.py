import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import rpc_demo as demo

class DemoTests(unittest.TestCase):
    def test_recovery_is_measured_at_successful_completion_not_request_start(self):
        report={'phases':[{'id':'primary-out','started_ms':100,'expected_provider':'backup'}],'requests':[{'phase':'primary-out','ok':False,'provider':None,'duration_ms':20,'completed_ms':130},{'phase':'primary-out','ok':True,'provider':'backup','duration_ms':45,'completed_ms':245}]}
        phase=demo.summarize(report)['phases'][0]
        self.assertEqual(phase['time_to_expected_provider_ms'],145)
        self.assertEqual(phase['failed'],1);self.assertEqual(phase['p95_ms'],45)

    def test_missing_recovery_is_not_reported_as_zero_milliseconds(self):
        report={'phases':[{'id':'primary-return','started_ms':0,'expected_provider':'primary'}],'requests':[{'phase':'primary-return','ok':True,'provider':'backup','duration_ms':10,'completed_ms':10}]}
        result=demo.summarize(report);self.assertFalse(result['passed']);self.assertIsNone(result['phases'][0]['time_to_expected_provider_ms'])

    def test_report_cannot_execute_provider_supplied_markup(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'demo.html';demo.render({'label':'</script><script>alert(1)</script>'},target)
            html=target.read_text();self.assertNotIn('const report={"label":"</script>',html)
            self.assertEqual(json.loads(target.with_suffix('.json').read_text())['label'],'</script><script>alert(1)</script>')

    def test_live_mode_requires_explicit_budget_before_runtime_initialization(self):
        with patch.object(sys,'argv',['rpc_demo.py','--live-config','missing.json','--output','out.html']),patch.object(demo,'live_runtime') as runtime:
            self.assertEqual(demo.main(),2);runtime.assert_not_called()

    def test_local_fault_injection_and_dispatch_cap_use_actual_router(self):
        with demo.fixture_runtime() as (m,cfg,labels,rates):
            with patch.object(demo,'PHASES',[('normal','Normal',set()),('primary-out','Fault',{'primary'}),('all-out','All',{'primary','backup-1','backup-2'})]):
                report=demo.run_drill(m,cfg,labels,rates,samples=3,interval=.1,fault_delay=0,max_dispatches=4)
            self.assertEqual(report['cost']['upstream_dispatches'],4)
            self.assertEqual(sum(a['dispatched'] for a in report['attempts']),4)
            self.assertTrue(all(not a['dispatched'] for a in report['attempts'] if a['injected_fault']))
            self.assertFalse(report['funded_contracts_tested'])
            self.assertEqual(report['summary']['phases'][-1]['successful'],0)

    def test_existing_public_provider_is_not_enough_without_dedicated_wallet_and_contracts(self):
        with self.assertRaisesRegex(demo.DemoError,'dedicated'):demo.validate_live_config({})

    def test_paid_dispatch_budget_is_reserved_before_transport_and_invalid_live_payload_fails(self):
        with demo.fixture_runtime() as (m,cfg,labels,_):
            with patch.object(demo,'PHASES',[('normal','Normal',set())]):
                report=demo.run_drill(m,cfg,labels,{'primary':7,'p1':11,'p2':13},live=True,samples=3,interval=.1,fault_delay=0,max_uarkeo=10,max_dispatches=10)
            self.assertEqual(report['cost']['reserved_uarkeo'],'7')
            self.assertEqual(report['cost']['upstream_dispatches'],1)
            self.assertEqual(report['summary']['successful'],0)
            self.assertFalse(report['summary']['passed'])
