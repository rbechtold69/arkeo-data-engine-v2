"""Provider identity and consumer-priority regressions against the actual subscriber."""
from contextlib import ExitStack
import tempfile
import unittest
from unittest.mock import patch
from test_admin_security import load_admin


class ProviderSelectionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.m = load_admin('subscriber', temp.name)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name, result in [('_load_cached', {}), ('_active_service_lookup', {}),
                             ('_lookup_settlement_duration', None), ('_active_provider_moniker', None)]:
            self.stack.enter_context(patch.object(self.m, name, return_value=result))
        self.primary = {'provider_pubkey':'liquify', 'sentinel_url':'https://primary.example', 'service_id':'32'}
        self.backup = {'provider_pubkey':'independent', 'sentinel_url':'https://backup.example', 'service_id':'32'}

    def candidates(self, **kwargs):
        return self.m._candidate_providers({'service_id':'32', **kwargs})

    def test_standalone_configured_primary_is_usable(self):
        rows = self.candidates(provider_pubkey='liquify', provider_sentinel_api='https://primary.example')
        self.assertEqual([x['provider_pubkey'] for x in rows], ['liquify'])

    def test_backup_cannot_borrow_primary_endpoint(self):
        rows = self.candidates(provider_pubkey='liquify', provider_sentinel_api='https://primary.example',
                               top_services=[{'provider_pubkey':'independent'}])
        self.assertEqual([x['provider_pubkey'] for x in rows], ['liquify'])
        self.assertEqual(rows[0]['sentinel_url'], 'https://primary.example')

    def test_incompatible_service_is_never_a_backup(self):
        rows = self.candidates(top_services=[self.primary, {**self.backup, 'service_id':'99'}])
        self.assertEqual([x['provider_pubkey'] for x in rows], ['liquify'])

    def test_recovered_primary_keeps_priority_despite_previous_down_label(self):
        rows = self.candidates(top_services=[{**self.primary, 'status':'Down'}, {**self.backup, 'status':'Up'}])
        self.assertEqual([x['provider_pubkey'] for x in rows], ['liquify','independent'])

    def test_consumer_can_choose_any_primary_and_duplicates_are_removed(self):
        rows = self.candidates(top_services=[self.backup, self.primary, self.backup])
        self.assertEqual([x['provider_pubkey'] for x in rows], ['independent','liquify'])

    def test_service_change_drops_previous_contract_state_and_providers(self):
        old = [{**self.primary, 'last_contract_id':7}]
        new = [{'provider_pubkey':'new-service-provider', 'service_id':'99'}]
        self.assertEqual(self.m._listener_provider_selection(old, old, new, True), new)
        self.assertEqual(self.m._listener_provider_selection(old, None, new), old)
        self.assertEqual(self.m._listener_provider_selection(old, [], new), [])

    def test_refresh_route_preserves_priority_and_funded_contract_state(self):
        existing = [{'provider_pubkey':'liquify', 'last_contract_id':7}, {'provider_pubkey':'independent'}]
        data = {'listeners':[{'id':'pilot', 'service_id':'32', 'top_services':existing}]}
        with patch.object(self.m, '_update_listeners_atomic', side_effect=lambda fn:fn(data)), \
             patch.object(self.m, '_top_active_services_by_payg', return_value=[self.backup, self.primary]), \
             patch.object(self.m, '_enrich_listener_for_response', side_effect=lambda x:x), \
             self.m.app.test_request_context('/', method='POST', json={}):
            response = self.m.refresh_listener_top_services('pilot')
        self.assertEqual(response.status_code,200)
        self.assertEqual(data['listeners'][0]['top_services'],existing)

    def test_refresh_only_changes_priority_when_explicitly_requested(self):
        data = {'listeners':[{'id':'pilot', 'service_id':'32', 'top_services':[{'provider_pubkey':'liquify', 'last_contract_id':7}]}]}
        with patch.object(self.m, '_update_listeners_atomic', side_effect=lambda fn:fn(data)), \
             patch.object(self.m, '_top_active_services_by_payg', return_value=[self.backup,self.primary]), \
             patch.object(self.m, '_enrich_listener_for_response', side_effect=lambda x:x), \
             self.m.app.test_request_context('/', method='POST', json={'reset_order':True}):
            self.m.refresh_listener_top_services('pilot')
        rows=data['listeners'][0]['top_services']
        self.assertEqual([r['provider_pubkey'] for r in rows],['independent','liquify'])
        self.assertEqual(rows[1]['last_contract_id'],7)
