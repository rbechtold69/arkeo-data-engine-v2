"""Exercise subscriber forwarding over real loopback HTTP; chain/signing are fixtures."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest
from unittest.mock import patch
import test_routing

class HTTPFailoverTests(unittest.TestCase):
 def setUp(self):
  self.fixture=test_routing.RoutingTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
  self.m=self.fixture.m
 def server(self,code,body):
  hits=[]
  class Handler(BaseHTTPRequestHandler):
   def do_POST(s):
    hits.append(s.rfile.read(int(s.headers.get('Content-Length','0'))))
    s.send_response(code);s.send_header('Content-Type','application/json');s.end_headers();s.wfile.write(body)
   def do_GET(s):s.do_POST()
   def log_message(s,*args):pass
  srv=ThreadingHTTPServer(('127.0.0.1',0),Handler)
  thread=threading.Thread(target=srv.serve_forever,daemon=True);thread.start()
  self.addCleanup(srv.server_close);self.addCleanup(srv.shutdown)
  return f'http://127.0.0.1:{srv.server_port}',hits
 def test_http_primary_failure_backup_success_and_cooldown(self):
  primary,p_hits=self.server(503,b'{"error":"offline"}')
  backup,b_hits=self.server(200,b'{"jsonrpc":"2.0","id":1,"result":"0x10"}')
  candidates=[{'provider_pubkey':'p1','sentinel_url':primary},{'provider_pubkey':'p2','sentinel_url':backup}]
  with patch.object(self.m,'_candidate_providers',return_value=candidates):
   result=self.m._handle_forward_lane(self.fixture.work(),self.fixture.cfg)
   self.assertEqual(result['status'],200)
   self.assertEqual(json.loads(result['body'])['result'],'0x10')
   self.assertEqual(len(p_hits),1);self.assertEqual(len(b_hits),1)
   self.assertEqual(self.m._handle_forward_lane(self.fixture.work(),self.fixture.cfg)['status'],200)
   self.assertEqual(len(p_hits),1);self.assertEqual(len(b_hits),2)
 def test_direct_primary_503_switches_to_paid_backup(self):
  primary,p_hits=self.server(503,b'{}');backup,b_hits=self.server(200,b'{"result":"0x10"}')
  self.fixture.cfg['bypass_uri']=primary
  with patch.object(self.m,'_candidate_providers',return_value=[{'provider_pubkey':'p1','sentinel_url':backup}]):
   self.assertEqual(self.m._handle_forward_lane(self.fixture.work(),self.fixture.cfg)['status'],200)
   self.assertEqual(len(p_hits),1);self.assertEqual(len(b_hits),1)
 def test_all_providers_down_does_not_report_success(self):
  primary,_=self.server(503,b'{}');backup,_=self.server(503,b'{}')
  with patch.object(self.m,'_candidate_providers',return_value=[{'provider_pubkey':'p1','sentinel_url':primary},{'provider_pubkey':'p2','sentinel_url':backup}]):
   self.assertEqual(self.m._handle_forward_lane(self.fixture.work(),self.fixture.cfg)['status'],503)
 def test_write_is_not_sent_to_second_provider(self):
  primary,p_hits=self.server(503,b'{}');backup,b_hits=self.server(200,b'{}')
  with patch.object(self.m,'_candidate_providers',return_value=[{'provider_pubkey':'p1','sentinel_url':primary},{'provider_pubkey':'p2','sentinel_url':backup}]):
   self.assertEqual(self.m._handle_forward_lane(self.fixture.work('eth_sendRawTransaction'),self.fixture.cfg)['status'],503)
   self.assertEqual(len(p_hits),1);self.assertEqual(b_hits,[])
