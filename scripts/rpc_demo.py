#!/usr/bin/env python3
"""Measure the actual subscriber router and export a standalone demonstration.
Fixture mode never contacts external providers. Live mode requires a dedicated
wallet, existing funded contracts and explicit limits; it never creates contracts.
"""
import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import importlib.util
import json
import math
import os
import re
from pathlib import Path
import statistics
import sys
import time
import types
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
LIQUIFY='arkeopub1addwnpepqdgt6w2qqkt4jydfud507nl740gxeag7gaaj5hzc8w7x9p0ka8ln6e8kkvk'
PHASES=[('normal','Liquify serves requests',set()),('primary-out','Primary connection interrupted',{'primary'}),('backup-one-out','First backup also interrupted',{'primary','backup-1'}),('all-out','All routes interrupted',{'primary','backup-1','backup-2'}),('backups-return','Backups restored',{'primary'}),('primary-return','Liquify restored',set())]

class DemoError(ValueError): pass

def percentile(values,fraction):
    return sorted(values)[max(0,math.ceil(len(values)*fraction)-1)] if values else None

def summarize(report):
    requests=report['requests'];stages=[]
    for phase in report['phases']:
        rows=[r for r in requests if r['phase']==phase['id']]
        good=[r for r in rows if r['ok']]
        recovered=next((r for r in good if r['provider']==phase['expected_provider']),None)
        stages.append({**phase,'requests':len(rows),'successful':len(good),'failed':len(rows)-len(good),
            'p50_ms':round(statistics.median([r['duration_ms'] for r in rows]),2) if rows else None,
            'p95_ms':percentile([r['duration_ms'] for r in rows],.95),
            'time_to_expected_provider_ms':round(recovered['completed_ms']-phase['started_ms'],2) if recovered else None,
            'passed':bool(rows) and (all(not r['ok'] for r in rows) if phase['id']=='all-out' else all(r['ok'] and r['provider']==phase['expected_provider'] for r in rows) if phase['id']=='normal' else recovered is not None and rows[-1]['ok'] and rows[-1]['provider']==phase['expected_provider'])})
    return {'phases':stages,'requests':len(requests),'successful':sum(r['ok'] for r in requests),'failed':sum(not r['ok'] for r in requests),'passed':all(p['passed'] for p in stages)}

@contextmanager
def fixture_runtime():
    sys.path.insert(0,str(ROOT/'tests'))
    from test_native_rehearsal import NativeRehearsalTests
    fixture=NativeRehearsalTests(methodName='test_second_backup_all_down_and_recovery_to_original_primary')
    try:
        fixture.setUp()
        fixture.cfg.update(service_name='arkeo-mainnet-fullnode',bypass_cooldown_sec=1)
        for row in fixture.nodes:row['network']='arkeo-main-v1'
        fixture.policy('arkeo-main-v1')
        fixture.m.PROXY_PROVIDER_COOLDOWN=1
        yield fixture.m,fixture.cfg,{'primary':'Liquify role (test server)','p1':'Backup 1 (test server)','p2':'Backup 2 (test server)'},{}
    finally:
        fixture.doCleanups();sys.path.remove(str(ROOT/'tests'))

def validate_live_config(data):
    from rpc_preflight import valid_url, PUBKEY
    if not isinstance(data,dict) or data.get('dedicated_wallet_confirmed') is not True:raise DemoError('Confirm a dedicated demo wallet; never reuse an active gateway wallet.')
    rows=data.get('providers',[])
    if not isinstance(rows,list) or len(rows)!=3:raise DemoError('This drill requires Liquify and exactly two compatible backups.')
    if rows[0].get('pubkey')!=LIQUIFY:raise DemoError('Liquify must be the first provider for this pilot.')
    if len({r.get('pubkey') for r in rows})!=3:raise DemoError('Three distinct provider identities are required.')
    if data.get('service_name')!='arkeo-mainnet-fullnode' or data.get('network')!='arkeo-main-v1':raise DemoError('This first live drill is restricted to Arkeo mainnet status reads.')
    if type(data.get('service_id')) is not int or data['service_id']<=0:raise DemoError('Exact registry service ID required.')
    if not PUBKEY.fullmatch(data.get('client_pubkey','')):raise DemoError('Demo wallet public key required.')
    if not re.fullmatch(r'[A-Za-z0-9_-]+',data.get('key_name','')):raise DemoError('Use a simple local key name without shell syntax.')
    for key in ('state_dir','wallet_home','health_file','key_name','node_rpc'):
        if not isinstance(data.get(key),str) or not data[key] or 'REPLACE' in data[key]:raise DemoError('Complete the local runtime configuration before live use.')
    if not valid_url(data['node_rpc']):raise DemoError('Chain query RPC must use HTTPS without embedded credentials.')
    for row in rows:
        if not PUBKEY.fullmatch(row.get('pubkey','')) or not valid_url(row.get('sentinel_url')):raise DemoError('Exact provider identity and HTTPS sentinel URL required.')
        if not str(row.get('contract_id','')).isdecimal() or int(row['contract_id'])<=0:raise DemoError('Pre-funded contract IDs are required.')
        if not str(row.get('max_rate_uarkeo','')).isdecimal():raise DemoError('Maximum per-request rate is required for each contract.')
    return data

@contextmanager
def live_runtime(data):
    validate_live_config(data)
    directory=Path(data['state_dir']).resolve()
    if directory.exists() and any(directory.iterdir()) and not (directory/'rpc-demo-state').is_file():raise DemoError('Use an empty dedicated demo state directory, not an existing gateway cache.')
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    # Prevent concurrent demonstration processes from sharing payment counters.
    import fcntl
    lock=(directory/'demo.lock').open('a')
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:lock.close();raise DemoError('Another demo is using this state directory.') from None
    (directory/'rpc-demo-state').touch(mode=0o600)
    with ExitStack() as stack:
        stack.callback(lock.close)
        stack.enter_context(patch.dict(os.environ,{'CONFIG_DIR':str(directory/'config'),'CACHE_DIR':str(directory/'cache'),'ARKEOD_HOME':str(Path(data['wallet_home']).resolve()),'ARKEOD_NODE':data['node_rpc'],'KEY_NAME':data['key_name'],'POSTHOG_ENABLED':'false','ARKEO_INSTITUTIONAL_MODE':'true','ARKEO_PROVIDER_HEALTH_FILE':str(Path(data['health_file']).resolve()),'PROXY_AUTO_CREATE':'false','PROXY_PROVIDER_COOLDOWN':'1'}))
        sys.path.insert(0,str(ROOT/'subscriber-core'));stack.callback(lambda:sys.path.remove(str(ROOT/'subscriber-core')))
        spec=importlib.util.spec_from_file_location('rpc_demo_runtime',ROOT/'subscriber-core/admin_api.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        _,client,error=m.derive_pubkeys(data['key_name'],m.KEYRING)
        if error or client!=data['client_pubkey']:raise DemoError('The local signing key does not match the dedicated demo wallet.')
        providers=data['providers'];cfg={'listener_id':'rpc-demo','service_id':data['service_id'],'service_name':data['service_name'],'auto_create':False,'whitelist_ips':'127.0.0.1','client_key':data['key_name'],'node_rpc':data['node_rpc'],'timeout_secs':2,'top_services':[{'provider_pubkey':p['pubkey'],'sentinel_url':p['sentinel_url'],'service_id':data['service_id']} for p in providers],'_server_ref':types.SimpleNamespace(client_pubkey=client,contract_cache={},nonce_stores={},cooldowns={},cors_configured={})}
        ids={str(p['contract_id']) for p in providers};fetch=m._fetch_contracts
        def pinned_contracts(*args,**kwargs):return [c for c in fetch(*args,**kwargs) if str(c.get('id')) in ids]
        stack.enter_context(patch.object(m,'_fetch_contracts',side_effect=pinned_contracts))
        height,cached=m._get_height_with_source(data['node_rpc'])
        if not isinstance(height,int) or height<=0 or cached:raise DemoError('A fresh chain height is required before paid requests.')
        contracts=pinned_contracts(data['node_rpc'],active_only=True,client_filter=client)
        rates={}
        for p in providers:
            c=m._select_active_contract(contracts,client,data['service_id'],height,provider_filter=p['pubkey'])
            if not c or str(c.get('id'))!=str(p['contract_id']):raise DemoError('A configured contract is missing, expired or unusable.')
            if c.get('contract_type') not in (1,'1','PAY_AS_YOU_GO'):raise DemoError('This drill requires explicit PAYG contracts.')
            rate=c.get('rate',{})
            if rate.get('denom')!='uarkeo' or not str(rate.get('amount','')).isdecimal() or int(rate['amount'])>int(p['max_rate_uarkeo']):raise DemoError('Contract rate does not match the approved limit.')
            rates[p['pubkey']]=int(rate['amount'])
            m.HEALTH_GATE.check('rpc-demo',p['pubkey'],p['sentinel_url'],time.time()+6)
        yield m,cfg,{p['pubkey']:p.get('label') or ('Liquify' if i==0 else 'Backup '+str(i)) for i,p in enumerate(providers)},rates


def run_drill(m,cfg,labels,rates,*,live=False,samples=5,interval=.35,fault_delay=.15,max_dispatches=90,max_uarkeo=0):
    if not 3<=samples<=12 or not .1<=interval<=5 or not 0<=fault_delay<=2:raise DemoError('Drill timing is outside the supported limits.')
    mode='live' if live else 'fixture'
    primary=next(iter(labels));keys=list(labels);role_by_key=dict(zip(keys,['primary','backup-1','backup-2']))
    url_to_key={r['sentinel_url'].rstrip('/'):r['provider_pubkey'] for r in cfg['top_services']}
    if cfg.get('bypass_uri'):url_to_key[cfg['bypass_uri'].rstrip('/')]='primary'
    report={'schema':1,'mode':mode,'created_at':datetime.now(timezone.utc).isoformat(),'service':cfg['service_name'],'labels':labels,'configuration':{'samples_per_phase':samples,'interval_seconds':interval,'fault_delay_seconds':fault_delay,'cooldown_seconds':1},'phases':[],'requests':[],'attempts':[],'funded_contracts_tested':live,'production_ready':False,'limitations':('Live paid status reads; outages are injected locally. This is a bounded demonstration, not a load test or uptime SLA.' if live else 'Local HTTP test servers stand in for Liquify and both backups. Chain data, contracts and signatures are fixtures. Timings are local measurements, not provider performance.')}
    blocked=set();started=time.perf_counter();current=None;reserved=0;dispatches=0
    def elapsed():return round((time.perf_counter()-started)*1000,2)
    def transport(original,sentinel,*args,**kwargs):
        nonlocal reserved,dispatches
        key=url_to_key.get(sentinel.rstrip('/'))
        if key not in role_by_key:raise DemoError('An unconfigured provider was selected.')
        begin=elapsed();injected=role_by_key[key] in blocked;sent=False
        if injected:
            time.sleep(min(fault_delay,float(kwargs.get('timeout',fault_delay))))
            result=(503,b'{"error":"demo_local_fault"}',{'Content-Type':'application/json'},sentinel,{})
        else:
            if dispatches>=max_dispatches or (live and reserved+rates[key]>max_uarkeo):
                result=(429,b'{"error":"demo_budget_exhausted"}',{'Content-Type':'application/json'},sentinel,{})
            else:
                dispatches+=1;reserved+=rates.get(key,0);sent=True;result=original(sentinel,*args,**kwargs)
        report['attempts'].append({'request':current,'provider':key,'started_ms':begin,'duration_ms':round(elapsed()-begin,2),'status':result[0],'injected_fault':injected,'dispatched':sent})
        return result
    with ExitStack() as stack:
        for name in ('_forward_to_sentinel','_forward_to_bypass'):
            original=getattr(m,name)
            stack.enter_context(patch.object(m,name,side_effect=lambda *a,_original=original,**kw:transport(_original,*a,**kw)))
        for phase_id,title,disabled in PHASES:
            blocked=set(disabled)
            expected=None if phase_id=='all-out' else keys[2] if phase_id=='backup-one-out' else keys[1] if phase_id in ('primary-out','backups-return') else primary
            phase={'id':phase_id,'title':title,'started_ms':elapsed(),'blocked_roles':sorted(blocked),'expected_provider':expected};report['phases'].append(phase)
            for i in range(samples if phase_id!='all-out' else 3):
                current=len(report['requests'])+1;begin=elapsed()
                work=m.WorkItem('GET',cfg['service_name']+'/status','',{},b'','127.0.0.1',raw_path='/status')
                try:response=m._handle_forward_lane(work,cfg)
                except Exception:response={'status':502,'body':'{}','headers':{}}
                status=int(response['status']);hdrs=response.get('headers',{});provider='primary' if hdrs.get('X-Arkeo-Bypass-Used')=='1' else hdrs.get('X-Arkeo-Provider');valid=200<=status<300 and provider in labels
                if live and valid:
                    try:
                        data=json.loads(response['body']);result=data.get('result',{});sync=result['sync_info'];stamp=datetime.fromisoformat(sync['latest_block_time'].replace('Z','+00:00'))
                        valid=result['node_info']['network']=='arkeo-main-v1' and int(sync['latest_block_height'])>0 and sync['catching_up'] is False and stamp.tzinfo is not None and -10<=(datetime.now(timezone.utc)-stamp).total_seconds()<=60
                    except (KeyError,ValueError,TypeError):valid=False
                report['requests'].append({'id':current,'phase':phase_id,'started_ms':begin,'completed_ms':elapsed(),'duration_ms':round(elapsed()-begin,2),'status':status,'ok':bool(valid),'provider':provider if valid else None})
                time.sleep(interval)
    report['funded_contracts_tested']=bool(live and dispatches)
    report['cost']={'upstream_dispatches':dispatches,'reserved_uarkeo':str(reserved),'maximum_uarkeo':str(max_uarkeo),'note':'Conservative request-rate reservation, not confirmed settlement; fixture runs have no payments.'}
    report['summary']=summarize(report)
    return report

def render(report,target):
    encoded=json.dumps(report,ensure_ascii=True,separators=(',',':')).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    template=(ROOT/'docs/rpc-demo.template.html').read_text()
    target=Path(target);target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(template.replace('/*DEMO_REPORT*/null',encoded),encoding='utf-8')
    target.with_suffix('.json').write_text(json.dumps(report,indent=2)+'\n')

def main():
    parser=argparse.ArgumentParser(description=__doc__);mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--fixture',action='store_true');mode.add_argument('--live-config',type=Path)
    parser.add_argument('--allow-paid-requests',action='store_true');parser.add_argument('--max-uarkeo',type=int,default=0);parser.add_argument('--max-dispatches',type=int,default=90)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    try:
        if not 1<=args.max_dispatches<=100:raise DemoError('Set a dispatch limit from 1 to 100.')
        if args.live_config and (not args.allow_paid_requests or args.max_uarkeo<=0):raise DemoError('Live requests require explicit payment authorization and a positive uarkeo cap.')
        if args.live_config and args.output.resolve().is_relative_to(ROOT/'docs'):raise DemoError('Save live evidence outside public docs; review it before publication.')
        runtime=fixture_runtime() if args.fixture else live_runtime(json.loads(args.live_config.read_text()))
        with runtime as (m,cfg,labels,rates):report=run_drill(m,cfg,labels,rates,live=not args.fixture,max_dispatches=args.max_dispatches,max_uarkeo=args.max_uarkeo)
        render(report,args.output)
        print(json.dumps({'html':str(args.output),'mode':report['mode'],'passed':report['summary']['passed'],'requests':report['summary']['requests'],'production_ready':False}))
        return 0 if report['summary']['passed'] else 1
    except (DemoError,OSError,ValueError) as error:
        print(json.dumps({'passed':False,'error':str(error) if isinstance(error,DemoError) else 'Cannot initialize the configured demo. Verify local files, runtime and access.'}),file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
