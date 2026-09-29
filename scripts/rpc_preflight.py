#!/usr/bin/env python3
"""Read-only configuration review. Never starts services or creates transactions."""
import argparse
import ipaddress
import json
import re
import sys
from urllib.parse import urlsplit

ROLES={'thorchain-rest','thorchain-rpc','thorchain-midgard','maya-rest','maya-rpc','maya-midgard'}
PUBKEY=re.compile(r'^arkeopub1[023456789acdefghjklmnpqrstuvwxyz]{50,100}$')

def valid_url(value, lab=False):
    if not isinstance(value,str): return False
    try:
        u=urlsplit(value); _=u.port
        loopback=u.hostname=='localhost'
        try: loopback=loopback or ipaddress.ip_address(u.hostname or '').is_loopback
        except ValueError: pass
        return bool(u.hostname and not u.username and not u.password and not u.query and not u.fragment and not u.hostname.endswith(('.example','.invalid')) and 'REPLACE' not in value and (u.scheme=='https' or (lab and u.scheme=='http' and loopback)))
    except ValueError: return False

def validate(manifest,listeners,health,lab=False):
    errors=[]
    def need(condition,message):
        if not condition: errors.append(message)
    if not all(isinstance(x,dict) for x in (manifest,listeners,health)):
        return ['Input documents must be JSON objects.']
    need(manifest.get('version')==1,'Manifest version must be 1.')
    env=manifest.get('environment',{})
    if not isinstance(env,dict): env={}
    need(env.get('ARKEO_INSTITUTIONAL_MODE')=='true','Institutional mode must be true.')
    need(env.get('PROXY_AUTO_CREATE')=='false','Automatic contract creation must be disabled.')
    need(bool(env.get('ARKEO_PROVIDER_HEALTH_FILE')),'Health policy path is required.')
    need(manifest.get('persistent_nonce_state') is True,'Persistent nonce storage must be declared.')
    need(manifest.get('admin_private_ingress') is True,'Admin must be behind private authenticated ingress.')
    need(manifest.get('redundant_gateway_hosts') is True,'Independent gateway hosts must be declared.')
    workload=manifest.get('workload'); runtime=listeners.get('listeners'); policies=health.get('listeners')
    if not isinstance(workload,list) or not workload or not isinstance(runtime,list) or not isinstance(policies,dict):
        return errors+['Workload, listener list and health policy map are required.']
    ids=[str(x.get('id','')) for x in runtime if isinstance(x,dict)]
    need(len(ids)==len(runtime) and len(ids)==len(set(ids)) and '' not in ids,'Runtime listener IDs must be present and unique.')
    lookup={str(x['id']):x for x in runtime if isinstance(x,dict) and 'id' in x}
    ports=[x.get('port') for x in lookup.values()]
    need(all(type(p) is int and 1024<=p<=65535 for p in ports) and len(set(map(str,ports)))==len(ports),'Listener ports must be unique integers from 1024 to 65535.')
    seen=set()
    for index,row in enumerate(workload):
        label=f'Workload {index+1}'
        if not isinstance(row,dict): errors.append(label+': invalid entry.');continue
        role=row.get('role'); lid=str(row.get('listener_id','')); seen.add(lid)
        need(role in ROLES or (isinstance(role,str) and role.startswith('external:') and len(role)>9),label+': unsupported service role.')
        current=lookup.get(lid)
        if current is None: errors.append(label+': listener is missing.');continue
        need(current.get('auto_create') is False,label+': auto_create must be explicitly false.')
        sid=str(row.get('service_id','')); name=row.get('service_name')
        need(sid.isdecimal() and int(sid)>0 and sid==str(current.get('service_id')),label+': exact registry service ID must match.')
        need(isinstance(name,str) and bool(name) and name==current.get('service_name'),label+': exact registry service name must match.')
        need(bool(row.get('network')) and 'REPLACE' not in str(row.get('network')),label+': expected network is required.')
        need(row.get('workload_confirmed') is True,label+': application methods and path mapping must be reviewed.')
        need(isinstance(row.get('sample_read_path'),str) and row['sample_read_path'].startswith('/') and not row['sample_read_path'].startswith('//'),label+': relative read path is required.')
        providers=row.get('providers',[])
        if not isinstance(providers,list) or not 2<=len(providers)<=3:
            errors.append(label+': primary and one or two backups are required.');continue
        direct=bool(current.get('bypass_uri')); top=current.get('top_services',[])
        if not isinstance(top,list): top=[]
        actual=([{'provider_pubkey':'primary','sentinel_url':current['bypass_uri']}] if direct else [])+top
        need(len(actual)==len(providers),label+': manifest and runtime provider counts differ.')
        domains=[];identities=[]
        bound=policies.get(lid,{})
        if not isinstance(bound,dict): bound={}
        for i,provider in enumerate(providers):
            prefix=f'{label}, provider {i+1}'
            if not isinstance(provider,dict): errors.append(prefix+': invalid entry.');continue
            pk=provider.get('provider_pubkey','');url=provider.get('upstream','');identities.append(pk)
            need((i==0 and direct and pk=='primary') or bool(PUBKEY.fullmatch(pk)),prefix+': exact provider public key is required.')
            need(valid_url(url,lab),prefix+': upstream must be a usable TLS URL without embedded credentials or placeholders.')
            domain=provider.get('failure_domain');domains.append(domain)
            need(isinstance(domain,str) and bool(domain) and 'REPLACE' not in domain,prefix+': independent operator/failure domain declaration is required.')
            need(provider.get('endpoint_approved') is True,prefix+': endpoint usage approval must be recorded.')
            if i<len(actual) and isinstance(actual[i],dict):
                need(actual[i].get('provider_pubkey')==pk and actual[i].get('sentinel_url','').rstrip('/')==url.rstrip('/'),prefix+': runtime identity/endpoint/order mismatch.')
                if not(i==0 and direct): need(str(actual[i].get('service_id',sid))==sid,prefix+': backup belongs to another service.')
            if not(i==0 and direct):
                contract=provider.get('contract',{})
                if not isinstance(contract,dict):contract={}
                need(bool(re.fullmatch(r'[1-9][0-9]*',str(contract.get('id','')))),prefix+': pre-funded contract ID is required.')
                need(contract.get('provider')==pk and str(contract.get('service'))==sid,prefix+': contract provider/service mismatch.')
                need(contract.get('verified_active') is True,prefix+': contract must be checked on chain before launch.')
            policy=bound.get(pk,{})
            if not isinstance(policy,dict):policy={}
            need(policy.get('upstream','').rstrip('/')==url.rstrip('/'),prefix+': health policy must bind the exact upstream.')
            checks=policy.get('checks',[])
            if not isinstance(checks,list) or not 1<=len(checks)<=3:
                errors.append(prefix+': one to three health checks are required.');continue
            network=fresh=False
            for check in checks:
                if not isinstance(check,dict):errors.append(prefix+': invalid health check.');continue
                need(valid_url(check.get('url'),lab),prefix+': invalid health URL.')
                if check.get('network_path'):
                    network=True;need(check.get('expected_network')==row.get('network'),prefix+': health network mismatch.')
                if check.get('timestamp_path'):
                    fresh=True;age=check.get('max_age_seconds',60)
                    need(type(age) in (float,int) and 1<=age<=600,prefix+': freshness must be bounded to 1–600 seconds.')
                for field in ('network_path','timestamp_path','height_path'):
                    if field in check:need(isinstance(check[field],str) and check[field].startswith('/'),prefix+': health field must be a JSON pointer.')
            need(network and fresh,prefix+': network and freshness checks are both required.')
            if role in ('thorchain-midgard','maya-midgard'):
                need(provider.get('indexer_freshness_verified') is True,prefix+': verify indexer freshness separately from node freshness.')
        need(len(set(map(str,domains)))==len(domains),label+': backups must have independent declared failure domains.')
        need(len(set(map(str,identities)))==len(identities),label+': duplicate provider identity.')
    need(len(seen)==len(workload),'Workload listener IDs must be unique.')
    need(seen==set(lookup),'Every deployed listener must appear in the reviewed workload.')
    return errors

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('manifest','listeners','health'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--lab',action='store_true',help='Allow loopback HTTP fixtures only; does not certify a deployment.')
    args=parser.parse_args()
    try:
        documents=[]
        for path in (args.manifest,args.listeners,args.health):
            with open(path,encoding='utf-8') as stream: documents.append(json.load(stream))
        errors=validate(*documents,lab=args.lab)
    except (OSError,ValueError,TypeError,KeyError,AttributeError):
        errors=['Cannot validate input documents. Check JSON structure and local file access.']
    print(json.dumps({'configuration_valid':not errors,'production_ready':False,'checks_are_offline':True,'errors':errors,'remaining':'Verify live registry/contracts, endpoint compatibility, credentials, gateway deployment, funded wallet flows, load and failover acceptance before approval.'},indent=2))
    return 1 if errors else 0
if __name__=='__main__':sys.exit(main())
