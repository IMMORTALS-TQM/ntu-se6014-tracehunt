"""Generate M2-shaped records and normalize them through the unmodified M3 API."""
import base64
import copy
from pathlib import Path
from .common import *


def raw_events():
    data = {s: [] for s in SOURCES}
    labels = []
    def add(s, minute, payload, relevant=False, stage=None):
        text = f'2026-10-23T14:{minute:02}:00+08:00'
        if s in ('windows-security', 'sysmon'):
            provider = 'Microsoft-Windows-Security-Auditing' if s == 'windows-security' else 'Microsoft-Windows-Sysmon'
            code = payload.pop('code')
            host = payload.pop('computer', 'WS-01')
            record = {'@timestamp': text, 'source_type': s, 'host': {'name': host},
                'event': {'code': str(code), 'provider': provider,
                          'dataset': 'windows.security' if s == 'windows-security' else 'sysmon.events'},
                'winlog': {'event_id': code, 'channel': 'Security' if s == 'windows-security' else 'Microsoft-Windows-Sysmon/Operational',
                    'provider_name': provider, 'computer_name': host,
                    'record_id': len(data[s])+1, 'event_data': payload},
                'raw_xml': '<Event><!-- synthetic fixture, not captured EVTX --></Event>'}
        else:
            record = {'ts': time_value(text), 'uid': f'M6HTTP{len(data[s])+1}',
                'source_type': 'zeek', 'log_type': 'http', 'event': {'dataset': 'zeek.http'}, **payload}
            record['raw_line'] = canonical({k:v for k,v in record.items() if k not in ('source_type', 'event', 'log_type')})
        data[s].append(record)
        labels.append((s, len(data[s])-1, relevant, stage))
        return record
    for minute in range(8):
        add('windows-security', minute, {'code':4625, 'TargetUserName':'lab-user',
            'TargetDomainName':'LAB', 'LogonType':'3', 'IpAddress':'10.10.10.99',
            'IpPort':'51515', 'Status':'0xC000006A'}, True, 'failed_logon')
    add('windows-security',9,{'code':4624,'TargetUserName':'lab-user','TargetDomainName':'LAB',
        'LogonType':'3','IpAddress':'10.10.10.99','IpPort':'51515','Status':'0x0'},True,'success_logon')
    encoded=base64.b64encode("Write-Output 'TraceHunt lab marker'".encode('utf-16-le')).decode()
    add('sysmon',12,{'code':1,'User':'LAB\\lab-user','Image':'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        'CommandLine':'powershell.exe -NoProfile -EncodedCommand '+encoded,'ProcessId':'4242','ProcessGuid':'{m6-process-4242}',
        'ParentImage':'C:\\Windows\\System32\\cmd.exe','ParentProcessId':'4000'},True,'encoded_process')
    add('zeek',14,{'id.orig_h':'10.10.10.21','id.orig_p':51000,'id.resp_h':'10.10.10.50','id.resp_p':8080,
        'method':'GET','host':'lab-server.team:8080','uri':'/checkin','status_code':200,'user_agent':'TraceHunt-Lab/1.0'},True,'http_connection')
    add('windows-security',10,{'code':4624,'computer':'WS-02','TargetUserName':'lab-user',
        'LogonType':'2','IpAddress':'10.10.10.80'})
    add('sysmon',11,{'code':1,'computer':'WS-02','User':'LAB\\admin','Image':'C:\\Windows\\powershell.exe',
        'CommandLine':'powershell.exe -EncodedCommand '+encoded})
    add('zeek',15,{'id.orig_h':'10.10.10.21','id.orig_p':51001,'id.resp_h':'10.10.10.60','id.resp_p':80,
        'method':'GET','host':'ordinary.team','uri':'/index.html','status_code':200})
    for source in SOURCES:
        for text in ['2026-10-23T13:55:00+08:00','2026-10-23T14:35:00+08:00']:
            if source == 'windows-security':
                record=add(source,20,{'code':4624,'computer':'WS-03','TargetUserName':'office-user','LogonType':'2','IpAddress':'10.10.10.30'})
            elif source == 'sysmon':
                record=add(source,20,{'code':1,'computer':'WS-03','User':'LAB\\office-user','Image':'C:\\Windows\\notepad.exe','CommandLine':'notepad.exe notes.txt'})
            else:
                record=add(source,20,{'id.orig_h':'10.10.10.30','id.resp_h':'10.10.10.60','id.resp_p':80,'method':'GET','uri':'/normal'})
            if source == 'zeek':
                record['ts']=time_value(text)
                record['raw_line']=canonical({k:v for k,v in record.items() if k not in ('source_type','event','log_type','raw_line')})
            else: record['@timestamp']=text
    return data,labels


def validate_mapping(doc, mapping, prefix=''):
    """Check all emitted field names and basic scalar types against M1 strict mapping."""
    for k,v in doc.items():
        path=f'{prefix}.{k}' if prefix else k
        if k not in mapping.get('properties',{}): raise ValueError(f'M1 mapping rejects {path}')
        spec=mapping['properties'][k]
        if 'properties' in spec:
            if not isinstance(v,dict): raise ValueError(f'object required: {path}')
            validate_mapping(v,spec,path)
        elif spec['type'] in ('keyword','wildcard','text','date','ip'):
            if not isinstance(v,str): raise ValueError(f'string required: {path}')
        elif spec['type'] in ('long','integer'):
            if not isinstance(v,int) or isinstance(v,bool): raise ValueError(f'integer required: {path}')


def prepare(out, private):
    out,private=Path(out).resolve(),Path(private).resolve()
    if out==private or out in private.parents or private in out.parents:
        raise ValueError('public/private outputs must be separate, non-nested directories')
    # A package must never accidentally contain its answer file.
    for p in (out,private):
        if p.exists() and (not p.is_dir() or any(p.iterdir())): raise ValueError(f'output must be empty: {p}')
    siblings()
    from tracehunt_schema import SchemaAgent,SchemaPipeline,SchemaRegistry
    from tracehunt_schema.config import Config
    out=new_directory(out); private=new_directory(private)
    raw,labels=raw_events(); registry=SchemaRegistry(out/'registry'); config=Config()
    mapping=read(REPO/'m1-elk/index_template.json')['template']['mappings']
    accepted=[]; by_position={}; audit=[]
    for source,records in raw.items():
        texts=[canonical(r) for r in records]
        write_rows(out/'raw'/f'{source}.ndjson',records)
        batch=SchemaAgent(registry=registry,config=config,frozen=True).process_batch(records,raw_texts=texts)
        if batch['summary']['accepted']!=len(records): raise ValueError(f'M3 quarantined hunt data: {batch}')
        audit.append({'source':source, 'summary':batch['summary'],'decisions':batch['decisions']})
        for pos,result in enumerate(batch['results']):
            validate_mapping(result['event'],mapping)
            by_position[source,pos]=result
            accepted.append(result)
    write_rows(out/'normalized/events.jsonl',accepted)
    bulk=[]
    for r in accepted: bulk += [{'create':{'_index':r['index'],'_id':r['document_id']}},r['event']]
    write_rows(out/'normalized/bulk.ndjson',bulk)
    write(out/'schema/known_audit.json',audit)
    # Unknown-format generation, durable registration, frozen reuse, and rejected input.
    unknown=[{'event_time':START,'machine':'CUSTOM-01','account':'fixture-user',
              'target_ip':'10.10.10.50','target_port':8080,'note':'fallback fixture'},
             {'event_time':END,'machine':'CUSTOM-02','account':'fixture-user',
              'target_ip':'10.10.10.60','target_port':80,'note':'fallback fixture'}]
    write_rows(out/'schema/unknown.ndjson',unknown)
    created=SchemaAgent(registry=registry,config=config).process_batch(unknown)
    reused=SchemaAgent(registry=SchemaRegistry(out/'registry'),config=config,frozen=True).process_batch(unknown)
    invalid=copy.deepcopy(raw['windows-security'][0]);invalid['winlog']['event_data']['IpAddress']='bad-ip'
    broken_custom=copy.deepcopy(unknown[0]);broken_custom['target_port']=70000
    rejected=SchemaAgent(registry=registry,config=config,frozen=True).process_batch([invalid,broken_custom])
    if created['summary']['created_schemas']!=1 or reused['summary']['accepted']!=2 or rejected['summary']['quarantined']!=2:
        raise ValueError('M3 fallback/reuse/quarantine checks failed')
    for result in created['results']: validate_mapping(result['event'],mapping)
    write_rows(out/'schema/fallback_events.jsonl',created['results'])
    write(out/'schema/fallback_audit.json',{'created':created['summary'],'create_decisions':created['decisions'],
          'reused':reused['summary'],'reuse_decisions':reused['decisions'],'invalid':rejected['summary']})
    write_rows(out/'schema/quarantine.jsonl',rejected['results'])
    counts={s:sum(r['source']==s for r in accepted) for s in SOURCES}
    scenario={'schema_version':2,'dataset_kind':'synthetic_m2_shapes_normalized_by_m3',
        'hypothesis':'Did lab-user on WS-01 show repeated failed network logons, a successful remote logon, encoded PowerShell and a subsequent host-correlated HTTP connection to the lab server?',
        'start':START,'end':END,'required_sources':list(SOURCES),'host_ip_map':{'WS-01':'10.10.10.21'},
        'account_forms':['lab-user','LAB\\lab-user'],'lab_server':{'ip':'10.10.10.50','port':8080},
        'counts':counts,'coverage_basis':'complete finite synthetic fixture, not real collector continuity',
        'network_attribution':'host and time correlation only, no process-level network attribution'}
    write(out/'scenario.json',scenario)
    write(out/'schema/config.json',{'ecs_version':config.ecs_version,'naive_timezone':config.naive_timezone,'routes':config.routes})
    # Every file below is generated deterministically; hash the actual M3 output and schema audit.
    hashes={p.relative_to(out).as_posix():file_sha(p) for p in sorted(out.rglob('*')) if p.is_file()}
    manifest={'schema_version':2,'files':hashes,'counts':counts}
    manifest['dataset_id']=payload_hash(manifest,'dataset_id')
    write(out/'dataset_manifest.json',manifest)
    event_manifest=[]
    for source,pos,relevant,stage in labels:
        r=by_position[source,pos]
        event_manifest.append({'index':r['index'],'doc_id':r['document_id'],'relevant':relevant,
            'stage':stage,'event':r['event']})
    write(private/'ground_truth.json',{'schema_version':2,'dataset_id':manifest['dataset_id'],'expected_verdict':'confirmed',
        'meaning':'The defined synthetic indicator sequence exists. This is not evidence of real compromise.',
        'events':event_manifest})
    (private/'README.txt').write_text('M6 evaluator only. Keep outside the repository and agent context. Use only after both reports are final. This manifest applies only to the matching dataset_id.\n')
    return {'dataset_id':manifest['dataset_id'],'counts':counts,'fallback':created['summary'],'quarantine':rejected['summary']}


def verify_dataset(path):
    root=Path(path); m=read(root/'dataset_manifest.json')
    if payload_hash(m,'dataset_id')!=m['dataset_id']:raise ValueError('dataset manifest integrity failure')
    actual={p.relative_to(root).as_posix():file_sha(p) for p in root.rglob('*') if p.is_file() and p!=root/'dataset_manifest.json'}
    if actual!=m['files']:raise ValueError('dataset changed, files added/removed or hashes differ')
    return m
