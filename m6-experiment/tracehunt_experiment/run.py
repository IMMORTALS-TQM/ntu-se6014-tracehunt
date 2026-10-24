"""Exercise real M4 ToolSet with fixture or live ES backend. No LLM is invoked."""
from dataclasses import replace
import time
from .common import *
from .dataset import verify_dataset
from .freeze import verify_freeze, effective_m4_limits
from .backend import FixtureBackend

class RecordingBackend:
    def __init__(self,backend,path):self.backend,self.path=backend,path
    def __getattr__(self,name):
        target=getattr(self.backend,name)
        if name not in ('search','mget','count','index_exists'):return target
        def call(*args,**kwargs):
            value=target(*args,**kwargs)
            with self.path.open('a',encoding='utf-8') as f:f.write(canonical({'operation':name,'args':args,'kwargs':kwargs,'response':value})+'\n')
            if name=='search' and (value.get('timed_out') or value.get('_shards',{}).get('failed',0)):
                raise ValueError('incomplete Elasticsearch response: timeout or failed shards')
            return value
        return call


def smoke(dataset,manifest,out,run_id,backend_kind='fixture'):
    if not run_id or not isinstance(run_id,str):raise ValueError('run ID required')
    f=verify_freeze(manifest,dataset=dataset)
    if f['configuration']['experiment_kind']!='typed_api_smoke':raise ValueError('smoke requires a typed_api_smoke freeze, never label it as an agent run')
    siblings()
    from tracehunt_mcp.config import Config
    from tracehunt_mcp.tools import ToolSet
    from tracehunt_mcp.ledger import EvidenceLedger
    from tracehunt_mcp.backend import EsBackend
    out=new_directory(out);scenario=f['scenario'];start,end=scenario['start'],scenario['end']
    cfg=replace(Config.from_env(),run_id=run_id,ledger_path=str(out/'ledger.jsonl'))
    if effective_m4_limits(cfg)!=f['m4_limits']:
        raise ValueError('effective execution limits differ from freeze')
    if tuple(cfg.indices)!=SOURCES:
        raise ValueError('M6 smoke requires the three exact scenario indices')
    backend=FixtureBackend(rows(Path(dataset)/'normalized/events.jsonl')) if backend_kind=='fixture' else EsBackend(cfg)
    backend=RecordingBackend(backend,out/'backend_responses.jsonl')
    tools=ToolSet(cfg,backend,EvidenceLedger(cfg.ledger_path,run_id))
    if backend_kind=='elasticsearch':
        from .snapshot import verify_index
        verify_index(dataset,out/'index_before.json')
    responses=[];claims=[];plan=[];began=time.monotonic();incomplete=[];complete=True
    def call(name,**args):
        nonlocal complete
        value=getattr(tools,name)(**args)
        from .results import result_complete
        ok=result_complete(name,value)
        complete &= ok
        seq=rows(out/'ledger.jsonl')[-1]['seq']
        if not ok:incomplete.append(seq)
        responses.append({'ledger_seq':seq,'tool':name,'arguments':args,'result':value})
        write_rows(out/'responses.jsonl',responses)
        return value,seq
    try:
        call('list_data_sources')
        bounds={s:call('get_time_bounds',index=s)[0] for s in SOURCES}
        def eq(k,v):return {'field':k,'op':'eq','value':v}
        stages=[('failed-logons','windows-security',[eq('host.name','WS-01'),eq('user.name','lab-user'),eq('event.code','4625')],
                 'Failed logon evidence for lab-user occurred on WS-01.'),
                ('successful-logon','windows-security',[eq('host.name','WS-01'),eq('user.name','lab-user'),eq('event.code','4624'),eq('winlog.logon.type',3)],
                 'A successful network logon for lab-user occurred on WS-01.'),
                ('encoded-process','sysmon',[eq('host.name','WS-01'),eq('user.name','lab-user'),eq('process.name','powershell.exe')],
                 'A PowerShell process for lab-user occurred on WS-01; inspect its command line for the encoded flag.'),
                ('network','zeek',[eq('source.ip','10.10.10.21'),eq('destination.ip','10.10.10.50'),eq('destination.port',8080)],
                 'The workstation IP connected to the lab server. Process attribution is unproven.')]
        found={}
        for ident,index,filters,statement in stages:
            result,seq=call('search_events',index=index,start=start,end=end,filters=filters,size=50)
            full=result['total_relation']=='eq' and result['returned']==result['total_matches']
            complete &= full
            found[ident]=result
            plan.append({'id':ident,'index':index,'status':'complete' if full else 'incomplete','ledger_seq':seq})
            if result['doc_ids']:
                fetched,fetch_seq=call('fetch_evidence',index=index,doc_ids=result['doc_ids'])
                complete &= fetched['found']==fetched['requested']
                claims.append({'id':ident,'statement':statement,'citations':[{'index':index,'doc_id':d['_id'],'ledger_seq':fetch_seq} for d in fetched['documents']]})
        call('aggregate_events',index='windows-security',start=start,end=end,kind='terms',field='event.code')
        call('run_sequence_query',index='windows-security',start=start,end=end,entity_field='user.name',steps=[
            {'name':'failure','filters':[eq('event.code','4625'),eq('host.name','WS-01'),eq('user.name','lab-user'),eq('source.ip','10.10.10.99')]},
            {'name':'success','filters':[eq('event.code','4624'),eq('host.name','WS-01'),eq('user.name','lab-user'),eq('source.ip','10.10.10.99')]}])
        call('get_query_history')
        # Exercise evidence path only. A real verdict belongs to M5's verifier.
        report={'schema_version':3,'run_id':run_id,'run_kind':'typed_api_smoke',
            'm4_limits':effective_m4_limits(cfg),'backend':backend_kind,'dataset_id':f['dataset_id'],'freeze_id':f['freeze_id'],
            'verdict':'inconclusive','verdict_basis':'M6 smoke checks typed tool integration, not M5 hypothesis verification.',
            'claims':claims,'source_coverage':{s:{'start':start,'end':end,
                'complete':backend_kind=='fixture','basis':'finite_fixture' if backend_kind=='fixture' else 'unverified_live_collection'} for s in SOURCES},
            'runtime_seconds':time.monotonic()-began,'model_usage':None,
            'plan':plan,'incomplete_tool_results':incomplete,'tool_results_complete':bool(complete),'source_bounds':bounds}
        if backend_kind=='elasticsearch':
            verify_index(dataset,out/'index_after.json')
        write(out/'run.json',report)
        return report
    finally:backend.close()
