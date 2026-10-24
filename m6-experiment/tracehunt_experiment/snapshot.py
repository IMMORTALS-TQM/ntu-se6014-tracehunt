"""Read-only exact dataset check for a small isolated experiment index set."""
from .common import *
from .dataset import verify_dataset

def expected_records(dataset):
    return sorted([{'index':r['index'],'id':r['document_id'],'source':r['event']}
        for r in rows(Path(dataset)/'normalized/events.jsonl')],key=lambda x:(x['index'],x['id']))

def verify_index(dataset,out=None):
    m=verify_dataset(dataset);siblings()
    from tracehunt_mcp.config import Config
    from tracehunt_mcp.backend import EsBackend
    cfg=Config.from_env()
    if set(cfg.indices)!=set(SOURCES):raise ValueError('live check requires the three exact M1/M4 indices')
    backend=EsBackend(cfg);actual=[]
    try:
        for index in SOURCES:
            if not backend.index_exists(index):raise ValueError(f'missing index {index}')
            response=backend.search(index,{'query':{'match_all':{}},'size':10000,'track_total_hits':True})
            total=response.get('hits',{}).get('total',{});hits=response.get('hits',{}).get('hits',[])
            if response.get('timed_out') or response.get('_shards',{}).get('failed',0):raise ValueError('incomplete snapshot response')
            if total.get('relation')!='eq' or total.get('value')!=len(hits):raise ValueError('index exceeds bounded full export or export incomplete')
            actual += [{'index':index,'id':h['_id'],'source':h['_source']} for h in hits]
    finally:backend.close()
    actual.sort(key=lambda x:(x['index'],x['id']))
    if actual!=expected_records(dataset):raise ValueError('live indices differ from normalized M3 dataset: extra, missing, changed documents or IDs')
    result={'dataset_id':m['dataset_id'],'snapshot_sha256':sha(actual),'verification':'exact_small_index_export',
        'note':'Instantaneous index equality, not proof of collector continuity or immutability between checks.'}
    if out:
        if Path(out).exists():raise ValueError('snapshot receipt exists')
        write(out,result)
    return result
