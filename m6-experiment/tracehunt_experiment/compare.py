"""Compare unmodified M4 ledgers and M5 run exports without inventing results."""
import csv
import html
import re
from .common import *
from .freeze import verify_freeze

HUNT_TOOLS={'search_events','aggregate_events','run_sequence_query'}

def requests(row):
    q=row['query']
    if 'request' in q:return [q['request']]
    return q.get('requests',[])

def normalized_request(req):
    # Ignore descriptive sequence step names, but retain all execution semantics.
    return canonical({k:v for k,v in req.items() if k!='step'})

def ranges(query):
    out=[]
    if isinstance(query,dict):
        spec=query.get('range',{}).get('@timestamp')
        if isinstance(spec,dict) and 'gte' in spec and 'lt' in spec:
            out.append((time_value(spec['gte']),time_value(spec['lt'])))
        for v in query.values():out.extend(ranges(v))
    elif isinstance(query,list):
        for v in query:out.extend(ranges(v))
    return out

def covers(intervals,start,end):
    cursor=start
    for a,b in sorted(intervals):
        if b<=cursor:continue
        if a>cursor:return False
        cursor=max(cursor,b)
        if cursor>=end:return True
    return False

def evaluate(directory,frozen):
    directory=Path(directory);r=read(directory/'run.json')
    required=['schema_version','run_id','run_kind','dataset_id','freeze_id','verdict','claims','source_coverage','runtime_seconds','model_usage','plan','m4_limits']
    if any(k not in r for k in required):raise ValueError('run.json missing fields: '+str([k for k in required if k not in r]))
    if r['schema_version']!=3 or r['run_kind'] not in ('agent','typed_api_smoke'):raise ValueError('invalid run contract version/kind')
    if r['verdict'] not in ('confirmed','rejected','inconclusive'):raise ValueError('invalid verdict')
    if r['dataset_id']!=frozen['dataset_id'] or r['freeze_id']!=frozen['freeze_id']:raise ValueError('run dataset/freeze mismatch')
    if r['m4_limits']!=frozen['m4_limits']:raise ValueError('run M4 behavioral limits differ from freeze')
    if r['run_kind']!=frozen['configuration']['experiment_kind']:raise ValueError('run kind does not match frozen configuration')
    runtime=r['runtime_seconds']
    if runtime is not None and (isinstance(runtime,bool) or not isinstance(runtime,(int,float)) or runtime<0):raise ValueError('invalid runtime')
    usage=r['model_usage']
    if usage is not None:
        if not isinstance(usage,dict):raise ValueError('model usage must be an object or null')
        for k,v in usage.items():
            if not isinstance(v,int) or isinstance(v,bool) or v<0:raise ValueError(f'invalid token usage {k}')
    ledger=rows(directory/'ledger.jsonl')
    if not ledger:raise ValueError('empty evidence ledger')
    last=0; by_seq={}
    for row in ledger:
        seq=row['seq']
        if not isinstance(seq,int) or isinstance(seq,bool) or seq<=last:raise ValueError('ledger sequence must strictly increase')
        last=seq;by_seq[seq]=row
        if row['run_id']!=r['run_id']:raise ValueError('mixed run IDs in ledger')
        if row['status'] not in ('ok','error'):raise ValueError('invalid ledger status')
        if sha(row['query'])!=row['query_hash']:raise ValueError('ledger query hash mismatch')
        if not isinstance(row.get('doc_ids'),list) or not all(isinstance(x,str) for x in row['doc_ids']):raise ValueError('invalid document IDs')
    responses=rows(directory/'responses.jsonl') if (directory/'responses.jsonl').exists() else []
    response_map={}
    for response in responses:
        seq=response['ledger_seq']
        if seq in response_map:raise ValueError('duplicate response sequence')
        if seq not in by_seq or response['tool']!=by_seq[seq]['tool']:raise ValueError('response not linked to matching ledger tool')
        response_map[seq]=response
    queries=set();evidence=set();fetched=set();retrieved_docs={};queried=set();intervals={s:[] for s in SOURCES}
    violations=set();attempted=set();truncated_fetches=[];archive_unlinked=set()
    for row in ledger:
        if row['status']=='error':
            idx=row['query'].get('input',{}).get('index')
            if idx is not None and idx not in SOURCES:attempted.add(str(idx))
        if row['status']=='ok' and row['tool']=='run_sequence_query':
            ordered=[{k:v for k,v in q.items() if k!='step'} for q in requests(row)]
            queries.add(canonical({'tool':'run_sequence_query','requests':ordered}))
        for req in requests(row):
            idx=req.get('index')
            if row['status']=='ok' and idx is not None and idx not in SOURCES:violations.add(str(idx))
            if row['status']=='ok' and row['tool'] in HUNT_TOOLS and req.get('op')=='search':
                if row['tool']!='run_sequence_query':queries.add(normalized_request(req))
                queried.add(idx)
                if idx in intervals:intervals[idx]+=ranges(req.get('body',{}).get('query',{}))
        if row['status']!='ok':continue
        if not row['doc_ids'] and row['tool']=='fetch_evidence' and row['seq'] in response_map:
            empty_result=response_map[row['seq']]['result']
            if empty_result.get('documents') or empty_result.get('found',0):
                raise ValueError('positive fetch archive has no retained ledger IDs')
        if row['doc_ids']:
            indices={q['index'] for q in requests(row) if 'index' in q}
            if len(indices)!=1:raise ValueError('ambiguous index attribution in ledger')
            index=next(iter(indices))
            evidence.update((index,d) for d in row['doc_ids'])
            if row['tool']=='fetch_evidence':
                fetched.update((row['seq'],index,d) for d in row['doc_ids'])
                response=response_map.get(row['seq'])
                if response:
                    result=response['result']
                    if result.get('index')!=index:raise ValueError('fetch response index mismatch')
                    docs=result.get('documents',[])
                    if len({d['_id'] for d in docs})!=len(docs):raise ValueError('duplicate fetched documents')
                    archived_ids=[d['_id'] for d in docs]
                    retained=row['doc_ids']
                    if row.get('doc_ids_truncated',False):
                        siblings()
                        from tracehunt_mcp.ledger import MAX_DOC_IDS_IN_LEDGER
                        if (len(retained)!=MAX_DOC_IDS_IN_LEDGER
                                or len(archived_ids)<=len(retained)
                                or archived_ids[:len(retained)]!=retained):
                            raise ValueError('truncated fetch retained IDs contradict archive prefix')
                        truncated_fetches.append(row['seq'])
                        archive_unlinked.update((row['seq'],index,d) for d in archived_ids[len(retained):])
                    elif set(archived_ids)!=set(retained):
                        raise ValueError('fetch response and ledger IDs differ')
                    # Validate the full archive against the exact fetch request, not just
                    # the 100 IDs retained by M4's capped ledger serialization.
                    wanted=requests(row)[0].get('body',{}).get('ids',[])
                    missing=result.get('missing_ids',[])
                    if (len(archived_ids)!=result.get('found') or result.get('requested')!=len(wanted)
                            or not set(archived_ids).issubset(set(wanted))
                            or set(missing)!=set(wanted)-set(archived_ids)
                            or row.get('result_count')!=len(archived_ids)):
                        raise ValueError('fetch archive contradicts request/counts')
                    for d in docs:retrieved_docs[row['seq'],index,d['_id']]=d
    plan=r['plan']
    if not isinstance(plan,list) or any(x.get('status') not in ('complete','incomplete','skipped') for x in plan):raise ValueError('invalid plan statuses')
    if len({x.get('id') for x in plan})!=len(plan):raise ValueError('duplicate plan IDs')
    claims=r['claims']
    if not isinstance(claims,list):raise ValueError('claims must be a list')
    ids=[c.get('id') for c in claims]
    if any(not isinstance(i,str) or not i.strip() for i in ids) or len(set(ids))!=len(ids):raise ValueError('claim IDs must be unique strings')
    linked=0; archived=0;claim_set=set();claim_evidence=set()
    for claim in claims:
        if not isinstance(claim.get('statement'),str) or not claim['statement'].strip():raise ValueError('claim statement required')
        claim_set.add(canonical({'id':claim['id'],'statement':claim['statement']}))
        refs=claim.get('citations',[])
        if not isinstance(refs,list):raise ValueError('citations must be a list')
        keys=[(c.get('ledger_seq'),c.get('index'),c.get('doc_id')) for c in refs]
        ok=bool(keys) and all(k in fetched for k in keys)
        linked+=ok
        archived+=bool(keys) and all(k in retrieved_docs for k in keys)
        if ok:claim_evidence.update((k[1],k[2]) for k in keys)
    scenario=frozen['scenario'];start,end=time_value(scenario['start']),time_value(scenario['end'])
    declared={}
    for s in SOURCES:
        c=r['source_coverage'].get(s,{})
        try:declared[s]=c.get('complete') is True and time_value(c['start'])<=start and time_value(c['end'])>=end
        except (ValueError,KeyError,TypeError):declared[s]=False
    from .results import result_complete
    incomplete=[response['ledger_seq'] for response in responses
                if not result_complete(response['tool'],response['result'])]
    computed_complete=(set(response_map)==set(by_seq) and not incomplete
                       and all(x['status']=='ok' for x in ledger))
    return {'run_id':r['run_id'],'run_kind':r['run_kind'],'backend':r.get('backend','not_declared'),
        'verdict':r['verdict'],'queried_source_coverage':rate(len(queried&set(SOURCES)),len(SOURCES)),
        'query_window_coverage':{s:covers(intervals[s],start,end) for s in SOURCES},
        'declared_time_window_coverage':declared,
        'coverage_note':'Query intervals and declared coverage do not prove real collector continuity.',
        'citation_linkage':rate(linked,len(claims)),'archived_citation_coverage':rate(archived,len(claims)),
        'truncated_fetch_sequences':truncated_fetches,
        'archive_only_fetch_ids':len(archive_unlinked),
        'citation_note':'Ledger linkage may be incomplete after truncation. Archive coverage is separate; neither proves semantic support.',
        'plan_completion':rate(sum(x['status']=='complete' for x in plan),len(plan)),'claim_count':len(claims),'tool_calls':len(ledger),'tool_errors':sum(x['status']=='error' for x in ledger),
        'response_archive_complete':set(response_map)==set(by_seq),
        'incomplete_tool_results':sorted(set(incomplete)),
        'tool_results_complete':computed_complete,
        'summary_completeness_consistent':r.get('tool_results_complete',computed_complete)==computed_complete,
        'ledger_ids_truncated':any(x.get('doc_ids_truncated',False) for x in ledger),
        'executed_allowlist_violations':sorted(violations),'rejected_outside_allowlist':sorted(attempted),
        'runtime_seconds':runtime,'model_usage':usage,'_queries':queries,'_evidence':evidence,
        '_claims':claim_set,'_claim_evidence':claim_evidence}


def compare(a,b,manifest,truth=None):
    frozen=verify_freeze(manifest,check_code=False,check_limits=False)
    runs=[evaluate(a,frozen),evaluate(b,frozen)]
    if runs[0]['run_id']==runs[1]['run_id']:raise ValueError('independent run IDs required')
    if runs[0]['run_kind']!=runs[1]['run_kind'] or runs[0]['backend']!=runs[1]['backend']:raise ValueError('cannot compare different run kinds/backends')
    result={'schema_version':3,'dataset_id':frozen['dataset_id'],'freeze_id':frozen['freeze_id'],
        'run_kind':runs[0]['run_kind'],'verdict_agreement':runs[0]['verdict']==runs[1]['verdict'],
        'query_jaccard':jaccard(*(r['_queries'] for r in runs)),
        'evidence_jaccard':jaccard(*(r['_evidence'] for r in runs)),
        'claim_exact_jaccard':jaccard(*(r['_claims'] for r in runs)),
        'claim_note':'Stable claim ID and exact statement match, not semantic equivalence.',
        'assessment_status':'metrics_only_requires_human_review',
        'differences':{key[1:]:{'only_a':sorted(runs[0][key]-runs[1][key]),'only_b':sorted(runs[1][key]-runs[0][key])}
            for key in ['_queries','_evidence','_claims']}}
    if truth:
        t=read(truth)
        if t['dataset_id']!=frozen['dataset_id']:raise ValueError('ground truth belongs to a different dataset')
        relevant={(x['index'],x['doc_id']) for x in t['events'] if x['relevant']}
        decoys={(x['index'],x['doc_id']) for x in t['events'] if not x['relevant']}
        for r in runs:
            r['ground_truth']={'verdict_correct':r['verdict']==t['expected_verdict'],
                'retrieval_recall':rate(len(r['_evidence']&relevant),len(relevant)),
                'retrieval_precision':rate(len(r['_evidence']&relevant),len(r['_evidence'])),
                'decoy_ids_cited':sorted(r['_claim_evidence']&decoys)}
    result['runs']=[{k:v for k,v in r.items() if not k.startswith('_')} for r in runs]
    return result


def export(result,out):
    out=Path(out)
    if out.exists() and any(out.iterdir()):raise ValueError('comparison output must be empty')
    out.mkdir(parents=True,exist_ok=True);write(out/'comparison.json',result)
    cells=[['Metric','Run A','Run B','Comparison']]
    def display(x):return 'Not measured' if x is None else canonical(x) if isinstance(x,(dict,list)) else str(x)
    keys=sorted(set(result['runs'][0])|set(result['runs'][1]))
    for k in keys:cells.append([k,*[display(r.get(k)) for r in result['runs']],''])
    for k in ['verdict_agreement','query_jaccard','evidence_jaccard','claim_exact_jaccard','assessment_status']:
        cells.append([k,'','',display(result[k])])
    with (out/'comparison.csv').open('w',encoding='utf-8-sig',newline='') as f:csv.writer(f).writerows(cells)
    escaped=[[s.replace('|','\\|').replace('\n',' ') for s in row] for row in cells]
    md=['# Two-run comparison','',f"Run kind: **{result['run_kind']}**. Human factual-support review required.",'','| Metric | Run A | Run B | Comparison |','|---|---|---|---|']
    md+=['| '+' | '.join(row)+' |' for row in escaped[1:]]
    (out/'comparison.md').write_text('\n'.join(md)+'\n',encoding='utf-8')
    body=''.join('<tr>'+''.join('<'+('th' if i==0 else 'td')+'>'+html.escape(c)+'</'+('th' if i==0 else 'td')+'>' for c in row)+'</tr>' for i,row in enumerate(cells))
    (out/'comparison.html').write_text('<!doctype html><meta charset="utf-8"><title>TraceHunt M6 comparison</title><style>body{font:16px system-ui;margin:40px;color:#123}table{border-collapse:collapse}td,th{border:1px solid #ccd;padding:10px;text-align:left;overflow-wrap:anywhere;max-width:520px}th{background:#123;color:white}</style><h1>TraceHunt comparison</h1><p>Run kind: '+html.escape(result['run_kind'])+'. Metrics only. Human review required.</p><table>'+body+'</table>',encoding='utf-8')
    write(out/'differences.json',result['differences'])
    from .product import narrative
    narrative(result,out/'REPORT_SUMMARY.md')

