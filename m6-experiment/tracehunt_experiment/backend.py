"""Small, strict fixture backend for the query shapes emitted by actual M4 tools.

This is NOT Elasticsearch. Unsupported operations raise rather than fabricating success.
"""
import copy
from .common import *

class FixtureBackend:
    def __init__(self,records,mapping=None):
        self.mapping=mapping or read(REPO/'m1-elk/index_template.json')['template']['mappings']
        self.docs={s:[] for s in SOURCES}
        for r in records:
            if r['status']!='accepted':raise ValueError('fixture backend only accepts M3 accepted results')
            self.docs.setdefault(r['index'],[]).append({'_id':r['document_id'],'_index':r['index'],'_source':r['event']})
    def field_mapping(self,path):
        node=self.mapping
        for part in path.split('.'):
            node=node.get('properties',{}).get(part,{})
        if 'type' not in node:raise ValueError(f'unknown scalar mapping: {path}')
        return node
    def index_exists(self,index):return index in self.docs
    def match(self,doc,q):
        if 'match_all' in q:return True
        if 'bool' in q:
            if set(q['bool'])!={'filter'}:raise ValueError('unsupported bool operation')
            return all(self.match(doc,c) for c in q['bool']['filter'])
        if 'term' in q:
            k,v=next(iter(q['term'].items()));return field(doc,k)==v
        if 'match_phrase' in q:
            k,v=next(iter(q['match_phrase'].items()));actual=field(doc,k)
            spec=self.field_mapping(k)
            if spec.get('index') is False:
                raise ValueError(f'field is not indexed: {k}')
            if spec.get('type')!='keyword' or spec.get('normalizer') or spec.get('analyzer') or spec.get('search_analyzer'):
                raise ValueError(f'unsupported match_phrase mapping for {k}: {spec}')
            if not isinstance(v,str):
                raise ValueError('fixture match_phrase supports string keyword queries only')
            return isinstance(actual,str) and actual==v
        if 'exists' in q:return field(doc,q['exists']['field']) is not None
        if 'range' in q:
            k,spec=next(iter(q['range'].items()));val=field(doc,k)
            if val is None:return False
            v=time_value(val) if k=='@timestamp' else val
            for op,bound in spec.items():
                b=time_value(bound) if k=='@timestamp' else bound
                if op=='gte' and v<b:return False
                elif op=='lt' and v>=b:return False
                elif op not in ['gte','lt']:raise ValueError('unsupported range bound')
            return True
        raise ValueError(f'unsupported query {q}')
    def count(self,index,query):return sum(self.match(d['_source'],query) for d in self.docs.get(index,[]))
    def mget(self,index,ids):
        by_id={d['_id']:d for d in self.docs.get(index,[])}
        return [dict(copy.deepcopy(by_id[i]),found=True) if i in by_id else {'_id':i,'found':False} for i in ids]
    def search(self,index,body):
        docs=[d for d in self.docs.get(index,[]) if self.match(d['_source'],body.get('query',{'match_all':{}}))]
        docs=sorted(docs,key=lambda d:(time_value(d['_source']['@timestamp']),d['_id']))
        if body.get('sort') and list(body['sort'][0].values())[0].get('order')=='desc':docs.reverse()
        result={'hits':{'total':{'value':len(docs),'relation':'eq'},'hits':copy.deepcopy(docs[:body.get('size',10)])}}
        aggs={}
        for name,spec in body.get('aggs',{}).items():
            if 'min' in spec or 'max' in spec:
                op=next(iter(spec));vals=[field(d['_source'],spec[op]['field']) for d in docs]
                vals=[v for v in vals if v is not None]
                val=(min if op=='min' else max)(vals,key=time_value) if vals else None
                aggs[name]={'value':time_value(val)*1000 if val else None,'value_as_string':val}
            elif 'terms' in spec:
                counts={}
                for d in docs:
                    v=field(d['_source'],spec['terms']['field'])
                    if v is not None:counts[v]=counts.get(v,0)+1
                values=sorted(counts.items(),key=lambda kv:(-kv[1],str(kv[0])))
                limit=spec['terms']['size'];aggs[name]={'buckets':[{'key':k,'doc_count':v} for k,v in values[:limit]],'sum_other_doc_count':sum(v for _,v in values[limit:])}
            else:raise ValueError('fixture backend supports min/max/terms aggregations only')
        if aggs:result['aggregations']=aggs
        return result
    def close(self):pass
