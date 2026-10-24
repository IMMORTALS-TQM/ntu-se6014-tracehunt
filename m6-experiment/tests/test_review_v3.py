"""Regressions for the correctness review of v2 (real M3 and M4 APIs)."""
import copy
import importlib
import os
from dataclasses import replace
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tracehunt_experiment.common import *
from tracehunt_experiment.dataset import prepare
from tracehunt_experiment.freeze import freeze,verify_freeze,source_files,effective_m4_limits
from tracehunt_experiment.run import smoke
from tracehunt_experiment.compare import evaluate,compare
from tracehunt_experiment.backend import FixtureBackend

class ReviewRegressions(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.data=self.root/'data'
        prepare(self.data,self.root/'private')
        self.config=self.root/'config.json';write(self.config,read(ROOT/'smoke-config.json'))
        self.manifest=self.root/'freeze.json'
        self.f=freeze(self.data,self.config,[ROOT/'SMOKE_PROTOCOL.md'],self.manifest)
        siblings()
        from tracehunt_mcp.config import Config
        from tracehunt_mcp.tools import ToolSet
        from tracehunt_mcp.ledger import EvidenceLedger
        self.Config,self.ToolSet,self.Ledger=Config,ToolSet,EvidenceLedger
    def toolset(self,out,run_id,records=None,cfg=None):
        out.mkdir(parents=True)
        cfg=cfg or self.Config.from_env()
        cfg=replace(cfg,run_id=run_id,ledger_path=str(out/'ledger.jsonl'))
        tools=self.ToolSet(cfg,FixtureBackend(records or rows(self.data/'normalized/events.jsonl')),self.Ledger(cfg.ledger_path,run_id))
        return tools,cfg
    def save_run(self,out,run_id,cfg,responses,claims=None,frozen=None):
        f=frozen or self.f
        write_rows(out/'responses.jsonl',responses)
        write(out/'run.json',{'schema_version':3,'run_id':run_id,'run_kind':'typed_api_smoke',
            'backend':'fixture','m4_limits':effective_m4_limits(cfg),'dataset_id':f['dataset_id'],
            'freeze_id':f['freeze_id'],'verdict':'inconclusive','claims':claims or [],
            'source_coverage':{},'plan':[],'runtime_seconds':None,'model_usage':None})
    def call(self,tools,out,name,**args):
        result=getattr(tools,name)(**args)
        return {'ledger_seq':rows(out/'ledger.jsonl')[-1]['seq'],'tool':name,'arguments':args,'result':result}
    def isolated_change(self,relative,mutate,add=False):
        # Real copied files, not an assertion against a mocked inventory value.
        repo=self.root/'copy'
        if repo.exists():shutil.rmtree(repo)
        for name in ['m1-elk','m2-connectors','m3-schema','m4-mcp','m5-hunt','m6-experiment','.github']:
            if (REPO/name).exists():shutil.copytree(REPO/name,repo/name,ignore=shutil.ignore_patterns('__pycache__','examples','fixtures'))
        target=repo/relative
        if add:target.parent.mkdir(parents=True,exist_ok=True);target.write_text('value=1\n')
        # Use the real scanner on the isolated tree for both freeze and verify.
        module=importlib.import_module('tracehunt_experiment.freeze')
        with patch.object(module,'source_files',side_effect=lambda:source_files(repo)):
            fpath=self.root/'isolated-freeze.json'
            if fpath.exists():fpath.unlink()
            freeze(self.data,self.config,[ROOT/'SMOKE_PROTOCOL.md'],fpath)
            target.write_text(mutate(target.read_text()),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'source/config'):
                verify_freeze(fpath,self.data)
    def test_logstash_conf_change_invalidates_freeze(self):
        self.isolated_change('m1-elk/pipeline/logstash.conf',lambda s:s.replace('tracehunt-raw-', 'changed-raw-'))
    def test_readonly_role_change_invalidates_freeze(self):
        self.isolated_change('m4-mcp/es/readonly_role.json',lambda s:s.replace('"read"','"all"'))
    def test_m5_new_file_invalidates_freeze(self):
        repo=self.root/'source-copy';shutil.copytree(REPO,repo,ignore=shutil.ignore_patterns('__pycache__','examples','fixtures'))
        module=importlib.import_module('tracehunt_experiment.freeze')
        with patch.object(module,'source_files',side_effect=lambda:source_files(repo)):
            fpath=self.root/'m5-freeze.json';freeze(self.data,self.config,[ROOT/'SMOKE_PROTOCOL.md'],fpath)
            (repo/'m5-hunt/review_example.py').write_text('value=1\n')
            with self.assertRaisesRegex(ValueError,'source/config'):verify_freeze(fpath)
    def test_m5_existing_file_change_invalidates_freeze(self):
        self.isolated_change('m5-hunt/review_example.py',lambda s:s.replace('1','2'),add=True)
    def test_m4_environment_limit_change_rejected_before_smoke(self):
        smoke(self.data,self.manifest,self.root/'a','a')
        with patch.dict(os.environ,{'TRACEHUNT_MAX_SCAN':'1'}):
            with self.assertRaisesRegex(ValueError,'behavioral limits'):verify_freeze(self.manifest)
            with self.assertRaisesRegex(ValueError,'behavioral limits'):smoke(self.data,self.manifest,self.root/'b','b')
        self.assertFalse((self.root/'b').exists())
    def test_each_m4_behavioral_limit_is_frozen(self):
        settings={'TRACEHUNT_DEFAULT_SIZE':'49','TRACEHUNT_MAX_SIZE':'499',
            'TRACEHUNT_MAX_WINDOW_HOURS':'71','TRACEHUNT_REQUEST_TIMEOUT_S':'9',
            'TRACEHUNT_MAX_SCAN':'1','TRACEHUNT_MAX_DOC_IDS':'101',
            'TRACEHUNT_MAX_SEQ_STEPS':'4','TRACEHUNT_MAX_AGG_BUCKETS':'1',
            'TRACEHUNT_INDICES':'windows-security,sysmon'}
        for name,value in settings.items():
            with self.subTest(setting=name),patch.dict(os.environ,{name:value}):
                with self.assertRaisesRegex(ValueError,'behavioral limits'):verify_freeze(self.manifest)
    def test_credentials_are_not_recorded_or_compared(self):
        secret='EXAMPLE-DO-NOT-STORE-4937'
        with patch.dict(os.environ,{'TRACEHUNT_ES_PASSWORD':secret,'TRACEHUNT_ES_USERNAME':secret}):
            fpath=self.root/'safe-freeze.json'
            f=freeze(self.data,self.config,[ROOT/'SMOKE_PROTOCOL.md'],fpath)
            self.assertNotIn(secret,fpath.read_text());self.assertEqual(f['m4_limits'],self.f['m4_limits'])
        verify_freeze(fpath)
    def test_secret_files_excluded_without_hiding_m5_token_code(self):
        repo=self.root/'scan';(repo/'m5-hunt').mkdir(parents=True)
        (repo/'m5-hunt/.env').write_text('PASSWORD=example')
        (repo/'m5-hunt/credentials.json').write_text('{"password":"example"}')
        (repo/'m5-hunt/token_counter.py').write_text('count=1')
        inventory=source_files(repo)
        self.assertEqual(set(inventory),{'m5-hunt/token_counter.py'})
    def test_incomplete_sequence_updates_run_summary(self):
        with patch.dict(os.environ,{'TRACEHUNT_MAX_SCAN':'1'}):
            low=self.root/'low-freeze.json';freeze(self.data,self.config,[ROOT/'SMOKE_PROTOCOL.md'],low)
            r=smoke(self.data,low,self.root/'low','low')
            self.assertFalse(r['tool_results_complete']);self.assertIn(14,r['incomplete_tool_results'])
            self.assertIn(14,evaluate(self.root/'low',read(low))['incomplete_tool_results'])
    def test_incomplete_aggregation_updates_run_summary(self):
        with patch.dict(os.environ,{'TRACEHUNT_MAX_AGG_BUCKETS':'1'}):
            low=self.root/'agg-freeze.json';freeze(self.data,self.config,[ROOT/'SMOKE_PROTOCOL.md'],low)
            r=smoke(self.data,low,self.root/'agg','agg')
            self.assertFalse(r['tool_results_complete']);self.assertIn(13,r['incomplete_tool_results'])
    def test_run_with_different_declared_limits_rejected(self):
        smoke(self.data,self.manifest,self.root/'a','a')
        r=read(self.root/'a/run.json');r['m4_limits']['max_scan']=1;write(self.root/'a/run.json',r)
        with self.assertRaisesRegex(ValueError,'behavioral limits'):evaluate(self.root/'a',self.f)
    def sequence_run(self,name,reverse=False,rename=False):
        out=self.root/name;tools,cfg=self.toolset(out,name)
        def step(code,name):return {'name':name,'filters':[{'field':'event.code','op':'eq','value':code},
            {'field':'user.name','op':'eq','value':'lab-user'},{'field':'host.name','op':'eq','value':'WS-01'}]}
        steps=[step('4625','renamed-fail' if rename else 'failure'),step('4624','renamed-ok' if rename else 'success')]
        if reverse:steps.reverse()
        response=self.call(tools,out,'run_sequence_query',index='windows-security',start=START,end=END,entity_field='user.name',steps=steps)
        self.save_run(out,name,cfg,[response]);return out,response['result']
    def test_reversed_real_m4_sequence_has_different_signature(self):
        a,ra=self.sequence_run('forward');b,rb=self.sequence_run('reverse',reverse=True)
        self.assertEqual(ra['matched_entity_count'],1);self.assertEqual(rb['matched_entity_count'],0)
        result=compare(a,b,self.manifest)
        self.assertEqual(result['query_jaccard'],0);self.assertEqual(result['evidence_jaccard'],0)
        self.assertTrue(result['differences']['queries']['only_a'])
    def test_sequence_step_rename_remains_equivalent(self):
        a,_=self.sequence_run('original');b,_=self.sequence_run('renamed',rename=True)
        self.assertEqual(compare(a,b,self.manifest)['query_jaccard'],1)
    def fetch_101(self):
        from tracehunt_schema import SchemaPipeline
        raw=rows(self.data/'raw/windows-security.ndjson')[0];records=[]
        for i in range(101):
            r=copy.deepcopy(raw);r['winlog']['record_id']=1000+i
            result=SchemaPipeline().process(r,raw_text=canonical(r))
            self.assertEqual(result['status'],'accepted');records.append(result)
        data101=self.root/'data101';data101.mkdir()
        write_rows(data101/'normalized/events.jsonl',records)
        scenario=read(self.data/'scenario.json');scenario['counts']={'windows-security':101,'sysmon':0,'zeek':0}
        scenario['dataset_kind']='synthetic_m3_fetch_regression'
        write(data101/'scenario.json',scenario)
        inventory={'schema_version':2,'files':{p.relative_to(data101).as_posix():file_sha(p) for p in sorted(data101.rglob('*')) if p.is_file()},'counts':scenario['counts']}
        inventory['dataset_id']=payload_hash(inventory,'dataset_id');write(data101/'dataset_manifest.json',inventory)
        with patch.dict(os.environ,{'TRACEHUNT_MAX_DOC_IDS':'101'}):
            fpath=self.root/'101-freeze.json';f=freeze(data101,self.config,[ROOT/'SMOKE_PROTOCOL.md'],fpath)
            out=self.root/'fetch101';tools,cfg=self.toolset(out,'fetch101',records=records)
            ids=[r['document_id'] for r in records]
            response=self.call(tools,out,'fetch_evidence',index='windows-security',doc_ids=ids)
            claims=[{'id':str(i),'statement':'Fetched event '+str(i),
                'citations':[{'index':'windows-security','doc_id':doc_id,'ledger_seq':1}]} for i,doc_id in enumerate(ids)]
            self.save_run(out,'fetch101',cfg,[response],claims=claims,frozen=f)
        return out,f
    def test_real_101_document_m3_m4_fetch_is_accepted(self):
        out,f=self.fetch_101();ledger=rows(out/'ledger.jsonl')[0]
        self.assertEqual(len(ledger['doc_ids']),100);self.assertTrue(ledger['doc_ids_truncated'])
        self.assertEqual(len(rows(out/'responses.jsonl')[0]['result']['documents']),101)
        r=evaluate(out,f)
        self.assertAlmostEqual(r['citation_linkage'],100/101)
        self.assertEqual(r['archived_citation_coverage'],1)
        self.assertEqual(r['archive_only_fetch_ids'],1);self.assertEqual(r['truncated_fetch_sequences'],[1])
    def test_truncated_retained_id_contradiction_still_rejected(self):
        out,f=self.fetch_101();ledger=rows(out/'ledger.jsonl');ledger[0]['doc_ids'][0]='contradictory';write_rows(out/'ledger.jsonl',ledger)
        with self.assertRaisesRegex(ValueError,'contradict'):evaluate(out,f)
    def test_nontruncated_fetch_extra_archive_id_still_rejected(self):
        out=self.root/'one';tools,cfg=self.toolset(out,'one');doc_id=rows(self.data/'normalized/events.jsonl')[0]['document_id']
        response=self.call(tools,out,'fetch_evidence',index='windows-security',doc_ids=[doc_id])
        response['result']['documents'].append({'_id':'extra'})
        self.save_run(out,'one',cfg,[response])
        with self.assertRaises(ValueError):evaluate(out,self.f)
    def test_keyword_match_positives_and_partial_case_negatives(self):
        out=self.root/'match';tools,cfg=self.toolset(out,'match')
        for key,exact,partial,wrong_case in [('host.name','WS-01','WS-0','ws-01'),
                ('user.name','lab-user','lab','LAB-USER'),('event.code','4625','462',None)]:
            for value,positive in [(exact,True),(partial,False)]+([(wrong_case,False)] if wrong_case else []):
                with self.subTest(field=key,value=value):
                    r=tools.search_events(index='windows-security',start=START,end=END,filters=[{'field':key,'op':'match','value':value}])
                    self.assertGreater(r['returned'],0) if positive else self.assertEqual(r['returned'],0)
    def test_unimplemented_match_analyzers_are_rejected(self):
        backend=FixtureBackend(rows(self.data/'normalized/events.jsonl'))
        for q in [{'process.command_line':'-EncodedCommand'},{'event.original':'anything'}]:
            with self.assertRaises(ValueError):backend.search('sysmon',{'query':{'match_phrase':q}})

if __name__=='__main__':unittest.main()
