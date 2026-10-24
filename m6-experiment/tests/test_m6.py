import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tracehunt_experiment.common import *
from tracehunt_experiment.dataset import prepare,verify_dataset,validate_mapping
from tracehunt_experiment.freeze import freeze,verify_freeze
from tracehunt_experiment.run import smoke
from tracehunt_experiment.compare import compare,evaluate,export,jaccard
from tracehunt_experiment.backend import FixtureBackend

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.root=Path(self.t.name)
        self.data=self.root/'data';self.private=self.root/'private'
        self.summary=prepare(self.data,self.private)
        self.config=self.root/'config.json';write(self.config,read(ROOT/'smoke-config.json'))
        self.manifest=self.root/'freeze.json'
        self.f=freeze(self.data,self.config,[ROOT/'SMOKE_PROTOCOL.md'],self.manifest)
    def run_pair(self):
        a,b=self.root/'a',self.root/'b'
        smoke(self.data,self.manifest,a,'run-a');smoke(self.data,self.manifest,b,'run-b')
        return a,b
    def test_deterministic_m3_ids_and_bytes(self):
        other=self.root/'other';prepare(other,self.root/'truth2')
        self.assertEqual(verify_dataset(other),verify_dataset(self.data))
        siblings();from tracehunt_schema import SchemaPipeline
        raw=rows(self.data/'raw/windows-security.ndjson')[0]
        result=SchemaPipeline().process(raw,raw_text=canonical(raw))
        self.assertEqual(result,rows(self.data/'normalized/events.jsonl')[0])
    def test_mapping_and_raw_preservation(self):
        mapping=read(REPO/'m1-elk/index_template.json')['template']['mappings']
        for r in rows(self.data/'normalized/events.jsonl'):
            validate_mapping(r['event'],mapping)
            self.assertIn('source_hash',r['event']['tracehunt'])
        first=rows(self.data/'normalized/events.jsonl')[0]
        self.assertEqual(first['event']['event']['original'],canonical(rows(self.data/'raw/windows-security.ndjson')[0]))
    def test_fallback_reuse_quarantine(self):
        audit=read(self.data/'schema/fallback_audit.json')
        self.assertEqual(audit['created']['created_schemas'],1)
        self.assertEqual(audit['reused']['created_schemas'],0)
        self.assertEqual(audit['reused']['accepted'],2)
        self.assertEqual(len(rows(self.data/'schema/quarantine.jsonl')),2)
        self.assertTrue(list((self.data/'registry').glob('*.json')))
    def test_private_separation_and_counts(self):
        self.assertEqual(self.summary['counts'],{'windows-security':12,'sysmon':4,'zeek':4})
        self.assertEqual(len(read(self.private/'ground_truth.json')['events']),20)
        for p in self.data.rglob('*'):
            if p.is_file():self.assertNotIn('expected_verdict',p.read_text())
        with self.assertRaises(ValueError):prepare(self.root/'new',self.root/'new/private')
    def test_nonempty_directory_rejected(self):
        with self.assertRaises(ValueError):prepare(self.data,self.private)
    def test_data_change_detected(self):
        with (self.data/'raw/sysmon.ndjson').open('a') as f:f.write('\n')
        with self.assertRaises(ValueError):verify_dataset(self.data)
    def test_extra_file_detected(self):
        (self.data/'unexpected').write_text('x')
        with self.assertRaises(ValueError):verify_dataset(self.data)
    def test_asset_and_config_change_detected(self):
        bad=self.root/'SMOKE_PROTOCOL.md';bad.write_text('changed')
        with self.assertRaises(ValueError):verify_freeze(self.manifest,self.data,self.config,[bad])
        c=read(self.config);c['model']='another model';write(self.config,c)
        with self.assertRaises(ValueError):verify_freeze(self.manifest,self.data,self.config,[ROOT/'SMOKE_PROTOCOL.md'])
    def test_manifest_tamper_detected(self):
        f=read(self.manifest);f['configuration']['model']='other';write(self.manifest,f)
        with self.assertRaises(ValueError):verify_freeze(self.manifest)
    def test_real_m4_tools_two_runs(self):
        a,b=self.run_pair();r=compare(a,b,self.manifest,self.private/'ground_truth.json')
        self.assertEqual(r['query_jaccard'],1)
        self.assertEqual(r['evidence_jaccard'],1)
        self.assertEqual(r['claim_exact_jaccard'],1)
        self.assertEqual(r['run_kind'],'typed_api_smoke')
        self.assertEqual(r['runs'][0]['citation_linkage'],1)
        self.assertEqual(r['runs'][0]['archived_citation_coverage'],1)
        self.assertTrue(all(r['runs'][0]['query_window_coverage'].values()))
        self.assertFalse(r['runs'][0]['ground_truth']['verdict_correct'])
        self.assertEqual(r['runs'][0]['ground_truth']['retrieval_recall'],1)
        self.assertTrue(r['runs'][0]['response_archive_complete'])
    def test_same_run_id_rejected(self):
        a,b=self.run_pair()
        with self.assertRaises(ValueError):compare(a,a,self.manifest)
    def test_ledger_hash_mixed_run_detected(self):
        a,b=self.run_pair();ledger=rows(a/'ledger.jsonl');ledger[0]['run_id']='wrong';write_rows(a/'ledger.jsonl',ledger)
        with self.assertRaises(ValueError):evaluate(a,self.f)
        ledger[0]['run_id']='run-a';ledger[0]['query']['tampered']=True;write_rows(a/'ledger.jsonl',ledger)
        with self.assertRaises(ValueError):evaluate(a,self.f)
    def test_missing_and_wrong_citation(self):
        a,b=self.run_pair();r=read(a/'run.json');r['claims'][0]['citations']=[];r['claims'][1]['citations'][0]['ledger_seq']=1;write(a/'run.json',r)
        result=evaluate(a,self.f);self.assertEqual(result['citation_linkage'],0.5)
    def test_archived_response_forgery_detected(self):
        a,b=self.run_pair();response=rows(a/'responses.jsonl')
        for x in response:
            if x['tool']=='fetch_evidence':x['result']['documents'][0]['_id']='forged';break
        write_rows(a/'responses.jsonl',response)
        with self.assertRaises(ValueError):evaluate(a,self.f)
    def test_wrong_truth_rejected(self):
        a,b=self.run_pair();t=read(self.private/'ground_truth.json');t['dataset_id']='wrong';write(self.private/'ground_truth.json',t)
        with self.assertRaises(ValueError):compare(a,b,self.manifest,self.private/'ground_truth.json')
    def test_truncation_and_archive_missing_visible(self):
        a,b=self.run_pair();ledger=rows(a/'ledger.jsonl');ledger[0]['doc_ids_truncated']=True;write_rows(a/'ledger.jsonl',ledger)
        responses=rows(a/'responses.jsonl');responses.pop();write_rows(a/'responses.jsonl',responses)
        result=evaluate(a,self.f)
        self.assertTrue(result['ledger_ids_truncated']);self.assertFalse(result['response_archive_complete'])
    def test_exports_and_html_escaping(self):
        a,b=self.run_pair();r=compare(a,b,self.manifest);r['runs'][0]['verdict']='<script>alert(1)</script>'
        export(r,self.root/'export')
        self.assertTrue((self.root/'export/comparison.csv').read_bytes().startswith(b'\xef\xbb\xbf'))
        self.assertNotIn('<script>',(self.root/'export/comparison.html').read_text())
        self.assertTrue((self.root/'export/differences.json').is_file())
    def test_empty_claims_and_sets_not_perfect(self):
        a,b=self.run_pair();r=read(a/'run.json');r['claims']=[];write(a/'run.json',r)
        self.assertIsNone(evaluate(a,self.f)['citation_linkage'])
        self.assertIsNone(jaccard(set(),set()))
    def test_backend_refuses_unknown_dsl(self):
        backend=FixtureBackend(rows(self.data/'normalized/events.jsonl'))
        with self.assertRaises(ValueError):backend.search('sysmon',{'query':{'script':{}}})
    def test_m4_read_guard_and_unicode_hash(self):
        siblings();from tracehunt_mcp.ledger import EvidenceLedger,query_hash
        from tracehunt_mcp.config import Config
        from tracehunt_mcp.tools import ToolSet
        from tracehunt_mcp.errors import ToolInputError
        ledger=EvidenceLedger(str(self.root/'guard.jsonl'),'guard')
        tools=ToolSet(Config.from_env(),FixtureBackend(rows(self.data/'normalized/events.jsonl')),ledger)
        with self.assertRaises(ToolInputError):tools.fetch_evidence('not-allowed',['x'])
        self.assertEqual(rows(self.root/'guard.jsonl')[0]['status'],'error')
        self.assertEqual(sha({'user':'测试'}),query_hash({'user':'测试'}))

    def test_kibana_objects_resolve(self):
        from tracehunt_experiment.product import kibana
        out=self.root/'kibana';kibana(self.data,out)
        objects=rows(out/'m6_saved_objects.ndjson');keys={(x['type'],x['id']) for x in objects}
        self.assertEqual(len(keys),6)
        for x in objects:
            for ref in x['references']:self.assertIn((ref['type'],ref['id']),keys)
    def test_source_version_drift_detected(self):
        from unittest.mock import patch
        with patch('tracehunt_experiment.freeze.source_files',return_value={'changed.py':'different'}):
            with self.assertRaises(ValueError):verify_freeze(self.manifest,self.data)
    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(ValueError):decode('{"run_id":"a","run_id":"b"}')

if __name__=='__main__':unittest.main()
