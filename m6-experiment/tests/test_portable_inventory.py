"""Assert canonical manifest keys on the native filesystem, including Windows CI."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tracehunt_experiment.common import read
from tracehunt_experiment.dataset import prepare,verify_dataset
from tracehunt_experiment.freeze import source_files

class PortableInventoryTests(unittest.TestCase):
    def test_nested_source_keys_are_posix_and_credentials_stay_excluded(self):
        with tempfile.TemporaryDirectory() as t:
            repo=Path(t)
            nested=repo/'m5-hunt'/'nested'
            nested.mkdir(parents=True)
            (nested/'token_counter.py').write_text('count = 1\n',encoding='utf-8')
            (nested/'.env').write_text('PASSWORD=example\n',encoding='utf-8')
            (nested/'credentials.json').write_text('{"password":"example"}',encoding='utf-8')
            keys=set(source_files(repo))
            self.assertEqual(keys,{'m5-hunt/nested/token_counter.py'})
            self.assertTrue(all('\\' not in key for key in keys))
    def test_dataset_generated_and_verified_keys_are_posix(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);data=root/'data'
            prepare(data,root/'private')
            manifest=read(data/'dataset_manifest.json')
            self.assertIn('normalized/events.jsonl',manifest['files'])
            self.assertIn('schema/fallback_audit.json',manifest['files'])
            self.assertTrue(all('\\' not in key for key in manifest['files']))
            self.assertEqual(verify_dataset(data),manifest)

if __name__=='__main__':unittest.main()
