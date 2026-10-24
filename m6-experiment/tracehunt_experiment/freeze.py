"""Freeze actual dataset bytes and current M1-M4/M6 source files."""
from pathlib import Path
from .common import *
from .dataset import verify_dataset

CONFIG_KEYS={'experiment_kind','model','model_parameters','prompt_version','schema_version','index_snapshot'}

# Source/config inventories exclude generated output and credentials. Only digests
# are serialized; Config connection/authentication values are never recorded.
SOURCE_SUFFIXES={'.py','.ps1','.sh','.toml','.yml','.yaml','.json','.conf',
                 '.js','.mjs','.cjs','.ts','.tsx','.jsx','.ini','.cfg','.txt','.md'}
EXCLUDED_DIRS={'__pycache__','.git','.venv','venv','node_modules','output',
               'results','evidence','.pytest_cache'}
SECRET_NAMES={'credentials.json','secrets.json','passwords.json','tokens.json','auth.json'}
M4_LIMIT_FIELDS=('indices','default_size','max_size','max_window_hours',
                 'request_timeout_s','max_scan','max_doc_ids','max_seq_steps',
                 'max_agg_buckets')

def effective_m4_limits(cfg=None):
    siblings()
    from tracehunt_mcp.config import Config
    cfg=cfg or Config.from_env()
    result={name:getattr(cfg,name) for name in M4_LIMIT_FIELDS}
    result['indices']=list(result['indices'])
    return result

def source_files(repo=REPO):
    repo=Path(repo)
    paths=set()
    for name in ['m1-elk','m2-connectors','m3-schema','m4-mcp','m5-hunt']:
        for p in (repo/name).rglob('*'):
            relative=p.relative_to(repo/name)
            if (not p.is_file() or any(part in EXCLUDED_DIRS for part in relative.parts)
                    or p.name.startswith('.env')
                    or p.name.lower() in SECRET_NAMES):
                continue
            if p.suffix.lower() in SOURCE_SUFFIXES or (name=='m5-hunt' and p.name!='.gitkeep'):
                paths.add(p)
    module=repo/'m6-experiment'
    for directory in ('tracehunt_experiment','tests'):
        paths.update(p for p in (module/directory).rglob('*.py')
                     if '__pycache__' not in p.parts)
    for name in ('experiment.py','pyproject.toml','smoke-config.json',
                 'agent-config.example.json','SMOKE_PROTOCOL.md'):
        if (module/name).is_file():paths.add(module/name)
    workflow=repo/'.github/workflows/m6-tests.yml'
    if workflow.is_file():paths.add(workflow)
    return {p.relative_to(repo).as_posix():file_sha(p) for p in sorted(paths)}

def validate_config(c):
    if not isinstance(c,dict) or set(c)!=CONFIG_KEYS:raise ValueError(f'config keys must be exactly {sorted(CONFIG_KEYS)}; credentials never belong here')
    if c['experiment_kind'] not in ['agent','typed_api_smoke']:raise ValueError('experiment_kind must be agent or typed_api_smoke')
    if not isinstance(c['model_parameters'],dict):raise ValueError('model_parameters must be an object')
    for k in CONFIG_KEYS-{'model_parameters'}:
        if not isinstance(c[k],str) or not c[k].strip() or any(x in c[k].lower() for x in ['todo','replace_me','pending']):
            raise ValueError(f'concrete configuration required: {k}')
    def secrets(x):
        if isinstance(x,dict):
            for k,v in x.items():
                if any(s in k.lower() for s in ['password','secret','api_key','authorization','access_token']):raise ValueError('do not freeze credentials')
                secrets(v)
        elif isinstance(x,list):
            for v in x:secrets(v)
    secrets(c)

def freeze(dataset,config,assets,out):
    m=verify_dataset(dataset); c=read(config); validate_config(c)
    assets=[Path(p).resolve() for p in assets]
    if not assets:raise ValueError('freeze at least the actual prompt/run-protocol asset')
    if len({p.name for p in assets})!=len(assets):raise ValueError('asset names must be unique')
    if Path(out).resolve().is_relative_to(Path(dataset).resolve()):raise ValueError('freeze output must be outside dataset')
    p=Path(out)
    if p.exists():raise ValueError('freeze output exists; use a new path')
    f={'schema_version':3,'dataset_id':m['dataset_id'],'scenario':read(Path(dataset)/'scenario.json'),
        'configuration':c,'m4_limits':effective_m4_limits(),'code_files':source_files(),'assets':{p.name:file_sha(p) for p in assets},
        'freeze_scope_note':'Local dataset and code bytes. External ES snapshot and collection continuity require separate verification.'}
    f['freeze_id']=payload_hash(f,'freeze_id');write(out,f)
    return f

def verify_freeze(manifest,dataset=None,config=None,assets=None,check_code=True,check_limits=True):
    f=read(manifest)
    if payload_hash(f,'freeze_id')!=f['freeze_id']:raise ValueError('freeze manifest hash mismatch')
    if f.get('schema_version')!=3 or 'm4_limits' not in f:
        raise ValueError('v3 requires a new freeze with effective M4 limits')
    validate_config(f['configuration'])
    if check_limits and effective_m4_limits()!=f['m4_limits']:
        raise ValueError('effective M4 behavioral limits changed after freeze')
    if dataset is not None and verify_dataset(dataset)['dataset_id']!=f['dataset_id']:raise ValueError('frozen dataset mismatch')
    if config is not None and read(config)!=f['configuration']:raise ValueError('model/experiment configuration changed')
    if check_code and source_files()!=f['code_files']:raise ValueError('M1-M6 source/config files changed after freeze')
    if assets is not None:
        actual={Path(p).name:file_sha(p) for p in assets}
        if actual!=f['assets']:raise ValueError('prompt/protocol assets changed')
    return f
