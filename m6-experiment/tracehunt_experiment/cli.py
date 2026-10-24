import argparse
from pathlib import Path
from .common import canonical,write,read
from .dataset import prepare,verify_dataset
from .freeze import freeze,verify_freeze
from .run import smoke
from .compare import compare,export
from .snapshot import verify_index
from .product import kibana


def main():
    p=argparse.ArgumentParser(description='TraceHunt M6 v4: M3-derived data and M4 evidence evaluation')
    sub=p.add_subparsers(dest='command',required=True)
    s=sub.add_parser('prepare');s.add_argument('--out',required=True);s.add_argument('--private',required=True)
    s=sub.add_parser('kibana');s.add_argument('--dataset',required=True);s.add_argument('--out',required=True)
    s=sub.add_parser('check-data');s.add_argument('--dataset',required=True)
    s=sub.add_parser('freeze');s.add_argument('--dataset',required=True);s.add_argument('--config',required=True);s.add_argument('--asset',action='append',required=True);s.add_argument('--out',required=True)
    s=sub.add_parser('verify-freeze');s.add_argument('--manifest',required=True);s.add_argument('--dataset',required=True);s.add_argument('--config',required=True);s.add_argument('--asset',action='append',required=True)
    s=sub.add_parser('verify-index');s.add_argument('--dataset',required=True);s.add_argument('--out',required=True)
    s=sub.add_parser('smoke');s.add_argument('--dataset',required=True);s.add_argument('--manifest',required=True);s.add_argument('--out',required=True);s.add_argument('--run-id',required=True);s.add_argument('--backend',choices=['fixture','elasticsearch'],default='fixture')
    s=sub.add_parser('compare');s.add_argument('--run-a',required=True);s.add_argument('--run-b',required=True);s.add_argument('--manifest',required=True);s.add_argument('--truth');s.add_argument('--out',required=True)
    a=p.parse_args()
    try:
        if a.command=='prepare':result=prepare(a.out,a.private)
        elif a.command=='kibana':result=kibana(a.dataset,a.out)
        elif a.command=='check-data':result=verify_dataset(a.dataset)
        elif a.command=='freeze':result=freeze(a.dataset,a.config,a.asset,a.out)
        elif a.command=='verify-freeze':result=verify_freeze(a.manifest,a.dataset,a.config,a.asset)
        elif a.command=='verify-index':result=verify_index(a.dataset,a.out)
        elif a.command=='smoke':result=smoke(a.dataset,a.manifest,a.out,a.run_id,a.backend)
        else:
            result=compare(a.run_a,a.run_b,a.manifest,a.truth);export(result,a.out)
        print(canonical({k:v for k,v in result.items() if k in ['dataset_id','freeze_id','counts','fallback','quarantine','run_id','run_kind','query_jaccard','evidence_jaccard','claim_exact_jaccard','assessment_status','snapshot_sha256']}))
    except (ValueError,KeyError,TypeError,OSError,ImportError) as exc:
        p.exit(2,f'error: {exc}\n')
