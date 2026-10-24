"""Shared validation, hashing and JSON helpers (standard library only)."""
import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SOURCES = ('windows-security', 'sysmon', 'zeek')
START = '2026-10-23T14:00:00+08:00'
END = '2026-10-23T14:30:00+08:00'

def siblings():
    for name in ('m3-schema', 'm4-mcp'):
        p = REPO / name
        if not p.is_dir():
            raise ValueError(f'place m6-experiment beside {name} in the project root')
        sys.path.insert(0, str(p))

def canonical(value):
    # Match the M4 ledger serialization, including escaped Unicode.
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)

def sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def unique(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f'duplicate JSON key: {k}')
        out[k] = v
    return out

def decode(s):
    return json.loads(s, object_pairs_hook=unique,
        parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f'nonfinite JSON: {x}')))

def read(path):
    return decode(Path(path).read_text(encoding='utf-8-sig'))

def rows(path):
    return [decode(s) for s in Path(path).read_text(encoding='utf-8-sig').splitlines() if s.strip()]

def write(path, value):
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + '\n', encoding='utf-8')

def write_rows(path, values):
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(''.join(canonical(v)+'\n' for v in values), encoding='utf-8')

def time_value(s):
    if not isinstance(s, str): raise ValueError('timestamp must be a string')
    d = datetime.fromisoformat(s.replace('Z', '+00:00'))
    if d.tzinfo is None: raise ValueError('timestamps require explicit timezone')
    return d.timestamp()

def iso(s):
    return datetime.fromtimestamp(time_value(s), timezone.utc).isoformat()

def new_directory(path):
    p = Path(path).resolve()
    if p.exists() and (not p.is_dir() or any(p.iterdir())):
        raise ValueError(f'output directory must be empty: {p}')
    p.mkdir(parents=True, exist_ok=True)
    return p

def field(doc, path):
    for part in path.split('.'):
        if not isinstance(doc, dict): return None
        doc = doc.get(part)
    return doc

def rate(n, d):
    return n / d if d else None

def jaccard(a, b):
    return rate(len(a & b), len(a | b))

def payload_hash(value, key):
    return sha({k:v for k,v in value.items() if k != key})
