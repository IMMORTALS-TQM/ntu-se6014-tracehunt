# M6 — Experiment and Evaluation (v4)

V4 fixes the Windows path-key failure reported in the v3 CI review. It retains the earlier correctness fixes. It generates M2-shaped fixtures,
uses the supplied M3 parser and actual M4 Python tools, freezes experiment conditions,
and compares query, evidence and report exports. It does not implement M5.

## V4 portability change

Source-inventory keys now use `p.relative_to(repo).as_posix()`. Dataset inventory
creation/verification and the 101-document test fixture use the same canonical separator.
The exact credential-exclusion and `m5-hunt/token_counter.py` assertions are unchanged.
Two new tests assert nested canonical keys on the native filesystem, including Windows CI.
This normalizes path representation only; file bytes remain hashed as-is.

Package version is 4.0.0. The freeze/run/comparison wire format remains schema 3.
Re-freeze after updating source files. V4 does not claim an executed Windows matrix.

## Install into the team repository

1. Back up old experiment records and replace the **entire** `m6-experiment` code folder.
2. Also copy `.github/workflows/m6-tests.yml` from this archive into the repository.
3. Keep M1–M5 unchanged. Place M6 beside those folders at the project root.
4. Use Python **3.11+**. Run every command below from the project root.

Offline tests need no pip installation. Live checks require the dependencies and
connection settings described by M1/M4.

**Create new freezes and run directories. V2 freeze/run files are not accepted by v3.**
The generated dataset is unchanged, so an existing ground truth remains valid only
if its `dataset_id` matches. Never supply private ground truth to M5 or the model.

## Check installation

```bash
python --version
python m6-experiment/experiment.py check-data --dataset m6-experiment/fixtures
python -m unittest discover -s m6-experiment/tests -v
```

Expected local result: **43 M6 tests pass**. They include actual-M3/M4 regressions for
sequence order, keyword matching, a 101-document fetch, freeze changes and completeness.

## Run the offline workflow

Use unused output paths. The first command freezes the effective M4 environment as
well as source/configuration files, data and protocol assets.

```bash
python m6-experiment/experiment.py freeze --dataset m6-experiment/fixtures --config m6-experiment/smoke-config.json --asset m6-experiment/SMOKE_PROTOCOL.md --out evidence/m6-v4-freeze.json
python m6-experiment/experiment.py verify-freeze --dataset m6-experiment/fixtures --manifest evidence/m6-v4-freeze.json --config m6-experiment/smoke-config.json --asset m6-experiment/SMOKE_PROTOCOL.md
python m6-experiment/experiment.py smoke --dataset m6-experiment/fixtures --manifest evidence/m6-v4-freeze.json --run-id v4-a --out evidence/m6-v4-a
python m6-experiment/experiment.py smoke --dataset m6-experiment/fixtures --manifest evidence/m6-v4-freeze.json --run-id v4-b --out evidence/m6-v4-b
python m6-experiment/experiment.py compare --run-a evidence/m6-v4-a --run-b evidence/m6-v4-b --manifest evidence/m6-v4-freeze.json --out evidence/m6-v4-comparison
```

Open `evidence/m6-v4-comparison/comparison.html` in a browser. The directory also contains
CSV, Markdown, full comparison JSON, exact differences and `REPORT_SUMMARY.md`.

With default M4 limits, each run makes **15 actual M4 ToolSet calls** with zero errors.
Identical smoke runs have query/evidence/exact-claim Jaccard values of 1.0. The backend
is a strict local fixture, not Elasticsearch. No LLM, M5 verifier or MCP stdio transport
runs here. The smoke verdict is deliberately `inconclusive`.

If an effective M4 limit changes after freezing, both `verify-freeze` and `smoke` reject
the old conditions. To intentionally test a different limit, set it first and create
a new freeze. A low scan or aggregation limit may then produce a valid but incomplete
run, with `tool_results_complete=false` and explicit incomplete sequence numbers.

## Generate data and keep the answer private

The package includes 20 M3-normalized hunt events: Windows 12, Sysmon 4 and Zeek 4.
The half-open scenario interval is 23 October 2026, 14:00–14:30 Singapore (+08:00).
Unknown-format/reuse tests and two quarantined bad records remain separate.

```bash
python m6-experiment/experiment.py prepare --out lab/m6-v4-data --private ../m6-private-v3
```

Both destinations must be empty and non-nested. The public output includes raw records,
M3 accepted results, true M3 IDs, bulk create payload, schema audit, custom registry and
hashed dataset manifest. The private output contains `ground_truth.json`. Keep it outside
the repository and hunt agent context. Evaluate it only after both reports are final.
The fixtures simulate logs and never execute login attempts, PowerShell or HTTP requests.

## Frozen conditions retained from v3

- Dataset file inventory and hashes.
- Relevant M1–M4 source/config files, including `pipeline/logstash.conf` and
  `m4-mcp/es/readonly_role.json`.
- Non-secret files in M5, including additions/deletions, without implementing M5.
- M6 code/tests/config/protocol and its CI workflow.
- Model experiment metadata and supplied protocol/prompt assets.
- Effective M4 allowlist, default/max result size, window/timeout limits, sequence scan
  and step limits, fetch limit and aggregation limit.

Only the explicit behavioral allowlist is serialized from M4 Config. Passwords,
authentication values, run IDs, ledger paths and connection credentials are excluded.
Generated output/cache/dependency directories and known credential files are excluded
from source scanning. See `freeze.py` for the exact inventory policy.

## Comparison rules

- Sequence queries contribute **one ordered signature**. Step labels are descriptive
  and ignored. Reversing step order changes the signature and appears in query differences.
- Other hunt searches use conservative JSON normalization and preserve execution limits.
- Evidence IDs remain index-qualified. Evidence overlap uses IDs retained by the ledger;
  truncation is explicit rather than silently treating the retained set as complete.
- For a truncated fetch, retained IDs must match the archived prefix and full archived
  IDs must agree with the request and counts. Archive-only IDs do not become ledger-linked
  citations. `citation_linkage` and `archived_citation_coverage` remain separate.
- Keyword `match_phrase` follows M1's exact, case-sensitive, unnormalized mapping.
  Unsupported analyzers and non-keyword phrase matching fail explicitly. The smoke
  protocol selects PowerShell by exact process name and leaves command-line inspection
  to the archived evidence; it does not invent substring analysis for wildcard fields.
- Aggregate/sequence truncation affects both the run summary and comparison flags.
- Human review still checks statement meaning and collection continuity. Hashes are
  integrity checks, not proof of authenticity or real-time index immutability.

Comparisons validate each run's recorded effective M4 limits against the freeze. They
can be performed on another machine without requiring that machine's current environment
to equal the historical run configuration. Execution-time freeze verification does check it.

## M5 and live integration

Read **M5_CONTRACT.md** before implementing the report export. V3 requires `run.json`
with `schema_version=3` and `m4_limits` copied from the verified effective execution Config,
plus the original M4 ledger and complete tool responses.

Fill `agent-config.example.json` with actual model/prompt/schema/snapshot settings,
freeze the actual prompt and start two clean agent sessions. Do not use smoke results
as agent repeatability evidence. Add `--truth PATH/ground_truth.json` to `compare` only
when the private manifest belongs to the same dataset.

For live checks, M1 imports `fixtures/normalized/bulk.ndjson` into isolated indices and
checks every item. M6 does not delete or rebuild shared indices. Configure M4's existing
connection variables, then use `verify-index` or `smoke --backend elasticsearch`.

```bash
python m6-experiment/experiment.py verify-index --dataset m6-experiment/fixtures --out evidence/m6-index-check.json
python m6-experiment/experiment.py kibana --dataset m6-experiment/fixtures --out evidence/m6-kibana
```

Follow the generated Kibana IMPORT.md. Live import/rendering, ELK collection continuity,
MCP transport and independent agent investigations remain separate team checks.

## CI and troubleshooting

The new **M6 experiment checks** workflow runs the M6 suite and M3 compatibility tests
on Ubuntu/Windows with Python 3.11/3.12. Copy the workflow file as well as M6.
GitHub may require maintainer workflow authorization before upstream jobs can start.
An `action_required` run is not a completed or failed test run. Remote CI has not been
executed as part of this delivery.

- Output exists: choose a new path; preserve old evidence.
- Freeze differs: identify the changed files/limits and intentionally re-freeze.
- Old schema error: regenerate with v3; do not relabel v2 exports.
- Unsupported fixture query: use a supported mapped query or the live backend.
- Dataset/ground-truth mismatch: use the manifest for the exact dataset ID.

See **REVIEW_FIXES_V4.md** for this Windows fix and **REVIEW_FIXES_V3.md** for the earlier review fixes.
