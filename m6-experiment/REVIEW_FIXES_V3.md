# V3 response to the v2 correctness review

The review identified reproducible correctness defects in the shipped M6 tooling.
This release addresses them without implementing M5 or editing member-owned M1–M5 code.

| Review item | V3 change | Regression |
|---|---|---|
| Missing pipeline and role config | Inventory includes `.conf` and non-secret JSON, including actual Logstash output and M4 role | Mutate the actual copied Logstash config and role; original freeze rejects both |
| Missing M5 | Inventory includes non-secret M5 files, additions and changes | Add a new harmless Python file, then separately change an existing one; both reject old freeze |
| Runtime limits unbound | Freeze/run records include an explicit effective M4 behavioral allowlist; execution rechecks it | Change each limit/allowlist; verify-freeze rejects. MAX_SCAN=1 prevents a second old-freeze smoke before output creation |
| Incorrect completeness summary | Shared completeness policy for search, fetch, aggregation and sequence | Under newly frozen low scan/bucket limits, run summaries are incomplete and identify calls 14/13 |
| Sequence order lost | One ordered request vector per sequence; only descriptive step labels disappear | Real M4 failure/success gives one match, reversed order zero; query Jaccard is 0. Rename-only is 1 |
| Legitimate 101-ID truncation rejected | Validate retained prefix, full archive request/IDs/counts, and report ledger/archive coverage separately | 101 distinct real-M3 docs, actual M4 max_doc_ids=101: ledger retains 100, archive 101, evaluation succeeds |
| Contradictory IDs | Keep rejection for mismatched prefixes, extra nontruncated IDs or impossible counts | Both truncated retained-ID contradiction and nontruncated extra-ID tests reject |
| Keyword substring/case behavior | Exact, case-sensitive unnormalized keyword match from M1 mapping; unsupported phrase mappings fail | Actual M4 typed-match exact positives plus partial-value/case negatives on host, user and event code |
| CI did not run M6 | New `.github/workflows/m6-tests.yml` explicitly discovers M6 tests, plus M3 compatibility | Four configured Ubuntu/Windows and Python 3.11/3.12 jobs; remote execution pending authorization |

## Validation performed locally

Python 3.12.14, Linux:

```bash
python -m unittest discover -s m6-experiment/tests -v
python -m unittest discover -s m3-schema/tests -v
```

Results: **41 M6 tests passed**, **130 M3 tests passed**.
Default two-run smoke: 15 tool calls per run, zero errors, query/evidence/exact-claim
Jaccard 1.0. These remain typed-API fixture checks, not M5/LLM experiments.

## Migration and integration

1. Replace the entire M6 folder, including updated tests/docs/examples.
2. Copy `.github/workflows/m6-tests.yml` into the reviewed repository's workflow folder.
3. Re-freeze against that checkout. V3 manifest/run schema is 3; v2 exports must be rerun.
4. M5 should record `m4_limits` from its actual verified Config using the explicit helper.
5. Ground truth and hunt dataset are unchanged; reuse only when dataset_id matches.
6. Have the maintainer authorize upstream workflow execution. Do not describe an
   `action_required` run or configured matrix as passed hosted CI.

The archive does not push, merge, authorize workflows or change a live ELK service.
Live ELK/Kibana, MCP transport and independent agent investigations remain separate gates.
