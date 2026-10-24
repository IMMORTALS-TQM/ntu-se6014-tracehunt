# Proposed M5 → M6 run export, version 3

This is a NEW integration contract. The supplied M5 directory is empty. Do not assume
M5 already exports it. M6 does not replace the hunt state machine or decide its verdict.

Each run directory contains:

- `run.json`: final structured report below.
- `ledger.jsonl`: unmodified M4 EvidenceLedger from that one run.
- `responses.jsonl`: ordered `{ledger_seq, tool, arguments, result}` entries containing
  actual M4 return values, including complete fetch_evidence documents.
- Original report text, prompt/configuration records, coverage/collection records and plan.
- Independent before/after index verification receipts for live runs.

Set unique TRACEHUNT_RUN_ID and TRACEHUNT_LEDGER_PATH before each M4 server starts.
Use clean sessions and independent output folders. Copy ledger sequence numbers from actual
M4 records, never infer a citation number from the order of model messages. get_query_history
also logs a call. For concurrent calls, serialize collection or correlate actual records;
a `last-row` assumption is only valid for M6's sequential smoke protocol.

Example FORMAT ONLY, intentionally no fake evidence IDs:

```json
{
  "schema_version": 3,
  "run_id": "agent-a",
  "run_kind": "agent",
  "backend": "elasticsearch",
  "dataset_id": "REPLACE_ME",
  "freeze_id": "REPLACE_ME",
  "verdict": "inconclusive",
  "m4_limits": {},
  "runtime_seconds": null,
  "model_usage": null,
  "source_coverage": {},
  "plan": [],
  "claims": []
}
```

- verdict: confirmed, rejected or inconclusive, selected by M5's evidence verifier.
- model_usage: null if unavailable, otherwise nonnegative integer counters such as
  input_tokens and output_tokens. Do not use zero for missing values.
- plan: list of `{id, index, status, ledger_seq}`. Status: complete/incomplete/skipped.
  Every planned question should have a final status. Completion alone does not prove
  the investigation tested alternative explanations.
- source_coverage: source keys windows-security/sysmon/zeek with
  `{start, end, complete, basis}`. Include timezone. Preserve missing coverage as missing
  or complete=false. Retain independent records supporting a real collector's continuity.
- claims: every factual statement in the final report, each with stable `id`, `statement`
  and a `citations` list of `{index, doc_id, ledger_seq}`.
- References must point to successful fetch_evidence ledger entries and actual returned
  documents. A search match alone is insufficient for archived citation completeness.

For each actual M4 return, append a response record:

```json
{
  "ledger_seq": 12,
  "tool": "fetch_evidence",
  "arguments": {"index": "sysmon", "doc_ids": ["actual-M3-document-ID"]},
  "result": {"index": "sysmon", "requested": 1, "found": 1, "missing_ids": [], "documents": []}
}
```

The example's empty documents is a placeholder, NOT valid support for a citation.
Store the full returned list unchanged. Match its IDs and index to the ledger.

M6 can compare incomplete exports and flag missing linkage/archives, but malformed
identities, contradictory fetch IDs, duplicate sequences or changed query hashes fail.
Reference hashes detect accidental changes, not malicious coordinated rewriting.
Human review must check statement meaning, coverage truth and report completeness.

Do not supply the private manifest to M5 or the model. The public deterministic fixture
is for engineering checks. Use unseen independently prepared scenarios for a blind benchmark.

## V3 effective limits and truncation

The empty m4_limits object above is a placeholder, not a valid v3 run. Record
`effective_m4_limits(actual_m4_config)` from M6 freeze.py and verify that it equals
the freeze's m4_limits before tool execution. Never export the full Config object
because it contains connection/authentication fields. Changes to environment-driven
M4 limits require new frozen conditions.

V3 sequences retain ordered requests as one query signature. Labels do not affect
equivalence. For legitimate M4 ledger truncation, archive the full fetch result.
Only retained IDs establish direct ledger linkage; full archive coverage is a separate
metric. V3 validates the retained prefix and all archive IDs against the fetch request.
Aggregate and sequence incompleteness must propagate to tool_results_complete.
