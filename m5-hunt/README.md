# M5: Evidence-Driven Hunt Workflow



## Purpose



M5 implements the TraceHunt investigation workflow, evidence provenance verification, conservative verdict selection, and M6-compatible report export.



The current implementation is a Python workflow API. It is **not yet a standalone autonomous LLM agent or command-line application**. An external caller supplies the investigation plan, claim drafts, evidence interpretation labels, and alternative-explanation assessment. M5 executes the plan through the M4 tools, fetches and validates cited documents, checks investigation coverage, and exports the resulting evidence trail and verdict.



## Components



- `workflow.py`: Orchestrates M4 tool calls, query coverage validation, evidence retrieval, verification, and export.

- `coverage.py`: Tracks planned investigation questions and their completion status.

- `evidence_verifier.py`: Validates evidence provenance and selects a conservative verdict.

- `report.py`: Builds and writes `run.json` and `report.md`.

- `state_machine.py`: Enforces the hunt lifecycle.

- `token_counter.py`: Provides token-usage support.

- `test_*.py`: Unit and regression tests.



## Requirements



- Python 3.10 or newer.

- The M4 MCP implementation and its Python dependencies.

- An M4 tool client exposing the typed tools used by the workflow.

- A separate, fresh output directory for each hunt run.



Run the M5 unit tests from the repository root:



```bash

python -B -m unittest discover -s m5-hunt -p 'test_*.py' -v

```



## Integration contract



Create the M4 tool client using the actual M4 configuration and ledger implementation. The M4 `EvidenceLedger` must write to:



`<output_dir>/ledger.jsonl`



The M4 configuration's run ID must match the `run_id` passed to `HuntWorkflow`. The supplied `m4_limits` must match the effective M4 configuration.



Before executing a hunt, the caller must supply:



- `run_id`, `run_kind`, `backend`, `dataset_id`, and `freeze_id`.

- Effective `m4_limits`.

- `source_coverage`: collection-level coverage records.

- `investigation_window`: timezone-aware `start` and `end` timestamps.

- `plan`: at least one planned query step.

- `claim_drafts`: evidence-backed factual statements to verify.

- `required_sources`: the indices that must be queried for this hypothesis.

- `supporting_claim_ids` and `contradicting_claim_ids`: the caller's evidence interpretation.

- `alternatives_tested`: whether alternative explanations were actually investigated.



Supported source indices are `windows-security`, `sysmon`, and `zeek`. Choose `required_sources` according to the hypothesis; not every hypothesis necessarily requires all three sources.



## Plan and claim formats



Each plan step contains:



- `id`: unique step identifier.

- `index`: a supported source index.

- `question`: the investigation question.

- `tool`: `search_events`, `aggregate_events`, or `run_sequence_query`.

- `arguments`: the typed arguments for the selected M4 tool, including the matching `index`.



Each claim draft contains:



- `id`: unique claim identifier.

- `statement`: the factual statement to verify.

- `evidence`: a non-empty list of `{ "index": "...", "doc_id": "..." }` references.



Claim references must identify documents actually returned by an executed query. M5 fetches those documents through `fetch_evidence` and only exports citations linked to the actual M4 ledger sequence and returned documents.



The caller must base claim statements and supporting/contradicting labels on investigation findings, not merely on the presence of a search hit. Alternative explanations must be assessed using actual investigation evidence. Setting `alternatives_tested` to `true` is an input assertion, not an independent proof that alternatives were tested.



## Collection coverage versus investigation coverage



These are separate checks:



- **Collection coverage** (`source_coverage`) describes whether the underlying data collection covered the requested source and time range.

- **Investigation query coverage** checks the actual successful, complete M4 hunt queries against `required_sources` and `investigation_window`.



For each required source, actual query intervals must continuously cover the full investigation window. Missing sources, gaps, insufficient intervals, failed queries, or incomplete query results prevent the investigation from being considered complete and therefore prevent a conclusive verdict.



Query coverage is a scope check. It does not independently establish that the hypothesis is true or false, that every relevant event was collected, or that the caller's semantic interpretation is correct.



## Outputs and run isolation



A successful run writes the following files to its output directory:



- `ledger.jsonl`: the actual M4 evidence ledger for this run.

- `responses.jsonl`: archived M4 tool responses linked to their actual ledger sequence numbers.

- `run.json`: structured run report for downstream evaluation.

- `report.md`: human-readable report.



Each run needs a fresh, empty ledger and a unique output directory. Existing response archives or report outputs are rejected rather than overwritten. Do not manually renumber ledger sequences or fabricate evidence references.



## Verdicts



The evidence verifier supports three verdicts:



- `confirmed`: verified supporting evidence with the required preconditions satisfied and no unresolved support/refutation conflict.

- `rejected`: verified contradicting evidence with the required preconditions satisfied and no unresolved conflict.

- `inconclusive`: evidence is insufficient, invalid, incomplete, contradictory, or the required investigation checks are not satisfied.



Mixed supporting and contradicting verified claims result in `inconclusive` unless the conflict is resolved by a separately justified investigation process. Do not treat missing or truncated results as proof of absence.



## M6 integration



The exported `run.json`, ledger, and response archive are intended to support M6's run comparison and evidence-linkage checks. The M6 evaluator can check structural consistency and provenance, but cannot independently establish the semantic truth of a claim or the truth of collection-coverage assertions.



The current workflow API and unit tests establish the workflow and export contract. A live investigation using the actual M4 MCP client, a real dataset, and an externally supplied investigation plan remains a separate integration validation step. Do not supply M6's private ground-truth manifest to the agent.



## Known limitations



- No standalone CLI or autonomous LLM investigation loop is currently provided.

- The caller is responsible for producing the investigation plan and claim drafts and for honestly assessing alternative explanations.

- Coverage validation checks query scope and result completeness; it does not prove that the query logic is semantically sufficient for a hypothesis.

- A passing unit suite is not a substitute for an end-to-end live M4/M5/M6 integration test.
