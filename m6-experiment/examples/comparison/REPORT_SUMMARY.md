# M6 experiment summary

## Executive summary
The evaluation compares two typed-tool integration smoke runs with distinct run IDs and the same declared
frozen dataset and configuration. Query Jaccard is 1.0, retrieved
evidence Jaccard is 1.0, and exact claim Jaccard is
1.0. Verdict agreement is True.
These metrics require interpretation alongside coverage and factual-support review.

## Results
Run A: m6-v4-smoke-a (inconclusive). Run B: m6-v4-smoke-b (inconclusive).
See comparison.csv for per-run counts and differences.json for exact differences.
The current run kind is **typed_api_smoke**. A typed_api_smoke result does not measure LLM planning,
M5 verification, independent agent behavior or real collector continuity.

## Limitations
Source query windows and declared collection coverage do not establish real continuous
monitoring. Citation linkage and archived documents do not establish semantic support.
Exact statement matching detects wording differences, not semantic agreement. A single
synthetic sequence does not establish general security accuracy. Ledger truncation or
missing response archives can make comparisons incomplete. Reference hashes are integrity
checks, not cryptographic authenticity. Frozen run IDs alone cannot prove unchanged
external model settings or index state between checks.

## Conclusion
The artifacts permit a reviewer to compare queries and evidence and identify missing
or inconsistent records. Final conclusions about agent repeatability require actual
agent runs, independent setup verification and human review of every factual statement.
