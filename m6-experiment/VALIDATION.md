# V4 validation record

Local environment: Linux, Python 3.12.14.

- M6: **43 tests passed** (the original 41 plus 2 canonical-path regressions).
- M3: **130 tests passed**.
- The original exact credential-exclusion/token_counter.py assertion is unchanged.
- Nested source and dataset inventory keys are required to use forward slashes.
- Fresh default fixture smoke runs: 15 actual M4 ToolSet calls each, zero errors,
  query/evidence/exact-claim overlap 1.0.
- Relevant source/config bytes and effective M4 limits still invalidate freezes on drift.
- M1–M5 source and the four-job M6 CI workflow are unchanged from the v3 delivery.

These are local Linux results. Ubuntu/Windows x Python 3.11/3.12 is configured in
.github/workflows/m6-tests.yml, but the hosted matrix was not rerun here. The maintainer
must commit this version and authorize/re-run the workflow. An action_required run with
zero jobs has not executed and is neither green CI nor a failed test execution.

The Windows failure reported in the review comes from the reviewer's GitHub Actions
logs. This delivery does not claim a local Windows reproduction or hosted Windows pass.
No live ELK/Kibana, MCP transport or M5/LLM investigation ran here.
