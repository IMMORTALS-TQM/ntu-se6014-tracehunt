# V4 response to the Windows CI review

## Root cause and fix

The v3 source scanner serialized relative paths with `str(...)`, which uses native
backslashes on Windows. The canonical expected key was correctly written with `/`.

V4 changes the source-inventory serializer to:

```python
return {p.relative_to(repo).as_posix(): file_sha(p) for p in sorted(paths)}
```

The existing `test_secret_files_excluded_without_hiding_m5_token_code` still requires
exactly `m5-hunt/token_counter.py`. Its expected-key and credential checks were not
weakened. No platform-conditional assertion accepts alternate separators.

The same native-separator pattern also appeared in dataset manifest creation and
verification and the 101-document test inventory. Those keys now use as_posix() too.
File-content hashes, credential exclusions, source selection and behavioral limits
are otherwise unchanged.

## Added regression coverage

- A real nested filesystem inventory must contain exactly
  `m5-hunt/nested/token_counter.py`; nested `.env` and `credentials.json` stay excluded.
- A newly generated dataset must contain canonical nested keys such as
  `normalized/events.jsonl` and `schema/fallback_audit.json`, with no backslashes.
  Verification must accept the generated canonical inventory.

Both tests run through the existing four-job M6 CI workflow on the native filesystem.
No synthetic Linux check is described as a Windows execution.

## Validation and CI handoff

Local Linux/Python 3.12.14: **43 M6 tests and 130 M3 tests pass**. Default fresh smoke
runs retain 15 real M4 Python tool calls each, zero errors and overlaps 1.0.

The existing Ubuntu/Windows x Python 3.11/3.12 workflow is included unchanged. After
copying/committing v4, the maintainer should authorize and rerun that matrix. This delivery did not trigger or authorize remote jobs.
Upstream action_required/zero-job runs remain unexecuted, not failed tests or green CI.

## Integration

Replace M6, keep the CI workflow, re-freeze and use new output folders. Package version
is 4.0.0; wire schema stays 3. M1–M5 code is unchanged. No live service, remote branch,
PR merge, MCP transport or M5/LLM investigation was changed or run by this delivery.
