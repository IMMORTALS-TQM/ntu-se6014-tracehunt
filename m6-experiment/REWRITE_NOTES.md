# V4 migration notes

V4 fixes the platform-native path separator in source inventory keys using as_posix().
The same normalization applies to generated/verified dataset inventory keys and the
101-document regression's inventory. Credential filtering and exact expected keys remain.

Replace the full M6 directory, retain/copy the existing M6 workflow, and create new
freezes against the actual checkout. Package version is 4.0.0; run/freeze/comparison
schema remains 3. Existing frozen source hashes naturally differ after this update.
Do not edit old freeze IDs or turn Windows backslashes into accepted alternatives.

File content hashing remains byte-exact; canonical path keys do not guarantee identical
content hashes if checkout settings or line endings change actual file bytes.

The dataset is unchanged on Linux. Existing ground truth is reusable only when its
dataset_id matches. Real collector validation and agent investigations remain separate.
See REVIEW_FIXES_V4.md for the requested Windows fix and CI status.
