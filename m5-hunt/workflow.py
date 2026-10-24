"""Orchestrate a TraceHunt investigation using the M4 typed tools."""

import json
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from coverage import CoverageChecklist
from evidence_verifier import EvidenceVerifier
from report import build_run_report, write_report
from state_machine import HuntPhase, HuntStateMachine
from datetime import datetime


SOURCE_INDICES = ("windows-security", "sysmon", "zeek")
HUNT_TOOLS = {
    "search_events",
    "aggregate_events",
    "run_sequence_query",
}
M4_LIMIT_FIELDS = (
    "indices",
    "default_size",
    "max_size",
    "max_window_hours",
    "request_timeout_s",
    "max_scan",
    "max_doc_ids",
    "max_seq_steps",
    "max_agg_buckets",
)


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []

    records = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSONL at {path}, line {line_number}"
            ) from exc
        if not isinstance(value, dict):
            raise ValueError(
                f"JSONL record at {path}, line {line_number} is not an object"
            )
        records.append(value)
    return records


def _append_jsonl(path: Path, value: dict) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n"
        )


def _actual_limits(config: Any) -> dict:
    limits = {}
    for name in M4_LIMIT_FIELDS:
        if not hasattr(config, name):
            raise ValueError(f"M4 configuration is missing {name}")
        limits[name] = getattr(config, name)

    limits["indices"] = list(limits["indices"])
    return limits


def _result_complete(tool_name: str, result: Any) -> bool:
    """Use the same basic completeness rules as the M6 result checker."""
    if not isinstance(result, Mapping):
        return False

    if tool_name == "search_events":
        return (
            result.get("total_relation") == "eq"
            and result.get("returned") == result.get("total_matches")
        )

    if tool_name == "aggregate_events":
        return result.get("truncated") is False

    if tool_name == "run_sequence_query":
        return result.get("complete") is True

    if tool_name == "fetch_evidence":
        return (
            result.get("found") == result.get("requested")
            and not result.get("missing_ids")
        )

    return "error" not in result


def _parse_timestamp(value):
    """Parse an ISO-8601 timestamp and require an explicit timezone."""
    if not isinstance(value, str) or not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None

    return parsed


def _find_timestamp_ranges(value):
    """Find @timestamp range clauses anywhere inside an Elasticsearch query."""
    found = []

    if isinstance(value, Mapping):
        range_clause = value.get("range")
        if isinstance(range_clause, Mapping):
            timestamp_clause = range_clause.get("@timestamp")
            if isinstance(timestamp_clause, Mapping):
                start = _parse_timestamp(timestamp_clause.get("gte"))
                end = _parse_timestamp(timestamp_clause.get("lt"))
                if start is not None and end is not None and end > start:
                    found.append((start, end))

        for child in value.values():
            found.extend(_find_timestamp_ranges(child))

    elif isinstance(value, list):
        for child in value:
            found.extend(_find_timestamp_ranges(child))

    return found


def _intervals_cover_window(intervals, required_start, required_end):
    """Return True only when intervals continuously cover the required window."""
    valid = [
        (start, end)
        for start, end in intervals
        if start < end
    ]
    valid.sort(key=lambda interval: interval[0])

    if not valid:
        return False

    covered_until = required_start

    for start, end in valid:
        if end <= covered_until:
            continue

        if start > covered_until:
            return False

        covered_until = max(covered_until, end)

        if covered_until >= required_end:
            return True

    return False


def _validate_investigation_coverage(
    ledger_records,
    responses,
    run_id,
    required_sources,
    investigation_window,
):
    """Validate actual successful, complete queries against required scope."""
    blockers = []

    if (
        not isinstance(required_sources, (list, tuple))
        or not required_sources
        or len(set(required_sources)) != len(required_sources)
        or any(source not in SOURCE_INDICES for source in required_sources)
    ):
        raise ValueError(
            "required_sources must be a non-empty list of unique supported indices"
        )

    required_start = _parse_timestamp(investigation_window.get("start"))
    required_end = _parse_timestamp(investigation_window.get("end"))

    if (
        required_start is None
        or required_end is None
        or required_end <= required_start
    ):
        raise ValueError(
            "investigation_window must contain valid timezone-aware start/end"
        )

    response_by_seq = {
        item.get("ledger_seq"): item
        for item in responses
        if isinstance(item, Mapping)
    }

    intervals_by_source = {source: [] for source in required_sources}
    query_counts = {source: 0 for source in required_sources}

    for row in ledger_records:
        if not isinstance(row, Mapping):
            continue
        if row.get("run_id") != run_id or row.get("status") != "ok":
            continue

        response = response_by_seq.get(row.get("seq"))
        if not isinstance(response, Mapping):
            continue

        tool_name = response.get("tool")
        if tool_name not in HUNT_TOOLS:
            continue

        result = response.get("result")
        if not isinstance(result, Mapping):
            continue
        if not _result_complete(tool_name, result):
            continue

        query = row.get("query")
        requests = []

        if isinstance(query, Mapping):
            request = query.get("request")
            if isinstance(request, Mapping):
                requests.append(request)

            sequence_requests = query.get("requests")
            if isinstance(sequence_requests, list):
                requests.extend(
                    item for item in sequence_requests
                    if isinstance(item, Mapping)
                )

        for request in requests:
            source = request.get("index")
            if source not in intervals_by_source:
                continue

            body = request.get("body")
            for start, end in _find_timestamp_ranges(body):
                clipped_start = max(start, required_start)
                clipped_end = min(end, required_end)

                if clipped_start < clipped_end:
                    intervals_by_source[source].append(
                        (clipped_start, clipped_end)
                    )
                    query_counts[source] += 1

    source_results = {}

    for source in required_sources:
        covered = _intervals_cover_window(
            intervals_by_source[source],
            required_start,
            required_end,
        )

        source_results[source] = {
            "covered": covered,
            "complete_query_count": query_counts[source],
        }

        if not covered:
            blockers.append(
                f"Actual investigation queries do not completely cover "
                f"the required window for source '{source}'"
            )

    return {
        "required_sources": list(required_sources),
        "required_window": dict(investigation_window),
        "complete": not blockers,
        "sources": source_results,
        "blockers": blockers,
    }


class HuntWorkflow:
    """Run a supplied investigation plan and export its evidence trail.

    The ToolSet must write its real M4 ledger to output_dir/ledger.jsonl.
    This class never renumbers records and never fabricates evidence.
    """

    def __init__(
        self,
        tools: Any,
        output_dir: str | Path,
        *,
        run_id: str,
        run_kind: str,
        backend: str,
        dataset_id: str,
        freeze_id: str,
        m4_limits: Mapping,
        source_coverage: Mapping,
        investigation_window: Mapping,
        model_usage: dict | None = None,
    ) -> None:
        self.output_dir = Path(output_dir).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.ledger_path = self.output_dir / "ledger.jsonl"
        self.responses_path = self.output_dir / "responses.jsonl"

        ledger = getattr(tools, "ledger", None)
        ledger_file = getattr(ledger, "path", None)
        if ledger_file is None or Path(ledger_file).resolve() != self.ledger_path:
            raise ValueError(
                "Configure M4's EvidenceLedger at output_dir/ledger.jsonl"
            )


        for name in ("responses.jsonl", "run.json", "report.md"):
            if (self.output_dir / name).exists():
                raise FileExistsError(
                    f"{name} already exists; choose a fresh output folder"
                )

        if not self.ledger_path.exists():
            self.ledger_path.touch(exist_ok=False)

        if _read_jsonl(self.ledger_path):
            raise ValueError(
                "Each hunt needs a fresh, empty M4 ledger and a unique output folder"
            )


        config = getattr(tools, "cfg", None)
        if config is None or getattr(config, "run_id", None) != run_id:
            raise ValueError("run_id must match the actual M4 configuration")

        actual_limits = _actual_limits(config)
        if dict(m4_limits) != actual_limits:
            supplied = dict(m4_limits)
            if "indices" in supplied:
                supplied["indices"] = list(supplied["indices"])
            if supplied != actual_limits:
                raise ValueError(
                    "m4_limits must match the effective M4 configuration"
                )

        self.tools = tools
        self.run_id = run_id
        self.metadata = {
            "run_id": run_id,
            "run_kind": run_kind,
            "backend": backend,
            "dataset_id": dataset_id,
            "freeze_id": freeze_id,
            "m4_limits": actual_limits,
            "model_usage": model_usage,
        }
        self.source_coverage = dict(source_coverage)
        self.investigation_window = dict(investigation_window)
        self.responses: list[dict] = []
        self.state = HuntStateMachine()

    def _call_tool(self, name: str, arguments: dict | None = None) -> tuple[Any, int]:
        """Call one M4 tool, then link its actual ledger row to its response."""
        if name not in {
            "list_data_sources",
            "get_time_bounds",
            *HUNT_TOOLS,
            "fetch_evidence",
            "get_query_history",
        }:
            raise ValueError(f"Unsupported M4 tool: {name}")

        args = dict(arguments or {})
        before = _read_jsonl(self.ledger_path)

        try:
            result = getattr(self.tools, name)(**args)
        except Exception as exc:
            # M4 records the failed call. Keep the archive useful without
            # copying arbitrary exception text into another output file.
            result = {
                "error": "tool_call_failed",
                "error_type": type(exc).__name__,
            }

        after = _read_jsonl(self.ledger_path)
        if len(after) != len(before) + 1 or after[:len(before)] != before:
            raise RuntimeError(
                f"M4 call {name} did not append exactly one ledger row; "
                "do not guess its sequence number"
            )

        row = after[-1]
        if row.get("tool") != name or row.get("run_id") != self.run_id:
            raise RuntimeError("New M4 ledger row has a mismatched tool or run ID")

        seq = row.get("seq")
        if type(seq) is not int or seq < 1:
            raise RuntimeError("M4 returned an invalid ledger sequence")

        response = {
            "ledger_seq": seq,
            "tool": name,
            "arguments": args,
            "result": result,
        }
        _append_jsonl(self.responses_path, response)
        self.responses.append(response)
        return result, seq

    @staticmethod
    def _validate_plan(plan: list[dict]) -> list[dict]:
        if not isinstance(plan, list) or not plan:
            raise ValueError("An investigation plan must contain at least one step")

        normalized = []
        ids = set()

        for item in plan:
            if not isinstance(item, Mapping):
                raise ValueError("Every plan step must be an object")

            item_id = item.get("id")
            index = item.get("index")
            question = item.get("question")
            tool = item.get("tool")
            arguments = item.get("arguments", {})

            if not isinstance(item_id, str) or not item_id.strip():
                raise ValueError("Each plan step needs a non-empty id")
            if item_id in ids:
                raise ValueError(f"Duplicate plan step id: {item_id}")
            ids.add(item_id)

            if index not in SOURCE_INDICES:
                raise ValueError(f"Unsupported source index in {item_id}: {index}")
            if not isinstance(question, str) or not question.strip():
                raise ValueError(f"Plan question {item_id} must not be empty")
            if tool not in HUNT_TOOLS:
                raise ValueError(
                    f"Plan step {item_id} must use a typed hunt tool"
                )
            if not isinstance(arguments, Mapping) or arguments.get("index") != index:
                raise ValueError(
                    f"Plan step {item_id} must pass its matching index in arguments"
                )

            normalized.append({
                "id": item_id.strip(),
                "index": index,
                "question": question.strip(),
                "tool": tool,
                "arguments": dict(arguments),
            })

        return normalized

    @staticmethod
    def _validate_claim_drafts(claim_drafts: list[dict]) -> list[dict]:
        if not isinstance(claim_drafts, list):
            raise ValueError("claim_drafts must be a list")

        normalized = []
        ids = set()

        for draft in claim_drafts:
            if not isinstance(draft, Mapping):
                raise ValueError("Every claim draft must be an object")

            claim_id = draft.get("id")
            statement = draft.get("statement")
            evidence = draft.get("evidence")

            if not isinstance(claim_id, str) or not claim_id.strip():
                raise ValueError("Every claim draft needs a non-empty id")
            if claim_id in ids:
                raise ValueError(f"Duplicate claim draft id: {claim_id}")
            ids.add(claim_id)

            if not isinstance(statement, str) or not statement.strip():
                raise ValueError(f"Claim {claim_id} needs a statement")
            if not isinstance(evidence, list) or not evidence:
                raise ValueError(
                    f"Claim {claim_id} needs evidence references"
                )

            refs = []
            for ref in evidence:
                if not isinstance(ref, Mapping):
                    raise ValueError(f"Invalid evidence reference in {claim_id}")

                index = ref.get("index")
                doc_id = ref.get("doc_id")
                if index not in SOURCE_INDICES:
                    raise ValueError(f"Invalid source in claim {claim_id}")
                if not isinstance(doc_id, str) or not doc_id:
                    raise ValueError(f"Invalid document ID in claim {claim_id}")

                pair = (index, doc_id)
                if pair not in refs:
                    refs.append(pair)

            normalized.append({
                "id": claim_id.strip(),
                "statement": statement.strip(),
                "evidence": refs,
            })

        return normalized

    def execute(
        self,
        plan: list[dict],
        claim_drafts: list[dict],
        *,
        required_sources: list[str],
        supporting_claim_ids: list[str],
        contradicting_claim_ids: list[str],
        alternatives_tested: bool,
    ) -> dict:
        """Execute queries, fetch cited documents, verify and export a report.

        Each step has id, index, question, tool and typed-tool arguments.
        Each claim draft has id, statement and evidence=[{index, doc_id}].
        Claim text and semantic labels must come from the actual investigation,
        not be generated from the presence of a search hit alone.
        """
        steps = self._validate_plan(plan)
        drafts = self._validate_claim_drafts(claim_drafts)
        began = time.monotonic()

        checklist = CoverageChecklist()
        for step in steps:
            checklist.add(step["id"], step["index"], step["question"])

        self.state.transition(HuntPhase.PLANNING, "Investigation plan accepted")

        # Discover which allowlisted data sources are available before querying.
        source_result, _ = self._call_tool("list_data_sources")
        available = set()
        if isinstance(source_result, Mapping):
            for source in source_result.get("sources", []):
                if (
                    isinstance(source, Mapping)
                    and source.get("available") is True
                    and source.get("index") in SOURCE_INDICES
                ):
                    available.add(source["index"])

        self.state.transition(
            HuntPhase.INVESTIGATING,
            "M4 data-source preflight recorded",
        )

        observed_refs: set[tuple[str, str]] = set()

        for step in steps:
            if step["index"] not in available:
                checklist.mark_incomplete(
                    step["id"],
                    "The planned data source was unavailable during preflight",
                )
                continue

            result, seq = self._call_tool(step["tool"], step["arguments"])
            complete = _result_complete(step["tool"], result)

            if complete:
                checklist.record_result(step["id"], seq, True)
            else:
                checklist.record_result(
                    step["id"],
                    seq,
                    False,
                    "The tool result was incomplete or truncated",
                )

            if not isinstance(result, Mapping):
                continue

            # Search hits are candidates, not verified evidence yet.
            for doc_id in result.get("doc_ids", []):
                if isinstance(doc_id, str) and doc_id:
                    observed_refs.add((step["index"], doc_id))

            # Sequence results expose document IDs inside each matched chain.
            for match in result.get("matches", []):
                if not isinstance(match, Mapping):
                    continue
                for event in match.get("sequence", []):
                    if isinstance(event, Mapping):
                        doc_id = event.get("doc_id")
                        if isinstance(doc_id, str) and doc_id:
                            observed_refs.add((step["index"], doc_id))

        self.state.transition(
            HuntPhase.VERIFYING,
            "Planned queries finished; collecting complete evidence documents",
        )

        # Do not fetch invented IDs. Only fetch IDs actually returned by a query.
        eligible_drafts = []
        invalid_draft = False
        requested_refs: list[tuple[str, str]] = []

        for draft in drafts:
            if not all(ref in observed_refs for ref in draft["evidence"]):
                invalid_draft = True
                continue

            eligible_drafts.append(draft)
            for ref in draft["evidence"]:
                if ref not in requested_refs:
                    requested_refs.append(ref)

        ids_by_index: dict[str, list[str]] = {}
        for index, doc_id in requested_refs:
            ids_by_index.setdefault(index, []).append(doc_id)

        fetched_refs: dict[tuple[str, str], int] = {}
        # M4 may retain at most 100 IDs in the ledger; chunk within both limits.
        batch_size = min(self.metadata["m4_limits"]["max_doc_ids"], 100)

        for index, doc_ids in ids_by_index.items():
            for offset in range(0, len(doc_ids), batch_size):
                batch = doc_ids[offset:offset + batch_size]
                result, fetch_seq = self._call_tool(
                    "fetch_evidence",
                    {"index": index, "doc_ids": batch},
                )
                if not isinstance(result, Mapping):
                    continue

                documents = result.get("documents", [])
                if not isinstance(documents, list):
                    continue

                for document in documents:
                    if not isinstance(document, Mapping):
                        continue
                    doc_id = document.get("_id")
                    if isinstance(doc_id, str) and (index, doc_id) in requested_refs:
                        fetched_refs[(index, doc_id)] = fetch_seq

        claims = []
        for draft in eligible_drafts:
            if not all(ref in fetched_refs for ref in draft["evidence"]):
                invalid_draft = True
                continue

            claims.append({
                "id": draft["id"],
                "statement": draft["statement"],
                "citations": [
                    {
                        "index": index,
                        "doc_id": doc_id,
                        "ledger_seq": fetched_refs[(index, doc_id)],
                    }
                    for index, doc_id in draft["evidence"]
                ],
            })

        plan_records = checklist.finalize()
        self.state.transition(
            HuntPhase.REPORTING,
            "Evidence provenance and report preconditions are being checked",
        )

        ledger_records = _read_jsonl(self.ledger_path)
        verifier = EvidenceVerifier(
            ledger_records,
            self.responses,
            expected_run_id=self.run_id,
        )

        investigation_coverage = _validate_investigation_coverage(
            ledger_records=ledger_records,
            responses=self.responses,
            run_id=self.run_id,
            required_sources=required_sources,
            investigation_window=self.investigation_window,
        )

        all_questions_complete = all(
            item["status"] == "complete" for item in plan_records
        )
        investigation_complete = (
            all_questions_complete
            and not invalid_draft
            and investigation_coverage["complete"]
        )

        report = build_run_report(
            **self.metadata,
            runtime_seconds=time.monotonic() - began,
            source_coverage=self.source_coverage,
            investigation_window=self.investigation_window,
            investigation_coverage=investigation_coverage,
            plan=plan_records,
            claims=claims,
            verifier=verifier,
            supporting_claim_ids=supporting_claim_ids,
            contradicting_claim_ids=contradicting_claim_ids,
            investigation_complete=investigation_complete,
            alternatives_tested=alternatives_tested,
        )

        if invalid_draft:
            report["verdict_reasons"].append(
                "One or more claim drafts referenced documents that were not "
                "observed in query results or not returned by fetch_evidence"
            )
            report["verdict"] = "inconclusive"

        final_state = self.state.finalize(report["verdict"])
        report["workflow"] = final_state

        write_report(self.output_dir, report)
        return report
