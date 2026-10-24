"""Build and render TraceHunt M6-compatible run reports."""

import json
import math
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any


SOURCE_INDICES = ("windows-security", "sysmon", "zeek")
VERDICTS = ("confirmed", "rejected", "inconclusive")
RUN_KINDS = ("agent", "typed_api_smoke")

M4_LIMIT_KEYS = {
    "indices",
    "default_size",
    "max_size",
    "max_window_hours",
    "request_timeout_s",
    "max_scan",
    "max_doc_ids",
    "max_seq_steps",
    "max_agg_buckets",
}


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def _timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a timezone-aware timestamp")

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} is not a valid ISO timestamp") from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")

    return parsed


def _positive_int(value: Any, name: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _validate_limits(limits: Any) -> dict:
    if not isinstance(limits, Mapping):
        raise ValueError("m4_limits must be an object")

    if set(limits) != M4_LIMIT_KEYS:
        raise ValueError(
            "m4_limits must contain exactly the behavioral limit "
            f"fields expected by M6: {sorted(M4_LIMIT_KEYS)}"
        )

    indices = limits["indices"]
    if not isinstance(indices, (list, tuple)):
        raise ValueError("m4_limits.indices must be a list")

    if (
        not indices
        or len(indices) != len(set(indices))
        or any(index not in SOURCE_INDICES for index in indices)
    ):
        raise ValueError("m4_limits.indices contains invalid or duplicate indices")

    result = dict(limits)
    result["indices"] = list(indices)

    integer_keys = (
        "default_size", "max_size", "max_scan",
        "max_doc_ids", "max_seq_steps", "max_agg_buckets",
    )
    for key in integer_keys:
        _positive_int(result[key], f"m4_limits.{key}")

    for key in ("max_window_hours", "request_timeout_s"):
        value = result[key]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ValueError(f"m4_limits.{key} must be a positive finite number")

    return result


def _validate_coverage(
    coverage: Any,
    required_window: Mapping[str, str],
) -> tuple[dict, list[str]]:
    if not isinstance(coverage, Mapping):
        raise ValueError("source_coverage must be an object")

    if set(coverage) != set(SOURCE_INDICES):
        raise ValueError(
            "source_coverage must describe all three configured sources"
        )

    if not isinstance(required_window, Mapping):
        raise ValueError("investigation_window must be an object")

    window_start = _timestamp(required_window.get("start"), "investigation_window.start")
    window_end = _timestamp(required_window.get("end"), "investigation_window.end")

    if window_end <= window_start:
        raise ValueError("investigation_window.end must be after start")

    normalized = {}
    blockers = []

    for index in SOURCE_INDICES:
        source = coverage[index]
        if not isinstance(source, Mapping):
            raise ValueError(f"Coverage for {index} must be an object")

        start = _timestamp(source.get("start"), f"{index}.start")
        end = _timestamp(source.get("end"), f"{index}.end")
        complete = source.get("complete")
        basis = _text(source.get("basis"), f"{index}.basis")

        if end <= start:
            raise ValueError(f"Coverage end must be after start for {index}")

        if type(complete) is not bool:
            raise ValueError(f"{index}.complete must be a boolean")

        normalized[index] = {
            "start": source["start"],
            "end": source["end"],
            "complete": complete,
            "basis": basis,
        }

        if not complete:
            blockers.append(f"Source coverage is incomplete for {index}")

        if start > window_start or end < window_end:
            blockers.append(
                f"Declared coverage for {index} does not span the investigation window"
            )

    return normalized, blockers


def _validate_plan(plan: Any) -> tuple[list[dict], list[str]]:
    if not isinstance(plan, list) or not plan:
        raise ValueError("plan must be a non-empty list")

    normalized = []
    blockers = []
    seen_ids = set()

    for item in plan:
        if not isinstance(item, Mapping):
            raise ValueError("Each plan item must be an object")

        item_id = _text(item.get("id"), "plan.id")
        index = item.get("index")
        status = item.get("status")
        seq = item.get("ledger_seq")

        if item_id in seen_ids:
            raise ValueError(f"Duplicate plan ID: {item_id}")
        seen_ids.add(item_id)

        if index not in SOURCE_INDICES:
            raise ValueError(f"Invalid plan source index: {index}")

        if status not in ("complete", "incomplete", "skipped"):
            raise ValueError(f"Invalid plan status for {item_id}")

        if seq is not None:
            _positive_int(seq, f"plan[{item_id}].ledger_seq")

        if status == "complete" and seq is None:
            raise ValueError(
                f"Completed plan item {item_id} needs a real ledger sequence"
            )

        if status != "complete":
            blockers.append(f"Plan item {item_id} is {status}")

        normalized.append({
            "id": item_id,
            "index": index,
            "status": status,
            "ledger_seq": seq,
        })

    return normalized, blockers


def _validate_claims(claims: Any) -> list[dict]:
    if not isinstance(claims, list):
        raise ValueError("claims must be a list")

    normalized = []
    seen_ids = set()

    for claim in claims:
        if not isinstance(claim, Mapping):
            raise ValueError("Each claim must be an object")

        claim_id = _text(claim.get("id"), "claim.id")
        statement = _text(claim.get("statement"), "claim.statement")
        citations = claim.get("citations")

        if claim_id in seen_ids:
            raise ValueError(f"Duplicate claim ID: {claim_id}")
        seen_ids.add(claim_id)

        if not isinstance(citations, list) or not citations:
            raise ValueError(f"Claim {claim_id} requires citations")

        checked_citations = []
        seen_refs = set()

        for citation in citations:
            if not isinstance(citation, Mapping):
                raise ValueError("Each citation must be an object")

            index = citation.get("index")
            doc_id = _text(citation.get("doc_id"), "citation.doc_id")
            seq = _positive_int(
                citation.get("ledger_seq"), "citation.ledger_seq"
            )

            if index not in SOURCE_INDICES:
                raise ValueError(f"Invalid citation source: {index}")

            ref = (seq, index, doc_id)
            if ref in seen_refs:
                raise ValueError(f"Duplicate citation in claim {claim_id}")
            seen_refs.add(ref)

            checked_citations.append({
                "index": index,
                "doc_id": doc_id,
                "ledger_seq": seq,
            })

        normalized.append({
            "id": claim_id,
            "statement": statement,
            "citations": checked_citations,
        })

    return normalized


def build_run_report(
    *,
    run_id: str,
    run_kind: str,
    backend: str,
    dataset_id: str,
    freeze_id: str,
    m4_limits: Mapping,
    runtime_seconds: float | None,
    model_usage: dict | None,
    source_coverage: Mapping,
    investigation_window: Mapping,
    plan: list[dict],
    claims: list[dict],
    verifier: Any,
    supporting_claim_ids: list[str],
    contradicting_claim_ids: list[str],
    investigation_complete: bool,
    alternatives_tested: bool,
) -> dict:
    """Build a v3 report using the actual evidence verifier.

    Dataset/freeze IDs, effective limits, coverage and evidence are supplied
    by the caller from the real execution. This function never invents them.
    """
    run_id = _text(run_id, "run_id")
    backend = _text(backend, "backend")
    dataset_id = _text(dataset_id, "dataset_id")
    freeze_id = _text(freeze_id, "freeze_id")

    if dataset_id.upper() == "REPLACE_ME" or freeze_id.upper() == "REPLACE_ME":
        raise ValueError("Real dataset_id and freeze_id must be supplied")

    if run_kind not in RUN_KINDS:
        raise ValueError(f"Unsupported run_kind: {run_kind}")

    limits = _validate_limits(m4_limits)

    if runtime_seconds is not None and (
        isinstance(runtime_seconds, bool)
        or not isinstance(runtime_seconds, (int, float))
        or not math.isfinite(runtime_seconds)
        or runtime_seconds < 0
    ):
        raise ValueError("runtime_seconds must be non-negative or None")

    from token_counter import normalize_model_usage
    normalized_usage = normalize_model_usage(model_usage)

    coverage, coverage_blockers = _validate_coverage(
        source_coverage, investigation_window
    )
    normalized_plan, plan_blockers = _validate_plan(plan)
    normalized_claims = _validate_claims(claims)

    verification = verifier.select_verdict(
        normalized_claims,
        supporting_claim_ids,
        contradicting_claim_ids,
        investigation_complete=investigation_complete,
        alternatives_tested=alternatives_tested,
    )

    if verification.get("verdict") not in VERDICTS:
        raise ValueError("Evidence verifier returned an invalid verdict")

    validation = verification.get("validation")
    if not isinstance(validation, Mapping):
        raise ValueError("Evidence verifier did not return validation details")

    reasons = list(verification.get("reasons") or [])
    reasons.extend(coverage_blockers)
    reasons.extend(plan_blockers)

    if validation.get("ok") is not True:
        reasons.append("Evidence integrity or citation validation failed")

    tool_results_complete = validation.get("tool_results_complete") is True
    if not tool_results_complete:
        reasons.append("One or more tool results are incomplete")

    verdict = verification["verdict"]

    # Report-level preconditions may only make a verdict more conservative.
    if reasons:
        verdict = "inconclusive"

    if verdict == "inconclusive" and not reasons:
        reasons.append("There is not enough verified evidence to decide")

    return {
        "schema_version": 3,
        "run_id": run_id,
        "run_kind": run_kind,
        "backend": backend,
        "dataset_id": dataset_id,
        "freeze_id": freeze_id,
        "verdict": verdict,
        "m4_limits": limits,
        "runtime_seconds": runtime_seconds,
        "model_usage": normalized_usage,
        "source_coverage": coverage,
        "plan": normalized_plan,
        "claims": normalized_claims,
        "tool_results_complete": tool_results_complete,
        "verdict_reasons": list(dict.fromkeys(reasons)),
    }


def render_markdown(report: Mapping) -> str:
    """Render a human-readable report from the validated run structure."""
    lines = [
        "# TraceHunt Investigation Report",
        "",
        f"**Verdict:** {report['verdict']}",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Run kind: `{report['run_kind']}`",
        f"- Backend: `{report['backend']}`",
        f"- Dataset ID: `{report['dataset_id']}`",
        f"- Freeze ID: `{report['freeze_id']}`",
        f"- Tool results complete: `{report['tool_results_complete']}`",
        "",
        "## Source coverage",
        "",
        "| Source | Start | End | Complete | Basis |",
        "|---|---|---|---|---|",
    ]

    for index, item in report["source_coverage"].items():
        cells = [
            index, item["start"], item["end"],
            str(item["complete"]), item["basis"],
        ]
        lines.append("| " + " | ".join(
            value.replace("|", "\\|").replace("\n", " ")
            for value in cells
        ) + " |")

    lines.extend([
        "",
        "A declared time window does not by itself prove continuous log collection.",
        "",
        "## Investigation plan",
        "",
        "| ID | Source | Status | Ledger sequence |",
        "|---|---|---|---|",
    ])

    for item in report["plan"]:
        lines.append(
            f"| {item['id']} | {item['index']} | {item['status']} | "
            f"{item['ledger_seq'] if item['ledger_seq'] is not None else 'Not recorded'} |"
        )

    lines.extend(["", "## Evidence-backed claims", ""])

    if report["claims"]:
        for claim in report["claims"]:
            refs = ", ".join(
                f"{c['index']}:{c['doc_id']} (ledger {c['ledger_seq']})"
                for c in claim["citations"]
            )
            lines.append(f"- **{claim['id']}** — {claim['statement']}")
            lines.append(f"  - Evidence references: {refs}")
    else:
        lines.append("No factual claims were exported.")

    lines.extend(["", "## Verdict notes", ""])
    if report["verdict_reasons"]:
        lines.extend(f"- {reason}" for reason in report["verdict_reasons"])
    else:
        lines.append("The evidence verifier accepted the supplied decision preconditions.")

    lines.append("")
    return "\n".join(lines)


def write_report(output_dir: str | Path, report: Mapping) -> tuple[Path, Path]:
    """Write run.json and report.md without overwriting existing files."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)

    json_path = directory / "run.json"
    markdown_path = directory / "report.md"

    if json_path.exists() or markdown_path.exists():
        raise FileExistsError("run.json or report.md already exists")

    json_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(report), encoding="utf-8")

    return json_path, markdown_path
