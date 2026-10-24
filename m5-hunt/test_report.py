"""Tests for the M6-compatible report builder."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from evidence_verifier import EvidenceVerifier
from report import build_run_report, render_markdown, write_report


def _hash(query):
    raw = json.dumps(query, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def _fixture():
    index = "sysmon"
    doc_id = "doc-1"
    query = {
        "request": {
            "op": "mget",
            "index": index,
            "body": {"ids": [doc_id]},
        }
    }
    ledger = {
        "seq": 1,
        "run_id": "test-run",
        "tool": "fetch_evidence",
        "status": "ok",
        "query": query,
        "query_hash": _hash(query),
        "result_count": 1,
        "doc_ids": [doc_id],
        "doc_ids_truncated": False,
    }
    response = {
        "ledger_seq": 1,
        "tool": "fetch_evidence",
        "arguments": {"index": index, "doc_ids": [doc_id]},
        "result": {
            "index": index,
            "requested": 1,
            "found": 1,
            "missing_ids": [],
            "documents": [{"_id": doc_id, "@timestamp": "2026-10-23T14:10:00+08:00"}],
        },
    }
    verifier = EvidenceVerifier([ledger], [response], expected_run_id="test-run")
    claim = {
        "id": "claim-1",
        "statement": "A process event was retrieved.",
        "citations": [{"index": index, "doc_id": doc_id, "ledger_seq": 1}],
    }
    limits = {
        "indices": ["windows-security", "sysmon", "zeek"],
        "default_size": 50,
        "max_size": 100,
        "max_window_hours": 24,
        "request_timeout_s": 10,
        "max_scan": 1000,
        "max_doc_ids": 100,
        "max_seq_steps": 5,
        "max_agg_buckets": 100,
    }
    window = {
        "start": "2026-10-23T14:00:00+08:00",
        "end": "2026-10-23T14:30:00+08:00",
    }
    coverage = {
        source: {
            **window,
            "complete": True,
            "basis": "Test fixture coverage record",
        }
        for source in ("windows-security", "sysmon", "zeek")
    }
    plan = [{
        "id": "process-check",
        "index": "sysmon",
        "status": "complete",
        "ledger_seq": 1,
    }]
    return verifier, claim, limits, window, coverage, plan


def _build(**overrides):
    verifier, claim, limits, window, coverage, plan = _fixture()
    args = {
        "run_id": "test-run",
        "run_kind": "agent",
        "backend": "fixture",
        "dataset_id": "test-dataset",
        "freeze_id": "test-freeze",
        "m4_limits": limits,
        "runtime_seconds": 1.5,
        "model_usage": {"prompt_tokens": 10, "completion_tokens": 5},
        "source_coverage": coverage,
                "investigation_coverage": {
            "required_sources": ["sysmon"],
            "required_window": window,
            "complete": True,
            "sources": {
                "sysmon": {
                    "covered": True,
                    "complete_query_count": 1,
                }
            },
            "blockers": [],
        },
        "investigation_window": window,
        "plan": plan,
        "claims": [claim],
        "verifier": verifier,
        "supporting_claim_ids": ["claim-1"],
        "contradicting_claim_ids": [],
        "investigation_complete": True,
        "alternatives_tested": True,
    }
    args.update(overrides)
    return build_run_report(**args)


class TestReport(unittest.TestCase):
    def test_builds_v3_report(self):
        report = _build()
        self.assertEqual(report["schema_version"], 3)
        self.assertEqual(report["verdict"], "confirmed")
        self.assertEqual(report["model_usage"]["input_tokens"], 10)
        self.assertEqual(report["model_usage"]["output_tokens"], 5)

    def test_incomplete_required_source_forces_inconclusive(self):
        _, _, _, _, coverage, _ = _fixture()
        coverage["sysmon"]["complete"] = False

        report = _build(source_coverage=coverage)

        self.assertEqual(report["verdict"], "inconclusive")

    def test_uncovered_required_window_forces_inconclusive(self):
        _, _, _, _, coverage, _ = _fixture()
        coverage["sysmon"]["end"] = "2026-10-23T14:20:00+08:00"

        report = _build(source_coverage=coverage)

        self.assertEqual(report["verdict"], "inconclusive")

    def test_incomplete_optional_source_does_not_block_verdict(self):
        _, _, _, _, coverage, _ = _fixture()
        coverage["zeek"]["complete"] = False

        report = _build(source_coverage=coverage)

        self.assertEqual(report["verdict"], "confirmed")

    def test_missing_required_source_coverage_forces_inconclusive(self):
        _, _, _, _, coverage, _ = _fixture()
        coverage.pop("sysmon")

        report = _build(source_coverage=coverage)

        self.assertEqual(report["verdict"], "inconclusive")
        markdown = render_markdown(report)
        self.assertIn(
            "Missing source coverage for required source sysmon",
            markdown,
        )

    def test_sysmon_only_coverage_is_accepted(self):
        _, _, limits, _, coverage, _ = _fixture()
        limits["indices"] = ["sysmon"]

        report = _build(
            m4_limits=limits,
            source_coverage={"sysmon": coverage["sysmon"]},
        )

        self.assertEqual(report["verdict"], "confirmed")
        self.assertEqual(list(report["source_coverage"]), ["sysmon"])

    def test_incomplete_plan_forces_inconclusive(self):
        _, _, _, _, _, plan = _fixture()
        plan[0]["status"] = "incomplete"
        plan[0]["ledger_seq"] = None
        report = _build(plan=plan)
        self.assertEqual(report["verdict"], "inconclusive")

    def test_placeholder_freeze_id_is_rejected(self):
        with self.assertRaises(ValueError):
            _build(freeze_id="REPLACE_ME")

    def test_unknown_source_coverage_is_rejected(self):
        _, _, _, _, coverage, _ = _fixture()
        coverage["unknown"] = coverage["zeek"]
        with self.assertRaises(ValueError):
            _build(source_coverage=coverage)

    def test_naive_timestamp_is_rejected(self):
        _, _, _, _, coverage, _ = _fixture()
        coverage["sysmon"]["start"] = "2026-10-23T14:00:00"
        with self.assertRaises(ValueError):
            _build(source_coverage=coverage)

    def test_missing_m4_limit_fields_are_rejected(self):
        with self.assertRaises(ValueError):
            _build(m4_limits={"indices": ["sysmon"]})

    def test_negative_runtime_is_rejected(self):
        with self.assertRaises(ValueError):
            _build(runtime_seconds=-1)

    def test_missing_claim_citation_is_rejected(self):
        _, claim, _, _, _, _ = _fixture()
        claim["citations"] = []
        with self.assertRaises(ValueError):
            _build(claims=[claim])

    def test_markdown_contains_verdict_and_citation(self):
        report = _build()
        markdown = render_markdown(report)
        self.assertIn("**Verdict:** confirmed", markdown)
        self.assertIn("sysmon:doc-1 (ledger 1)", markdown)

    def test_writes_both_report_files(self):
        report = _build()
        with tempfile.TemporaryDirectory() as temporary:
            json_path, markdown_path = write_report(temporary, report)
            self.assertTrue(json_path.exists())
            self.assertTrue(markdown_path.exists())
            loaded = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["schema_version"], 3)
            with self.assertRaises(FileExistsError):
                write_report(temporary, report)


if __name__ == "__main__":
    unittest.main()
