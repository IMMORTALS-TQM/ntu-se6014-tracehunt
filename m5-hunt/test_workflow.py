"""Integration tests for the TraceHunt workflow coordinator."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import sys

M6_ROOT = Path(__file__).resolve().parents[1] / "m6-experiment"
sys.path.insert(0, str(M6_ROOT))

from tracehunt_experiment.compare import evaluate as m6_evaluate

M4_ROOT = Path(__file__).resolve().parents[1] / "m4-mcp"
sys.path.insert(0, str(M4_ROOT))

from tracehunt_mcp.ledger import EvidenceLedger

from types import SimpleNamespace

from workflow import HuntWorkflow


WINDOW = {
    "start": "2026-10-23T14:00:00+08:00",
    "end": "2026-10-23T14:30:00+08:00",
}

LIMITS = {
    "indices": ["windows-security", "sysmon", "zeek"],
    "default_size": 50,
    "max_size": 500,
    "max_window_hours": 72,
    "request_timeout_s": 10,
    "max_scan": 2000,
    "max_doc_ids": 50,
    "max_seq_steps": 5,
    "max_agg_buckets": 100,
}

COVERAGE = {
    source: {
        **WINDOW,
        "complete": True,
        "basis": "Independent deterministic fixture coverage record",
    }
    for source in ("windows-security", "sysmon", "zeek")
}


def _query_hash(query):
    raw = json.dumps(
        query,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class FakeLedger:
    """Write M4-shaped ledger rows for coordinator tests."""

    def __init__(self, path, run_id):
        self.path = str(path)
        self.run_id = run_id
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.path).touch(exist_ok=True)

    def append(self, tool, query, result_count=0, doc_ids=None):
        records = [
            line for line in Path(self.path).read_text(
                encoding="utf-8"
            ).splitlines() if line.strip()
        ]
        row = {
            "seq": len(records) + 1,
            "run_id": self.run_id,
            "ts": "2026-10-23T06:00:00+00:00",
            "tool": tool,
            "status": "ok",
            "query": query,
            "query_hash": _query_hash(query),
            "result_count": result_count,
            "doc_ids": list(doc_ids or []),
            "doc_ids_truncated": False,
            "duration_ms": 1,
        }
        with Path(self.path).open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            )
        return row["seq"]


class FakeToolSet:
    """Small fake implementing the M4 tool return shapes used by these tests."""

    def __init__(self, config, available=None, incomplete_search=False):
        self.cfg = config
        self.ledger = FakeLedger(config.ledger_path, config.run_id)
        self.available = set(available or ("windows-security", "sysmon", "zeek"))
        self.incomplete_search = incomplete_search

    def list_data_sources(self):
        result = {
            "run_id": self.cfg.run_id,
            "sources": [
                {
                    "index": index,
                    "available": index in self.available,
                    "doc_count": 1 if index in self.available else None,
                }
                for index in self.cfg.indices
            ],
            "indices_allowlist": list(self.cfg.indices),
        }
        self.ledger.append(
            "list_data_sources",
            {"requests": []},
            result_count=len(result["sources"]),
        )
        return result

    def search_events(
        self, index, start, end, filters=None, size=None, sort=None
    ):
        query = {
            "request": {
                "op": "search",
                "index": index,
                "body": {
                    "query": {
                        "bool": {
                            "filter": [
                                {
                                    "range": {
                                        "@timestamp": {
                                            "gte": start,
                                            "lt": end,
                                        }
                                    }
                                }
                            ]
                        }
                    }
                },
            }
        }
        relation = "gte" if self.incomplete_search else "eq"
        total_matches = 2 if self.incomplete_search else 1
        result = {
            "index": index,
            "total_matches": total_matches,
            "total_relation": relation,
            "returned": 1,
            "events": [{"_id": "doc-1", "@timestamp": start}],
            "doc_ids": ["doc-1"],
        }
        self.ledger.append(
            "search_events",
            query,
            result_count=total_matches,
            doc_ids=result["doc_ids"],
        )
        return result

    def fetch_evidence(self, index, doc_ids):
        query = {
            "request": {
                "op": "mget",
                "index": index,
                "body": {"ids": list(doc_ids)},
            }
        }
        documents = [
            {"_id": doc_id, "@timestamp": WINDOW["start"]}
            for doc_id in doc_ids
        ]
        result = {
            "index": index,
            "requested": len(doc_ids),
            "found": len(documents),
            "missing_ids": [],
            "documents": documents,
        }
        self.ledger.append(
            "fetch_evidence",
            query,
            result_count=len(documents),
            doc_ids=[doc["_id"] for doc in documents],
        )
        return result


def make_workflow(
    output_dir,
    *,
    available=None,
    incomplete_search=False,
):
    ledger_path = str(Path(output_dir) / "ledger.jsonl")
    config = SimpleNamespace(
        run_id="workflow-test-run",
        ledger_path=ledger_path,
        indices=tuple(LIMITS["indices"]),
        default_size=LIMITS["default_size"],
        max_size=LIMITS["max_size"],
        max_window_hours=LIMITS["max_window_hours"],
        request_timeout_s=LIMITS["request_timeout_s"],
        max_scan=LIMITS["max_scan"],
        max_doc_ids=LIMITS["max_doc_ids"],
        max_seq_steps=LIMITS["max_seq_steps"],
        max_agg_buckets=LIMITS["max_agg_buckets"],
    )
    tools = FakeToolSet(
        config,
        available=available,
        incomplete_search=incomplete_search,
    )
    return HuntWorkflow(
        tools,
        output_dir,
        run_id=config.run_id,
        run_kind="typed_api_smoke",
        backend="fixture",
        dataset_id="workflow-test-dataset",
        freeze_id="workflow-test-freeze",
        m4_limits=LIMITS,
        source_coverage=COVERAGE,
        investigation_window=WINDOW,
        model_usage=None,
    )


def make_plan(index="sysmon"):
    return [{
        "id": "process-check",
        "index": index,
        "question": "Check process events in the investigation window",
        "tool": "search_events",
        "arguments": {
            "index": index,
            "start": WINDOW["start"],
            "end": WINDOW["end"],
            "filters": [],
            "size": 10,
        },
    }]


def make_claim(doc_id="doc-1", index="sysmon"):
    return [{
        "id": "claim-1",
        "statement": "The fixture contains the retrieved process event.",
        "evidence": [{"index": index, "doc_id": doc_id}],
    }]


class TestHuntWorkflow(unittest.TestCase):
    def test_executes_and_exports_archived_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run-output"
            workflow = make_workflow(output)

            report = workflow.execute(
                make_plan(),
                make_claim(),
                required_sources=["sysmon"],
                supporting_claim_ids=["claim-1"],
                contradicting_claim_ids=[],
                alternatives_tested=True,
            )

            self.assertEqual(report["verdict"], "confirmed")
            self.assertTrue(report["investigation_coverage"]["complete"])
            self.assertTrue(
                report["investigation_coverage"]["sources"]["sysmon"]["covered"]
            )
            self.assertTrue((output / "ledger.jsonl").exists())
            self.assertTrue((output / "responses.jsonl").exists())
            self.assertTrue((output / "run.json").exists())
            self.assertTrue((output / "report.md").exists())

            ledger_rows = [
                json.loads(line)
                for line in (output / "ledger.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]
            response_rows = [
                json.loads(line)
                for line in (output / "responses.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]

            self.assertEqual(len(ledger_rows), len(response_rows))
            self.assertEqual(
                [row["seq"] for row in ledger_rows],
                [row["ledger_seq"] for row in response_rows],
            )
            self.assertEqual(
                report["claims"][0]["citations"][0]["ledger_seq"],
                3,
            )
            self.assertEqual(report["workflow"]["phase"], "completed")

    def test_incomplete_search_forces_inconclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run-output"
            workflow = make_workflow(output, incomplete_search=True)

            report = workflow.execute(
                make_plan(),
                make_claim(),
                required_sources=["sysmon"],
                supporting_claim_ids=["claim-1"],
                contradicting_claim_ids=[],
                alternatives_tested=True,
            )

            self.assertEqual(report["verdict"], "inconclusive")
            self.assertFalse(report["tool_results_complete"])
            self.assertEqual(report["plan"][0]["status"], "incomplete")

    def test_unobserved_claim_document_is_not_fetched_or_cited(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run-output"
            workflow = make_workflow(output)

            report = workflow.execute(
                make_plan(),
                make_claim(doc_id="invented-doc"),
                required_sources=["sysmon"],
                supporting_claim_ids=["claim-1"],
                contradicting_claim_ids=[],
                alternatives_tested=True,
            )

            self.assertEqual(report["verdict"], "inconclusive")
            self.assertEqual(report["claims"], [])
            self.assertTrue(any(
                response["tool"] == "search_events"
                for response in workflow.responses
            ))
            self.assertFalse(any(
                response["tool"] == "fetch_evidence"
                for response in workflow.responses
            ))

    def test_duplicate_plan_ids_are_rejected_before_tool_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run-output"
            workflow = make_workflow(output)
            plan = make_plan()
            plan.append(dict(plan[0]))

            with self.assertRaises(ValueError):
                workflow.execute(
                    plan,
                    [],
                    required_sources=["sysmon"],
                    supporting_claim_ids=[],
                    contradicting_claim_ids=[],
                    alternatives_tested=False,
                )

            self.assertEqual(workflow.responses, [])
            self.assertEqual(
                Path(workflow.ledger_path).read_text(encoding="utf-8"),
                "",
            )


    def test_missing_required_source_forces_inconclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            workflow = make_workflow(Path(temporary) / "run-output")

            report = workflow.execute(
                make_plan(index="sysmon"),
                make_claim(index="sysmon"),
                required_sources=["sysmon", "windows-security"],
                supporting_claim_ids=["claim-1"],
                contradicting_claim_ids=[],
                alternatives_tested=True,
            )

            self.assertEqual(report["verdict"], "inconclusive")
            self.assertFalse(report["investigation_coverage"]["complete"])
            self.assertFalse(
                report["investigation_coverage"]["sources"]
                ["windows-security"]["covered"]
            )

    def test_short_query_window_forces_inconclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            workflow = make_workflow(Path(temporary) / "run-output")
            plan = make_plan()
            plan[0]["arguments"]["start"] = "2026-10-23T14:05:00+08:00"
            plan[0]["arguments"]["end"] = "2026-10-23T14:25:00+08:00"

            report = workflow.execute(
                plan,
                make_claim(),
                required_sources=["sysmon"],
                supporting_claim_ids=["claim-1"],
                contradicting_claim_ids=[],
                alternatives_tested=True,
            )

            self.assertEqual(report["verdict"], "inconclusive")
            self.assertFalse(report["investigation_coverage"]["complete"])
            self.assertFalse(
                report["investigation_coverage"]["sources"]["sysmon"]["covered"]
            )

    def test_gap_between_query_windows_forces_inconclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            workflow = make_workflow(Path(temporary) / "run-output")
            plan = make_plan()
            first = dict(plan[0])
            first["arguments"] = dict(plan[0]["arguments"])
            first["id"] = "first-window"
            first["arguments"]["end"] = "2026-10-23T14:10:00+08:00"

            second = dict(plan[0])
            second["arguments"] = dict(plan[0]["arguments"])
            second["id"] = "second-window"
            second["arguments"]["start"] = "2026-10-23T14:20:00+08:00"

            report = workflow.execute(
                [first, second],
                make_claim(),
                required_sources=["sysmon"],
                supporting_claim_ids=["claim-1"],
                contradicting_claim_ids=[],
                alternatives_tested=True,
            )

            self.assertEqual(report["verdict"], "inconclusive")
            self.assertFalse(report["investigation_coverage"]["complete"])
            self.assertFalse(
                report["investigation_coverage"]["sources"]["sysmon"]["covered"]
            )



    def test_real_m4_ledger_is_initialized_when_file_is_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fresh-run"
            output.mkdir()
            ledger_path = output / "ledger.jsonl"

            ledger = EvidenceLedger(
                str(ledger_path),
                "workflow-test-run",
            )

            # The real M4 EvidenceLedger creates the parent directory,
            # but does not create the ledger file in its constructor.
            self.assertFalse(ledger_path.exists())

            config = SimpleNamespace(
                run_id="workflow-test-run",
                ledger_path=str(ledger_path),
                indices=tuple(LIMITS["indices"]),
                default_size=LIMITS["default_size"],
                max_size=LIMITS["max_size"],
                max_window_hours=LIMITS["max_window_hours"],
                request_timeout_s=LIMITS["request_timeout_s"],
                max_scan=LIMITS["max_scan"],
                max_doc_ids=LIMITS["max_doc_ids"],
                max_seq_steps=LIMITS["max_seq_steps"],
                max_agg_buckets=LIMITS["max_agg_buckets"],
            )
            tools = SimpleNamespace(ledger=ledger, cfg=config)

            workflow = HuntWorkflow(
                tools,
                output,
                run_id=config.run_id,
                run_kind="typed_api_smoke",
                backend="fixture",
                dataset_id="workflow-test-dataset",
                freeze_id="workflow-test-freeze",
                m4_limits=LIMITS,
                source_coverage=COVERAGE,
                investigation_window=WINDOW,
                model_usage=None,
            )

            self.assertTrue(ledger_path.exists())
            self.assertEqual(
                ledger_path.read_text(encoding="utf-8"),
                "",
            )
            self.assertEqual(workflow.responses, [])


    def test_m5_export_is_readable_by_m6_comparator(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run-output"
            workflow = make_workflow(output)

            report = workflow.execute(
                make_plan(),
                make_claim(),
                required_sources=["sysmon"],
                supporting_claim_ids=["claim-1"],
                contradicting_claim_ids=[],
                alternatives_tested=True,
            )

            frozen = {
                "dataset_id": report["dataset_id"],
                "freeze_id": report["freeze_id"],
                "m4_limits": report["m4_limits"],
                "configuration": {
                    "experiment_kind": report["run_kind"],
                },
                "scenario": WINDOW,
            }

            metrics = m6_evaluate(output, frozen)

            self.assertTrue(metrics["response_archive_complete"])
            self.assertTrue(metrics["tool_results_complete"])
            self.assertTrue(metrics["summary_completeness_consistent"])
            self.assertEqual(metrics["citation_linkage"], 1.0)
            self.assertEqual(metrics["archived_citation_coverage"], 1.0)


    def test_nonempty_ledger_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "existing-run"
            output.mkdir()
            ledger_path = output / "ledger.jsonl"
            ledger_path.write_text('{"seq":1}\n', encoding="utf-8")

            ledger = EvidenceLedger(
                str(ledger_path),
                "workflow-test-run",
            )
            config = SimpleNamespace(
                run_id="workflow-test-run",
                ledger_path=str(ledger_path),
                indices=tuple(LIMITS["indices"]),
                default_size=LIMITS["default_size"],
                max_size=LIMITS["max_size"],
                max_window_hours=LIMITS["max_window_hours"],
                request_timeout_s=LIMITS["request_timeout_s"],
                max_scan=LIMITS["max_scan"],
                max_doc_ids=LIMITS["max_doc_ids"],
                max_seq_steps=LIMITS["max_seq_steps"],
                max_agg_buckets=LIMITS["max_agg_buckets"],
            )
            tools = SimpleNamespace(ledger=ledger, cfg=config)

            with self.assertRaisesRegex(ValueError, "fresh, empty M4 ledger"):
                HuntWorkflow(
                    tools,
                    output,
                    run_id=config.run_id,
                    run_kind="typed_api_smoke",
                    backend="fixture",
                    dataset_id="workflow-test-dataset",
                    freeze_id="workflow-test-freeze",
                    m4_limits=LIMITS,
                    source_coverage=COVERAGE,
                    investigation_window=WINDOW,
                    model_usage=None,
                )

            self.assertEqual(
                ledger_path.read_text(encoding="utf-8"),
                '{"seq":1}\n',
            )


    def test_existing_report_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "existing-run"
            output.mkdir()
            (output / "report.md").write_text(
                "keep existing report",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(FileExistsError, "report.md"):
                make_workflow(output)

            self.assertEqual(
                (output / "report.md").read_text(encoding="utf-8"),
                "keep existing report",
            )


if __name__ == "__main__":
    unittest.main()
