"""Tests for evidence provenance and conservative verdict selection."""

import hashlib
import json
import unittest

from evidence_verifier import EvidenceVerifier


def query_hash(query):
    canonical = json.dumps(
        query,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def make_fetch_fixture(index="sysmon", wanted=None, found=None):
    wanted = ["doc-1"] if wanted is None else wanted
    found = wanted[:] if found is None else found

    query = {
        "request": {
            "op": "mget",
            "index": index,
            "body": {"ids": wanted},
        }
    }

    ledger = {
        "seq": 1,
        "run_id": "test-run",
        "tool": "fetch_evidence",
        "status": "ok",
        "query": query,
        "query_hash": query_hash(query),
        "result_count": len(found),
        "doc_ids": found[:],
        "doc_ids_truncated": False,
    }

    response = {
        "ledger_seq": 1,
        "tool": "fetch_evidence",
        "arguments": {
            "index": index,
            "doc_ids": wanted[:],
        },
        "result": {
            "index": index,
            "requested": len(wanted),
            "found": len(found),
            "missing_ids": [item for item in wanted if item not in found],
            "documents": [
                {"_id": doc_id, "@timestamp": "2026-10-23T14:10:00+08:00"}
                for doc_id in found
            ],
        },
    }

    return ledger, response


def make_claim(index="sysmon", doc_id="doc-1", ledger_seq=1):
    return {
        "id": "claim-1",
        "statement": "A matching process event was retrieved.",
        "citations": [
            {
                "index": index,
                "doc_id": doc_id,
                "ledger_seq": ledger_seq,
            }
        ],
    }


class TestEvidenceVerifier(unittest.TestCase):
    def test_actual_fetch_document_is_valid_citation(self):
        ledger, response = make_fetch_fixture()
        verifier = EvidenceVerifier([ledger], [response])

        result = verifier.validate_claims([make_claim()])

        self.assertTrue(result["ok"], result["issues"])
        self.assertEqual(result["verified_claim_ids"], ["claim-1"])
        self.assertTrue(result["tool_results_complete"])

    def test_search_result_id_alone_is_not_a_valid_citation(self):
        query = {
            "request": {
                "op": "search",
                "index": "sysmon",
                "body": {"query": {"match_all": {}}},
            }
        }
        ledger = {
            "seq": 1,
            "run_id": "test-run",
            "tool": "search_events",
            "status": "ok",
            "query": query,
            "query_hash": query_hash(query),
            "result_count": 1,
            "doc_ids": ["doc-1"],
            "doc_ids_truncated": False,
        }
        response = {
            "ledger_seq": 1,
            "tool": "search_events",
            "arguments": {},
            "result": {
                "total_relation": "eq",
                "total_matches": 1,
                "returned": 1,
                "events": [{"_id": "doc-1"}],
                "doc_ids": ["doc-1"],
            },
        }

        verifier = EvidenceVerifier([ledger], [response])
        result = verifier.validate_claims([make_claim()])

        self.assertFalse(result["ok"])
        self.assertNotIn("claim-1", result["verified_claim_ids"])

    def test_wrong_index_or_document_id_is_rejected(self):
        ledger, response = make_fetch_fixture()
        verifier = EvidenceVerifier([ledger], [response])

        wrong_index = verifier.validate_claims(
            [make_claim(index="zeek")]
        )
        wrong_id = verifier.validate_claims(
            [make_claim(doc_id="invented-id")]
        )

        self.assertFalse(wrong_index["ok"])
        self.assertFalse(wrong_id["ok"])

    def test_supporting_evidence_can_confirm_when_preconditions_hold(self):
        ledger, response = make_fetch_fixture()
        verifier = EvidenceVerifier([ledger], [response])

        result = verifier.select_verdict(
            [make_claim()],
            supporting_claim_ids=["claim-1"],
            contradicting_claim_ids=[],
            investigation_complete=True,
            alternatives_tested=True,
        )

        self.assertEqual(result["verdict"], "confirmed")

    def test_contradicting_evidence_can_reject_when_preconditions_hold(self):
        ledger, response = make_fetch_fixture()
        verifier = EvidenceVerifier([ledger], [response])

        result = verifier.select_verdict(
            [make_claim()],
            supporting_claim_ids=[],
            contradicting_claim_ids=["claim-1"],
            investigation_complete=True,
            alternatives_tested=True,
        )

        self.assertEqual(result["verdict"], "rejected")

    def test_partial_fetch_forces_inconclusive_verdict(self):
        ledger, response = make_fetch_fixture(
            wanted=["doc-1", "doc-2"],
            found=["doc-1"],
        )
        verifier = EvidenceVerifier([ledger], [response])

        result = verifier.select_verdict(
            [make_claim()],
            supporting_claim_ids=["claim-1"],
            contradicting_claim_ids=[],
            investigation_complete=True,
            alternatives_tested=True,
        )

        self.assertEqual(result["verdict"], "inconclusive")
        self.assertFalse(result["validation"]["tool_results_complete"])

    def test_untested_alternatives_force_inconclusive(self):
        ledger, response = make_fetch_fixture()
        verifier = EvidenceVerifier([ledger], [response])

        result = verifier.select_verdict(
            [make_claim()],
            supporting_claim_ids=["claim-1"],
            contradicting_claim_ids=[],
            investigation_complete=True,
            alternatives_tested=False,
        )

        self.assertEqual(result["verdict"], "inconclusive")

    def test_same_claim_cannot_support_and_refute_verdict(self):
        ledger, response = make_fetch_fixture()
        verifier = EvidenceVerifier([ledger], [response])

        result = verifier.select_verdict(
            [make_claim()],
            supporting_claim_ids=["claim-1"],
            contradicting_claim_ids=["claim-1"],
            investigation_complete=True,
            alternatives_tested=True,
        )

        self.assertEqual(result["verdict"], "inconclusive")

    def test_changed_query_hash_blocks_final_verdict(self):
        ledger, response = make_fetch_fixture()
        ledger["query_hash"] = "0" * 64
        verifier = EvidenceVerifier([ledger], [response])

        result = verifier.select_verdict(
            [make_claim()],
            supporting_claim_ids=["claim-1"],
            contradicting_claim_ids=[],
            investigation_complete=True,
            alternatives_tested=True,
        )

        self.assertFalse(result["validation"]["ok"])
        self.assertEqual(result["verdict"], "inconclusive")

    def test_missing_response_archive_blocks_final_verdict(self):
        ledger, _ = make_fetch_fixture()
        verifier = EvidenceVerifier([ledger], [])

        result = verifier.select_verdict(
            [make_claim()],
            supporting_claim_ids=["claim-1"],
            contradicting_claim_ids=[],
            investigation_complete=True,
            alternatives_tested=True,
        )

        self.assertFalse(result["validation"]["ok"])
        self.assertEqual(result["verdict"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
