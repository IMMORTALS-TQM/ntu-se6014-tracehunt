"""Validate evidence provenance before producing a TraceHunt verdict.

This module checks the audit trail and citation links. It does not claim
to determine the semantic meaning of a log event automatically.
"""

import hashlib
import json
from collections.abc import Mapping
from typing import Any


SOURCE_INDICES = frozenset({
    "windows-security",
    "sysmon",
    "zeek",
})


def _canonical_json(value: Any) -> str:
    """Match the canonical JSON format used by the M4 evidence ledger."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _query_hash(query: Any) -> str:
    return hashlib.sha256(
        _canonical_json(query).encode("utf-8")
    ).hexdigest()


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _non_negative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


class EvidenceVerifier:
    """Check ledger integrity, archived fetches and claim citations."""

    def __init__(
        self,
        ledger_records: list[dict],
        responses: list[dict],
        expected_run_id: str | None = None,
    ) -> None:
        self.ledger_by_seq: dict[int, dict] = {}
        self.response_by_seq: dict[int, dict] = {}
        self.valid_fetch_refs: set[tuple[int, str, str]] = set()
        self.integrity_issues: list[dict[str, Any]] = []

        self._validate_ledger(ledger_records, expected_run_id)
        self._validate_responses(responses)
        self._index_fetch_evidence()

    def _issue(
        self,
        code: str,
        message: str,
        ledger_seq: int | None = None,
    ) -> None:
        issue = {"code": code, "message": message}
        if ledger_seq is not None:
            issue["ledger_seq"] = ledger_seq
        self.integrity_issues.append(issue)

    def _validate_ledger(
        self,
        records: list[dict],
        expected_run_id: str | None,
    ) -> None:
        if not isinstance(records, list) or not records:
            self._issue("empty_ledger", "The evidence ledger is empty")
            return

        last_seq = 0
        run_id = expected_run_id

        for row in records:
            if not isinstance(row, Mapping):
                self._issue("invalid_ledger_row", "A ledger row is not an object")
                continue

            seq = row.get("seq")
            if not _positive_int(seq):
                self._issue("invalid_sequence", "Invalid ledger sequence")
                continue

            if seq <= last_seq:
                self._issue(
                    "ledger_order",
                    "Ledger sequence numbers must strictly increase",
                    seq,
                )
            last_seq = seq

            if seq in self.ledger_by_seq:
                self._issue("duplicate_sequence", "Duplicate ledger sequence", seq)
                continue

            self.ledger_by_seq[seq] = dict(row)

            current_run_id = row.get("run_id")
            if not isinstance(current_run_id, str) or not current_run_id.strip():
                self._issue("invalid_run_id", "Ledger row has no valid run ID", seq)
            elif run_id is None:
                run_id = current_run_id
            elif current_run_id != run_id:
                self._issue("mixed_run_ids", "Ledger contains different run IDs", seq)

            if row.get("status") not in ("ok", "error"):
                self._issue("invalid_status", "Invalid ledger status", seq)

            query = row.get("query")
            if not isinstance(query, Mapping):
                self._issue("invalid_query", "Ledger query must be an object", seq)
            elif row.get("query_hash") != _query_hash(query):
                self._issue("query_hash_mismatch", "Ledger query hash does not match", seq)

            doc_ids = row.get("doc_ids")
            if not isinstance(doc_ids, list) or not all(
                isinstance(doc_id, str) for doc_id in doc_ids
            ):
                self._issue("invalid_doc_ids", "Ledger document IDs are invalid", seq)
            elif len(set(doc_ids)) != len(doc_ids):
                self._issue("duplicate_doc_ids", "Ledger contains duplicate document IDs", seq)

            if not _non_negative_int(row.get("result_count")):
                self._issue("invalid_result_count", "Invalid ledger result count", seq)

    def _validate_responses(self, responses: list[dict]) -> None:
        if not isinstance(responses, list):
            self._issue("invalid_responses", "Responses archive must be a list")
            return

        for response in responses:
            if not isinstance(response, Mapping):
                self._issue("invalid_response", "A response record is not an object")
                continue

            seq = response.get("ledger_seq")
            if not _positive_int(seq):
                self._issue("invalid_response_sequence", "Invalid response sequence")
                continue

            if seq in self.response_by_seq:
                self._issue("duplicate_response", "Duplicate response sequence", seq)
                continue

            row = self.ledger_by_seq.get(seq)
            if row is None:
                self._issue(
                    "orphan_response",
                    "Response has no corresponding ledger row",
                    seq,
                )
                continue

            if response.get("tool") != row.get("tool"):
                self._issue(
                    "response_tool_mismatch",
                    "Response tool does not match the ledger",
                    seq,
                )
                continue

            if not isinstance(response.get("result"), Mapping):
                self._issue(
                    "invalid_response_result",
                    "Response result must be an object",
                    seq,
                )
                continue

            self.response_by_seq[seq] = dict(response)

        for seq in self.ledger_by_seq:
            if seq not in self.response_by_seq:
                self._issue(
                    "missing_response",
                    "No archived tool response exists for this ledger row",
                    seq,
                )

    def _index_fetch_evidence(self) -> None:
        """Index documents only when the M4 fetch archive matches its ledger."""
        for seq, row in self.ledger_by_seq.items():
            if row.get("tool") != "fetch_evidence" or row.get("status") != "ok":
                continue

            response = self.response_by_seq.get(seq)
            if response is None:
                continue

            query = row.get("query")
            request = query.get("request") if isinstance(query, Mapping) else None
            if not isinstance(request, Mapping):
                self._issue("invalid_fetch_query", "Fetch query has no request object", seq)
                continue

            index = request.get("index")
            body = request.get("body")
            wanted = body.get("ids") if isinstance(body, Mapping) else None

            if (
                index not in SOURCE_INDICES
                or not isinstance(wanted, list)
                or not all(isinstance(item, str) for item in wanted)
                or len(set(wanted)) != len(wanted)
            ):
                self._issue("invalid_fetch_request", "Fetch request is malformed", seq)
                continue

            arguments = response.get("arguments")
            if (
                not isinstance(arguments, Mapping)
                or arguments.get("index") != index
                or arguments.get("doc_ids") != wanted
            ):
                self._issue(
                    "fetch_arguments_mismatch",
                    "Archived fetch arguments differ from the ledger request",
                    seq,
                )
                continue

            result = response["result"]
            documents = result.get("documents")
            missing = result.get("missing_ids")

            if (
                result.get("index") != index
                or not isinstance(documents, list)
                or not isinstance(missing, list)
                or not all(isinstance(item, str) for item in missing)
                or len(set(missing)) != len(missing)
                or not _non_negative_int(result.get("requested"))
                or not _non_negative_int(result.get("found"))
            ):
                self._issue("invalid_fetch_result", "Fetch result is malformed", seq)
                continue

            archived_ids: list[str] = []
            documents_valid = True
            for document in documents:
                if not isinstance(document, Mapping):
                    documents_valid = False
                    break
                doc_id = document.get("_id")
                if not isinstance(doc_id, str) or not doc_id:
                    documents_valid = False
                    break
                archived_ids.append(doc_id)

            if not documents_valid or len(set(archived_ids)) != len(archived_ids):
                self._issue(
                    "invalid_archived_documents",
                    "Fetched documents have invalid or duplicate IDs",
                    seq,
                )
                continue

            if (
                result["requested"] != len(wanted)
                or result["found"] != len(archived_ids)
                or not set(archived_ids).issubset(set(wanted))
                or set(missing) != set(wanted) - set(archived_ids)
                or row.get("result_count") != len(archived_ids)
            ):
                self._issue(
                    "fetch_count_mismatch",
                    "Fetch request, returned documents and counts disagree",
                    seq,
                )
                continue

            retained_ids = row.get("doc_ids", [])
            if row.get("doc_ids_truncated", False):
                # M4 retains the first 100 IDs when ledger IDs are truncated.
                if (
                    len(retained_ids) != 100
                    or len(archived_ids) <= len(retained_ids)
                    or archived_ids[:len(retained_ids)] != retained_ids
                ):
                    self._issue(
                        "truncated_fetch_mismatch",
                        "Truncated ledger IDs do not match the archive prefix",
                        seq,
                    )
                    continue
            elif set(retained_ids) != set(archived_ids):
                self._issue(
                    "fetch_ids_mismatch",
                    "Fetched documents do not match ledger document IDs",
                    seq,
                )
                continue

            # A partially successful fetch may still cite documents it actually
            # returned. Overall completeness is checked separately below.
            for doc_id in archived_ids:
                self.valid_fetch_refs.add((seq, index, doc_id))

    @property
    def integrity_ok(self) -> bool:
        return not self.integrity_issues

    @property
    def tool_results_complete(self) -> bool:
        """Apply the same basic result-completeness rules as M6."""
        if (
            not self.ledger_by_seq
            or not self.integrity_ok
            or len(self.response_by_seq) != len(self.ledger_by_seq)
        ):
            return False

        for seq, row in self.ledger_by_seq.items():
            if row.get("status") != "ok":
                return False

            response = self.response_by_seq.get(seq)
            if response is None:
                return False

            tool = response.get("tool")
            result = response.get("result", {})

            if tool == "search_events":
                if (
                    result.get("total_relation") != "eq"
                    or result.get("returned") != result.get("total_matches")
                ):
                    return False
            elif tool == "aggregate_events":
                if result.get("truncated") is not False:
                    return False
            elif tool == "run_sequence_query":
                if result.get("complete") is not True:
                    return False
            elif tool == "fetch_evidence":
                if (
                    result.get("found") != result.get("requested")
                    or result.get("missing_ids")
                ):
                    return False

        return True

    def validate_claims(self, claims: list[dict]) -> dict:
        """Validate every factual claim's citation provenance."""
        claim_issues: list[dict[str, Any]] = []
        verified_claim_ids: set[str] = set()
        seen_ids: set[str] = set()

        if not isinstance(claims, list):
            claim_issues.append({
                "code": "invalid_claims",
                "message": "Claims must be a list",
            })
            claims = []

        for claim in claims:
            if not isinstance(claim, Mapping):
                claim_issues.append({
                    "code": "invalid_claim",
                    "message": "A claim is not an object",
                })
                continue

            claim_id = claim.get("id")
            statement = claim.get("statement")
            valid = True

            if not isinstance(claim_id, str) or not claim_id.strip():
                claim_issues.append({
                    "code": "invalid_claim_id",
                    "message": "Claim ID must be a non-empty string",
                })
                valid = False
            elif claim_id in seen_ids:
                claim_issues.append({
                    "code": "duplicate_claim_id",
                    "message": f"Duplicate claim ID: {claim_id}",
                })
                valid = False
            else:
                seen_ids.add(claim_id)

            if not isinstance(statement, str) or not statement.strip():
                claim_issues.append({
                    "code": "empty_statement",
                    "message": "A claim statement must not be empty",
                })
                valid = False

            citations = claim.get("citations")
            if not isinstance(citations, list) or not citations:
                claim_issues.append({
                    "code": "missing_citations",
                    "message": f"Claim {claim_id!r} needs at least one citation",
                })
                valid = False
                citations = []

            for citation in citations:
                if not isinstance(citation, Mapping):
                    valid = False
                    claim_issues.append({
                        "code": "invalid_citation",
                        "message": f"Claim {claim_id!r} has a malformed citation",
                    })
                    continue

                index = citation.get("index")
                doc_id = citation.get("doc_id")
                seq = citation.get("ledger_seq")
                reference = (seq, index, doc_id)

                if (
                    not _positive_int(seq)
                    or index not in SOURCE_INDICES
                    or not isinstance(doc_id, str)
                    or not doc_id
                    or reference not in self.valid_fetch_refs
                ):
                    valid = False
                    claim_issues.append({
                        "code": "unverified_citation",
                        "message": (
                            f"Claim {claim_id!r} cites a document that cannot "
                            "be linked to a successful archived fetch"
                        ),
                    })

            if valid and isinstance(claim_id, str):
                verified_claim_ids.add(claim_id)

        issues = [*self.integrity_issues, *claim_issues]
        return {
            "ok": not issues,
            "verified_claim_ids": sorted(verified_claim_ids),
            "issues": issues,
            "tool_results_complete": self.tool_results_complete,
        }

    def select_verdict(
        self,
        claims: list[dict],
        supporting_claim_ids: list[str],
        contradicting_claim_ids: list[str],
        *,
        investigation_complete: bool,
        alternatives_tested: bool,
    ) -> dict:
        """Choose a conservative verdict using verified claims and preconditions.

        The caller supplies the semantic classification of claims. This method
        verifies provenance and completeness; it does not interpret log meaning.
        """
        validation = self.validate_claims(claims)
        reasons: list[str] = []

        if not isinstance(supporting_claim_ids, list) or not all(
            isinstance(item, str) for item in supporting_claim_ids
        ):
            supporting = set()
            reasons.append("Supporting claim IDs are invalid")
        else:
            supporting = set(supporting_claim_ids)

        if not isinstance(contradicting_claim_ids, list) or not all(
            isinstance(item, str) for item in contradicting_claim_ids
        ):
            contradicting = set()
            reasons.append("Contradicting claim IDs are invalid")
        else:
            contradicting = set(contradicting_claim_ids)

        verified = set(validation["verified_claim_ids"])
        if (supporting | contradicting) - verified:
            reasons.append("A support/refutation label refers to an unverified claim")

        if type(investigation_complete) is not bool or not investigation_complete:
            reasons.append("Investigation coverage is incomplete")

        if type(alternatives_tested) is not bool or not alternatives_tested:
            reasons.append("Alternative explanations have not been fully tested")

        if not validation["ok"]:
            reasons.append("Evidence integrity or citation validation failed")

        if not validation["tool_results_complete"]:
            reasons.append("One or more tool results are incomplete")

        verdict = "inconclusive"

        if supporting and contradicting:
            reasons.append(
                "Verified supporting and contradicting evidence conflict"
            )
        elif not reasons and supporting:
            verdict = "confirmed"
        elif not reasons and contradicting:
            verdict = "rejected"

        if not reasons and verdict == "inconclusive":
            reasons.append("There is not enough verified evidence to decide")

        return {
            "verdict": verdict,
            "reasons": reasons,
            "validation": validation,
        }
