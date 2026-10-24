"""Automated tests for the TraceHunt coverage checklist."""

import unittest

from coverage import CoverageChecklist


class TestCoverageChecklist(unittest.TestCase):
    def test_add_and_export_plan(self):
        checklist = CoverageChecklist()
        checklist.add(
            "failed-logons",
            "windows-security",
            "Check failed logons during the investigation window",
        )

        plan = checklist.to_plan()

        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["id"], "failed-logons")
        self.assertEqual(plan[0]["index"], "windows-security")
        self.assertEqual(plan[0]["status"], "incomplete")
        self.assertIsNone(plan[0]["ledger_seq"])

    def test_complete_result_requires_actual_sequence(self):
        checklist = CoverageChecklist()
        checklist.add("process-check", "sysmon", "Check process events")

        checklist.record_result(
            "process-check",
            ledger_seq=12,
            complete=True,
        )

        plan = checklist.to_plan()
        self.assertEqual(plan[0]["status"], "complete")
        self.assertEqual(plan[0]["ledger_seq"], 12)
        self.assertTrue(checklist.all_complete)

    def test_incomplete_result_does_not_count_as_complete(self):
        checklist = CoverageChecklist()
        checklist.add("network-check", "zeek", "Check network events")

        checklist.record_result(
            "network-check",
            ledger_seq=8,
            complete=False,
            reason="The query result was truncated",
        )

        self.assertEqual(
            checklist.to_plan()[0]["status"],
            "incomplete",
        )
        self.assertFalse(checklist.all_complete)

    def test_pending_items_are_finalized_as_incomplete(self):
        checklist = CoverageChecklist()
        checklist.add("unanswered", "sysmon", "Check process ancestry")

        plan = checklist.finalize()

        self.assertEqual(plan[0]["status"], "incomplete")
        self.assertIsNone(plan[0]["ledger_seq"])
        self.assertEqual(checklist.summary()["pending"], 0)

    def test_skip_requires_a_reason(self):
        checklist = CoverageChecklist()
        checklist.add("optional-check", "zeek", "Optional network check")

        with self.assertRaises(ValueError):
            checklist.skip("optional-check", " ")

        checklist.skip("optional-check", "Not applicable to this hypothesis")
        self.assertEqual(
            checklist.to_plan()[0]["status"],
            "skipped",
        )

    def test_duplicate_ids_are_rejected(self):
        checklist = CoverageChecklist()
        checklist.add("check-1", "sysmon", "First question")

        with self.assertRaises(ValueError):
            checklist.add("check-1", "zeek", "Duplicate question")

    def test_unknown_source_is_rejected(self):
        checklist = CoverageChecklist()

        with self.assertRaises(ValueError):
            checklist.add("check-1", "unknown-index", "Check events")

    def test_invalid_ledger_sequence_is_rejected(self):
        checklist = CoverageChecklist()
        checklist.add("check-1", "sysmon", "Check events")

        with self.assertRaises(ValueError):
            checklist.record_result(
                "check-1",
                ledger_seq=0,
                complete=True,
            )

    def test_incomplete_result_requires_reason(self):
        checklist = CoverageChecklist()
        checklist.add("check-1", "sysmon", "Check events")

        with self.assertRaises(ValueError):
            checklist.record_result(
                "check-1",
                ledger_seq=3,
                complete=False,
            )

    def test_summary_counts_each_status(self):
        checklist = CoverageChecklist()
        checklist.add("a", "sysmon", "Question A")
        checklist.add("b", "zeek", "Question B")
        checklist.add("c", "windows-security", "Question C")

        checklist.record_result("a", 1, True)
        checklist.skip("b", "Not relevant to this scenario")

        summary = checklist.summary()
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["complete"], 1)
        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(summary["pending"], 1)
        self.assertEqual(summary["incomplete"], 1)


if __name__ == "__main__":
    unittest.main()
