"""Automated tests for the TraceHunt hunt state machine."""

import unittest

from state_machine import HuntPhase, HuntStateMachine, Verdict


def move_to_reporting(hunt: HuntStateMachine) -> None:
    """Move a new hunt to the reporting phase."""
    hunt.transition(HuntPhase.PLANNING, "Hypothesis received")
    hunt.transition(HuntPhase.INVESTIGATING, "Plan ready")
    hunt.transition(HuntPhase.VERIFYING, "Initial queries finished")
    hunt.transition(HuntPhase.REPORTING, "Evidence reviewed")


class TestHuntStateMachine(unittest.TestCase):
    def test_normal_lifecycle(self):
        hunt = HuntStateMachine()

        move_to_reporting(hunt)
        result = hunt.finalize(Verdict.INCONCLUSIVE)

        self.assertEqual(result["phase"], "completed")
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(len(result["history"]), 5)

    def test_all_three_verdicts_are_supported(self):
        for verdict in Verdict:
            with self.subTest(verdict=verdict.value):
                hunt = HuntStateMachine()
                move_to_reporting(hunt)

                result = hunt.finalize(verdict)

                self.assertEqual(result["verdict"], verdict.value)

    def test_cannot_skip_directly_to_completed(self):
        hunt = HuntStateMachine()

        with self.assertRaises(ValueError):
            hunt.transition(HuntPhase.COMPLETED, "Skip investigation")

        self.assertEqual(hunt.phase, HuntPhase.CREATED)
        self.assertEqual(hunt.history, [])

    def test_cannot_finalize_before_reporting(self):
        hunt = HuntStateMachine()

        with self.assertRaises(RuntimeError):
            hunt.finalize(Verdict.CONFIRMED)

        self.assertEqual(hunt.phase, HuntPhase.CREATED)

    def test_verification_can_return_to_investigation(self):
        hunt = HuntStateMachine()

        hunt.transition(HuntPhase.PLANNING, "Hypothesis received")
        hunt.transition(HuntPhase.INVESTIGATING, "Plan ready")
        hunt.transition(HuntPhase.VERIFYING, "Initial evidence reviewed")
        hunt.transition(
            HuntPhase.INVESTIGATING,
            "Need to test an alternative explanation",
        )

        self.assertEqual(hunt.phase, HuntPhase.INVESTIGATING)

    def test_transition_requires_a_reason(self):
        hunt = HuntStateMachine()

        with self.assertRaises(ValueError):
            hunt.transition(HuntPhase.PLANNING, "  ")

        self.assertEqual(hunt.phase, HuntPhase.CREATED)

    def test_completed_hunt_cannot_transition_again(self):
        hunt = HuntStateMachine()
        move_to_reporting(hunt)
        hunt.finalize(Verdict.REJECTED)

        with self.assertRaises(ValueError):
            hunt.transition(HuntPhase.PLANNING, "Restart")

    def test_verdict_cannot_be_changed_by_finalizing_twice(self):
        hunt = HuntStateMachine()
        move_to_reporting(hunt)
        hunt.finalize(Verdict.CONFIRMED)

        with self.assertRaises(RuntimeError):
            hunt.finalize(Verdict.REJECTED)

        self.assertEqual(hunt.verdict, "confirmed")


if __name__ == "__main__":
    unittest.main()
