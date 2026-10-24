"""State machine for the TraceHunt investigation workflow.

The state machine controls workflow order. It does not decide whether
a threat is confirmed; that decision belongs to the evidence verifier.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class HuntPhase(str, Enum):
    CREATED = "created"
    PLANNING = "planning"
    INVESTIGATING = "investigating"
    VERIFYING = "verifying"
    REPORTING = "reporting"
    COMPLETED = "completed"
    ABORTED = "aborted"


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


_ALLOWED_TRANSITIONS = {
    HuntPhase.CREATED: {
        HuntPhase.PLANNING,
        HuntPhase.ABORTED,
    },
    HuntPhase.PLANNING: {
        HuntPhase.INVESTIGATING,
        HuntPhase.ABORTED,
    },
    HuntPhase.INVESTIGATING: {
        HuntPhase.INVESTIGATING,
        HuntPhase.VERIFYING,
        HuntPhase.ABORTED,
    },
    HuntPhase.VERIFYING: {
        HuntPhase.INVESTIGATING,
        HuntPhase.REPORTING,
        HuntPhase.ABORTED,
    },
    HuntPhase.REPORTING: {
        HuntPhase.COMPLETED,
        HuntPhase.ABORTED,
    },
    HuntPhase.COMPLETED: set(),
    HuntPhase.ABORTED: set(),
}


@dataclass
class HuntStateMachine:
    """Track legal workflow transitions and an auditable history."""

    phase: HuntPhase = HuntPhase.CREATED
    verdict: str | None = None
    history: list[dict[str, str]] = field(default_factory=list)

    def transition(
        self,
        to_phase: HuntPhase | str,
        reason: str,
    ) -> dict[str, str]:
        """Move to a permitted phase or reject an invalid transition."""
        try:
            target = (
                to_phase
                if isinstance(to_phase, HuntPhase)
                else HuntPhase(to_phase)
            )
        except ValueError as exc:
            raise ValueError(f"Unknown workflow phase: {to_phase}") from exc

        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("A non-empty transition reason is required")

        if target not in _ALLOWED_TRANSITIONS[self.phase]:
            raise ValueError(
                f"Invalid workflow transition: "
                f"{self.phase.value} -> {target.value}"
            )

        record = {
            "from": self.phase.value,
            "to": target.value,
            "reason": reason.strip(),
            "at": datetime.now(timezone.utc).isoformat(),
        }

        self.phase = target
        self.history.append(record)
        return record.copy()

    def finalize(self, verdict: Verdict | str) -> dict:
        """Complete reporting with a verifier-supplied verdict."""
        if self.phase is not HuntPhase.REPORTING:
            raise RuntimeError(
                "A hunt can only be finalized from the reporting phase"
            )

        if self.verdict is not None:
            raise RuntimeError("This hunt already has a final verdict")

        try:
            selected = (
                verdict if isinstance(verdict, Verdict) else Verdict(verdict)
            )
        except ValueError as exc:
            raise ValueError(f"Invalid final verdict: {verdict}") from exc

        self.transition(
            HuntPhase.COMPLETED,
            f"Evidence verifier selected verdict: {selected.value}",
        )
        self.verdict = selected.value
        return self.snapshot()

    def snapshot(self) -> dict:
        """Return a JSON-serializable snapshot of the current workflow."""
        return {
            "phase": self.phase.value,
            "verdict": self.verdict,
            "history": [entry.copy() for entry in self.history],
        }
