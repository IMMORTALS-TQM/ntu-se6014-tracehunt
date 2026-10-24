"""Investigation coverage checklist for TraceHunt.

This module tracks planned questions and their final status.
It never invents ledger sequence numbers or treats missing evidence
as proof that a threat is absent.
"""

from dataclasses import dataclass, field


SOURCE_INDICES = frozenset({
    "windows-security",
    "sysmon",
    "zeek",
})

PLAN_STATUSES = frozenset({
    "complete",
    "incomplete",
    "skipped",
})


def _require_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _validate_ledger_seq(value: int) -> int:
    if type(value) is not int or value < 1:
        raise ValueError("ledger_seq must be a positive integer")
    return value


@dataclass
class CoverageItem:
    """One planned investigation question."""

    id: str
    index: str
    question: str
    ledger_seq: int | None = None
    reason: str | None = None
    _state: str = field(default="pending", init=False, repr=False)

    def __post_init__(self) -> None:
        self.id = _require_text(self.id, "id")
        self.index = _require_text(self.index, "index")
        self.question = _require_text(self.question, "question")

        if self.index not in SOURCE_INDICES:
            raise ValueError(f"Unsupported source index: {self.index}")

        if self.ledger_seq is not None:
            self.ledger_seq = _validate_ledger_seq(self.ledger_seq)

    @property
    def state(self) -> str:
        """Internal state, including pending."""
        return self._state

    @property
    def status(self) -> str:
        """Status compatible with the M6 export contract."""
        return "incomplete" if self._state == "pending" else self._state

    def record_result(
        self,
        ledger_seq: int,
        complete: bool,
        reason: str | None = None,
    ) -> None:
        """Record a result using the actual M4 ledger sequence.

        The caller must determine completeness from the real tool response.
        """
        if self._state == "skipped":
            raise ValueError("A skipped item cannot receive a result")

        seq = _validate_ledger_seq(ledger_seq)

        if type(complete) is not bool:
            raise ValueError("complete must be a boolean")

        if complete:
            self._state = "complete"
            self.ledger_seq = seq
            self.reason = reason.strip() if reason and reason.strip() else None
            return

        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(
                "An incomplete result requires an explanation"
            )

        self._state = "incomplete"
        self.ledger_seq = seq
        self.reason = reason.strip()

    def mark_incomplete(
        self,
        reason: str,
        ledger_seq: int | None = None,
    ) -> None:
        """Mark an item incomplete, optionally linking an actual tool call."""
        if self._state == "skipped":
            raise ValueError("A skipped item cannot be marked incomplete")

        self.reason = _require_text(reason, "reason")

        if ledger_seq is not None:
            self.ledger_seq = _validate_ledger_seq(ledger_seq)

        self._state = "incomplete"

    def skip(self, reason: str) -> None:
        """Explicitly record why a planned question was not investigated."""
        if self._state != "pending":
            raise ValueError("Only a pending item can be skipped")

        self.reason = _require_text(reason, "reason")
        self._state = "skipped"

    def finalize_pending(self) -> None:
        """Close an untouched item as incomplete before report export."""
        if self._state == "pending":
            self._state = "incomplete"
            self.reason = (
                "No completed investigation result was recorded "
                "before report finalization"
            )

    def to_plan_record(self) -> dict:
        """Export the fields required by the M5-to-M6 v3 contract."""
        return {
            "id": self.id,
            "index": self.index,
            "status": self.status,
            "ledger_seq": self.ledger_seq,
        }


class CoverageChecklist:
    """Manage unique investigation questions in insertion order."""

    def __init__(self) -> None:
        self._items: dict[str, CoverageItem] = {}

    def add(
        self,
        item_id: str,
        index: str,
        question: str,
    ) -> CoverageItem:
        item_id = _require_text(item_id, "id")

        if item_id in self._items:
            raise ValueError(f"Duplicate coverage item id: {item_id}")

        item = CoverageItem(
            id=item_id,
            index=index,
            question=question,
        )
        self._items[item.id] = item
        return item

    def get(self, item_id: str) -> CoverageItem:
        try:
            return self._items[item_id]
        except KeyError as exc:
            raise KeyError(
                f"Unknown coverage item: {item_id}"
            ) from exc

    def record_result(
        self,
        item_id: str,
        ledger_seq: int,
        complete: bool,
        reason: str | None = None,
    ) -> None:
        self.get(item_id).record_result(
            ledger_seq=ledger_seq,
            complete=complete,
            reason=reason,
        )

    def mark_incomplete(
        self,
        item_id: str,
        reason: str,
        ledger_seq: int | None = None,
    ) -> None:
        self.get(item_id).mark_incomplete(
            reason=reason,
            ledger_seq=ledger_seq,
        )

    def skip(self, item_id: str, reason: str) -> None:
        self.get(item_id).skip(reason)

    def finalize(self) -> list[dict]:
        """Ensure every planned question has a final exportable status."""
        for item in self._items.values():
            item.finalize_pending()
        return self.to_plan()

    def to_plan(self) -> list[dict]:
        return [
            item.to_plan_record()
            for item in self._items.values()
        ]

    @property
    def all_complete(self) -> bool:
        return bool(self._items) and all(
            item.state == "complete"
            for item in self._items.values()
        )

    def summary(self) -> dict[str, int]:
        states = [item.state for item in self._items.values()]
        return {
            "total": len(states),
            "complete": states.count("complete"),
            "incomplete": (
                states.count("incomplete") + states.count("pending")
            ),
            "skipped": states.count("skipped"),
            "pending": states.count("pending"),
        }
