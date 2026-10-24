"""Normalize actual model token-usage metadata for M5 run exports."""

from collections.abc import Mapping
from typing import Any


_ALIASES = {
    "input_tokens": ("input_tokens", "prompt_tokens"),
    "output_tokens": ("output_tokens", "completion_tokens"),
    "total_tokens": ("total_tokens",),
}


def _read_field(usage: Any, name: str) -> Any:
    """Read a usage counter from a mapping or an object."""
    if isinstance(usage, Mapping):
        return usage.get(name)
    return getattr(usage, name, None)


def normalize_model_usage(
    usage: Any,
) -> dict[str, int] | None:
    """Normalize actual token counters; never invent missing values."""
    if usage is None:
        return None

    normalized: dict[str, int] = {}

    for canonical_name, aliases in _ALIASES.items():
        values: list[int] = []

        for alias in aliases:
            value = _read_field(usage, alias)

            if value is None:
                continue

            if type(value) is not int or value < 0:
                raise ValueError(
                    f"{alias} must be a non-negative integer"
                )

            values.append(value)

        if not values:
            continue

        if len(set(values)) > 1:
            raise ValueError(
                f"Conflicting values for {canonical_name}"
            )

        normalized[canonical_name] = values[0]

    return normalized or None