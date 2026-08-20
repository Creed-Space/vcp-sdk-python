"""Strict JSON decoding for load-bearing VCP documents."""

from __future__ import annotations

import json
from typing import Any


class DuplicateJSONKey(ValueError):
    """Raised when an object repeats a key and therefore has ambiguous meaning."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKey(f"duplicate key {key!r}")
        result[key] = value
    return result


def loads_strict(document: str | bytes) -> Any:
    """Decode JSON while rejecting duplicate object keys."""
    return json.loads(document, object_pairs_hook=_unique_object)
