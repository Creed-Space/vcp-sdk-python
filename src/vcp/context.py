"""VCP Context encoding and decoding.

Encode and decode the 18 VCP context dimensions (13 situational + 5 personal)
for portable context propagation across AI agent sessions and platforms.

Per VEP-0004 (2026-04-17), four new situational dimensions were added to the
canonical 9: EMBODIMENT, PROXIMITY, RELATIONSHIP, and FORMALITY. Extended support
is advertised via capability token ``vcp-a-ext-v1``.

    >>> from vcp import Context
    >>> ctx = Context(space="hospital", agency="peer", constraints=["legal"])
    >>> ctx.to_wire()
    '📍🏥|🎯🤝|🔒⚖️'
    >>> ctx.to_dict()
    {'space': 'hospital', 'agency': 'peer', 'constraints': ['legal'], 'version': '3.2'}

    >>> # Embodied-AI example (VEP-0004)
    >>> ctx = Context(
    ...     space="hospital",
    ...     embodiment="manipulating",
    ...     proximity="close",
    ...     relationship="colleague:professional",
    ...     formality="professional",
    ... )

For Managed Agents integration:
    >>> metadata = ctx.to_session_metadata()
    >>> restored = Context.from_session_metadata(metadata)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ._json import loads_strict

# Emoji symbols for wire format
# Canonical 9 situational dimensions (VCP/A v2.0)
# Plus VEP-0004 dimensions: EMBODIMENT, PROXIMITY, RELATIONSHIP, FORMALITY
_SITUATIONAL_SYMBOLS: dict[str, str] = {
    "time": "\U0001f550",  # clock
    "space": "\U0001f4cd",  # pin
    "company": "\U0001f465",  # people
    "culture": "\U0001f30d",  # globe
    "occasion": "\U0001f4c5",  # calendar
    "environment": "\U0001f324",  # sun
    "agency": "\U0001f3af",  # target
    "constraints": "\U0001f512",  # lock
    "system_context": "\U0001f4e1",  # satellite antenna
    # VEP-0004 extended dimensions
    "embodiment": "\U0001f9cd",  # 🧍 person standing
    "proximity": "\u2194\ufe0f",  # ↔️ left-right arrow
    "relationship": "\U0001faa2",  # 🪢 knot
    "formality": "\U0001f3a9",  # 🎩 top hat
}

_PERSONAL_SYMBOLS: dict[str, str] = {
    "cognitive_state": "\U0001f9e0",  # brain
    "emotional_tone": "\U0001f4ad",  # thought
    "energy_level": "\U0001f50b",  # battery
    "perceived_urgency": "\u26a1",  # lightning
    "body_signals": "\U0001fa7a",  # stethoscope
}

PERSONAL_SEPARATOR = "\u2016"  # ‖, normative VCP/A band separator
DIMENSION_SEPARATOR = "|"
INTENSITY_SEPARATOR = ":"
MAX_CONTEXT_VALUE_LENGTH = 4096
MAX_MULTI_VALUES = 64
MAX_SESSION_METADATA_BYTES = 4 * 1024 * 1024

# Canonical value symbols from VCP/A v3.2. Unknown, well-formed strings are
# retained verbatim for forward compatibility, while known values produce the
# interoperable wire representation used by the main SDK.
_SITUATIONAL_VALUE_SYMBOLS: dict[str, dict[str, str]] = {
    "time": {"morning": "🌅", "midday": "☀️", "evening": "🌆", "night": "🌙"},
    "space": {
        "home": "🏡",
        "office": "🏢",
        "school": "🏫",
        "hospital": "🏥",
        "transit": "🚗",
    },
    "company": {
        "alone": "👤",
        "children": "👶",
        "colleagues": "👔",
        "family": "👨‍👩‍👧",
        "strangers": "👥",
    },
    "culture": {
        "high_context": "🔇",
        "low_context": "📢",
        "formal": "🎩",
        "casual": "😎",
        "mixed": "🌐",
    },
    "occasion": {
        "normal": "➖",
        "celebration": "🎂",
        "mourning": "😢",
        "emergency": "🚨",
        "business": "💼",
    },
    "environment": {
        "comfortable": "☀️",
        "hot": "🥵",
        "cold": "🥶",
        "quiet": "🔇",
        "noisy": "🔊",
    },
    "agency": {"leader": "👑", "peer": "🤝", "subordinate": "📋", "limited": "🔐"},
    "constraints": {"minimal": "○", "legal": "⚖️", "economic": "💸", "time": "⏱️"},
    "system_context": {
        "online": "🟢",
        "degraded": "🟡",
        "offline": "🔴",
        "sandboxed": "🔒",
        "testing": "🧪",
    },
    "embodiment": {
        "stationary": "🪑",
        "navigating": "🚶",
        "manipulating": "✋",
        "carrying": "📦",
        "emergency_stop": "🛑",
    },
    "proximity": {
        "distant": "🌐",
        "same_room": "🏠",
        "nearby": "👣",
        "close": "🤏",
        "contact": "👆",
    },
    "formality": {
        "casual": "😎",
        "professional": "💼",
        "formal": "🎓",
        "ceremonial": "🏛️",
    },
}

SITUATIONAL_DIMENSIONS = (
    "time",
    "space",
    "company",
    "culture",
    "occasion",
    "environment",
    "agency",
    "constraints",
    "system_context",
    # VEP-0004 extended dimensions (order fixed per spec §2.5)
    "embodiment",
    "proximity",
    "relationship",
    "formality",
)

PERSONAL_DIMENSIONS = (
    "cognitive_state",
    "emotional_tone",
    "energy_level",
    "perceived_urgency",
    "body_signals",
)

# VEP-0004 canonical value vocabularies (for validation helpers)
EMBODIMENT_VALUES = (
    "stationary",
    "navigating",
    "manipulating",
    "carrying",
    "emergency_stop",
)
PROXIMITY_VALUES = (
    "distant",
    "same_room",
    "nearby",
    "close",
    "contact",
)
FORMALITY_VALUES = (
    "casual",
    "professional",
    "formal",
    "ceremonial",
)
# RELATIONSHIP is compound "{tie}:{function}"; components below
RELATIONSHIP_TIES = (
    "stranger",
    "acquaintance",
    "colleague",
    "friend",
    "family",
    "intimate",
    "long_term",
    "trusted_collaborator",
)
RELATIONSHIP_FUNCTIONS = (
    "transactional",
    "professional",
    "educational",
    "therapeutic",
    "social",
    "intimate",
    "adversarial",
)


@dataclass
class Context:
    """VCP 3.2 context with 18 dimensions (VEP-0004).

    Situational (13): time, space, company, culture, occasion, environment,
                      agency, constraints, system_context, embodiment, proximity,
                      relationship, formality
    Personal (5):     cognitive_state, emotional_tone, energy_level,
                      perceived_urgency, body_signals (each with optional 1-5 intensity)

    VEP-0004 dimensions (embodiment, proximity, relationship, formality) are
    optional. Implementations MAY omit them from wire encodings when at default
    or unknown. Receivers MUST treat absent dimensions as "no information".
    Advertise support via capability token ``vcp-a-ext-v1`` (see VEP-0002).
    """

    # Canonical situational (9)
    time: str | None = None
    space: str | None = None
    company: str | list[str] | None = None
    culture: str | None = None
    occasion: str | None = None
    environment: str | None = None
    agency: str | None = None
    constraints: str | list[str] | None = None
    system_context: str | None = None

    # VEP-0004 extended situational (4)
    embodiment: str | None = None
    proximity: str | None = None
    relationship: str | None = None  # Compound "{tie}:{function}"
    formality: str | None = None

    # Personal (category + optional intensity)
    cognitive_state: str | None = None
    cognitive_state_intensity: int | None = None
    emotional_tone: str | None = None
    emotional_tone_intensity: int | None = None
    energy_level: str | None = None
    energy_level_intensity: int | None = None
    perceived_urgency: str | None = None
    perceived_urgency_intensity: int | None = None
    body_signals: str | None = None
    body_signals_intensity: int | None = None

    version: str = "3.2"

    def __post_init__(self) -> None:
        for dim in SITUATIONAL_DIMENSIONS:
            value = getattr(self, dim)
            if value is None:
                continue
            if dim in {"company", "constraints"} and isinstance(value, list):
                if not value or len(value) > MAX_MULTI_VALUES:
                    raise ValueError(f"{dim} must contain 1-{MAX_MULTI_VALUES} values")
                for item in value:
                    self._validate_wire_value(dim, item)
                setattr(self, dim, list(value))
            else:
                self._validate_wire_value(dim, value)

        for dim in PERSONAL_DIMENSIONS:
            value = getattr(self, dim)
            intensity = getattr(self, f"{dim}_intensity")
            if value is not None:
                self._validate_wire_value(dim, value)
            if intensity is not None:
                if value is None:
                    raise ValueError(f"{dim}_intensity requires {dim}")
                if isinstance(intensity, bool) or not isinstance(intensity, int) or not 1 <= intensity <= 5:
                    raise ValueError(f"{dim}_intensity must be an integer 1-5")

        if not isinstance(self.version, str) or not self.version or len(self.version) > 32:
            raise ValueError("version must be a non-empty string of at most 32 characters")

    @staticmethod
    def _validate_wire_value(dimension: str, value: Any) -> None:
        if not isinstance(value, str) or not value:
            raise ValueError(f"{dimension} must be a non-empty string")
        if len(value) > MAX_CONTEXT_VALUE_LENGTH:
            raise ValueError(f"{dimension} exceeds maximum length {MAX_CONTEXT_VALUE_LENGTH}")
        if DIMENSION_SEPARATOR in value or PERSONAL_SEPARATOR in value:
            raise ValueError(f"{dimension} contains a reserved wire separator")
        if dimension in PERSONAL_DIMENSIONS and INTENSITY_SEPARATOR in value:
            raise ValueError(f"{dimension} contains the reserved intensity separator")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError(f"{dimension} contains a control character")

    @staticmethod
    def _encode_situational_value(dimension: str, value: str) -> str:
        mapping = _SITUATIONAL_VALUE_SYMBOLS.get(dimension, {})
        if value in mapping.values():
            return value
        return mapping.get(value.lower(), value)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict, omitting None values."""
        result: dict[str, Any] = {}
        for dim in SITUATIONAL_DIMENSIONS:
            val = getattr(self, dim, None)
            if val is not None:
                result[dim] = val
        for dim in PERSONAL_DIMENSIONS:
            val = getattr(self, dim, None)
            if val is not None:
                entry: dict[str, Any] = {"category": val}
                intensity = getattr(self, f"{dim}_intensity", None)
                if intensity is not None:
                    entry["intensity"] = intensity
                result[dim] = entry
        result["version"] = self.version
        return result

    def to_wire(self) -> str:
        """Encode to compact wire format (emoji-based).

        Situational dimensions are separated by ``|``. The personal band starts
        after the normative U+2016 ``‖`` separator; intensity uses ``:``.
        """
        parts: list[str] = []
        for dim, symbol in _SITUATIONAL_SYMBOLS.items():
            val = getattr(self, dim, None)
            if val is not None:
                if isinstance(val, list):
                    encoded = "".join(self._encode_situational_value(dim, item) for item in val)
                else:
                    encoded = self._encode_situational_value(dim, val)
                parts.append(f"{symbol}{encoded}")
        wire = DIMENSION_SEPARATOR.join(parts) if parts else ""

        personal_parts: list[str] = []
        for dim, symbol in _PERSONAL_SYMBOLS.items():
            val = getattr(self, dim, None)
            if val is not None:
                intensity = getattr(self, f"{dim}_intensity", None)
                suffix = f"{INTENSITY_SEPARATOR}{intensity}" if intensity is not None else ""
                personal_parts.append(f"{symbol}{val}{suffix}")
        if personal_parts:
            personal = DIMENSION_SEPARATOR.join(personal_parts)
            wire = f"{wire}{PERSONAL_SEPARATOR}{personal}" if wire else f"{PERSONAL_SEPARATOR}{personal}"
        return wire

    def to_session_metadata(self) -> dict[str, str]:
        """Encode for AI agent session metadata (string key-value pairs)."""
        return {
            "vcp_wire": self.to_wire(),
            "vcp_version": self.version,
            "vcp_context": json.dumps(self.to_dict(), ensure_ascii=False),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Context:
        """Reconstruct from a serialized dict."""
        if not isinstance(data, dict):
            raise ValueError("context data must be an object")
        allowed_fields = {*SITUATIONAL_DIMENSIONS, *PERSONAL_DIMENSIONS, "version"}
        unknown_fields = set(data) - allowed_fields
        if unknown_fields:
            raise ValueError(f"context data contains unknown fields: {sorted(unknown_fields)}")
        kwargs: dict[str, Any] = {}
        for dim in SITUATIONAL_DIMENSIONS:
            if dim in data:
                kwargs[dim] = data[dim]
        for dim in PERSONAL_DIMENSIONS:
            if dim in data:
                val = data[dim]
                if isinstance(val, dict):
                    unknown_personal_fields = set(val) - {"category", "intensity"}
                    if unknown_personal_fields:
                        raise ValueError(f"{dim} contains unknown fields: {sorted(unknown_personal_fields)}")
                    if not isinstance(val.get("category"), str):
                        raise ValueError(f"{dim}.category must be a string")
                    kwargs[dim] = val["category"]
                    if "intensity" in val:
                        kwargs[f"{dim}_intensity"] = val["intensity"]
                elif isinstance(val, str):
                    kwargs[dim] = val
                else:
                    raise ValueError(f"{dim} must be a string or an object")
        kwargs["version"] = data.get("version", "3.2")
        return cls(**kwargs)

    @classmethod
    def from_session_metadata(cls, metadata: dict[str, str]) -> Context | None:
        """Reconstruct from AI agent session metadata. Returns None if absent."""
        if not isinstance(metadata, dict):
            return None
        raw = metadata.get("vcp_context")
        if not isinstance(raw, str) or not raw:
            return None
        if len(raw) > MAX_SESSION_METADATA_BYTES or len(raw.encode("utf-8")) > MAX_SESSION_METADATA_BYTES:
            return None
        try:
            data = loads_strict(raw)
            if not isinstance(data, dict):
                return None
            return cls.from_dict(data)
        except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
            return None

    def to_natural_language(self) -> str:
        """Convert to a human-readable context description."""
        lines: list[str] = []
        if self.space:
            lines.append(f"Setting: {self.space}")
        if self.agency:
            lines.append(f"Role: {self.agency}")
        if self.occasion:
            lines.append(f"Occasion: {self.occasion}")
        if self.constraints:
            c = self.constraints if isinstance(self.constraints, str) else ", ".join(self.constraints)
            lines.append(f"Constraints: {c}")
        if self.company:
            c = self.company if isinstance(self.company, str) else ", ".join(self.company)
            lines.append(f"Present: {c}")
        if self.relationship:
            lines.append(f"Relationship: {self.relationship}")
        if self.formality:
            lines.append(f"Register: {self.formality}")
        if self.embodiment and self.embodiment != "stationary":
            lines.append(f"Motor state: {self.embodiment}")
        if self.proximity:
            lines.append(f"Proximity: {self.proximity}")
        if self.perceived_urgency:
            lines.append(f"Urgency: {self.perceived_urgency}")
        if self.cognitive_state:
            lines.append(f"State: {self.cognitive_state}")
        return "; ".join(lines) if lines else ""
