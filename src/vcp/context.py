"""VCP Context encoding and decoding.

Encode and decode the 18 VCP context dimensions (13 situational + 5 personal)
for portable context propagation across AI agent sessions and platforms.

Per VEP-0004 (2026-04-17), four new situational dimensions were added to the
canonical 9: EMBODIMENT, PROXIMITY, RELATIONSHIP, and FORMALITY. Extended support
is advertised via capability token ``vcp-a-ext-v1``.

    >>> from vcp import Context
    >>> ctx = Context(space="hospital", agency="peer", constraints=["legal"])
    >>> ctx.to_wire()
    '📍hospital|🎯peer|🔒legal'
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

        Situational dims separated by ``|``, personal after ``||``.
        """
        parts: list[str] = []
        for dim, symbol in _SITUATIONAL_SYMBOLS.items():
            val = getattr(self, dim, None)
            if val is not None:
                if isinstance(val, list):
                    val = "+".join(val)
                parts.append(f"{symbol}{val}")
        wire = "|".join(parts) if parts else ""

        personal_parts: list[str] = []
        for dim, symbol in _PERSONAL_SYMBOLS.items():
            val = getattr(self, dim, None)
            if val is not None:
                intensity = getattr(self, f"{dim}_intensity", None)
                suffix = str(intensity) if intensity else ""
                personal_parts.append(f"{symbol}{val}{suffix}")
        if personal_parts:
            personal = "".join(personal_parts)
            wire = f"{wire}||{personal}" if wire else personal
        return wire

    def to_session_metadata(self) -> dict[str, str]:
        """Encode for AI agent session metadata (string key-value pairs)."""
        return {
            "vcp_wire": self.to_wire(),
            "vcp_version": self.version,
            "vcp_context": json.dumps(self.to_dict()),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Context:
        """Reconstruct from a serialized dict."""
        kwargs: dict[str, Any] = {}
        for dim in SITUATIONAL_DIMENSIONS:
            if dim in data:
                kwargs[dim] = data[dim]
        for dim in PERSONAL_DIMENSIONS:
            if dim in data:
                val = data[dim]
                if isinstance(val, dict):
                    kwargs[dim] = val.get("category")
                    if "intensity" in val:
                        kwargs[f"{dim}_intensity"] = val["intensity"]
                elif isinstance(val, str):
                    kwargs[dim] = val
        kwargs["version"] = data.get("version", "3.2")
        return cls(**kwargs)

    @classmethod
    def from_session_metadata(cls, metadata: dict[str, str]) -> Context | None:
        """Reconstruct from AI agent session metadata. Returns None if absent."""
        raw = metadata.get("vcp_context")
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None
        return cls.from_dict(data)

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
