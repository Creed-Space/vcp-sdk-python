"""VCP/S CSM1 Grammar Parser (v1.1).

CSM1 (Constitutional Safety Minicode) is a compact encoding for
constitutional configurations per VCP/S Semantics Layer Specification v2.0.

Format (ABNF):
    csm1-code     = persona adherence [scopes] [":" namespace] ["@" version]
    persona       = "N" / "Z" / "G" / "A" / "M" / "D" / "C"
    adherence     = "0" / "1" / "2" / "3" / "4" / "5"
    scopes        = 1*("+" scope-code)
    scope-code    = "F" / "W" / "P" / "E" / "T" / "O" / "V" / "A" / "H" / "S" / "R"

Examples:
    N5+F+E       - Nanny persona, level 5, Family+Education scopes
    Z4+P+T+W:SEC - Sentinel persona, level 4, Privacy+Technical+Work, SEC namespace
    M2+A         - Muse persona, level 2, Adult scope
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .token import Token


class Persona(Enum):
    """6+1 archetypal personas for constitutional profiles."""

    NANNY = "N"
    SENTINEL = "Z"
    GODPARENT = "G"
    AMBASSADOR = "A"
    MUSE = "M"
    MEDIATOR = "D"
    CUSTOM = "C"

    @classmethod
    def from_char(cls, char: str) -> Persona:
        """Get persona from single character."""
        if not isinstance(char, str) or len(char) != 1:
            raise ValueError("Persona character must be a single-character string")
        for persona in cls:
            if persona.value == char.upper():
                return persona
        raise ValueError(f"Unknown persona character: {char}")

    @classmethod
    def from_name(cls, name: str) -> Persona:
        """Get persona from lowercase name (e.g. 'nanny', 'sentinel')."""
        if not isinstance(name, str):
            raise ValueError("Persona name must be a string")
        if len(name) > 32:
            raise ValueError("Persona name exceeds maximum length 32")
        normalized_name = name.lower()
        for code, pname in PERSONA_NAMES.items():
            if pname == normalized_name:
                return cls(code)
        raise ValueError(f"Unknown persona name: {name}")

    @property
    def persona_name(self) -> str:
        """Lowercase name for this persona."""
        return PERSONA_NAMES[self.value]

    @property
    def description(self) -> str:
        """Human-readable description."""
        descriptions = {
            Persona.NANNY: "Child safety and family-appropriate content",
            Persona.SENTINEL: "Security, privacy, and operational safety",
            Persona.GODPARENT: "Ethical guidance and moral reasoning",
            Persona.AMBASSADOR: "Professional conduct and diplomatic communication",
            Persona.MUSE: "Creativity and artistic expression",
            Persona.MEDIATOR: "Fair resolution and balanced mediation",
            Persona.CUSTOM: "User-defined constitution",
        }
        return descriptions[self]


PERSONA_NAMES: dict[str, str] = {
    "N": "nanny",
    "Z": "sentinel",
    "G": "godparent",
    "A": "ambassador",
    "M": "muse",
    "D": "mediator",
    "C": "custom",
}


class Scope(Enum):
    """Context scopes for constitutional application.

    The eleven v2 CSM1 scopes are accepted on the wire.  The additional enum
    members remain import-compatible for callers that used older experimental
    vocabularies, but are deliberately rejected by :class:`CSM1Code`.
    """

    FAMILY = "F"
    WORK = "W"
    PRIVACY = "P"
    EDUCATION = "E"
    TECHNICAL = "T"
    OFFICIAL = "O"
    VULNERABLE = "V"
    ADULT = "A"
    HEALTHCARE = "H"
    SOCIAL = "S"
    RELIGIOUS = "R"
    BODILY = "B"  # Physical safety, force limits, movement constraints (VCP-E)
    SPATIAL = "X"  # Spatial/proximity governance, zone awareness (VCP-E)

    # Deprecated pre-v2.0 scopes (kept for backward compat)
    FINANCE = "I"
    LEGAL = "L"
    GENERAL = "G"

    @classmethod
    def from_char(cls, char: str) -> Scope:
        """Get scope from single character."""
        if not isinstance(char, str) or len(char) != 1:
            raise ValueError("Scope character must be a single-character string")
        for scope in cls:
            if scope.value == char.upper():
                return scope
        raise ValueError(f"Unknown scope character: {char}")

    @property
    def is_deprecated(self) -> bool:
        """Whether this scope is deprecated (pre-v2.0)."""
        return self in _DEPRECATED_SCOPES

    @property
    def description(self) -> str:
        """Human-readable description."""
        descriptions = {
            Scope.FAMILY: "Family-appropriate, child-safe",
            Scope.WORK: "Professional workplace",
            Scope.PRIVACY: "Privacy-focused, data protection",
            Scope.EDUCATION: "Educational context",
            Scope.TECHNICAL: "Developer/technical context",
            Scope.OFFICIAL: "Official/governmental",
            Scope.VULNERABLE: "Vulnerable populations",
            Scope.ADULT: "Adult-only, explicit allowed",
            Scope.HEALTHCARE: "Healthcare/medical",
            Scope.SOCIAL: "Social media/community",
            Scope.RELIGIOUS: "Religious/spiritual",
            Scope.BODILY: "Physical safety, force limits, movement constraints",
            Scope.SPATIAL: "Spatial/proximity governance, zone awareness",
            Scope.FINANCE: "Financial and investment (deprecated)",
            Scope.LEGAL: "Legal and compliance (deprecated)",
            Scope.GENERAL: "General purpose (deprecated)",
        }
        return descriptions[self]


_DEPRECATED_SCOPES = frozenset({Scope.FINANCE, Scope.LEGAL, Scope.GENERAL})

V2_SCOPE_CHARS = frozenset("FWPETOVAHSR")
ALL_SCOPE_CHARS = frozenset("FWPETOVAHSRBXILG")

SCOPE_CONFLICTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("F", "A"),  # Family and Adult are mutually exclusive
        ("V", "A"),  # Vulnerable and Adult conflict
        ("H", "A"),  # Health contexts should not be adult-only
    }
)

SCOPE_SYNERGIES: frozenset[tuple[str, str]] = frozenset(
    {
        ("F", "E"),  # Family + Education = child learning
        ("W", "P"),  # Work + Privacy = corporate data protection
        ("H", "P"),  # Health + Privacy = HIPAA-compliant
        ("E", "T"),  # Education + Technical = coding education
    }
)


def check_scope_conflicts(scopes: list[Scope]) -> list[tuple[Scope, Scope]]:
    """Return list of conflicting scope pairs found in the given scopes."""
    if not isinstance(scopes, list):
        raise ValueError("scopes must be a list of Scope values")
    if len(scopes) > len(V2_SCOPE_CHARS):
        raise ValueError(f"scopes must contain at most {len(V2_SCOPE_CHARS)} values")
    if not all(isinstance(scope, Scope) for scope in scopes):
        raise ValueError("scopes must be a list of Scope values")
    codes = {s.value for s in scopes}
    conflicts: list[tuple[Scope, Scope]] = []
    for a, b in SCOPE_CONFLICTS:
        if a in codes and b in codes:
            conflicts.append((Scope.from_char(a), Scope.from_char(b)))
    return conflicts


ADHERENCE_BEHAVIORS: dict[int, dict[str, str]] = {
    0: {
        "enforcement": "advisory",
        "user_override": "always",
        "warning_level": "none",
        "block_threshold": "never",
        "logging": "minimal",
    },
    1: {
        "enforcement": "soft",
        "user_override": "with_acknowledgment",
        "warning_level": "gentle",
        "block_threshold": "extreme_harm_only",
        "logging": "basic",
    },
    2: {
        "enforcement": "moderate",
        "user_override": "with_reason",
        "warning_level": "clear",
        "block_threshold": "harmful_content",
        "logging": "standard",
    },
    3: {
        "enforcement": "active",
        "user_override": "limited_scenarios",
        "warning_level": "prominent",
        "block_threshold": "policy_violation",
        "logging": "detailed",
    },
    4: {
        "enforcement": "strict",
        "user_override": "exceptional_only",
        "warning_level": "explicit",
        "block_threshold": "any_risk",
        "logging": "comprehensive",
    },
    5: {
        "enforcement": "absolute",
        "user_override": "never",
        "warning_level": "blocking",
        "block_threshold": "proactive",
        "logging": "full_audit",
    },
}

PERSONA_PROFILES: dict[str, dict[str, Any]] = {
    "N": {
        "name": "Nanny",
        "focus": "Child safety and family-appropriate content",
        "default_adherence": 5,
        "compatible_scopes": ["F", "E", "V"],
        "incompatible_scopes": ["A"],
    },
    "Z": {
        "name": "Sentinel",
        "focus": "Security, privacy, and operational safety",
        "default_adherence": 4,
        "compatible_scopes": ["P", "W", "T", "O"],
        "incompatible_scopes": [],
    },
    "G": {
        "name": "Godparent",
        "focus": "Ethical guidance and moral reasoning",
        "default_adherence": 4,
        "compatible_scopes": ["R", "E", "S"],
        "incompatible_scopes": [],
    },
    "A": {
        "name": "Ambassador",
        "focus": "Professional conduct and diplomatic communication",
        "default_adherence": 3,
        "compatible_scopes": ["W", "O", "S"],
        "incompatible_scopes": ["A"],
    },
    "M": {
        "name": "Muse",
        "focus": "Creativity and artistic expression",
        "default_adherence": 2,
        "compatible_scopes": ["A", "E"],
        "incompatible_scopes": ["O"],
    },
    "D": {
        "name": "Mediator",
        "focus": "Fair resolution and balanced mediation",
        "default_adherence": 3,
        "compatible_scopes": ["S", "E", "W", "O"],
        "incompatible_scopes": [],
    },
    "C": {
        "name": "Custom",
        "focus": "User-defined constitution",
        "default_adherence": 3,
        "compatible_scopes": [],
        "incompatible_scopes": [],
        "requires_namespace": True,
    },
}


@dataclass
class CSM1Code:
    """Parsed CSM1 constitutional code.

    Supports NANO, MICRO, and COMPACT encoding tiers.  ``token`` is the UVC
    identity carried by the COMPACT tier; NANO/MICRO codes leave it ``None``.
    """

    persona: Persona
    adherence_level: int  # 0-5
    scopes: list[Scope] = field(default_factory=list)
    namespace: str | None = None
    version: str | None = None
    token: str | None = None

    PATTERN = re.compile(
        r"^(?P<persona>[NZGAMDC])"
        r"(?P<level>[0-5])"
        r"(?P<scopes>(?:\+[FWPETOVAHSR])*)"
        r"(?::(?P<namespace>[A-Z]{1,8}))?"
        r"(?:@(?P<version>"
        r"(?:(?:0|[1-9]\d{0,2})\.(?:0|[1-9]\d{0,2})\.(?:0|[1-9]\d{0,2}))"
        r"|latest"
        r"|canary"
        r"))?\Z"
    )

    COMPACT_PATTERN = re.compile(r"CS1\|([a-z]+)\|([0-5])\|([^|]{1,255})\|([FWPETOVAHSR](?:,[FWPETOVAHSR])*)\Z")
    # Spec §2.8 bounds: MICRO codes are 2-45 characters, COMPACT codes 18-294.
    MAX_MICRO_LENGTH = 45
    MAX_COMPACT_LENGTH = 294

    def __post_init__(self) -> None:
        if not isinstance(self.persona, Persona):
            raise ValueError("persona must be a Persona")
        if isinstance(self.adherence_level, bool) or not isinstance(self.adherence_level, int):
            raise ValueError("adherence level must be an integer 0-5")
        if not 0 <= self.adherence_level <= 5:
            raise ValueError("adherence level must be 0-5")
        if not isinstance(self.scopes, list):
            raise ValueError("scopes must be a list of Scope values")
        if len(self.scopes) > len(V2_SCOPE_CHARS):
            raise ValueError(f"scopes must contain at most {len(V2_SCOPE_CHARS)} values")
        if not all(isinstance(scope, Scope) for scope in self.scopes):
            raise ValueError("scopes must be a list of Scope values")
        if any(scope.value not in V2_SCOPE_CHARS for scope in self.scopes):
            raise ValueError("CSM1 wire codes accept only the v2 scope vocabulary")
        if len(self.scopes) != len(set(self.scopes)):
            raise ValueError("CSM1 scopes must be unique")
        conflicts = check_scope_conflicts(self.scopes)
        if conflicts:
            rendered = ", ".join(f"{left.value}+{right.value}" for left, right in conflicts)
            raise ValueError(f"CSM1 contains mutually exclusive scopes: {rendered}")
        if self.token is not None:
            if not isinstance(self.token, str):
                raise ValueError("token must be a string")
            Token.parse(self.token)
        # COMPACT codes carry the custom identity in the UVC token rather than
        # in a namespace field (spec §2.8.3: CS1|custom|3|company.acme.legal|O,W).
        if self.persona is Persona.CUSTOM and not self.namespace and not self.token:
            raise ValueError("Custom persona requires a namespace")
        if self.namespace is not None and (
            not isinstance(self.namespace, str) or re.fullmatch(r"[A-Z]{1,8}", self.namespace) is None
        ):
            raise ValueError("Namespace must be 1-8 uppercase letters")
        if self.version is not None and (
            not isinstance(self.version, str)
            or re.fullmatch(
                r"(?:(?:0|[1-9]\d{0,2})\.(?:0|[1-9]\d{0,2})\.(?:0|[1-9]\d{0,2})|latest|canary)",
                self.version,
            )
            is None
        ):
            raise ValueError("Invalid CSM1 version")
        if len(self.encode()) > self.MAX_MICRO_LENGTH:
            raise ValueError(f"CSM1 code exceeds maximum length {self.MAX_MICRO_LENGTH}")

    @classmethod
    def parse(cls, raw: str) -> CSM1Code:
        """Parse CSM1 code string in any tier format.

        Supports NANO (N5+F+E), MICRO (N5+F:ELEM@1.2.0), and
        COMPACT (CS1|nanny|5|family.safe.guide|F,E) formats.
        """
        if not isinstance(raw, str) or not raw:
            raise ValueError("CSM1 code cannot be empty")
        if raw.startswith("CS1|"):
            if len(raw) > cls.MAX_COMPACT_LENGTH:
                raise ValueError(f"CSM1 code exceeds maximum length {cls.MAX_COMPACT_LENGTH}")
            return cls._parse_compact(raw)
        if len(raw) > cls.MAX_MICRO_LENGTH:
            raise ValueError(f"CSM1 code exceeds maximum length {cls.MAX_MICRO_LENGTH}")

        match = cls.PATTERN.fullmatch(raw)
        if not match:
            raise ValueError(f"Invalid CSM1 code: {raw}")

        groups = match.groupdict()
        persona = Persona.from_char(groups["persona"])
        level = int(groups["level"])

        scopes: list[Scope] = []
        if groups["scopes"]:
            scope_chars = groups["scopes"].replace("+", "")
            scopes = [Scope.from_char(c) for c in scope_chars]

        version_raw = groups.get("version")
        if version_raw is not None:
            version_raw = version_raw.lower()

        return cls(
            persona=persona,
            adherence_level=level,
            scopes=scopes,
            namespace=groups.get("namespace"),
            version=version_raw,
        )

    @classmethod
    def _parse_compact(cls, raw: str) -> CSM1Code:
        """Parse COMPACT format: CS1|nanny|5|family.safe.guide|F,E"""
        match = cls.COMPACT_PATTERN.fullmatch(raw)
        if not match:
            raise ValueError(f"Invalid COMPACT CSM1 code: {raw}")

        persona_name = match.group(1).lower()
        adherence = int(match.group(2))
        token = Token.parse(match.group(3))
        scope_str = match.group(4)

        persona = Persona.from_name(persona_name)
        scopes = [Scope.from_char(s) for s in scope_str.split(",") if s]

        return cls(
            persona=persona,
            adherence_level=adherence,
            scopes=scopes,
            namespace=token.namespace,
            token=token.full,
        )

    def encode(self) -> str:
        """Encode to the canonical wire form (e.g. 'N5+E+F').

        Scopes are emitted in sorted order per spec §2.10.1, so codes built
        from the same fields compare equal as strings regardless of the order
        the scopes were given in.  ``to_nano``/``to_micro`` preserve input order.
        """
        return self.to_canonical()

    def to_nano(self) -> str:
        """Serialize to NANO format (persona + adherence + scopes only)."""
        scopes = "".join(f"+{s.value}" for s in self.scopes)
        return f"{self.persona.value}{self.adherence_level}{scopes}"

    def to_micro(self) -> str:
        """Serialize to MICRO format (with namespace and version)."""
        base = f"{self.persona.value}{self.adherence_level}"
        scopes = "".join(f"+{s.value}" for s in self.scopes)
        result = base + scopes
        if self.namespace:
            result += f":{self.namespace}"
        if self.version:
            result += f"@{self.version}"
        return result

    def to_compact(self, uvc_token: str) -> str:
        """Serialize to COMPACT format."""
        token = Token.parse(uvc_token).full
        scope_list = ",".join(s.value for s in self.scopes)
        if not scope_list:
            raise ValueError("COMPACT CSM1 requires at least one scope")
        compact = f"CS1|{self.persona.persona_name}|{self.adherence_level}|{token}|{scope_list}"
        if len(compact) > self.MAX_COMPACT_LENGTH:
            raise ValueError(f"CSM1 code exceeds maximum length {self.MAX_COMPACT_LENGTH}")
        return compact

    def to_canonical(self) -> str:
        """Canonical form for hashing/comparison (sorted scopes)."""
        sorted_scopes = sorted(self.scopes, key=lambda s: s.value)
        result = f"{self.persona.value}{self.adherence_level}"
        result += "".join(f"+{s.value}" for s in sorted_scopes)
        if self.namespace:
            result += f":{self.namespace.upper()}"
        if self.version:
            result += f"@{self.version}"
        return result

    def get_conflicts(self) -> list[tuple[Scope, Scope]]:
        """Return any scope conflicts in this code."""
        return check_scope_conflicts(self.scopes)

    def __str__(self) -> str:
        return self.encode()

    def __repr__(self) -> str:
        return f"CSM1Code({self.encode()!r})"
