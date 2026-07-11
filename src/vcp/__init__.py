"""VCP SDK — Value Context Protocol for portable AI ethics.

Validate tokens, parse CSM1 codes, and work with VCP-Lite definitions.

    >>> from vcp import Token, CSM1Code, validate_lite
    >>> token = Token.parse("family.safe.guide@1.0.0")
    >>> code = CSM1Code.parse("N5+F+E")
    >>> errors = validate_lite({"vcp_version": "lite-1.0", ...})
"""

from .context import Context
from .csm1 import (
    ADHERENCE_BEHAVIORS,
    PERSONA_NAMES,
    SCOPE_CONFLICTS,
    SCOPE_SYNERGIES,
    V2_SCOPE_CHARS,
    CSM1Code,
    Persona,
    Scope,
    check_scope_conflicts,
)
from .lite import lite_to_csm1, lite_to_token, validate_lite
from .token import Token, canonicalize_token, tokens_equal, uri_to_canonical

__all__ = [
    # Context (v0.2.0)
    "Context",
    # Token
    "Token",
    "canonicalize_token",
    "tokens_equal",
    "uri_to_canonical",
    # CSM1
    "CSM1Code",
    "Persona",
    "Scope",
    "PERSONA_NAMES",
    "V2_SCOPE_CHARS",
    "SCOPE_CONFLICTS",
    "SCOPE_SYNERGIES",
    "ADHERENCE_BEHAVIORS",
    "check_scope_conflicts",
    # Lite
    "validate_lite",
    "lite_to_csm1",
    "lite_to_token",
]

__version__ = "0.4.0"
