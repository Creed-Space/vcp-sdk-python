"""Protocol operations shared by the MCP server and the ``vcp`` CLI.

Each function takes plain arguments and returns a plain JSON-serialisable
dict. The MCP tools serialise the dict; the CLI prints it. Keeping the shaping
here means the two surfaces cannot drift apart — a field added for one is
present in the other.

Nothing here imports ``mcp``, so the CLI works without the ``[mcp]`` extra.
"""

from __future__ import annotations

from typing import Any

from . import __version__
from ._schwartz_classifier import HIGHER_ORDER_MAPPING, classify_principle, detect_tensions
from .context import PERSONAL_DIMENSIONS, SITUATIONAL_DIMENSIONS, Context
from .csm1 import CSM1Code, Persona
from .lite import lite_to_csm1 as _lite_to_csm1
from .lite import lite_to_token as _lite_to_token
from .lite import validate_lite as _validate_lite
from .token import Token

VCP_SPEC_VERSION = "2.0.0"
VCP_CONTEXT_VERSION = "3.2"
VCP_LITE_VERSION = "lite-1.0"

#: Tool names the MCP server exposes; also what ``vcp status`` reports.
TOOL_NAMES = (
    "vcp_status",
    "vcp_validate_token",
    "vcp_parse_csm1",
    "vcp_encode_context",
    "vcp_validate_lite",
    "vcp_lite_to_csm1",
    "creed_classify_principle",
)

#: Context dimensions that accept multiple values.
MULTI_VALUE_DIMENSIONS = ("company", "constraints")

#: Confidence at or above which a Schwartz classification is worth trusting
#: without inspecting the runner-up candidates.
CLASSIFY_CONFIDENCE_THRESHOLD = 0.7


def validate_token(token: str) -> dict[str, Any]:
    """Parse a VCP/I identity token into its components."""
    try:
        parsed = Token.parse(token)
    except ValueError as e:
        return {"valid": False, "error": str(e)}

    return {
        "valid": True,
        "canonical": parsed.canonical,
        "full": parsed.full,
        "domain": parsed.domain,
        "approach": parsed.approach,
        "role": parsed.role,
        "segments": list(parsed.segments),
        "depth": parsed.depth,
        "version": parsed.version,
        "namespace": parsed.namespace,
        "uri": parsed.to_uri(),
    }


def parse_csm1(code: str) -> dict[str, Any]:
    """Parse a CSM1 constitutional code, reporting scopes and scope conflicts."""
    try:
        parsed = CSM1Code.parse(code)
    except ValueError as e:
        return {"valid": False, "error": str(e)}

    return {
        "valid": True,
        "persona": parsed.persona.name,
        "persona_name": parsed.persona.persona_name,
        "persona_description": parsed.persona.description,
        "adherence_level": parsed.adherence_level,
        "scopes": [s.name for s in parsed.scopes],
        "scope_descriptions": {s.name: s.description for s in parsed.scopes},
        "deprecated_scopes": [s.name for s in parsed.scopes if s.is_deprecated],
        "conflicts": [[a.name, b.name] for a, b in parsed.get_conflicts()],
        "namespace": parsed.namespace,
        "version": parsed.version,
        "encoded": parsed.encode(),
        "canonical": parsed.to_canonical(),
    }


def encode_context(**dimensions: Any) -> dict[str, Any]:
    """Encode context dimensions to the VCP/A wire format and its companions."""
    context = Context(**dimensions)
    payload = context.to_dict()
    dimensions_set = [dim for dim in (*SITUATIONAL_DIMENSIONS, *PERSONAL_DIMENSIONS) if dim in payload]

    return {
        "wire_format": context.to_wire(),
        "json_format": payload,
        "session_metadata": context.to_session_metadata(),
        "natural_language": context.to_natural_language(),
        "dimensions_set": dimensions_set,
        "version": context.version,
    }


def validate_lite(document: dict[str, Any]) -> dict[str, Any]:
    """Validate a VCP-Lite document; on success also return its CSM1 code and token."""
    errors = _validate_lite(document)
    if errors:
        return {"valid": False, "errors": errors}

    return {
        "valid": True,
        "errors": [],
        "csm1_code": _lite_to_csm1(document),
        "token": _lite_to_token(document),
        "persona": document.get("persona"),
        "adherence": document.get("adherence"),
        "scopes": document.get("scopes"),
        "namespace": document.get("namespace"),
    }


def lite_to_csm1(
    persona: str,
    adherence: int,
    scopes: list[str],
    namespace: str | None = None,
) -> dict[str, Any]:
    """Convert VCP-Lite core fields to a CSM1 code, verifying it round-trips."""
    try:
        Persona.from_name(persona)
    except ValueError as e:
        return {"error": str(e)}

    if isinstance(adherence, bool) or not isinstance(adherence, int) or not (0 <= adherence <= 5):
        return {"error": "adherence must be an integer 0-5"}

    document: dict[str, Any] = {"persona": persona.lower(), "adherence": adherence, "scopes": scopes}
    if namespace:
        document["namespace"] = namespace

    code = _lite_to_csm1(document)

    try:
        parsed = CSM1Code.parse(code)
    except ValueError as e:
        return {"error": f"Produced an invalid CSM1 code {code!r}: {e}"}

    return {
        "csm1_code": parsed.encode(),
        "persona": parsed.persona.name,
        "adherence_level": parsed.adherence_level,
        "scopes": [s.name for s in parsed.scopes],
        "namespace": parsed.namespace,
    }


def classify_principle_op(
    principle_text: str,
    principle_type: str = "never",
    existing_values: list[str] | None = None,
) -> dict[str, Any]:
    """Map a principle to a Schwartz value and flag circular-model tensions."""
    classification = classify_principle(principle_text, principle_type)

    result: dict[str, Any] = {
        "principle": principle_text,
        "principle_type": principle_type,
        "schwartz_value": classification.primary_value,
        "higher_order": HIGHER_ORDER_MAPPING.get(classification.primary_value, "unknown"),
        "confidence": classification.confidence,
        "confident": classification.confidence >= CLASSIFY_CONFIDENCE_THRESHOLD,
        "candidates": classification.top_3,
    }

    if existing_values:
        result["tensions"] = detect_tensions(classification.primary_value, existing_values)

    return result


def status() -> dict[str, Any]:
    """Report SDK/spec versions, capabilities, and the exposed vocabularies."""
    return {
        "sdk_version": __version__,
        "spec_version": VCP_SPEC_VERSION,
        "context_version": VCP_CONTEXT_VERSION,
        "lite_version": VCP_LITE_VERSION,
        "tools": list(TOOL_NAMES),
        "capabilities": {
            "token_parsing": True,
            "csm1_parsing": True,
            "context_encoding": True,
            "lite_validation": True,
            "schwartz_classification": True,
        },
        "capability_tokens": ["vcp-a-ext-v1"],
        "situational_dimensions": list(SITUATIONAL_DIMENSIONS),
        "personal_dimensions": list(PERSONAL_DIMENSIONS),
        "personas": [p.name for p in Persona],
        "network_access": False,
    }
