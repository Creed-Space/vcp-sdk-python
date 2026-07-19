"""MCP server for the Value Context Protocol.

Exposes the VCP SDK — token parsing, CSM1 codes, VCP-Lite documents,
context encoding, and Schwartz value classification — over the Model
Context Protocol via stdio.

Every tool is pure local computation. The server makes no network calls,
reads no user data, and holds no state between calls.

    pip install "vcp-sdk[mcp]"
    vcp-mcp
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from ._schwartz_classifier import HIGHER_ORDER_MAPPING, classify_principle, detect_tensions
from .context import PERSONAL_DIMENSIONS, SITUATIONAL_DIMENSIONS, Context
from .csm1 import CSM1Code, Persona
from .lite import lite_to_csm1 as _lite_to_csm1
from .lite import lite_to_token as _lite_to_token
from .lite import validate_lite as _validate_lite
from .token import Token

from . import __version__

VCP_SPEC_VERSION = "2.0.0"
VCP_CONTEXT_VERSION = "3.2"
VCP_LITE_VERSION = "lite-1.0"

_EXAMPLES_DIR = Path(__file__).parent / "_examples"

mcp = FastMCP("vcp")


def _json(payload: Any) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False)


# === Identity and semantics ===


@mcp.tool()
def vcp_validate_token(token: str) -> str:
    """Validate a VCP/I identity token string.

    Parses the token per the VCP/I grammar and returns its components:
    - domain: value domain (first segment, e.g. 'family')
    - approach: constitutional approach (second-to-last segment, e.g. 'safe')
    - role: functional role (last segment, e.g. 'guide')
    - version: semantic version, 'latest', or 'canary' (optional)
    - namespace: uppercase namespace tier (optional)

    Token format: 3-10 dot-separated lowercase segments, optional @version
    and :NAMESPACE.

    Examples:
        vcp_validate_token(token="family.safe.guide")
        # => {"valid": true, "canonical": "family.safe.guide", "domain": "family",
        #     "approach": "safe", "role": "guide", "version": null,
        #     "namespace": null, "uri": "creed://creed.space/family.safe.guide"}

        vcp_validate_token(token="company.acme.legal.compliance:SEC")
        # => {"valid": true, "domain": "company", "approach": "legal",
        #     "role": "compliance", "namespace": "SEC", ...}

        vcp_validate_token(token="invalid")
        # => {"valid": false, "error": "Invalid VCP/I token format: invalid"}
    """
    try:
        parsed = Token.parse(token)
    except ValueError as e:
        return _json({"valid": False, "error": str(e)})

    return _json(
        {
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
    )


@mcp.tool()
def vcp_parse_csm1(code: str) -> str:
    """Parse a CSM1 constitutional code.

    CSM1 (Constitutional Semantics Mark 1) is a compact encoding for
    constitutional profiles. NANO/MICRO format is persona letter + adherence
    level (0-5) + scopes (+X) + optional :NAMESPACE + optional @version.
    COMPACT format is 'CS1|persona|level|token|SCOPES'.

    Persona letters: N(anny), Z(sentinel), G(odparent), A(mbassador),
    M(use), D(mediator), C(ustom).

    Returns the parsed persona, adherence level, scope names, and any
    scope conflicts detected on the CSM1 conflict table.

    Examples:
        vcp_parse_csm1(code="N5+F+E")
        # => {"valid": true, "persona": "NANNY", "adherence_level": 5,
        #     "scopes": ["FAMILY", "EDUCATION"], "encoded": "N5+F+E", ...}

        vcp_parse_csm1(code="A2+W+L@1.0.0")
        # => {"valid": true, "persona": "AMBASSADOR", "version": "1.0.0", ...}

        vcp_parse_csm1(code="XYZ")
        # => {"valid": false, "error": "Invalid CSM1 code: XYZ"}
    """
    try:
        parsed = CSM1Code.parse(code)
    except ValueError as e:
        return _json({"valid": False, "error": str(e)})

    return _json(
        {
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
    )


# === Context ===


@mcp.tool()
def vcp_encode_context(
    time: str | None = None,
    space: str | None = None,
    company: list[str] | None = None,
    culture: str | None = None,
    occasion: str | None = None,
    environment: str | None = None,
    agency: str | None = None,
    constraints: list[str] | None = None,
    system_context: str | None = None,
    embodiment: str | None = None,
    proximity: str | None = None,
    relationship: str | None = None,
    formality: str | None = None,
    cognitive_state: str | None = None,
    cognitive_state_intensity: int | None = None,
    emotional_tone: str | None = None,
    emotional_tone_intensity: int | None = None,
    energy_level: str | None = None,
    energy_level_intensity: int | None = None,
    perceived_urgency: str | None = None,
    perceived_urgency_intensity: int | None = None,
    body_signals: str | None = None,
    body_signals_intensity: int | None = None,
) -> str:
    """Encode context dimensions to VCP/A wire format (VCP 3.2).

    Encodes contextual state across 18 dimensions (13 situational +
    5 personal) and returns the emoji wire format, the JSON form, session
    metadata for agent handoff, and a natural-language summary.

    Situational dimensions (9 canonical):
    - time: "morning", "midday", "evening", "night"
    - space: "home", "office", "school", "hospital", "transit"
    - company: ["alone"], ["children", "family"], ["colleagues"], ["strangers"]
    - culture: "global", "american", "european", "japanese"
    - occasion: "normal", "celebration", "mourning", "emergency"
    - environment: "outdoors", "hot", "cold", "quiet", "noisy"
    - agency: "leader", "peer", "subordinate", "limited"
    - constraints: ["minimal"], ["legal"], ["economic"], ["time"]
    - system_context: free-form description of the operating system context

    Situational dimensions (4 extended, VEP-0004 — for embodied agents):
    - embodiment: "stationary", "navigating", "manipulating", "carrying",
      "emergency_stop"
    - proximity: "distant", "same_room", "nearby", "close", "contact"
    - relationship: compound "{tie}:{function}", e.g. "colleague:professional"
    - formality: "casual", "professional", "formal", "ceremonial"

    Personal state dimensions (5, optional). Each takes a category plus an
    optional intensity 1-5:
    - cognitive_state: "focused", "distracted", "overloaded", "foggy", "reflective"
    - emotional_tone: "calm", "tense", "frustrated", "neutral", "uplifted"
    - energy_level: "rested", "low_energy", "fatigued", "wired", "depleted"
    - perceived_urgency: "unhurried", "time_aware", "pressured", "critical"
    - body_signals: "neutral", "discomfort", "pain", "unwell", "recovering"

    Wire format separates situational dimensions with '|' and prefixes the
    personal state section with '||'.

    Examples:
        vcp_encode_context(space="hospital", agency="peer", constraints=["legal"])
        # => {"wire_format": "📍hospital|🎯peer|🔒legal", ...}

        vcp_encode_context(space="office", cognitive_state="focused",
                           cognitive_state_intensity=4)
        # => {"wire_format": "📍office||🧠focused4", ...}
    """
    context = Context(
        time=time,
        space=space,
        company=company,
        culture=culture,
        occasion=occasion,
        environment=environment,
        agency=agency,
        constraints=constraints,
        system_context=system_context,
        embodiment=embodiment,
        proximity=proximity,
        relationship=relationship,
        formality=formality,
        cognitive_state=cognitive_state,
        cognitive_state_intensity=cognitive_state_intensity,
        emotional_tone=emotional_tone,
        emotional_tone_intensity=emotional_tone_intensity,
        energy_level=energy_level,
        energy_level_intensity=energy_level_intensity,
        perceived_urgency=perceived_urgency,
        perceived_urgency_intensity=perceived_urgency_intensity,
        body_signals=body_signals,
        body_signals_intensity=body_signals_intensity,
    )

    payload = context.to_dict()
    dimensions_set = [dim for dim in (*SITUATIONAL_DIMENSIONS, *PERSONAL_DIMENSIONS) if dim in payload]

    return _json(
        {
            "wire_format": context.to_wire(),
            "json_format": payload,
            "session_metadata": context.to_session_metadata(),
            "natural_language": context.to_natural_language(),
            "dimensions_set": dimensions_set,
            "version": context.version,
        }
    )


# === VCP-Lite ===


@mcp.tool()
def vcp_validate_lite(document: dict[str, Any]) -> str:
    """Validate a VCP-Lite document against the lite-1.0 schema.

    VCP-Lite is the single-file entry point to VCP: one JSON document that
    declares an agent's ethical identity (persona, adherence level, scopes,
    values, constraints).

    Required fields: vcp_version ("lite-1.0"), identity (domain/approach/role),
    persona (nanny/sentinel/godparent/ambassador/muse/mediator/custom),
    adherence (0-5), scopes (non-empty array of F/W/P/E/T/O/V/A/H/S/R).

    Optional fields: values (principles with weights), constraints (hard
    boundaries), adaptation_hints (formality/sensitivity/autonomy/transparency),
    namespace (required for the custom persona), metadata.

    Returns valid (bool) and errors (list). When valid, also returns the
    equivalent csm1_code and the canonical VCP/I token.

    Example valid document:
        {"vcp_version": "lite-1.0",
         "identity": {"domain": "family", "approach": "safe", "role": "guide"},
         "persona": "nanny", "adherence": 5, "scopes": ["F", "E"]}
    """
    errors = _validate_lite(document)
    if errors:
        return _json({"valid": False, "errors": errors})

    return _json(
        {
            "valid": True,
            "errors": [],
            "csm1_code": _lite_to_csm1(document),
            "token": _lite_to_token(document),
            "persona": document.get("persona"),
            "adherence": document.get("adherence"),
            "scopes": document.get("scopes"),
            "namespace": document.get("namespace"),
        }
    )


@mcp.tool()
def vcp_lite_to_csm1(
    persona: str,
    adherence: int,
    scopes: list[str],
    namespace: str | None = None,
) -> str:
    """Convert VCP-Lite fields to a CSM1 code string.

    Takes the core VCP-Lite fields and produces the equivalent CSM1 compact
    encoding, then verifies the result round-trips through the CSM1 parser.

    Persona: nanny/sentinel/godparent/ambassador/muse/mediator/custom
    Adherence: 0 (advisory) through 5 (absolute)
    Scopes: array of scope codes (F/W/P/E/T/O/V/A/H/S/R)
    Namespace: optional, 1-8 uppercase alphanumeric chars; required for the
    custom persona.

    Examples:
        vcp_lite_to_csm1(persona="nanny", adherence=5, scopes=["F", "E"])
        # => {"csm1_code": "N5+F+E", ...}

        vcp_lite_to_csm1(persona="sentinel", adherence=4,
                         scopes=["P", "T", "W"], namespace="SEC")
        # => {"csm1_code": "Z4+P+T+W:SEC", ...}
    """
    try:
        Persona.from_name(persona)
    except ValueError as e:
        return _json({"error": str(e)})

    if isinstance(adherence, bool) or not isinstance(adherence, int) or not (0 <= adherence <= 5):
        return _json({"error": "adherence must be an integer 0-5"})

    document: dict[str, Any] = {"persona": persona.lower(), "adherence": adherence, "scopes": scopes}
    if namespace:
        document["namespace"] = namespace

    code = _lite_to_csm1(document)

    try:
        parsed = CSM1Code.parse(code)
    except ValueError as e:
        return _json({"error": f"Produced an invalid CSM1 code {code!r}: {e}"})

    return _json(
        {
            "csm1_code": parsed.encode(),
            "persona": parsed.persona.name,
            "adherence_level": parsed.adherence_level,
            "scopes": [s.name for s in parsed.scopes],
            "namespace": parsed.namespace,
        }
    )


# === Constitution authoring ===


@mcp.tool()
def creed_classify_principle(
    principle_text: str,
    principle_type: str = "never",
    existing_values: list[str] | None = None,
) -> str:
    """Classify a constitution principle against Schwartz value dimensions.

    Maps principle text to one of the 10 Schwartz basic values using
    deterministic keyword, bigram, and description-overlap scoring — no model
    call. Also reports tensions with existing values on the Schwartz circular
    model, where opposing higher-order dimensions collide.

    Schwartz values: power, achievement, hedonism, stimulation, self_direction,
    universalism, benevolence, tradition, conformity, security.

    A confidence below 0.7 means the mapping is a best guess — inspect
    `candidates` and pick deliberately rather than trusting `schwartz_value`.

    Examples:
        creed_classify_principle(principle_text="Never endanger a child",
                                 principle_type="never")

        creed_classify_principle(principle_text="Aim for kindness in all responses",
                                 principle_type="aim_for",
                                 existing_values=["power", "achievement"])
    """
    classification = classify_principle(principle_text, principle_type)
    confident = classification.confidence >= 0.7

    result: dict[str, Any] = {
        "principle": principle_text,
        "principle_type": principle_type,
        "schwartz_value": classification.primary_value,
        "higher_order": HIGHER_ORDER_MAPPING.get(classification.primary_value, "unknown"),
        "confidence": classification.confidence,
        "confident": confident,
        "candidates": classification.top_3,
    }

    if existing_values:
        result["tensions"] = detect_tensions(classification.primary_value, existing_values)

    return _json(result)


# === Server status ===


@mcp.tool()
def vcp_status() -> str:
    """Report the VCP SDK version, spec versions, and available capabilities.

    Takes no arguments. Useful for confirming which VCP surfaces this server
    exposes before calling the other tools.

    Examples:
        vcp_status()
        # => {"sdk_version": "0.5.0", "spec_version": "2.0.0",
        #     "context_version": "3.2", "lite_version": "lite-1.0",
        #     "tools": [...], "capabilities": {...}, "network_access": false}
    """
    return _json(
        {
            "sdk_version": __version__,
            "spec_version": VCP_SPEC_VERSION,
            "context_version": VCP_CONTEXT_VERSION,
            "lite_version": VCP_LITE_VERSION,
            "tools": [
                "vcp_status",
                "vcp_validate_token",
                "vcp_parse_csm1",
                "vcp_encode_context",
                "vcp_validate_lite",
                "vcp_lite_to_csm1",
                "creed_classify_principle",
            ],
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
    )


# === Resources ===


@mcp.resource("vcp://lite/examples")
def get_lite_examples() -> str:
    """Bundled VCP-Lite example documents, keyed by filename."""
    examples = {path.name: json.loads(path.read_text()) for path in sorted(_EXAMPLES_DIR.glob("*.json"))}
    return _json(examples)


def main() -> None:
    """Run the VCP MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
