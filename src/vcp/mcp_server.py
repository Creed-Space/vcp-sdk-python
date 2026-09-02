"""MCP server for the Value Context Protocol.

Exposes the VCP SDK — token parsing, CSM1 codes, VCP-Lite documents,
context encoding, and Schwartz value classification — over the Model
Context Protocol, via stdio (default) or Streamable HTTP.

Tool payloads are shaped in :mod:`vcp._ops`, shared with the ``vcp`` CLI so
the two surfaces cannot drift apart.

Every tool is pure local computation. The server makes no network calls,
reads no user data, and holds no state between calls.

    python -m pip install ".[mcp]"
    vcp-mcp                      # stdio
    vcp-mcp --transport http     # Streamable HTTP on 127.0.0.1:8080
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import _ops

# Re-exported for callers that import the spec versions from this module.
VCP_SPEC_VERSION = _ops.VCP_SPEC_VERSION
VCP_SEMANTICS_VERSION = _ops.VCP_SEMANTICS_VERSION
VCP_CONTEXT_VERSION = _ops.VCP_CONTEXT_VERSION
VCP_LITE_VERSION = _ops.VCP_LITE_VERSION

_EXAMPLES_DIR = Path(__file__).parent / "_examples"

from vcp import __version__

mcp = FastMCP("vcp")
# FastMCP exposes no public version parameter; without this, the initialize
# handshake reports the mcp SDK's version as serverInfo.version. The low-level
# server's `version` feeds create_initialization_options() directly.
mcp._mcp_server.version = __version__


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
    and :NAMESPACE. creed:// and vcp:// URIs are also accepted and normalised
    to canonical form (the project-maintained VCP-SDK's parse rejects URIs;
    use the returned "canonical"/"full" value for interop).

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
    return _json(_ops.validate_token(token))


@mcp.tool()
def vcp_parse_csm1(code: str) -> str:
    """Parse a CSM1 constitutional code.

    CSM1 (Constitutional Safety Minicode) is a compact encoding for
    constitutional profiles. NANO/MICRO format is persona letter + adherence
    level (0-5) + scopes (for example +F) + optional :NAMESPACE + optional @version.
    COMPACT format is 'CS1|persona|level|token|SCOPES'.

    Persona letters: N(anny), Z(sentinel), G(odparent), A(mbassador),
    M(use), D(mediator), C(ustom).

    Returns the parsed persona, adherence level, scope names, namespace,
    version and (COMPACT only) the UVC identity token. Codes with mutually
    exclusive scopes (F+A, V+A, H+A) or non-v2 scopes are rejected with
    valid=false. "encoded" and "canonical" both carry the canonical form with
    scopes sorted, so they string-compare across SDKs.

    Examples:
        vcp_parse_csm1(code="N5+F+E")
        # => {"valid": true, "persona": "NANNY", "adherence_level": 5,
        #     "scopes": ["FAMILY", "EDUCATION"], "encoded": "N5+E+F",
        #     "canonical": "N5+E+F", "token": null, ...}

        vcp_parse_csm1(code="A2+W+O@1.0.0")
        # => {"valid": true, "persona": "AMBASSADOR", "version": "1.0.0", ...}

        vcp_parse_csm1(code="XYZ")
        # => {"valid": false, "error": "Invalid CSM1 code: XYZ"}
    """
    return _json(_ops.parse_csm1(code))


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
    - culture: communication style, NOT nationality — "high_context",
      "low_context", "formal", "casual", "mixed"
    - occasion: "normal", "celebration", "mourning", "emergency", "business"
    - environment: "comfortable", "hot", "cold", "quiet", "noisy"
    - agency: "leader", "peer", "subordinate", "limited"
    - constraints: ["minimal"], ["legal"], ["economic"], ["time"]
    - system_context: "online", "degraded", "offline", "sandboxed", "testing"

    Values outside these vocabularies are passed through verbatim on the wire
    (no canonical symbol), so other implementations may not understand them.

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
    personal state section with the U+2016 '‖' band separator. Personal
    intensity is separated from its category by ':'.

    Examples:
        vcp_encode_context(space="hospital", agency="peer", constraints=["legal"])
        # => {"wire_format": "📍🏥|🎯🤝|🔒⚖️", ...}

        vcp_encode_context(space="office", cognitive_state="focused",
                           cognitive_state_intensity=4)
        # => {"wire_format": "📍🏢‖🧠focused:4", ...}

        vcp_encode_context(space="a|b")
        # => {"valid": false, "error": "space contains a reserved wire separator"}
    """
    try:
        payload = _ops.encode_context(
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
    except ValueError as exc:
        return _json({"valid": False, "error": str(exc)})
    return _json(payload)


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
    return _json(_ops.validate_lite(document))


@mcp.tool()
def vcp_lite_to_csm1(
    persona: str,
    adherence: int,
    scopes: list[str],
    namespace: str | None = None,
) -> str:
    """Convert VCP-Lite fields to a CSM1 code string.

    Takes the core VCP-Lite fields and produces the equivalent CSM1 code in
    canonical form (scopes sorted), then verifies the result round-trips
    through the CSM1 parser.

    Persona: nanny/sentinel/godparent/ambassador/muse/mediator/custom
    Adherence: 0 (advisory) through 5 (absolute)
    Scopes: array of scope codes (F/W/P/E/T/O/V/A/H/S/R)
    Namespace: optional, 1-8 uppercase ASCII letters; required for the
    custom persona.

    Examples:
        vcp_lite_to_csm1(persona="nanny", adherence=5, scopes=["F", "E"])
        # => {"csm1_code": "N5+E+F", ...}

        vcp_lite_to_csm1(persona="sentinel", adherence=4,
                         scopes=["P", "T", "W"], namespace="SEC")
        # => {"csm1_code": "Z4+P+T+W:SEC", ...}
    """
    return _json(_ops.lite_to_csm1(persona, adherence, scopes, namespace))


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
    universalism, benevolence, tradition, conformity, security. Each entry in
    existing_values must be one of these (case-insensitive); anything else
    returns an error payload rather than a silently empty tensions list.

    A confidence below 0.7 means the mapping is a best guess — inspect
    `candidates` and pick deliberately rather than trusting `schwartz_value`.

    Examples:
        creed_classify_principle(principle_text="Never endanger a child",
                                 principle_type="never")

        creed_classify_principle(principle_text="Aim for kindness in all responses",
                                 principle_type="aim_for",
                                 existing_values=["power", "achievement"])
    """
    return _json(_ops.classify_principle_op(principle_text, principle_type, existing_values))


# === Server status ===


@mcp.tool()
def vcp_status() -> str:
    """Report the VCP SDK version, spec versions, and available capabilities.

    Takes no arguments. Useful for confirming which VCP surfaces this server
    exposes before calling the other tools.

    Examples:
        vcp_status()
        # => {"sdk_version": "<package version>", "spec_version": "3.1",
        #     "semantics_version": "2.0.0", "context_version": "3.2",
        #     "lite_version": "lite-1.0",
        #     "tools": [...], "capabilities": {...}, "network_access": false}
    """
    return _json(_ops.status())


# === Resources ===


@mcp.resource("vcp://lite/examples")
def get_lite_examples() -> str:
    """Bundled VCP-Lite example documents, keyed by filename."""
    examples = {path.name: json.loads(path.read_text(encoding="utf-8")) for path in sorted(_EXAMPLES_DIR.glob("*.json"))}
    return _json(examples)


def main(argv: list[str] | None = None) -> int:
    """Run the VCP MCP server over stdio (default) or Streamable HTTP."""
    import argparse

    def port_number(value: str) -> int:
        try:
            port = int(value)
        except (TypeError, ValueError) as exc:
            raise argparse.ArgumentTypeError("port must be an integer from 1 to 65535") from exc
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError("port must be an integer from 1 to 65535")
        return port

    parser = argparse.ArgumentParser(
        prog="vcp-mcp",
        description="MCP server exposing the VCP SDK (tokens, CSM1, VCP-Lite, context, classification).",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="stdio (default) for local MCP clients; http for hosted deployments",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="http mode: bind address (default 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=port_number,
        default=None,
        help="http mode: port (default $PORT, else 8080)",
    )
    args = parser.parse_args(argv)

    if args.transport == "stdio":
        mcp.run(transport="stdio")
        return 0

    # Resolve $PORT only in http mode, so a malformed PORT in the environment
    # cannot stop a stdio launch that never uses it.
    port = args.port
    if port is None:
        try:
            port = port_number(os.environ.get("PORT", "8080"))
        except argparse.ArgumentTypeError as exc:
            parser.error(f"argument --port: {exc}")

    from ._http import check_bind_allowed, run_http

    try:
        check_bind_allowed(args.host)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    run_http(mcp._mcp_server, host=args.host, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
