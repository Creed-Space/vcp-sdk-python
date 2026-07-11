"""VCP-Lite validation and conversion.

Validates VCP-Lite JSON documents and converts them to full VCP
token and CSM1 code representations.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .csm1 import PERSONA_NAMES, V2_SCOPE_CHARS, Persona

_SCHEMA_PATH = Path(__file__).parent / "_schema" / "vcp-lite-1.0.schema.json"

_VALID_PERSONAS = set(PERSONA_NAMES.values())
_VALID_SCOPES = V2_SCOPE_CHARS
_SEGMENT_RE = __import__("re").compile(r"^[a-z][a-z0-9-]*$")


def validate_lite(data: dict[str, Any]) -> list[str]:
    """Validate a VCP-Lite document against the schema.

    Returns a list of error strings. Empty list means valid.
    Performs structural validation without requiring jsonschema dependency.

    Args:
        data: Parsed VCP-Lite JSON document.

    Returns:
        List of validation error messages (empty if valid).
    """
    errors: list[str] = []

    # Required: vcp_version
    if data.get("vcp_version") != "lite-1.0":
        errors.append("vcp_version must be 'lite-1.0'")

    # Required: identity
    identity = data.get("identity")
    if not isinstance(identity, dict):
        errors.append("identity is required and must be an object")
    else:
        for field_name in ("domain", "approach", "role"):
            val = identity.get(field_name)
            if not isinstance(val, str):
                errors.append(f"identity.{field_name} is required and must be a string")
            elif not _SEGMENT_RE.match(val):
                errors.append(f"identity.{field_name} must match ^[a-z][a-z0-9-]*$ (got: {val!r})")
            elif len(val) > 32:
                errors.append(f"identity.{field_name} exceeds max length 32 (got: {len(val)})")

    # Required: persona
    persona = data.get("persona")
    if not isinstance(persona, str) or persona not in _VALID_PERSONAS:
        errors.append(f"persona must be one of: {', '.join(sorted(_VALID_PERSONAS))}")

    # Required: adherence
    adherence = data.get("adherence")
    if not isinstance(adherence, int) or not (0 <= adherence <= 5):
        errors.append("adherence must be an integer 0-5")

    # Required: scopes
    scopes = data.get("scopes")
    if not isinstance(scopes, list) or len(scopes) == 0:
        errors.append("scopes must be a non-empty array")
    elif scopes:
        for s in scopes:
            if s not in _VALID_SCOPES:
                errors.append(f"Invalid scope code: {s!r}")
        if len(scopes) != len(set(scopes)):
            errors.append("scopes must contain unique items")

        # Check scope conflicts
        scope_set = set(scopes)
        if "F" in scope_set and "A" in scope_set:
            errors.append("Scope conflict: F (Family) and A (Adult) are mutually exclusive")
        if "V" in scope_set and "A" in scope_set:
            errors.append("Scope conflict: V (Vulnerable) and A (Adult) are mutually exclusive")

    # Conditional: namespace required for custom persona
    if persona == "custom":
        ns = data.get("namespace")
        if not isinstance(ns, str) or not __import__("re").match(r"^[A-Z][A-Z0-9]{0,7}$", ns):
            errors.append("namespace is required for custom persona (1-8 uppercase chars)")

    # Optional: values
    values = data.get("values")
    if values is not None:
        if not isinstance(values, list):
            errors.append("values must be an array")
        else:
            for i, v in enumerate(values):
                if not isinstance(v, dict):
                    errors.append(f"values[{i}] must be an object")
                    continue
                if not isinstance(v.get("principle"), str):
                    errors.append(f"values[{i}].principle must be a string")
                weight = v.get("weight")
                if not isinstance(weight, (int, float)) or not (0.0 <= weight <= 1.0):
                    errors.append(f"values[{i}].weight must be a number 0.0-1.0")

    # Optional: constraints
    constraints = data.get("constraints")
    if constraints is not None:
        if not isinstance(constraints, list):
            errors.append("constraints must be an array")
        else:
            for i, c in enumerate(constraints):
                if not isinstance(c, str):
                    errors.append(f"constraints[{i}] must be a string")

    # Optional: adaptation_hints
    hints = data.get("adaptation_hints")
    if hints is not None:
        if not isinstance(hints, dict):
            errors.append("adaptation_hints must be an object")
        else:
            valid_values = {
                "formality": {"casual", "neutral", "formal"},
                "sensitivity": {"low", "moderate", "high"},
                "autonomy": {"autonomous", "guided", "supervised"},
                "transparency": {"minimal", "standard", "full"},
            }
            for key, val in hints.items():
                if key not in valid_values:
                    errors.append(f"Unknown adaptation_hints key: {key!r}")
                elif val not in valid_values[key]:
                    errors.append(f"adaptation_hints.{key} must be one of: {', '.join(sorted(valid_values[key]))}")

    return errors


def lite_to_csm1(data: dict[str, Any]) -> str:
    """Convert a VCP-Lite document to a CSM1 code string.

    Args:
        data: Valid VCP-Lite document.

    Returns:
        CSM1 code string (e.g. 'N5+F+E').

    Raises:
        ValueError: If required fields are missing.
    """
    persona_name = data.get("persona")
    if not persona_name:
        raise ValueError("Missing required field: persona")

    persona = Persona.from_name(persona_name)
    adherence = data.get("adherence", 3)
    scopes = data.get("scopes", [])
    namespace = data.get("namespace")

    result = f"{persona.value}{adherence}"
    if scopes:
        result += "+" + "+".join(scopes)
    if namespace:
        result += f":{namespace}"
    return result


def lite_to_token(data: dict[str, Any]) -> str:
    """Convert a VCP-Lite document to a canonical VCP/I token string.

    Args:
        data: Valid VCP-Lite document.

    Returns:
        Canonical token string (e.g. 'family.safe.guide').

    Raises:
        ValueError: If required identity fields are missing.
    """
    identity = data.get("identity")
    if not isinstance(identity, dict):
        raise ValueError("Missing required field: identity")

    domain = identity.get("domain")
    approach = identity.get("approach")
    role = identity.get("role")

    if not all(isinstance(f, str) for f in (domain, approach, role)):
        raise ValueError("identity requires domain, approach, and role strings")

    token = f"{domain}.{approach}.{role}"

    version = identity.get("version")
    if version:
        token += f"@{version}"

    return token


def load_schema() -> dict[str, Any]:
    """Load the bundled VCP-Lite JSON Schema.

    Returns:
        Parsed JSON Schema dict.
    """
    with open(_SCHEMA_PATH) as f:
        return json.load(f)
