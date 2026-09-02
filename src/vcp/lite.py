"""VCP-Lite validation and conversion.

Validates VCP-Lite JSON documents and converts them to full VCP
token and CSM1 code representations.
"""

from __future__ import annotations

import json
import math
import re
from datetime import date
from itertools import islice
from pathlib import Path
from typing import Any

from .csm1 import PERSONA_NAMES, V2_SCOPE_CHARS, CSM1Code, Persona, Scope
from .token import Token

_SCHEMA_PATH = Path(__file__).parent / "_schema" / "vcp-lite-1.0.schema.json"

_VALID_PERSONAS = set(PERSONA_NAMES.values())
_VALID_SCOPES = V2_SCOPE_CHARS
_SEGMENT_RE = re.compile(r"[a-z][a-z0-9-]*\Z")
_VERSION_RE = re.compile(r"(?:[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}|latest|canary)\Z")
_NAMESPACE_RE = re.compile(r"[A-Z]{1,8}\Z")
MAX_LITE_VERSION_LENGTH = 17
MAX_METADATA_TEXT_LENGTH = 500
MAX_TAG_LENGTH = 100
_TOP_LEVEL_FIELDS = {
    "vcp_version",
    "identity",
    "persona",
    "adherence",
    "scopes",
    "values",
    "constraints",
    "adaptation_hints",
    "namespace",
    "metadata",
}


def _reject_unknown_fields(value: dict[str, Any], allowed: set[str], path: str, errors: list[str]) -> None:
    if len(value) > len(allowed):
        errors.append(f"{path} contains too many fields")
    for key in islice(value, len(allowed) + 1):
        if not isinstance(key, str) or key not in allowed:
            errors.append(f"Unknown {path} field: {key!r}")


def validate_lite(data: dict[str, Any]) -> list[str]:
    """Validate a VCP-Lite document against the schema.

    Returns a list of error strings. Empty list means valid.
    Performs structural validation without requiring jsonschema dependency.

    Args:
        data: Parsed VCP-Lite JSON document.

    Returns:
        List of validation error messages (empty if valid).
    """
    if not isinstance(data, dict):
        return ["document must be an object"]

    errors: list[str] = []
    _reject_unknown_fields(data, _TOP_LEVEL_FIELDS, "top-level", errors)

    # Required: vcp_version
    if data.get("vcp_version") != "lite-1.0":
        errors.append("vcp_version must be 'lite-1.0'")

    # Required: identity
    identity = data.get("identity")
    if not isinstance(identity, dict):
        errors.append("identity is required and must be an object")
    else:
        _reject_unknown_fields(identity, {"domain", "approach", "role", "version"}, "identity", errors)
        for field_name in ("domain", "approach", "role"):
            val = identity.get(field_name)
            if not isinstance(val, str):
                errors.append(f"identity.{field_name} is required and must be a string")
            elif len(val) > 32:
                errors.append(f"identity.{field_name} exceeds max length 32 (got: {len(val)})")
            elif _SEGMENT_RE.fullmatch(val) is None:
                errors.append(f"identity.{field_name} must match ^[a-z][a-z0-9-]*$ (got: {val!r})")
        version = identity.get("version")
        if version is not None and (
            not isinstance(version, str)
            or len(version) > MAX_LITE_VERSION_LENGTH
            or _VERSION_RE.fullmatch(version) is None
        ):
            errors.append(
                "identity.version components must contain 1-5 digits and use MAJOR.MINOR.PATCH, 'latest', or 'canary'"
            )

    # Required: persona
    persona = data.get("persona")
    if not isinstance(persona, str) or persona not in _VALID_PERSONAS:
        errors.append(f"persona must be one of: {', '.join(sorted(_VALID_PERSONAS))}")

    # Required: adherence
    adherence = data.get("adherence")
    if isinstance(adherence, bool) or not isinstance(adherence, int) or not (0 <= adherence <= 5):
        errors.append("adherence must be an integer 0-5")

    # Required: scopes
    scopes = data.get("scopes")
    if not isinstance(scopes, list) or len(scopes) == 0:
        errors.append("scopes must be a non-empty array")
    elif scopes:
        if len(scopes) > len(_VALID_SCOPES):
            errors.append(f"scopes must contain at most {len(_VALID_SCOPES)} items")
        valid_scope_items: list[str] = []
        for s in scopes[: len(_VALID_SCOPES) + 1]:
            if not isinstance(s, str) or s not in _VALID_SCOPES:
                errors.append(f"Invalid scope code: {s!r}")
            else:
                valid_scope_items.append(s)
        if len(valid_scope_items) != len(set(valid_scope_items)):
            errors.append("scopes must contain unique items")

        # Check scope conflicts
        scope_set = set(valid_scope_items)
        if "F" in scope_set and "A" in scope_set:
            errors.append("Scope conflict: F (Family) and A (Adult) are mutually exclusive")
        if "V" in scope_set and "A" in scope_set:
            errors.append("Scope conflict: V (Vulnerable) and A (Adult) are mutually exclusive")
        if "H" in scope_set and "A" in scope_set:
            errors.append("Scope conflict: H (Healthcare) and A (Adult) are mutually exclusive")

    # Conditional: namespace required for custom persona
    ns = data.get("namespace")
    if ns is not None and (not isinstance(ns, str) or _NAMESPACE_RE.fullmatch(ns) is None):
        errors.append("namespace must contain 1-8 uppercase letters")
    if persona == "custom" and ns is None:
        errors.append("namespace is required for custom persona (1-8 uppercase letters)")

    # Optional: values
    values = data.get("values")
    if values is not None:
        if not isinstance(values, list):
            errors.append("values must be an array")
        else:
            if len(values) > 20:
                errors.append("values must contain at most 20 items")
            for i, v in enumerate(values[:21]):
                if not isinstance(v, dict):
                    errors.append(f"values[{i}] must be an object")
                    continue
                _reject_unknown_fields(v, {"principle", "weight"}, f"values[{i}]", errors)
                principle = v.get("principle")
                if not isinstance(principle, str):
                    errors.append(f"values[{i}].principle must be a string")
                elif len(principle) > 500:
                    errors.append(f"values[{i}].principle exceeds max length 500")
                weight = v.get("weight")
                if (
                    isinstance(weight, bool)
                    or not isinstance(weight, (int, float))
                    or not math.isfinite(weight)
                    or not (0.0 <= weight <= 1.0)
                ):
                    errors.append(f"values[{i}].weight must be a number 0.0-1.0")

    # Optional: constraints
    constraints = data.get("constraints")
    if constraints is not None:
        if not isinstance(constraints, list):
            errors.append("constraints must be an array")
        else:
            if len(constraints) > 20:
                errors.append("constraints must contain at most 20 items")
            for i, c in enumerate(constraints[:21]):
                if not isinstance(c, str):
                    errors.append(f"constraints[{i}] must be a string")
                elif len(c) > 500:
                    errors.append(f"constraints[{i}] exceeds max length 500")

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
            if len(hints) > len(valid_values):
                errors.append("adaptation_hints contains too many fields")
            for key, val in islice(hints.items(), len(valid_values) + 1):
                if key not in valid_values:
                    errors.append(f"Unknown adaptation_hints key: {key!r}")
                elif not isinstance(val, str) or val not in valid_values[key]:
                    errors.append(f"adaptation_hints.{key} must be one of: {', '.join(sorted(valid_values[key]))}")

    # Optional: metadata
    metadata = data.get("metadata")
    if metadata is not None:
        if not isinstance(metadata, dict):
            errors.append("metadata must be an object")
        else:
            _reject_unknown_fields(
                metadata,
                {"author", "license", "created", "description", "extends", "tags"},
                "metadata",
                errors,
            )
            for key in ("author", "license", "created", "description", "extends"):
                if key in metadata and not isinstance(metadata[key], str):
                    errors.append(f"metadata.{key} must be a string")
            for key in ("author", "license"):
                if isinstance(metadata.get(key), str) and len(metadata[key]) > MAX_METADATA_TEXT_LENGTH:
                    errors.append(f"metadata.{key} exceeds max length {MAX_METADATA_TEXT_LENGTH}")
            description = metadata.get("description")
            if isinstance(description, str) and len(description) > 1000:
                errors.append("metadata.description exceeds max length 1000")
            created = metadata.get("created")
            if isinstance(created, str):
                if len(created) != 10:
                    errors.append("metadata.created must use canonical YYYY-MM-DD form")
                else:
                    try:
                        parsed_date = date.fromisoformat(created)
                    except ValueError:
                        errors.append("metadata.created must be an ISO 8601 calendar date")
                    else:
                        if parsed_date.isoformat() != created:
                            errors.append("metadata.created must use canonical YYYY-MM-DD form")
            extends = metadata.get("extends")
            if isinstance(extends, str):
                try:
                    Token.parse(extends)
                except ValueError as exc:
                    errors.append(f"metadata.extends must be a valid VCP token: {exc}")
            tags = metadata.get("tags")
            if tags is not None:
                if not isinstance(tags, list):
                    errors.append("metadata.tags must be an array")
                else:
                    if len(tags) > 10:
                        errors.append("metadata.tags must contain at most 10 items")
                    for i, tag in enumerate(tags[:11]):
                        if not isinstance(tag, str):
                            errors.append(f"metadata.tags[{i}] must be a string")
                        elif len(tag) > MAX_TAG_LENGTH:
                            errors.append(f"metadata.tags[{i}] exceeds max length {MAX_TAG_LENGTH}")

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
    errors = validate_lite(data)
    if errors:
        raise ValueError("Invalid VCP-Lite document: " + "; ".join(errors))
    return CSM1Code(
        persona=Persona.from_name(data["persona"]),
        adherence_level=data["adherence"],
        scopes=[Scope(scope) for scope in data["scopes"]],
        namespace=data.get("namespace"),
    ).encode()


def lite_to_token(data: dict[str, Any]) -> str:
    """Convert a VCP-Lite document to a canonical VCP/I token string.

    Args:
        data: Valid VCP-Lite document.

    Returns:
        Canonical token string (e.g. 'family.safe.guide').

    Raises:
        ValueError: If required identity fields are missing.
    """
    errors = validate_lite(data)
    if errors:
        raise ValueError("Invalid VCP-Lite document: " + "; ".join(errors))
    identity = data["identity"]
    token = f"{identity['domain']}.{identity['approach']}.{identity['role']}"
    if identity.get("version"):
        token += f"@{identity['version']}"
    return Token.parse(token).full


def load_schema() -> dict[str, Any]:
    """Load the bundled VCP-Lite JSON Schema.

    Returns:
        Parsed JSON Schema dict.
    """
    with open(_SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)
