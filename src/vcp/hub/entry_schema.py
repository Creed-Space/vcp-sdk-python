"""Registry-entry schema validation for Creed Commons.

The schema ships bundled with the SDK (``vcp/_schema/registry_entry.schema.json``)
so validation does not depend on the registry being honest about its own rules.
Schema validation is part of the install verification chain, so a missing
``jsonschema`` package refuses (fail closed) rather than skipping the check.
"""

from __future__ import annotations

import json
from importlib import resources
from typing import Any, Iterable

from .errors import VerificationError
from .namespace_registry import FOUNDER_NAMESPACE

_SCHEMA_RESOURCE = "registry_entry.schema.json"


def load_entry_schema() -> dict[str, Any]:
    """Load the bundled registry-entry schema."""
    with resources.files("vcp._schema").joinpath(_SCHEMA_RESOURCE).open("rb") as f:
        return json.load(f)


def validate_entry(
    entry: dict[str, Any],
    require_distribution: bool = True,
    known_namespaces: Iterable[str] | None = None,
) -> None:
    """Validate a registry entry against the bundled schema.

    Args:
        entry: Parsed entry.json.
        require_distribution: When True (install / publish paths), the entry must
            carry the distribution fields (namespace, content_sha256, distribution,
            trust_tier) and a registered namespace. Legacy local entries validate
            with False.
        known_namespaces: The namespaces admitted by the hub's ROOT-VERIFIED
            namespace registry. ``None`` falls back to founder-only — callers
            with access to a hub must pass the verified set, never a guess.

    Raises:
        VerificationError: on schema violation, missing distribution fields,
            unregistered namespace, or jsonschema being unavailable.
    """
    try:
        import jsonschema
    except ImportError as exc:  # fail secure: schema check is part of verification
        raise VerificationError(
            "the 'jsonschema' package is unavailable; refusing to skip schema verification (install vcp-sdk[hub])"
        ) from exc

    try:
        jsonschema.validate(entry, load_entry_schema())
    except jsonschema.ValidationError as exc:
        raise VerificationError(f"registry entry failed schema validation: {exc.message}") from exc

    if not require_distribution:
        return

    for field in ("namespace", "content_sha256", "distribution", "trust_tier"):
        if field not in entry:
            raise VerificationError(
                f"registry entry is not publishable: missing {field!r} (legacy/local entries cannot be distributed)"
            )
    admitted = {FOUNDER_NAMESPACE} if known_namespaces is None else set(known_namespaces)
    if entry["namespace"] not in admitted:
        raise VerificationError(
            f"namespace {entry['namespace']!r} is not registered in this hub's "
            "namespace registry; see GOVERNANCE.md in the vcp-hub repo to register one"
        )
    if not entry["distribution"].get("signatures"):
        raise VerificationError("registry entry declares no signatures; unsigned artifacts are refused")
