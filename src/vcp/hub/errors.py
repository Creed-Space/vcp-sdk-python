"""Errors for the Creed Commons hub client. All verification failures fail closed."""

from __future__ import annotations


class HubError(Exception):
    """Base error for hub operations (registry access, install, publish)."""


class VerificationError(HubError):
    """An artifact failed signature, hash, or schema verification.

    Raised for: missing/unparseable signature, unknown signer key, signature
    mismatch, content-hash mismatch, schema violation, or crypto being
    unavailable. In every case the artifact is refused — never installed.
    """
