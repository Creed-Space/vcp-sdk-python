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


class NotFoundError(HubError):
    """A registry object does not exist (distinct from tampering or outage).

    Only object ABSENCE maps here; failed fetches and invalid content stay
    HubError/VerificationError so callers cannot mistake an attack for a 404.
    """
