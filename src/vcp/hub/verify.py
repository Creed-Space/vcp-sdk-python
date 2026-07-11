"""Fail-secure Ed25519 + sha256 verification of Creed Commons artifacts.

Every path through this module either returns a fully verified artifact or raises
:class:`VerificationError`. There is no partial trust: unknown signer key, missing
signature, hash mismatch, malformed sidecar, or the ``cryptography`` package being
unavailable all refuse identically (fail closed, mirroring the platform's
``verify_event_signature`` behaviour).

Artifact content is treated strictly as bytes. Nothing here imports, parses as
code, evals, or executes artifact content.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .errors import VerificationError
from .keys import PINNED_PUBLISHER_KEYS

SUPPORTED_ALGORITHM = "Ed25519"
SUPPORTED_SIG_VERSION = 1


@dataclass(frozen=True)
class VerifiedArtifact:
    """Proof-of-verification record for one artifact."""

    key_id: str
    content_sha256: str
    signed_at: str | None


def _load_public_key(key_id: str):  # -> Ed25519PublicKey
    """Load a pinned publisher key. Unknown key ids and missing crypto refuse."""
    pem = PINNED_PUBLISHER_KEYS.get(key_id)
    if pem is None:
        raise VerificationError(
            f"signer key id {key_id!r} is not in the pinned publisher allowlist; "
            "refusing (unknown keys are never trusted, even with a valid signature)"
        )
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError as exc:  # fail secure: no crypto, no trust
        raise VerificationError(
            "the 'cryptography' package is unavailable; refusing to treat the "
            "artifact as verified (install vcp-sdk[hub])"
        ) from exc
    try:
        key = load_pem_public_key(pem.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise VerificationError(f"pinned key {key_id!r} failed to load: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise VerificationError(f"pinned key {key_id!r} is not an Ed25519 key")
    return key


def parse_signature_sidecar(sig_bytes: bytes) -> dict[str, Any]:
    """Parse and structurally validate a ``.ed25519.sig`` JSON sidecar."""
    try:
        sig_data = json.loads(sig_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"signature sidecar is not valid JSON: {exc}") from exc
    if not isinstance(sig_data, dict):
        raise VerificationError("signature sidecar must be a JSON object")
    if sig_data.get("version") != SUPPORTED_SIG_VERSION:
        raise VerificationError(f"unsupported signature sidecar version {sig_data.get('version')!r}")
    if sig_data.get("algorithm") != SUPPORTED_ALGORITHM:
        raise VerificationError(
            f"unsupported signature algorithm {sig_data.get('algorithm')!r}; only {SUPPORTED_ALGORITHM} is accepted"
        )
    for field in ("key_id", "content_hash", "signature"):
        if not isinstance(sig_data.get(field), str) or not sig_data[field]:
            raise VerificationError(f"signature sidecar missing field {field!r}")
    return sig_data


def verify_artifact_bytes(
    content: bytes,
    sig_bytes: bytes | None,
    expected_sha256: str | None = None,
) -> VerifiedArtifact:
    """Verify artifact ``content`` against its signature sidecar and expected hash.

    Args:
        content: Raw artifact bytes (treated as opaque data, never executed).
        sig_bytes: Raw bytes of the ``.ed25519.sig`` sidecar; ``None`` refuses.
        expected_sha256: Optional independently-sourced hash (registry entry /
            lockfile) that must also match — this is what pins content across
            the registry boundary (Threat T2).

    Returns:
        VerifiedArtifact on success.

    Raises:
        VerificationError: on ANY failure. Fail closed; never partially trust.
    """
    if sig_bytes is None:
        raise VerificationError("artifact has no signature; unsigned artifacts are refused")

    sig_data = parse_signature_sidecar(sig_bytes)

    content_sha256 = hashlib.sha256(content).hexdigest()
    if sig_data["content_hash"] != content_sha256:
        raise VerificationError(
            "content hash mismatch: signature sidecar signs "
            f"{sig_data['content_hash'][:12]}…, artifact bytes hash to "
            f"{content_sha256[:12]}… — content was modified after signing"
        )
    if expected_sha256 is not None and expected_sha256 != content_sha256:
        raise VerificationError(
            f"content hash mismatch: expected {expected_sha256[:12]}… "
            f"(registry entry / lockfile), artifact bytes hash to {content_sha256[:12]}…"
        )

    key_id = sig_data["key_id"]
    public_key = _load_public_key(key_id)

    try:
        signature = base64.b64decode(sig_data["signature"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VerificationError(f"signature is not valid base64: {exc}") from exc

    try:
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise VerificationError("the 'cryptography' package is unavailable; refusing (install vcp-sdk[hub])") from exc
    try:
        public_key.verify(signature, content)
    except InvalidSignature as exc:
        raise VerificationError(f"Ed25519 signature verification FAILED for key {key_id!r}") from exc

    return VerifiedArtifact(
        key_id=key_id,
        content_sha256=content_sha256,
        signed_at=sig_data.get("signed_at"),
    )
