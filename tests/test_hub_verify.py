"""Fail-secure behaviour of vcp.hub.verify.verify_artifact_bytes.

Every negative case must be valid up to the check under test — the verifier is
strictly ordered (unsigned → sidecar JSON → version → algorithm → fields →
sidecar hash → expected hash → pinned key → base64 → crypto import → signature),
so an incidental defect earlier in the chain would mask the behaviour we pin.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys

import pytest
from conftest import FIXED_SIGNED_AT, TEST_KEY_ID, make_sidecar
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vcp.hub.errors import VerificationError
from vcp.hub.verify import VerifiedArtifact, verify_artifact_bytes

CONTENT = b"a constitution, as opaque bytes\n"


def test_valid_signature_and_hash_round_trips(pinned_test_key, sign_artifact):
    sig = sign_artifact(CONTENT)

    verified = verify_artifact_bytes(CONTENT, sig)

    assert verified == VerifiedArtifact(
        key_id=TEST_KEY_ID,
        content_sha256=hashlib.sha256(CONTENT).hexdigest(),
        signed_at=FIXED_SIGNED_AT,
    )


def test_valid_signature_accepts_matching_expected_sha256(pinned_test_key, sign_artifact):
    sig = sign_artifact(CONTENT)

    verified = verify_artifact_bytes(CONTENT, sig, expected_sha256=hashlib.sha256(CONTENT).hexdigest())

    assert verified.key_id == TEST_KEY_ID


def test_missing_signature_is_refused(pinned_test_key):
    with pytest.raises(VerificationError, match="unsigned"):
        verify_artifact_bytes(CONTENT, None)


def test_unknown_key_id_is_refused(pinned_test_key, sign_artifact):
    sig = sign_artifact(CONTENT, key_id="attacker-key")

    with pytest.raises(VerificationError, match="pinned publisher allowlist"):
        verify_artifact_bytes(CONTENT, sig)


def test_tampered_content_is_refused(pinned_test_key, sign_artifact):
    sig = sign_artifact(CONTENT)

    with pytest.raises(VerificationError, match="content hash mismatch"):
        verify_artifact_bytes(CONTENT + b"evil appendix", sig)


def test_expected_sha256_disagreement_is_refused(pinned_test_key, sign_artifact):
    sig = sign_artifact(CONTENT)

    with pytest.raises(VerificationError, match="content hash mismatch"):
        verify_artifact_bytes(CONTENT, sig, expected_sha256="0" * 64)


def test_sidecar_that_is_not_json_is_refused(pinned_test_key):
    with pytest.raises(VerificationError, match="not valid JSON"):
        verify_artifact_bytes(CONTENT, b"not json at all")


def test_sidecar_with_wrong_algorithm_is_refused(pinned_test_key, sign_artifact):
    sig = sign_artifact(CONTENT, algorithm="RSA")

    with pytest.raises(VerificationError, match="unsupported signature algorithm"):
        verify_artifact_bytes(CONTENT, sig)


def test_sidecar_with_unsupported_version_is_refused(pinned_test_key, sign_artifact):
    sig = sign_artifact(CONTENT, version=2)

    with pytest.raises(VerificationError, match="unsupported signature sidecar version"):
        verify_artifact_bytes(CONTENT, sig)


def test_sidecar_missing_required_field_is_refused(pinned_test_key, sign_artifact):
    sig_data = json.loads(sign_artifact(CONTENT))
    del sig_data["signature"]

    with pytest.raises(VerificationError, match="missing field 'signature'"):
        verify_artifact_bytes(CONTENT, json.dumps(sig_data).encode("utf-8"))


def test_sidecar_with_bad_base64_signature_is_refused(pinned_test_key, sign_artifact):
    sig = sign_artifact(CONTENT, signature_b64="!!!not base64!!!")

    with pytest.raises(VerificationError, match="not valid base64"):
        verify_artifact_bytes(CONTENT, sig)


def test_signature_by_a_different_key_under_a_pinned_key_id_is_refused(pinned_test_key):
    """Well-formed signature, pinned key id, wrong private key — must not verify."""
    impostor = Ed25519PrivateKey.generate()
    sig = make_sidecar(CONTENT, impostor, key_id=TEST_KEY_ID)

    with pytest.raises(VerificationError, match="verification FAILED"):
        verify_artifact_bytes(CONTENT, sig)


def test_missing_crypto_serialization_fails_secure(monkeypatch, pinned_test_key, sign_artifact):
    """No crypto, no trust: a VerificationError, never a crash or a silent pass."""
    sig = sign_artifact(CONTENT)
    monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.serialization", None)

    with pytest.raises(VerificationError, match="unavailable"):
        verify_artifact_bytes(CONTENT, sig)


def test_missing_crypto_exceptions_fails_secure(monkeypatch, pinned_test_key, sign_artifact):
    """The second crypto import is guarded too — reached with everything else valid."""
    sig = sign_artifact(CONTENT)
    assert base64.b64decode(json.loads(sig)["signature"], validate=True)
    monkeypatch.setitem(sys.modules, "cryptography.exceptions", None)

    with pytest.raises(VerificationError, match="unavailable"):
        verify_artifact_bytes(CONTENT, sig)
