"""Shared fixtures for the vcp.hub test-suite.

The production pinned-key allowlist holds real publisher keys whose private
halves live nowhere near this repo. Tests therefore generate their own Ed25519
keypair and register the public half into ``PINNED_PUBLISHER_KEYS`` via
``monkeypatch.setitem`` — ``verify.py`` holds a reference to that same dict, so
the injection is visible to it and is undone automatically after each test.

Never mutate ``PINNED_PUBLISHER_KEYS`` without monkeypatch.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vcp.hub.keys import PINNED_PUBLISHER_KEYS
from vcp.hub.lint import write_index

TEST_KEY_ID = "test-signer"
FIXED_SIGNED_AT = "2026-07-10T00:00:00+00:00"


def public_pem(private_key: Ed25519PrivateKey) -> str:
    """PEM (SubjectPublicKeyInfo) text for the public half of ``private_key``."""
    return (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


def make_sidecar(
    content: bytes,
    private_key: Ed25519PrivateKey,
    key_id: str = TEST_KEY_ID,
    *,
    content_hash: str | None = None,
    algorithm: str = "Ed25519",
    version: int = 1,
    signature_b64: str | None = None,
) -> bytes:
    """Build a ``.ed25519.sig`` sidecar. Overrides exist for negative tests."""
    if signature_b64 is None:
        signature_b64 = base64.b64encode(private_key.sign(content)).decode("ascii")
    sidecar = {
        "version": version,
        "algorithm": algorithm,
        "key_id": key_id,
        "content_hash": content_hash or hashlib.sha256(content).hexdigest(),
        "signed_at": FIXED_SIGNED_AT,
        "signature": signature_b64,
    }
    return json.dumps(sidecar, indent=2, sort_keys=True).encode("utf-8")


@pytest.fixture(scope="session")
def test_private_key() -> Ed25519PrivateKey:
    """A keypair the tests own end-to-end (session-scoped: generation is pure)."""
    return Ed25519PrivateKey.generate()


@pytest.fixture
def pinned_test_key(monkeypatch, test_private_key) -> str:
    """Register the test public key into the pinned allowlist for one test."""
    monkeypatch.setitem(PINNED_PUBLISHER_KEYS, TEST_KEY_ID, public_pem(test_private_key))
    return TEST_KEY_ID


@pytest.fixture
def sign_artifact(test_private_key):
    """``sign_artifact(content, key_id=..., private_key=...) -> sidecar bytes``."""

    def _sign(
        content: bytes,
        key_id: str = TEST_KEY_ID,
        private_key: Ed25519PrivateKey | None = None,
        **overrides,
    ) -> bytes:
        return make_sidecar(
            content,
            private_key if private_key is not None else test_private_key,
            key_id=key_id,
            **overrides,
        )

    return _sign


ARTIFACT_BODY = "---\nid: {id}\nversion: {version}\ntitle: T\n---\nbody text for {id}\n"


def artifact_text(artifact_id: str, version: str = "1.0.0") -> str:
    """Artifact markdown with YAML frontmatter (publish reads it for metadata)."""
    return ARTIFACT_BODY.format(id=artifact_id, version=version)


def build_entry_dict(
    artifact_id: str,
    version: str,
    content: bytes,
    key_id: str = TEST_KEY_ID,
    namespace: str = "creed-space",
) -> dict:
    return {
        "id": artifact_id,
        "version": version,
        "name": "T",
        "namespace": namespace,
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "trust_tier": "signed",
        "distribution": {
            "signatures": {"ed25519": key_id},
            "source_repo": "https://example.invalid/repo",
            "artifact": f"{artifact_id}.md",
        },
    }


def write_version_dir(
    hub_root: Path,
    artifact_id: str,
    version: str,
    content: bytes,
    sig_bytes: bytes,
    entry: dict,
    namespace: str = "creed-space",
) -> Path:
    """Write one ``namespaces/<ns>/<id>/<version>/`` directory. No index rebuild."""
    version_dir = hub_root / "namespaces" / namespace / artifact_id / version
    version_dir.mkdir(parents=True, exist_ok=True)
    (version_dir / f"{artifact_id}.md").write_bytes(content)
    (version_dir / f"{artifact_id}.md.ed25519.sig").write_bytes(sig_bytes)
    (version_dir / "entry.json").write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return version_dir


@pytest.fixture
def make_hub(tmp_path, test_private_key, pinned_test_key):
    """``make_hub(root=..., artifact_id=..., version=..., content=...) -> Path``.

    Builds a lint-clean hub tree with a regenerated index.json.
    """

    def _make(
        root: Path | None = None,
        artifact_id: str = "anti_gaslighting",
        version: str = "1.0.0",
        content: bytes | None = None,
    ) -> Path:
        hub_root = Path(root) if root is not None else tmp_path / "hub"
        hub_root.mkdir(parents=True, exist_ok=True)
        body = content if content is not None else artifact_text(artifact_id, version).encode("utf-8")
        sig_bytes = make_sidecar(body, test_private_key)
        entry = build_entry_dict(artifact_id, version, body)
        write_version_dir(hub_root, artifact_id, version, body, sig_bytes, entry)
        report = write_index(hub_root)
        assert report.ok, report.problems
        return hub_root

    return _make
