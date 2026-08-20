"""Shared fixtures for the vcp.hub test-suite.

The production pinned-key allowlist holds real publisher keys whose private
halves live nowhere near this repo. Tests therefore generate their own Ed25519
keypair and register the public half into ``PINNED_PUBLISHER_KEYS`` via
``monkeypatch.setitem`` — ``verify.py`` holds a reference to that same dict, so
the injection is visible to it and is undone automatically after each test.

Never mutate ``PINNED_PUBLISHER_KEYS`` without monkeypatch.

Three signature shapes exist and are NOT interchangeable (that is the point):

- artifact sidecars sign RAW content (``make_sidecar``);
- trust documents — the namespace registry and index.json — sign
  ``CONTEXT + content`` (``make_detached_sidecar``);
- ``verified``-tier counter-signatures sign ``CONTEXT + ref + NUL + content``
  (``make_countersig``), so they are bound to one ``namespace/id@version``.

A hub tree is only installable once its index is ROOT-SIGNED: ``write_index``
writes the document, ``sign_index`` performs the (test) release ceremony.
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
from vcp.hub.namespace_registry import REGISTRY_FILENAME, REGISTRY_VERSION
from vcp.hub.verify import INDEX_CONTEXT, countersign_message_context

TEST_KEY_ID = "test-signer"
FIXED_SIGNED_AT = "2026-07-10T00:00:00+00:00"

INDEX_FILENAME = "index.json"

# A community publisher key id, deliberately NOT pinned into the root allowlist:
# community trust is delegated through the root-signed namespace registry, never
# by expanding PINNED_PUBLISHER_KEYS.
COMMUNITY_KEY_ID = "acme-signer"


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


def make_detached_sidecar(
    content: bytes,
    private_key: Ed25519PrivateKey,
    context: bytes,
    key_id: str = TEST_KEY_ID,
    **overrides,
) -> bytes:
    """Build a DOMAIN-SEPARATED sidecar whose signature covers ``context + content``.

    Trust documents sign this way (``NS_REGISTRY_CONTEXT`` for the namespace
    registry, ``INDEX_CONTEXT`` for index.json, the ref-bound countersign context
    for the verified tier), so a signature of one document kind can never be
    replayed as another. ``content_hash`` still names sha256(content) for human
    correlation. Overrides feed the forgery tests.
    """
    overrides.setdefault(
        "signature_b64",
        base64.b64encode(private_key.sign(context + content)).decode("ascii"),
    )
    return make_sidecar(content, private_key, key_id=key_id, **overrides)


def make_countersig(
    content: bytes,
    private_key: Ed25519PrivateKey,
    ref: str,
    key_id: str = TEST_KEY_ID,
    **overrides,
) -> bytes:
    """Build a ``verified``-tier ``.ed25519.countersig`` sidecar bound to ``ref``.

    The signature covers ``COUNTERSIGN_CONTEXT + ref + NUL + content``: bound to the
    exact bytes AND the exact ``namespace/id@version``, so it can be neither an
    artifact's own signature nor a counter-signature replayed onto the same bytes
    republished under a different id or version.
    """
    return make_detached_sidecar(
        content,
        private_key,
        countersign_message_context(ref),
        key_id=key_id,
        **overrides,
    )


def make_registry_doc(namespaces: dict[str, dict[str, str]], sequence: int = 1) -> bytes:
    """Serialize a namespace-registry document.

    ``namespaces`` maps namespace -> {key_id: PEM}. The founder namespace must be
    included for the document to parse; callers control that so the missing-founder
    case can be exercised too. ``sequence`` is the monotonic anti-rollback counter
    (must be >= 1): clients keep a high-water mark and refuse a lower one, so a
    validly-signed but STALE registry cannot re-admit a revoked key.
    """
    doc = {
        "registry_version": REGISTRY_VERSION,
        "sequence": sequence,
        "namespaces": {ns: {"keys": keys} for ns, keys in namespaces.items()},
    }
    return json.dumps(doc, indent=2, sort_keys=True).encode("utf-8")


def write_namespace_registry(hub_root: Path, registry_bytes: bytes, sig_bytes: bytes | None) -> None:
    """Write ``namespace_registry.json`` and (when signed) its root sidecar."""
    hub_root.mkdir(parents=True, exist_ok=True)
    (hub_root / REGISTRY_FILENAME).write_bytes(registry_bytes)
    sig_path = hub_root / (REGISTRY_FILENAME + ".ed25519.sig")
    if sig_bytes is not None:
        sig_path.write_bytes(sig_bytes)
    elif sig_path.exists():
        sig_path.unlink()


def sign_index(hub_root: Path, private_key: Ed25519PrivateKey, key_id: str = TEST_KEY_ID) -> None:
    """Root-sign ``index.json`` exactly as it sits on disk (the release ceremony).

    ``write_index`` only WRITES the index; signing it is a separate, root-held step.
    Clients refuse an unsigned or tampered index, so every tree that install or a
    strict lint touches must be signed here — and RE-signed after any later edit to
    index.json, or the sidecar's hash check will (correctly) reject it.
    """
    root = Path(hub_root)
    index_bytes = (root / INDEX_FILENAME).read_bytes()
    sidecar = make_detached_sidecar(index_bytes, private_key, INDEX_CONTEXT, key_id=key_id)
    (root / (INDEX_FILENAME + ".ed25519.sig")).write_bytes(sidecar)


@pytest.fixture(scope="session")
def test_private_key() -> Ed25519PrivateKey:
    """A keypair the tests own end-to-end (session-scoped: generation is pure)."""
    return Ed25519PrivateKey.generate()


@pytest.fixture(scope="session")
def community_private_key() -> Ed25519PrivateKey:
    """A SECOND keypair, standing in for a community publisher. Distinct from the
    test root and never pinned — trust in it is granted only via a root-signed
    namespace registry entry, never via the pinned allowlist."""
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

    Builds a lint-clean hub tree with a regenerated AND root-signed index.json —
    i.e. a released hub, the only kind a client will install from. Tests that want
    the unsigned-index (PR-time) posture delete ``index.json.ed25519.sig``.
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
        sign_index(hub_root, test_private_key)
        return hub_root

    return _make
