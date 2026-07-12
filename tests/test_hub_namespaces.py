"""Delegated publisher trust for community namespaces (Creed Commons launch).

The client's root of trust never changes: it is the pinned Creed Space key
allowlist. Community publishing works by DELEGATION through a
``namespace_registry.json`` that must itself verify against the pinned ROOT key.
These tests pin the delegated-trust design end to end:

- a namespace registry is trusted only when root-signed, untampered, and carrying
  the founder namespace;
- an artifact in namespace X must be signed by a key REGISTERED TO X — keys never
  cross namespaces, and community keys are never a new root;
- the ``verified`` tier is a domain-separated ROOT counter-signature that no
  publisher can self-declare;
- revocation blocks future installs while a locked, on-disk tree keeps verifying
  against the PEM pinned at install time (TOFU-style).

Fixtures follow the repo rules: a second "community" keypair distinct from the
test root, the registry document signed by the TEST ROOT key (registered via the
``pinned_test_key`` monkeypatch fixture), tmp_path trees, and no direct mutation
of ``PINNED_PUBLISHER_KEYS``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import (
    COMMUNITY_KEY_ID,
    TEST_KEY_ID,
    artifact_text,
    build_entry_dict,
    make_countersig,
    make_detached_sidecar,
    make_registry_doc,
    make_sidecar,
    public_pem,
    sign_index,
    write_namespace_registry,
    write_version_dir,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vcp.hub import cli
from vcp.hub.errors import HubError, VerificationError
from vcp.hub.install import install, verify_tree
from vcp.hub.lint import lint_hub_tree, write_index
from vcp.hub.namespace_registry import (
    FOUNDER_NAMESPACE,
    check_community_name,
    parse_namespace_registry,
)
from vcp.hub.registry import RegistryClient
from vcp.hub.verify import NS_REGISTRY_CONTEXT

COMMUNITY_NS = "acme-values"
COMMUNITY_ID = "acme_charter"
COMMUNITY_REF = f"{COMMUNITY_NS}/{COMMUNITY_ID}"

VERIFIED_ID = "verified_charter"
VERIFIED_REF = f"{FOUNDER_NAMESPACE}/{VERIFIED_ID}"
VERIFIED_FULL_REF = f"{VERIFIED_REF}@1.0.0"


def sign_registry_doc(doc: bytes, key: Ed25519PrivateKey, key_id: str = TEST_KEY_ID) -> bytes:
    """Root sidecar for a namespace-registry document (domain-separated)."""
    return make_detached_sidecar(doc, key, NS_REGISTRY_CONTEXT, key_id=key_id)


# --- builders ----------------------------------------------------------------


def founder_community_doc(root_key: Ed25519PrivateKey, community_key: Ed25519PrivateKey) -> bytes:
    """Registry doc binding the founder (root key) and 'acme-values' (community key)."""
    return make_registry_doc(
        {
            FOUNDER_NAMESPACE: {TEST_KEY_ID: public_pem(root_key)},
            COMMUNITY_NS: {COMMUNITY_KEY_ID: public_pem(community_key)},
        }
    )


def build_community_hub(hub_root: Path, root_key: Ed25519PrivateKey, community_key: Ed25519PrivateKey) -> bytes:
    """A RELEASED hub registering founder + 'acme-values', with one community-signed
    artifact under acme-values and a regenerated, root-signed, lint-clean index.

    Returns the artifact bytes. Requires ``pinned_test_key`` to be active so the
    root-signed registry sidecar and index signature verify.
    """
    doc = founder_community_doc(root_key, community_key)
    write_namespace_registry(hub_root, doc, sign_registry_doc(doc, root_key))
    content = artifact_text(COMMUNITY_ID).encode("utf-8")
    sig = make_sidecar(content, community_key, key_id=COMMUNITY_KEY_ID)
    entry = build_entry_dict(COMMUNITY_ID, "1.0.0", content, key_id=COMMUNITY_KEY_ID, namespace=COMMUNITY_NS)
    write_version_dir(hub_root, COMMUNITY_ID, "1.0.0", content, sig, entry, namespace=COMMUNITY_NS)
    report = write_index(hub_root)
    assert report.ok, report.problems
    sign_index(hub_root, root_key)
    return content


def build_verified_hub(hub_root: Path, root_key: Ed25519PrivateKey) -> tuple[bytes, Path]:
    """A founder (creed-space) artifact at trust_tier 'verified' with a valid ROOT
    counter-signature bound to its ref. Uses the founder builtin registry (no
    registry file).

    Returns (content, version_dir). Does NOT build the index — callers that install
    run ``release_index`` for a signed one; the lint-only negative cases skip it.
    """
    content = artifact_text(VERIFIED_ID).encode("utf-8")
    sig = make_sidecar(content, root_key)
    entry = build_entry_dict(VERIFIED_ID, "1.0.0", content)
    entry["trust_tier"] = "verified"
    entry["distribution"]["counter_signatures"] = {"ed25519": TEST_KEY_ID}
    vdir = write_version_dir(hub_root, VERIFIED_ID, "1.0.0", content, sig, entry)
    (vdir / f"{VERIFIED_ID}.md.ed25519.countersig").write_bytes(
        make_countersig(content, root_key, ref=VERIFIED_FULL_REF)
    )
    return content, vdir


def release_index(hub_root: Path, root_key: Ed25519PrivateKey) -> None:
    """Regenerate index.json and root-sign it — a hub is only installable once released."""
    report = write_index(hub_root)
    assert report.ok, report.problems
    sign_index(hub_root, root_key)


# --- 1. parse a valid signed registry ----------------------------------------


def test_valid_signed_registry_parses_and_exposes_community_keys(
    test_private_key, community_private_key, pinned_test_key
):
    doc = founder_community_doc(test_private_key, community_private_key)

    registry = parse_namespace_registry(doc, sign_registry_doc(doc, test_private_key))

    assert registry.is_registered(COMMUNITY_NS)
    assert registry.publisher_keys(COMMUNITY_NS) == {COMMUNITY_KEY_ID: public_pem(community_private_key)}
    assert registry.sequence == 1


# --- 2-5. the registry cannot vouch for itself (root of trust never moves) ----


def test_unsigned_registry_is_refused(test_private_key, community_private_key):
    doc = founder_community_doc(test_private_key, community_private_key)

    with pytest.raises(VerificationError, match="unsigned"):
        parse_namespace_registry(doc, None)


def test_registry_tampered_after_signing_is_refused(test_private_key, community_private_key, pinned_test_key):
    doc = founder_community_doc(test_private_key, community_private_key)
    sig = sign_registry_doc(doc, test_private_key)
    tampered = doc + b"   "  # any post-signing byte change breaks the root hash

    with pytest.raises(VerificationError, match="content hash mismatch"):
        parse_namespace_registry(tampered, sig)


def test_registry_signed_by_a_non_root_key_is_refused(test_private_key, community_private_key, pinned_test_key):
    """A community key can never authorize a registry: only the pinned root may."""
    doc = founder_community_doc(test_private_key, community_private_key)
    community_signed = sign_registry_doc(doc, community_private_key, key_id=COMMUNITY_KEY_ID)

    with pytest.raises(VerificationError, match="pinned publisher allowlist"):
        parse_namespace_registry(doc, community_signed)


def test_registry_signed_as_a_plain_artifact_is_refused(test_private_key, community_private_key, pinned_test_key):
    """Domain separation: a ROOT signature over the RAW registry bytes (an artifact-
    shaped signature) is not a registry signature. Only NS_REGISTRY_CONTEXT counts,
    so no signature of another document kind can be replayed as a trust document."""
    doc = founder_community_doc(test_private_key, community_private_key)
    artifact_shaped = make_sidecar(doc, test_private_key)  # signs `doc`, not CONTEXT + doc

    with pytest.raises(VerificationError, match="verification FAILED"):
        parse_namespace_registry(doc, artifact_shaped)


def test_registry_missing_the_founder_namespace_is_refused(test_private_key, community_private_key, pinned_test_key):
    doc = make_registry_doc({COMMUNITY_NS: {COMMUNITY_KEY_ID: public_pem(community_private_key)}})

    with pytest.raises(VerificationError, match="founder namespace"):
        parse_namespace_registry(doc, sign_registry_doc(doc, test_private_key))


def test_registry_without_a_monotonic_sequence_is_refused(test_private_key, community_private_key, pinned_test_key):
    """The sequence is what makes rollback detectable; a registry without one is refused."""
    doc = founder_community_doc(test_private_key, community_private_key)
    unsequenced = json.loads(doc)
    del unsequenced["sequence"]
    raw = json.dumps(unsequenced, indent=2, sort_keys=True).encode("utf-8")

    with pytest.raises(VerificationError, match="no valid monotonic sequence"):
        parse_namespace_registry(raw, sign_registry_doc(raw, test_private_key))


# --- 6. community name policy -------------------------------------------------


@pytest.mark.parametrize(
    "name, existing, match",
    [
        ("ab", set(), "3-63"),  # too short
        ("vcp", set(), "reserved"),  # reserved infrastructure term
        ("creed", set(), "reserved"),  # reserved founder-adjacent term
        ("creedspace", set(), "reserved"),  # separator-fold of the founder name
        # Underscores are now rejected by the CHARSET gate before the reserved-name
        # check is ever reached — 'creed_space' can never be registered either way.
        ("creed_space", set(), "must match"),
        ("acme-c0rp", {"acme-corp"}, "confusable"),  # homoglyph squat (0 -> o)
    ],
)
def test_check_community_name_rejects_policy_violations(name, existing, match):
    with pytest.raises(VerificationError, match=match):
        check_community_name(name, existing)


def test_check_community_name_accepts_a_clean_distinct_name():
    check_community_name("acme-values", {"other-org"})  # must not raise


# --- 7. end-to-end community install pins the community key -------------------


def test_community_artifact_installs_and_pins_the_community_key(
    tmp_path, test_private_key, community_private_key, pinned_test_key
):
    hub = tmp_path / "hub"
    build_community_hub(hub, test_private_key, community_private_key)
    target = tmp_path / "artifacts"

    result = install(COMMUNITY_REF, target, RegistryClient(str(hub)))

    assert result.version == "1.0.0"
    pin = json.loads((target / "vcp.lock").read_text())["artifacts"][COMMUNITY_REF]
    assert pin["key_id"] == COMMUNITY_KEY_ID
    assert pin["public_key"] == public_pem(community_private_key)
    assert verify_tree(target) == [f"{COMMUNITY_REF}@1.0.0"]


# --- 8. keys do not cross namespaces -----------------------------------------


def _resign_community_artifact_with_root(hub: Path, root_key: Ed25519PrivateKey) -> None:
    """Replace the acme-values artifact's sidecar with a ROOT-signed one (key id
    'test-signer', which is NOT registered to acme-values). Content is unchanged,
    so only the signer-vs-namespace check can reject it."""
    vdir = hub / "namespaces" / COMMUNITY_NS / COMMUNITY_ID / "1.0.0"
    content = (vdir / f"{COMMUNITY_ID}.md").read_bytes()
    (vdir / f"{COMMUNITY_ID}.md.ed25519.sig").write_bytes(make_sidecar(content, root_key, key_id=TEST_KEY_ID))


def test_cross_namespace_signing_is_refused_at_install(
    tmp_path, test_private_key, community_private_key, pinned_test_key
):
    hub = tmp_path / "hub"
    build_community_hub(hub, test_private_key, community_private_key)
    _resign_community_artifact_with_root(hub, test_private_key)

    with pytest.raises(VerificationError, match="keys registered for this namespace"):
        install(COMMUNITY_REF, tmp_path / "artifacts", RegistryClient(str(hub)))


def test_cross_namespace_signing_is_refused_by_lint(tmp_path, test_private_key, community_private_key, pinned_test_key):
    hub = tmp_path / "hub"
    build_community_hub(hub, test_private_key, community_private_key)
    _resign_community_artifact_with_root(hub, test_private_key)

    report = lint_hub_tree(hub)

    assert not report.ok
    assert any("keys registered for this namespace" in p for p in report.problems)


# --- 9. an unregistered namespace directory is a lint problem -----------------


def test_artifact_in_an_unregistered_namespace_dir_is_a_lint_problem(
    tmp_path, test_private_key, community_private_key, pinned_test_key
):
    hub = tmp_path / "hub"
    build_community_hub(hub, test_private_key, community_private_key)
    # Syntactically valid, but absent from the signed registry.
    (hub / "namespaces" / "rogue-ns" / "thing" / "1.0.0").mkdir(parents=True)

    report = lint_hub_tree(hub)

    assert not report.ok
    assert any("rogue-ns" in p and "not registered" in p for p in report.problems)


# --- 10-11. the `verified` tier is a domain-separated ROOT counter-signature --


def test_verified_tier_installs_with_a_root_countersignature(tmp_path, test_private_key, pinned_test_key):
    hub = tmp_path / "hub"
    build_verified_hub(hub, test_private_key)
    release_index(hub, test_private_key)
    target = tmp_path / "artifacts"

    install(VERIFIED_REF, target, RegistryClient(str(hub)))

    pin = json.loads((target / "vcp.lock").read_text())["artifacts"][VERIFIED_REF]
    assert pin["trust_tier"] == "verified"
    installed = target / FOUNDER_NAMESPACE / VERIFIED_ID / "1.0.0"
    assert (installed / f"{VERIFIED_ID}.md.ed25519.countersig").is_file()
    assert verify_tree(target) == [VERIFIED_FULL_REF]


def test_verified_tier_rejects_a_countersig_copied_from_the_artifact_signature(
    tmp_path, test_private_key, pinned_test_key
):
    """Domain separation: the artifact's own signature signs `content`, the
    counter-signature signs COUNTERSIGN_CONTEXT+ref+NUL+content — a copy cannot pass."""
    hub = tmp_path / "hub"
    _content, vdir = build_verified_hub(hub, test_private_key)
    release_index(hub, test_private_key)
    own_sig = (vdir / f"{VERIFIED_ID}.md.ed25519.sig").read_bytes()
    (vdir / f"{VERIFIED_ID}.md.ed25519.countersig").write_bytes(own_sig)

    with pytest.raises(VerificationError, match="verification FAILED"):
        install(VERIFIED_REF, tmp_path / "artifacts", RegistryClient(str(hub)))


def test_verified_tier_rejects_a_community_signed_countersig(
    tmp_path, test_private_key, community_private_key, pinned_test_key
):
    """Only the ROOT issues the verified tier — a community key cannot."""
    hub = tmp_path / "hub"
    content, vdir = build_verified_hub(hub, test_private_key)
    release_index(hub, test_private_key)
    forged = make_countersig(content, community_private_key, ref=VERIFIED_FULL_REF, key_id=COMMUNITY_KEY_ID)
    (vdir / f"{VERIFIED_ID}.md.ed25519.countersig").write_bytes(forged)

    with pytest.raises(VerificationError, match="pinned publisher allowlist"):
        install(VERIFIED_REF, tmp_path / "artifacts", RegistryClient(str(hub)))


def test_verified_tier_without_a_countersig_is_a_lint_problem(tmp_path, test_private_key, pinned_test_key):
    hub = tmp_path / "hub"
    content = artifact_text(VERIFIED_ID).encode("utf-8")
    entry = build_entry_dict(VERIFIED_ID, "1.0.0", content)
    entry["trust_tier"] = "verified"
    write_version_dir(hub, VERIFIED_ID, "1.0.0", content, make_sidecar(content, test_private_key), entry)

    # PR-time lint: the index is not signed yet, so the self-declared 'verified' tier
    # is the only problem this tree has.
    report = lint_hub_tree(hub, require_signed_index=False)

    assert not report.ok
    assert any("no .ed25519.countersig sidecar exists" in p for p in report.problems)


def test_verified_tier_without_a_countersig_is_refused_at_install(tmp_path, test_private_key, pinned_test_key):
    hub = tmp_path / "hub"
    _content, vdir = build_verified_hub(hub, test_private_key)
    release_index(hub, test_private_key)
    (vdir / f"{VERIFIED_ID}.md.ed25519.countersig").unlink()

    with pytest.raises(HubError):
        install(VERIFIED_REF, tmp_path / "artifacts", RegistryClient(str(hub)))


def test_a_countersig_under_the_signed_tier_is_a_lint_problem(tmp_path, test_private_key, pinned_test_key):
    """Entry and sidecars must agree: a counter-signature implies the verified tier."""
    hub = tmp_path / "hub"
    content = artifact_text("signed_charter").encode("utf-8")
    entry = build_entry_dict("signed_charter", "1.0.0", content)  # trust_tier "signed"
    vdir = write_version_dir(hub, "signed_charter", "1.0.0", content, make_sidecar(content, test_private_key), entry)
    (vdir / "signed_charter.md.ed25519.countersig").write_bytes(
        make_countersig(content, test_private_key, ref=f"{FOUNDER_NAMESPACE}/signed_charter@1.0.0")
    )

    report = lint_hub_tree(hub, require_signed_index=False)

    assert not report.ok
    assert any("must agree" in p for p in report.problems)


# --- 12. revocation: TOFU-style semantics ------------------------------------


def test_revoking_a_namespace_blocks_new_installs_but_not_the_locked_tree(
    tmp_path, test_private_key, community_private_key, pinned_test_key
):
    hub = tmp_path / "hub"
    build_community_hub(hub, test_private_key, community_private_key)
    target = tmp_path / "artifacts"
    install(COMMUNITY_REF, target, RegistryClient(str(hub)))  # succeeds, pins the community PEM

    # Revoke: re-sign a registry doc that no longer registers acme-values. The
    # sequence advances (1 -> 2), as a real revocation ceremony's would.
    revoked = make_registry_doc({FOUNDER_NAMESPACE: {TEST_KEY_ID: public_pem(test_private_key)}}, sequence=2)
    write_namespace_registry(hub, revoked, sign_registry_doc(revoked, test_private_key))

    # A FRESH install (fresh client re-reads the registry) is now refused.
    with pytest.raises(VerificationError, match="not registered"):
        install(COMMUNITY_REF, tmp_path / "artifacts2", RegistryClient(str(hub)))

    # Lint flags the now-orphaned namespace directory.
    report = lint_hub_tree(hub)
    assert any(COMMUNITY_NS in p and "not registered" in p for p in report.problems)

    # BUT the already-installed tree still verifies: vcp.lock pinned the exact PEM
    # at install time, so a later registry change cannot retroactively invalidate
    # an on-disk artifact (deliberate trust-on-first-use semantics).
    assert verify_tree(target) == [f"{COMMUNITY_REF}@1.0.0"]


# --- 13. RegistryClient.namespace_registry() resolution ----------------------


def test_hub_without_a_registry_file_is_founder_only(make_hub):
    registry = RegistryClient(str(make_hub())).namespace_registry()

    assert registry.is_registered(FOUNDER_NAMESPACE)
    assert not registry.is_registered(COMMUNITY_NS)


def test_invalid_registry_file_fails_closed_even_for_founder_refs(make_hub, tmp_path, test_private_key):
    hub = make_hub()  # lint-clean, no registry file (index already built)
    # A present-but-UNSIGNED registry is an attack, not a downgrade: refuse
    # everything, including a founder-namespace install that would otherwise work.
    doc = make_registry_doc({FOUNDER_NAMESPACE: {TEST_KEY_ID: public_pem(test_private_key)}})
    write_namespace_registry(hub, doc, None)

    with pytest.raises(VerificationError, match="unsigned"):
        install("creed-space/anti_gaslighting", tmp_path / "artifacts", RegistryClient(str(hub)))


# --- 14. cli namespaces subcommand -------------------------------------------


def test_cli_namespaces_lists_registered_names(
    tmp_path, test_private_key, community_private_key, pinned_test_key, capsys
):
    hub = tmp_path / "hub"
    build_community_hub(hub, test_private_key, community_private_key)

    assert cli.main(["namespaces", "--registry", str(hub)]) == 0

    out = capsys.readouterr().out
    assert COMMUNITY_NS in out
    assert FOUNDER_NAMESPACE in out
