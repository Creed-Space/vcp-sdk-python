"""Post-review hardening of the Creed Commons trust chain.

The properties pinned here all answer the same question: *what is the client
allowed to believe, and who told it?* Before this hardening, registry-controlled
metadata (index.json, entry.json) was trusted on sight, so a registry that turned
hostile — or an attacker who could serve bytes as one — could re-point a signed
artifact, downgrade its trust tier, replay a retired trust document, or replay a
counter-signature onto different bytes. Each is now refused:

- **the index is ROOT-SIGNED** (domain-separated): unsigned, tampered, community-
  signed, or sequence-less indexes refuse everything (T3 — the registry can never
  supply its own trust root);
- **entry.json is UNSIGNED and therefore not an authority**: its load-bearing
  fields (hash, tier, artifact filename) must agree with the signed index (T2);
- **anti-rollback**: a validly-signed but STALE index or namespace registry is a
  replay of retired state (e.g. re-admitting a revoked key) and is refused against
  the lockfile's high-water mark;
- **counter-signatures are bound to a ref**: one issued for ``ns/id@1.0.0`` cannot
  be replayed onto the same bytes republished at ``@2.0.0`` or under another id;
- **name policy + root-collision**: a community namespace can neither squat the
  founder's brand space nor claim root identity by reusing a pinned key id or PEM;
- **``verify_tree(registry=...)``** re-checks every pin against the LIVE signed
  index, which is the only thing an attacker holding the local tree cannot forge.
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
from vcp.hub.errors import VerificationError
from vcp.hub.install import install, verify_tree
from vcp.hub.lint import lint_hub_tree, write_index
from vcp.hub.namespace_registry import (
    FOUNDER_NAMESPACE,
    check_community_name,
    parse_namespace_registry,
)
from vcp.hub.registry import RegistryClient
from vcp.hub.verify import NS_REGISTRY_CONTEXT, verify_countersignature

ARTIFACT_ID = "anti_gaslighting"
REF = f"{FOUNDER_NAMESPACE}/{ARTIFACT_ID}"

COMMUNITY_NS = "acme-values"
COMMUNITY_ID = "acme_charter"
COMMUNITY_REF = f"{COMMUNITY_NS}/{COMMUNITY_ID}"


# --- builders ----------------------------------------------------------------


def entry_path(hub_root: Path, namespace: str = FOUNDER_NAMESPACE, artifact_id: str = ARTIFACT_ID) -> Path:
    return Path(hub_root) / "namespaces" / namespace / artifact_id / "1.0.0" / "entry.json"


def rewrite_index(hub_root: Path, root_key: Ed25519PrivateKey, **changes) -> None:
    """Edit index.json's top-level fields and RE-SIGN it.

    The result is a perfectly valid root signature over DIFFERENT content — exactly
    what a compromised-but-key-holding release ceremony, or a rollback, looks like.
    """
    index_path = Path(hub_root) / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index.update(changes)
    index_path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sign_index(hub_root, root_key)


def community_doc(
    root_key: Ed25519PrivateKey, community_key: Ed25519PrivateKey, sequence: int = 1
) -> bytes:
    return make_registry_doc(
        {
            FOUNDER_NAMESPACE: {TEST_KEY_ID: public_pem(root_key)},
            COMMUNITY_NS: {COMMUNITY_KEY_ID: public_pem(community_key)},
        },
        sequence=sequence,
    )


def publish_registry(hub_root: Path, doc: bytes, root_key: Ed25519PrivateKey) -> None:
    """Write a namespace registry with a valid, domain-separated ROOT sidecar."""
    write_namespace_registry(hub_root, doc, make_detached_sidecar(doc, root_key, NS_REGISTRY_CONTEXT))


def build_community_hub(
    hub_root: Path,
    root_key: Ed25519PrivateKey,
    community_key: Ed25519PrivateKey,
    ns_sequence: int = 1,
) -> None:
    """A released community hub: signed registry, community-signed artifact, signed index."""
    publish_registry(hub_root, community_doc(root_key, community_key, ns_sequence), root_key)
    content = artifact_text(COMMUNITY_ID).encode("utf-8")
    write_version_dir(
        hub_root,
        COMMUNITY_ID,
        "1.0.0",
        content,
        make_sidecar(content, community_key, key_id=COMMUNITY_KEY_ID),
        build_entry_dict(COMMUNITY_ID, "1.0.0", content, key_id=COMMUNITY_KEY_ID, namespace=COMMUNITY_NS),
        namespace=COMMUNITY_NS,
    )
    report = write_index(hub_root)
    assert report.ok, report.problems
    sign_index(hub_root, root_key)


# --- 1-3. the index is root-signed, or it is worthless ------------------------


def test_unsigned_index_is_refused_by_install_and_by_strict_lint(make_hub, tmp_path):
    """An unsigned index decides version resolution, hashes and tiers on nobody's
    authority. Install refuses it outright; strict lint reports it; only the
    explicit PR-time posture (require_signed_index=False) tolerates it."""
    hub = make_hub()
    (hub / "index.json.ed25519.sig").unlink()

    with pytest.raises(VerificationError, match="unsigned"):
        install(REF, tmp_path / "artifacts", RegistryClient(str(hub)))

    strict = lint_hub_tree(hub)
    assert not strict.ok
    assert any("index.json" in p and "unsigned" in p for p in strict.problems)

    assert lint_hub_tree(hub, require_signed_index=False).ok


def test_index_tampered_after_signing_is_refused(make_hub, tmp_path):
    hub = make_hub()
    index_path = hub / "index.json"
    index_path.write_bytes(index_path.read_bytes() + b"   ")  # any post-signing byte change

    with pytest.raises(VerificationError, match="content hash mismatch"):
        install(REF, tmp_path / "artifacts", RegistryClient(str(hub)))


def test_index_signed_by_a_community_key_is_refused(make_hub, tmp_path, community_private_key):
    """Only the ROOT signs the index. A community publisher holding a registered key
    for its own namespace still cannot vouch for the index that governs everyone."""
    hub = make_hub()
    sign_index(hub, community_private_key, key_id=COMMUNITY_KEY_ID)

    with pytest.raises(VerificationError, match="pinned publisher allowlist"):
        install(REF, tmp_path / "artifacts", RegistryClient(str(hub)))


def test_index_without_a_monotonic_sequence_is_refused(make_hub, tmp_path, test_private_key):
    """A validly-signed index is still refused without the sequence that makes
    rollback detectable — signing is necessary, not sufficient."""
    hub = make_hub()
    index = json.loads((hub / "index.json").read_text(encoding="utf-8"))
    del index["sequence"]
    (hub / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sign_index(hub, test_private_key)

    with pytest.raises(VerificationError, match="no valid monotonic sequence"):
        install(REF, tmp_path / "artifacts", RegistryClient(str(hub)))


# --- 4. entry.json is unsigned, so the SIGNED index outranks it ---------------


@pytest.mark.parametrize(
    "field, value",
    [
        ("trust_tier", "verified"),  # self-declared promotion to the vouched-for tier
        ("content_sha256", "0" * 64),  # re-pointing the pin at other bytes
    ],
)
def test_entry_disagreeing_with_the_signed_index_is_refused(make_hub, tmp_path, field, value):
    hub = make_hub()
    path = entry_path(hub)
    entry = json.loads(path.read_text(encoding="utf-8"))
    entry[field] = value
    path.write_text(json.dumps(entry), encoding="utf-8")

    with pytest.raises(VerificationError, match="disagrees with the signed index"):
        install(REF, tmp_path / "artifacts", RegistryClient(str(hub)))


def test_entry_naming_a_different_artifact_file_than_the_signed_index_is_refused(make_hub, tmp_path):
    """The artifact FILENAME is load-bearing too: it selects which bytes get verified
    and installed, so a rewritten entry cannot swap it behind the index's back."""
    hub = make_hub()
    path = entry_path(hub)
    entry = json.loads(path.read_text(encoding="utf-8"))
    entry["distribution"]["artifact"] = "other.md"
    path.write_text(json.dumps(entry), encoding="utf-8")

    with pytest.raises(VerificationError, match="disagrees with the signed index"):
        install(REF, tmp_path / "artifacts", RegistryClient(str(hub)))


# --- 5. anti-rollback: a signed-but-STALE trust document is an attack ---------


def test_install_refuses_an_index_sequence_rollback(make_hub, tmp_path, test_private_key):
    """Re-serving a validly-signed OLDER index replays retired state (a since-fixed
    hash, a since-revoked tier). The lockfile's high-water mark refuses it."""
    hub = make_hub()
    target = tmp_path / "artifacts"
    rewrite_index(hub, test_private_key, sequence=2)

    install(REF, target, RegistryClient(str(hub)))  # lock records index_sequence=2

    assert json.loads((target / "vcp.lock").read_text())["registries"][str(hub)]["index_sequence"] == 2

    rewrite_index(hub, test_private_key, sequence=1)  # correctly signed, but stale

    with pytest.raises(VerificationError, match="index sequence went BACKWARDS"):
        install(REF, target, RegistryClient(str(hub)))


def test_install_refuses_a_namespace_registry_sequence_rollback(
    tmp_path, test_private_key, community_private_key, pinned_test_key
):
    """The same defence on the document that grants publisher keys: re-serving an
    older registry is how a revoked key gets re-admitted."""
    hub = tmp_path / "hub"
    build_community_hub(hub, test_private_key, community_private_key, ns_sequence=2)
    target = tmp_path / "artifacts"

    install(COMMUNITY_REF, target, RegistryClient(str(hub)))  # lock records namespace_sequence=2

    assert json.loads((target / "vcp.lock").read_text())["registries"][str(hub)]["namespace_sequence"] == 2

    # Re-sign the registry at a LOWER sequence — the stale document is still a
    # perfectly valid root signature; only the sequence exposes the replay.
    publish_registry(hub, community_doc(test_private_key, community_private_key, sequence=1), test_private_key)

    with pytest.raises(VerificationError, match="namespace registry sequence went BACKWARDS"):
        install(COMMUNITY_REF, target, RegistryClient(str(hub)))


# --- 6. counter-signatures are bound to one namespace/id@version --------------


def test_countersignature_is_bound_to_its_ref(pinned_test_key, test_private_key):
    """A `verified` counter-signature vouches for THESE bytes AS this ref. Identical
    bytes republished at another version or under another id are a different claim,
    so the signature must not carry over."""
    content = b"identical verified bytes, two refs\n"
    countersig = make_countersig(content, test_private_key, ref=f"{FOUNDER_NAMESPACE}/thing@1.0.0")

    verified = verify_countersignature(content, countersig, ref=f"{FOUNDER_NAMESPACE}/thing@1.0.0")
    assert verified.key_id == TEST_KEY_ID

    with pytest.raises(VerificationError, match="verification FAILED"):
        verify_countersignature(content, countersig, ref=f"{FOUNDER_NAMESPACE}/thing@2.0.0")

    with pytest.raises(VerificationError, match="verification FAILED"):
        verify_countersignature(content, countersig, ref=f"{FOUNDER_NAMESPACE}/other@1.0.0")


def test_countersignature_replayed_at_another_version_is_a_lint_problem(
    tmp_path, test_private_key, pinned_test_key
):
    """End to end: republishing the same bytes at 2.0.0 while reusing 1.0.0's
    counter-signature does not carry the verified tier across."""
    hub = tmp_path / "hub"
    vid = "verified_charter"
    content = artifact_text(vid).encode("utf-8")  # identical bytes at both versions
    countersig_v1 = make_countersig(content, test_private_key, ref=f"{FOUNDER_NAMESPACE}/{vid}@1.0.0")

    for version in ("1.0.0", "2.0.0"):
        entry = build_entry_dict(vid, version, content)
        entry["trust_tier"] = "verified"
        vdir = write_version_dir(hub, vid, version, content, make_sidecar(content, test_private_key), entry)
        (vdir / f"{vid}.md.ed25519.countersig").write_bytes(countersig_v1)  # replayed at 2.0.0

    report = lint_hub_tree(hub, require_signed_index=False)

    assert report.checked == [f"{FOUNDER_NAMESPACE}/{vid}@1.0.0"]  # the genuine one still passes
    assert any(f"{vid}@2.0.0" in p and "verification FAILED" in p for p in report.problems)


# --- 7. community name policy ------------------------------------------------


@pytest.mark.parametrize(
    "name, existing, match",
    [
        # The founder's brand space is reserved by PREFIX, not by an enumerable list.
        ("creedlike-values", set(), "reserved"),
        ("vcp-tools", set(), "reserved"),
        ("acme_corp", set(), "must match"),  # charset: underscores never parse
        ("acme-c0rp", {"acme-corp"}, "confusable"),  # homoglyph squat of a live name
        # Homoglyph fold maps both i and 1 to l, so 'admin' and 'adm1n' both fold to
        # 'admln' — the digit swap cannot dodge the reserved name.
        ("adm1n", set(), "confusable"),
    ],
)
def test_community_name_policy_refuses_squats(name, existing, match):
    with pytest.raises(VerificationError, match=match):
        check_community_name(name, existing)


def test_community_name_policy_accepts_a_clean_name():
    check_community_name("orchard-values", {"acme-corp", "other-org"})  # must not raise


# --- 8. a community namespace can never claim ROOT identity ------------------


def test_community_namespace_reusing_a_root_key_id_is_refused(
    test_private_key, community_private_key, pinned_test_key
):
    """Key ids are how the client names its root. A community namespace claiming
    'constitution-signer' would make its artifacts look root-signed."""
    doc = make_registry_doc(
        {
            FOUNDER_NAMESPACE: {TEST_KEY_ID: public_pem(test_private_key)},
            COMMUNITY_NS: {"constitution-signer": public_pem(community_private_key)},
        }
    )

    with pytest.raises(VerificationError, match="collides with a pinned ROOT"):
        parse_namespace_registry(doc, make_detached_sidecar(doc, test_private_key, NS_REGISTRY_CONTEXT))


def test_community_namespace_reusing_a_root_pem_under_a_new_key_id_is_refused(
    test_private_key, pinned_test_key
):
    """The key ITSELF is checked, not just its id: registering a pinned root PEM under
    a fresh id would delegate root signing authority into a community namespace."""
    doc = make_registry_doc(
        {
            FOUNDER_NAMESPACE: {TEST_KEY_ID: public_pem(test_private_key)},
            COMMUNITY_NS: {COMMUNITY_KEY_ID: public_pem(test_private_key)},  # root PEM, new id
        }
    )

    with pytest.raises(VerificationError, match="collides with a pinned ROOT"):
        parse_namespace_registry(doc, make_detached_sidecar(doc, test_private_key, NS_REGISTRY_CONTEXT))


# --- 9. verify_tree against the LIVE signed index ----------------------------


def test_verify_tree_with_a_registry_detects_revocation(make_hub, tmp_path, test_private_key):
    hub = make_hub()
    target = tmp_path / "artifacts"
    install(REF, target, RegistryClient(str(hub)))

    # Honest state: the live signed index still vouches for exactly this pin.
    assert verify_tree(target, registry=RegistryClient(str(hub))) == [f"{REF}@1.0.0"]

    # Revoke: drop the artifact from the index, advance the sequence, re-sign.
    rewrite_index(hub, test_private_key, artifacts={}, sequence=2)

    with pytest.raises(VerificationError, match="revoked or removed"):
        verify_tree(target, registry=RegistryClient(str(hub)))

    # The lockfile TOFU boundary, deliberately: vcp.lock is LOCAL state, so a plain
    # verify_tree still passes against it. Only a live, root-signed index can tell
    # you a pin was withdrawn — which is exactly why `--registry` exists.
    assert verify_tree(target) == [f"{REF}@1.0.0"]


def test_verify_tree_with_a_registry_detects_a_live_trust_tier_change(make_hub, tmp_path, test_private_key):
    """An attacker who rewrites BOTH the tree and the lock is outside verify_tree's
    local threat model — but they cannot forge the root-signed index, so the live
    re-check still catches a tier that no longer matches."""
    hub = make_hub()
    target = tmp_path / "artifacts"
    install(REF, target, RegistryClient(str(hub)))

    index = json.loads((hub / "index.json").read_text(encoding="utf-8"))
    index["artifacts"][REF]["versions"]["1.0.0"]["trust_tier"] = "verified"
    rewrite_index(hub, test_private_key, artifacts=index["artifacts"], sequence=2)

    with pytest.raises(VerificationError, match="disagrees with the live signed index"):
        verify_tree(target, registry=RegistryClient(str(hub)))


# --- 10. cli surfaces for both postures --------------------------------------


def test_cli_lint_pr_accepts_a_tree_whose_index_is_not_yet_signed(make_hub):
    """`vcp lint --pr` is what a publisher runs: only the maintainer ceremony holds
    the root key, so a PR's index is legitimately unsigned."""
    hub = make_hub()
    (hub / "index.json.ed25519.sig").unlink()

    assert cli.main(["lint", "--pr", str(hub)]) == 0
    assert cli.main(["lint", str(hub)]) == 1  # the release posture still refuses it


def test_cli_verify_with_a_registry_re_checks_against_the_live_index(make_hub, tmp_path, capsys):
    hub = make_hub()
    target = tmp_path / "artifacts"

    assert cli.main(["install", REF, "--target", str(target), "--registry", str(hub)]) == 0
    assert cli.main(["verify", "--target", str(target), "--registry", str(hub)]) == 0

    assert "vcp.lock + live signed index" in capsys.readouterr().out
