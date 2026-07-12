"""Publishing signed artifacts into a hub tree (vcp.hub.publish)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import TEST_KEY_ID, artifact_text, make_sidecar
from vcp.hub.errors import VerificationError
from vcp.hub.lint import lint_hub_tree
from vcp.hub.publish import build_entry, publish

ARTIFACT_ID = "anti_gaslighting"
REF = f"creed-space/{ARTIFACT_ID}@1.0.0"


@pytest.fixture
def signed_artifact(tmp_path, test_private_key, pinned_test_key):
    """A signed <id>.md on disk, with its sidecar. Returns (path, resign)."""
    source = tmp_path / "source"
    source.mkdir()
    md_path = source / f"{ARTIFACT_ID}.md"

    def _write(text: str) -> Path:
        content = text.encode("utf-8")
        md_path.write_bytes(content)
        md_path.with_suffix(".md.ed25519.sig").write_bytes(make_sidecar(content, test_private_key))
        return md_path

    _write(artifact_text(ARTIFACT_ID))
    return md_path, _write


@pytest.fixture
def hub_root(tmp_path):
    root = tmp_path / "hub"
    root.mkdir()
    return root


def test_publish_writes_a_lint_clean_tree_with_an_index(signed_artifact, hub_root):
    md_path, _ = signed_artifact

    ref = publish(md_path, hub_root)

    assert ref == REF
    assert (hub_root / "index.json").is_file()
    # PR-time posture: publish REGENERATES index.json but cannot SIGN it — only the
    # maintainer release ceremony holds the root key. `vcp lint --pr` is the check a
    # publisher runs, so the signed-index requirement is off here. A strict lint of
    # the same tree correctly refuses it until the ceremony signs the index.
    assert lint_hub_tree(hub_root, require_signed_index=False).ok
    strict = lint_hub_tree(hub_root)
    assert any("index.json" in p and "unsigned" in p for p in strict.problems)


def test_unsigned_artifact_is_never_published(tmp_path, hub_root, pinned_test_key):
    md_path = tmp_path / f"{ARTIFACT_ID}.md"
    md_path.write_text(artifact_text(ARTIFACT_ID), encoding="utf-8")

    with pytest.raises(VerificationError, match="never published"):
        publish(md_path, hub_root)


def test_republishing_a_version_with_different_content_is_refused(signed_artifact, hub_root):
    md_path, rewrite = signed_artifact
    publish(md_path, hub_root)
    rewrite(artifact_text(ARTIFACT_ID) + "an extra clause\n")

    with pytest.raises(VerificationError, match="immutable"):
        publish(md_path, hub_root)


def test_republishing_identical_bytes_is_allowed(signed_artifact, hub_root):
    md_path, _ = signed_artifact
    publish(md_path, hub_root)

    assert publish(md_path, hub_root) == REF


def test_build_entry_issues_only_the_signed_tier_and_records_the_signer(signed_artifact):
    md_path, _ = signed_artifact

    entry = build_entry(md_path)

    assert entry["trust_tier"] == "signed"
    assert entry["distribution"]["signatures"] == {"ed25519": TEST_KEY_ID}


def test_base_entry_legacy_fields_survive_into_the_published_entry(signed_artifact, hub_root):
    md_path, _ = signed_artifact
    base_entry = {
        "id": ARTIFACT_ID,
        "version": "1.0.0",
        "name": "Anti Gaslighting",
        "tier": "tier_a_certified",
        "wefa_priors": {"autonomy": 0.9},
    }

    publish(md_path, hub_root, base_entry=base_entry)

    entry = json.loads((hub_root / "namespaces" / "creed-space" / ARTIFACT_ID / "1.0.0" / "entry.json").read_text())
    assert entry["tier"] == "tier_a_certified"
    assert entry["wefa_priors"] == {"autonomy": 0.9}
    assert entry["name"] == "Anti Gaslighting"
