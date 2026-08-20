"""Hub-tree lint, index building, and registry-entry schema validation."""

from __future__ import annotations

import json

import pytest
from conftest import build_entry_dict, write_version_dir

from vcp.hub.entry_schema import validate_entry
from vcp.hub.errors import VerificationError
from vcp.hub.lint import build_index, lint_hub_tree, write_index

ARTIFACT_ID = "anti_gaslighting"
LABEL = f"creed-space/{ARTIFACT_ID}@1.0.0"


def _version_dir(hub_root):
    return hub_root / "namespaces" / "creed-space" / ARTIFACT_ID / "1.0.0"


def test_lint_passes_on_a_well_formed_tree(make_hub):
    report = lint_hub_tree(make_hub())

    assert report.ok
    assert report.checked == [LABEL]


def test_lint_refuses_an_artifact_with_no_signature_sidecar(make_hub):
    hub = make_hub()
    (_version_dir(hub) / f"{ARTIFACT_ID}.md.ed25519.sig").unlink()

    report = lint_hub_tree(hub)

    assert not report.ok
    assert any("unsigned artifacts are refused" in p for p in report.problems)


def test_lint_detects_artifact_bytes_tampered_after_signing(make_hub):
    hub = make_hub()
    artifact = _version_dir(hub) / f"{ARTIFACT_ID}.md"
    artifact.write_bytes(artifact.read_bytes() + b"\nsmuggled\n")

    report = lint_hub_tree(hub)

    assert any("content hash mismatch" in p for p in report.problems)


def test_lint_refuses_a_foreign_namespace_directory(make_hub):
    hub = make_hub()
    (hub / "namespaces" / "evil-corp" / "thing" / "1.0.0").mkdir(parents=True)

    report = lint_hub_tree(hub)

    assert any("is not registered in namespace_registry.json" in p for p in report.problems)


def test_lint_refuses_a_schema_invalid_entry(make_hub):
    hub = make_hub()
    entry_path = _version_dir(hub) / "entry.json"
    entry = json.loads(entry_path.read_text())
    entry["trust_tier"] = "gold"
    entry_path.write_text(json.dumps(entry))

    report = lint_hub_tree(hub)

    assert any("schema validation" in p for p in report.problems)


def test_build_index_reports_skipped_entries_and_indexes_only_passing_ones(make_hub):
    """A broken sibling is skipped from the index and surfaced as a problem."""
    hub = make_hub()
    broken = b"unsigned bytes"
    write_version_dir(
        hub,
        "broken_one",
        "1.0.0",
        broken,
        b"{}",  # structurally invalid sidecar
        build_entry_dict("broken_one", "1.0.0", broken),
    )

    index, report = build_index(hub)

    assert not report.ok
    assert any("broken_one" in p for p in report.problems)
    assert set(index["artifacts"]) == {f"creed-space/{ARTIFACT_ID}"}


def test_write_index_writes_index_json(make_hub):
    hub = make_hub()

    report = write_index(hub)

    assert report.ok
    index = json.loads((hub / "index.json").read_text())
    assert index["artifacts"][f"creed-space/{ARTIFACT_ID}"]["latest"] == "1.0.0"


def test_legacy_entry_validates_locally_but_is_not_publishable():
    legacy = {"id": "old_thing", "version": "1.0.0", "name": "Old Thing"}

    validate_entry(legacy, require_distribution=False)

    with pytest.raises(VerificationError, match="not publishable"):
        validate_entry(legacy, require_distribution=True)


def test_entry_with_empty_distribution_signatures_is_refused():
    entry = build_entry_dict(ARTIFACT_ID, "1.0.0", b"body")
    entry["distribution"]["signatures"] = {}

    with pytest.raises(VerificationError):
        validate_entry(entry, require_distribution=True)
