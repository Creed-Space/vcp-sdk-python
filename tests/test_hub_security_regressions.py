"""Regression pins for the 2026-11-04 Claude Security findings on vcp.hub.

- F26/F41: publisher signatures are domain-separated AND bound to
  ``namespace/id@version``. Already-signed bytes cannot be republished under
  another ref, and no other root-signed message (index, registry,
  counter-signature) can pose as an artifact. Legacy v1 content-only sidecars
  verify only for the pinned ``(ref, sha256)`` pairs shipped before ref binding.
- F37 (client side): ``publish`` cannot repoint an existing version at a
  differently-named artifact, and ``install`` refuses a registry that serves
  different bytes for a version the lockfile already pinned.
- F45: ``verify_tree(registry=...)`` enforces AND advances the lockfile's
  anti-rollback high-water mark, and every client refuses an index older than
  its max age (root-signed ``issued_at``), so a replayed pre-revocation index
  cannot hide a revocation (beyond the max-age window for a client that never
  saw the revoking release).
- F56: publisher-controlled display text cannot carry terminal control
  characters: lint refuses them, and ``vcp search`` escapes them on output.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from conftest import (
    TEST_KEY_ID,
    UTC,
    artifact_text,
    build_entry_dict,
    make_detached_sidecar,
    make_sidecar,
    sign_index,
    write_version_dir,
)

from vcp.hub import cli
from vcp.hub import registry as registry_mod
from vcp.hub import verify as verify_mod
from vcp.hub.entry_schema import validate_entry
from vcp.hub.errors import HubError, VerificationError
from vcp.hub.install import install, verify_tree
from vcp.hub.lint import build_index, lint_hub_tree, write_index
from vcp.hub.publish import publish
from vcp.hub.registry import DEFAULT_MAX_INDEX_AGE, RegistryClient, validate_ref
from vcp.hub.verify import INDEX_CONTEXT, artifact_message_context, verify_artifact_bytes

# A vcp-hub checkout: the sibling directory in a monorepo, or VCP_HUB_DIR. The
# standalone SDK repo ships no hub, so the shipped-index test skips without one.
SHIPPED_HUB = Path(os.environ.get("VCP_HUB_DIR") or Path(__file__).resolve().parents[2] / "vcp-hub")
NS = "creed-space"
ART = "anti_gaslighting"
REF = f"{NS}/{ART}"


def _version_dir(hub: Path, artifact_id: str, version: str) -> Path:
    return hub / "namespaces" / NS / artifact_id / version


def _copy_version(hub: Path, src: tuple[str, str], dst: tuple[str, str]) -> Path:
    """Copy a published artifact's bytes + signature verbatim to another ref and
    hand-write a self-consistent entry.json there (the F26/F41 PR author's move)."""
    src_dir = _version_dir(hub, *src)
    src_entry = json.loads((src_dir / "entry.json").read_text(encoding="utf-8"))
    name = src_entry["distribution"]["artifact"]
    dst_dir = _version_dir(hub, *dst)
    dst_dir.mkdir(parents=True)
    shutil.copy(src_dir / name, dst_dir / name)
    shutil.copy(src_dir / f"{name}.ed25519.sig", dst_dir / f"{name}.ed25519.sig")
    entry = dict(src_entry, id=dst[0], version=dst[1])
    (dst_dir / "entry.json").write_text(json.dumps(entry, indent=2, sort_keys=True), encoding="utf-8")
    return dst_dir


# --- F26 / F41: ref-bound, domain-separated publisher signatures --------------


def test_artifact_signature_cannot_be_republished_under_another_version(make_hub):
    hub = make_hub()
    _copy_version(hub, (ART, "1.0.0"), (ART, "9.0.0"))

    report = lint_hub_tree(hub, require_signed_index=False)

    assert report.checked == [f"{REF}@1.0.0"]
    assert any("@9.0.0" in p and "bound to" in p for p in report.problems), report.problems


def test_artifact_signature_cannot_be_republished_under_another_id(make_hub):
    hub = make_hub()
    _copy_version(hub, (ART, "1.0.0"), ("no_undue_influence", "1.0.0"))

    report = lint_hub_tree(hub, require_signed_index=False)

    assert any("no_undue_influence@1.0.0" in p and "bound to" in p for p in report.problems), report.problems


def test_a_signature_bound_to_one_ref_fails_even_if_the_sidecar_ref_is_rewritten(make_hub):
    """The sidecar's ``ref`` field is unsigned metadata; the SIGNATURE covers the ref,
    so editing the field to match the new location still fails verification."""
    hub = make_hub()
    dst = _copy_version(hub, (ART, "1.0.0"), (ART, "9.0.0"))
    sig_path = dst / f"{ART}.md.ed25519.sig"
    sig = json.loads(sig_path.read_text(encoding="utf-8"))
    sig["ref"] = f"{REF}@9.0.0"
    sig_path.write_text(json.dumps(sig), encoding="utf-8")

    report = lint_hub_tree(hub, require_signed_index=False)

    assert any("@9.0.0" in p and "verification FAILED" in p for p in report.problems), report.problems


def test_legacy_v1_signature_verifies_only_for_its_pinned_ref(tmp_path, monkeypatch, test_private_key, pinned_test_key):
    """A shipped content-only (v1) sidecar keeps verifying at its own ref, and the
    same bytes+sidecar copied to another ref are refused (the exact F26 exploit)."""
    hub = tmp_path / "hub"
    content = artifact_text(ART).encode("utf-8")
    legacy_sig = make_sidecar(content, test_private_key)  # v1: raw content, no ref
    monkeypatch.setattr(
        verify_mod,
        "LEGACY_UNBOUND_ARTIFACT_PINS",
        {f"{REF}@1.0.0": hashlib.sha256(content).hexdigest()},
    )
    write_version_dir(hub, ART, "1.0.0", content, legacy_sig, build_entry_dict(ART, "1.0.0", content))
    _copy_version(hub, (ART, "1.0.0"), (ART, "9.0.0"))

    report = lint_hub_tree(hub, require_signed_index=False)

    assert report.checked == [f"{REF}@1.0.0"]
    assert any("@9.0.0" in p and "legacy content-only" in p for p in report.problems), report.problems


def test_legacy_v1_signature_for_unpinned_content_is_refused(pinned_test_key, test_private_key):
    content = b"new content, never shipped"
    with pytest.raises(VerificationError, match="legacy content-only"):
        verify_artifact_bytes(content, make_sidecar(content, test_private_key), ref=f"{REF}@2.0.0")


def test_a_root_signed_index_cannot_pose_as_a_founder_artifact(make_hub):
    """F41 variant: artifact bytes = INDEX_CONTEXT + index.json, sidecar copied from
    index.json.ed25519.sig with content_hash recomputed. The root really signed
    exactly those bytes, but in the index domain, not the artifact domain."""
    hub = make_hub()
    index_bytes = (hub / "index.json").read_bytes()
    forged = INDEX_CONTEXT + index_bytes
    sig = json.loads((hub / "index.json.ed25519.sig").read_text(encoding="utf-8"))
    sig["content_hash"] = hashlib.sha256(forged).hexdigest()
    entry = build_entry_dict("uef", "9.9.9", forged)
    write_version_dir(hub, "uef", "9.9.9", forged, json.dumps(sig).encode("utf-8"), entry)

    report = lint_hub_tree(hub, require_signed_index=False)

    assert any("uef@9.9.9" in p for p in report.problems), report.problems
    assert f"{NS}/uef@9.9.9" not in report.checked


def test_artifact_and_countersign_contexts_are_distinct():
    ref = f"{REF}@1.0.0"
    assert artifact_message_context(ref) != verify_mod.countersign_message_context(ref)
    for other in (verify_mod.INDEX_CONTEXT, verify_mod.NS_REGISTRY_CONTEXT, verify_mod.COUNTERSIGN_CONTEXT):
        assert not artifact_message_context(ref).startswith(other)


@pytest.mark.parametrize(
    "bad_ref",
    [
        "creed-space/x",
        "creed-space/x@1.0.0\x00evil",
        "../x@1.0.0",
        "",
        "creed-space/x@1.0.0\n",
        "creed-space/x@1.0.0\r\n",
    ],
)
def test_malformed_refs_never_enter_a_signed_message(bad_ref):
    with pytest.raises(VerificationError, match="invalid artifact ref"):
        artifact_message_context(bad_ref)


@pytest.mark.parametrize("bad_ref", ["creed-space/x@1.0.0\n", "creed-space/x\n@1.0.0", "creed-space\n/x@1.0.0"])
def test_validate_ref_refuses_a_trailing_newline_in_any_component(bad_ref):
    """``$`` matches before a final newline; every ref component must anchor with \\Z."""
    with pytest.raises(HubError, match="invalid"):
        validate_ref(bad_ref)


def test_publish_requires_a_signature_bound_to_the_published_ref(tmp_path, test_private_key, pinned_test_key):
    source = tmp_path / "src"
    source.mkdir()
    md = source / f"{ART}.md"
    content = artifact_text(ART, "2.0.0").encode("utf-8")
    md.write_bytes(content)
    # Signed for 1.0.0, but the frontmatter says 2.0.0.
    md.with_suffix(".md.ed25519.sig").write_bytes(make_sidecar(content, test_private_key, ref=f"{REF}@1.0.0"))

    with pytest.raises(VerificationError, match="bound to"):
        publish(md, tmp_path / "hub")


def test_publish_accepts_a_separately_stored_ref_bound_sidecar(tmp_path, test_private_key, pinned_test_key):
    source = tmp_path / "src"
    source.mkdir()
    md = source / f"{ART}.md"
    content = artifact_text(ART).encode("utf-8")
    md.write_bytes(content)
    elsewhere = tmp_path / "hub-signature.json"
    elsewhere.write_bytes(make_sidecar(content, test_private_key, ref=f"{REF}@1.0.0"))
    hub = tmp_path / "hub"

    assert publish(md, hub, signature_path=elsewhere) == f"{REF}@1.0.0"
    assert (_version_dir(hub, ART, "1.0.0") / f"{ART}.md.ed25519.sig").read_bytes() == elsewhere.read_bytes()


# --- F37 (client side): no repointing a published version ----------------------


def test_publish_refuses_to_repoint_an_existing_version_at_a_new_file(tmp_path, test_private_key, pinned_test_key):
    hub = tmp_path / "hub"
    source = tmp_path / "src"
    source.mkdir()
    first = source / f"{ART}.md"
    first.write_bytes(artifact_text(ART).encode("utf-8"))
    first.with_suffix(".md.ed25519.sig").write_bytes(
        make_sidecar(first.read_bytes(), test_private_key, ref=f"{REF}@1.0.0")
    )
    publish(first, hub)

    other = source / "replacement.md"
    other.write_bytes(artifact_text(ART).encode("utf-8") + b"\nweaker rules\n")
    other.with_suffix(".md.ed25519.sig").write_bytes(
        make_sidecar(other.read_bytes(), test_private_key, ref=f"{REF}@1.0.0")
    )

    with pytest.raises(VerificationError, match="immutable"):
        publish(other, hub)
    entry = json.loads((_version_dir(hub, ART, "1.0.0") / "entry.json").read_text(encoding="utf-8"))
    assert entry["distribution"]["artifact"] == f"{ART}.md"


def test_install_refuses_a_version_whose_bytes_changed_since_the_lock_pinned_it(make_hub, tmp_path, test_private_key):
    hub = make_hub()
    target = tmp_path / "artifacts"
    install(REF, target, RegistryClient(str(hub)))
    pinned = json.loads((target / "vcp.lock").read_text(encoding="utf-8"))["artifacts"][REF]["content_sha256"]

    # The hub repoints 1.0.0 at different (validly signed) bytes and re-releases.
    vdir = _version_dir(hub, ART, "1.0.0")
    new = artifact_text(ART).encode("utf-8") + b"\nrepointed\n"
    (vdir / f"{ART}.md").write_bytes(new)
    (vdir / f"{ART}.md.ed25519.sig").write_bytes(make_sidecar(new, test_private_key, ref=f"{REF}@1.0.0"))
    entry = json.loads((vdir / "entry.json").read_text(encoding="utf-8"))
    entry["content_sha256"] = hashlib.sha256(new).hexdigest()
    (vdir / "entry.json").write_text(json.dumps(entry), encoding="utf-8")
    assert write_index(hub).ok
    sign_index(hub, test_private_key)

    with pytest.raises(VerificationError, match="immutable"):
        install(f"{REF}@1.0.0", target, RegistryClient(str(hub)))
    lock = json.loads((target / "vcp.lock").read_text(encoding="utf-8"))
    assert lock["artifacts"][REF]["content_sha256"] == pinned
    assert (target / NS / ART / "1.0.0" / f"{ART}.md").read_bytes() != new


# --- F45: verify --registry enforces the anti-rollback high-water mark ---------


def _rewrite_index(hub: Path, key, **changes) -> None:
    index_path = hub / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index.update(changes)
    index_path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if "issued_at" in changes:
        sign_index(hub, key, issued_at=None)  # sign the caller's stamp as written
    else:
        sign_index(hub, key)


def test_verify_against_a_registry_refuses_a_replayed_stale_index(make_hub, tmp_path, test_private_key):
    hub = make_hub()
    target = tmp_path / "artifacts"

    # The client installs from release 2, so the lock's high-water mark is 2.
    _rewrite_index(hub, test_private_key, sequence=2)
    install(REF, target, RegistryClient(str(hub)))
    install_index = (hub / "index.json").read_bytes()  # sequence 2, still vouches for the artifact
    install_sig = (hub / "index.json.ed25519.sig").read_bytes()

    # Release 3 revokes it; verify sees the revocation (and must remember seq 3).
    _rewrite_index(hub, test_private_key, sequence=3, artifacts={})
    with pytest.raises(VerificationError, match="revoked or removed"):
        verify_tree(target, registry=RegistryClient(str(hub)))
    assert json.loads((target / "vcp.lock").read_text())["registries"][str(hub)]["index_sequence"] == 3

    # An attacker replays the INSTALL-TIME index: at the install high-water mark,
    # validly signed, still fresh. Only the mark verify recorded refuses it.
    (hub / "index.json").write_bytes(install_index)
    (hub / "index.json.ed25519.sig").write_bytes(install_sig)

    with pytest.raises(VerificationError, match="index sequence went BACKWARDS"):
        verify_tree(target, registry=RegistryClient(str(hub)))


def test_replaying_the_install_time_index_after_it_goes_stale_cannot_hide_a_revocation(
    make_hub, tmp_path, test_private_key, monkeypatch
):
    """The reviewer's F45 residual: the client never saw the revoking release, so
    no high-water mark can help; the signed issued_at bounds how long the replay works."""
    hub = make_hub()
    target = tmp_path / "artifacts"
    _rewrite_index(hub, test_private_key, sequence=2)
    install(REF, target, RegistryClient(str(hub)))
    install_index = (hub / "index.json").read_bytes()
    install_sig = (hub / "index.json.ed25519.sig").read_bytes()
    _rewrite_index(hub, test_private_key, sequence=3, artifacts={})  # revocation
    (hub / "index.json").write_bytes(install_index)
    (hub / "index.json.ed25519.sig").write_bytes(install_sig)

    later = datetime.now(UTC) + DEFAULT_MAX_INDEX_AGE + timedelta(days=1)
    monkeypatch.setattr(registry_mod, "_utcnow", lambda: later)

    with pytest.raises(VerificationError, match="STALE"):
        verify_tree(target, registry=RegistryClient(str(hub)))


def _days_ago(days: float) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).isoformat()


def test_an_index_older_than_the_max_age_is_refused(make_hub, tmp_path, test_private_key):
    hub = make_hub()
    sign_index(hub, test_private_key, issued_at=_days_ago(DEFAULT_MAX_INDEX_AGE.days + 1))

    with pytest.raises(VerificationError, match="STALE"):
        install(REF, tmp_path / "artifacts", RegistryClient(str(hub)))


def test_the_max_index_age_is_configurable(make_hub, test_private_key):
    hub = make_hub()
    sign_index(hub, test_private_key, issued_at=_days_ago(10))

    assert RegistryClient(str(hub)).index()["sequence"] == 1
    with pytest.raises(VerificationError, match="STALE"):
        RegistryClient(str(hub), max_index_age=timedelta(days=7)).index()
    with pytest.raises(HubError, match="positive"):
        RegistryClient(str(hub), max_index_age=timedelta(0))


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"issued_at": "2999-01-01T00:00:00+00:00"}, "in the future"),
        ({"issued_at": "not a time"}, "not an ISO-8601"),
        ({"issued_at": "2026-11-01T00:00:00"}, "no timezone"),
        ({"issued_at": 1700000000}, "must be an ISO-8601"),
        ({"expires_at": "2000-01-01T00:00:00+00:00"}, "not after issued_at"),
        ({"issued_at": _days_ago(2), "expires_at": _days_ago(1)}, "EXPIRED"),
    ],
)
def test_a_malformed_or_expired_freshness_stamp_is_refused(make_hub, test_private_key, changes, match):
    hub = make_hub()
    _rewrite_index(hub, test_private_key, **changes)

    with pytest.raises(VerificationError, match=match):
        RegistryClient(str(hub)).index()


def test_a_future_expires_at_within_the_max_age_is_accepted(make_hub, test_private_key):
    hub = make_hub()
    expires = (datetime.now(UTC) + timedelta(days=7)).isoformat()
    _rewrite_index(hub, test_private_key, issued_at=_days_ago(1), expires_at=expires)

    assert RegistryClient(str(hub)).index()["expires_at"] == expires


def test_an_undated_index_is_refused_unless_it_is_the_pinned_shipped_one(make_hub, test_private_key, monkeypatch):
    hub = make_hub()
    index = json.loads((hub / "index.json").read_text(encoding="utf-8"))
    del index["issued_at"]
    (hub / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sign_index(hub, test_private_key, issued_at=None)

    with pytest.raises(VerificationError, match="no signed issued_at"):
        RegistryClient(str(hub)).index()

    pinned = hashlib.sha256((hub / "index.json").read_bytes()).hexdigest()
    monkeypatch.setattr(registry_mod, "LEGACY_UNDATED_INDEX_PINS", frozenset({pinned}))
    assert RegistryClient(str(hub)).index()["sequence"] == 1


@pytest.mark.skipif(not (SHIPPED_HUB / "index.json").is_file(), reason="no vcp-hub checkout (set VCP_HUB_DIR)")
def test_the_shipped_hub_index_is_accepted_through_the_grace_pin():
    """The transition path: today's vcp-hub/index.json (undated, sequence 2) still loads."""
    index = RegistryClient(str(SHIPPED_HUB)).index()
    assert "issued_at" not in index and index["sequence"] >= 2


def test_build_index_carries_the_signed_freshness_stamps_over(make_hub):
    hub = make_hub()
    index = json.loads((hub / "index.json").read_text(encoding="utf-8"))
    index["expires_at"] = "2030-01-01T00:00:00+00:00"
    (hub / "index.json").write_text(json.dumps(index), encoding="utf-8")

    rebuilt, report = build_index(hub)

    assert report.ok
    assert rebuilt["issued_at"] == index["issued_at"]
    assert rebuilt["expires_at"] == "2030-01-01T00:00:00+00:00"


def test_verify_against_a_registry_still_passes_at_or_above_the_high_water_mark(make_hub, tmp_path, test_private_key):
    hub = make_hub()
    target = tmp_path / "artifacts"
    install(REF, target, RegistryClient(str(hub)))
    _rewrite_index(hub, test_private_key, sequence=5)

    assert verify_tree(target, registry=RegistryClient(str(hub))) == [f"{REF}@1.0.0"]


# --- F56: terminal control characters in publisher display text ---------------


@pytest.mark.parametrize("field", ["name", "description"])
@pytest.mark.parametrize("payload", ["\rcommunity/foo@1.0.0  [verified]", "\x1b[2Kfake", "a\u202eb", "x\u2028y"])
def test_lint_refuses_control_characters_in_display_text(make_hub, field, payload):
    hub = make_hub()
    path = _version_dir(hub, ART, "1.0.0") / "entry.json"
    entry = json.loads(path.read_text(encoding="utf-8"))
    entry[field] = payload
    path.write_text(json.dumps(entry), encoding="utf-8")

    report = lint_hub_tree(hub, require_signed_index=False)

    assert any(f"'{field}' contains control/format character" in p for p in report.problems), report.problems


def test_display_text_refuses_controls_but_keeps_ordinary_unicode():
    content = b"x"
    entry = build_entry_dict(ART, "1.0.0", content)
    entry["name"] = "Ética — Grundsätze 原則"
    entry["description"] = "Tabs\tare not allowed but accents and dashes are fine"
    with pytest.raises(VerificationError, match="'description' contains"):
        validate_entry(entry)
    entry["description"] = "Accents, dashes — and CJK 原則 are fine"
    validate_entry(entry)


def test_search_escapes_control_characters_from_a_signed_index(make_hub, test_private_key, capsys):
    """Even if a signed index carries a hostile name (signed before lint refused
    it), ``vcp search`` must not let it rewrite the terminal."""
    hub = make_hub()
    index = json.loads((hub / "index.json").read_text(encoding="utf-8"))
    rec = index["artifacts"][REF]["versions"]["1.0.0"]
    rec["name"] = "\rcreed-space/evil@1.0.0  [verified]  Official"
    rec["description"] = "\x1b[1A\x1b[2Kfake line"
    (hub / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sign_index(hub, test_private_key)

    assert cli.main(["search", "gaslighting", "--registry", str(hub)]) == 0
    out = capsys.readouterr().out

    assert "\r" not in out and "\x1b" not in out
    assert f"{REF}@1.0.0  [signed]  \\x0dcreed-space/evil@1.0.0  [verified]  Official" in out
    assert "\\x1b[1A\\x1b[2Kfake line" in out


def test_cli_lint_output_escapes_control_characters(make_hub, capsys, test_private_key):
    hub = make_hub()
    bogus = hub / "namespaces" / NS / ART / "1.0.0" / "entry.json"
    entry = json.loads(bogus.read_text(encoding="utf-8"))
    entry["id"] = "x\x1b[31m"
    bogus.write_text(json.dumps(entry), encoding="utf-8")

    assert cli.main(["lint", "--pr", str(hub)]) == 1
    assert "\x1b" not in capsys.readouterr().err


def test_detached_sidecar_helper_still_produces_v1_trust_documents(test_private_key):
    """Trust documents (index/registry) keep sidecar v1; only artifacts moved to v2."""
    sig = json.loads(make_detached_sidecar(b"doc", test_private_key, INDEX_CONTEXT, key_id=TEST_KEY_ID))
    assert sig["version"] == 1 and "ref" not in sig
