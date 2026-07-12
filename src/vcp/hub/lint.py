"""Publish lint + index builder for a Creed Commons registry tree.

``lint_hub_tree`` is the check the vcp-hub CI runs on every PR: every artifact
version in the tree must be signed by a pinned publisher key, schema-valid,
hash-consistent, and inside an allowed namespace. Any violation fails the lint —
there is no way to publish an unsigned or tampered artifact past it.

``build_index`` regenerates ``index.json`` from entries that pass the lint, and
reports anything it skipped — nothing is ever silently dropped.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .entry_schema import validate_entry
from .errors import HubError, VerificationError
from .namespace_registry import (
    REGISTRY_FILENAME,
    NamespaceRegistry,
    load_hub_namespace_registry,
)
from .registry import (
    ARTIFACT_ID_RE,
    INDEX_VERSION,
    NAMESPACE_RE,
    VERSION_RE,
)
from .verify import (
    INDEX_CONTEXT,
    verify_artifact_bytes,
    verify_countersignature,
    verify_detached,
)


@dataclass
class LintReport:
    """Outcome of linting a hub tree."""

    checked: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def _lint_version_dir(
    version_dir: Path,
    namespace: str,
    artifact_id: str,
    version: str,
    ns_registry: NamespaceRegistry,
) -> dict[str, Any]:
    """Fully verify one artifact version directory; returns the entry. Raises on failure."""
    entry_path = version_dir / "entry.json"
    if not entry_path.is_file():
        raise VerificationError("entry.json is missing")
    try:
        entry = json.loads(entry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"entry.json is not valid JSON: {exc}") from exc
    if not isinstance(entry, dict):
        raise VerificationError("entry.json must be a JSON object")

    validate_entry(entry, require_distribution=True, known_namespaces=ns_registry.names)

    if entry.get("namespace") != namespace or entry.get("id") != artifact_id or entry.get("version") != version:
        raise VerificationError(
            f"entry describes {entry.get('namespace')}/{entry.get('id')}@{entry.get('version')} "
            f"but lives in namespaces/{namespace}/{artifact_id}/{version}"
        )

    artifact_name = entry["distribution"].get("artifact")
    if not isinstance(artifact_name, str) or not artifact_name:
        raise VerificationError("entry names no artifact file")
    if "/" in artifact_name or "\\" in artifact_name or artifact_name.startswith("."):
        raise VerificationError(f"illegal artifact filename {artifact_name!r}")

    artifact_path = version_dir / artifact_name
    sig_path = version_dir / (artifact_name + ".ed25519.sig")
    if not artifact_path.is_file():
        raise VerificationError(f"artifact file {artifact_name} is missing")
    if not sig_path.is_file():
        raise VerificationError(
            f"signature sidecar {artifact_name}.ed25519.sig is missing; unsigned artifacts are refused"
        )

    content = artifact_path.read_bytes()
    verify_artifact_bytes(
        content,
        sig_path.read_bytes(),
        expected_sha256=entry["content_sha256"],
        publisher_keys=ns_registry.publisher_keys(namespace),
    )

    # `verified` tier: only a domain-separated, ref-bound ROOT counter-signature
    # grants it.
    countersig_path = version_dir / (artifact_name + ".ed25519.countersig")
    if entry["trust_tier"] == "verified":
        if not countersig_path.is_file():
            raise VerificationError("trust_tier is 'verified' but no .ed25519.countersig sidecar exists")
        verify_countersignature(content, countersig_path.read_bytes(), ref=f"{namespace}/{artifact_id}@{version}")
    elif countersig_path.is_file():
        raise VerificationError(
            "a counter-signature sidecar exists but trust_tier is not 'verified'; entry and sidecars must agree"
        )
    return entry


def lint_hub_tree(hub_root: str | Path, require_signed_index: bool = True) -> LintReport:
    """Lint every artifact version under ``<hub_root>/namespaces/``.

    Namespace admission comes from the hub's own ``namespace_registry.json``,
    which must verify against the pinned ROOT keys. A present-but-invalid
    registry fails the whole lint (a tampered trust document is an attack);
    an absent one means founder-only.

    ``require_signed_index=True`` (release/CI-on-main posture) additionally
    requires ``index.json`` to carry a valid root signature and sequence.
    Publishers preparing a PR run with ``False`` (``vcp lint --pr``) since only
    the maintainer ceremony can sign; the index CONTENT is still checked by
    CI's regenerate-and-diff step either way.
    """
    root = Path(hub_root).resolve()
    ns_root = root / "namespaces"
    report = LintReport()

    try:
        ns_registry = load_hub_namespace_registry(root)
    except HubError as exc:
        report.problems.append(f"{REGISTRY_FILENAME}: {exc}")
        return report

    if require_signed_index:
        index_path = root / "index.json"
        sig_path = root / "index.json.ed25519.sig"
        if not index_path.is_file():
            report.problems.append("index.json is missing")
        else:
            try:
                verify_detached(
                    index_path.read_bytes(),
                    sig_path.read_bytes() if sig_path.is_file() else None,
                    context=INDEX_CONTEXT,
                    what="registry index",
                )
            except HubError as exc:
                report.problems.append(f"index.json: {exc}")

    if not ns_root.is_dir():
        report.problems.append(f"{root} has no namespaces/ directory")
        return report

    for ns_dir in sorted(p for p in ns_root.iterdir() if p.is_dir()):
        namespace = ns_dir.name
        if not NAMESPACE_RE.match(namespace) or not ns_registry.is_registered(namespace):
            report.problems.append(
                f"namespaces/{namespace}: namespace is not registered in "
                f"{REGISTRY_FILENAME} (registered: {sorted(ns_registry.names)})"
            )
            continue
        for id_dir in sorted(p for p in ns_dir.iterdir() if p.is_dir()):
            artifact_id = id_dir.name
            if not ARTIFACT_ID_RE.match(artifact_id):
                report.problems.append(f"namespaces/{namespace}/{artifact_id}: invalid artifact id")
                continue
            version_dirs = sorted(p for p in id_dir.iterdir() if p.is_dir())
            if not version_dirs:
                report.problems.append(f"namespaces/{namespace}/{artifact_id}: no version directories")
            for v_dir in version_dirs:
                version = v_dir.name
                label = f"{namespace}/{artifact_id}@{version}"
                if not VERSION_RE.match(version):
                    report.problems.append(f"{label}: invalid version directory name")
                    continue
                try:
                    _lint_version_dir(v_dir, namespace, artifact_id, version, ns_registry)
                    report.checked.append(label)
                except HubError as exc:
                    report.problems.append(f"{label}: {exc}")
    return report


def build_index(hub_root: str | Path) -> tuple[dict[str, Any], LintReport]:
    """Build index.json from all lint-passing entries under ``hub_root``.

    Returns (index_dict, lint_report). Callers MUST fail (or at minimum surface
    report.problems) when the report is not ok — skipped entries are reported,
    never silently dropped.
    """
    root = Path(hub_root).resolve()
    # The index is what we are BUILDING; only the tree is linted here. The
    # signature requirement applies to consuming/releasing, not generating.
    report = lint_hub_tree(root, require_signed_index=False)

    artifacts: dict[str, Any] = {}
    for label in report.checked:
        ref, _, version = label.partition("@")
        namespace, _, artifact_id = ref.partition("/")
        entry = json.loads(
            (root / "namespaces" / namespace / artifact_id / version / "entry.json").read_text(encoding="utf-8")
        )
        record = artifacts.setdefault(ref, {"latest": version, "versions": {}})
        record["versions"][version] = {
            "content_sha256": entry["content_sha256"],
            "trust_tier": entry["trust_tier"],
            "artifact": entry["distribution"]["artifact"],
            "tier": entry.get("tier"),
            "name": entry.get("name"),
            "description": entry.get("description"),
            "signatures": sorted(entry["distribution"]["signatures"].keys()),
        }
        record["latest"] = max(record["versions"], key=lambda v: tuple(int(x) for x in v.split(".")))

    index = {
        "index_version": INDEX_VERSION,
        # Preserved across rebuilds; BUMPED (and re-signed) only by the release
        # ceremony. Clients keep a high-water mark and refuse lower sequences.
        "sequence": _existing_sequence(root),
        "artifacts": artifacts,
    }
    return index, report


def _existing_sequence(root: Path) -> int:
    index_path = root / "index.json"
    if index_path.is_file():
        try:
            existing = json.loads(index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return 1
        seq = existing.get("sequence")
        if isinstance(seq, int) and seq >= 1:
            return seq
    return 1


def write_index(hub_root: str | Path) -> LintReport:
    """Regenerate ``<hub_root>/index.json`` from lint-passing entries."""
    root = Path(hub_root).resolve()
    index, report = build_index(root)
    (root / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report
