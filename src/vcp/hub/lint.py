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
from .registry import (
    ALLOWED_NAMESPACES,
    ARTIFACT_ID_RE,
    INDEX_VERSION,
    NAMESPACE_RE,
    VERSION_RE,
)
from .verify import verify_artifact_bytes


@dataclass
class LintReport:
    """Outcome of linting a hub tree."""

    checked: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def _lint_version_dir(version_dir: Path, namespace: str, artifact_id: str, version: str) -> dict[str, Any]:
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

    validate_entry(entry, require_distribution=True)

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

    verify_artifact_bytes(
        artifact_path.read_bytes(),
        sig_path.read_bytes(),
        expected_sha256=entry["content_sha256"],
    )
    return entry


def lint_hub_tree(hub_root: str | Path) -> LintReport:
    """Lint every artifact version under ``<hub_root>/namespaces/``."""
    root = Path(hub_root).resolve()
    ns_root = root / "namespaces"
    report = LintReport()
    if not ns_root.is_dir():
        report.problems.append(f"{root} has no namespaces/ directory")
        return report

    for ns_dir in sorted(p for p in ns_root.iterdir() if p.is_dir()):
        namespace = ns_dir.name
        if not NAMESPACE_RE.match(namespace) or namespace not in ALLOWED_NAMESPACES:
            report.problems.append(
                f"namespaces/{namespace}: namespace not permitted (launch allowlist: {sorted(ALLOWED_NAMESPACES)})"
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
                    _lint_version_dir(v_dir, namespace, artifact_id, version)
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
    report = lint_hub_tree(root)

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
            "tier": entry.get("tier"),
            "name": entry.get("name"),
            "description": entry.get("description"),
            "signatures": sorted(entry["distribution"]["signatures"].keys()),
        }
        record["latest"] = max(record["versions"], key=lambda v: tuple(int(x) for x in v.split(".")))

    index = {
        "index_version": INDEX_VERSION,
        "artifacts": artifacts,
    }
    return index, report


def write_index(hub_root: str | Path) -> LintReport:
    """Regenerate ``<hub_root>/index.json`` from lint-passing entries."""
    root = Path(hub_root).resolve()
    index, report = build_index(root)
    (root / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report
