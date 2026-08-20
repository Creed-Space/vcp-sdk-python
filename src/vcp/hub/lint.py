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
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .._json import loads_strict
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
    MAX_FETCH_BYTES,
    NAMESPACE_RE,
    VERSION_RE,
    validate_artifact_filename,
)
from .verify import (
    INDEX_CONTEXT,
    MAX_SIGNATURE_SIDECAR_BYTES,
    verify_artifact_bytes,
    verify_countersignature,
    verify_detached,
)

MAX_HUB_VERSIONS = 10_000
MAX_CHILD_DIRECTORIES = 10_000


def _read_bounded(path: Path, cap: int, description: str) -> bytes:
    try:
        if path.is_symlink():
            raise VerificationError(f"{description} must not be a symbolic link")
        if path.stat().st_size > cap:
            raise VerificationError(f"{description} exceeds size cap")
        with path.open("rb") as handle:
            data = handle.read(cap + 1)
    except VerificationError:
        raise
    except OSError as exc:
        raise VerificationError(f"cannot read {description}: {exc}") from exc
    if len(data) > cap:
        raise VerificationError(f"{description} exceeds size cap")
    return data


def _bounded_child_dirs(path: Path, description: str) -> list[Path]:
    """List child directories with a cap and without following symlinks."""
    children: list[Path] = []
    try:
        for child in path.iterdir():
            if child.is_symlink():
                if child.is_dir():
                    raise VerificationError(f"{description} contains symbolic-link directory {child.name!r}")
                continue
            if child.is_dir():
                children.append(child)
                if len(children) > MAX_CHILD_DIRECTORIES:
                    raise VerificationError(f"{description} exceeds child-directory cap of {MAX_CHILD_DIRECTORIES}")
    except VerificationError:
        raise
    except OSError as exc:
        raise VerificationError(f"cannot enumerate {description}: {exc}") from exc
    return sorted(children)


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
        entry = loads_strict(_read_bounded(entry_path, MAX_FETCH_BYTES, "entry.json").decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError, VerificationError) as exc:
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
    try:
        validate_artifact_filename(artifact_name)
    except HubError as exc:
        raise VerificationError(str(exc)) from exc

    artifact_path = version_dir / artifact_name
    sig_path = version_dir / (artifact_name + ".ed25519.sig")
    if not artifact_path.is_file():
        raise VerificationError(f"artifact file {artifact_name} is missing")
    if not sig_path.is_file():
        raise VerificationError(
            f"signature sidecar {artifact_name}.ed25519.sig is missing; unsigned artifacts are refused"
        )

    content = _read_bounded(artifact_path, MAX_FETCH_BYTES, f"artifact file {artifact_name}")
    verify_artifact_bytes(
        content,
        _read_bounded(sig_path, MAX_SIGNATURE_SIDECAR_BYTES, f"signature sidecar {sig_path.name}"),
        expected_sha256=entry["content_sha256"],
        publisher_keys=ns_registry.publisher_keys(namespace),
    )

    # `verified` tier: only a domain-separated, ref-bound ROOT counter-signature
    # grants it.
    countersig_path = version_dir / (artifact_name + ".ed25519.countersig")
    if entry["trust_tier"] == "verified":
        if not countersig_path.is_file():
            raise VerificationError("trust_tier is 'verified' but no .ed25519.countersig sidecar exists")
        verify_countersignature(
            content,
            _read_bounded(
                countersig_path,
                MAX_SIGNATURE_SIDECAR_BYTES,
                f"counter-signature sidecar {countersig_path.name}",
            ),
            ref=f"{namespace}/{artifact_id}@{version}",
        )
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
                    _read_bounded(index_path, MAX_FETCH_BYTES, "index.json"),
                    _read_bounded(sig_path, MAX_SIGNATURE_SIDECAR_BYTES, "index signature")
                    if sig_path.is_file()
                    else None,
                    context=INDEX_CONTEXT,
                    what="registry index",
                )
            except HubError as exc:
                report.problems.append(f"index.json: {exc}")

    if not ns_root.is_dir():
        report.problems.append(f"{root} has no namespaces/ directory")
        return report

    version_count = 0
    try:
        namespace_dirs = _bounded_child_dirs(ns_root, "namespaces directory")
    except VerificationError as exc:
        report.problems.append(str(exc))
        return report
    for ns_dir in namespace_dirs:
        namespace = ns_dir.name
        if NAMESPACE_RE.fullmatch(namespace) is None or not ns_registry.is_registered(namespace):
            report.problems.append(
                f"namespaces/{namespace}: namespace is not registered in "
                f"{REGISTRY_FILENAME} (registered: {sorted(ns_registry.names)})"
            )
            continue
        try:
            id_dirs = _bounded_child_dirs(ns_dir, f"namespaces/{namespace}")
        except VerificationError as exc:
            report.problems.append(str(exc))
            continue
        for id_dir in id_dirs:
            artifact_id = id_dir.name
            if ARTIFACT_ID_RE.fullmatch(artifact_id) is None:
                report.problems.append(f"namespaces/{namespace}/{artifact_id}: invalid artifact id")
                continue
            try:
                version_dirs = _bounded_child_dirs(id_dir, f"namespaces/{namespace}/{artifact_id}")
            except VerificationError as exc:
                report.problems.append(str(exc))
                continue
            if not version_dirs:
                report.problems.append(f"namespaces/{namespace}/{artifact_id}: no version directories")
            for v_dir in version_dirs:
                version_count += 1
                if version_count > MAX_HUB_VERSIONS:
                    report.problems.append(f"hub exceeds version-directory cap of {MAX_HUB_VERSIONS}")
                    return report
                version = v_dir.name
                label = f"{namespace}/{artifact_id}@{version}"
                if VERSION_RE.fullmatch(version) is None:
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
        entry_path = root / "namespaces" / namespace / artifact_id / version / "entry.json"
        entry = loads_strict(_read_bounded(entry_path, MAX_FETCH_BYTES, "entry.json").decode("utf-8"))
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
            existing = loads_strict(_read_bounded(index_path, MAX_FETCH_BYTES, "index.json").decode("utf-8"))
        except (HubError, UnicodeDecodeError, ValueError, RecursionError):
            return 1
        seq = existing.get("sequence")
        if type(seq) is int and seq >= 1:
            return seq
    return 1


def write_index(hub_root: str | Path) -> LintReport:
    """Regenerate ``<hub_root>/index.json`` from lint-passing entries."""
    root = Path(hub_root).resolve()
    index, report = build_index(root)
    root.mkdir(parents=True, exist_ok=True)
    index_path = root / "index.json"
    fd, raw_temp = tempfile.mkstemp(prefix=".index.json.", suffix=".tmp", dir=root)
    temp_path = Path(raw_temp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(index, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, index_path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise
    return report
