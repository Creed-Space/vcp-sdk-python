"""Install and verify Creed Commons artifacts with a signed lockfile.

``install`` fetches an artifact version from a registry, verifies it fully
(Ed25519 signature against the pinned key allowlist, content sha256 cross-checked
between sidecar and registry entry, entry schema), and only then writes it to the
target directory and pins it in ``vcp.lock``. Verification happens in memory
BEFORE anything touches disk.

``verify_tree`` re-checks every locked artifact on disk against the lockfile:
recomputes hashes, re-verifies signatures, and fails on any drift.

Nothing in this module imports, evals, or executes artifact content.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .entry_schema import validate_entry
from .errors import HubError, VerificationError
from .registry import RegistryClient, validate_ref
from .verify import verify_artifact_bytes

LOCKFILE_NAME = "vcp.lock"
LOCKFILE_VERSION = 1


@dataclass(frozen=True)
class InstallResult:
    ref: str
    version: str
    content_sha256: str
    key_id: str
    files: tuple[str, ...]


def _load_lock(lock_path: Path) -> dict[str, Any]:
    if not lock_path.exists():
        return {"lockfile_version": LOCKFILE_VERSION, "artifacts": {}}
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HubError(f"cannot read lockfile {lock_path}: {exc}") from exc
    if not isinstance(lock, dict) or lock.get("lockfile_version") != LOCKFILE_VERSION:
        raise HubError(f"lockfile {lock_path} has an unsupported format")
    if not isinstance(lock.get("artifacts"), dict):
        raise HubError(f"lockfile {lock_path} has no artifacts map")
    return lock


def _safe_target(root: Path, *parts: str) -> Path:
    """Join parts under root, refusing any escape (Threat T7)."""
    candidate = root.joinpath(*parts).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise HubError(f"install path {'/'.join(parts)!r} escapes the target directory")
    return candidate


def install(
    ref: str,
    target_dir: str | Path,
    registry: RegistryClient,
    lock_path: str | Path | None = None,
) -> InstallResult:
    """Install ``namespace/id[@version]`` into ``target_dir`` after full verification."""
    namespace, artifact_id, requested = validate_ref(ref)
    version = registry.resolve_version(namespace, artifact_id, requested)

    entry = registry.entry(namespace, artifact_id, version)
    validate_entry(entry, require_distribution=True)
    if entry.get("id") != artifact_id or entry.get("version") != version or entry.get("namespace") != namespace:
        raise VerificationError(
            f"registry entry does not describe {namespace}/{artifact_id}@{version} "
            f"(entry says {entry.get('namespace')}/{entry.get('id')}@{entry.get('version')})"
        )

    artifact_name = entry["distribution"].get("artifact")
    if not isinstance(artifact_name, str) or not artifact_name:
        raise VerificationError("registry entry names no artifact file")

    content = registry.artifact(namespace, artifact_id, version, artifact_name)
    sig_bytes = registry.artifact(namespace, artifact_id, version, artifact_name + ".ed25519.sig")

    # Signature + sidecar hash + entry hash must all agree (T2, T3).
    verified = verify_artifact_bytes(content, sig_bytes, expected_sha256=entry["content_sha256"])

    target = Path(target_dir).resolve()
    dest_dir = _safe_target(target, namespace, artifact_id, version)
    dest_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for filename, data in (
        (artifact_name, content),
        (artifact_name + ".ed25519.sig", sig_bytes),
        ("entry.json", json.dumps(entry, indent=2, sort_keys=True).encode("utf-8")),
    ):
        dest = _safe_target(dest_dir, filename)
        dest.write_bytes(data)
        written.append(str(dest.relative_to(target)))

    lock_file = Path(lock_path) if lock_path else target / LOCKFILE_NAME
    lock = _load_lock(lock_file)
    lock["artifacts"][f"{namespace}/{artifact_id}"] = {
        "version": version,
        "content_sha256": verified.content_sha256,
        "key_id": verified.key_id,
        "artifact": artifact_name,
        "trust_tier": entry["trust_tier"],
    }
    lock_file.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return InstallResult(
        ref=f"{namespace}/{artifact_id}",
        version=version,
        content_sha256=verified.content_sha256,
        key_id=verified.key_id,
        files=tuple(written),
    )


def verify_tree(target_dir: str | Path, lock_path: str | Path | None = None) -> list[str]:
    """Re-verify every locked artifact on disk. Returns verified refs; raises on drift."""
    target = Path(target_dir).resolve()
    lock_file = Path(lock_path) if lock_path else target / LOCKFILE_NAME
    if not lock_file.exists():
        raise HubError(f"no lockfile at {lock_file}; nothing to verify")
    lock = _load_lock(lock_file)

    verified_refs: list[str] = []
    problems: list[str] = []
    for ref, pin in sorted(lock["artifacts"].items()):
        try:
            namespace, artifact_id, _ = validate_ref(f"{ref}@{pin['version']}")
            artifact_name = pin["artifact"]
            if "/" in artifact_name or "\\" in artifact_name or artifact_name.startswith("."):
                raise HubError(f"lockfile names an illegal artifact file {artifact_name!r}")
            base = _safe_target(target, namespace, artifact_id, pin["version"])
            content_path = _safe_target(base, artifact_name)
            sig_path = _safe_target(base, artifact_name + ".ed25519.sig")
            if not content_path.is_file():
                raise VerificationError(f"installed artifact missing: {content_path}")
            if not sig_path.is_file():
                raise VerificationError(f"installed signature missing: {sig_path}")
            verified = verify_artifact_bytes(
                content_path.read_bytes(),
                sig_path.read_bytes(),
                expected_sha256=pin["content_sha256"],
            )
            if verified.key_id != pin["key_id"]:
                raise VerificationError(
                    f"{ref}: signer changed since install ({pin['key_id']!r} -> {verified.key_id!r})"
                )
            verified_refs.append(f"{ref}@{pin['version']}")
        except (HubError, KeyError, TypeError) as exc:
            problems.append(f"{ref}: {exc}")
    if problems:
        raise VerificationError("installed tree has drifted from vcp.lock:\n  " + "\n  ".join(problems))
    return verified_refs
