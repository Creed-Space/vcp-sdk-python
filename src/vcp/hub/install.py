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

import contextlib
import json
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .._json import loads_strict
from .entry_schema import validate_entry
from .errors import HubError, NotFoundError, VerificationError
from .registry import (
    MAX_FETCH_BYTES,
    RegistryClient,
    validate_artifact_filename,
    validate_ref,
)
from .verify import (
    MAX_SIGNATURE_SIDECAR_BYTES,
    verify_artifact_bytes,
    verify_countersignature,
)

LOCKFILE_NAME = "vcp.lock"
LOCKFILE_VERSION = 1
MAX_LOCK_ARTIFACTS = 10_000


@dataclass(frozen=True)
class InstallResult:
    ref: str
    version: str
    content_sha256: str
    key_id: str
    files: tuple[str, ...]
    trust_tier: str = "signed"


def _load_lock(lock_path: Path) -> dict[str, Any]:
    if not lock_path.exists():
        return {"lockfile_version": LOCKFILE_VERSION, "artifacts": {}}
    try:
        if lock_path.is_symlink():
            raise HubError(f"lockfile {lock_path} must not be a symbolic link")
        if lock_path.stat().st_size > MAX_FETCH_BYTES:
            raise HubError(f"lockfile {lock_path} exceeds size cap")
        lock = loads_strict(lock_path.read_text(encoding="utf-8"))
    except HubError:
        raise
    except (OSError, json.JSONDecodeError, RecursionError) as exc:
        raise HubError(f"cannot read lockfile {lock_path}: {exc}") from exc
    if not isinstance(lock, dict) or lock.get("lockfile_version") != LOCKFILE_VERSION:
        raise HubError(f"lockfile {lock_path} has an unsupported format")
    if not isinstance(lock.get("artifacts"), dict):
        raise HubError(f"lockfile {lock_path} has no artifacts map")
    if len(lock["artifacts"]) > MAX_LOCK_ARTIFACTS:
        raise HubError(f"lockfile {lock_path} exceeds artifact-count cap")
    if not all(isinstance(ref, str) and isinstance(pin, dict) for ref, pin in lock["artifacts"].items()):
        raise HubError(f"lockfile {lock_path} has malformed artifact pins")
    registries = lock.get("registries", {})
    if not isinstance(registries, dict):
        raise HubError(f"lockfile {lock_path} has a malformed registries map")
    for location, record in registries.items():
        if not isinstance(location, str) or not isinstance(record, dict):
            raise HubError(f"lockfile {lock_path} has a malformed registry record")
        for field_name in ("index_sequence", "namespace_sequence"):
            sequence = record.get(field_name, 0)
            if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
                raise HubError(f"lockfile {lock_path} has an invalid {field_name}")
    return lock


def _read_bounded(path: Path, size_cap: int, description: str) -> bytes:
    """Read a regular file without allocating beyond its declared cap."""
    try:
        if path.is_symlink():
            raise VerificationError(f"{description} must not be a symbolic link")
        if path.stat().st_size > size_cap:
            raise VerificationError(f"{description} exceeds size cap")
        with path.open("rb") as handle:
            data = handle.read(size_cap + 1)
    except VerificationError:
        raise
    except OSError as exc:
        raise VerificationError(f"cannot read {description}: {exc}") from exc
    if len(data) > size_cap:
        raise VerificationError(f"{description} exceeds size cap")
    return data


@contextlib.contextmanager
def _lockfile_mutex(lock_path: Path):
    """Serialize lockfile and install-tree commits across threads and processes."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    guard_path = lock_path.with_name(f".{lock_path.name}.mutex")
    if guard_path.is_symlink():
        raise HubError(f"lock mutex {guard_path} must not be a symbolic link")
    with guard_path.open("a+b") as handle:
        if os.name == "nt":  # pragma: no cover - exercised on Windows CI
            import msvcrt

            handle.seek(0)
            if handle.read(1) == b"":
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            locking = getattr(msvcrt, "locking")
            locking(handle.fileno(), getattr(msvcrt, "LK_LOCK"), 1)
            try:
                yield
            finally:
                handle.seek(0)
                locking(handle.fileno(), getattr(msvcrt, "LK_UNLCK"), 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _write_lock_atomically(lock_path: Path, lock: dict[str, Any]) -> None:
    """Replace a complete lockfile in one filesystem operation."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_temp = tempfile.mkstemp(prefix=f".{lock_path.name}.", suffix=".tmp", dir=lock_path.parent)
    temp_path = Path(raw_temp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(lock, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, lock_path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _updated_lock(
    lock: dict[str, Any],
    *,
    namespace: str,
    artifact_id: str,
    version: str,
    artifact_name: str,
    trust_tier: str,
    verified: Any,
    registry: RegistryClient,
    index: dict[str, Any],
    namespace_sequence: int,
) -> dict[str, Any]:
    """Build the next lock state without mutating the parsed input."""
    updated = loads_strict(json.dumps(lock))
    updated["artifacts"][f"{namespace}/{artifact_id}"] = {
        "version": version,
        "content_sha256": verified.content_sha256,
        "key_id": verified.key_id,
        "public_key": verified.public_key_pem,
        "artifact": artifact_name,
        "trust_tier": trust_tier,
    }
    registries = updated.setdefault("registries", {})
    seen = registries.setdefault(registry.location, {})
    seen["index_sequence"] = max(seen.get("index_sequence", 0), index["sequence"])
    seen["namespace_sequence"] = max(seen.get("namespace_sequence", 0), namespace_sequence)
    return updated


def _commit_install(
    *,
    target: Path,
    dest_dir: Path,
    lock_file: Path,
    files: list[tuple[str, bytes]],
    namespace: str,
    artifact_id: str,
    version: str,
    artifact_name: str,
    trust_tier: str,
    verified: Any,
    registry: RegistryClient,
    index: dict[str, Any],
    ns_registry: Any,
) -> list[str]:
    """Atomically commit verified files and their pin, rolling back on failure."""
    parent = dest_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{version}.staging-", dir=parent))
    backup: Path | None = None
    try:
        for filename, data in files:
            validate_artifact_filename(filename)
            (staging / filename).write_bytes(data)

        with _lockfile_mutex(lock_file):
            _check_sequences(registry, index, ns_registry, target, lock_file)
            lock = _load_lock(lock_file)
            updated = _updated_lock(
                lock,
                namespace=namespace,
                artifact_id=artifact_id,
                version=version,
                artifact_name=artifact_name,
                trust_tier=trust_tier,
                verified=verified,
                registry=registry,
                index=index,
                namespace_sequence=ns_registry.sequence,
            )

            if dest_dir.exists():
                if dest_dir.is_symlink() or not dest_dir.is_dir():
                    raise HubError(f"install destination {dest_dir} is not a regular directory")
                backup = parent / f".{version}.backup-{uuid.uuid4().hex}"
            try:
                if backup is not None:
                    os.replace(dest_dir, backup)
                os.replace(staging, dest_dir)
                _write_lock_atomically(lock_file, updated)
            except Exception:
                if dest_dir.exists():
                    shutil.rmtree(dest_dir, ignore_errors=True)
                if backup is not None and backup.exists():
                    os.replace(backup, dest_dir)
                    backup = None
                raise

        if backup is not None:
            shutil.rmtree(backup, ignore_errors=True)
        return [str((dest_dir / filename).relative_to(target)) for filename, _ in files]
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        if backup is not None and backup.exists():
            shutil.rmtree(backup, ignore_errors=True)


def _check_sequences(registry, index, ns_registry, target_dir: Path, lock_path) -> None:
    """Anti-rollback: refuse signed-but-STALE trust documents.

    The lockfile records the highest index/namespace-registry sequence seen per
    registry location; a validly-signed document with a LOWER sequence is a
    replay of retired state (e.g. re-admitting a revoked key) and is refused.
    First contact has no high-water mark — that residual window is documented
    in GOVERNANCE.md.
    """
    target = Path(target_dir).resolve()
    lock_file = Path(lock_path) if lock_path else target / LOCKFILE_NAME
    if not lock_file.exists():
        return
    lock = _load_lock(lock_file)
    seen = lock.get("registries", {}).get(registry.location, {})
    for label, current, floor in (
        ("index", index.get("sequence", 0), seen.get("index_sequence", 0)),
        ("namespace registry", ns_registry.sequence, seen.get("namespace_sequence", 0)),
    ):
        if current < floor:
            raise VerificationError(
                f"registry {label} sequence went BACKWARDS ({floor} -> {current}); "
                "a validly-signed but stale trust document is a rollback attack, refusing"
            )


def _safe_target(root: Path, *parts: str) -> Path:
    """Join parts under root, refusing any escape (Threat T7)."""
    root_resolved = root.resolve()
    joined = root_resolved
    for part in parts:
        joined = joined / part
        if joined.is_symlink():
            raise HubError(f"install path {'/'.join(parts)!r} contains a symbolic link")
    candidate = joined.resolve()
    if not candidate.is_relative_to(root_resolved):
        raise HubError(f"install path {'/'.join(parts)!r} escapes the target directory")
    return joined


def install(
    ref: str,
    target_dir: str | Path,
    registry: RegistryClient,
    lock_path: str | Path | None = None,
) -> InstallResult:
    """Install ``namespace/id[@version]`` into ``target_dir`` after full verification."""
    namespace, artifact_id, requested = validate_ref(ref)

    # Namespace membership + publisher keys come from the ROOT-verified
    # namespace registry; community keys are delegated, never a new root.
    # Checked BEFORE any index lookup so an unregistered namespace reports
    # "not registered", not "not found".
    ns_registry = registry.namespace_registry()
    publisher_keys = ns_registry.publisher_keys(namespace)

    index = registry.index()
    version = registry.resolve_version(namespace, artifact_id, requested, index=index)
    index_rec = index["artifacts"].get(f"{namespace}/{artifact_id}", {}).get("versions", {}).get(version)
    if not isinstance(index_rec, dict):
        raise VerificationError(f"signed index has no record for {namespace}/{artifact_id}@{version}")

    entry = registry.entry(namespace, artifact_id, version)
    validate_entry(entry, require_distribution=True, known_namespaces=ns_registry.names)
    if entry.get("id") != artifact_id or entry.get("version") != version or entry.get("namespace") != namespace:
        raise VerificationError(
            f"registry entry does not describe {namespace}/{artifact_id}@{version} "
            f"(entry says {entry.get('namespace')}/{entry.get('id')}@{entry.get('version')})"
        )
    # entry.json is unsigned; its load-bearing fields must match the SIGNED index.
    for field_name in ("content_sha256", "trust_tier"):
        if entry.get(field_name) != index_rec.get(field_name):
            raise VerificationError(
                f"entry.json {field_name} ({entry.get(field_name)!r}) disagrees with the "
                f"signed index ({index_rec.get(field_name)!r}); refusing"
            )

    artifact_name = entry["distribution"].get("artifact")
    if not isinstance(artifact_name, str) or not artifact_name:
        raise VerificationError("registry entry names no artifact file")
    validate_artifact_filename(artifact_name)
    if index_rec.get("artifact") is not None and index_rec["artifact"] != artifact_name:
        raise VerificationError(
            f"entry.json artifact filename ({artifact_name!r}) disagrees with the "
            f"signed index ({index_rec['artifact']!r}); refusing"
        )

    content = registry.artifact(namespace, artifact_id, version, artifact_name)
    sig_bytes = registry.artifact(namespace, artifact_id, version, artifact_name + ".ed25519.sig")

    # Signature (namespace-scoped keys) + sidecar hash + entry hash must all
    # agree (T2, T3).
    verified = verify_artifact_bytes(
        content,
        sig_bytes,
        expected_sha256=entry["content_sha256"],
        publisher_keys=publisher_keys,
    )

    # The `verified` tier is issued ONLY by a domain-separated ROOT
    # counter-signature; no publisher (founder included) can self-declare it by
    # editing entry.json, and an artifact's own signature cannot be replayed
    # as a counter-signature.
    countersig_bytes: bytes | None = None
    if entry["trust_tier"] == "verified":
        countersig_name = artifact_name + ".ed25519.countersig"
        try:
            countersig_bytes = registry.artifact(namespace, artifact_id, version, countersig_name)
        except NotFoundError as exc:
            raise VerificationError(
                f"entry claims trust tier 'verified' but {countersig_name} does not exist in the registry; refusing"
            ) from exc
        verify_countersignature(content, countersig_bytes, ref=f"{namespace}/{artifact_id}@{version}")

    target = Path(target_dir).resolve()
    dest_dir = _safe_target(target, namespace, artifact_id, version)
    files: list[tuple[str, bytes]] = [
        (artifact_name, content),
        (artifact_name + ".ed25519.sig", sig_bytes),
        ("entry.json", json.dumps(entry, indent=2, sort_keys=True).encode("utf-8")),
    ]
    if countersig_bytes is not None:
        files.append((artifact_name + ".ed25519.countersig", countersig_bytes))
    # Keep a caller-supplied path lexical so _load_lock can detect a symlink.
    # Resolving it here would silently turn the link target into the write target.
    lock_file = Path(lock_path).absolute() if lock_path else target / LOCKFILE_NAME
    try:
        written = _commit_install(
            target=target,
            dest_dir=dest_dir,
            lock_file=lock_file,
            files=files,
            namespace=namespace,
            artifact_id=artifact_id,
            version=version,
            artifact_name=artifact_name,
            trust_tier=entry["trust_tier"],
            verified=verified,
            registry=registry,
            index=index,
            ns_registry=ns_registry,
        )
    except (HubError, VerificationError):
        raise
    except OSError as exc:
        raise HubError(f"cannot commit install for {namespace}/{artifact_id}@{version}: {exc}") from exc

    return InstallResult(
        ref=f"{namespace}/{artifact_id}",
        version=version,
        content_sha256=verified.content_sha256,
        key_id=verified.key_id,
        files=tuple(written),
        trust_tier=entry["trust_tier"],
    )


def verify_tree(
    target_dir: str | Path,
    lock_path: str | Path | None = None,
    registry: RegistryClient | None = None,
) -> list[str]:
    """Re-verify every locked artifact on disk. Returns verified refs; raises on drift.

    Scope: this detects drift between the tree and vcp.lock (tampered bytes,
    swapped signatures, missing files). Like every lockfile, vcp.lock itself is
    local state — an attacker who can rewrite BOTH the lock and the tree is
    outside its threat model. Pass ``registry`` to additionally re-check every
    pin against the LIVE root-signed index (hash + trust tier + revocations),
    which that attacker cannot forge.
    """
    target = Path(target_dir).resolve()
    lock_file = Path(lock_path) if lock_path else target / LOCKFILE_NAME
    if not lock_file.exists():
        raise HubError(f"no lockfile at {lock_file}; nothing to verify")
    lock = _load_lock(lock_file)
    live_index: dict[str, Any] | None = None
    live_namespace_registry: Any | None = None
    if registry is not None:
        live_namespace_registry = registry.namespace_registry()
        live_index = registry.index()
        _check_sequences(registry, live_index, live_namespace_registry, target, lock_file)

    verified_refs: list[str] = []
    problems: list[str] = []
    for ref, pin in sorted(lock["artifacts"].items()):
        try:
            namespace, artifact_id, _ = validate_ref(f"{ref}@{pin['version']}")
            artifact_name = pin["artifact"]
            validate_artifact_filename(artifact_name)
            base = _safe_target(target, namespace, artifact_id, pin["version"])
            content_path = _safe_target(base, artifact_name)
            sig_path = _safe_target(base, artifact_name + ".ed25519.sig")
            if not content_path.is_file():
                raise VerificationError(f"installed artifact missing: {content_path}")
            if not sig_path.is_file():
                raise VerificationError(f"installed signature missing: {sig_path}")
            content = _read_bounded(content_path, MAX_FETCH_BYTES, f"installed artifact {content_path}")
            # Re-check the SAME trust decision made at install time: the lock
            # pins the exact key that verified then. Locks written before key
            # pinning fall back to the pinned root allowlist.
            locked_keys = {pin["key_id"]: pin["public_key"]} if pin.get("public_key") else None
            verified = verify_artifact_bytes(
                content,
                _read_bounded(
                    sig_path,
                    MAX_SIGNATURE_SIDECAR_BYTES,
                    f"installed signature {sig_path}",
                ),
                expected_sha256=pin["content_sha256"],
                publisher_keys=locked_keys,
            )
            if verified.key_id != pin["key_id"]:
                raise VerificationError(
                    f"{ref}: signer changed since install ({pin['key_id']!r} -> {verified.key_id!r})"
                )
            if pin.get("trust_tier") == "verified":
                countersig_path = _safe_target(base, pin["artifact"] + ".ed25519.countersig")
                if not countersig_path.is_file():
                    raise VerificationError(f"installed counter-signature missing: {countersig_path}")
                verify_countersignature(
                    content,
                    _read_bounded(
                        countersig_path,
                        MAX_SIGNATURE_SIDECAR_BYTES,
                        f"installed counter-signature {countersig_path}",
                    ),
                    ref=f"{ref}@{pin['version']}",
                )
            if live_index is not None:
                # Live re-check: the root-signed index must still vouch for
                # exactly this hash and tier, and the current root-signed
                # namespace registry must still authorize the pinned signer.
                assert live_namespace_registry is not None
                current_keys = live_namespace_registry.publisher_keys(namespace)
                current_pem = current_keys.get(pin["key_id"])
                if current_pem is None:
                    raise VerificationError("pinned signer is no longer authorized by the live namespace registry")
                if pin.get("public_key") is not None and current_pem != pin["public_key"]:
                    raise VerificationError("pinned signer key changed in the live namespace registry")
                live = live_index["artifacts"].get(ref, {}).get("versions", {}).get(pin["version"])
                if not isinstance(live, dict):
                    raise VerificationError("no longer present in the live signed index (revoked or removed)")
                if live.get("content_sha256") != pin["content_sha256"]:
                    raise VerificationError("lockfile hash disagrees with the live signed index")
                if live.get("trust_tier") != pin.get("trust_tier"):
                    raise VerificationError(
                        f"lockfile trust tier {pin.get('trust_tier')!r} disagrees with the "
                        f"live signed index ({live.get('trust_tier')!r})"
                    )
            verified_refs.append(f"{ref}@{pin['version']}")
        except (HubError, KeyError, TypeError) as exc:
            problems.append(f"{ref}: {exc}")
    if problems:
        raise VerificationError("installed tree has drifted from vcp.lock:\n  " + "\n  ".join(problems))
    return verified_refs
