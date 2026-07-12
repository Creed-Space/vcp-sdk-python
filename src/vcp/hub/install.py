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
from .errors import HubError, NotFoundError, VerificationError
from .registry import RegistryClient, validate_ref
from .verify import verify_artifact_bytes, verify_countersignature

LOCKFILE_NAME = "vcp.lock"
LOCKFILE_VERSION = 1


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
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HubError(f"cannot read lockfile {lock_path}: {exc}") from exc
    if not isinstance(lock, dict) or lock.get("lockfile_version") != LOCKFILE_VERSION:
        raise HubError(f"lockfile {lock_path} has an unsupported format")
    if not isinstance(lock.get("artifacts"), dict):
        raise HubError(f"lockfile {lock_path} has no artifacts map")
    return lock


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

    # Namespace membership + publisher keys come from the ROOT-verified
    # namespace registry; community keys are delegated, never a new root.
    # Checked BEFORE any index lookup so an unregistered namespace reports
    # "not registered", not "not found".
    ns_registry = registry.namespace_registry()
    publisher_keys = ns_registry.publisher_keys(namespace)

    index = registry.index()
    _check_sequences(registry, index, ns_registry, Path(target_dir), lock_path)
    version = registry.resolve_version(namespace, artifact_id, requested)
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
        content, sig_bytes, expected_sha256=entry["content_sha256"], publisher_keys=publisher_keys
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
    dest_dir.mkdir(parents=True, exist_ok=True)
    written = []
    files: list[tuple[str, bytes]] = [
        (artifact_name, content),
        (artifact_name + ".ed25519.sig", sig_bytes),
        ("entry.json", json.dumps(entry, indent=2, sort_keys=True).encode("utf-8")),
    ]
    if countersig_bytes is not None:
        files.append((artifact_name + ".ed25519.countersig", countersig_bytes))
    for filename, data in files:
        dest = _safe_target(dest_dir, filename)
        dest.write_bytes(data)
        written.append(str(dest.relative_to(target)))

    lock_file = Path(lock_path) if lock_path else target / LOCKFILE_NAME
    lock = _load_lock(lock_file)
    lock["artifacts"][f"{namespace}/{artifact_id}"] = {
        "version": version,
        "content_sha256": verified.content_sha256,
        "key_id": verified.key_id,
        # Pin the exact key that verified, so vcp verify re-checks the same
        # trust decision even if the namespace registry changes later.
        "public_key": verified.public_key_pem,
        "artifact": artifact_name,
        "trust_tier": entry["trust_tier"],
    }
    # Anti-rollback high-water marks (never lowered).
    registries = lock.setdefault("registries", {})
    seen = registries.setdefault(registry.location, {})
    seen["index_sequence"] = max(seen.get("index_sequence", 0), index["sequence"])
    seen["namespace_sequence"] = max(seen.get("namespace_sequence", 0), ns_registry.sequence)
    lock_file.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")

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
            content = content_path.read_bytes()
            # Re-check the SAME trust decision made at install time: the lock
            # pins the exact key that verified then. Locks written before key
            # pinning fall back to the pinned root allowlist.
            locked_keys = {pin["key_id"]: pin["public_key"]} if pin.get("public_key") else None
            verified = verify_artifact_bytes(
                content,
                sig_path.read_bytes(),
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
                verify_countersignature(content, countersig_path.read_bytes(), ref=f"{ref}@{pin['version']}")
            if registry is not None:
                # Live re-check: the root-signed index must still vouch for
                # exactly this hash and tier (catches lock+tree co-tampering,
                # revocations, and tier downgrades a local attacker could fake).
                live = registry.index()["artifacts"].get(ref, {}).get("versions", {}).get(pin["version"])
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
