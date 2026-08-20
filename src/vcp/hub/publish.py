"""Publish a signed artifact into a Creed Commons registry tree (PR flow).

``publish`` takes a SIGNED source artifact (e.g. a constitution ``.md`` with its
``.ed25519.sig`` sidecar), builds a distribution registry entry (optionally
extending an existing compiled registry entry), verifies everything, and writes
the ``namespaces/<ns>/<id>/<version>/`` directory plus a regenerated index.

Refusals (fail closed):
- unsigned artifact (no ``.ed25519.sig`` sidecar) — never publishable
- signature that does not verify against the pinned publisher allowlist
- schema-invalid resulting entry
- namespace outside the launch allowlist
- republishing an existing version with different bytes (immutability, T2)
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .._json import loads_strict
from .entry_schema import validate_entry
from .errors import HubError, VerificationError
from .lint import write_index
from .namespace_registry import load_hub_namespace_registry
from .registry import (
    ARTIFACT_ID_RE,
    MAX_FETCH_BYTES,
    VERSION_RE,
    validate_artifact_filename,
    validate_ref,
)
from .verify import MAX_SIGNATURE_SIDECAR_BYTES, verify_artifact_bytes

SOURCE_REPO = "https://github.com/Creed-Space/Rewind"
MAX_FRONTMATTER_BYTES = 64 * 1024


def _read_bounded(path: Path, cap: int, description: str) -> bytes:
    try:
        if not path.is_file():
            raise HubError(f"{description} is not a regular file")
        if path.stat().st_size > cap:
            raise HubError(f"{description} exceeds size cap")
        with path.open("rb") as handle:
            data = handle.read(cap + 1)
    except HubError:
        raise
    except OSError as exc:
        raise HubError(f"cannot read {description}: {exc}") from exc
    if len(data) > cap:
        raise HubError(f"{description} exceeds size cap")
    return data


@contextlib.contextmanager
def _publish_mutex(root: Path):
    """Serialize version and index commits by cooperating publisher processes."""
    root.mkdir(parents=True, exist_ok=True)
    guard_path = root / ".vcp-publish.mutex"
    if guard_path.is_symlink():
        raise HubError(f"publish mutex {guard_path} must not be a symbolic link")
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


def _write_bytes_atomically(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_temp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp_path = Path(raw_temp)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _safe_hub_path(root: Path, *parts: str) -> Path:
    """Construct a hub-local path without traversing symbolic-link directories."""
    root_resolved = root.resolve()
    joined = root_resolved
    for part in parts:
        joined = joined / part
        if joined.is_symlink():
            raise HubError(f"hub path {'/'.join(parts)!r} contains a symbolic link")
    if not joined.resolve().is_relative_to(root_resolved):
        raise HubError(f"hub path {'/'.join(parts)!r} escapes the hub root")
    return joined


def _restore_file(path: Path, previous: bytes | None) -> None:
    if previous is None:
        path.unlink(missing_ok=True)
    else:
        _write_bytes_atomically(path, previous)


def _frontmatter_from_bytes(content: bytes, filename: str) -> dict[str, Any]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HubError(f"{filename}: artifact is not valid UTF-8: {exc}") from exc
    if text.startswith("---\r\n"):
        body_start = 5
    elif text.startswith("---\n"):
        body_start = 4
    else:
        raise HubError(f"{filename}: no YAML frontmatter")
    match = re.search(r"(?m)^---[ \t]*\r?$", text[body_start : body_start + MAX_FRONTMATTER_BYTES + 1])
    if match is None:
        raise HubError(f"{filename}: unterminated or oversized YAML frontmatter")
    fm = text[body_start : body_start + match.start()]
    if len(fm.encode("utf-8")) > MAX_FRONTMATTER_BYTES:
        raise HubError(f"{filename}: unterminated or oversized YAML frontmatter")
    try:
        import yaml
    except ImportError as exc:
        raise HubError(
            "the 'PyYAML' package is required to publish (install this checkout with the [hub] extra)"
        ) from exc

    class UniqueKeySafeLoader(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            self.flatten_mapping(node)
            mapping = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                try:
                    duplicate = key in mapping
                except TypeError as exc:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping",
                        node.start_mark,
                        "found an unhashable YAML key",
                        key_node.start_mark,
                    ) from exc
                if duplicate:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping",
                        node.start_mark,
                        f"found duplicate YAML key {key!r}",
                        key_node.start_mark,
                    )
                mapping[key] = self.construct_object(value_node, deep=deep)
            return mapping

    try:
        data = yaml.load(fm, Loader=UniqueKeySafeLoader)
    except (yaml.YAMLError, RecursionError) as exc:
        raise HubError(f"{filename}: invalid YAML frontmatter: {exc}") from exc
    if not isinstance(data, dict):
        raise HubError(f"{filename}: frontmatter is not a mapping")
    return data


def _frontmatter(md_path: Path) -> dict[str, Any]:
    """Parse YAML frontmatter for entry metadata. Data only — never executed."""
    return _frontmatter_from_bytes(_read_bounded(md_path, MAX_FETCH_BYTES, md_path.name), md_path.name)


def build_entry(
    artifact_path: Path,
    namespace: str = "creed-space",
    base_entry: dict[str, Any] | None = None,
    publisher_keys: dict[str, str] | None = None,
    known_namespaces: set[str] | None = None,
) -> dict[str, Any]:
    """Build a distribution registry entry for a signed artifact.

    ``base_entry`` (an existing compiled registry entry) is extended when given;
    otherwise a minimal entry is derived from the artifact's frontmatter.
    ``publisher_keys`` scopes signature trust to the namespace's registered keys
    (``None`` = pinned root, correct for the founder namespace).
    """
    if not isinstance(base_entry, (dict, type(None))):
        raise HubError("base_entry must be an object")
    try:
        validate_artifact_filename(artifact_path.name)
    except HubError as exc:
        raise HubError(f"invalid source artifact name: {exc}") from exc
    sig_path = artifact_path.with_suffix(artifact_path.suffix + ".ed25519.sig")
    if not sig_path.is_file():
        raise VerificationError(
            f"{artifact_path.name}: no .ed25519.sig sidecar; unsigned artifacts are never published"
        )
    content = _read_bounded(artifact_path, MAX_FETCH_BYTES, artifact_path.name)
    signature = _read_bounded(sig_path, MAX_SIGNATURE_SIDECAR_BYTES, sig_path.name)
    verified = verify_artifact_bytes(content, signature, publisher_keys=publisher_keys)

    entry: dict[str, Any] = dict(base_entry) if base_entry else {}
    fm = _frontmatter(artifact_path)

    artifact_id = entry.get("id") or fm.get("id")
    if not isinstance(artifact_id, str) or ARTIFACT_ID_RE.fullmatch(artifact_id) is None:
        raise HubError(f"{artifact_path.name}: no valid artifact id (frontmatter or base entry)")
    version = entry.get("version") or fm.get("version")
    if not isinstance(version, str) or VERSION_RE.fullmatch(version) is None:
        raise HubError(f"{artifact_path.name}: no valid MAJOR.MINOR.PATCH version (got {version!r})")

    entry.setdefault("id", artifact_id)
    entry["version"] = version
    if "name" not in entry:
        name = fm.get("display_title") or fm.get("title") or artifact_id
        if not isinstance(name, str):
            raise HubError(f"{artifact_path.name}: title must be a string")
        entry["name"] = name
    for field_name in ("description", "author"):
        value = fm.get(field_name)
        if value and field_name not in entry:
            if not isinstance(value, str):
                raise HubError(f"{artifact_path.name}: {field_name} must be a string")
            entry[field_name] = value

    entry["namespace"] = namespace
    entry["content_sha256"] = verified.content_sha256
    # MVP issues only the `signed` tier: signature+hash+schema verified, semantics
    # NOT vouched for. `verified` requires lint + red-team + counter-signature and
    # is never set by this tool.
    entry["trust_tier"] = "signed"
    entry["distribution"] = {
        "signatures": {"ed25519": verified.key_id},
        "source_repo": SOURCE_REPO,
        "artifact": artifact_path.name,
    }

    validate_entry(entry, require_distribution=True, known_namespaces=known_namespaces)
    validate_ref(f"{namespace}/{entry['id']}@{version}")
    return entry


def publish(
    artifact_path: str | Path,
    hub_root: str | Path,
    namespace: str = "creed-space",
    base_entry: dict[str, Any] | None = None,
) -> str:
    """Publish a signed artifact into ``hub_root`` and regenerate the index.

    Returns the published ref ``namespace/id@version``.
    """
    artifact_path = Path(artifact_path)
    root = Path(hub_root).resolve()
    # The hub's own root-verified namespace registry decides who may publish
    # where; the publisher's signature must verify against the keys registered
    # for the TARGET namespace (no cross-namespace signing).
    ns_registry = load_hub_namespace_registry(root)
    entry = build_entry(
        artifact_path,
        namespace=namespace,
        base_entry=base_entry,
        publisher_keys=ns_registry.publisher_keys(namespace),
        known_namespaces=ns_registry.names,
    )

    sig_path = artifact_path.with_suffix(artifact_path.suffix + ".ed25519.sig")
    content = _read_bounded(artifact_path, MAX_FETCH_BYTES, artifact_path.name)
    signature = _read_bounded(sig_path, MAX_SIGNATURE_SIDECAR_BYTES, sig_path.name)
    verify_artifact_bytes(
        content,
        signature,
        expected_sha256=entry["content_sha256"],
        publisher_keys=ns_registry.publisher_keys(namespace),
    )

    version_dir = _safe_hub_path(root, "namespaces", namespace, entry["id"], entry["version"])
    index_path = _safe_hub_path(root, "index.json")
    index_sig_path = _safe_hub_path(root, "index.json.ed25519.sig")
    ref = f"{namespace}/{entry['id']}@{entry['version']}"
    with _publish_mutex(root):
        old_index = _read_bounded(index_path, MAX_FETCH_BYTES, "index.json") if index_path.is_file() else None
        old_index_sig = (
            _read_bounded(index_sig_path, MAX_SIGNATURE_SIDECAR_BYTES, "index signature")
            if index_sig_path.is_file()
            else None
        )

        staging: Path | None = None
        committed_new_version = False
        try:
            if version_dir.exists():
                if version_dir.is_symlink() or not version_dir.is_dir():
                    raise VerificationError(f"{ref} exists but is not a regular version directory")
                existing_artifact = version_dir / artifact_path.name
                existing_signature = version_dir / sig_path.name
                existing_entry_path = version_dir / "entry.json"
                if not all(
                    path.is_file() and not path.is_symlink()
                    for path in (
                        existing_artifact,
                        existing_signature,
                        existing_entry_path,
                    )
                ):
                    raise VerificationError(f"{ref} already exists in a corrupt or incomplete state")
                existing_content = _read_bounded(existing_artifact, MAX_FETCH_BYTES, f"existing artifact for {ref}")
                if hashlib.sha256(existing_content).hexdigest() != entry["content_sha256"]:
                    raise VerificationError(
                        f"{ref} already exists with different content; published versions are immutable, "
                        "bump the version instead"
                    )
                try:
                    existing_entry = loads_strict(
                        _read_bounded(
                            existing_entry_path,
                            MAX_FETCH_BYTES,
                            f"existing entry for {ref}",
                        ).decode("utf-8")
                    )
                except (UnicodeDecodeError, ValueError, RecursionError) as exc:
                    raise VerificationError(f"existing entry.json for {ref} is unreadable: {exc}") from exc
                if existing_entry != entry:
                    raise VerificationError(f"{ref} already exists with different immutable metadata or provenance")
                verify_artifact_bytes(
                    existing_content,
                    _read_bounded(
                        existing_signature,
                        MAX_SIGNATURE_SIDECAR_BYTES,
                        f"existing signature for {ref}",
                    ),
                    expected_sha256=entry["content_sha256"],
                    publisher_keys=ns_registry.publisher_keys(namespace),
                )
            else:
                version_dir.parent.mkdir(parents=True, exist_ok=True)
                staging = Path(tempfile.mkdtemp(prefix=f".{entry['version']}.staging-", dir=version_dir.parent))
                (staging / artifact_path.name).write_bytes(content)
                (staging / sig_path.name).write_bytes(signature)
                (staging / "entry.json").write_text(
                    json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
                os.replace(staging, version_dir)
                committed_new_version = True

            report = write_index(root)
            if not report.ok:
                raise VerificationError("hub tree failed lint after publish:\n  " + "\n  ".join(report.problems))
            new_index = _read_bounded(index_path, MAX_FETCH_BYTES, "index.json")
            if old_index_sig is not None and new_index != old_index:
                index_sig_path.unlink(missing_ok=True)
        except Exception:
            if committed_new_version:
                shutil.rmtree(version_dir, ignore_errors=True)
            _restore_file(index_path, old_index)
            _restore_file(index_sig_path, old_index_sig)
            raise
        finally:
            if staging is not None and staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
    return ref
