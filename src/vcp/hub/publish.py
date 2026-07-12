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

import hashlib
import json
from pathlib import Path
from typing import Any

from .entry_schema import validate_entry
from .errors import HubError, VerificationError
from .lint import write_index
from .namespace_registry import load_hub_namespace_registry
from .registry import ARTIFACT_ID_RE, VERSION_RE, validate_ref
from .verify import verify_artifact_bytes

SOURCE_REPO = "https://github.com/Creed-Space/Rewind"


def _frontmatter(md_path: Path) -> dict[str, Any]:
    """Parse YAML frontmatter for entry metadata. Data only — never executed."""
    try:
        import yaml
    except ImportError as exc:
        raise HubError("the 'PyYAML' package is required to publish (install vcp-sdk[hub])") from exc
    text = md_path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        raise HubError(f"{md_path.name}: no YAML frontmatter")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise HubError(f"{md_path.name}: unterminated YAML frontmatter")
    fm = parts[1]
    data = yaml.safe_load(fm)
    if not isinstance(data, dict):
        raise HubError(f"{md_path.name}: frontmatter is not a mapping")
    return data


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
    sig_path = artifact_path.with_suffix(artifact_path.suffix + ".ed25519.sig")
    if not sig_path.is_file():
        raise VerificationError(
            f"{artifact_path.name}: no .ed25519.sig sidecar; unsigned artifacts are never published"
        )
    content = artifact_path.read_bytes()
    verified = verify_artifact_bytes(content, sig_path.read_bytes(), publisher_keys=publisher_keys)

    entry: dict[str, Any] = dict(base_entry) if base_entry else {}
    fm = _frontmatter(artifact_path)

    artifact_id = entry.get("id") or fm.get("id")
    if not artifact_id or not ARTIFACT_ID_RE.match(str(artifact_id)):
        raise HubError(f"{artifact_path.name}: no valid artifact id (frontmatter or base entry)")
    version = str(entry.get("version") or fm.get("version") or "")
    if not VERSION_RE.match(version):
        raise HubError(f"{artifact_path.name}: no valid MAJOR.MINOR.PATCH version (got {version!r})")

    entry.setdefault("id", str(artifact_id))
    entry["version"] = version
    entry.setdefault("name", str(fm.get("display_title") or fm.get("title") or artifact_id))
    if fm.get("description") and "description" not in entry:
        entry["description"] = str(fm["description"])
    if fm.get("author") and "author" not in entry:
        entry["author"] = str(fm["author"])

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

    version_dir = root / "namespaces" / namespace / entry["id"] / entry["version"]
    content = artifact_path.read_bytes()
    existing_artifact = version_dir / artifact_path.name
    if existing_artifact.exists():
        if hashlib.sha256(existing_artifact.read_bytes()).hexdigest() != entry["content_sha256"]:
            raise VerificationError(
                f"{namespace}/{entry['id']}@{entry['version']} already exists with different "
                "content; published versions are immutable — bump the version instead"
            )
        # Provenance is immutable too: identical bytes republished under a
        # different signer would silently swap the recorded key (T2/T3).
        existing_entry_path = version_dir / "entry.json"
        if existing_entry_path.exists():
            try:
                existing_entry = json.loads(existing_entry_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise VerificationError(
                    f"existing entry.json for {namespace}/{entry['id']}@{entry['version']} is unreadable: {exc}"
                ) from exc
            existing_sigs = existing_entry.get("distribution", {}).get("signatures")
            if existing_sigs != entry["distribution"]["signatures"]:
                raise VerificationError(
                    f"{namespace}/{entry['id']}@{entry['version']} already exists signed by "
                    f"{existing_sigs}; refusing to change the recorded signer of an "
                    "immutable version"
                )

    version_dir.mkdir(parents=True, exist_ok=True)
    (version_dir / artifact_path.name).write_bytes(content)
    sig_path = artifact_path.with_suffix(artifact_path.suffix + ".ed25519.sig")
    (version_dir / sig_path.name).write_bytes(sig_path.read_bytes())
    (version_dir / "entry.json").write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report = write_index(root)
    if not report.ok:
        raise VerificationError("hub tree failed lint after publish:\n  " + "\n  ".join(report.problems))
    return f"{namespace}/{entry['id']}@{entry['version']}"
