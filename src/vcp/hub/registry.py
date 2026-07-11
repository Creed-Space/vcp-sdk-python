"""Registry access for Creed Commons — fetch bytes, never execute them.

A registry is a directory tree (local or HTTP-served) with the layout::

    index.json
    namespaces/<namespace>/<id>/<version>/
        <artifact file>            e.g. anti_gaslighting.md
        <artifact file>.ed25519.sig
        entry.json

Only two URL schemes are accepted (Threat T7): ``file://`` (plus bare local
paths) and ``https://`` to an explicitly allowlisted host. Every id, namespace,
and version is validated against a strict regex before it touches a path or URL.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .errors import HubError

# Launch policy: only the Creed Space namespace may be published or installed.
# Community namespaces (and confusable variants like creed_space / creedspace)
# stay locked until a moderation + verified-tier process exists.
ALLOWED_NAMESPACES = frozenset({"creed-space"})

# https:// registries are only accepted on these hosts (Threat T7 — no SSRF
# via attacker-chosen registry URLs baked into refs or indexes).
ALLOWED_HTTPS_HOSTS = frozenset({"raw.githubusercontent.com"})

DEFAULT_REGISTRY_URL = "https://raw.githubusercontent.com/Creed-Space/vcp-hub/main"

NAMESPACE_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
ARTIFACT_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
VERSION_RE = re.compile(r"^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$")

MAX_FETCH_BYTES = 8 * 1024 * 1024  # generous cap for a text artifact

INDEX_VERSION = 1


def validate_ref(ref: str) -> tuple[str, str, str | None]:
    """Parse and validate ``namespace/id[@version]``. Raises HubError."""
    if "@" in ref:
        path_part, _, version = ref.partition("@")
        if not VERSION_RE.match(version):
            raise HubError(f"invalid version {version!r} (expected MAJOR.MINOR.PATCH)")
    else:
        path_part, version = ref, None
    namespace, sep, artifact_id = path_part.partition("/")
    if not sep or not artifact_id:
        raise HubError(f"invalid ref {ref!r} (expected namespace/id[@version])")
    if not NAMESPACE_RE.match(namespace):
        raise HubError(f"invalid namespace {namespace!r}")
    if namespace not in ALLOWED_NAMESPACES:
        raise HubError(
            f"namespace {namespace!r} is not yet open: Creed Commons is launch-locked "
            f"to {sorted(ALLOWED_NAMESPACES)}. Community publishing opens once a "
            "moderation and verified-tier process exists."
        )
    if not ARTIFACT_ID_RE.match(artifact_id):
        raise HubError(f"invalid artifact id {artifact_id!r}")
    return namespace, artifact_id, version


class RegistryClient:
    """Read-only client for a Creed Commons registry (file:// or allowlisted https://)."""

    def __init__(self, base: str = DEFAULT_REGISTRY_URL):
        self._base_path: Path | None = None
        self._base_url: str | None = None

        parsed = urllib.parse.urlparse(base)
        if parsed.scheme in ("", "file"):
            raw = urllib.request.url2pathname(parsed.path) if parsed.scheme == "file" else base
            self._base_path = Path(raw).resolve()
            if not self._base_path.is_dir():
                raise HubError(f"registry path {self._base_path} is not a directory")
        elif parsed.scheme == "https":
            if parsed.hostname not in ALLOWED_HTTPS_HOSTS:
                raise HubError(
                    f"https registry host {parsed.hostname!r} is not allowlisted "
                    f"(allowed: {sorted(ALLOWED_HTTPS_HOSTS)})"
                )
            self._base_url = base.rstrip("/")
        else:
            raise HubError(
                f"registry URL scheme {parsed.scheme!r} is not allowed (file:// and allowlisted https:// only)"
            )

    @property
    def location(self) -> str:
        return str(self._base_path) if self._base_path else str(self._base_url)

    def _fetch(self, rel_path: str) -> bytes:
        """Fetch raw bytes at a registry-relative path. Data only — never executed."""
        if "\\" in rel_path or rel_path.startswith("/") or ".." in rel_path.split("/"):
            raise HubError(f"illegal registry path {rel_path!r}")
        if self._base_path is not None:
            target = (self._base_path / rel_path).resolve()
            if not target.is_relative_to(self._base_path):
                raise HubError(f"registry path {rel_path!r} escapes the registry root")
            if not target.is_file():
                raise HubError(f"registry object not found: {rel_path}")
            data = target.read_bytes()
            if len(data) > MAX_FETCH_BYTES:
                raise HubError(f"registry object {rel_path} exceeds size cap")
            return data
        url = f"{self._base_url}/{rel_path}"
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:  # nosec B310 — scheme/host allowlisted in __init__
                data = resp.read(MAX_FETCH_BYTES + 1)
        except OSError as exc:
            raise HubError(f"failed to fetch {url}: {exc}") from exc
        if len(data) > MAX_FETCH_BYTES:
            raise HubError(f"registry object {rel_path} exceeds size cap")
        return data

    def index(self) -> dict[str, Any]:
        """Load and structurally validate index.json."""
        try:
            index = json.loads(self._fetch("index.json").decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HubError(f"registry index.json is not valid JSON: {exc}") from exc
        if not isinstance(index, dict) or index.get("index_version") != INDEX_VERSION:
            raise HubError("registry index.json has an unsupported format")
        if not isinstance(index.get("artifacts"), dict):
            raise HubError("registry index.json has no artifacts map")
        return index

    def resolve_version(self, namespace: str, artifact_id: str, version: str | None) -> str:
        """Resolve a possibly-absent version to a concrete one via the index."""
        index = self.index()
        record = index["artifacts"].get(f"{namespace}/{artifact_id}")
        if not isinstance(record, dict):
            raise HubError(f"artifact {namespace}/{artifact_id} not found in registry index")
        resolved = version or record.get("latest")
        if not isinstance(resolved, str) or not VERSION_RE.match(resolved):
            raise HubError(f"registry index has no valid version for {namespace}/{artifact_id}")
        versions = record.get("versions")
        if not isinstance(versions, dict) or resolved not in versions:
            raise HubError(f"version {resolved} of {namespace}/{artifact_id} not found in registry index")
        return resolved

    def _version_dir(self, namespace: str, artifact_id: str, version: str) -> str:
        for value, pattern, label in (
            (namespace, NAMESPACE_RE, "namespace"),
            (artifact_id, ARTIFACT_ID_RE, "artifact id"),
            (version, VERSION_RE, "version"),
        ):
            if not pattern.match(value):
                raise HubError(f"invalid {label} {value!r}")
        return f"namespaces/{namespace}/{artifact_id}/{version}"

    def entry(self, namespace: str, artifact_id: str, version: str) -> dict[str, Any]:
        """Fetch entry.json for one artifact version."""
        rel = f"{self._version_dir(namespace, artifact_id, version)}/entry.json"
        try:
            entry = json.loads(self._fetch(rel).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HubError(f"entry.json for {namespace}/{artifact_id}@{version} is not valid JSON: {exc}") from exc
        if not isinstance(entry, dict):
            raise HubError(f"entry.json for {namespace}/{artifact_id}@{version} must be a JSON object")
        return entry

    def artifact(self, namespace: str, artifact_id: str, version: str, filename: str) -> bytes:
        """Fetch the artifact (or sidecar) bytes for one version. Pure data."""
        if "/" in filename or "\\" in filename or filename.startswith("."):
            raise HubError(f"illegal artifact filename {filename!r}")
        return self._fetch(f"{self._version_dir(namespace, artifact_id, version)}/{filename}")
