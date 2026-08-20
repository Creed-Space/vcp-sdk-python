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

import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .._json import loads_strict
from .errors import HubError, NotFoundError, VerificationError
from .namespace_registry import (
    BUILTIN_REGISTRY,
    NAMESPACE_RE,
    REGISTRY_FILENAME,
    NamespaceRegistry,
    parse_namespace_registry,
)
from .verify import INDEX_CONTEXT, verify_detached

# Namespace policy (2026-07-12, community launch): membership is decided by the
# hub's namespace_registry.json, which must verify against the pinned ROOT keys
# (see vcp.hub.namespace_registry). A hub without one is founder-only.
# This constant remains as the bootstrap/founder set.
ALLOWED_NAMESPACES = frozenset({"creed-space"})

# https:// registries are only accepted on these hosts (Threat T7 — no SSRF
# via attacker-chosen registry URLs baked into refs or indexes).
ALLOWED_HTTPS_HOSTS = frozenset({"raw.githubusercontent.com"})

DEFAULT_REGISTRY_URL = "https://raw.githubusercontent.com/Creed-Space/vcp-hub/main"

# NAMESPACE_RE is canonical in namespace_registry.py (re-exported above).
ARTIFACT_ID_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
VERSION_RE = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\Z")
ARTIFACT_FILENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
_WINDOWS_RESERVED_STEM_RE = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])\Z", re.IGNORECASE)

MAX_FETCH_BYTES = 8 * 1024 * 1024  # generous cap for a text artifact
_CONTENT_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

# v2: index.json is ROOT-SIGNED (domain-separated) and carries a monotonic
# sequence, so registry-controlled metadata (latest, hashes, tiers) can no
# longer be silently forged or downgraded.
INDEX_VERSION = 2
MAX_INDEX_ARTIFACTS = 10_000
MAX_INDEX_VERSIONS = 100_000


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Keep an allowlisted HTTPS request from being redirected to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_ref(ref: str) -> tuple[str, str, str | None]:
    """Parse and validate ``namespace/id[@version]``. Raises HubError."""
    if not isinstance(ref, str) or not ref:
        raise HubError("ref must be a non-empty string")
    if "@" in ref:
        path_part, _, version = ref.partition("@")
        if not VERSION_RE.fullmatch(version):
            raise HubError(f"invalid version {version!r} (expected MAJOR.MINOR.PATCH)")
    else:
        path_part, version = ref, None
    namespace, sep, artifact_id = path_part.partition("/")
    if not sep or not artifact_id:
        raise HubError(f"invalid ref {ref!r} (expected namespace/id[@version])")
    if not NAMESPACE_RE.fullmatch(namespace):
        raise HubError(f"invalid namespace {namespace!r}")
    if not ARTIFACT_ID_RE.fullmatch(artifact_id):
        raise HubError(f"invalid artifact id {artifact_id!r}")
    # Syntax only: namespace MEMBERSHIP is enforced against the root-verified
    # namespace registry at install/lint time (see RegistryClient.namespace_registry).
    return namespace, artifact_id, version


def validate_artifact_filename(filename: str) -> str:
    """Validate one portable, registry-local artifact filename."""
    if (
        not isinstance(filename, str)
        or ARTIFACT_FILENAME_RE.fullmatch(filename) is None
        or filename.endswith(".")
        or _WINDOWS_RESERVED_STEM_RE.fullmatch(filename.split(".", 1)[0]) is not None
    ):
        raise HubError(f"illegal artifact filename {filename!r} (expected 1-255 portable ASCII filename characters)")
    return filename


class RegistryClient:
    """Read-only client for a Creed Commons registry (file:// or allowlisted https://)."""

    def __init__(self, base: str = DEFAULT_REGISTRY_URL):
        self._base_path: Path | None = None
        self._base_url: str | None = None

        if not isinstance(base, str) or not base:
            raise HubError("registry location must be a non-empty string")
        parsed = urllib.parse.urlparse(base)
        if parsed.query or parsed.fragment:
            raise HubError("registry location must not contain a query or fragment")
        if parsed.scheme in ("", "file"):
            if parsed.scheme == "file" and parsed.netloc not in ("", "localhost"):
                raise HubError("file registry location must be local")
            raw = urllib.request.url2pathname(parsed.path) if parsed.scheme == "file" else base
            self._base_path = Path(raw).resolve()
            if not self._base_path.is_dir():
                raise HubError(f"registry path {self._base_path} is not a directory")
        elif parsed.scheme == "https":
            try:
                port = parsed.port
            except ValueError as exc:
                raise HubError(f"invalid registry URL port: {exc}") from exc
            if parsed.hostname not in ALLOWED_HTTPS_HOSTS:
                raise HubError(
                    f"https registry host {parsed.hostname!r} is not allowlisted "
                    f"(allowed: {sorted(ALLOWED_HTTPS_HOSTS)})"
                )
            if parsed.username or parsed.password or port not in (None, 443):
                raise HubError("https registry must not contain userinfo or a non-443 port")
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
            target = self._base_path
            for part in rel_path.split("/"):
                target = target / part
                if target.is_symlink():
                    raise HubError(f"registry path {rel_path!r} contains a symbolic link")
            resolved = target.resolve()
            if not resolved.is_relative_to(self._base_path):
                raise HubError(f"registry path {rel_path!r} escapes the registry root")
            if not target.is_file():
                raise NotFoundError(f"registry object not found: {rel_path}")
            try:
                if target.stat().st_size > MAX_FETCH_BYTES:
                    raise HubError(f"registry object {rel_path} exceeds size cap")
                with target.open("rb") as handle:
                    data = handle.read(MAX_FETCH_BYTES + 1)
            except HubError:
                raise
            except OSError as exc:
                raise HubError(f"failed to read registry object {rel_path}: {exc}") from exc
            if len(data) > MAX_FETCH_BYTES:
                raise HubError(f"registry object {rel_path} exceeds size cap")
            return data
        url = f"{self._base_url}/{rel_path}"
        try:
            opener = urllib.request.build_opener(_RejectRedirects())
            with opener.open(url, timeout=30) as resp:  # nosec B310 — scheme/host allowlisted; redirects disabled
                data = resp.read(MAX_FETCH_BYTES + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise NotFoundError(f"registry object not found: {rel_path}") from exc
            raise HubError(f"failed to fetch {url}: {exc}") from exc
        except OSError as exc:
            raise HubError(f"failed to fetch {url}: {exc}") from exc
        if len(data) > MAX_FETCH_BYTES:
            raise HubError(f"registry object {rel_path} exceeds size cap")
        return data

    def namespace_registry(self) -> NamespaceRegistry:
        """The hub's namespace -> publisher-keys binding, verified against the ROOT.

        Fail-closed semantics:
        - registry file ABSENT (genuinely 404/missing): founder-only builtin —
          absence can only reduce what installs, never extend trust;
        - registry file present but unsigned, tampered, or malformed: refuse
          everything (a bad trust document is an attack, not a downgrade);
        - fetch FAILURE that is not a clean 404 (outage, MITM): refuse rather
          than silently downgrade.
        """
        try:
            registry_bytes = self._fetch(REGISTRY_FILENAME)
        except NotFoundError:
            return BUILTIN_REGISTRY
        try:
            sig_bytes = self._fetch(REGISTRY_FILENAME + ".ed25519.sig")
        except NotFoundError:
            sig_bytes = None  # parse_namespace_registry refuses unsigned
        return parse_namespace_registry(registry_bytes, sig_bytes)

    def index(self) -> dict[str, Any]:
        """Load, ROOT-VERIFY, and structurally validate index.json.

        The index decides version resolution, expected hashes, and trust tiers,
        so it must be signed by the pinned root (domain-separated). An unsigned
        or tampered index refuses everything — there is no fallback.
        """
        index_bytes = self._fetch("index.json")
        try:
            sig_bytes: bytes | None = self._fetch("index.json.ed25519.sig")
        except NotFoundError:
            sig_bytes = None  # verify_detached refuses unsigned
        verify_detached(index_bytes, sig_bytes, context=INDEX_CONTEXT, what="registry index")
        try:
            index = loads_strict(index_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise HubError(f"registry index.json is not valid JSON: {exc}") from exc
        if not isinstance(index, dict) or index.get("index_version") != INDEX_VERSION:
            raise HubError("registry index.json has an unsupported format")
        if type(index.get("sequence")) is not int or index["sequence"] < 1:
            raise VerificationError("registry index has no valid monotonic sequence")
        if not isinstance(index.get("artifacts"), dict):
            raise HubError("registry index.json has no artifacts map")
        if len(index["artifacts"]) > MAX_INDEX_ARTIFACTS:
            raise HubError("registry index.json exceeds artifact-count cap")
        version_count = 0
        for ref, record in index["artifacts"].items():
            try:
                namespace, artifact_id, embedded_version = validate_ref(ref)
            except HubError as exc:
                raise HubError(f"registry index contains invalid artifact ref {ref!r}: {exc}") from exc
            if embedded_version is not None:
                raise HubError(f"registry index artifact ref {ref!r} must not include a version")
            if not isinstance(record, dict):
                raise HubError(f"registry index record for {namespace}/{artifact_id} must be an object")
            latest = record.get("latest")
            versions = record.get("versions")
            if not isinstance(latest, str) or VERSION_RE.fullmatch(latest) is None:
                raise HubError(f"registry index record for {ref} has an invalid latest version")
            if not isinstance(versions, dict) or not versions:
                raise HubError(f"registry index record for {ref} has no versions map")
            if latest not in versions:
                raise HubError(f"registry index latest version for {ref} is absent from versions")
            version_count += len(versions)
            if version_count > MAX_INDEX_VERSIONS:
                raise HubError("registry index exceeds total version-count cap")
            for version, metadata in versions.items():
                if not isinstance(version, str) or VERSION_RE.fullmatch(version) is None:
                    raise HubError(f"registry index record for {ref} has invalid version {version!r}")
                if not isinstance(metadata, dict):
                    raise HubError(f"registry index metadata for {ref}@{version} must be an object")
                content_sha256 = metadata.get("content_sha256")
                if not isinstance(content_sha256, str) or _CONTENT_SHA256_RE.fullmatch(content_sha256) is None:
                    raise HubError(f"registry index metadata for {ref}@{version} has an invalid content hash")
                if metadata.get("trust_tier") not in {"signed", "verified"}:
                    raise HubError(f"registry index metadata for {ref}@{version} has an invalid trust tier")
                artifact = metadata.get("artifact")
                if artifact is not None:
                    validate_artifact_filename(artifact)
        return index

    def resolve_version(
        self,
        namespace: str,
        artifact_id: str,
        version: str | None,
        *,
        index: dict[str, Any] | None = None,
    ) -> str:
        """Resolve a possibly-absent version to a concrete one via the index."""
        index = self.index() if index is None else index
        record = index["artifacts"].get(f"{namespace}/{artifact_id}")
        if not isinstance(record, dict):
            raise HubError(f"artifact {namespace}/{artifact_id} not found in registry index")
        resolved = version or record.get("latest")
        if not isinstance(resolved, str) or VERSION_RE.fullmatch(resolved) is None:
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
            if not isinstance(value, str) or pattern.fullmatch(value) is None:
                raise HubError(f"invalid {label} {value!r}")
        return f"namespaces/{namespace}/{artifact_id}/{version}"

    def entry(self, namespace: str, artifact_id: str, version: str) -> dict[str, Any]:
        """Fetch entry.json for one artifact version."""
        rel = f"{self._version_dir(namespace, artifact_id, version)}/entry.json"
        try:
            entry = loads_strict(self._fetch(rel).decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise HubError(f"entry.json for {namespace}/{artifact_id}@{version} is not valid JSON: {exc}") from exc
        if not isinstance(entry, dict):
            raise HubError(f"entry.json for {namespace}/{artifact_id}@{version} must be a JSON object")
        return entry

    def artifact(self, namespace: str, artifact_id: str, version: str, filename: str) -> bytes:
        """Fetch the artifact (or sidecar) bytes for one version. Pure data."""
        validate_artifact_filename(filename)
        return self._fetch(f"{self._version_dir(namespace, artifact_id, version)}/{filename}")
