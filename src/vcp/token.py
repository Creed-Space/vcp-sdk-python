"""VCP/I Token parsing and validation (VCP 2.0).

Token format (ABNF from VCP/I v2.0 spec):
    canonical-token = segment *("." segment) ["@" version]
    segment         = 1*32(LALPHA / DIGIT / "-")
    version         = semver / "latest" / "canary"

    uvc-token       = token-path ["@" version] [":" namespace-suffix]
    token-path      = segment 2*9("." segment)
    namespace-suffix = UALPHA *(UALPHA / DIGIT)

Minimum 3 segments, maximum 10. The first segment is the domain,
the last is the role, and everything in between defines the path.

Examples:
    family.safe.guide                      (3 segments)
    family.safe.guide@1.2.0
    company.acme.legal.compliance:SEC
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

_CREED_SCHEME = "creed://"
_VCP_SCHEME = "vcp://"
MAX_TOKEN_INPUT_LENGTH = 4096
_ISSUER_PATTERN = re.compile(
    r"(?=.{1,253}\Z)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\Z",
    re.IGNORECASE,
)


def _normalize_issuer(issuer: str) -> str:
    if not isinstance(issuer, str) or _ISSUER_PATTERN.fullmatch(issuer) is None:
        raise ValueError("VCP URI issuer must be a valid ASCII domain name")
    return issuer.lower()


def canonicalize_token(raw: str) -> str:
    """Canonicalize a raw token string per VCP/I v2.0 Section 2.2.3.

    Steps: NFKC normalize, separate namespace (stays uppercase),
    lowercase path, strip whitespace, collapse dots, normalize version.
    """
    if not isinstance(raw, str):
        raise ValueError("Token must be a string")
    if len(raw) > MAX_TOKEN_INPUT_LENGTH:
        raise ValueError(f"Token input exceeds maximum length {MAX_TOKEN_INPUT_LENGTH}")
    token = unicodedata.normalize("NFKC", raw)

    namespace_suffix = ""
    if ":" in token:
        token, namespace_suffix = token.rsplit(":", 1)
        namespace_suffix = namespace_suffix.strip().upper()

    token = token.lower().strip()
    token = re.sub(r"\s+", "", token)
    token = re.sub(r"\.+", ".", token)
    token = token.strip(".")

    if "@" in token:
        base, version = token.rsplit("@", 1)
        version = _normalize_version(version)
        token = f"{base}@{version}"

    if namespace_suffix:
        token = f"{token}:{namespace_suffix}"
    return Token.parse(token).full


def _normalize_version(version: str) -> str:
    """Normalize a version string per VCP/I v2.0 spec."""
    if version in ("latest", "canary"):
        return version
    prefix = ""
    if version.startswith(("^", "~")):
        prefix = version[0]
        version = version[1:]
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(-.*)?$", version)
    if not match:
        return prefix + version
    major, minor, patch, prerelease = match.groups()
    result = f"{int(major)}.{int(minor)}.{int(patch)}"
    if prerelease:
        result += prerelease.lower()
    return prefix + result


def tokens_equal(token1: str, token2: str) -> bool:
    """Check if two token strings are semantically equal."""
    return canonicalize_token(token1) == canonicalize_token(token2)


def uri_to_canonical(uri: str) -> str:
    """Convert a ``creed://`` or ``vcp://`` URI to canonical token form."""
    if not isinstance(uri, str):
        raise ValueError("VCP URI must be a string")
    if len(uri) > MAX_TOKEN_INPUT_LENGTH:
        raise ValueError(f"VCP URI exceeds maximum length {MAX_TOKEN_INPUT_LENGTH}")
    if uri.startswith(_CREED_SCHEME):
        rest = uri[len(_CREED_SCHEME) :]
        parts = rest.split("/", 1)
        if len(parts) < 2 or not parts[0] or not parts[1]:
            raise ValueError(f"URI missing issuer or path component: {uri}")
        _normalize_issuer(parts[0])
        path = parts[1]
    elif uri.startswith(_VCP_SCHEME):
        path = uri[len(_VCP_SCHEME) :]
        if not path or "/" in path:
            raise ValueError(f"vcp:// URI requires a dotted token path: {uri}")
    else:
        raise ValueError(f"Not a VCP URI (expected creed:// or vcp:// scheme): {uri}")

    if ":" in path:
        raise ValueError("VCP URI path cannot contain a namespace suffix")
    version: str | None = None
    if "@" in path:
        path, version = path.rsplit("@", 1)

    token = path.replace("/", ".")
    if version:
        token += f"@{version}"
    canonical = canonicalize_token(token)
    return Token.parse(canonical).full


@dataclass(frozen=True)
class Token:
    """VCP/I Token with full validation per VCP 2.0 ABNF grammar.

    Supports variable-length tokens with 3-10 segments.
    Domain = first segment, role = last, approach = second-to-last.
    """

    segments: tuple[str, ...] = field(default_factory=tuple)
    version: str | None = None
    namespace: str | None = None

    SEGMENT_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")
    SEMVER_PATTERN = re.compile(r"^[\^~]?[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}(-[a-zA-Z0-9.-]+)?$")
    VERSION_PATTERN = re.compile(r"^(?:[\^~]?[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}(?:-[a-zA-Z0-9.-]+)?|latest|canary)$")
    NAMESPACE_PATTERN = re.compile(r"^[A-Z][A-Z0-9]{0,31}$")
    TOKEN_PATTERN = re.compile(
        r"^(?P<path>[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*){2,})"
        r"(?:@(?P<version>[\^~]?[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}"
        r"(?:-[a-zA-Z0-9.-]+)?|latest|canary))?"
        r"(?::(?P<namespace>[A-Z][A-Z0-9]{0,31}))?$"
    )

    MAX_LENGTH = 256
    MAX_SEGMENT = 32
    MIN_SEGMENTS = 3
    MAX_SEGMENTS = 10

    def __post_init__(self) -> None:
        if not isinstance(self.segments, tuple):
            raise ValueError("Token segments must be a tuple")
        if len(self.segments) < self.MIN_SEGMENTS:
            raise ValueError(f"Token requires at least {self.MIN_SEGMENTS} segments, got {len(self.segments)}")
        if len(self.segments) > self.MAX_SEGMENTS:
            raise ValueError(f"Token exceeds maximum {self.MAX_SEGMENTS} segments, got {len(self.segments)}")
        for i, segment in enumerate(self.segments):
            if not isinstance(segment, str):
                raise ValueError(f"Segment {i + 1} has invalid format: {segment!r}")
            if len(segment) > self.MAX_SEGMENT:
                raise ValueError(f"Segment {i + 1} exceeds max length {self.MAX_SEGMENT}: {segment}")
            if self.SEGMENT_PATTERN.fullmatch(segment) is None:
                raise ValueError(f"Segment {i + 1} has invalid format: {segment!r}")
        if self.version is not None:
            if not isinstance(self.version, str) or len(self.version) > self.MAX_LENGTH:
                raise ValueError(f"Invalid version format: {self.version}")
            if self.VERSION_PATTERN.fullmatch(self.version) is None:
                raise ValueError(f"Invalid version format: {self.version}")
            object.__setattr__(self, "version", _normalize_version(self.version))
        if self.namespace is not None:
            if not isinstance(self.namespace, str) or len(self.namespace) > 32:
                raise ValueError(f"Invalid namespace format: {self.namespace}")
            if self.NAMESPACE_PATTERN.fullmatch(self.namespace) is None:
                raise ValueError(f"Invalid namespace format: {self.namespace}")
        if len(self.full) > self.MAX_LENGTH:
            raise ValueError(f"Token exceeds max length {self.MAX_LENGTH}: {len(self.full)}")

    @classmethod
    def parse(cls, raw: str) -> Token:
        """Parse and validate a VCP/I token string.

        Accepts canonical form, creed:// URIs, and vcp:// URIs.
        """
        if not isinstance(raw, str) or not raw:
            raise ValueError("Token cannot be empty")
        if len(raw) > MAX_TOKEN_INPUT_LENGTH:
            raise ValueError(f"Token input exceeds maximum length {MAX_TOKEN_INPUT_LENGTH}")

        if raw.startswith((_CREED_SCHEME, _VCP_SCHEME)):
            raw = uri_to_canonical(raw)

        if len(raw) > cls.MAX_LENGTH:
            raise ValueError(f"Token exceeds max length {cls.MAX_LENGTH}: {len(raw)}")

        match = cls.TOKEN_PATTERN.fullmatch(raw)
        if not match:
            raise ValueError(f"Invalid VCP/I token format: {raw}")

        groups = match.groupdict()
        path = groups["path"]
        segments = tuple(path.split("."))

        if len(segments) < cls.MIN_SEGMENTS:
            raise ValueError(f"Token requires at least {cls.MIN_SEGMENTS} segments, got {len(segments)}")

        for i, seg in enumerate(segments):
            if len(seg) > cls.MAX_SEGMENT:
                raise ValueError(f"Segment {i + 1} exceeds max length {cls.MAX_SEGMENT}: {seg}")

        version = groups.get("version")
        if version:
            version = _normalize_version(version)

        return cls(
            segments=segments,
            version=version,
            namespace=groups.get("namespace"),
        )

    @property
    def domain(self) -> str:
        """First segment."""
        return self.segments[0]

    @property
    def approach(self) -> str:
        """Second-to-last segment."""
        return self.segments[-2]

    @property
    def role(self) -> str:
        """Last segment."""
        return self.segments[-1]

    @property
    def path(self) -> tuple[str, ...]:
        """Middle segments (empty for 3-segment tokens)."""
        if len(self.segments) <= 3:
            return ()
        return self.segments[1:-2]

    @property
    def canonical(self) -> str:
        """Canonical form: segments joined, no version/namespace."""
        return ".".join(self.segments)

    @property
    def full(self) -> str:
        """Full form with version and namespace."""
        result = self.canonical
        if self.version:
            result += f"@{self.version}"
        if self.namespace:
            result += f":{self.namespace}"
        return result

    @property
    def depth(self) -> int:
        """Number of segments."""
        return len(self.segments)

    def to_uri(self, registry: str = "creed.space") -> str:
        """Convert to creed:// URI."""
        registry = _normalize_issuer(registry)
        version_part = f"@{self.version}" if self.version else ""
        return f"creed://{registry}/{self.canonical}{version_part}"

    @classmethod
    def from_uri(cls, uri: str) -> Token:
        """Parse a creed:// or vcp:// URI into a Token."""
        canonical = uri_to_canonical(uri)
        return cls.parse(canonical)

    def with_version(self, version: str) -> Token:
        """Return new token with specified version."""
        if not isinstance(version, str) or len(version) > self.MAX_LENGTH:
            raise ValueError(f"Invalid version format: {version}")
        if self.VERSION_PATTERN.fullmatch(version) is None:
            raise ValueError(f"Invalid version format: {version}")
        return Token(
            segments=self.segments,
            version=_normalize_version(version),
            namespace=self.namespace,
        )

    def with_namespace(self, namespace: str) -> Token:
        """Return new token with specified namespace."""
        if not isinstance(namespace, str) or len(namespace) > 32:
            raise ValueError(f"Invalid namespace format: {namespace}")
        if self.NAMESPACE_PATTERN.fullmatch(namespace) is None:
            raise ValueError(f"Invalid namespace format: {namespace}")
        return Token(
            segments=self.segments,
            version=self.version,
            namespace=namespace,
        )

    def matches_pattern(self, pattern: str) -> bool:
        """Check if token matches a glob-like pattern (* and **)."""
        if not isinstance(pattern, str) or pattern.count("**") > 1:
            return False
        parts = pattern.split(".")

        if "**" in parts:
            idx = parts.index("**")
            prefix = parts[:idx]
            suffix = parts[idx + 1 :]
            if len(self.segments) < len(prefix) + len(suffix):
                return False
            for i, p in enumerate(prefix):
                if p != "*" and p != self.segments[i]:
                    return False
            for i, p in enumerate(suffix):
                if p != "*" and p != self.segments[-(len(suffix) - i)]:
                    return False
            return True

        if len(parts) != len(self.segments):
            return False
        return all(pat == "*" or pat == seg for seg, pat in zip(self.segments, parts, strict=True))

    def is_ancestor_of(self, other: Token) -> bool:
        """Check if this token is a prefix of another."""
        if not isinstance(other, Token):
            return False
        if len(self.segments) >= len(other.segments):
            return False
        return other.segments[: len(self.segments)] == self.segments

    def __str__(self) -> str:
        return self.full

    def __repr__(self) -> str:
        return f"Token({self.full!r})"

    def __hash__(self) -> int:
        return hash((self.segments, self.version, self.namespace))
