"""Namespace registry — delegated publisher trust for community namespaces.

The client's root of trust never changes: it is the pinned Creed Space key
allowlist shipped in :mod:`vcp.hub.keys`. Community publishing works by
DELEGATION, not by expanding that root:

- ``namespace_registry.json`` at the hub root binds each namespace to its
  publisher's Ed25519 public keys.
- That file ships with a ``namespace_registry.json.ed25519.sig`` sidecar signed
  by the pinned ROOT key. A registry that fails root verification is refused
  outright — the registry still cannot vouch for itself (Threat T3).
- An artifact in namespace X must verify against a key REGISTERED TO X. Keys do
  not cross namespaces, so a community publisher can neither claim Creed Space's
  key ids nor sign into someone else's namespace.
- Removing a key from the signed registry revokes it for future installs.

Name policy (Threat T5): community namespaces are 3-63 chars of
``[a-z][a-z0-9-]``, must not be reserved, and must not be confusable with any
existing or reserved name after normalization (case/separator/homoglyph
folding). ``creed-space`` is the founder namespace and predates the length rule.

Governance (registration review, moderation, verified tier, revocation) is
documented in the vcp-hub repo's GOVERNANCE.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .._json import loads_strict
from .errors import VerificationError
from .keys import PINNED_PUBLISHER_KEYS
from .verify import MAX_KEY_ID_LENGTH, MAX_SIGNATURE_SIDECAR_BYTES, NS_REGISTRY_CONTEXT, verify_detached

REGISTRY_FILENAME = "namespace_registry.json"
REGISTRY_VERSION = 1
MAX_NAMESPACE_REGISTRY_BYTES = 8 * 1024 * 1024
MAX_REGISTERED_NAMESPACES = 10_000
MAX_KEYS_PER_NAMESPACE = 100
MAX_TOTAL_PUBLISHER_KEYS = 10_000
MAX_PEM_LENGTH = 4_096

# Canonical namespace syntax (single source of truth; registry.py re-exports).
NAMESPACE_RE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")

# Prefixes only the founder may use: reserves the whole `creed*` / `vcp*`
# brand space against squats the literal list below cannot enumerate.
FOUNDER_RESERVED_PREFIXES = ("creed", "vcp")

# The founder namespace, trusted via the pinned root keys even when a hub has
# no namespace_registry.json yet (bootstrap / pre-community hubs).
FOUNDER_NAMESPACE = "creed-space"

# Names nobody may register: infrastructure terms, trust-tier terms, and the
# founder's name. Confusable variants are additionally caught by normalization.
RESERVED_NAMESPACES = frozenset(
    {
        "creed-space",
        "creedspace",
        "creed_space",
        "creed",
        "creed-space-official",
        "vcp",
        "vcp-hub",
        "value-context-protocol",
        "anthropic",
        "official",
        "admin",
        "moderator",
        "registry",
        "hub",
        "namespace",
        "namespaces",
        "verified",
        "signed",
        "trusted",
        "system",
    }
)

COMMUNITY_NAME_MIN = 3
COMMUNITY_NAME_MAX = 63

# Homoglyph fold for confusable detection. Deliberately aggressive on the
# cheap side: false positives cost a publisher a nicer name; false negatives
# enable squats. `1`, `l`, and `i` all fold together (adm1n ≈ admin class).
_HOMOGLYPHS = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "9": "g",
        "i": "l",
    }
)


def normalize_namespace(name: str) -> str:
    """Fold a namespace to its confusable-comparison form."""
    if not isinstance(name, str) or len(name) > 64:
        raise VerificationError("namespace must be a string of at most 64 characters")
    return name.lower().replace("-", "").replace("_", "").translate(_HOMOGLYPHS)


def check_community_name(name: str, existing: set[str]) -> None:
    """Enforce the registration name policy. Raises VerificationError."""
    if not isinstance(name, str) or NAMESPACE_RE.fullmatch(name) is None:
        raise VerificationError(f"namespace {name!r} must match [a-z][a-z0-9-]* (lowercase ASCII only)")
    if not (COMMUNITY_NAME_MIN <= len(name) <= COMMUNITY_NAME_MAX):
        raise VerificationError(f"namespace {name!r} must be {COMMUNITY_NAME_MIN}-{COMMUNITY_NAME_MAX} characters")
    if name in RESERVED_NAMESPACES:
        raise VerificationError(f"namespace {name!r} is reserved")
    for prefix in FOUNDER_RESERVED_PREFIXES:
        if name.startswith(prefix):
            raise VerificationError(
                f"namespace {name!r} is reserved: the {prefix}* prefix belongs to the founder namespace"
            )
    folded = normalize_namespace(name)
    for taken in existing | RESERVED_NAMESPACES:
        if taken != name and normalize_namespace(taken) == folded:
            raise VerificationError(f"namespace {name!r} is confusable with {taken!r} after normalization")
    for prefix in FOUNDER_RESERVED_PREFIXES:
        if folded.startswith(normalize_namespace(prefix)):
            raise VerificationError(
                f"namespace {name!r} folds to {folded!r}, which squats the reserved {prefix}* prefix"
            )


@dataclass(frozen=True)
class NamespaceRegistry:
    """A root-verified namespace -> publisher-keys binding.

    ``sequence`` increases monotonically with every re-signing ceremony;
    clients persist the highest sequence seen (in vcp.lock) and refuse a
    lower one, so a validly-signed but STALE registry cannot re-admit a
    revoked key after first contact (anti-rollback).
    """

    namespaces: dict[str, dict[str, str]]  # namespace -> {key_id: PEM}
    sequence: int = 0  # 0 = builtin/bootstrap (no signed document)

    def is_registered(self, namespace: str) -> bool:
        return isinstance(namespace, str) and len(namespace) <= 64 and namespace in self.namespaces

    def publisher_keys(self, namespace: str) -> dict[str, str]:
        """Keys trusted to sign artifacts in ``namespace``. Refuses unknowns."""
        if not isinstance(namespace, str) or len(namespace) > 64:
            raise VerificationError("namespace must be a string of at most 64 characters")
        keys = self.namespaces.get(namespace)
        if not keys:
            raise VerificationError(
                f"namespace {namespace!r} is not registered in the namespace registry; "
                "see GOVERNANCE.md in the vcp-hub repo for how to register one"
            )
        return keys

    @property
    def names(self) -> set[str]:
        return set(self.namespaces)


#: Registry used when a hub has no namespace_registry.json: founder-only,
#: rooted directly in the pinned allowlist. Deliberately aliases (not copies)
#: PINNED_PUBLISHER_KEYS so there is exactly one root-key source of truth.
BUILTIN_REGISTRY = NamespaceRegistry(namespaces={FOUNDER_NAMESPACE: PINNED_PUBLISHER_KEYS})


def load_hub_namespace_registry(hub_root) -> NamespaceRegistry:
    """Load and root-verify a hub tree's namespace registry from disk.

    Absent file -> founder-only builtin. Present but unsigned/tampered/malformed
    -> refuse (raises VerificationError); never partially accept.
    """
    from pathlib import Path

    root = Path(hub_root).resolve()
    registry_path = root / REGISTRY_FILENAME
    if registry_path.is_symlink():
        raise VerificationError("namespace registry must not be a symbolic link")
    if not registry_path.is_file():
        return BUILTIN_REGISTRY
    sig_path = root / (REGISTRY_FILENAME + ".ed25519.sig")

    def read_bounded(path: Path, cap: int, description: str) -> bytes:
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

    return parse_namespace_registry(
        read_bounded(registry_path, MAX_NAMESPACE_REGISTRY_BYTES, "namespace registry"),
        read_bounded(sig_path, MAX_SIGNATURE_SIDECAR_BYTES, "namespace registry signature")
        if sig_path.is_file()
        else None,
    )


def _pinned_pem_bodies() -> set[str]:
    return {pem.strip() for pem in PINNED_PUBLISHER_KEYS.values()}


def parse_namespace_registry(registry_bytes: bytes, sig_bytes: bytes | None) -> NamespaceRegistry:
    """Verify (against the PINNED ROOT, domain-separated) and parse a registry.

    Fail closed: a missing/invalid signature, malformed document, policy-violating
    name, root-key collision, or malformed key entry refuses the WHOLE registry —
    there is no partial acceptance of a tampered trust document.
    """
    if not isinstance(registry_bytes, bytes):
        raise VerificationError("namespace registry must be bytes")
    if len(registry_bytes) > MAX_NAMESPACE_REGISTRY_BYTES:
        raise VerificationError("namespace registry exceeds size cap")
    # Root verification first; content is untrusted bytes until this passes.
    # Domain-separated: an artifact signature can never pose as a registry.
    verify_detached(
        registry_bytes,
        sig_bytes,
        context=NS_REGISTRY_CONTEXT,
        what="namespace registry",
    )

    try:
        doc = loads_strict(registry_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise VerificationError(f"namespace registry is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("registry_version") != REGISTRY_VERSION:
        raise VerificationError("namespace registry has an unsupported format")
    sequence = doc.get("sequence")
    if type(sequence) is not int or sequence < 1:
        raise VerificationError("namespace registry has no valid monotonic sequence")
    raw = doc.get("namespaces")
    if not isinstance(raw, dict) or not raw:
        raise VerificationError("namespace registry has no namespaces map")
    if len(raw) > MAX_REGISTERED_NAMESPACES:
        raise VerificationError(f"namespace registry exceeds namespace-count cap of {MAX_REGISTERED_NAMESPACES}")

    namespaces: dict[str, dict[str, str]] = {}
    root_pems = _pinned_pem_bodies()
    folded_names: dict[str, str] = {}
    total_keys = 0
    for name, record in raw.items():
        if name != FOUNDER_NAMESPACE:
            check_community_name(name, existing=set())
            folded = normalize_namespace(name)
            if folded in folded_names:
                raise VerificationError(
                    f"namespace {name!r} is confusable with {folded_names[folded]!r} after normalization"
                )
            folded_names[folded] = name
        if not isinstance(record, dict):
            raise VerificationError(f"namespace {name!r}: record must be an object")
        keys = record.get("keys")
        if not isinstance(keys, dict) or not keys:
            raise VerificationError(f"namespace {name!r}: no publisher keys registered")
        if len(keys) > MAX_KEYS_PER_NAMESPACE:
            raise VerificationError(f"namespace {name!r}: exceeds publisher-key cap of {MAX_KEYS_PER_NAMESPACE}")
        total_keys += len(keys)
        if total_keys > MAX_TOTAL_PUBLISHER_KEYS:
            raise VerificationError(f"namespace registry exceeds total publisher-key cap of {MAX_TOTAL_PUBLISHER_KEYS}")
        for key_id, pem in keys.items():
            if (
                not isinstance(key_id, str)
                or not key_id
                or len(key_id) > MAX_KEY_ID_LENGTH
                or not isinstance(pem, str)
                or len(pem) > MAX_PEM_LENGTH
                or "BEGIN PUBLIC KEY" not in pem
            ):
                raise VerificationError(f"namespace {name!r}: key {key_id!r} is not a PEM public key")
            if name != FOUNDER_NAMESPACE and (key_id in PINNED_PUBLISHER_KEYS or pem.strip() in root_pems):
                raise VerificationError(
                    f"namespace {name!r}: key {key_id!r} collides with a pinned ROOT key id or key; "
                    "community namespaces can never claim root identity"
                )
        namespaces[name] = dict(keys)

    if FOUNDER_NAMESPACE not in namespaces:
        raise VerificationError(f"namespace registry is missing the founder namespace {FOUNDER_NAMESPACE!r}")
    return NamespaceRegistry(namespaces=namespaces, sequence=sequence)
