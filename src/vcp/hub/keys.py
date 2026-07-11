"""Pinned publisher-key allowlist for Creed Commons signature verification.

These Ed25519 public keys ship WITH the client, deliberately not fetched from the
registry — a registry that could supply its own trust root could vouch for its own
forgeries (Threat T3). Signatures from any key id not in this allowlist are refused.

The ``keys/`` directory published in the vcp-hub repo is for human display only;
it is never used as a trust root.

Key provenance: exported from the Creed Space signing infrastructure
(``constitution-signer`` primary + backup) on 2026-07-10.
"""

from __future__ import annotations

# key_id -> PEM-encoded Ed25519 public key (SubjectPublicKeyInfo)
PINNED_PUBLISHER_KEYS: dict[str, str] = {
    "constitution-signer": (
        "-----BEGIN PUBLIC KEY-----\n"
        "MCowBQYDK2VwAyEAdWqwlUdtvgY0j9sop2iDzK2pVy4hBs3/evV1vJhMs4U=\n"
        "-----END PUBLIC KEY-----\n"
    ),
    "constitution-signer-backup": (
        "-----BEGIN PUBLIC KEY-----\n"
        "MCowBQYDK2VwAyEA7cdtWi44PuPk3sS6nAhl0wKdtE6JZm0yH9jk0iM5RJA=\n"
        "-----END PUBLIC KEY-----\n"
    ),
}
