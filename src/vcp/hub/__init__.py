"""Creed Commons hub client — signed value-artifact distribution.

The unit of distribution is a SIGNED DATA ARTIFACT (constitution, creed, detector
config), never executable code. Installing an artifact is a signature-verification
decision, not a code-execution one: `vcp install` verifies an Ed25519 signature
against a pinned publisher-key allowlist, a content sha256, and the registry-entry
schema before writing anything — and nothing in the install path imports, evals,
or executes artifact content.

Trust tiers: ``signed`` means signature + hash + schema verified; it does NOT vouch
for the semantics of the artifact. ``verified`` (lint + red-team + Creed Space
counter-signature) is the semantic gate and is not yet issued.
"""

from .errors import HubError, VerificationError
from .keys import PINNED_PUBLISHER_KEYS
from .verify import ARTIFACT_SIG_VERSION, VerifiedArtifact, artifact_message_context, verify_artifact_bytes

__all__ = [
    "HubError",
    "VerificationError",
    "PINNED_PUBLISHER_KEYS",
    "ARTIFACT_SIG_VERSION",
    "VerifiedArtifact",
    "artifact_message_context",
    "verify_artifact_bytes",
]
