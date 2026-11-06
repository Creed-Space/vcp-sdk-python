# Changelog

All notable changes to the `vcp` Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-11-06

### Security

Fixes from the 2026-11-05 Claude Security scan. Several change the signing and verification contract, so the next release is 0.9.0 (a pre-1.0 breaking change takes a minor bump), and the hub must be re-signed in the order below.

- **Breaking:** `verify_artifact_bytes` takes a required `ref` keyword. Artifact signatures (sidecar version 2) are domain-separated and bound to the artifact's `namespace/id@version`, so a root signature made for another purpose (an index, a namespace registry, a counter-signature) or for another artifact no longer verifies (F41). A v2 sidecar signs `artifact_message_context(ref) + content` and names its `ref`. Version-1 (content-only) sidecars verify only for the five artifacts already shipped, through `LEGACY_UNBOUND_ARTIFACT_PINS`, which match on exact ref and hash; publishing anything else needs a v2 sidecar.
- Hub lint, `vcp publish`, `vcp install` and `vcp verify` reject an artifact whose signature is not bound to the ref it sits under, so signed bytes and their sidecar copied to another id or version no longer pass (F26).
- **Breaking for hub operators:** every client refuses a registry index without a root-signed `issued_at`, or one older than 30 days (`DEFAULT_MAX_INDEX_AGE`; set per client with `RegistryClient(max_index_age=...)`). An optional signed `expires_at` is honoured. This applies to `vcp search`, `vcp install` and `vcp verify --registry`, and to any third-party hub. The currently shipped undated index is accepted only through `LEGACY_UNDATED_INDEX_PINS`, pinned to its exact hash. `vcp build-index` carries `issued_at` and `expires_at` over from the existing index but never stamps them; the signing ceremony must (F45). Strict lint (the release and hub-CI posture) applies the same freshness check, so hub CI fails on an index clients would refuse.
- `vcp verify --registry` now records the index and namespace-registry sequences it accepted, so it rewrites `vcp.lock` (it was read-only before). Once a client has seen a revocation it refuses an older index, even if that verify run fails (F45).
- Published versions stay immutable on the client: `vcp install` refuses a registry that serves different bytes for a version `vcp.lock` already pinned, and `vcp publish` refuses a differently named artifact file for an existing version with an "immutable" error.
- `vcp search`, `vcp namespaces`, `vcp lint`, `vcp build-index` and CLI error output escape control and format characters in registry-supplied text, and entry validation (lint, publish, install) rejects them in `name` and `description` (F56).
- New: `vcp publish --signature SIDECAR` and `publish(signature_path=...)` take a ref-bound sidecar stored outside the artifact's directory; the hub stores it as `<artifact>.ed25519.sig`.

### Release order (maintainers)

1. Tag and publish this SDK as 0.9.0. vcp-hub CI installs the SDK from this repository, and an older `vcp build-index` would drop `issued_at`.
2. Re-sign the five shipped artifacts as version-2 sidecars (Rewind's `scripts/sign_hub_artifact.py`), then rebuild and root-sign `vcp-hub/index.json` (`vcp build-index`, then Rewind's `scripts/hub_release.py`). `hub_release.py` stamps a fresh `issued_at` before root-signing and checks the result as a client would; an undated index at a new sequence is refused by every client, so don't sign the index any other way. Ship `vcp-hub/.github/workflows/ci.yml` and `.github/scripts/check_published_immutability.py` in the same vcp-hub commit.
3. In a later SDK release, once the re-signed hub is live, empty `LEGACY_UNBOUND_ARTIFACT_PINS` and `LEGACY_UNDATED_INDEX_PINS`.
4. Re-sign the index at least every 30 days, or every client refuses the hub.
