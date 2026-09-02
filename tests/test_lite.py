"""Tests for VCP-Lite validation and conversion."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vcp.lite import lite_to_csm1, lite_to_token, validate_lite

# Bundled with the package, so the suite is self-contained (was a sibling-repo path).
EXAMPLES_DIR = Path(__file__).parent.parent / "src" / "vcp" / "_examples"


def _load_example(name: str) -> dict:
    with open(EXAMPLES_DIR / name) as f:
        return json.load(f)


class TestValidateLite:
    def test_family_safe_guide(self):
        doc = _load_example("family-safe-guide.vcp-lite.json")
        errors = validate_lite(doc)
        assert errors == [], f"Validation errors: {errors}"

    def test_security_ops(self):
        doc = _load_example("security-ops.vcp-lite.json")
        errors = validate_lite(doc)
        assert errors == [], f"Validation errors: {errors}"

    def test_creative_writing(self):
        doc = _load_example("creative-writing.vcp-lite.json")
        errors = validate_lite(doc)
        assert errors == [], f"Validation errors: {errors}"

    def test_custom_org(self):
        doc = _load_example("custom-org.vcp-lite.json")
        errors = validate_lite(doc)
        assert errors == [], f"Validation errors: {errors}"

    def test_missing_version(self):
        doc = {
            "identity": {"domain": "a", "approach": "b", "role": "c"},
            "persona": "nanny",
            "adherence": 5,
            "scopes": ["F"],
        }
        errors = validate_lite(doc)
        assert any("vcp_version" in e for e in errors)

    def test_missing_identity(self):
        doc = {"vcp_version": "lite-1.0", "persona": "nanny", "adherence": 5, "scopes": ["F"]}
        errors = validate_lite(doc)
        assert any("identity" in e for e in errors)

    def test_invalid_persona(self):
        doc = {
            "vcp_version": "lite-1.0",
            "identity": {"domain": "a", "approach": "b", "role": "c"},
            "persona": "wizard",
            "adherence": 5,
            "scopes": ["F"],
        }
        errors = validate_lite(doc)
        assert any("persona" in e for e in errors)

    def test_adherence_out_of_range(self):
        doc = {
            "vcp_version": "lite-1.0",
            "identity": {"domain": "a", "approach": "b", "role": "c"},
            "persona": "nanny",
            "adherence": 7,
            "scopes": ["F"],
        }
        errors = validate_lite(doc)
        assert any("adherence" in e for e in errors)

    def test_empty_scopes(self):
        doc = {
            "vcp_version": "lite-1.0",
            "identity": {"domain": "a", "approach": "b", "role": "c"},
            "persona": "nanny",
            "adherence": 5,
            "scopes": [],
        }
        errors = validate_lite(doc)
        assert any("scopes" in e for e in errors)

    def test_invalid_scope_code(self):
        doc = {
            "vcp_version": "lite-1.0",
            "identity": {"domain": "a", "approach": "b", "role": "c"},
            "persona": "nanny",
            "adherence": 5,
            "scopes": ["Q"],  # Q is not a valid scope character
        }
        errors = validate_lite(doc)
        assert any("Invalid scope" in e for e in errors)

    def test_scope_conflict_family_adult(self):
        doc = {
            "vcp_version": "lite-1.0",
            "identity": {"domain": "a", "approach": "b", "role": "c"},
            "persona": "nanny",
            "adherence": 5,
            "scopes": ["F", "A"],
        }
        errors = validate_lite(doc)
        assert any("conflict" in e.lower() for e in errors)

    def test_custom_requires_namespace(self):
        doc = {
            "vcp_version": "lite-1.0",
            "identity": {"domain": "a", "approach": "b", "role": "c"},
            "persona": "custom",
            "adherence": 3,
            "scopes": ["W"],
        }
        errors = validate_lite(doc)
        assert any("namespace" in e for e in errors)

    def test_custom_with_namespace_valid(self):
        doc = {
            "vcp_version": "lite-1.0",
            "identity": {"domain": "a", "approach": "b", "role": "c"},
            "persona": "custom",
            "adherence": 3,
            "scopes": ["W"],
            "namespace": "ACME",
        }
        errors = validate_lite(doc)
        assert errors == []

    def test_invalid_segment_format(self):
        doc = {
            "vcp_version": "lite-1.0",
            "identity": {"domain": "Family", "approach": "b", "role": "c"},
            "persona": "nanny",
            "adherence": 5,
            "scopes": ["F"],
        }
        errors = validate_lite(doc)
        assert any("domain" in e for e in errors)

    def test_invalid_adaptation_hint(self):
        doc = {
            "vcp_version": "lite-1.0",
            "identity": {"domain": "a", "approach": "b", "role": "c"},
            "persona": "nanny",
            "adherence": 5,
            "scopes": ["F"],
            "adaptation_hints": {"formality": "super_formal"},
        }
        errors = validate_lite(doc)
        assert any("formality" in e for e in errors)

    def test_minimal_valid(self):
        doc = {
            "vcp_version": "lite-1.0",
            "identity": {"domain": "a", "approach": "b", "role": "c"},
            "persona": "nanny",
            "adherence": 0,
            "scopes": ["F"],
        }
        errors = validate_lite(doc)
        assert errors == []


class TestLiteToCSM1:
    def test_family_safe_guide(self):
        doc = _load_example("family-safe-guide.vcp-lite.json")
        assert lite_to_csm1(doc) == "N5+E+F"

    def test_security_ops(self):
        doc = _load_example("security-ops.vcp-lite.json")
        assert lite_to_csm1(doc) == "Z4+P+T+W:SEC"

    def test_creative_writing(self):
        doc = _load_example("creative-writing.vcp-lite.json")
        assert lite_to_csm1(doc) == "M2+A"

    def test_custom_org(self):
        doc = _load_example("custom-org.vcp-lite.json")
        assert lite_to_csm1(doc) == "C3+O+W:ACME"

    def test_missing_persona_raises(self):
        with pytest.raises(ValueError):
            lite_to_csm1({})


class TestLiteToToken:
    def test_family_safe_guide(self):
        doc = _load_example("family-safe-guide.vcp-lite.json")
        assert lite_to_token(doc) == "family.safe.guide"

    def test_security_ops(self):
        doc = _load_example("security-ops.vcp-lite.json")
        assert lite_to_token(doc) == "enterprise.secure.guardian"

    def test_creative_writing(self):
        doc = _load_example("creative-writing.vcp-lite.json")
        assert lite_to_token(doc) == "creative.open.collaborator"

    def test_missing_identity_raises(self):
        with pytest.raises(ValueError):
            lite_to_token({})
