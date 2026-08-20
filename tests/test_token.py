"""Tests for VCP/I token parsing and validation."""

import sys
from pathlib import Path

import pytest

# Add src to path for standalone testing
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vcp.token import Token, canonicalize_token, tokens_equal, uri_to_canonical


class TestCanonicalize:
    def test_basic(self):
        assert canonicalize_token("Family.Safe.Guide") == "family.safe.guide"

    def test_whitespace(self):
        assert canonicalize_token("  family . safe . guide  ") == "family.safe.guide"

    def test_consecutive_dots(self):
        assert canonicalize_token("family..safe...guide") == "family.safe.guide"

    def test_version_preserved(self):
        assert canonicalize_token("family.safe.guide@1.2.3") == "family.safe.guide@1.2.3"

    def test_version_alias(self):
        assert canonicalize_token("family.safe.guide@LATEST") == "family.safe.guide@latest"

    def test_namespace_uppercase(self):
        assert canonicalize_token("family.safe.guide:sec") == "family.safe.guide:SEC"

    def test_version_and_namespace(self):
        result = canonicalize_token("Family.Safe.Guide@1.0.0:sec")
        assert result == "family.safe.guide@1.0.0:SEC"

    def test_leading_zeros_stripped(self):
        assert canonicalize_token("a.b.c@01.02.03") == "a.b.c@1.2.3"


class TestTokensEqual:
    def test_case_insensitive(self):
        assert tokens_equal("Family.Safe.Guide", "family.safe.guide")

    def test_whitespace_insensitive(self):
        assert tokens_equal("family.safe.guide", "  family . safe . guide  ")

    def test_different_tokens(self):
        assert not tokens_equal("family.safe.guide", "company.strict.guardian")


class TestUriToCanonical:
    def test_creed_uri(self):
        assert uri_to_canonical("creed://creed.space/family.safe.guide") == "family.safe.guide"

    def test_vcp_uri(self):
        assert uri_to_canonical("vcp://family.safe.guide") == "family.safe.guide"

    def test_uri_with_version(self):
        result = uri_to_canonical("creed://creed.space/family.safe.guide@1.0.0")
        assert result == "family.safe.guide@1.0.0"

    def test_uri_with_slashes(self):
        result = uri_to_canonical("creed://creed.space/family/safe/guide")
        assert result == "family.safe.guide"

    def test_invalid_scheme(self):
        with pytest.raises(ValueError, match="Not a VCP URI"):
            uri_to_canonical("http://example.com/token")

    def test_missing_path(self):
        with pytest.raises(ValueError, match="missing issuer or path"):
            uri_to_canonical("creed://creed.space/")


class TestTokenParse:
    def test_three_segments(self):
        t = Token.parse("family.safe.guide")
        assert t.domain == "family"
        assert t.approach == "safe"
        assert t.role == "guide"
        assert t.depth == 3
        assert t.path == ()

    def test_four_segments(self):
        t = Token.parse("company.acme.legal.compliance")
        assert t.domain == "company"
        assert t.role == "compliance"
        assert t.approach == "legal"
        assert t.path == ("acme",)
        assert t.depth == 4

    def test_with_version(self):
        t = Token.parse("family.safe.guide@1.2.3")
        assert t.version == "1.2.3"
        assert t.full == "family.safe.guide@1.2.3"

    def test_with_latest(self):
        t = Token.parse("family.safe.guide@latest")
        assert t.version == "latest"

    def test_with_namespace(self):
        t = Token.parse("company.acme.legal.compliance:SEC")
        assert t.namespace == "SEC"

    def test_canonical_property(self):
        t = Token.parse("family.safe.guide@1.0.0:NS")
        assert t.canonical == "family.safe.guide"
        assert t.full == "family.safe.guide@1.0.0:NS"

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            Token.parse("")

    def test_too_few_segments(self):
        with pytest.raises(ValueError):
            Token.parse("only.two")

    def test_wire_parser_rejects_noncanonical_case(self):
        with pytest.raises(ValueError, match="Invalid VCP/I token"):
            Token.parse("Family.Safe.Guide")

    def test_from_creed_uri(self):
        t = Token.from_uri("creed://creed.space/family.safe.guide@1.0.0")
        assert t.domain == "family"
        assert t.version == "1.0.0"


class TestTokenMethods:
    def test_to_uri(self):
        t = Token.parse("family.safe.guide@1.0.0")
        assert t.to_uri() == "creed://creed.space/family.safe.guide@1.0.0"

    def test_with_version(self):
        t = Token.parse("family.safe.guide")
        t2 = t.with_version("2.0.0")
        assert t2.version == "2.0.0"
        assert t.version is None  # Original unchanged (frozen)

    def test_with_namespace(self):
        t = Token.parse("family.safe.guide")
        t2 = t.with_namespace("ELEM")
        assert t2.namespace == "ELEM"

    def test_matches_exact(self):
        t = Token.parse("family.safe.guide")
        assert t.matches_pattern("family.safe.guide")
        assert not t.matches_pattern("family.strict.guide")

    def test_matches_wildcard(self):
        t = Token.parse("family.safe.guide")
        assert t.matches_pattern("family.*.guide")
        assert not t.matches_pattern("company.*.guide")

    def test_matches_globstar(self):
        t = Token.parse("company.acme.legal.compliance")
        assert t.matches_pattern("company.**")
        assert not t.matches_pattern("family.**")

    def test_is_ancestor_of(self):
        parent = Token.parse("company.acme.legal.compliance")
        child = Token.parse("company.acme.legal.compliance.sub")
        assert parent.is_ancestor_of(child)
        assert not child.is_ancestor_of(parent)

    def test_str_repr(self):
        t = Token.parse("family.safe.guide@1.0.0")
        assert str(t) == "family.safe.guide@1.0.0"
        assert repr(t) == "Token('family.safe.guide@1.0.0')"
