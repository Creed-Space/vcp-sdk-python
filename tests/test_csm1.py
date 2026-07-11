"""Tests for VCP/S CSM1 parsing and encoding."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vcp.csm1 import (
    ADHERENCE_BEHAVIORS,
    PERSONA_NAMES,
    CSM1Code,
    Persona,
    Scope,
    check_scope_conflicts,
)


class TestPersona:
    def test_from_char(self):
        assert Persona.from_char("N") == Persona.NANNY
        assert Persona.from_char("Z") == Persona.SENTINEL
        assert Persona.from_char("C") == Persona.CUSTOM

    def test_from_char_lowercase(self):
        assert Persona.from_char("n") == Persona.NANNY

    def test_from_name(self):
        assert Persona.from_name("nanny") == Persona.NANNY
        assert Persona.from_name("sentinel") == Persona.SENTINEL

    def test_persona_name(self):
        assert Persona.NANNY.persona_name == "nanny"
        assert Persona.SENTINEL.persona_name == "sentinel"

    def test_description(self):
        assert "Child safety" in Persona.NANNY.description
        assert "Security" in Persona.SENTINEL.description

    def test_invalid_char(self):
        with pytest.raises(ValueError, match="Unknown persona"):
            Persona.from_char("X")

    def test_all_personas_named(self):
        for persona in Persona:
            assert persona.value in PERSONA_NAMES


class TestScope:
    def test_from_char(self):
        assert Scope.from_char("F") == Scope.FAMILY
        assert Scope.from_char("W") == Scope.WORK

    def test_deprecated(self):
        assert Scope.FINANCE.is_deprecated
        assert Scope.LEGAL.is_deprecated
        assert not Scope.FAMILY.is_deprecated

    def test_description(self):
        assert "Family" in Scope.FAMILY.description
        assert "Privacy" in Scope.PRIVACY.description

    def test_invalid_char(self):
        with pytest.raises(ValueError, match="Unknown scope"):
            Scope.from_char("Q")  # Q is not a valid scope character


class TestScopeConflicts:
    def test_family_adult_conflict(self):
        scopes = [Scope.FAMILY, Scope.ADULT]
        conflicts = check_scope_conflicts(scopes)
        assert len(conflicts) >= 1
        codes = {(a.value, b.value) for a, b in conflicts}
        assert ("F", "A") in codes

    def test_no_conflicts(self):
        scopes = [Scope.FAMILY, Scope.EDUCATION]
        assert check_scope_conflicts(scopes) == []


class TestCSM1Parse:
    def test_nano_basic(self):
        code = CSM1Code.parse("N5")
        assert code.persona == Persona.NANNY
        assert code.adherence_level == 5
        assert code.scopes == []

    def test_nano_with_scopes(self):
        code = CSM1Code.parse("N5+F+E")
        assert code.persona == Persona.NANNY
        assert code.adherence_level == 5
        assert len(code.scopes) == 2
        assert Scope.FAMILY in code.scopes
        assert Scope.EDUCATION in code.scopes

    def test_nano_lowercase(self):
        code = CSM1Code.parse("n5+f+e")
        assert code.persona == Persona.NANNY
        assert code.scopes == [Scope.FAMILY, Scope.EDUCATION]

    def test_micro_with_namespace(self):
        # ABNF: persona adherence scopes namespace version
        code = CSM1Code.parse("Z4+P+T+W:SEC")
        assert code.persona == Persona.SENTINEL
        assert code.adherence_level == 4
        assert code.namespace == "SEC"
        assert len(code.scopes) == 3

    def test_micro_with_version(self):
        code = CSM1Code.parse("N5+F+E@1.2.0")
        assert code.version == "1.2.0"

    def test_micro_with_latest(self):
        code = CSM1Code.parse("M2+A@latest")
        assert code.version == "latest"

    def test_compact_format(self):
        code = CSM1Code.parse("CS1|nanny|5|family.safe.guide|F,E")
        assert code.persona == Persona.NANNY
        assert code.adherence_level == 5
        assert len(code.scopes) == 2

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            CSM1Code.parse("")

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="Invalid"):
            CSM1Code.parse("INVALID")

    def test_all_personas(self):
        for char in "NZGAMDC":
            code = CSM1Code.parse(f"{char}3")
            assert code.persona.value == char


class TestCSM1Encode:
    def test_encode_nano(self):
        code = CSM1Code(
            persona=Persona.NANNY,
            adherence_level=5,
            scopes=[Scope.FAMILY, Scope.EDUCATION],
        )
        assert code.encode() == "N5+F+E"

    def test_encode_with_namespace(self):
        code = CSM1Code(
            persona=Persona.SENTINEL,
            adherence_level=4,
            scopes=[Scope.PRIVACY],
            namespace="SEC",
        )
        assert code.encode() == "Z4+P:SEC"

    def test_encode_with_version(self):
        code = CSM1Code(
            persona=Persona.MUSE,
            adherence_level=2,
            scopes=[Scope.ADULT],
            version="1.0.0",
        )
        assert code.encode() == "M2+A@1.0.0"

    def test_to_nano(self):
        # ABNF order: scopes before namespace
        code = CSM1Code.parse("N5+F+E:ELEM@1.0.0")
        assert code.to_nano() == "N5+F+E"

    def test_to_compact(self):
        code = CSM1Code.parse("N5+F+E")
        result = code.to_compact("family.safe.guide")
        assert result == "CS1|nanny|5|family.safe.guide|F,E"

    def test_roundtrip_nano(self):
        original = "N5+F+E"
        code = CSM1Code.parse(original)
        assert code.encode() == original

    def test_roundtrip_all_scopes(self):
        original = "G4+F+W+P+E+T+O+V+A+H+S+R"
        code = CSM1Code.parse(original)
        assert code.encode() == original


class TestCSM1Canonical:
    def test_scopes_sorted(self):
        code = CSM1Code.parse("N5+E+F")
        assert code.to_canonical() == "N5+E+F"  # E before F alphabetically

    def test_canonical_with_namespace(self):
        code = CSM1Code.parse("Z4+W+P:SEC")
        canonical = code.to_canonical()
        assert canonical.startswith("Z4:SEC")

    def test_get_conflicts(self):
        code = CSM1Code.parse("M2+F+A")  # Family + Adult = conflict
        conflicts = code.get_conflicts()
        assert len(conflicts) >= 1


class TestAdherenceBehaviors:
    def test_all_levels_defined(self):
        for level in range(6):
            assert level in ADHERENCE_BEHAVIORS
            assert "enforcement" in ADHERENCE_BEHAVIORS[level]

    def test_level_0_advisory(self):
        assert ADHERENCE_BEHAVIORS[0]["enforcement"] == "advisory"

    def test_level_5_absolute(self):
        assert ADHERENCE_BEHAVIORS[5]["enforcement"] == "absolute"
        assert ADHERENCE_BEHAVIORS[5]["user_override"] == "never"
