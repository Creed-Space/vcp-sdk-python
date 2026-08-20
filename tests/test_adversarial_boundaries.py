"""Permanent regressions for malformed, boundary, and corruption paths.

These cases deliberately exercise runtime inputs that static type annotations do
not protect.  Each case names a distinct externally observable contract rather
than repeating a happy-path assertion from the focused module suites.
"""

from __future__ import annotations

import copy
import json
from dataclasses import replace

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from vcp import _ops
from vcp.context import MAX_SESSION_METADATA_BYTES, Context
from vcp.csm1 import CSM1Code, Persona, Scope, check_scope_conflicts
from vcp.lite import lite_to_csm1, lite_to_token, load_schema, validate_lite
from vcp.token import MAX_TOKEN_INPUT_LENGTH, Token, canonicalize_token, uri_to_canonical


def valid_lite() -> dict:
    return {
        "vcp_version": "lite-1.0",
        "identity": {"domain": "family", "approach": "safe", "role": "guide"},
        "persona": "nanny",
        "adherence": 5,
        "scopes": ["F"],
    }


@pytest.mark.parametrize("malformed", [None, [], "document", 1, True])
def test_lite_validator_rejects_non_objects_without_crashing(malformed):
    assert validate_lite(malformed) == ["document must be an object"]


@pytest.mark.parametrize(
    ("mutation", "needle"),
    [
        (lambda doc: doc.update(adherence=True), "adherence"),
        (lambda doc: doc.update(scopes=[{}]), "Invalid scope"),
        (lambda doc: doc.update(adaptation_hints={"formality": []}), "formality"),
        (lambda doc: doc.update(namespace="A1"), "namespace"),
        (lambda doc: doc.update(unexpected=True), "Unknown top-level"),
        (lambda doc: doc["identity"].update(unexpected=True), "Unknown identity"),
        (
            lambda doc: doc.update(values=[{"principle": "p", "weight": float("nan")}]),
            "weight",
        ),
        (lambda doc: doc.update(metadata={"created": "2025-02-29"}), "created"),
        (lambda doc: doc["identity"].update(version="100000.0.0"), "version"),
        (lambda doc: doc.update(metadata={"author": "a" * 501}), "author"),
        (lambda doc: doc.update(metadata={"extends": "not-a-token"}), "extends"),
        (lambda doc: doc.update(metadata={"tags": ["t" * 101]}), "tags"),
    ],
)
def test_lite_malformed_values_return_diagnostic_errors(mutation, needle):
    document = valid_lite()
    mutation(document)

    assert any(needle in error for error in validate_lite(document))


@pytest.mark.parametrize(
    ("field", "value", "needle"),
    [
        ("scopes", ["F"] * 100_000, "at most 11"),
        ("values", [{"principle": "p", "weight": 1.0}] * 100_000, "at most 20"),
        ("constraints", ["c"] * 100_000, "at most 20"),
        ("metadata", {"tags": ["t"] * 100_000}, "at most 10"),
    ],
)
def test_lite_collection_limits_reject_bounded_resource_pressure(field, value, needle):
    document = valid_lite()
    if field == "metadata":
        document[field] = value
    else:
        document[field] = value

    assert any(needle in error for error in validate_lite(document))


def test_lite_adaptation_hints_bound_unknown_field_traversal():
    document = valid_lite()
    document["adaptation_hints"] = {f"unknown_{index}": "value" for index in range(10_000)}

    errors = validate_lite(document)

    assert "adaptation_hints contains too many fields" in errors
    assert len(errors) <= 7


def test_runtime_lite_validation_matches_bundled_schema_on_adversarial_documents():
    validator = Draft202012Validator(load_schema(), format_checker=FormatChecker())
    documents = []
    for mutation in (
        lambda doc: None,
        lambda doc: doc.update(namespace="ACME"),
        lambda doc: doc.update(namespace="A1"),
        lambda doc: doc.update(unexpected=True),
        lambda doc: doc["identity"].update(version="1.2"),
        lambda doc: doc.update(values=[{"principle": "x" * 501, "weight": 1.0}]),
        lambda doc: doc.update(constraints=["x" * 501]),
        lambda doc: doc.update(scopes=["F", "A"]),
        lambda doc: doc.update(scopes=["V", "A"]),
        lambda doc: doc.update(scopes=["H", "A"]),
        lambda doc: doc.update(scopes=["F"] * 12),
        lambda doc: doc["identity"].update(version="100000.0.0"),
        lambda doc: doc.update(metadata={"author": "a" * 501}),
        lambda doc: doc.update(metadata={"extends": "not-a-token"}),
        lambda doc: doc.update(metadata={"extends": "family.safe.guide@100000.1.1"}),
        lambda doc: doc.update(metadata={"extends": f"family.safe.guide:{'A' * 33}"}),
        lambda doc: doc.update(metadata={"tags": ["t" * 101]}),
        lambda doc: doc.update(metadata={"created": "2025-02-29"}),
    ):
        document = valid_lite()
        mutation(document)
        documents.append(document)

    for document in documents:
        assert bool(validate_lite(document)) == bool(list(validator.iter_errors(document)))


@pytest.mark.parametrize(
    "arguments",
    [
        (None, 1, ["F"], None),
        ("nanny", True, ["F"], None),
        ("nanny", 1, None, None),
        ("nanny", 1, [{}], None),
        ("custom", 3, ["W"], None),
        ("nanny", 1, ["F", "F"], None),
        ("nanny", 1, ["F", "A"], None),
        ("nanny", 1, ["H", "A"], None),
        ("nanny", 1, ["F"] * 100_000, None),
    ],
)
def test_lite_to_csm1_operation_returns_stable_errors_for_invalid_runtime_types(
    arguments,
):
    result = _ops.lite_to_csm1(*arguments)

    assert set(result) == {"error"}
    assert result["error"]


@pytest.mark.parametrize("converter", [lite_to_csm1, lite_to_token])
@pytest.mark.parametrize("malformed", [None, [], {}, {"persona": 1}, valid_lite() | {"adherence": True}])
def test_direct_lite_converters_reject_invalid_documents_without_crashing(converter, malformed):
    with pytest.raises(ValueError, match="Invalid VCP-Lite document"):
        converter(malformed)


def test_token_uri_omits_namespace_that_uri_grammar_cannot_represent():
    token = Token.parse("company.safe.guide@1.2.3:SEC")

    assert token.to_uri() == "creed://creed.space/company.safe.guide@1.2.3"
    assert Token.from_uri(token.to_uri()).full == "company.safe.guide@1.2.3"
    assert uri_to_canonical(token.to_uri()) == "company.safe.guide@1.2.3"


@pytest.mark.parametrize(
    "uri",
    [
        "creed://user@creed.space/family.safe.guide",
        "creed://creed..space/family.safe.guide",
        "creed://-creed.space/family.safe.guide",
        "creed://creed.space/family.safe.guide?override=true",
        "creed://creed.space/family.safe.guide#fragment",
        "creed://creed.space/family.safe.guide@1.2.3:SEC",
        "creed://creed.space/only.two",
        "vcp://registry/family.safe.guide",
    ],
)
def test_token_uri_converter_rejects_malformed_authority_or_path(uri):
    with pytest.raises(ValueError):
        uri_to_canonical(uri)


@pytest.mark.parametrize("issuer", [None, "", "creed..space", "-creed.space", "creed.space/path", "creed space"])
def test_token_uri_serializer_rejects_invalid_issuer(issuer):
    with pytest.raises(ValueError, match="valid ASCII domain"):
        Token.parse("family.safe.guide").to_uri(issuer)


def test_token_relationship_helpers_fail_closed_on_invalid_runtime_types():
    token = Token.parse("family.safe.guide")

    assert token.matches_pattern(None) is False
    assert token.matches_pattern("**.**") is False
    assert token.is_ancestor_of("family.safe.guide.child") is False


def test_token_canonicalizer_rejects_resource_exhausting_input_before_normalization():
    with pytest.raises(ValueError, match="maximum length"):
        canonicalize_token(" " * (MAX_TOKEN_INPUT_LENGTH + 1) + "family.safe.guide")


@pytest.mark.parametrize(
    "raw",
    [
        "family.safe.guide\n",
        "family.safe.guide@100000.1.1",
        "family.safe.guide@1.2.3-rc_1",
        f"family.safe.guide:{'A' * 33}",
    ],
)
def test_token_wire_parser_rejects_cross_surface_noncanonical_boundaries(raw):
    with pytest.raises(ValueError, match="Invalid VCP/I token"):
        Token.parse(raw)


@pytest.mark.parametrize("bad", [None, b"a.b.c", [], {}])
def test_token_string_entry_points_reject_non_strings_cleanly(bad):
    with pytest.raises(ValueError):
        canonicalize_token(bad)
    with pytest.raises(ValueError):
        Token.parse(bad)


@pytest.mark.parametrize(
    "segments",
    [
        ("Bad", "safe", "guide"),
        ("bad_underscore", "safe", "guide"),
        ("a" * 33, "safe", "guide"),
    ],
)
def test_direct_token_construction_cannot_bypass_parser_validation(segments):
    with pytest.raises(ValueError):
        Token(segments=segments)


def test_direct_token_construction_bounds_segment_before_regex_validation():
    with pytest.raises(ValueError, match="exceeds max length"):
        Token(segments=("a" * 1_000_000, "safe", "guide"))


def test_frozen_token_replace_cannot_inject_invalid_version_or_namespace():
    token = Token.parse("family.safe.guide")

    with pytest.raises(ValueError):
        replace(token, version="1.2")
    with pytest.raises(ValueError):
        replace(token, namespace="not-upper")


@pytest.mark.parametrize(
    "raw",
    [
        "N5+F+F",
        "N5+F+A",
        "N5+H+A",
        "C3",
        "N5+I",
        "N5+L",
        "N5+G",
        "N5+B",
        "N5+X",
        "N5:ABC123",
        "N5@1000.0.0",
        "N5@01.2.3",
        "N5@1.02.3",
        "N5@1.2.03",
        "N5\n",
        "CS1|nanny|5|not-a-token|F,E",
        "CS1|nanny|5|family.safe.guide|",
        "CS1|nanny|5|family.safe.guide|F,F",
        "CS1|nanny|5|family.safe.guide|F,A",
        "CS1|nanny|5|" + "a" * 40 + ".safe.guide|F,E",
    ],
)
def test_csm1_rejects_noncanonical_or_semantically_invalid_codes(raw):
    with pytest.raises(ValueError):
        CSM1Code.parse(raw)


def test_csm1_direct_construction_enforces_the_same_invariants_as_parse():
    with pytest.raises(ValueError, match="unique"):
        CSM1Code(Persona.NANNY, 5, [Scope.FAMILY, Scope.FAMILY])
    with pytest.raises(ValueError, match="v2 scope"):
        CSM1Code(Persona.NANNY, 5, [Scope.FINANCE])
    with pytest.raises(ValueError, match="namespace"):
        CSM1Code(Persona.CUSTOM, 3, [Scope.WORK])


def test_csm1_public_enum_helpers_reject_invalid_runtime_types_cleanly():
    for operation in (Persona.from_char, Persona.from_name, Scope.from_char):
        with pytest.raises(ValueError):
            operation(None)
    with pytest.raises(ValueError, match="list of Scope"):
        check_scope_conflicts(["F", "A"])
    with pytest.raises(ValueError, match="at most 11"):
        check_scope_conflicts([Scope.FAMILY] * 100_000)
    for operation, hostile in (
        (Persona.from_char, "N" * 100_000),
        (Persona.from_name, "nanny" * 100_000),
        (Scope.from_char, "F" * 100_000),
    ):
        with pytest.raises(ValueError):
            operation(hostile)


def test_csm1_micro_serializer_uses_the_normative_field_order():
    code = CSM1Code.parse("N5+F+E:ELEM@1.2.0")

    assert code.to_micro() == "N5+F+E:ELEM@1.2.0"
    assert CSM1Code.parse(code.to_micro()) == code


def test_csm1_canonical_serializer_remains_parseable_with_namespace():
    code = CSM1Code.parse("Z4+W+P:SEC@1.2.0")

    assert code.to_canonical() == "Z4+P+W:SEC@1.2.0"
    assert CSM1Code.parse(code.to_canonical()) == CSM1Code.parse("Z4+P+W:SEC@1.2.0")


def test_csm1_compact_serializer_validates_its_token_and_scope_list():
    with pytest.raises(ValueError):
        CSM1Code.parse("N5+F").to_compact("not-a-token")
    with pytest.raises(ValueError, match="at least one scope"):
        CSM1Code.parse("N5").to_compact("family.safe.guide")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"cognitive_state": "focused", "cognitive_state_intensity": 0},
        {"cognitive_state": "focused", "cognitive_state_intensity": True},
        {"cognitive_state_intensity": 5},
        {"company": [1]},
        {"company": []},
        {"constraints": ["x"] * 65},
        {"relationship": "friend:social|📍🏡"},
        {"space": "line\nbreak"},
        {"version": None},
    ],
)
def test_context_constructor_rejects_invalid_or_ambiguous_state(kwargs):
    with pytest.raises(ValueError):
        Context(**kwargs)


def test_context_wire_encoding_matches_vcp_3_2_delimiters_and_symbols():
    context = Context(
        space="hospital",
        agency="peer",
        constraints=["legal"],
        cognitive_state="focused",
        cognitive_state_intensity=4,
    )

    assert context.to_wire() == "📍🏥|🎯🤝|🔒⚖️‖🧠focused:4"
    assert Context.from_session_metadata(context.to_session_metadata()) == context


@pytest.mark.parametrize(
    "serialized",
    [
        "[]",
        "null",
        "1",
        '"string"',
        "{",
        '{"version":"3.2","version":"9.9"}',
        '{"cognitive_state":{"category":"focused","unknown":true}}',
        '{"unknown":' + "[" * 2_000 + "0" + "]" * 2_000 + "}",
    ],
)
def test_corrupted_session_metadata_fails_closed_without_exception(serialized):
    assert Context.from_session_metadata({"vcp_context": serialized}) is None


def test_session_metadata_parser_rejects_resource_exhausting_payload_before_json_decode():
    serialized = " " * (MAX_SESSION_METADATA_BYTES + 1)

    assert Context.from_session_metadata({"vcp_context": serialized}) is None


def test_context_from_dict_does_not_alias_mutable_input():
    source = {"company": ["family"], "version": "3.2"}
    restored = Context.from_dict(source)
    source["company"].append("strangers")

    assert restored.company == ["family"]
    assert json.loads(restored.to_session_metadata()["vcp_context"])["company"] == ["family"]


def test_context_metadata_round_trip_is_independent_of_source_mutation():
    source = {"constraints": ["legal"], "version": "3.2"}
    original = copy.deepcopy(source)

    restored = Context.from_dict(source)
    assert source == original
    assert Context.from_session_metadata(restored.to_session_metadata()) == restored
