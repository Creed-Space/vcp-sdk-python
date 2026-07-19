"""Tests for the `vcp` CLI's protocol subcommands.

Driven through `main()` — the same entry point the console script uses — so
these cover argument parsing, exit codes, and output shape the way a script
consuming the CLI sees them.
"""

from __future__ import annotations

import json

import pytest

from vcp import _ops
from vcp._schwartz_classifier import HIGHER_ORDER_MAPPING
from vcp.hub.cli import main

VALID_LITE = {
    "vcp_version": "lite-1.0",
    "identity": {"domain": "family", "approach": "safe", "role": "guide"},
    "persona": "nanny",
    "adherence": 5,
    "scopes": ["F", "E"],
}

INVALID_LITE = {"vcp_version": "lite-1.0", "persona": "nanny"}


@pytest.fixture
def run(capsys):
    """Run the CLI and return (exit_code, stdout, stderr)."""

    def _run(*argv: str):
        code = main(list(argv))
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return _run


@pytest.fixture
def lite_file(tmp_path):
    def _write(document, name="doc.json"):
        path = tmp_path / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return str(path)

    return _write


# === vcp token validate ===


def test_token_validate_valid(run):
    code, out, _ = run("token", "validate", "family.safe.guide@1.0.0")
    assert code == 0
    payload = json.loads(out)
    assert payload["valid"] is True
    assert payload["domain"] == "family"
    assert payload["version"] == "1.0.0"


def test_token_validate_invalid_exits_one(run):
    code, out, _ = run("token", "validate", "nope")
    assert code == 1
    assert json.loads(out)["valid"] is False


def test_token_validate_quiet_prints_bare_canonical(run):
    code, out, _ = run("token", "validate", "family.safe.guide@1.0.0", "--quiet")
    assert code == 0
    assert out.strip() == "family.safe.guide"


def test_token_validate_quiet_still_shows_why_it_failed(run):
    """--quiet must not swallow the reason an invalid token was rejected."""
    code, out, _ = run("token", "validate", "nope", "--quiet")
    assert code == 1
    assert "Invalid VCP/I token format" in out


# === vcp token parse ===


def test_token_parse_valid(run):
    code, out, _ = run("token", "parse", "N5+F+E")
    assert code == 0
    payload = json.loads(out)
    assert payload["valid"] is True
    assert payload["persona"] == "NANNY"
    assert payload["adherence_level"] == 5
    assert set(payload["scopes"]) == {"FAMILY", "EDUCATION"}


def test_token_parse_invalid_exits_one(run):
    code, out, _ = run("token", "parse", "XYZ")
    assert code == 1
    assert json.loads(out)["valid"] is False


# === vcp lite ===


def test_lite_validate_valid(run, lite_file):
    code, out, _ = run("lite", "validate", lite_file(VALID_LITE))
    assert code == 0
    payload = json.loads(out)
    assert payload["valid"] is True
    assert payload["csm1_code"] == "N5+F+E"
    assert payload["token"] == "family.safe.guide"


def test_lite_validate_invalid_exits_one(run, lite_file):
    code, out, _ = run("lite", "validate", lite_file(INVALID_LITE))
    assert code == 1
    payload = json.loads(out)
    assert payload["valid"] is False
    assert payload["errors"]


def test_lite_validate_missing_file(run, tmp_path):
    code, _, err = run("lite", "validate", str(tmp_path / "absent.json"))
    assert code == 1
    assert "cannot read" in err


def test_lite_validate_malformed_json(run, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    code, _, err = run("lite", "validate", str(path))
    assert code == 1
    assert "not valid JSON" in err


def test_lite_validate_rejects_non_object(run, tmp_path):
    path = tmp_path / "list.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    code, _, err = run("lite", "validate", str(path))
    assert code == 1
    assert "must contain a JSON object" in err


def test_lite_to_csm1(run, lite_file):
    code, out, _ = run("lite", "to-csm1", lite_file(VALID_LITE), "--quiet")
    assert code == 0
    assert out.strip() == "N5+F+E"


def test_lite_to_csm1_refuses_invalid_document(run, lite_file):
    """Converting an invalid document would report a code for a rejected profile."""
    code, out, err = run("lite", "to-csm1", lite_file(INVALID_LITE))
    assert code == 1
    assert out == ""
    assert json.loads(err)["valid"] is False


# === vcp encode ===


def test_encode_situational_dimensions(run):
    code, out, _ = run("encode", "--space", "hospital", "--agency", "peer")
    assert code == 0
    payload = json.loads(out)
    assert "hospital" in payload["wire_format"]
    assert payload["json_format"]["space"] == "hospital"
    assert set(payload["dimensions_set"]) == {"space", "agency"}


def test_encode_multi_value_dimension_repeats(run):
    code, out, _ = run("encode", "--constraints", "legal", "--constraints", "time")
    assert code == 0
    assert json.loads(out)["json_format"]["constraints"] == ["legal", "time"]


def test_encode_personal_dimension_with_intensity(run):
    code, out, _ = run(
        "encode", "--cognitive-state", "focused", "--cognitive-state-intensity", "4", "--quiet"
    )
    assert code == 0
    assert "focused4" in out


def test_encode_no_dimensions_is_empty_not_an_error(run):
    code, out, _ = run("encode")
    assert code == 0
    assert json.loads(out)["dimensions_set"] == []


def test_encode_rejects_non_integer_intensity(run):
    with pytest.raises(SystemExit):
        run("encode", "--cognitive-state", "focused", "--cognitive-state-intensity", "high")


# === vcp classify ===


def test_classify_returns_schwartz_value(run):
    code, out, _ = run("classify", "Never endanger a child")
    assert code == 0
    payload = json.loads(out)
    assert payload["schwartz_value"] in HIGHER_ORDER_MAPPING
    assert payload["higher_order"] == HIGHER_ORDER_MAPPING[payload["schwartz_value"]]
    assert 0.0 <= payload["confidence"] <= 1.0
    assert len(payload["candidates"]) == 3
    assert "tensions" not in payload


def test_classify_reports_tensions_against_existing_values(run):
    code, out, _ = run(
        "classify", "Aim for kindness in all responses", "--type", "aim_for", "--existing", "power"
    )
    assert code == 0
    assert "tensions" in json.loads(out)


def test_classify_quiet(run):
    code, out, _ = run("classify", "Never endanger a child", "--quiet")
    assert code == 0
    assert out.strip().isidentifier()


# === vcp status ===


def test_status_lists_the_same_tools_the_mcp_server_exposes(run):
    code, out, _ = run("status")
    assert code == 0
    payload = json.loads(out)
    assert set(payload["tools"]) == set(_ops.TOOL_NAMES)
    assert payload["network_access"] is False


# === CLI/MCP parity ===


def test_cli_and_ops_agree_on_token_payload(run):
    """The CLI is a thin printer over _ops — the shared shaping the MCP server uses."""
    code, out, _ = run("token", "validate", "company.acme.legal.compliance:SEC")
    assert code == 0
    assert json.loads(out) == _ops.validate_token("company.acme.legal.compliance:SEC")


# === Existing hub commands are undisturbed ===


@pytest.mark.parametrize(
    "command", ["search", "install", "verify", "namespaces", "lint", "build-index", "publish"]
)
def test_hub_subcommands_still_parse(command):
    """Adding protocol commands must not displace any Creed Commons command.

    Checked by parsing each subcommand's own --help, which fails loudly if the
    subparser is gone — stronger than substring-matching the top-level help.
    """
    with pytest.raises(SystemExit) as exc:
        main([command, "--help"])
    assert exc.value.code == 0


def test_unknown_subcommand_is_rejected():
    with pytest.raises(SystemExit):
        main(["definitely-not-a-command"])
