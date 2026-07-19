"""End-to-end tests for the VCP MCP server.

These drive the real server over stdio with the MCP client, so they cover the
transport, tool registration, and JSON payloads the way a client sees them.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

import pytest

mcp_client = pytest.importorskip("mcp.client.stdio", reason="requires vcp-sdk[mcp]")

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

EXPECTED_TOOLS = {
    "creed_classify_principle",
    "vcp_encode_context",
    "vcp_lite_to_csm1",
    "vcp_parse_csm1",
    "vcp_status",
    "vcp_validate_lite",
    "vcp_validate_token",
}

SERVER_PARAMS = StdioServerParameters(command=sys.executable, args=["-m", "vcp.mcp_server"])


async def _with_session(body):
    async with stdio_client(SERVER_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await body(session)


def run_session(body):
    """Run an async body against a freshly handshaken server session."""
    return asyncio.run(asyncio.wait_for(_with_session(body), timeout=60))


def call(result: Any) -> dict[str, Any]:
    """Extract the JSON payload from a CallToolResult."""
    assert result.content, "tool returned no content"
    return json.loads(result.content[0].text)


def test_handshake_and_tool_list():
    async def body(session):
        return await session.list_tools()

    tools = run_session(body)
    names = {t.name for t in tools.tools}
    assert names == EXPECTED_TOOLS

    # Every tool must carry a description and an input schema for clients to render.
    for tool in tools.tools:
        assert tool.description, f"{tool.name} has no description"
        assert tool.inputSchema["type"] == "object"


def test_status_reports_offline_sdk():
    async def body(session):
        return call(await session.call_tool("vcp_status", {}))

    status = run_session(body)
    assert status["network_access"] is False
    assert status["lite_version"] == "lite-1.0"
    assert set(status["tools"]) == EXPECTED_TOOLS


def test_token_validation_good_and_bad():
    async def body(session):
        good = call(await session.call_tool("vcp_validate_token", {"token": "family.safe.guide@1.0.0"}))
        bad = call(await session.call_tool("vcp_validate_token", {"token": "invalid"}))
        return good, bad

    good, bad = run_session(body)

    assert good["valid"] is True
    assert good["canonical"] == "family.safe.guide"
    assert good["domain"] == "family"
    assert good["approach"] == "safe"
    assert good["role"] == "guide"
    assert good["version"] == "1.0.0"
    assert good["full"] == "family.safe.guide@1.0.0"
    assert good["uri"] == "creed://creed.space/family.safe.guide@1.0.0"

    assert bad["valid"] is False
    assert bad["error"]


def test_encode_context_round_trips_through_parse_of_wire_dimensions():
    """encode → the emitted JSON is the same shape the SDK reads back."""

    async def body(session):
        return call(
            await session.call_tool(
                "vcp_encode_context",
                {
                    "space": "hospital",
                    "agency": "peer",
                    "constraints": ["legal"],
                    "cognitive_state": "focused",
                    "cognitive_state_intensity": 4,
                },
            )
        )

    encoded = run_session(body)

    assert encoded["wire_format"] == "📍hospital|🎯peer|🔒legal||🧠focused4"
    assert encoded["dimensions_set"] == ["space", "agency", "constraints", "cognitive_state"]
    assert encoded["json_format"]["cognitive_state"] == {"category": "focused", "intensity": 4}
    assert "Setting: hospital" in encoded["natural_language"]

    from vcp import Context

    restored = Context.from_session_metadata(encoded["session_metadata"])
    assert restored is not None
    assert restored.space == "hospital"
    assert restored.cognitive_state_intensity == 4
    assert restored.to_wire() == encoded["wire_format"]


def test_lite_validate_then_parse_csm1():
    """validate_lite emits a CSM1 code that parse_csm1 accepts."""
    document = {
        "vcp_version": "lite-1.0",
        "identity": {"domain": "family", "approach": "safe", "role": "guide"},
        "persona": "nanny",
        "adherence": 5,
        "scopes": ["F", "E"],
    }

    async def body(session):
        validated = call(await session.call_tool("vcp_validate_lite", {"document": document}))
        parsed = call(await session.call_tool("vcp_parse_csm1", {"code": validated["csm1_code"]}))
        return validated, parsed

    validated, parsed = run_session(body)

    assert validated["valid"] is True
    assert validated["errors"] == []
    assert validated["csm1_code"] == "N5+F+E"
    assert validated["token"] == "family.safe.guide"

    assert parsed["valid"] is True
    assert parsed["persona"] == "NANNY"
    assert parsed["adherence_level"] == 5
    assert parsed["scopes"] == ["FAMILY", "EDUCATION"]


def test_lite_validate_rejects_bad_document():
    async def body(session):
        return call(
            await session.call_tool(
                "vcp_validate_lite",
                {"document": {"vcp_version": "lite-9.9", "persona": "wizard", "adherence": 11}},
            )
        )

    result = run_session(body)
    assert result["valid"] is False
    assert result["errors"]


def test_lite_to_csm1_matches_parse_csm1():
    async def body(session):
        converted = call(
            await session.call_tool(
                "vcp_lite_to_csm1",
                {"persona": "sentinel", "adherence": 4, "scopes": ["P", "T", "W"], "namespace": "SEC"},
            )
        )
        rejected = call(
            await session.call_tool("vcp_lite_to_csm1", {"persona": "wizard", "adherence": 4, "scopes": ["P"]})
        )
        return converted, rejected

    converted, rejected = run_session(body)

    assert converted["csm1_code"] == "Z4+P+T+W:SEC"
    assert converted["persona"] == "SENTINEL"
    assert converted["namespace"] == "SEC"

    assert "error" in rejected


def test_classify_principle_is_deterministic_and_reports_tension():
    async def body(session):
        first = call(
            await session.call_tool(
                "creed_classify_principle",
                {"principle_text": "Protect the safety and security of the family", "existing_values": ["power"]},
            )
        )
        second = call(
            await session.call_tool(
                "creed_classify_principle",
                {"principle_text": "Protect the safety and security of the family", "existing_values": ["power"]},
            )
        )
        return first, second

    first, second = run_session(body)

    assert first == second, "classification must be deterministic"
    assert first["schwartz_value"] in {
        "power",
        "achievement",
        "hedonism",
        "stimulation",
        "self_direction",
        "universalism",
        "benevolence",
        "tradition",
        "conformity",
        "security",
    }
    assert first["higher_order"] != "unknown"
    assert isinstance(first["tensions"], list)


def test_lite_examples_resource():
    async def body(session):
        listed = await session.list_resources()
        content = await session.read_resource("vcp://lite/examples")
        return listed, content

    listed, content = run_session(body)

    assert any(str(r.uri) == "vcp://lite/examples" for r in listed.resources)
    examples = json.loads(content.contents[0].text)
    assert "family-safe-guide.vcp-lite.json" in examples
    assert examples["family-safe-guide.vcp-lite.json"]["persona"] == "nanny"
