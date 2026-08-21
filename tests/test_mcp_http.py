"""End-to-end tests for the VCP MCP server's Streamable HTTP transport.

These start the real `vcp-mcp --transport http` process and drive it the way a
hosted client would: the MCP streamable-http client for the handshake, raw
httpx for the abuse cases (bad method, malformed body).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import subprocess
import sys
import time

import pytest

pytest.importorskip("mcp.client.streamable_http", reason="requires vcp-sdk[mcp]")
httpx = pytest.importorskip("httpx")

from mcp import ClientSession  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402

from vcp._http import ALLOW_INSECURE_ENV, check_bind_allowed, is_loopback  # noqa: E402

EXPECTED_TOOL_COUNT = 7

# Any single request must settle well inside this. A GET that hangs (the bug the
# POST-only gate exists to prevent) blows the budget instead of hanging the suite.
REQUEST_TIMEOUT = 10.0


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def http_server():
    """Run `vcp-mcp --transport http` on a free loopback port for the module."""
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcp.mcp_server", "--transport", "http", "--host", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            output = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
            pytest.fail(f"vcp-mcp http exited early (rc={proc.returncode}):\n{output}")
        try:
            if httpx.get(f"{base}/health", timeout=1.0).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("vcp-mcp http never became healthy")

    try:
        yield base
    finally:
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=10)
        proc.kill()


def run_http_session(base: str, body):
    """Run an async body against a freshly handshaken HTTP server session."""

    async def _go():
        async with streamable_http_client(f"{base}/mcp") as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await body(session)

    return asyncio.run(asyncio.wait_for(_go(), timeout=60))


def test_http_handshake_and_tool_list(http_server):
    """initialize + tools/list over HTTP surfaces the same 7 tools as stdio."""

    async def body(session):
        return await session.list_tools()

    tools = run_http_session(http_server, body)
    assert len(tools.tools) == EXPECTED_TOOL_COUNT
    assert "vcp_validate_token" in {t.name for t in tools.tools}


def test_http_tool_call_returns_payload(http_server):
    """A tool call over HTTP returns the same JSON payload shape as stdio."""
    import json

    async def body(session):
        result = await session.call_tool("vcp_validate_token", {"token": "family.safe.guide"})
        return json.loads(result.content[0].text)

    payload = run_http_session(http_server, body)
    assert payload["valid"] is True
    assert payload["domain"] == "family"


def test_bare_mcp_redirect_is_relative(http_server):
    """A TLS-terminating proxy must not turn the MCP redirect into plain HTTP."""
    response = httpx.post(
        f"{http_server}/mcp",
        content=b"{}",
        headers={"Content-Type": "application/json"},
        follow_redirects=False,
        timeout=REQUEST_TIMEOUT,
    )

    assert response.status_code == 307
    assert response.headers["location"] == "/mcp/"


def test_get_does_not_hang(http_server):
    """GET on the MCP endpoint returns 405 promptly rather than holding an SSE stream.

    An idle held stream per GET is a connection-exhaustion DoS; stateless mode
    has no session for a server->client stream to belong to anyway.
    """
    started = time.monotonic()
    response = httpx.get(f"{http_server}/mcp/", timeout=REQUEST_TIMEOUT)
    assert time.monotonic() - started < REQUEST_TIMEOUT
    assert response.status_code == 405
    assert response.headers["allow"] == "POST"
    assert response.json()["error"]["code"] == -32600


def test_delete_rejected(http_server):
    """DELETE (session teardown) is equally meaningless statelessly and is refused."""
    response = httpx.request("DELETE", f"{http_server}/mcp/", timeout=REQUEST_TIMEOUT)
    assert response.status_code == 405


def test_malformed_body_is_a_clean_error(http_server):
    """Garbage in the body yields a JSON-RPC error with no stack trace or path leak."""
    response = httpx.post(
        f"{http_server}/mcp/",
        content=b"{not json at all",
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
        timeout=REQUEST_TIMEOUT,
    )
    assert response.status_code >= 400
    body = response.text
    assert "jsonrpc" in body or "error" in body
    # CWE-209: no internal detail reaches the client.
    for leak in ("Traceback", "site-packages", "/src/vcp", 'File "'):
        assert leak not in body, f"response leaked {leak!r}: {body[:400]}"


def test_health_endpoint(http_server):
    assert httpx.get(f"{http_server}/health", timeout=REQUEST_TIMEOUT).json() == {"status": "ok"}


# === Bind guard (pure unit — no server needed) ===


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "LocalHost"])
def test_loopback_hosts_recognised(host):
    assert is_loopback(host)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "example.com"])
def test_non_loopback_hosts_recognised(host):
    assert not is_loopback(host)


def test_loopback_bind_needs_no_opt_in():
    check_bind_allowed("127.0.0.1", env={})


def test_public_bind_refused_without_opt_in():
    with pytest.raises(ValueError, match="refusing to bind"):
        check_bind_allowed("0.0.0.0", env={})


def test_public_bind_allowed_with_opt_in():
    check_bind_allowed("0.0.0.0", env={ALLOW_INSECURE_ENV: "true"})


@pytest.mark.parametrize("value", ["false", "1", "yes", ""])
def test_opt_in_requires_literal_true(value):
    with pytest.raises(ValueError):
        check_bind_allowed("0.0.0.0", env={ALLOW_INSECURE_ENV: value})


def test_cli_refuses_public_bind():
    """The guard is wired into main(), not just importable."""
    proc = subprocess.run(
        [sys.executable, "-m", "vcp.mcp_server", "--transport", "http", "--host", "0.0.0.0"],
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode == 2
    assert b"refusing to bind" in proc.stderr


@pytest.mark.parametrize("port", ["0", "65536", "-1", "not-a-port"])
def test_cli_rejects_invalid_port_without_starting_server(port):
    proc = subprocess.run(
        [sys.executable, "-m", "vcp.mcp_server", "--transport", "http", "--port", port],
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode == 2
    assert b"port must be an integer from 1 to 65535" in proc.stderr


def test_cli_rejects_malformed_port_environment_cleanly():
    env = os.environ.copy()
    env["PORT"] = "not-a-port"
    proc = subprocess.run(
        [sys.executable, "-m", "vcp.mcp_server", "--transport", "http"],
        capture_output=True,
        timeout=30,
        env=env,
    )
    assert proc.returncode == 2
    assert b"port must be an integer from 1 to 65535" in proc.stderr
    assert b"Traceback" not in proc.stderr
