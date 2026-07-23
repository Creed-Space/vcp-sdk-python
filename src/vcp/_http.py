"""Streamable HTTP transport for the VCP MCP server — additive; stdio stays the default.

Selected with ``vcp-mcp --transport http``. Binds loopback by default: a
reverse proxy or hosting gateway is expected to be the only public-facing
component. The MCP tools are transport-agnostic and are not touched here —
this module only provides an alternate run harness for hosted deployments.

Everything runs stateless (a fresh transport per request), so a gateway may
route each request to any replica without session affinity.
"""

from __future__ import annotations

import contextlib
import os

from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send

#: Opt out of the "no unauthenticated non-loopback bind" guard. Set only where
#: something else fronts the server (the container image sets it for Smithery).
ALLOW_INSECURE_ENV = "VCP_MCP_ALLOW_INSECURE_HTTP"

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def is_loopback(host: str) -> bool:
    """True if ``host`` binds only the loopback interface.

    ``0.0.0.0`` and ``::`` bind every interface and are deliberately *not*
    loopback — that is the case the guard exists to catch.
    """
    return host.strip().lower() in _LOOPBACK_HOSTS


def check_bind_allowed(host: str, env: dict[str, str] | None = None) -> None:
    """Raise unless binding ``host`` is safe or explicitly opted into.

    The server has no authentication of its own, so exposing it beyond loopback
    is only sound when a gateway in front handles auth. Requiring an explicit
    env opt-in makes that a deliberate deployment decision rather than an
    accident of passing ``--host 0.0.0.0``.
    """
    if is_loopback(host):
        return
    environ = os.environ if env is None else env
    if environ.get(ALLOW_INSECURE_ENV, "").strip().lower() == "true":
        return
    raise ValueError(
        f"refusing to bind {host!r}: vcp-mcp has no authentication of its own. "
        f"Set {ALLOW_INSECURE_ENV}=true only when a gateway or proxy fronts it "
        f"and handles client auth; otherwise bind 127.0.0.1."
    )


def build_http_app(server: Server) -> Starlette:
    """Wrap a low-level MCP ``Server`` in a Starlette ASGI app over Streamable HTTP.

    Stateless mode (a fresh transport per request, no persisted sessions) avoids
    the idle-session / held-event-stream class of connection-exhaustion DoS.
    ``debug=False`` ensures Starlette never renders a stack trace or a source
    path to a client (CWE-209).
    """
    manager = StreamableHTTPSessionManager(
        app=server,
        event_store=None,
        json_response=True,
        stateless=True,
    )

    async def handle_mcp(scope: Scope, receive: Receive, send: Send) -> None:
        # Stateless mode has no session, so GET (the server->client SSE stream)
        # and DELETE (teardown) are meaningless — and a GET would hold an idle
        # event stream open indefinitely. Accept only POST; reject the rest with
        # a clean JSON-RPC 405. Defense in depth: a front proxy should also
        # restrict methods, but the app must be safe when run alone.
        if scope.get("type") == "http" and scope.get("method") != "POST":
            response = JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32600, "message": "Only POST is supported"},
                    "id": None,
                },
                status_code=405,
                headers={"Allow": "POST"},
            )
            await response(scope, receive, send)
            return
        await manager.handle_request(scope, receive, send)

    async def health(_request):
        return JSONResponse({"status": "ok"})

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette):
        # run() sets up the manager's task group; it must live for the app's
        # lifetime and may only be entered once per instance.
        async with manager.run():
            yield

    # Mount at /mcp. A bare `/mcp` request 307-redirects to `/mcp/`; this is the
    # reference MCP behaviour and SDK/httpx clients follow it transparently.
    return Starlette(
        debug=False,
        routes=[
            Route("/health", health, methods=["GET"]),
            Mount("/mcp", app=handle_mcp),
        ],
        lifespan=lifespan,
    )


def run_http(server: Server, host: str, port: int) -> None:
    """Serve ``server`` over Streamable HTTP (blocking).

    Callers are expected to have run :func:`check_bind_allowed` first.
    """
    import uvicorn

    uvicorn.run(
        build_http_app(server),
        host=host,
        port=port,
        log_level="info",
        access_log=False,
    )
