# Container image for the VCP MCP server (Streamable HTTP).
#
# Built for hosted deployment behind a gateway (Smithery). Local MCP clients
# should use stdio instead — `pip install "vcp-sdk[mcp]"` and run `vcp-mcp`,
# no container needed.
FROM python:3.12-slim

WORKDIR /app

# Copy the package sources, then install from them. Building from the checkout
# rather than PyPI means the image always matches this commit — no window where
# the container serves a version that has not been released yet.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir '.[mcp]'

# This image serves HTTP behind Smithery's gateway, which is the only path in
# and handles client auth, so it opts out of vcp-mcp's "no unauthenticated
# non-loopback bind" guard. Set ONLY here — anyone running vcp-mcp directly
# keeps the guard and has to make that choice deliberately.
ENV VCP_MCP_ALLOW_INSECURE_HTTP=true

# The gateway injects $PORT at runtime; expose a sensible default for local runs.
ENV PORT=8080
EXPOSE 8080

# sh -c (not JSON exec form) so ${PORT} expands at runtime; `exec` replaces the
# shell so signals reach the server directly.
ENTRYPOINT ["sh", "-c", "exec vcp-mcp --transport http --host 0.0.0.0 --port ${PORT:-8080}"]
