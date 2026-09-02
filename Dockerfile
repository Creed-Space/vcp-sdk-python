# Container image for the VCP MCP server (Streamable HTTP).
#
# Built for hosted deployment (Smithery, Render). Local MCP clients
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

# vcp-mcp has no authentication. This image opts out of its "no unauthenticated
# non-loopback bind" guard because it is deployed either behind a gateway that
# handles client auth (Smithery) or, via render.yaml, as an intentionally
# public, unauthenticated, stateless compute endpoint. In the public case put a
# rate limit / WAF in front: the exposure is abuse of paid compute, not data.
# Set ONLY here — anyone running vcp-mcp directly keeps the guard and has to
# make that choice deliberately.
ENV VCP_MCP_ALLOW_INSECURE_HTTP=true

# The platform injects $PORT at runtime; expose a sensible default for local runs.
ENV PORT=8080
EXPOSE 8080

# Pure compute needs no privileges: run as an unprivileged user.
RUN useradd --system --no-create-home vcp
USER vcp

# sh -c (not JSON exec form) so ${PORT} expands at runtime; `exec` replaces the
# shell so signals reach the server directly.
ENTRYPOINT ["sh", "-c", "exec vcp-mcp --transport http --host 0.0.0.0 --port ${PORT:-8080}"]
