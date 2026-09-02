# vcp-sdk

Python SDK for the **Value Context Protocol (VCP)** — portable AI ethics
validation — plus the **Creed Commons** client (`vcp` CLI) for installing
signed value artifacts.

- Protocol and docs: [valuecontextprotocol.org](https://valuecontextprotocol.org)
- Creed Commons registry: [Creed-Space/vcp-hub](https://github.com/Creed-Space/vcp-hub)

## Legacy distribution status

This repository supplies the legacy standalone `vcp-sdk` 0.7.0 distribution on
[PyPI](https://pypi.org/project/vcp-sdk/0.7.0/) and the
`io.github.Creed-Space/vcp-mcp` 0.7.0 server entry in the MCP Registry. It is
separate from, and is not, the project-maintained VCP-SDK. To review and run
this source directly, select and verify an exact commit, then install that
checkout:

```bash
git checkout --detach <reviewed-vcp-sdk-python-commit>
python -m pip install .
python -m pip install ".[hub]"  # include the Creed Commons CLI dependencies
```

This candidate and the project-maintained VCP-SDK both use the `vcp` Python
import namespace. Install them in separate virtual environments. Installing
both into one environment is unsupported because one distribution can replace
the other's modules.

## SDK — tokens, CSM1, VCP-Lite

```python
from vcp import Token, CSM1Code, validate_lite

token = Token.parse("family.safe.guide@1.0.0")
code = CSM1Code.parse("N5+F+E")
identity = {"domain": "family", "approach": "safe", "role": "guide"}
document = {"vcp_version": "lite-1.0", "identity": identity, "persona": "nanny", "adherence": 5, "scopes": ["F"]}
errors = validate_lite(document)
```

`CSM1Code.encode()` (and `str(code)`) emits the canonical form with scopes
sorted (`N5+F+E` encodes as `N5+E+F`), matching the project-maintained
VCP-SDK and spec §2.10.1; `to_nano()`/`to_micro()` preserve input order.
`Token.parse` also accepts `creed://` and `vcp://` URIs and normalises them to
canonical form — a superset of the reference SDK, whose `parse` takes only
the bare token grammar.

## Creed Commons — signed value artifacts

Creed Commons distributes constitutions, creeds, and detector configs as
**signed data that a values engine interprets — never executable code**.
Installing an artifact is a signature-verification decision, not a
code-execution one:

```bash
vcp search gaslighting
vcp install creed-space/anti_gaslighting     # verify Ed25519 + sha256 + schema, then write
vcp verify                                    # re-check installed tree against vcp.lock
```

`vcp install` verifies against a trust root **pinned inside this package**
(the registry cannot vouch for itself), pins `name@version` + content sha256 +
the verifying key in `vcp.lock`, and never imports, evals, or executes what it
fetched.

**Community namespaces** are delegated, never a new root: the hub's
`namespace_registry.json` binds each namespace to its publisher's Ed25519 keys
and is itself signed by the pinned root; artifacts must verify against a key
registered to their own namespace. Registration and moderation:
[GOVERNANCE.md](https://github.com/Creed-Space/vcp-hub/blob/main/GOVERNANCE.md).

Trust tiers: `signed` proves integrity and origin, not semantics; `verified`
additionally carries a domain-separated **root counter-signature** (issued
after lint + red-team + human review) that the client checks on install and
on every `vcp verify`.

## CLI — protocol operations

Alongside the Creed Commons commands, `vcp` runs the protocol operations
directly. These call the same functions the MCP tools do, so scripted CLI
output and MCP tool output carry the same fields.

```bash
vcp token validate family.safe.guide@1.0.0   # parse a VCP/I token
vcp token parse N5+F+E                       # parse a CSM1 code
vcp lite validate agent.json                 # validate a VCP-Lite document
vcp lite to-csm1 agent.json                  # VCP-Lite document -> CSM1 code
vcp encode --space office --agency peer      # context -> VCP/A wire format
vcp classify "Never endanger a child"        # principle -> Schwartz value
vcp status                                   # versions, capabilities, vocabularies
```

Output is JSON by default. `--quiet` prints just the value the command is
about, for shell consumption:

```bash
$ vcp lite to-csm1 agent.json --quiet
N5+E+F

$ vcp encode --space office --constraints legal --constraints time --quiet
📍🏢|🔒⚖️⏱️
```

The `validate`/`parse` commands **exit 0 when valid and 1 when invalid**, so
they work as a CI gate:

```bash
vcp lite validate agent.json --quiet || exit 1
```

`vcp encode` takes one flag per context dimension (`--space`, `--agency`,
`--cognitive-state`, …); `--company` and `--constraints` repeat for multiple
values, and each personal dimension has a matching `--<dim>-intensity` (1-5).
Run `vcp encode --help` for the full list.

## MCP Server

<!-- mcp-name: io.github.Creed-Space/vcp-mcp -->

`vcp-mcp` exposes the SDK to any MCP client (Claude Code, Claude Desktop, or
anything else that speaks the protocol). It runs over stdio by default and is
**pure local computation** — no network calls, no state between calls, no user
data read.

```bash
python -m pip install ".[mcp]"
vcp-mcp
```

Claude Desktop / Claude Code config:

```json
{
  "mcpServers": {
    "vcp": {
      "command": "vcp-mcp"
    }
  }
}
```

### Tools

| Tool | What it does |
|---|---|
| `vcp_status` | SDK/spec versions, capabilities, dimension and persona vocabularies |
| `vcp_validate_token` | Parse a VCP/I token into domain / approach / role / version / namespace |
| `vcp_parse_csm1` | Parse a CSM1 code into persona / adherence / scopes / namespace / version (conflicting or deprecated scopes are rejected) |
| `vcp_encode_context` | Encode the 18 VCP/A context dimensions to wire, JSON, and session metadata |
| `vcp_validate_lite` | Validate a VCP-Lite document; returns the equivalent CSM1 code and token |
| `vcp_lite_to_csm1` | Convert VCP-Lite persona/adherence/scopes to a CSM1 code |
| `creed_classify_principle` | Map a constitution principle to a Schwartz value; flag circular-model tensions |

Resource `vcp://lite/examples` serves the bundled VCP-Lite example documents.

### HTTP transport

For hosted deployments, `vcp-mcp` also speaks Streamable HTTP:

```bash
vcp-mcp --transport http --port 8080     # binds 127.0.0.1, endpoint /mcp
```

`--port` defaults to `$PORT` then `8080`. The endpoint runs **stateless** (a
fresh transport per request), so a gateway may route any request to any
replica. Only `POST /mcp` is served — `GET` would otherwise hold an idle event
stream open per connection, so it is refused with a clean JSON-RPC 405. A
`GET /health` endpoint returns `{"status": "ok"}`.

The server has no authentication, so binding beyond loopback requires an
explicit opt-in:

```bash
VCP_MCP_ALLOW_INSECURE_HTTP=true vcp-mcp --transport http --host 0.0.0.0
```

Set that only when either a gateway or reverse proxy fronts the server and
handles client auth, or you intentionally run it as a public, unauthenticated,
stateless compute endpoint (as `render.yaml` in this repo does). In the latter
case put a rate limit / WAF in front of it: the exposure is abuse of paid
compute rather than data, since the server holds no state and reads nothing.

## Development

```bash
pip install -e ".[dev]"
pytest tests/
```

## License

Apache-2.0. © Creed Space.
