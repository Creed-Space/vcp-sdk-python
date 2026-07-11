# vcp-sdk

Python SDK for the **Value Context Protocol (VCP)** — portable AI ethics
validation — plus the **Creed Commons** client (`vcp` CLI) for installing
signed value artifacts.

- Protocol and docs: [valuecontextprotocol.org](https://valuecontextprotocol.org)
- Creed Commons registry: [Creed-Space/vcp-hub](https://github.com/Creed-Space/vcp-hub)

## Install

```bash
pip install vcp-sdk            # core SDK (stdlib-only)
pip install "vcp-sdk[hub]"     # + the vcp CLI for Creed Commons
```

## SDK — tokens, CSM1, VCP-Lite

```python
from vcp import Token, CSM1Code, validate_lite

token = Token.parse("family.safe.guide@1.0.0")
code = CSM1Code.parse("N5+F+E")
errors = validate_lite({"vcp_version": "lite-1.0", ...})
```

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

`vcp install` verifies against a publisher-key allowlist **pinned inside this
package** (the registry cannot vouch for itself), pins `name@version` +
content sha256 in `vcp.lock`, and never imports, evals, or executes what it
fetched. Trust tiers: `signed` proves integrity and origin, not semantics;
`verified` (lint + red-team + counter-signature) is not yet issued.

## Development

```bash
pip install -e ".[dev]"
pytest tests/
```

## License

Apache-2.0. © Creed Space.
