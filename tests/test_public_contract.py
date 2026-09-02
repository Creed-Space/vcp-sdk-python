"""Regression checks for the legacy package publication boundary."""

import doctest
import re
from pathlib import Path

import vcp

README = Path(__file__).parents[1] / "README.md"
PYPROJECT = Path(__file__).parents[1] / "pyproject.toml"


def test_readme_identifies_the_published_legacy_distribution() -> None:
    text = README.read_text(encoding="utf-8")
    prose = re.sub(r"\s+", " ", text)

    assert "legacy standalone `vcp-sdk` 0.8.0 distribution" in prose
    assert "`io.github.Creed-Space/vcp-mcp` 0.8.0 server entry" in prose
    assert "is not, the project-maintained VCP-SDK" in prose
    assert 'python -m pip install ".[hub]"' in text


def test_readme_warns_that_the_two_vcp_import_namespaces_cannot_coexist() -> None:
    prose = re.sub(r"\s+", " ", README.read_text(encoding="utf-8"))

    assert "both use the `vcp` Python import namespace" in prose
    assert "separate virtual environments" in prose


def test_package_docstring_examples_are_executable() -> None:
    result = doctest.testmod(vcp, raise_on_error=True)

    assert result.attempted == 6


def test_mcp_runtime_dependency_stays_within_the_supported_major() -> None:
    """A fresh install must not resolve MCP 2, which removed FastMCP, nor
    anything below 1.8, the first release with ``StreamableHTTPSessionManager``
    and its ``json_response``/``stateless`` options that the HTTP transport uses."""
    metadata = PYPROJECT.read_text(encoding="utf-8")
    dev = re.search(r"(?ms)^dev = \[\n(.*?)^\]", metadata)

    assert 'mcp = ["mcp>=1.8,<2"]' in metadata
    assert dev is not None and '"mcp>=1.8,<2"' in dev.group(1)


def test_package_metadata_uses_the_live_documentation_root() -> None:
    """Published metadata must not send users to the removed /docs/sdk route."""
    metadata = PYPROJECT.read_text(encoding="utf-8")

    assert 'Documentation = "https://valuecontextprotocol.org/docs/"' in metadata
    assert "valuecontextprotocol.org/docs/sdk" not in metadata
