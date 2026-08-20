"""Regression checks for the source-only package publication boundary."""

import doctest
import re
from pathlib import Path

import vcp

README = Path(__file__).parents[1] / "README.md"
SOURCE = Path(__file__).parents[1] / "src"


def test_readme_does_not_advertise_an_unratified_registry_install() -> None:
    text = README.read_text(encoding="utf-8")
    prose = re.sub(r"\s+", " ", text)

    assert re.search(r"pip\s+install\s+['\"]?vcp-sdk(?:\[|['\"\s])", text) is None
    assert "no PyPI release or registry package name is claimed" in prose
    assert 'python -m pip install ".[hub]"' in text

    packaged_source = "\n".join(path.read_text(encoding="utf-8") for path in SOURCE.rglob("*.py"))
    assert re.search(r"(?:pip\s+install|install)\s+['\"]?vcp-sdk(?:\[|['\"\s])", packaged_source) is None


def test_readme_warns_that_the_two_vcp_import_namespaces_cannot_coexist() -> None:
    prose = re.sub(r"\s+", " ", README.read_text(encoding="utf-8"))

    assert "both use the `vcp` Python import namespace" in prose
    assert "separate virtual environments" in prose


def test_package_docstring_examples_are_executable() -> None:
    result = doctest.testmod(vcp, raise_on_error=True)

    assert result.attempted == 6
